use std::{collections::HashMap, path::PathBuf, rc::Rc};

use anyhow::{anyhow, bail, Result};
use serde::{de::{self, MapAccess, Visitor}, Deserialize};
use url::Url;

use crate::{config::{CertificatePair, CertificateRef}, ssh::ConnectOptions};

#[derive(Deserialize, Debug)]
struct RawConfig {
    pub certificate: CertificateRef,

    pub url: Url,

    #[serde(rename = "ssh")]
    pub ssh_config: Option<crate::ssh::Config>,

    #[serde(rename = "http")]
    pub http_config: Option<crate::http::Config>,

    // #[serde(rename = "verify")]
    // pub verify_config: crate::verify::RawConfig,

    /// The pfSense certificate reference ID
    pub refid: String,
}


#[derive(Debug, Clone)]
pub enum ProtocolConfig {
    Ssh {
        ssh_options: crate::ssh::ConnectOptions,
    },
    Http {}
}

#[derive(Debug, Clone)]
pub struct Config<CertT> {
    pub certificate: CertT,

    refid: String,

    protocol: ProtocolConfig
}

impl Config<CertificateRef> {
    pub fn try_resolve_certificate(self, global_certs: &HashMap<String, Rc<CertificatePair>>) -> Result<Config<Rc<CertificatePair>>> {
        Ok(Config {
            certificate: self.certificate.try_resolve(global_certs).map_err(|e| anyhow!("{e} for key `certificate`"))?,
            refid: self.refid,
            protocol: self.protocol
        })
    }
}

impl <'de> Deserialize<'de> for Config<CertificateRef> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>
    {
        let raw = RawConfig::deserialize(deserializer)?;

        let pc = match raw.url.scheme() {
            proto @ ("http" | "https") => {
                if raw.ssh_config.is_some() {
                    return Err(de::Error::custom(format!("key `ssh` cannot be set for {proto} connections")))
                }

                ProtocolConfig::Http {  }
            },
            proto @ "ssh" => {
                if raw.http_config.is_some() {
                    return Err(de::Error::custom(format!("key `http` cannot be set for {proto} connections")))
                }

                let ssh_config = raw.ssh_config
                    .ok_or(de::Error::custom(format!("key `ssh` is required for {proto} connections")))?;

                let ssh_options = ConnectOptions::new(raw.url, &ssh_config).unwrap();

                ProtocolConfig::Ssh { ssh_options }
            },
            other => {
                return Err(de::Error::custom(format!("unknown protocol '{other}'")));
            }
        };

        Ok(Config { certificate: raw.certificate, refid: raw.refid, protocol: pc })
    }
}

mod ssh {
    use std::{fmt::Display, sync::Arc};

    use anyhow::{bail, Context, Result};
    use russh::{ChannelMsg, CryptoVec};
    use tokio::io::AsyncWriteExt as _;
    use tracing::{debug, event, Level};
    use url::Url;

    use crate::{config::CertificatePair, ssh::{ssh_connect, ConnectOptions}};

    use super::Config;

    const UPDATE_SCRIPT: &str = include_str!("pfsense-update.php");

    pub async fn update_certificate(certificate: &CertificatePair, ref_id: &String, ssh_options: &ConnectOptions) -> Result<()> {
        let script = UPDATE_SCRIPT.replace("@@REFID@@", ref_id)
            .replace("@@CERTIFICATE@@", &certificate.fullchain_certificate_pem_string()?)
            .replace("@@PRIVATE_KEY@@", &certificate.private_key_pem_string()?)
            .into_bytes();

        let handle = ssh_connect(ssh_options).await?;

        debug!("opening session");
        let mut channel = handle.channel_open_session().await?;

        debug!("running PHP update script");
        channel.exec(true, "php").await?;
        channel.data(&script[..]).await?;
        channel.eof().await?;

        let mut exit_status = None;

        loop {
            let Some(msg) = channel.wait().await else {
                break;
            };

            match msg {
                ChannelMsg::Data { ref data } => {
                    struct DisplayUtf8CryptoVec<'a>(&'a CryptoVec);

                    impl Display for DisplayUtf8CryptoVec<'_> {
                        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                            write!(f,"{}", String::from_utf8_lossy(self.0))
                        }
                    }

                    debug!("script stdout: {}", DisplayUtf8CryptoVec(data))
                }
                ChannelMsg::ExitStatus { exit_status: status } => exit_status = Some(status),
                _ => {}
            }
        }

        let Some(exit_status) = exit_status else {
            bail!("SSH channel closed without an exit status from the script");
        };

        match exit_status {
            0 => Ok(()),
            other => bail!("certificate update script exited with status {other}")
        }
    }
}

// mod http {
//     use std::{sync::Arc, collections::HashMap};
//     use anyhow::{Result, Context};

//     use regex::Regex;
//     use reqwest::{cookie::Jar, header::HeaderMap, Client, IntoUrl, Url};

//     use super::Config;


//     fn extract_csrf_token<'h>(body: &'h str) -> Option<&'h str> {
//         let re = Regex::new(r#"<input type="hidden" name="__csrf_magic" value="(.+)">"#).unwrap();
        
//         if let Some(caps) = re.captures(body) {
//             Some(caps.get(1).expect("capture group 1").as_str())
    
//         } else {
//             None
//         }
//     }
    
//     async fn login<U: IntoUrl>(client: &Client, url: U,) {
//         // get the form page
//         let response = client.get(url)
//             .send().expect("send request")
//             .text().expect("valid text response");
    
//         let csrf_token = extract_csrf_token(&response).expect("csrf token");
    
//         let mut creds = HashMap::new();
//         creds.insert("__csrf_magic", csrf_token);
//         creds.insert("usernamefld", "certupdate");
//         creds.insert("passwordfld", "test");
    
//         // client.post(url)
//         //     .form(&creds);
    
    
//     }
    
//     pub async fn update_certificate(config: &Config) -> Result<()> {
//         let base_url = Url::parse(config.url).expect("valid base_url");
    
//         let api_url = |path: &str| -> Url {
//             base_url.join(path).expect("valid API url")
//         };
    
    
//         let client = Client::builder()
//                 .cookie_store(true)
//                 .danger_accept_invalid_certs(true)
//                 .build().expect("valid client");
    
    
//         let response = client.get(base_url)
//             .send().expect("send request")
//             .text().expect("valid text response");
    
//         let login_csrf = extract_csrf_token(&response);
    
//         // TODO: check result == 401 and "error"="Invalid Authentication"
    
//         let mut creds = HashMap::new();
//         creds.insert("username", "admin");
//         creds.insert("password", "password");
//     }
// }


pub async fn update_certificate(config: &Config<Rc<CertificatePair>>) -> Result<()> {
    match &config.protocol {
        ProtocolConfig::Ssh { ssh_options } => ssh::update_certificate(&config.certificate, &config.refid, &ssh_options).await,
        ProtocolConfig::Http {  } => todo!(),
    }
}



#[cfg(test)]
mod test {
    use figment::{providers::{Format as _, Toml}, Figment};

    use crate::{config, ssh::ssh_connect};

    use super::*;

    // #[tokio::test]
    // async fn test_config() {
    //     #[derive(Deserialize)]
    //     struct Foo {
    //         pub pfsense: Config
    //     };

    //     let config = Figment::new()
    //             .merge(Toml::string(r"
    //             [pfsense]
    //             url = 'ssh://admin@nexus.zegelin.net'
    //             refid = 'hello'

    //             ssh.private_key_file = 'test-pkey.key'
    //             ssh.host_key = 'AAAAC3NzaC1lZDI1NTE5AAAAIHMIoo/JwMf1Z4n+tfg0gtUFOj07KwYK74/4ebZ+r2B6' 

                
    //             "))
    //             .extract::<Foo>();

    //     match config {
    //         Ok(c) => {
    //             println!("all g!");

    //             match c.pfsense.protocol {
    //                 ProtocolConfig::Ssh { ssh_options } => ssh_connect(&ssh_options).await.unwrap(),
    //                 ProtocolConfig::Http {  } => todo!(),
    //             };
    //         },
    //         Err(e) => {
    //             println!("{e}");
    //             println!("{e:?}");
    //         },
    //     }
    // }

    
}
