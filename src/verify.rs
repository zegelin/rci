use rustls_pki_types::UnixTime;
use serde::Deserialize;
use url::Url;
use anyhow::{anyhow, bail, Result};
use webpki::{EndEntityCert, KeyUsage};

use crate::config::CertificatePair;


enum VerifyProtocol {
    Https,
    TcpTls
}


#[derive(Deserialize, Debug)]
pub struct RawConfig {
    url: Option<Url>
}

#[derive(Debug, Deserialize)]
// #[serde(try_from = "RawConfig")]
pub struct Config {
    url: Url
}

// impl TryFrom<RawConfig> for Config {
//     type Error = anyhow::Error;

//     fn try_from(c: RawConfig) -> Result<Self> {
//         let url = c.url.ok_or_else(|| anyhow!("url must be present"))?;

//         match url.scheme() {
//             "https" => (),
//             "tcp+tls" => (),
//             other => bail!("unknown verification protocol {other}")
//         }

//         todo!()
//     }
// }

pub fn precheck_certificate(certificate: &CertificatePair) -> Result<()> {
    let end_entity_cert: EndEntityCert = certificate.certificate_chain.first().try_into()?;

    end_entity_cert.verify_for_usage(&[], &[], &[], UnixTime::now(), KeyUsage::server_auth(), None, None)?;

    Ok(())
}

fn check_remote_certificate() {

}

#[cfg(test)]
mod test {
    use reqwest::{tls::TlsInfo, Client};
    use x509_cert::{der::{Decode, EncodePem}, Certificate};


    #[tokio::test]
    async fn http_test() {
        // let client = Client::builder()
        //     .https_only(true)
        //     .tls_info(true)
        //     .danger_accept_invalid_certs(true)
        //     .build().unwrap();

        // let response = client.get("https://nexus.zegelin.net").send().await.unwrap();

        // let ext = response.extensions();
        // let tls_info: Option<&TlsInfo> = ext.get();
        // let tls_info = tls_info.unwrap();

        // // tls_info.peer_certificate()

        // let cert = Certificate::from_der(tls_info.peer_certificate().unwrap()).unwrap();

        // let pem = cert.to_pem(x509_cert::der::pem::LineEnding::CRLF).unwrap();

        // println!("{pem}");
        
    }
}