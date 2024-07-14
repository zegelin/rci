use std::{collections::HashMap, env::VarError, fs::File, io::BufReader, ops::Deref, path::{Path, PathBuf}, rc::Rc};

use figment::{providers::{Format, Toml}, value::magic::{Magic, RelativePathBuf, Tagged}, Figment};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use serde::{de::{self, value::MapAccessDeserializer, MapAccess, Visitor}, Deserialize, Deserializer};

use anyhow::{anyhow, bail, Context, Result};
use tracing::debug;
use url::Host;
use vec1::Vec1;

use crate::remote::{pfsense, megarac};

#[derive(Deserialize, Debug, Clone)]
#[serde(try_from = "figment::value::magic::RelativePathBuf")]
pub struct CredentialPathBuf(PathBuf);

impl TryFrom<RelativePathBuf> for CredentialPathBuf {
    type Error = anyhow::Error;

    fn try_from(value: RelativePathBuf) -> std::prelude::v1::Result<Self, Self::Error> {
        // if the path is prefixed with the env var reference, try and
        // replace the prefix with the path from the env. It is an error the env var doesn't exist.
        let path = if let Ok(sub) = value.original().strip_prefix("$CREDENTIALS_DIRECTORY") {
            match std::env::var_os("CREDENTIALS_DIRECTORY") {
                Some(cd) => PathBuf::from(cd).join(sub),
                None => bail!("$CREDENTIALS_DIRECTORY is referenced yet that environment variable isn't set"),
            }
        } else {
            value.relative()
        };

        Ok(Self(path))
    }
}

impl Deref for CredentialPathBuf {
    type Target = PathBuf;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<Path> for CredentialPathBuf {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}


#[derive(Deserialize, Debug)]
pub struct CertificatePair {
    #[serde(rename = "certificate_chain_path", deserialize_with = "CertificatePair::load_certificate_chain")]
    pub certificate_chain: Vec1<CertificateDer<'static>>,

    #[serde(rename = "private_key_path", deserialize_with = "CertificatePair::load_private_key")]
    pub private_key: PrivateKeyDer<'static>,
}

impl CertificatePair {
    /// load the certificate chain from a PEM file
    fn load_certificate_chain<'de, D>(d: D) -> Result<Vec1<CertificateDer<'static>>, D::Error> where
        D: Deserializer<'de>
    {
        let path = CredentialPathBuf::deserialize(d)?;

        let file = File::open(&path)
            .with_context(|| format!("failed to open \"{}\"", path.display()))
            .map_err(de::Error::custom)?;

        let mut reader = BufReader::new(file);

        let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()
            .with_context(|| format!("failed to read certificates from PEM file \"{}\"", path.display()))
            .map_err(de::Error::custom)?;

        let certs = Vec1::try_from_vec(certs).map_err(de::Error::custom)?;

        // if certs.is_empty() {
        //     return Err(de::Error::custom(format!("no certificates found in PEM file \"{}\"", path.display())))
        // }

        Ok(certs)
    }
    
    fn load_private_key<'de, D>(d: D) -> Result<PrivateKeyDer<'static>, D::Error> where
        D: Deserializer<'de>
    {
        let path = CredentialPathBuf::deserialize(d)?;

        let file = File::open(&path)
            .with_context(|| format!("failed to open \"{}\"", path.display()))
            .map_err(de::Error::custom)?;
        
        let mut reader = BufReader::new(file);

        let key = rustls_pemfile::private_key(&mut reader)
            .with_context(|| format!("failed to read private key from PEM file \"{}\"", path.display()))
            .map_err(de::Error::custom)?;

        key.ok_or_else(|| de::Error::custom(format!("no private key found in PEM file \"{}\"", path.display())))
    }

    pub fn fullchain_certificate_pem_string(&self) -> Result<String> {
        const LABEL: &str = "CERTIFICATE";

        use pem_rfc7468::*;

        let line_ending = LineEnding::default();

        let required_length = self.certificate_chain.iter()
            .map(|cert| encoded_len(LABEL, line_ending, cert))
            .sum::<Result<usize>>()?;

        let buffer = String::with_capacity(required_length);

        self.certificate_chain.iter()
            .try_fold(buffer, |acc, cert| {
                let s = acc + &pem_rfc7468::encode_string(LABEL, pem_rfc7468::LineEnding::default(), cert)?;
                Result::Ok(s)
            })
            .context("failed to encode full certificate chain as PEM")
    }

    pub fn private_key_pem_string(&self) -> Result<String> {
        let label = match &self.private_key {
            PrivateKeyDer::Pkcs1(_) => "RSA PRIVATE KEY",
            PrivateKeyDer::Sec1(_) => "EC PRIVATE KEY",
            PrivateKeyDer::Pkcs8(_) => "PRIVATE KEY",
            other => unimplemented!("private keys of type {other:?} are not supported"),
        };

        pem_rfc7468::encode_string(label, pem_rfc7468::LineEnding::default(), self.private_key.secret_der())
            .context("failed to encode private key as PEM")
    }

}

/// Either the name of a globally defined certificate pair
/// or an inline certificate pair specific to the attached remote. 
#[derive(Debug, Clone)]
pub enum CertificateRef {
    Named(String),
    Certificate(Rc<CertificatePair>)
}

impl CertificateRef {
    pub fn try_resolve(&self, global_certs: &HashMap<String, Rc<CertificatePair>>) -> Result<Rc<CertificatePair>> {
        Ok(match self {
            CertificateRef::Named(name) => {
                let cert = global_certs.get(name).ok_or_else(|| anyhow!("no such global certificate named \"{name}\""))?;
                cert.clone()
            },
            CertificateRef::Certificate(cert) => cert.clone(),
        })
    }
}

impl Default for CertificateRef {
    fn default() -> Self {
        CertificateRef::Named("default".to_string())
    }
}

impl<'de> Deserialize<'de> for CertificateRef {
    /// deserialize either a string (the name of a globally defined cert pair) or an
    /// inline cert pair
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>
    {
        struct NamedOrCert;
        
        impl <'de> Visitor<'de> for NamedOrCert {
            type Value = CertificateRef;
        
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a global certificate pair name or a certificate pair")
            }

            fn visit_str<E>(self, value: &str) -> Result<CertificateRef, E>
            where
                E: de::Error,
            {
                Ok(CertificateRef::Named(value.to_owned()))
            }

            fn visit_map<M>(self, map: M) -> Result<CertificateRef, M::Error>
            where
                M: MapAccess<'de>,
            {
                CertificatePair::deserialize(MapAccessDeserializer::new(map))
                    .map(|v| CertificateRef::Certificate(Rc::new(v)))
            }
        }
        
        deserializer.deserialize_any(NamedOrCert {})
    }
}


#[derive(Deserialize, Debug)]
pub struct RawConfig {
    #[serde(rename = "certs")]
    certificates: HashMap<String, CertificatePair>,

    pfsense: HashMap<String, pfsense::Config<CertificateRef>>,

    // #[serde(rename = "megarac-bmc")]
    // megarac_bmc: Tagged<HashMap<String, megarac::Config>>
}

#[derive(Debug)]
pub enum RemoteConfig {
    PfSense(pfsense::Config<Rc<CertificatePair>>),
    Megarac(megarac::Config<Rc<CertificatePair>>),
    Brother,
    Cloudkey,
}


#[derive(Deserialize, Debug)]
#[serde(try_from = "RawConfig")]
pub struct Config {
    pub remotes: HashMap<String, RemoteConfig>
}

impl TryFrom<RawConfig> for Config {
    type Error = anyhow::Error;

    fn try_from(config: RawConfig) -> Result<Self> {
        let global_certs = config.certificates.into_iter()
            .map(|(name, pair)| (name, Rc::new(pair)))
            .collect::<HashMap<_, _>>();

        let mut remotes = HashMap::new();

        for (name, c) in config.pfsense {
            let name = format!("pfsense.{name}");
            let c = c.try_resolve_certificate(&global_certs)
                .map_err(|e| anyhow!("{e} in remote config `{name}`"))?;

            remotes.insert(name, RemoteConfig::PfSense(c));
        }

        Ok(Config {
            remotes
        })
    }
}

pub fn load_config(path: &PathBuf) -> Result<Config> {
    debug!("loading config file {}", path.display());

    if !path.exists() {
        bail!("{}: file not found", path.display())
    }

    let f = Figment::from(Toml::file(path));

    Ok(f.extract()?)
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_credentials_pathbuf() {
        #[derive(Deserialize, Debug)]
        struct Config {
            path: CredentialPathBuf
        }

        figment::Jail::expect_with(|jail| {
            jail.create_file("config.toml", r#"
                path = "./some-file"
            "#)?;

            let config: Config = Figment::new()
                .merge(Toml::file("config.toml"))
                .extract().unwrap();

            //assert_eq!(config.path, )

            println!("{config:?}");

            Ok(())
        });

        figment::Jail::expect_with(|jail| {
            jail.set_env("CREDENTIALS_DIRECTORY", "/some/directory");

            jail.create_file("config.toml", r#"
                path = "$CREDENTIALS_DIRECTORY/some-file"
            "#)?;

            let config: Config = Figment::new()
                .merge(Toml::file("config.toml"))
                .extract().unwrap();

            println!("{config:?}");

            Ok(())
        });
    }

    struct Data {}

    enum PropertyData {
        Named(String),
        Data(Rc<Data>)
    }

    impl PropertyData {
        fn resolve(&mut self, global_data: &HashMap<String, Rc<Data>>) {
            match self {
                PropertyData::Named(name) => {
                    let data = global_data.get(name).unwrap();

                    *self = PropertyData::Data(data.clone());
                },
                _ => (),
            }
        }
    }

    struct Config {
        global_data: HashMap<String, Rc<Data>>,

        other_thing: PropertyData
    }

    impl Config {
        fn resolve_data(&mut self) {
            self.other_thing.resolve(&self.global_data)
        }
    }

    fn enum_test() {
        let mut config = Config {
            global_data: HashMap::new(),
            other_thing: PropertyData::Named("awesome".into())
        };

        config.global_data.insert("awesome".into(), Rc::new(Data {}));

        config.other_thing.resolve(&config.global_data);
    }
}