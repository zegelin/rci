use std::{default, path::{Path, PathBuf}, sync::Arc};

use async_trait::async_trait;
use anyhow::{bail, Context, Result};
use figment::value::magic::Tagged;
use russh::client::{self, Handle, Session};
use russh_keys::{key::{KeyPair, PublicKey}, load_secret_key, parse_public_key_base64};
use serde::{Deserialize, Deserializer};
use tracing::{event, Level};
use url::{Host, Url};

use crate::config::CredentialPathBuf;

#[derive(Debug, Clone)]
enum HostKey {
    Ignore,
    PublicKey(PublicKey)
}

#[derive(Deserialize, Debug)]
pub struct Config {
    #[serde(rename = "private_key_file", deserialize_with = "Config::load_private_key")]
    private_key: KeyPair,

    // 'ignore' is not the default -- best to let configs be explicit about such things
    #[serde(deserialize_with = "Config::host_key")]
    host_key: HostKey
}

impl Config {
    fn load_private_key<'de, D>(d: D) -> Result<KeyPair, D::Error>
        where D: Deserializer<'de>
    {
        let path = CredentialPathBuf::deserialize(d)?;

        let key = load_secret_key(path.as_path(), None)
            .map_err(|e| serde::de::Error::custom(format!("failed to load private key \"{}\" ({e})", path.display())));

        Ok(key?)
    }

    fn host_key<'de, D>(d: D) -> Result<HostKey, D::Error>
        where D: Deserializer<'de>
    {
        let key = String::deserialize(d)?;

        let key = match key.as_str() {
            "ignore" => HostKey::Ignore,
            key => {
                let key = parse_public_key_base64(key)
                    .map_err(|e| serde::de::Error::custom(format!("parse host key failed ({e})")));

                HostKey::PublicKey(key?)
            }
        };

        Ok(key)
    }
}


#[derive(Debug, Clone)]
pub struct ConnectOptions {
    host: String,
    port: u16,

    username: String,

    private_key: KeyPair,

    host_key: HostKey,
}

impl ConnectOptions {
    pub fn new(url: Url, config: &Config) -> Result<Self> {
        let host = url.host_str().context("a hostname must be specified in the URL for SSH connections")?;
        let port = url.port().unwrap_or(22);

        let username = {
            let username = url.username();
            if username.is_empty() {
                bail!("a username must be specified in the URL for SSH connections")
            }
            username
        };


        Ok(Self {
            host: host.to_owned(), port,
            username: username.to_owned(),

            private_key: config.private_key.clone(),
            host_key: config.host_key.clone()
        })

    }
}

// struct Client {}

// impl client::Handler for Client {
//     type Error = russh::Error;
// }

pub struct ClientHandler {
    host_key: HostKey
}

#[async_trait]
impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(&mut self, server_public_key: &PublicKey) -> Result<bool, Self::Error> {
        match &self.host_key {
            HostKey::Ignore => return Ok(true),
            HostKey::PublicKey(key) => return Ok(*server_public_key == *key),
        }
    }
}


pub async fn ssh_connect(options: &ConnectOptions) -> Result<Handle<ClientHandler>> {
    let client_config = Arc::new(client::Config {
        .. <_>::default()
    });

    let handler = ClientHandler {
        host_key: options.host_key.clone()
    };

    event!(Level::INFO, "establishing SSH connection to {}", &options.host);
    let mut handle = client::connect(client_config, (options.host.as_str(), options.port), handler).await
        .with_context(|| format!("error while establishing SSH connection to {}", &options.host))?;

    let auth_result = handle.authenticate_publickey(&options.username, Arc::new(options.private_key.clone())).await
        .with_context(|| format!("error while authenticating SSH connection to {}", &options.host))?;

    if !auth_result {
        bail!("public key authentication unsuccessful for SSH connection to {}", &options.host)
    }

    Ok(handle)
}