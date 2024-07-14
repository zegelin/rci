use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::Parser;
use clap::command;
use config::load_config;
use tracing::info;
// use remote::megarac::Config;
use url::Url;

use anyhow::Result;
use verify::precheck_certificate;

use crate::config::RemoteConfig;

mod config;
mod remote;
mod ssh;
mod http;
mod verify;

const DEFAULT_CONFIG_FILE_PATH: &str = match option_env!("DEFAULT_CONFIG_FILE_PATH") {
    Some(v) => v,
    None => if cfg!(debug_assertions) {
        "certinstaller.toml"
    } else {
        "/etc/certinstaller.conf"
    }
};


#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg[long, default_value=DEFAULT_CONFIG_FILE_PATH]]
    config_file: PathBuf
}

async fn update_certificate(config: &RemoteConfig) -> Result<()> {
    match config {
        RemoteConfig::PfSense(config) => remote::pfsense::update_certificate(config).await,
        RemoteConfig::Megarac(config) => remote::megarac::update_certificate(config).await,
        RemoteConfig::Brother => todo!(),
        RemoteConfig::Cloudkey => todo!(),
    }
}

//async fn update_certificates(remotes: &Map<String, ((), &RemoteConfig))


#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    let config = load_config(&args.config_file)?;



    for (name, config) in &config.remotes {
        match config {
            RemoteConfig::PfSense(config) => precheck_certificate(&config.certificate)?,
            other => todo!()
            // RemoteConfig::Megarac(_) => todo!(),
            // RemoteConfig::Brother => todo!(),
            // RemoteConfig::Cloudkey => todo!(),
        }
    }

    
    info!("updating certificates");
    for (name, config) in config.remotes {
        update_certificate(&config).await
            .context("failed to update certificate for \"{name}\"")?;

        info!("sucessfully updated certificate on {name}")
    }

    //

    Ok(())

    // remote::megarac::update_certificate(&Config {
    //     url: Url::parse("https://admin:password@hyperion-ipmi.zegelin.net").unwrap(),
    //     certificate: Some(Path::new("certs/fullchain.pem").into()),
    //     private_key: Some(Path::new("certs/key.pem").into()),
    //     password: None,
    // }).await.context("failed to update certificate on remote \"megarac.hyperion\"")
}
