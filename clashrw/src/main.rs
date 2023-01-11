mod parser;

use crate::parser::RemoteConfigure;
use anyhow::anyhow;
use clap::{arg, command};
use log::LevelFilter;

const DEFAULT_CONFIG_LOCATION: &str = "config.toml";

async fn fetch_remote_file(url: &String) -> anyhow::Result<RemoteConfigure> {
    let client = reqwest::ClientBuilder::new().build().unwrap();
    let ret = client
        .get(url)
        .send()
        .await
        .map_err(|e| anyhow!("Get error while fetch remote file: {:?}", e))?;

    let txt = ret
        .text()
        .await
        .map_err(|e| anyhow!("Get error while obtain text: {:?}", e))?;

    Ok(serde_yaml::from_str(txt.as_str())
        .map_err(|e| anyhow!("Got error while decode remote file: {:?}", e))?)
}

async fn async_main(subscribe_url: String, configure_file: String) -> anyhow::Result<()> {
    fetch_remote_file(&subscribe_url).await?;
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let matches = command!()
        .args(&[
            arg!(<url> "Remote subscribe link"),
            arg!(--config [configure_file]"Specify configure location"),
        ])
        .get_matches();

    env_logger::Builder::from_default_env()
        .filter_module("rustls", LevelFilter::Warn)
        .filter_module("reqwest", LevelFilter::Warn)
        .init();

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async_main(
            matches.get_one::<String>("url").unwrap().to_string(),
            matches
                .get_one("config")
                .map(|s: &String| s.to_string())
                .unwrap_or_else(|| DEFAULT_CONFIG_LOCATION.to_string()),
        ))
}
