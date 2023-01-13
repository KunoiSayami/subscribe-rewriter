mod parser;

use crate::parser::{Configure, ProxyGroup, RemoteConfigure};
use anyhow::anyhow;
use clap::{arg, command};
use log::LevelFilter;
use tokio::io::AsyncWriteExt;

const DEFAULT_CONFIG_LOCATION: &str = "config.yaml";

async fn fetch_remote_file(url: &String) -> anyhow::Result<(RemoteConfigure, String)> {
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

    let mut additional = txt
        .split('\n')
        .filter(|s| s.starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    additional.push('\n');

    let mut ret = serde_yaml::from_str::<RemoteConfigure>(txt.as_str())
        .map_err(|e| anyhow!("Got error while decode remote file: {:?}", e))?;

    ret.optimize();

    Ok((ret, additional))
}

fn apply_change(mut remote: RemoteConfigure, local: Configure) -> anyhow::Result<RemoteConfigure> {
    //let mut new_proxy_group_element = vec![];

    let proxy_group_str = remote
        .proxy_groups()
        .get_vec()
        .iter()
        // Get first proxies length > 2
        .filter(|x| x.proxies().len() > 2)
        .next()
        // Make Option to Result
        .ok_or_else(|| anyhow!("Group is smaller then excepted."))?
        .proxies()
        .iter()
        // Keyword filter
        .filter(|x| {
            !local
                .keyword()
                .filter()
                .iter()
                .any(|keyword| x.contains(keyword))
        })
        .map(|item| item.clone())
        .collect::<Vec<_>>();

    // Filter interest proxy to relay
    let interest_proxy = proxy_group_str
        .iter()
        .filter(|x| {
            local
                .keyword()
                .accepted()
                .iter()
                .any(|keyword| x.contains(keyword))
        })
        .collect::<Vec<_>>();

    // Build new relay proxy group
    let mut new_proxy_group = vec![];
    for proxy in local.proxies().get_vec() {
        for original_proxy in &interest_proxy {
            new_proxy_group.push(ProxyGroup::new_relay(
                proxy.name().to_string(),
                original_proxy.to_string(),
            ));
        }
    }

    // Build new proxy group
    let mut proxy_group_items = new_proxy_group
        .iter()
        .map(|proxy| proxy.name().to_string())
        .collect::<Vec<String>>();
    proxy_group_items.extend(proxy_group_str);

    let real_proxy_group = remote
        .proxy_groups()
        .get_vec()
        .iter()
        .map(|element| {
            let mut ret = element.clone();

            if element.group_type().eq("select") && element.proxies().len() > 2 {
                ret.set_proxies(proxy_group_items.clone())
            }
            ret
        })
        .collect::<Vec<ProxyGroup>>();

    // Add relay to proxy group
    new_proxy_group.extend(real_proxy_group);

    remote.mut_proxy_groups().set_vec(new_proxy_group);
    remote
        .mut_proxies()
        .insert_head(local.proxies().get_vec().clone());

    Ok(remote)
}

async fn output(
    path: String,
    additional_msg: String,
    configure_file: RemoteConfigure,
) -> anyhow::Result<()> {
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .await
        .map_err(|e| anyhow!("Got error while open file: {:?}", e))?;
    let s = serde_yaml::to_string(&configure_file)
        .map_err(|e| anyhow!("Got error while output configure file, {:?}", e))?;
    file.write_all(additional_msg.as_bytes())
        .await
        .map_err(|e| anyhow!("Got error while write additional messages: {:?}", e))?;
    file.write_all(s.as_bytes())
        .await
        .map_err(|e| anyhow!("Got error while write file: {:?}", e))?;
    Ok(())
}

async fn async_main(subscribe_url: String, configure_file: String) -> anyhow::Result<()> {
    let local_file = serde_yaml::from_str(
        tokio::fs::read_to_string(configure_file)
            .await
            .map_err(|e| anyhow!("Got error while read local configure: {:?}", e))?
            .as_str(),
    )
    .map_err(|e| anyhow!("Got error while parse local configure: {:?}", e))?;
    let (remote_file, additional_message) = fetch_remote_file(&subscribe_url).await?;
    let result_configure = apply_change(remote_file, local_file)?;
    output(
        "output.yaml".to_string(),
        additional_message,
        result_configure,
    )
    .await?;
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let matches = command!()
        .args(&[
            arg!(<url> "Remote subscribe link"),
            arg!(--config [configure_file] "Specify configure location"),
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
