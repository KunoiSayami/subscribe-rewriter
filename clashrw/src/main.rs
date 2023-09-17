mod cache;
mod file_watcher;
mod parser;
mod web;

use crate::file_watcher::FileWatchDog;
use crate::parser::{Configure, ProxyGroup, RemoteConfigure, ShareConfig, UpdateConfigureEvent};
use crate::web::get;
use anyhow::anyhow;
use axum::http::StatusCode;
use axum::{Json, Router};
use clap::{arg, command};
use log::{info, warn, LevelFilter};
use once_cell::sync::OnceCell;
use serde_json::json;
use std::io::Write;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::{RwLock, RwLockReadGuard};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;

const DEFAULT_CONFIG_LOCATION: &str = "config.yaml";

const DEFAULT_PROXY_OR_DIRECT_NAME: &str = "Proxy or Direct";
const DEFAULT_FORCE_PROXY_OR_DIRECT_NAME: &str = "Force proxy or Direct";

const DIRECT_NAME: &str = "DIRECT";

const DEFAULT_URL_TEST_INTERVAL: u64 = 600;
const DEFAULT_SUB_PREFIX: &str = "sub";

static DISABLE_CACHE: OnceCell<bool> = OnceCell::new();
static URL_TEST_INTERVAL: OnceCell<u64> = OnceCell::new();
static SUB_PREFIX: OnceCell<String> = OnceCell::new();

fn apply_change(
    mut remote: RemoteConfigure,
    local: RwLockReadGuard<ShareConfig>,
) -> anyhow::Result<RemoteConfigure> {
    //let mut new_proxy_group_element = vec![];

    // Build new relay proxy group
    let mut new_proxy_group = vec![];

    let local_proxy_name = local
        .proxies()
        .get_vec()
        .iter()
        .map(|proxy| proxy.name().to_string())
        .collect::<Vec<_>>();

    let backup_or_direct = ProxyGroup::new_select(
        DEFAULT_FORCE_PROXY_OR_DIRECT_NAME.to_string(),
        local_proxy_name.clone(),
    );

    let proxy_or_direct = ProxyGroup::new_select(DEFAULT_PROXY_OR_DIRECT_NAME.to_string(), {
        let mut v = vec![DEFAULT_FORCE_PROXY_OR_DIRECT_NAME.to_string()];
        v.extend(local_proxy_name.into_iter());
        v.extend(local.manual_insert_proxies().iter().cloned());
        v
    })
    .insert_direct();

    new_proxy_group.extend(vec![backup_or_direct, proxy_or_direct]);

    // Build new proxy group
    //let mut proxy_group_items = vec![base_relay.name().to_string()];
    //proxy_group_items.extend(proxy_group_str);

    let real_proxy_group = remote
        .proxy_groups()
        .get_vec()
        .iter()
        .map(|element| {
            let mut ret = element.clone();

            if element.group_type().eq("select") && element.proxies().len() > 2 {
                ret.insert_to_head(DEFAULT_FORCE_PROXY_OR_DIRECT_NAME.to_string());
            }
            ret
        })
        .collect::<Vec<ProxyGroup>>();

    // Add relay to proxy group
    new_proxy_group.extend(real_proxy_group);

    remote.mut_proxy_groups().set_vec(new_proxy_group);
    let mut new_proxy_pending = local.proxies().get_vec().clone();

    new_proxy_pending.extend(
        remote
            .mut_proxies()
            .get_vec()
            .iter()
            // TODO: Should reserve empty configure
            .filter(|x| !x.password().is_empty())
            .cloned(),
    );

    remote.mut_proxies().set_vec(new_proxy_pending);

    remote.mut_rules().insert_head(local.rules().get_element());

    Ok(remote)
}

async fn async_main(
    configure_path: String,
    file_update_sender: mpsc::Sender<UpdateConfigureEvent>,
    file_update_receiver: mpsc::Receiver<UpdateConfigureEvent>,
) -> anyhow::Result<()> {
    let local_file: Configure = serde_yaml::from_str(
        tokio::fs::read_to_string(&configure_path)
            .await
            .map_err(|e| anyhow!("Got error while read local configure: {:?}", e))?
            .as_str(),
    )
    .map_err(|e| anyhow!("Got error while parse local configure: {:?}", e))?;

    let redis_conn = redis::Client::open(local_file.http().redis_address())?;
    let bind = format!(
        "{}:{}",
        local_file.http().address(),
        local_file.http().port()
    );

    let arc_configure = Arc::new(RwLock::new(ShareConfig::new(local_file, redis_conn)));

    let router = Router::new()
        .route(
            &format!("/{}/:sub_id", SUB_PREFIX.get().unwrap()),
            axum::routing::get({
                let share_configure = arc_configure.clone();
                move |sub_id| get(sub_id, share_configure)
            }),
        )
        .route(
            "/",
            axum::routing::get(|| async {
                Json(json!({ "version": env!("CARGO_PKG_VERSION"), "status": 200 }))
            }),
        )
        .fallback(|| async { (StatusCode::FORBIDDEN, "403 Forbidden") })
        .layer(ServiceBuilder::new().layer(TraceLayer::new_for_http()));

    let server_handler = axum_server::Handle::new();
    let server = tokio::spawn(
        axum_server::bind(bind.parse().unwrap())
            .handle(server_handler.clone())
            .serve(router.into_make_service()),
    );

    let file_reloader = tokio::spawn(ShareConfig::configure_file_updater(
        configure_path,
        arc_configure,
        file_update_receiver,
    ));

    tokio::select! {
        _ = async {
            tokio::signal::ctrl_c().await.unwrap();
            info!("Recv Control-C send graceful shutdown command.");
            server_handler.graceful_shutdown(None);
            file_update_sender.send(UpdateConfigureEvent::Terminate).await.ok();
            tokio::signal::ctrl_c().await.unwrap();
            warn!("Force to exit!");
            std::process::exit(137)
        } => {
        },
        _ = server => {
        }
    }

    tokio::select! {
        _ = async {
            tokio::signal::ctrl_c().await.unwrap();
        } => {
            warn!("Force exit from file reloader!");
        }
        ret = file_reloader => {
            ret?;
        }
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let matches = command!()
        .args(&[
            arg!(-c --config [configure_file] "Specify configure location")
                .default_value(DEFAULT_CONFIG_LOCATION),
            arg!(--interval [url_test_interval] "Specify url test interval [default: 600]"),
            arg!(--systemd "Disable datetime output in syslog"),
            arg!(--nocache "Disable cache"),
            arg!(--prefix [prefix] "Override server default prefix")
                .default_value(DEFAULT_SUB_PREFIX),
        ])
        .get_matches();

    let mut binding = env_logger::Builder::from_default_env();
    binding
        .filter_module("rustls", LevelFilter::Warn)
        .filter_module("reqwest", LevelFilter::Warn)
        .filter_module("h2", LevelFilter::Warn);
    if matches.get_flag("systemd") {
        binding.format(|buf, record| writeln!(buf, "[{}] - {}", record.level(), record.args()));
    }
    binding.init();

    DISABLE_CACHE.set(matches.get_flag("nocache")).unwrap();
    URL_TEST_INTERVAL
        .set(
            *matches
                .get_one("interval")
                .unwrap_or(&DEFAULT_URL_TEST_INTERVAL),
        )
        .unwrap();
    SUB_PREFIX
        .set(matches.get_one::<String>("prefix").unwrap().to_string())
        .unwrap();

    let config_path = matches
        .get_one("config")
        .map(|s: &String| s.to_string())
        .unwrap_or_else(|| DEFAULT_CONFIG_LOCATION.to_string());

    let (file_update_sender, file_update_receiver) = tokio::sync::mpsc::channel(1);

    let file_watching_thread = FileWatchDog::start(config_path.clone(), file_update_sender.clone());

    let main_ret = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async_main(
            config_path,
            file_update_sender,
            file_update_receiver,
        ));

    file_watching_thread.stop();
    main_ret
}
