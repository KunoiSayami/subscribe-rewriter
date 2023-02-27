mod cache;
mod parser;
mod web;

use crate::parser::{
    default_test_url, Configure, ProxyGroup, RemoteConfigure, ShareConfig, UpdateConfigureEvent,
};
use crate::web::get;
use anyhow::anyhow;
use axum::http::StatusCode;
use axum::{Json, Router};
use clap::{arg, command};
use log::{debug, error, info, warn, LevelFilter};
use notify::{RecursiveMode, Watcher};
use once_cell::sync::OnceCell;
use serde_json::json;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, RwLockReadGuard};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;

const DEFAULT_CONFIG_LOCATION: &str = "config.yaml";
const DEFAULT_RELAY_SELECTOR_NAME: &str = "Relay selector";
const DEFAULT_FORCE_RELAY_SELECTOR_NAME: &str = "Force relay selector";
const DEFAULT_RELAY_BACKEND_SELECTOR_NAME: &str = "Relay backend selector";
const DEFAULT_RELAY_NAME: &str = "Use Relay";
const DEFAULT_FORCE_RELAY_NAME: &str = "Force use Relay";
const DEFAULT_BACKEND_AUTO_OR_MANUAL_SELECTOR_NAME: &str = "Backend Manual or Auto";
const DEFAULT_CHOOSE_AUTO_PROFILE_NAME: &str = "Manual or Auto";
const DEFAULT_URL_TEST_PROFILE_NAME: &str = "Auto select";
const DEFAULT_RELAY_URL_TEST_PROFILE_NAME: &str = "Relay auto select";
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

    // Filter interest proxy to relay
    let interest_proxy = remote
        .proxy_groups()
        .get_vec()
        .iter()
        // Get first proxies length > 2
        .find(|x| x.proxies().len() > 2)
        // Make Option to Result
        .ok_or_else(|| anyhow!("Group is smaller then excepted."))?
        .proxies()
        .iter()
        .filter(|x| {
            local
                .keyword()
                .accepted()
                .iter()
                .any(|keyword| x.contains(keyword))
        })
        .cloned()
        .collect::<Vec<_>>();

    // Build new relay proxy group
    let mut new_proxy_group = vec![];

    let local_proxy_name = local
        .proxies()
        .get_vec()
        .iter()
        .map(|proxy| proxy.name().to_string())
        .collect::<Vec<_>>();

    let relay_selector = ProxyGroup::new_select(
        DEFAULT_RELAY_SELECTOR_NAME.to_string(),
        local_proxy_name.clone(),
    )
    .insert_direct();

    let force_relay_selector = ProxyGroup::new_select(
        DEFAULT_FORCE_RELAY_SELECTOR_NAME.to_string(),
        local_proxy_name,
    );

    let relay_backend_selector = ProxyGroup::new_select(
        DEFAULT_RELAY_BACKEND_SELECTOR_NAME.to_string(),
        interest_proxy.iter().map(|x| x.to_string()).collect(),
    );

    let url_test_proxies = ProxyGroup::new_url_test(
        DEFAULT_URL_TEST_PROFILE_NAME.to_string(),
        interest_proxy.clone(),
        default_test_url(),
    );

    let relay_url_test_proxies = ProxyGroup::new_url_test(
        DEFAULT_RELAY_URL_TEST_PROFILE_NAME.to_string(),
        interest_proxy,
        local.test_url(),
    );

    let backend_manual_or_auto_selector = ProxyGroup::new_select(
        DEFAULT_BACKEND_AUTO_OR_MANUAL_SELECTOR_NAME.to_string(),
        vec![
            DEFAULT_RELAY_BACKEND_SELECTOR_NAME.to_string(),
            DEFAULT_RELAY_URL_TEST_PROFILE_NAME.to_string(),
        ],
    );

    let manual_or_auto_selector = ProxyGroup::new_select(
        DEFAULT_CHOOSE_AUTO_PROFILE_NAME.to_string(),
        vec![
            DEFAULT_BACKEND_AUTO_OR_MANUAL_SELECTOR_NAME.to_string(),
            DEFAULT_RELAY_URL_TEST_PROFILE_NAME.to_string(),
        ],
    );

    let base_relay = ProxyGroup::new_relay(
        DEFAULT_RELAY_NAME.to_string(),
        DEFAULT_CHOOSE_AUTO_PROFILE_NAME.to_string(),
        DEFAULT_RELAY_SELECTOR_NAME.to_string(),
    );

    let base_force_relay = ProxyGroup::new_relay(
        DEFAULT_FORCE_RELAY_NAME.to_string(),
        DEFAULT_CHOOSE_AUTO_PROFILE_NAME.to_string(),
        DEFAULT_FORCE_RELAY_SELECTOR_NAME.to_string(),
    );

    new_proxy_group.extend(vec![
        force_relay_selector,
        url_test_proxies,
        relay_url_test_proxies,
        relay_selector,
        relay_backend_selector,
        backend_manual_or_auto_selector,
        manual_or_auto_selector,
        base_relay.clone(),
        base_force_relay,
    ]);

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
                ret.insert_to_head(DEFAULT_BACKEND_AUTO_OR_MANUAL_SELECTOR_NAME.to_string());
                ret.insert_to_head(base_relay.name().to_string());
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

async fn configure_file_updater(
    configure_path: String,
    configure_file: Arc<RwLock<ShareConfig>>,
    mut receiver: tokio::sync::mpsc::Receiver<UpdateConfigureEvent>,
) -> () {
    while let Some(event) = receiver.recv().await {
        match event {
            UpdateConfigureEvent::NeedUpdate => {
                let mut cfg = configure_file.write().await;
                if let Some(new_cfg) = tokio::fs::read_to_string(&configure_path)
                    .await
                    .map_err(|e| {
                        error!(
                            "[Can be safely ignored] Unable to read configure file: {:?}",
                            e
                        )
                    })
                    .ok()
                    .map(|s| {
                        serde_yaml::from_str::<Configure>(s.as_str())
                            .map_err(|e| {
                                error!(
                                    "[Can be safely ignored] Unable to parse local configure: {:?}",
                                    e
                                )
                            })
                            .ok()
                    })
                    .flatten()
                {
                    cfg.update(new_cfg);
                    info!("Reloaded local configure file.");
                };
            }
            UpdateConfigureEvent::Terminate => break,
        }
    }
    debug!("File updater exited!");
}

async fn async_main(
    configure_path: String,
    file_update_sender: tokio::sync::mpsc::Sender<UpdateConfigureEvent>,
    file_update_receiver: tokio::sync::mpsc::Receiver<UpdateConfigureEvent>,
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
        _ = configure_file_updater(configure_path, arc_configure, file_update_receiver) => {

        }
        _ = server => {
        }
    }

    Ok(())
}

async fn send_event(sender: tokio::sync::mpsc::Sender<UpdateConfigureEvent>) -> Option<()> {
    sender
        .send(UpdateConfigureEvent::NeedUpdate)
        .await
        .map_err(|_| {
            error!("[Can be safely ignored] Got error while sending event to update thread")
        })
        .ok()
}

fn file_watching(
    file: String,
    stop_signal_channel: oneshot::Receiver<bool>,
    sender: tokio::sync::mpsc::Sender<UpdateConfigureEvent>,
) -> Option<()> {
    let mut watcher = notify::recommended_watcher(move |res| match res {
        Ok(_event) => {
            tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .build()
                .unwrap()
                .block_on(send_event(sender.clone()));
        }
        Err(e) => {
            error!(
                "[Can be safely ignored] Got error while watching file {:?}",
                e
            )
        }
    })
    .map_err(|e| error!("[Can be safely ignored] Can't start watcher {:?}", e))
    .ok()?;

    let path = PathBuf::from(file);

    watcher
        .watch(&path, RecursiveMode::NonRecursive)
        .map_err(|e| error!("[Can be safely ignored] Unable to watch file: {:?}", e))
        .ok()?;

    stop_signal_channel
        .recv()
        .map_err(|e| {
            error!(
                "[Can be safely ignored] Got error while poll oneshot event: {:?}",
                e
            )
        })
        .ok();

    watcher
        .unwatch(&path)
        .map_err(|e| error!("[Can be safely ignored] Unable to unwatch file: {:?}", e))
        .ok()?;

    debug!("File watcher exited!");
    Some(())
}

fn main() -> anyhow::Result<()> {
    let matches = command!()
        .args(&[
            arg!(--nocache "Disable cache"),
            arg!(--config [configure_file] "Specify configure location (Default: ./config.yaml)"),
            arg!(--interval [url_test_interval] "Specify url test interval (Default: 600)"),
            arg!(--systemd "Disable log output in systemd"),
            arg!(--prefix [prefix] "Override server default prefix"),
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
        .set(
            matches
                .get_one("prefix")
                .unwrap_or(&DEFAULT_SUB_PREFIX.to_string())
                .to_string(),
        )
        .unwrap();

    let config_path = matches
        .get_one("config")
        .map(|s: &String| s.to_string())
        .unwrap_or_else(|| DEFAULT_CONFIG_LOCATION.to_string());
    let alt_configure_path = config_path.clone();

    let (watcher_stop_signal, receiver) = oneshot::channel();
    let (file_update_sender, file_update_receiver) = tokio::sync::mpsc::channel(1);

    let file_watching_thread = {
        let sender = file_update_sender.clone();
        std::thread::spawn(|| file_watching(alt_configure_path, receiver, sender))
    };

    let main_ret = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async_main(
            config_path,
            file_update_sender,
            file_update_receiver,
        ));

    if !file_watching_thread.is_finished() {
        let ret = watcher_stop_signal.send(true).map_err(|e| {
            error!(
                "[Can be safely ignored] Unable send terminate signal to file watcher thread: {:?}",
                e
            )
        });
        if ret.is_err() {
            return main_ret;
        }
        std::thread::spawn(move || {
            for _ in 0..5 {
                std::thread::sleep(Duration::from_millis(100));
                if file_watching_thread.is_finished() {
                    break;
                }
            }
            if !file_watching_thread.is_finished() {
                warn!("[Can be safely ignored] File watching not finished yet.");
            }
        })
        .join()
        .unwrap();
    }

    main_ret
}
