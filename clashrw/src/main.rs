mod cache;
mod file_watcher;
mod parser;
mod web;

use crate::file_watcher::FileWatchDog;
use crate::parser::{
    Configure, Proxy, ProxyGroup, RemoteConfigure, ShareConfig, UpdateConfigureEvent,
};
use crate::web::get;
use axum::http::StatusCode;
use axum::{Extension, Json, Router};
use clap::{arg, command};
use log::{LevelFilter, debug, info, warn};
use serde_json::json;
use std::io::Write;
use std::string::ToString;
use std::sync::{Arc, LazyLock, OnceLock};
use tokio::sync::mpsc;
use tokio::sync::{RwLock, RwLockReadGuard};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;

const DEFAULT_CONFIG_LOCATION: &str = "config.yaml";

const DEFAULT_PROXY_OR_DIRECT_NAME: &str = "Proxy or Direct";
const DEFAULT_FORCE_PROXY_OR_DIRECT_NAME: &str = "Force proxy or Direct";

const DIRECT_NAME: &str = "DIRECT";

const DEFAULT_URL_TEST_INTERVAL: u64 = 600;
static DEFAULT_URL_TEST_INTERVAL_STR: LazyLock<String> =
    LazyLock::new(|| DEFAULT_URL_TEST_INTERVAL.to_string());
const DEFAULT_SUB_PREFIX: &str = "sub";

static DISABLE_CACHE: OnceLock<bool> = OnceLock::new();
static URL_TEST_INTERVAL: OnceLock<u64> = OnceLock::new();
static SUB_PREFIX: OnceLock<String> = OnceLock::new();

pub fn get_name(value: &serde_yaml::Value) -> Option<String> {
    if let serde_yaml::Value::Mapping(map) = value {
        if let serde_yaml::Value::String(s) = map.get("name")? {
            return Some(s.clone());
        }
    }
    None
}

fn apply_change(
    sub_id: &str,
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
        .map(|proxy| get_name(proxy).unwrap())
        .collect::<Vec<_>>();

    let backup_or_direct = ProxyGroup::new_select(
        DEFAULT_FORCE_PROXY_OR_DIRECT_NAME.to_string(),
        local_proxy_name.clone(),
    );

    let mut last_proxies = None;

    let proxy_or_direct = ProxyGroup::new_select(DEFAULT_PROXY_OR_DIRECT_NAME.to_string(), {
        let mut v = vec![DEFAULT_FORCE_PROXY_OR_DIRECT_NAME.to_string()];
        v.extend(local_proxy_name);
        for proxy in local.manual_insert_proxies().iter() {
            if remote
                .proxy_groups()
                .get_vec()
                .iter()
                .any(|p| p.name().eq(proxy))
            {
                v.push(proxy.clone());
                last_proxies.replace(proxy.clone());
            }
        }
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

            if element.group_type().eq("select") && element.proxies().len() > 4 {
                ret.insert(1, DEFAULT_FORCE_PROXY_OR_DIRECT_NAME.to_string());
            }
            ret
        })
        .collect::<Vec<ProxyGroup>>();

    // Add relay to proxy group
    new_proxy_group.extend(real_proxy_group);

    // At least have two configure
    let last2 = new_proxy_group.len() - 1;
    let mut replaced_relay = 0;
    let mut additional_groups = local.groups().clone();
    let sub_id = sub_id.to_string();
    additional_groups.retain(|group| {
        if group.not_apply_to().contains(&sub_id) {
            return false;
        }
        if !group.apply_to().is_empty() {
            return group.apply_to().contains(&sub_id);
        }
        true
    });

    // Find additional group if there is a relay group with <PlaceHold> need to fill
    if let Some(ref replace_target) = last_proxies {
        for group in additional_groups.iter_mut() {
            for proxy in group.proxies_mut() {
                if proxy == "<PlaceHold>" {
                    *proxy = replace_target.clone();
                    replaced_relay += 1;
                }
            }
        }
    } else {
        log::warn!("Find <PlaceHold> relay group, but target outbound not found");
    }

    new_proxy_group.splice(last2..last2, additional_groups);
    if replaced_relay > 0 {
        log::debug!("Replaced {replaced_relay} relay");
    }

    remote.mut_proxy_groups().set_vec(new_proxy_group);
    let mut new_proxy_pending = local.proxies().get_vec().clone();

    if let Some(ref replace_target) = last_proxies {
        for proxy in &mut new_proxy_pending {
            Proxy::replace_dialer_proxy(proxy, replace_target);
        }
    }

    new_proxy_pending.extend(
        remote
            .mut_proxies()
            .get_vec()
            .iter()
            // TODO: Should reserve empty configure
            .filter(|x| Proxy::is_empty_password((*x).clone()).is_none())
            .cloned(),
    );

    remote.mut_proxies().set_vec(new_proxy_pending);

    remote.mut_rules().insert_head(local.rules().get_element());

    remote.normalize();

    Ok(remote)
}

async fn async_main(
    configure_path: String,
    file_update_sender: mpsc::Sender<UpdateConfigureEvent>,
    file_update_receiver: mpsc::Receiver<UpdateConfigureEvent>,
) -> anyhow::Result<()> {
    let local_file = Configure::load(&configure_path).await?;

    let redis_conn = redis::Client::open(local_file.http().redis_address())?;
    let bind = format!(
        "{}:{}",
        local_file.http().address(),
        local_file.http().port()
    );
    debug!(
        "Listen on {}:{}",
        local_file.http().address(),
        local_file.http().port()
    );

    let arc_configure = Arc::new(RwLock::new(ShareConfig::new(local_file, redis_conn)));

    let router = Router::new()
        .route(
            &format!("/{}/{{sub_id}}", SUB_PREFIX.get().unwrap()),
            axum::routing::get(get),
        )
        .route(
            "/",
            axum::routing::get(|| async {
                Json(json!({ "version": env!("CARGO_PKG_VERSION"), "status": 200 }))
            }),
        )
        .fallback(|| async { (StatusCode::FORBIDDEN, "403 Forbidden") })
        .layer(Extension(arc_configure.clone()))
        .layer(ServiceBuilder::new().layer(TraceLayer::new_for_http()));

    let server_handler = axum_server::Handle::<std::net::SocketAddr>::new();
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
            warn!("Force exit from file reload-er!");
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
            arg!(--interval [url_test_interval] "Specify url test interval [default: 600]")
                .default_value(DEFAULT_URL_TEST_INTERVAL_STR.as_str())
                .value_parser(clap::value_parser!(u64)),
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
        .set(*matches.get_one("interval").unwrap())
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
