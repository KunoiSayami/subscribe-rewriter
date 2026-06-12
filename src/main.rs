mod cache;
mod file_watcher;
mod parser;
mod ruleset;
mod singbox;
mod web;

use crate::file_watcher::FileWatchDog;
use crate::parser::{
    Configure, Proxy, ProxyGroup, RemoteConfigure, ShareConfig, UpdateConfigureEvent,
};
use crate::web::get;
use axum::http::StatusCode;
use axum::{Extension, Json, Router};
use clap::{ArgMatches, arg, command};
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
static SHOW_CACHE: OnceLock<bool> = OnceLock::new();

pub fn get_name(value: &serde_yaml::Value) -> Option<String> {
    if let serde_yaml::Value::Mapping(map) = value
        && let serde_yaml::Value::String(s) = map.get("name")?
    {
        return Some(s.clone());
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
    let (local_file, singbox_base, singbox_bases) = Configure::load(&configure_path).await?;

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

    let arc_configure = Arc::new(RwLock::new(ShareConfig::new(
        local_file,
        singbox_base,
        singbox_bases,
        redis_conn,
    )));

    let router = Router::new()
        .route(
            &format!("/{}/{{sub_id}}", SUB_PREFIX.get().unwrap()),
            axum::routing::get(get),
        )
        .route("/rule-set/{tag}", axum::routing::get(web::get_rule_set))
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
        file_update_sender.clone(),
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

fn init_log(verbose: u8, systemd: bool) {
    let mut binding = env_logger::Builder::from_default_env();

    SHOW_CACHE.set(verbose >= 1).unwrap();

    if verbose < 2 {
        binding
            .filter_module("rustls", LevelFilter::Warn)
            .filter_module("reqwest", LevelFilter::Warn);
    }

    if verbose < 3 {
        binding
            .filter_module("h2", LevelFilter::Warn)
            .filter_module("hyper_util", LevelFilter::Warn)
            .filter_module("tower_http", LevelFilter::Warn);
    }

    if verbose < 4 {
        binding
            .filter_module("mio", LevelFilter::Warn)
            .filter_module("notify", LevelFilter::Warn)
            .filter_module("tracing", LevelFilter::Warn);
    }

    if systemd {
        binding.format(|buf, record| writeln!(buf, "[{}] - {}", record.level(), record.args()));
    }
    binding.init();
}

fn config_arg() -> clap::Arg {
    arg!(-c --config [configure_file] "Specify configure location")
        .default_value(DEFAULT_CONFIG_LOCATION)
}

fn serve_subcommand() -> clap::Command {
    clap::Command::new("serve")
        .about("Start the subscription rewriting server (default)")
        .args(&[
            config_arg(),
            arg!(--interval [url_test_interval] "Specify url test interval [default: 600]")
                .default_value(DEFAULT_URL_TEST_INTERVAL_STR.as_str())
                .value_parser(clap::value_parser!(u64)),
            arg!(--systemd "Disable datetime output in syslog"),
            arg!(--nocache "Disable cache"),
            arg!(--prefix [prefix] "Override server default prefix")
                .default_value(DEFAULT_SUB_PREFIX),
            arg!(-v --verbose ... "Show more logs"),
        ])
}

fn suggest_subcommand() -> clap::Command {
    clap::Command::new("suggest")
        .about("Analyse the config and suggest whether to use `inherit` or keep subs separate")
        .args(&[
            config_arg(),
            arg!(-o --output [output_file] "Write the modified config to this path (\"-\" for stdout)"),
        ])
}

fn run_serve(matches: &ArgMatches) -> anyhow::Result<()> {
    init_log(matches.get_count("verbose"), matches.get_flag("systemd"));

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

fn run_suggest(matches: &ArgMatches) -> anyhow::Result<()> {
    let config_path = matches
        .get_one("config")
        .map(|s: &String| s.to_string())
        .unwrap_or_else(|| DEFAULT_CONFIG_LOCATION.to_string());

    let output_path = matches.get_one::<String>("output").cloned();

    let (raw_yaml, upstreams) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let raw = Configure::load_raw_yaml(&config_path).await?;
            let ups = Configure::parse_raw_upstreams(&raw)?;
            anyhow::Ok((raw, ups))
        })?;

    let actions = suggest::analyse_and_print(&upstreams);

    if let Some(path) = output_path {
        let modified = suggest::apply_actions(raw_yaml, &actions)?;
        let yaml_str = serde_yaml::to_string(&modified)?;
        if path == "-" {
            print!("{yaml_str}");
        } else {
            std::fs::write(&path, &yaml_str)?;
            println!("Written to {path}");
        }
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let matches = command!()
        .subcommand_required(false)
        .subcommand(serve_subcommand())
        .subcommand(suggest_subcommand())
        // Legacy flat args so the binary keeps working without a subcommand.
        .args(&[
            config_arg(),
            arg!(--interval [url_test_interval] "Specify url test interval [default: 600]")
                .default_value(DEFAULT_URL_TEST_INTERVAL_STR.as_str())
                .value_parser(clap::value_parser!(u64)),
            arg!(--systemd "Disable datetime output in syslog"),
            arg!(--nocache "Disable cache"),
            arg!(--prefix [prefix] "Override server default prefix")
                .default_value(DEFAULT_SUB_PREFIX),
            arg!(-v --verbose ... "Show more logs"),
        ])
        .get_matches();

    match matches.subcommand() {
        Some(("serve", sub)) => run_serve(sub),
        Some(("suggest", sub)) => run_suggest(sub),
        _ => run_serve(&matches),
    }
}

mod suggest {
    use crate::parser::UpStream;

    /// What transformation to apply to a pair of subs in the output config.
    pub enum Action {
        /// Keep the first sub, append the second's sub_id (and aliases) to the
        /// first's alias list, and remove the second entry entirely.
        MergeAsAlias {
            keep: String,
            remove: String,
            extra_aliases: Vec<String>,
        },
        /// Rewrite the child to use `inherit:` from the parent and strip all
        /// URL fields from the child that are identical to the parent's.
        UseInherit { parent: String, child: String },
    }

    #[derive(PartialEq)]
    struct UrlSet<'a> {
        upstream: &'a str,
        raw: Option<&'a str>,
        singbox: Option<&'a str>,
        singbox_config_path: Option<&'a str>,
    }

    impl<'a> UrlSet<'a> {
        fn from(u: &'a UpStream) -> Self {
            Self {
                upstream: u.upstream(),
                raw: u.raw().map(String::as_str),
                singbox: u.singbox().map(String::as_str),
                singbox_config_path: u.singbox_config_path(),
            }
        }

        fn shares_upstream(&self, other: &UrlSet) -> bool {
            self.upstream == other.upstream
        }
    }

    fn non_url_identical(a: &UpStream, b: &UpStream) -> bool {
        format!("{:?}", a.sub_override()) == format!("{:?}", b.sub_override())
            && a.passthrough() == b.passthrough()
    }

    /// Analyse upstreams, print findings, and return the list of actions to
    /// apply when `--output` is requested.
    pub fn analyse_and_print(upstreams: &[UpStream]) -> Vec<Action> {
        // Only look at base subs (those without inherit already set).
        let bases: Vec<&UpStream> = upstreams.iter().filter(|u| u.inherit().is_none()).collect();

        let mut actions = Vec::new();
        let mut found_any = false;

        for i in 0..bases.len() {
            for j in (i + 1)..bases.len() {
                let a = bases[i];
                let b = bases[j];
                let ua = UrlSet::from(a);
                let ub = UrlSet::from(b);

                if !ua.shares_upstream(&ub) {
                    continue;
                }

                found_any = true;

                let urls_identical = ua == ub;
                let non_url_same = non_url_identical(a, b);

                if urls_identical && non_url_same {
                    println!(
                        "[alias] '{}' and '{}' are completely identical.",
                        a.sub_id(),
                        b.sub_id()
                    );
                    println!(
                        "  Suggestion: remove '{}' and add its sub_id as an alias on '{}'.",
                        b.sub_id(),
                        a.sub_id()
                    );
                    let mut extra = vec![b.sub_id().to_string()];
                    extra.extend(b.alias().iter().cloned());
                    actions.push(Action::MergeAsAlias {
                        keep: a.sub_id().to_string(),
                        remove: b.sub_id().to_string(),
                        extra_aliases: extra,
                    });
                } else if urls_identical {
                    println!(
                        "[inherit] '{}' and '{}' share all URL fields but differ in non-URL fields.",
                        a.sub_id(),
                        b.sub_id()
                    );
                    println!(
                        "  Suggestion: keep '{}' as the base and rewrite '{}' to use `inherit: {}`.",
                        a.sub_id(),
                        b.sub_id(),
                        a.sub_id()
                    );
                    print_non_url_diffs(a, b);
                    actions.push(Action::UseInherit {
                        parent: a.sub_id().to_string(),
                        child: b.sub_id().to_string(),
                    });
                } else {
                    println!(
                        "[inherit] '{}' and '{}' share `upstream` but differ in optional URL fields.",
                        a.sub_id(),
                        b.sub_id()
                    );
                    println!(
                        "  Suggestion: keep '{}' as the base and rewrite '{}' to use `inherit: {}`,",
                        a.sub_id(),
                        b.sub_id(),
                        a.sub_id()
                    );
                    println!("  then explicitly set the differing URL fields on the child.");
                    print_url_diffs(&ua, &ub);
                    print_non_url_diffs(a, b);
                    actions.push(Action::UseInherit {
                        parent: a.sub_id().to_string(),
                        child: b.sub_id().to_string(),
                    });
                }
                println!();
            }
        }

        if !found_any {
            println!(
                "No overlapping upstream URLs found. All subs look independent — no changes needed."
            );
        }

        actions
    }

    /// Apply the suggested actions to the raw YAML value and return the result.
    ///
    /// For `MergeAsAlias`: appends extra aliases to the `keep` entry's `alias`
    /// list and removes the `remove` entry from the `upstream` sequence.
    ///
    /// For `UseInherit`: adds `inherit: <parent>` to the child entry and
    /// removes URL fields on the child that are identical to the parent's.
    pub fn apply_actions(
        mut raw: serde_yaml::Value,
        actions: &[Action],
    ) -> anyhow::Result<serde_yaml::Value> {
        let upstream_key = serde_yaml::Value::String("upstream".into());
        let Some(serde_yaml::Value::Sequence(seq)) = raw.get_mut(&upstream_key) else {
            anyhow::bail!("missing `upstream` sequence in config");
        };

        for action in actions {
            match action {
                Action::MergeAsAlias {
                    keep,
                    remove,
                    extra_aliases,
                } => {
                    // Append extra aliases to the `keep` entry.
                    if let Some(entry) = seq
                        .iter_mut()
                        .find(|e| e.get("sub_id").and_then(|v| v.as_str()) == Some(keep.as_str()))
                    {
                        let alias_key = serde_yaml::Value::String("alias".into());
                        let alias_list = entry
                            .as_mapping_mut()
                            .and_then(|m| m.get_mut(&alias_key))
                            .and_then(|v| v.as_sequence_mut());

                        if let Some(list) = alias_list {
                            for al in extra_aliases {
                                list.push(serde_yaml::Value::String(al.clone()));
                            }
                        } else if let Some(map) = entry.as_mapping_mut() {
                            map.insert(
                                alias_key,
                                serde_yaml::Value::Sequence(
                                    extra_aliases
                                        .iter()
                                        .map(|s| serde_yaml::Value::String(s.clone()))
                                        .collect(),
                                ),
                            );
                        }
                    }
                    // Remove the `remove` entry.
                    seq.retain(|e| {
                        e.get("sub_id").and_then(|v| v.as_str()) != Some(remove.as_str())
                    });
                }

                Action::UseInherit { parent, child } => {
                    // Collect parent's URL field values for comparison.
                    let parent_urls: std::collections::HashMap<String, serde_yaml::Value> = seq
                        .iter()
                        .find(|e| e.get("sub_id").and_then(|v| v.as_str()) == Some(parent.as_str()))
                        .and_then(|e| e.as_mapping())
                        .map(|m| {
                            URL_FIELDS
                                .iter()
                                .filter_map(|&k| {
                                    let key = serde_yaml::Value::String(k.into());
                                    m.get(&key).map(|v| (k.to_string(), v.clone()))
                                })
                                .collect()
                        })
                        .unwrap_or_default();

                    if let Some(entry) = seq
                        .iter_mut()
                        .find(|e| e.get("sub_id").and_then(|v| v.as_str()) == Some(child.as_str()))
                    {
                        if let Some(map) = entry.as_mapping_mut() {
                            // Add inherit key.
                            map.insert(
                                serde_yaml::Value::String("inherit".into()),
                                serde_yaml::Value::String(parent.clone()),
                            );
                            // Remove URL fields on the child that match the parent's.
                            for field in URL_FIELDS {
                                let key = serde_yaml::Value::String((*field).into());
                                let child_val = map.get(&key).cloned();
                                let parent_val = parent_urls.get(*field);
                                if child_val.as_ref() == parent_val {
                                    map.remove(&key);
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(raw)
    }

    const URL_FIELDS: &[&str] = &["upstream", "raw", "singbox", "singbox_config_path"];

    fn print_url_diffs(a: &UrlSet, b: &UrlSet) {
        if a.raw != b.raw {
            println!("  raw:                 {:?} vs {:?}", a.raw, b.raw);
        }
        if a.singbox != b.singbox {
            println!("  singbox:             {:?} vs {:?}", a.singbox, b.singbox);
        }
        if a.singbox_config_path != b.singbox_config_path {
            println!(
                "  singbox_config_path: {:?} vs {:?}",
                a.singbox_config_path, b.singbox_config_path
            );
        }
    }

    fn print_non_url_diffs(a: &UpStream, b: &UpStream) {
        match (a.sub_override(), b.sub_override()) {
            (None, Some(_)) => println!(
                "  override: '{}' has none; '{}' has one",
                a.sub_id(),
                b.sub_id()
            ),
            (Some(_), None) => println!(
                "  override: '{}' has one; '{}' has none",
                a.sub_id(),
                b.sub_id()
            ),
            (Some(oa), Some(ob)) => {
                if format!("{oa:?}") != format!("{ob:?}") {
                    println!("  override values differ: {oa:?} vs {ob:?}");
                }
            }
            (None, None) => {}
        }
        if a.passthrough() != b.passthrough() {
            println!("  passthrough: {} vs {}", a.passthrough(), b.passthrough());
        }
    }
}
