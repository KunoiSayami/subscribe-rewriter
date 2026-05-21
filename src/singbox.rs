use serde_json::{Value, json};
use std::collections::HashMap;

// ── Clash YAML proxy parser ───────────────────────────────────────────────────

fn str_field<'a>(v: &'a serde_yaml::Value, key: &str) -> &'a str {
    v[key].as_str().unwrap_or("")
}

fn bool_field(v: &serde_yaml::Value, key: &str) -> bool {
    v[key].as_bool().unwrap_or(false)
}

fn u16_field(v: &serde_yaml::Value, key: &str) -> u16 {
    v[key].as_u64().unwrap_or(0) as u16
}

fn apply_detour(out: &mut Value, v: &serde_yaml::Value, resolved: Option<&str>) {
    let dp = str_field(v, "dialer-proxy");
    if dp.is_empty() {
        return;
    }
    let detour = if dp == "<PlaceHold>" {
        match resolved {
            Some(t) => t,
            None => return,
        }
    } else {
        dp
    };
    out["detour"] = json!(detour);
}

fn build_shadowsocks_clash(v: &serde_yaml::Value, resolved_detour: Option<&str>) -> Option<Value> {
    let tag = str_field(v, "name");
    let server = str_field(v, "server");
    let port = u16_field(v, "port");
    let method = str_field(v, "cipher");
    let password = str_field(v, "password");
    if tag.is_empty() || server.is_empty() || port == 0 {
        return None;
    }
    let mut out = json!({
        "type": "shadowsocks",
        "tag": tag,
        "server": server,
        "server_port": port,
        "method": method,
        "password": password,
    });
    if let Some(plugin) = v["plugin"].as_str() {
        if !plugin.is_empty() {
            out["plugin"] = json!(plugin);
            if let Some(opts) = v["plugin-opts"].as_str() {
                out["plugin_opts"] = json!(opts);
            }
        }
    }
    apply_detour(&mut out, v, resolved_detour);
    Some(out)
}

fn build_vmess_clash(v: &serde_yaml::Value, resolved_detour: Option<&str>) -> Option<Value> {
    let tag = str_field(v, "name");
    let server = str_field(v, "server");
    let port = u16_field(v, "port");
    let uuid = str_field(v, "uuid");
    let cipher = str_field(v, "cipher");
    let alter_id = v["alterId"].as_u64().unwrap_or(0);
    if tag.is_empty() || server.is_empty() || port == 0 {
        return None;
    }
    let security = if cipher.is_empty() { "auto" } else { cipher };
    let mut out = json!({
        "type": "vmess",
        "tag": tag,
        "server": server,
        "server_port": port,
        "uuid": uuid,
        "security": security,
        "alter_id": alter_id,
    });
    if bool_field(v, "tls") {
        let sni = str_field(v, "servername");
        let skip_cert = bool_field(v, "skip-cert-verify");
        out["tls"] = tls_object(
            if sni.is_empty() { None } else { Some(sni) },
            skip_cert,
            None,
        );
    }
    apply_detour(&mut out, v, resolved_detour);
    Some(out)
}

fn parse_clash_proxy(v: &serde_yaml::Value, resolved_detour: Option<&str>) -> Option<Value> {
    match str_field(v, "type") {
        "ss" => build_shadowsocks_clash(v, resolved_detour),
        "vmess" => build_vmess_clash(v, resolved_detour),
        "trojan" => {
            let tag = str_field(v, "name");
            let server = str_field(v, "server");
            let port = u16_field(v, "port");
            let password = str_field(v, "password");
            if tag.is_empty() || server.is_empty() || port == 0 {
                return None;
            }
            let sni = str_field(v, "sni");
            let skip_cert = bool_field(v, "skip-cert-verify");
            let mut out = json!({
                "type": "trojan",
                "tag": tag,
                "server": server,
                "server_port": port,
                "password": password,
                "tls": tls_object(if sni.is_empty() { None } else { Some(sni) }, skip_cert, None),
            });
            apply_detour(&mut out, v, resolved_detour);
            Some(out)
        }
        _ => None,
    }
}

// ── Surge-line key=value parser ───────────────────────────────────────────────

fn parse_kv(line: &str) -> HashMap<&str, &str> {
    let mut map = HashMap::new();
    for part in line.split(',') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            map.insert(k.trim(), v.trim());
        }
    }
    map
}

/// Parse a single Surge proxy line into a sing-box outbound `Value`.
/// Returns `None` for unsupported or malformed lines.
fn parse_line(line: &str) -> Option<Value> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    // format: <type>=<host>:<port>, key=value, ..., tag=<name>
    let (type_part, rest) = line.split_once('=')?;
    let proto = type_part.trim();

    // First token before the first comma is host:port
    let (addr_part, kv_part) = rest.split_once(',').unwrap_or((rest, ""));
    let addr_part = addr_part.trim();
    let (host, port_str) = addr_part.split_once(':')?;
    let port: u16 = port_str.parse().ok()?;

    // Build a kv map from the remaining comma-separated fields
    // We re-parse the whole rest (including addr) via split, skipping the first token
    let all_kv_str = format!("dummy={addr_part},{kv_part}");
    let kv = parse_kv(&all_kv_str);

    let tag = kv.get("tag").copied().unwrap_or("").to_string();
    let password = kv.get("password").copied().unwrap_or("").to_string();

    match proto {
        "trojan" => Some(build_trojan(host, port, &password, &tag, &kv)),
        "vless" => Some(build_vless(host, port, &password, &tag, &kv)),
        "anytls" => Some(build_anytls(host, port, &password, &tag, &kv)),
        _ => None,
    }
}

fn tls_object(server_name: Option<&str>, insecure: bool, reality: Option<Value>) -> Value {
    let mut tls = json!({
        "enabled": true,
    });
    if let Some(sni) = server_name {
        tls["server_name"] = json!(sni);
    }
    if insecure {
        tls["insecure"] = json!(true);
    }
    if let Some(r) = reality {
        tls["reality"] = r;
    }
    tls
}

fn build_trojan(
    host: &str,
    port: u16,
    password: &str,
    tag: &str,
    kv: &HashMap<&str, &str>,
) -> Value {
    let sni = kv.get("tls-host").copied();
    let insecure = kv
        .get("tls-verification")
        .map(|v| v.eq_ignore_ascii_case("false"))
        .unwrap_or(false);

    json!({
        "type": "trojan",
        "tag": tag,
        "server": host,
        "server_port": port,
        "password": password,
        "tls": tls_object(sni, insecure, None),
    })
}

fn build_vless(host: &str, port: u16, uuid: &str, tag: &str, kv: &HashMap<&str, &str>) -> Value {
    let sni = kv.get("obfs-host").copied();
    let flow = kv.get("vless-flow").copied().unwrap_or("");

    // Reality TLS
    let reality = if kv.get("obfs").copied() == Some("over-tls")
        && kv.contains_key("reality-base64-pubkey")
    {
        let pub_key = kv.get("reality-base64-pubkey").copied().unwrap_or("");
        let short_id = kv.get("reality-hex-shortid").copied().unwrap_or("");
        Some(json!({
            "enabled": true,
            "public_key": pub_key,
            "short_id": short_id,
        }))
    } else {
        None
    };

    let mut tls = tls_object(sni, false, reality);
    if tls["reality"]["enabled"].as_bool() == Some(true) {
        tls["utls"] = json!({"enabled": true, "fingerprint": "chrome"});
    }
    let tls = tls;

    let mut out = json!({
        "type": "vless",
        "tag": tag,
        "server": host,
        "server_port": port,
        "uuid": uuid,
        "tls": tls,
    });
    if !flow.is_empty() {
        out["flow"] = json!(flow);
    }
    out
}

fn build_anytls(
    host: &str,
    port: u16,
    password: &str,
    tag: &str,
    kv: &HashMap<&str, &str>,
) -> Value {
    let sni = kv.get("tls-host").copied();
    let insecure = kv
        .get("tls-verification")
        .map(|v| v.eq_ignore_ascii_case("false"))
        .unwrap_or(false);

    json!({
        "type": "anytls",
        "tag": tag,
        "server": host,
        "server_port": port,
        "password": password,
        "tls": tls_object(sni, insecure, None),
    })
}

// ── Public API ────────────────────────────────────────────────────────────────

fn tag_of(v: &Value) -> Option<&str> {
    v["tag"].as_str()
}

fn type_of(v: &Value) -> Option<&str> {
    v["type"].as_str()
}

/// Return true if `tag` contains any `|`-separated keyword from `pattern`.
fn tag_matches_pattern(tag: &str, pattern: &str) -> bool {
    pattern.split('|').any(|kw| tag.contains(kw))
}

/// Apply a `filter` array to `proxy_tags`, returning the surviving tags.
/// Each rule has `"action": "include"|"exclude"` and
/// `"keywords": ["pat1|pat2", ...]` where each element is a `|`-joined pattern.
fn apply_filter(proxy_tags: &[String], filter: &[Value]) -> Vec<String> {
    let mut tags: Vec<String> = proxy_tags.to_vec();
    for rule in filter {
        let action = rule["action"].as_str().unwrap_or("");
        let keywords: Vec<&str> = rule["keywords"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|k| k.as_str()).collect())
            .unwrap_or_default();

        tags = tags
            .into_iter()
            .filter(|tag| {
                let matched = keywords.iter().any(|pat| tag_matches_pattern(tag, pat));
                match action {
                    "include" => matched,
                    "exclude" => !matched,
                    _ => true,
                }
            })
            .collect();
    }
    tags
}

/// If the outbound's `outbounds` list contains `"{all}"`, `"{config_proxy}"`, or
/// `"{upstream_proxy}"`, expand them using the outbound's own `filter` rules.
/// - `{all}`: all proxy tags (config + upstream)
/// - `{config_proxy}`: only local config proxy tags
/// - `{upstream_proxy}`: only upstream subscription proxy tags (all minus config)
/// Outbounds without any placeholder are untouched.
fn expand_all(entry: &mut Value, proxy_tags: &[String], config_tags: &[String]) {
    let outbounds = match entry["outbounds"].as_array() {
        Some(a) => a,
        None => return,
    };
    let has_all = outbounds.iter().any(|v| v.as_str() == Some("{all}"));
    let has_config = outbounds
        .iter()
        .any(|v| v.as_str() == Some("{config_proxy}"));
    let has_upstream = outbounds
        .iter()
        .any(|v| v.as_str() == Some("{upstream_proxy}"));
    if !has_all && !has_config && !has_upstream {
        return;
    }

    let config_tag_set: std::collections::HashSet<&String> = config_tags.iter().collect();
    let upstream_tags: Vec<String> = proxy_tags
        .iter()
        .filter(|t| !config_tag_set.contains(t))
        .cloned()
        .collect();

    let filter_val = entry.get("filter").cloned().unwrap_or(Value::Null);
    let filter_rules: Vec<Value> = filter_val.as_array().cloned().unwrap_or_default();
    let filtered_all = apply_filter(proxy_tags, &filter_rules);
    let filtered_config = apply_filter(config_tags, &filter_rules);
    let filtered_upstream = apply_filter(&upstream_tags, &filter_rules);

    let arr = match entry["outbounds"].as_array_mut() {
        Some(a) => a,
        None => return,
    };
    let mut expanded: Vec<Value> = Vec::new();
    for item in arr.drain(..) {
        match item.as_str() {
            Some("{all}") => expanded.extend(filtered_all.iter().map(|t| json!(t))),
            Some("{config_proxy}") => expanded.extend(filtered_config.iter().map(|t| json!(t))),
            Some("{upstream_proxy}") => expanded.extend(filtered_upstream.iter().map(|t| json!(t))),
            _ => expanded.push(item),
        }
    }
    *arr = expanded;

    if let Some(obj) = entry.as_object_mut() {
        obj.remove("filter");
    }
}

/// Merge converted proxy outbounds into the `outbounds` array of a base config.
///
/// - Outbounds containing `"{all}"` in their list have it replaced with proxy
///   tags filtered by their own `filter` rules.
/// - `direct`: kept as-is if present, otherwise appended.
/// - `selector`: if absent, a new one with `default: "urltest"` is prepended.
/// - `urltest`: if absent, a new one with all proxy tags is prepended.
/// - Converted proxy outbounds are appended at the end.
/// Returns true if this outbound was produced by expanding a placeholder
/// (`{all}`, `{config_proxy}`, or `{upstream_proxy}`). Only expanded outbounds
/// can legitimately end up empty, so we only prune those.
fn was_expanded(entry: &Value) -> bool {
    // After expand_all the "filter" key is removed from expanded entries.
    // We mark them during expansion instead by checking whether the type is
    // selector/urltest (the only types that carry an outbounds list in configs).
    matches!(type_of(entry), Some("selector") | Some("urltest")) && entry.get("filter").is_none()
}

fn merge_outbounds(
    mut existing: Vec<Value>,
    proxy_tags: &[String],
    config_tags: &[String],
    proxies: Vec<Value>,
) -> Vec<Value> {
    let has_direct = existing.iter().any(|v| type_of(v) == Some("direct"));
    let has_selector = existing.iter().any(|v| type_of(v) == Some("selector"));
    let has_urltest = existing.iter().any(|v| type_of(v) == Some("urltest"));

    for entry in existing.iter_mut() {
        expand_all(entry, proxy_tags, config_tags);
    }

    // Collect tags of expanded outbounds whose outbounds list is now empty.
    let empty_tags: std::collections::HashSet<String> = existing
        .iter()
        .filter(|e| {
            was_expanded(e)
                && e["outbounds"]
                    .as_array()
                    .map(|a| a.is_empty())
                    .unwrap_or(false)
        })
        .filter_map(|e| tag_of(e).map(|t| t.to_string()))
        .collect();

    if !empty_tags.is_empty() {
        // Remove cross-references to empty outbounds from all other entries.
        for entry in existing.iter_mut() {
            if let Some(arr) = entry["outbounds"].as_array_mut() {
                arr.retain(|v| v.as_str().map(|t| !empty_tags.contains(t)).unwrap_or(true));
            }
        }
        // Remove the empty outbounds themselves.
        existing.retain(|e| tag_of(e).map(|t| !empty_tags.contains(t)).unwrap_or(true));
    }

    if !has_direct {
        existing.insert(0, json!({"type": "direct", "tag": "direct"}));
    }
    if !has_urltest {
        existing.insert(
            0,
            json!({"type": "urltest", "tag": "urltest", "outbounds": proxy_tags}),
        );
    }
    if !has_selector {
        existing.insert(
            0,
            json!({"type": "selector", "tag": "select", "default": "urltest", "outbounds": proxy_tags}),
        );
    }

    existing.extend(proxies);
    existing
}

// ── Clash rule → sing-box route rule ─────────────────────────────────────────

/// A single parsed Clash rule entry before sing-box combination.
pub(crate) struct ClashRule {
    pub(crate) field: &'static str,
    pub(crate) value: String,
    pub(crate) outbound: String,
}

/// Parse one Clash rule string into a `ClashRule`.
///
/// Supported types: DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, DOMAIN-REGEX,
/// IP-CIDR, IP-CIDR6. Returns `None` for unsupported types.
pub(crate) fn parse_clash_rule(rule: &str) -> Option<ClashRule> {
    let rule = rule.trim().split('#').next()?.trim();
    let parts: Vec<&str> = rule.splitn(4, ',').map(str::trim).collect();
    if parts.len() < 3 {
        return None;
    }
    let (kind, value, outbound) = (parts[0], parts[1], parts[2]);
    let outbound = if outbound.eq_ignore_ascii_case("direct") {
        "direct".to_string()
    } else {
        outbound.to_string()
    };
    let field = match kind {
        "DOMAIN" => "domain",
        "DOMAIN-SUFFIX" => "domain_suffix",
        "DOMAIN-KEYWORD" => "domain_keyword",
        "DOMAIN-REGEX" => "domain_regex",
        "IP-CIDR" | "IP-CIDR6" => "ip_cidr",
        _ => return None,
    };
    Some(ClashRule {
        field,
        value: value.to_string(),
        outbound,
    })
}

/// Convert and combine Clash rules into sing-box route rules.
///
/// Rules targeting the same outbound are merged into a single rule object,
/// accumulating values per field (OR within a field). This mirrors sing-box's
/// own default-rule AND-across-fields / OR-within-field semantics.
fn combine_clash_rules(clash_rules: &[String]) -> Vec<Value> {
    // Accumulate: outbound → field → [values]
    // Use a Vec to preserve first-seen insertion order per outbound.
    let mut order: Vec<String> = Vec::new();
    let mut map: std::collections::HashMap<
        String,
        std::collections::HashMap<&'static str, Vec<String>>,
    > = std::collections::HashMap::new();

    for raw in clash_rules {
        let Some(r) = parse_clash_rule(raw) else {
            continue;
        };
        if !map.contains_key(&r.outbound) {
            order.push(r.outbound.clone());
        }
        map.entry(r.outbound)
            .or_default()
            .entry(r.field)
            .or_default()
            .push(r.value);
    }

    order
        .into_iter()
        .map(|outbound| {
            let fields = map.remove(&outbound).unwrap();
            let mut rule = serde_json::Map::new();
            for (field, values) in fields {
                rule.insert(field.to_string(), json!(values));
            }
            rule.insert("outbound".to_string(), json!(outbound));
            Value::Object(rule)
        })
        .collect()
}

/// Merge converted Clash rules into the `route.rules` array of the config.
/// New rules are prepended before any existing ones so they take priority.
fn merge_rules(cfg: &mut Value, clash_rules: &[String]) {
    let new_rules = combine_clash_rules(clash_rules);

    if new_rules.is_empty() {
        return;
    }

    let existing: Vec<Value> = cfg["route"]["rules"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    let mut merged = new_rules;
    merged.extend(existing);

    cfg["route"]["rules"] = json!(merged);
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Parse a raw subscription (Clash YAML or Surge line format) and return a sing-box
/// config JSON. If `base` is provided the `outbounds` array is merged per the
/// rules above; otherwise a minimal skeleton is generated.
///
/// `extra` are additional Clash YAML proxy entries (e.g. from the local config
/// file) prepended before the subscription proxies.
///
/// `clash_rules` are Clash-format rule strings from the local config file that
/// are converted and prepended to `route.rules`.
/// Resolve the `<PlaceHold>` detour tag by finding the last entry in
/// `candidates` that exists as a tag in the base config outbounds.
fn resolve_placeholder_detour<'a>(
    candidates: &'a [String],
    base: Option<&Value>,
) -> Option<&'a str> {
    let outbounds = base?.get("outbounds")?.as_array()?;
    candidates.iter().rev().find_map(|name| {
        outbounds
            .iter()
            .any(|ob| ob["tag"].as_str() == Some(name.as_str()))
            .then_some(name.as_str())
    })
}

pub fn convert(
    raw: &str,
    base: Option<&Value>,
    extra: &[serde_yaml::Value],
    clash_rules: &[String],
    placeholder_detour: &[String],
) -> Value {
    let resolved_detour = resolve_placeholder_detour(placeholder_detour, base);

    let config_proxies: Vec<Value> = extra
        .iter()
        .filter_map(|v| parse_clash_proxy(v, resolved_detour))
        .collect();
    let config_tags: Vec<String> = config_proxies
        .iter()
        .filter_map(|v| tag_of(v).map(|s| s.to_string()))
        .collect();

    let mut proxies = config_proxies;

    let remote: Vec<Value> = if let Ok(yaml) = serde_yaml::from_str::<serde_yaml::Value>(raw) {
        yaml["proxies"]
            .as_sequence()
            .map(|seq| {
                seq.iter()
                    .filter_map(|v| parse_clash_proxy(v, None))
                    .collect()
            })
            .unwrap_or_else(|| raw.lines().filter_map(parse_line).collect())
    } else {
        raw.lines().filter_map(parse_line).collect()
    };
    proxies.extend(remote);

    let proxy_tags: Vec<String> = proxies
        .iter()
        .filter_map(|v| tag_of(v).map(|s| s.to_string()))
        .collect();

    let mut cfg = match base {
        Some(base) => {
            let mut cfg = base.clone();
            let existing = cfg["outbounds"].as_array().cloned().unwrap_or_default();
            cfg["outbounds"] = json!(merge_outbounds(
                existing,
                &proxy_tags,
                &config_tags,
                proxies
            ));
            cfg
        }
        None => {
            let outbounds = merge_outbounds(vec![], &proxy_tags, &config_tags, proxies);
            json!({
                "log":      {},
                "dns":      {},
                "inbounds": [],
                "outbounds": outbounds,
                "route":    {},
                "experimental": {},
            })
        }
    };

    merge_rules(&mut cfg, clash_rules);
    cfg
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_trojan() {
        let line = "trojan=example.com:10086, password=abc123, tls-host=cdn.example.com, over-tls=true, tls-verification=false, tag=Test Node";
        let v = parse_line(line).unwrap();
        assert_eq!(v["type"], "trojan");
        assert_eq!(v["server"], "example.com");
        assert_eq!(v["server_port"], 10086);
        assert_eq!(v["password"], "abc123");
        assert_eq!(v["tag"], "Test Node");
        assert_eq!(v["tls"]["server_name"], "cdn.example.com");
        assert_eq!(v["tls"]["insecure"], true);
    }

    #[test]
    fn parses_vless_reality() {
        let line = "vless=example.com:31827, method=none, password=uuid-here, obfs=over-tls, obfs-host=www.microsoft.com, reality-base64-pubkey=PUBKEY, reality-hex-shortid=SHORTID, vless-flow=xtls-rprx-vision, tag=TW Node";
        let v = parse_line(line).unwrap();
        assert_eq!(v["type"], "vless");
        assert_eq!(v["uuid"], "uuid-here");
        assert_eq!(v["flow"], "xtls-rprx-vision");
        assert_eq!(v["tls"]["reality"]["enabled"], true);
        assert_eq!(v["tls"]["reality"]["public_key"], "PUBKEY");
    }

    #[test]
    fn parses_anytls() {
        let line = "anytls=example.com:38691, password=abc123, tls-host=cdn.example.com, tls-verification=false, tag=SG Node";
        let v = parse_line(line).unwrap();
        assert_eq!(v["type"], "anytls");
        assert_eq!(v["tls"]["insecure"], true);
        assert_eq!(v["tls"]["server_name"], "cdn.example.com");
    }

    #[test]
    fn convert_no_base_creates_all_fixed_outbounds() {
        let raw = "trojan=h.example.com:443, password=pw, tls-host=sni.example.com, over-tls=true, tls-verification=false, tag=JP T01\n";
        let cfg = convert(raw, None, &[], &[], &[]);
        let obs = cfg["outbounds"].as_array().unwrap();
        assert_eq!(obs[0]["type"], "selector");
        assert_eq!(obs[0]["outbounds"][0], "JP T01");
        assert_eq!(obs[1]["type"], "urltest");
        assert_eq!(obs[1]["outbounds"][0], "JP T01");
        assert_eq!(obs[2]["type"], "direct");
        assert_eq!(obs[3]["tag"], "JP T01");
    }

    #[test]
    fn convert_with_base_missing_selector_and_urltest_creates_them() {
        let raw = "trojan=h.example.com:443, password=pw, tls-host=sni.example.com, over-tls=true, tls-verification=false, tag=JP T01\n";
        let base = json!({
            "outbounds": [{"type": "direct", "tag": "direct"}],
        });
        let cfg = convert(raw, Some(&base), &[], &[], &[]);
        let obs = cfg["outbounds"].as_array().unwrap();
        assert_eq!(obs[0]["type"], "selector");
        assert_eq!(obs[0]["default"], "urltest");
        assert_eq!(obs[1]["type"], "urltest");
        assert_eq!(obs[2]["type"], "direct");
        assert_eq!(obs[3]["tag"], "JP T01");
    }

    #[test]
    fn expand_all_with_no_filter_inserts_all_tags() {
        let raw = "trojan=h.example.com:443, password=pw, tls-host=s.example.com, over-tls=true, tls-verification=false, tag=HK Node\ntrojan=h.example.com:444, password=pw, tls-host=s.example.com, over-tls=true, tls-verification=false, tag=JP Node\n";
        let base = json!({
            "outbounds": [
                {"type": "selector", "tag": "all", "outbounds": ["{all}"]},
                {"type": "direct", "tag": "direct"},
            ],
        });
        let cfg = convert(raw, Some(&base), &[], &[], &[]);
        let outs = cfg["outbounds"][0]["outbounds"].as_array().unwrap();
        assert!(outs.contains(&json!("HK Node")));
        assert!(outs.contains(&json!("JP Node")));
    }

    fn find_by_tag<'a>(obs: &'a [Value], tag: &str) -> &'a Value {
        obs.iter().find(|v| v["tag"].as_str() == Some(tag)).unwrap()
    }

    #[test]
    fn expand_all_include_filter() {
        let raw = "trojan=h.example.com:443, password=pw, tls-host=s.example.com, over-tls=true, tls-verification=false, tag=HK Node\ntrojan=h.example.com:444, password=pw, tls-host=s.example.com, over-tls=true, tls-verification=false, tag=JP Node\n";
        let base = json!({
            "outbounds": [
                {
                    "type": "selector", "tag": "hk-only", "outbounds": ["{all}"],
                    "filter": [{"action": "include", "keywords": ["HK|香港"]}]
                },
                {"type": "direct", "tag": "direct"},
            ],
        });
        let cfg = convert(raw, Some(&base), &[], &[], &[]);
        let obs = cfg["outbounds"].as_array().unwrap();
        let outs = find_by_tag(obs, "hk-only")["outbounds"].as_array().unwrap();
        assert!(outs.contains(&json!("HK Node")));
        assert!(!outs.contains(&json!("JP Node")));
    }

    #[test]
    fn parses_clash_ss() {
        let yaml = "proxies:\n  - name: abc\n    type: ss\n    server: example.com\n    port: 2333\n    cipher: chacha20-ietf-poly1305\n    password: example114514\n    udp: true\n";
        let cfg = convert(yaml, None, &[], &[], &[]);
        let obs = cfg["outbounds"].as_array().unwrap();
        let ss = obs.iter().find(|v| v["type"] == "shadowsocks").unwrap();
        assert_eq!(ss["tag"], "abc");
        assert_eq!(ss["server"], "example.com");
        assert_eq!(ss["server_port"], 2333);
        assert_eq!(ss["method"], "chacha20-ietf-poly1305");
        assert_eq!(ss["password"], "example114514");
    }

    #[test]
    fn parses_clash_vmess() {
        let yaml = "proxies:\n  - name: vmtest\n    type: vmess\n    server: v.example.com\n    port: 443\n    uuid: bf000d23-0752-40b4-affe-68f7707a9661\n    alterId: 0\n    cipher: auto\n    tls: true\n    servername: sni.example.com\n    skip-cert-verify: false\n";
        let cfg = convert(yaml, None, &[], &[], &[]);
        let obs = cfg["outbounds"].as_array().unwrap();
        let vm = obs.iter().find(|v| v["type"] == "vmess").unwrap();
        assert_eq!(vm["tag"], "vmtest");
        assert_eq!(vm["uuid"], "bf000d23-0752-40b4-affe-68f7707a9661");
        assert_eq!(vm["security"], "auto");
        assert_eq!(vm["tls"]["server_name"], "sni.example.com");
    }

    #[test]
    fn parses_clash_trojan() {
        let yaml = "proxies:\n  - name: tj\n    type: trojan\n    server: t.example.com\n    port: 443\n    password: secret\n    sni: sni.example.com\n    skip-cert-verify: false\n";
        let cfg = convert(yaml, None, &[], &[], &[]);
        let obs = cfg["outbounds"].as_array().unwrap();
        let tj = obs.iter().find(|v| v["type"] == "trojan").unwrap();
        assert_eq!(tj["tag"], "tj");
        assert_eq!(tj["password"], "secret");
        assert_eq!(tj["tls"]["server_name"], "sni.example.com");
    }

    #[test]
    fn expand_all_exclude_filter() {
        let raw = "trojan=h.example.com:443, password=pw, tls-host=s.example.com, over-tls=true, tls-verification=false, tag=HK Node\ntrojan=h.example.com:444, password=pw, tls-host=s.example.com, over-tls=true, tls-verification=false, tag=JP 免费\n";
        let base = json!({
            "outbounds": [
                {
                    "type": "selector", "tag": "no-free", "outbounds": ["{all}"],
                    "filter": [{"action": "exclude", "keywords": ["免费"]}]
                },
                {"type": "direct", "tag": "direct"},
            ],
        });
        let cfg = convert(raw, Some(&base), &[], &[], &[]);
        let obs = cfg["outbounds"].as_array().unwrap();
        let outs = find_by_tag(obs, "no-free")["outbounds"].as_array().unwrap();
        assert!(outs.contains(&json!("HK Node")));
        assert!(!outs.contains(&json!("JP 免费")));
    }

    #[test]
    fn dialer_proxy_placeholder_resolved_to_detour() {
        let extra_yaml = "name: chained\ntype: ss\nserver: 1.2.3.4\nport: 1234\ncipher: chacha20-ietf-poly1305\npassword: pw\ndialer-proxy: <PlaceHold>\n";
        let extra: serde_yaml::Value = serde_yaml::from_str(extra_yaml).unwrap();
        let base = json!({
            "outbounds": [
                {"type": "selector", "tag": "🔰 节点选择", "outbounds": []},
                {"type": "direct", "tag": "direct"},
            ],
        });
        let candidates = vec!["🔰 节点选择".to_string()];
        let cfg = convert(
            "",
            Some(&base),
            std::slice::from_ref(&extra),
            &[],
            &candidates,
        );
        let obs = cfg["outbounds"].as_array().unwrap();
        let chained = obs.iter().find(|v| v["tag"] == "chained").unwrap();
        assert_eq!(chained["detour"], "🔰 节点选择");
    }

    #[test]
    fn dialer_proxy_literal_becomes_detour() {
        let extra_yaml = "name: chained\ntype: ss\nserver: 1.2.3.4\nport: 1234\ncipher: chacha20-ietf-poly1305\npassword: pw\ndialer-proxy: some-group\n";
        let extra: serde_yaml::Value = serde_yaml::from_str(extra_yaml).unwrap();
        let cfg = convert("", None, std::slice::from_ref(&extra), &[], &[]);
        let obs = cfg["outbounds"].as_array().unwrap();
        let chained = obs.iter().find(|v| v["tag"] == "chained").unwrap();
        assert_eq!(chained["detour"], "some-group");
    }

    #[test]
    fn clash_rules_combined_by_outbound() {
        let rules = vec![
            "DOMAIN-SUFFIX,cloudfront.net,Proxy".to_string(),
            "DOMAIN-SUFFIX,github.com,Proxy".to_string(),
            "IP-CIDR,10.0.0.0/8,DIRECT".to_string(),
            "DOMAIN,cdn.example.com,Proxy".to_string(),
        ];
        let combined = combine_clash_rules(&rules);
        // Two outbounds: "Proxy" and "direct"
        assert_eq!(combined.len(), 2);
        let proxy_rule = combined.iter().find(|r| r["outbound"] == "Proxy").unwrap();
        let suffixes = proxy_rule["domain_suffix"].as_array().unwrap();
        assert!(suffixes.contains(&json!("cloudfront.net")));
        assert!(suffixes.contains(&json!("github.com")));
        let domains = proxy_rule["domain"].as_array().unwrap();
        assert!(domains.contains(&json!("cdn.example.com")));
        let direct_rule = combined.iter().find(|r| r["outbound"] == "direct").unwrap();
        let cidrs = direct_rule["ip_cidr"].as_array().unwrap();
        assert!(cidrs.contains(&json!("10.0.0.0/8")));
    }

    #[test]
    fn empty_expanded_outbound_is_removed_with_cross_refs() {
        // "hk-only" will expand to nothing (no HK nodes in subscription).
        // "main" references "hk-only" — that reference must be pruned too.
        let raw = "trojan=h.example.com:443, password=pw, tls-host=s.example.com, over-tls=true, tls-verification=false, tag=JP Node\n";
        let base = json!({
            "outbounds": [
                {
                    "type": "selector", "tag": "hk-only", "outbounds": ["{all}"],
                    "filter": [{"action": "include", "keywords": ["HK|香港"]}]
                },
                {
                    "type": "selector", "tag": "main",
                    "outbounds": ["hk-only", "🎯 全球直连"]
                },
                {"type": "direct", "tag": "🎯 全球直连"},
            ],
        });
        let cfg = convert(raw, Some(&base), &[], &[], &[]);
        let obs = cfg["outbounds"].as_array().unwrap();

        // "hk-only" must be absent.
        assert!(obs.iter().all(|v| v["tag"] != "hk-only"));

        // "main" must no longer reference "hk-only".
        let main = find_by_tag(obs, "main");
        let main_outs = main["outbounds"].as_array().unwrap();
        assert!(!main_outs.contains(&json!("hk-only")));
        assert!(main_outs.contains(&json!("🎯 全球直连")));
    }

    #[test]
    fn upstream_proxy_expands_to_non_config_tags() {
        let raw = "trojan=h.example.com:443, password=pw, tls-host=s.example.com, over-tls=true, tls-verification=false, tag=Remote Node\n";
        let config_yaml = "name: Config Node\ntype: ss\nserver: 1.2.3.4\nport: 1234\ncipher: chacha20-ietf-poly1305\npassword: pw\nudp: true\n";
        let extra: serde_yaml::Value = serde_yaml::from_str(config_yaml).unwrap();
        let base = json!({
            "outbounds": [
                {"type": "selector", "tag": "upstream-only", "outbounds": ["{upstream_proxy}"]},
                {"type": "selector", "tag": "config-only", "outbounds": ["{config_proxy}"]},
                {"type": "direct", "tag": "direct"},
            ],
        });
        let cfg = convert(raw, Some(&base), std::slice::from_ref(&extra), &[], &[]);
        let obs = cfg["outbounds"].as_array().unwrap();

        let upstream_outs = find_by_tag(obs, "upstream-only")["outbounds"]
            .as_array()
            .unwrap();
        assert!(upstream_outs.contains(&json!("Remote Node")));
        assert!(!upstream_outs.contains(&json!("Config Node")));

        let config_outs = find_by_tag(obs, "config-only")["outbounds"]
            .as_array()
            .unwrap();
        assert!(config_outs.contains(&json!("Config Node")));
        assert!(!config_outs.contains(&json!("Remote Node")));
    }
}
