use serde_json::{Value, json};
use std::collections::HashMap;

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

/// If the outbound's `outbounds` list contains `"{all}"`, expand it using
/// the outbound's own `filter` rules. Outbounds without `{all}` are untouched.
fn expand_all(entry: &mut Value, proxy_tags: &[String]) {
    // Check and clone filter before taking a mutable borrow on entry.
    let has_all = entry["outbounds"]
        .as_array()
        .is_some_and(|a| a.iter().any(|v| v.as_str() == Some("{all}")));
    if !has_all {
        return;
    }

    let filter_val = entry.get("filter").cloned().unwrap_or(Value::Null);
    let filter_rules: Vec<Value> = filter_val.as_array().cloned().unwrap_or_default();
    let filtered = apply_filter(proxy_tags, &filter_rules);

    let arr = match entry["outbounds"].as_array_mut() {
        Some(a) => a,
        None => return,
    };
    let mut expanded: Vec<Value> = Vec::new();
    for item in arr.drain(..) {
        if item.as_str() == Some("{all}") {
            expanded.extend(filtered.iter().map(|t| json!(t)));
        } else {
            expanded.push(item);
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
fn merge_outbounds(
    mut existing: Vec<Value>,
    proxy_tags: &[String],
    proxies: Vec<Value>,
) -> Vec<Value> {
    let has_direct = existing.iter().any(|v| type_of(v) == Some("direct"));
    let has_selector = existing.iter().any(|v| type_of(v) == Some("selector"));
    let has_urltest = existing.iter().any(|v| type_of(v) == Some("urltest"));

    for entry in existing.iter_mut() {
        expand_all(entry, proxy_tags);
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

/// Parse a raw Surge subscription (one proxy per line) and return a sing-box
/// config JSON. If `base` is provided the `outbounds` array is merged per the
/// rules above; otherwise a minimal skeleton is generated.
pub fn convert(raw: &str, base: Option<&Value>) -> Value {
    let proxies: Vec<Value> = raw.lines().filter_map(parse_line).collect();

    let proxy_tags: Vec<String> = proxies
        .iter()
        .filter_map(|v| tag_of(v).map(|s| s.to_string()))
        .collect();

    match base {
        Some(base) => {
            let mut cfg = base.clone();
            let existing = cfg["outbounds"].as_array().cloned().unwrap_or_default();
            cfg["outbounds"] = json!(merge_outbounds(existing, &proxy_tags, proxies));
            cfg
        }
        None => {
            let outbounds = merge_outbounds(vec![], &proxy_tags, proxies);
            json!({
                "log":      {},
                "dns":      {},
                "inbounds": [],
                "outbounds": outbounds,
                "route":    {},
                "experimental": {},
            })
        }
    }
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
        let cfg = convert(raw, None);
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
        let cfg = convert(raw, Some(&base));
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
        let cfg = convert(raw, Some(&base));
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
        let cfg = convert(raw, Some(&base));
        let obs = cfg["outbounds"].as_array().unwrap();
        let outs = find_by_tag(obs, "hk-only")["outbounds"].as_array().unwrap();
        assert!(outs.contains(&json!("HK Node")));
        assert!(!outs.contains(&json!("JP Node")));
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
        let cfg = convert(raw, Some(&base));
        let obs = cfg["outbounds"].as_array().unwrap();
        let outs = find_by_tag(obs, "no-free")["outbounds"].as_array().unwrap();
        assert!(outs.contains(&json!("HK Node")));
        assert!(!outs.contains(&json!("JP 免费")));
    }
}
