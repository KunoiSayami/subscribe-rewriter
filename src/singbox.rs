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

    let tls = tls_object(sni, false, reality);

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

/// Parse a raw Surge subscription (one proxy per line) and return a sing-box
/// config JSON. If `base` is provided the converted proxies + selector are
/// prepended to the skeleton's existing `outbounds`; otherwise a minimal
/// skeleton is generated.
pub fn convert(raw: &str, base: Option<&Value>) -> Value {
    let outbounds: Vec<Value> = raw.lines().filter_map(parse_line).collect();

    let proxy_tags: Vec<String> = outbounds
        .iter()
        .filter_map(|v| v["tag"].as_str().map(|s| s.to_string()))
        .collect();

    let selector = json!({
        "type": "selector",
        "tag": "proxy",
        "outbounds": proxy_tags,
    });

    match base {
        Some(base) => {
            let mut cfg = base.clone();
            let existing: Vec<Value> = cfg["outbounds"].as_array().cloned().unwrap_or_default();
            let mut all_outbounds = vec![selector];
            all_outbounds.extend(outbounds);
            all_outbounds.extend(existing);
            cfg["outbounds"] = json!(all_outbounds);
            cfg
        }
        None => {
            let mut all_outbounds = vec![
                selector,
                json!({"type": "direct", "tag": "direct"}),
                json!({"type": "block",  "tag": "block"}),
                json!({"type": "dns",    "tag": "dns-out"}),
            ];
            all_outbounds.extend(outbounds);
            json!({
                "log":  {"level": "info", "timestamp": true},
                "dns":  {},
                "inbounds":  [],
                "outbounds": all_outbounds,
                "route": {},
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
    fn convert_produces_selector() {
        let raw = "trojan=h.example.com:443, password=pw, tls-host=sni.example.com, over-tls=true, tls-verification=false, tag=JP T01\n";
        let cfg = convert(raw, None);
        assert_eq!(cfg["outbounds"][0]["type"], "selector");
        assert_eq!(cfg["outbounds"][0]["outbounds"][0], "JP T01");
    }

    #[test]
    fn convert_with_base_prepends_outbounds() {
        let raw = "trojan=h.example.com:443, password=pw, tls-host=sni.example.com, over-tls=true, tls-verification=false, tag=JP T01\n";
        let base = json!({
            "log": {"level": "warn"},
            "outbounds": [{"type": "direct", "tag": "direct"}],
        });
        let cfg = convert(raw, Some(&base));
        assert_eq!(cfg["log"]["level"], "warn");
        assert_eq!(cfg["outbounds"][0]["type"], "selector");
        assert_eq!(cfg["outbounds"][1]["tag"], "JP T01");
        assert_eq!(cfg["outbounds"][2]["tag"], "direct");
    }
}
