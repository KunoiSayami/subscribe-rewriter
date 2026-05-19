# Subscribe rewriter

A proxy subscription rewriting service for Clash and sing-box. It fetches remote configurations, merges them with locally defined proxies, rules, and proxy groups, and serves the rewritten result over HTTP.

## Features

- **Subscription rewriting** — Fetches upstream Clash subscription configs and injects local proxies, custom rules, and additional proxy groups before serving them to clients.
- **sing-box conversion** — Converts Surge-format upstream subscriptions into sing-box outbound JSON via `?method=singbox`. Supports trojan, VLESS (with Reality), and AnyTLS protocols. Optionally merges converted outbounds into a static sing-box config skeleton.
- **Custom proxy groups** — Define local proxy groups (select, relay, url-test) in the config. Supports `<PlaceHold>` placeholder resolution and per-subscription filtering via `apply_to` / `not_apply_to`.
- **Dialer proxy chaining** — Local proxies can use `dialer-proxy: <PlaceHold>` to automatically chain through a matched upstream proxy group.
- **Multi-subscription support** — Maps multiple `sub_id` paths to different upstream URLs, each with optional overrides (e.g. expiry, traffic limits).
- **Redis caching** — Caches fetched upstream configs in Redis (default TTL: 600s) to reduce redundant requests. Can be disabled with `--nocache`.
- **External rules** — Import rules from external JSON config files via the `additional_rules` field, with support for domain, domain-suffix, and domain-regex rule types.
- **Hot reload** — Watches the config file for changes and reloads automatically without restarting the server.
- **Raw passthrough** — Supports a `?method=raw` query parameter to return the upstream content unmodified (useful for non-Clash clients like Quantumult X).
- **Per-subscription passthrough** — Set `passthrough: true` on an upstream entry to always return its content as-is, without any rewriting, regardless of the query method.
- **Local file serving** — The `upstream`, `raw`, and `singbox` fields accept local filesystem paths. If the path exists as a file, it is read directly instead of fetched over HTTP.
- **Subscription-userinfo forwarding** — Preserves and optionally overrides the `subscription-userinfo` header from upstream.

## Usage

```
clashrw [OPTIONS]
```

### Options

| Flag | Description | Default |
|---|---|---|
| `-c, --config <file>` | Path to the config file | `config.yaml` |
| `--interval <seconds>` | URL test interval for proxy groups | `600` |
| `--prefix <prefix>` | URL path prefix for subscription endpoints | `sub` |
| `--systemd` | Disable datetime in log output (for journald) | — |
| `--nocache` | Disable Redis caching | — |

### Endpoints

| Endpoint | Description |
|---|---|
| `GET /<prefix>/<sub_id>` | Returns the rewritten Clash YAML config. |
| `GET /<prefix>/<sub_id>?method=raw` | Returns the raw upstream content without rewriting. |
| `GET /<prefix>/<sub_id>?method=singbox` | Converts the `singbox` upstream (Surge-format) to a sing-box JSON config. Returns `406` if no `singbox` URL is configured for that subscription. |
| `GET /` | Returns version and status info as JSON. |

## Configuration

The config file (`config.yaml`) defines:

```yaml
# HTTP server settings (optional, defaults shown)
http:
  address: "127.0.0.1"
  port: 11451
  redis_address: "redis://127.0.0.1/"

# Upstream subscriptions
upstream:
  - sub_id: <unique_id>
    upstream: "https://example.com/clash-sub"
    raw: "https://example.com/raw-sub"        # optional, used with ?method=raw; may be a local file path
    singbox: "https://example.com/surge-sub"  # optional, used with ?method=singbox (Surge-format); may be a local file path
    passthrough: false                         # optional; if true, content is returned as-is without rewriting
    override:                                  # optional
      expire: 1711451400
      total: 114514191981
      download: 0
      upload: 0

# Extra rules prepended to the upstream config
rules:
  - "DOMAIN-SUFFIX,example.com,DIRECT"

# Extra proxies prepended to the upstream config
# dialer-proxy: <PlaceHold> is resolved to the last matched manual_add_group_name entry
proxies:
  - name: "My Proxy"
    type: ss
    server: "1.2.3.4"
    port: 8388
    cipher: chacha20-ietf-poly1305
    password: secret
    udp: true
  - name: "Chained Proxy"
    type: ss
    server: "5.6.7.8"
    port: 8388
    dialer-proxy: <PlaceHold>
    cipher: chacha20-ietf-poly1305
    password: secret

# Proxy name keywords for filtering
keyword:
  filter:
    - IPV6
  accepted:
    - US
    - SG

# Names of upstream proxy groups to add to the custom select group
manual_add_group_name:
  - "Endpoint Choose"

# Custom local proxy groups (aliases: "groups", "proxy-groups")
# <PlaceHold> in proxy lists is replaced with the last matched manual_add_group_name entry
# apply_to: only include this group for the listed sub_ids
# not_apply_to: exclude this group for the listed sub_ids
proxy_groups:
  - name: "Custom Relay"
    type: relay
    proxies:
      - <PlaceHold>
      - "My Proxy"
    not_apply_to:
      - "some_sub_id"

# External rule files (aliases: "additional-rules")
# Format: "<path_to_json>,<target_proxy_group>"
additional_rules:
  - "rules/custom.json,Proxy or Direct"

# Health check URL
test_url: "http://www.gstatic.com/generate_204"

# Path to a sing-box JSON skeleton (optional)
# When set, ?method=singbox prepends the selector + converted proxies to the
# skeleton's existing outbounds array and returns the merged config.
# If omitted, a minimal skeleton is generated automatically.
singbox-config: "/etc/subscribe-rewriter/singbox-base.json"
```

### sing-box Base Config

When `singbox-config` is set, the file must be a valid sing-box JSON config. The `outbounds` array in that file should contain your static entries (`direct`, `block`, `dns-out`, and any fixed outbounds). On each `?method=singbox` request the server prepends a `selector` group (containing all converted proxy tags) and the converted proxy outbounds to that array, leaving all other top-level keys (`log`, `dns`, `inbounds`, `route`, `experimental`, etc.) untouched.

Example skeleton (`singbox-base.json`):

```json
{
  "log": { "level": "info", "timestamp": true },
  "dns": { "servers": [ { "tag": "remote", "address": "tls://1.1.1.1" } ] },
  "inbounds": [
    { "type": "tun", "tag": "tun-in", "address": "172.19.0.1/30", "auto_route": true }
  ],
  "outbounds": [
    { "type": "direct", "tag": "direct" },
    { "type": "block",  "tag": "block"  },
    { "type": "dns",    "tag": "dns-out" }
  ],
  "route": {
    "rules": [
      { "inbound": "tun-in", "outbound": "proxy" }
    ]
  },
  "experimental": {}
}
```

The resulting `outbounds` array served to the client will be:

```
[ selector, <converted proxy 1>, <converted proxy 2>, ..., direct, block, dns-out ]
```

If `singbox-config` is omitted, those three fixed outbounds are generated automatically and the rest of the config skeleton is minimal.

### External Rules JSON Format

Files referenced by `additional_rules` use the following JSON structure:

```json
{
  "rules": [
    {
      "domain": ["example.com"],
      "domain_suffix": ["example.org"],
      "domain_regex": [".*\\.example\\.net"]
    }
  ]
}
```

Each entry is expanded into `DOMAIN`, `DOMAIN-SUFFIX`, and `DOMAIN-REGEX` Clash rules targeting the proxy group specified after the comma in the `additional_rules` value.

## Building

```
cargo build --release
```

Requires Rust edition 2024.

## Dependencies

- [axum](https://crates.io/crates/axum) — HTTP framework
- [reqwest](https://crates.io/crates/reqwest) — Upstream HTTP fetching (with SOCKS proxy & rustls support)
- [redis](https://crates.io/crates/redis) — Caching layer
- [notify](https://crates.io/crates/notify) — Config file watching
- [serde_yaml](https://crates.io/crates/serde_yaml) — Clash config parsing & serialization
- [clap](https://crates.io/crates/clap) — CLI argument parsing

## License

AGPL-3.0
