# clashrw

A proxy subscription rewriting service for Clash. It fetches remote Clash configurations, merges them with locally defined proxies, rules, and proxy groups, and serves the rewritten result over HTTP.

## Features

- **Subscription rewriting** — Fetches upstream Clash subscription configs and injects local proxies, custom rules, and additional proxy groups before serving them to clients.
- **Custom proxy groups** — Define local proxy groups (select, relay, url-test) in the config. Relay groups support a `<PlaceHold>` placeholder that is automatically resolved to an upstream proxy group.
- **Multi-subscription support** — Maps multiple `sub_id` paths to different upstream URLs, each with optional overrides (e.g. expiry, traffic limits).
- **Redis caching** — Caches fetched upstream configs in Redis (default TTL: 600s) to reduce redundant requests. Can be disabled with `--nocache`.
- **Hot reload** — Watches the config file for changes and reloads automatically without restarting the server.
- **Raw passthrough** — Supports a `?method=raw` query parameter to return the upstream content unmodified (useful for non-Clash clients like Quantumult X).
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

- `GET /<prefix>/<sub_id>` — Returns the rewritten Clash config for the given subscription ID.
- `GET /<prefix>/<sub_id>?method=raw` — Returns the raw upstream content without rewriting.
- `GET /` — Returns version and status info as JSON.

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
    raw: "https://example.com/raw-sub"        # optional, used with ?method=raw
    override:                                  # optional
      expire: 1711451400
      total: 114514191981
      download: 0
      upload: 0

# Extra rules prepended to the upstream config
rules:
  - "DOMAIN-SUFFIX,example.com,DIRECT"

# Extra proxies prepended to the upstream config
proxies:
  - name: "My Proxy"
    type: ss
    server: "1.2.3.4"
    port: 8388
    cipher: chacha20-ietf-poly1305
    password: secret
    udp: true

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
# <PlaceHold> in relay groups is replaced with the last matched manual_add_group_name entry
proxy_groups:
  - name: "Custom Relay"
    type: relay
    proxies:
      - <PlaceHold>
      - "My Proxy"

# Health check URL
test_url: "http://www.gstatic.com/generate_204"
```

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
