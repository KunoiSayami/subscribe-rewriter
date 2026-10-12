# Subscribe rewriter

A proxy subscription rewriting service for Clash and sing-box. It fetches remote configurations, merges them with locally defined proxies, rules, and proxy groups, and serves the rewritten result over HTTP.

## Features

- **Subscription rewriting** — Fetches upstream Clash subscription configs and injects local proxies, custom rules, and additional proxy groups before serving them to clients.
- **sing-box conversion** — Converts Surge-format upstream subscriptions into sing-box outbound JSON via `?method=singbox`. Supports trojan, VLESS (with Reality), and AnyTLS protocols. Optionally merges converted outbounds into a static sing-box config skeleton.
- **sing-box rule-set serving** — Fetches remote sing-box rule-set source JSON files, applies local add/remove patches, compiles them to binary `.srs` format via `sing-box rule-set compile`, and serves them over HTTP. Useful for self-hosting rule-sets with local customisations.
- **Custom proxy groups** — Define local proxy groups (select, relay, url-test) in the config. Supports `<PlaceHold>` placeholder resolution and per-subscription filtering via `apply_to` / `not_apply_to`.
- **Dialer proxy chaining** — Local proxies can use `dialer-proxy: <PlaceHold>` to automatically chain through a matched upstream proxy group.
- **Multi-subscription support** — Maps multiple `sub_id` paths to different upstream URLs, each with optional overrides (e.g. expiry, traffic limits).
- **Subscription inheritance** — An upstream entry can set `inherit: <parent_sub_id>` to copy all fields from another entry. Any field explicitly set on the child overrides the inherited value. Useful for creating variants of a subscription that differ only in a few fields (e.g. different `override` values or an extra `alias`).
- **Redis caching** — Caches fetched upstream configs in Redis (default TTL: 600s) to reduce redundant requests. Can be disabled with `--nocache`.
- **External rules** — Import rules from external JSON config files via the `additional_rules` field, with support for domain, domain-suffix, and domain-regex rule types.
- **Hot reload** — Watches both the config file and the sing-box base JSON file for changes and reloads automatically without restarting the server. If `singbox.config_path` changes between reloads, the watcher is restarted on the new path. A configured sing-box base (global or per-subscription `singbox_config_path`) that cannot be read or parsed is a hard error: the server refuses to start, and a failed reload keeps the previous config.
- **Raw passthrough** — Supports a `?method=raw` query parameter to return the upstream content unmodified (useful for non-Clash clients like Quantumult X).
- **Per-subscription passthrough** — Set `passthrough: true` on an upstream entry to always return its content as-is, without any rewriting, regardless of the query method.
- **Local file serving** — The `upstream`, `raw`, and `singbox` fields accept local filesystem paths. If the path exists as a file, it is read directly instead of fetched over HTTP.
- **Client levels** — Give each subscription a `level`; sing-box outbounds and endpoints marked with a higher `level` in the base config are removed from that subscription's config. See [Client Levels](#client-levels).
- **Rule labels** — Tag sing-box `route.rules` and `dns.rules` in the base config with a `label`, and drop them per request with `?no-label=<label>[,<label>...]`. See [Rule Labels](#rule-labels).
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
| `GET /<prefix>/<sub_id>?method=singbox&wg=<name>[,<name>...]` | Same as above, but fills in the named WireGuard keys from `singbox.wireguard`. Unknown names, and keys not bound to `<sub_id>`, are ignored. Returns `406` if two names target the same endpoint tag. |
| `GET /<prefix>/<sub_id>?method=singbox&tun=false` | Same as `?method=singbox`, but removes every `tun` inbound and strips its tag from the `inbound` match of `route.rules` and `dns.rules`. A rule whose `inbound` list ends up empty is dropped. Accepts `false`, `0`, `no` or `off`; can be combined with `wg`. |
| `GET /<prefix>/<sub_id>?method=singbox&port=<n>` | Same as `?method=singbox`, but sets `listen_port` of every `mixed` inbound to `<n>` (1–65535). Invalid values are ignored; can be combined with `wg` and `tun`. |
| `GET /<prefix>/<sub_id>?method=singbox&no-label=<label>[,<label>...]` | Same as `?method=singbox`, but removes every rule in the base config's `route.rules` and `dns.rules` labeled with one of the given labels. See [Rule Labels](#rule-labels). Can be combined with `wg`, `tun` and `port`. |
| `GET /rule-set/<tag>` | Fetches the upstream rule-set source JSON for `<tag>`, applies local add/remove patches, compiles it to a binary `.srs` file, and returns it as `application/octet-stream`. Returns `404` if the tag is not configured. |
| `GET /rule-set/<tag>.srs` | Same as above (explicit `.srs` suffix). |
| `GET /rule-set/<tag>.json` | Returns the patched rule-set source as pretty-printed JSON instead of compiling to binary. |
| `GET /rule-set/<tag>?raw` | Same as the `.json` form — returns the raw JSON source. |
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
    singbox_config_path: "/etc/sub/custom-singbox-base.json"  # optional, per-subscription sing-box base config (also used by its aliases)
    passthrough: false                         # optional; if true, content is returned as-is without rewriting
    level: 0                                   # optional, client level for sing-box output (default 0); see "Client Levels"
    override:                                  # optional
      expire: 1711451400
      total: 114514191981
      download: 0
      upload: 0
    alias:                                     # optional, alternative sub_ids that resolve to this entry
      - <alias_id>

  # Subscription with inheritance — copies all fields from the parent above,
  # then overrides only what is explicitly set here.
  - sub_id: <variant_id>
    inherit: <unique_id>                       # must reference a sub_id that does not itself use inherit
    override:
      expire: 1900000000                       # overrides the inherited expire value

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

# sing-box settings (grouped)
singbox:
  # Path to a sing-box JSON skeleton (optional).
  # When set, ?method=singbox prepends the selector + converted proxies to the
  # skeleton's existing outbounds array and returns the merged config.
  # If omitted, a minimal skeleton is generated automatically.
  config_path: "/etc/subscribe-rewriter/singbox-base.json"

  # Path to the sing-box executable (optional).
  # If unset, sing-box is looked up on PATH. Returns 500 if the binary cannot be found or fails.
  bin_path: "/usr/local/bin/sing-box"

  # Tag name of the direct outbound in the sing-box base config (optional).
  # Clash rules targeting DIRECT are rewritten to this tag name.
  # Defaults to "direct" if unset.
  direct_tag: "DIRECT"

  # Per-device WireGuard keys, selected with ?method=singbox&wg=<name>[,<name>...]
  wireguard:
    - name: phone
      tag: wg-home                      # tag of the wireguard endpoint in the base config
      private_key: "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
      address:                          # optional; overrides the endpoint's address
        - 10.0.0.2/32
      pre_shared_key: "..."             # optional; set on every peer of the endpoint
      subs:                             # optional; only served on these sub_ids (default: all)
        - alice
    - name: laptop
      tag: wg-home
      private_key: "..."
      address:
        - 10.0.0.3/32

  # Rule-sets to compile and serve at GET /rule-set/<tag>
  rule_sets:
    - tag: cn-domain
      url: "https://example.com/cn-domain.json"
      add:                              # optional: Clash-style rules to add
        - DOMAIN-SUFFIX,corp.internal
        - DOMAIN,local.dev
      remove:                           # optional: rules to strip
        keyword:                        # remove any value containing these substrings
          - tracker
          - ads
        rules:                          # remove exact entries (Clash rule format)
          - DOMAIN-SUFFIX,unwanted.example.com
```

> **Backward compatibility:** the legacy flat keys `singbox-config` and `singbox_rule_set` are still accepted and are automatically migrated to the `singbox:` block on load.

### sing-box Base Config

When `singbox.config_path` is set, the file must be a valid sing-box JSON config. The `outbounds` array in that file should contain your static entries (`direct`, `block`, `dns-out`, and any fixed outbounds). On each `?method=singbox` request the server prepends a `selector` group (containing all converted proxy tags) and the converted proxy outbounds to that array, leaving all other top-level keys (`log`, `dns`, `inbounds`, `route`, `experimental`, etc.) untouched.

Outbounds that use `{all}`, `{config_proxy}`, or `{upstream_proxy}` placeholders are expanded at request time using the converted proxy list. If a placeholder expands to an empty list (e.g. because a keyword filter matches nothing in the current subscription), that outbound is removed from the result, and so is any group left empty as a result. References to removed tags are cleaned up in the same way as for [WireGuard endpoints](#wireguard-key-pairs): group `outbounds` lists, a selector's `default`, `route.rules` and `route.final`, and `preferred_by`/`outbound` matches in DNS rules. Otherwise sing-box would reject the config because of empty outbound lists or `outbound not found` errors. `detour` references are not rewritten.

On load, the server cross-validates all rules in `config.yaml` against the outbound tags declared in the sing-box base config. Clash `DIRECT` rules are first rewritten to `singbox.direct_tag` (defaulting to `"direct"`) before the lookup, so the check correctly accounts for custom direct tag names. Any rule whose target outbound does not exist as a tag in the base config emits a warning in the log. This check runs on both initial load and every hot reload of either file.

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

If `singbox.config_path` is omitted, those three fixed outbounds are generated automatically and the rest of the config skeleton is minimal.

### WireGuard Key Pairs

Each device needs its own WireGuard key pair, and some devices should not get the tunnel at all. Put the shared part of the endpoint (peer, MTU, etc.) in the base config's `endpoints` array, leaving out `private_key`:

```json
"endpoints": [
  {
    "type": "wireguard",
    "tag": "wg-home",
    "peers": [
      { "address": "vpn.example.com", "port": 51820, "public_key": "...", "allowed_ips": ["0.0.0.0/0"] }
    ]
  }
]
```

Every `wireguard` endpoint whose tag appears in `singbox.wireguard` is *managed*:

- `?wg=` takes a comma-separated list of key names, e.g. `?wg=phone,phone-office`. Each selected key's endpoint gets that entry's `private_key` and `address`. `address` is required by sing-box, so either the base endpoint or the key entry must provide it. If the entry sets `pre_shared_key`, it is written to every peer in the endpoint's `peers`, overriding any value in the base config. Generate one with `sing-box generate rand --base64 32` and set the same value as the peer's Preshared Key on the server.
- Empty entries and unknown names are ignored. A key with `subs` is only served on those `sub_id`s; on any other subscription it is ignored as if unknown, so its private key cannot be fetched by guessing the name. `subs` is matched exactly against the `sub_id` in the request URL, so an alias must be listed explicitly: `subs: [alice]` does not match a request to `alice`'s alias `alice-phone`, and vice versa. Listing only an alias binds the key to that one URL. Selecting two keys for the same tag returns `406`.
- A managed endpoint with no selected key is removed and references to its tag are cleaned up:
  - group `outbounds` lists and a selector's `default` (groups left empty are pruned as usual);
  - `route.rules` whose `outbound` is that tag;
  - `route.final`;
  - `preferred_by` in `route.rules` and `dns.rules`, and the `outbound` match in `dns.rules`. The tag is removed from the list; if the list becomes empty, the whole top-level rule is dropped, since matching without that condition would be broader. This also applies inside logical rules.

Unmanaged endpoints are left as-is. Only the `endpoints` form (sing-box 1.11+) is managed: legacy `wireguard` entries in `outbounds`, which sing-box removed in 1.13.0, are never patched or removed, even if their tag is listed in `singbox.wireguard`. `detour` references (on outbounds, endpoints, DNS servers, rule-set `download_detour`, etc.) are **not** rewritten. Don't point them at a managed WireGuard tag, or sing-box will fail to start when `wg` is omitted.

The private and pre-shared keys live only in `config.yaml`; the URL carries just the device name.

### Client Levels

Some outbounds should only reach some clients, for example a home-network selector that only family devices get. Give each subscription a `level` in `config.yaml`, and mark the restricted outbounds or endpoints in the sing-box base config with a `level` field:

```yaml
upstream:
  - sub_id: family
    upstream: "https://example.com/sub"
    singbox: "https://example.com/surge-sub"
    level: 2
  - sub_id: guest
    inherit: family
    level: 0                            # must be set, otherwise `level: 2` is inherited
```

```json
"endpoints": [
  { "type": "wireguard", "tag": "wg-home", "level": 2, "peers": [ ... ] }
],
"outbounds": [
  { "type": "selector", "tag": "🏠 Home", "level": 1, "outbounds": ["wg-home", "direct"] },
  { "type": "direct", "tag": "direct" }
]
```

On every `?method=singbox` request:

- An entry in `outbounds` or `endpoints` is kept if it has no `level`, or if its `level` is lower than or equal to the subscription's level. A `level` that is not a non-negative integer hides the entry from every client.
- `level` is stripped from every kept entry, so sing-box never sees it.
- Removed entries are cleaned up the same way as unselected [WireGuard endpoints](#wireguard-key-pairs): group `outbounds` lists, selector `default`, `route.rules`, `route.final` and the `outbound`/`preferred_by` matches in `dns.rules`. Groups left empty are pruned, and a rule whose list match ends up empty is dropped entirely, so nothing that only a hidden outbound uses (IP ranges, SSIDs, …) leaks.

A subscription without `level` has level `0`, and its aliases share its level. `level` is inherited through `inherit` like the other fields, so a child meant to see less must set its own `level` explicitly. The level is set only in `config.yaml`, never in the URL, so a client cannot raise it. `detour` references are **not** rewritten. Don't point a visible outbound's `detour` at a hidden tag, or sing-box will fail to start on lower-level clients.

Levels only apply to sing-box output. Clash output is unaffected.

### Rule Labels

Some rules are only wanted by some clients, for example an ad-blocking rule that a client already handles itself. Mark rules or rule-sets in the sing-box base config with a `label`, a string or a list of strings:

```json
"route": {
  "rule_set": [
    { "type": "remote", "tag": "anti-ads", "label": "ads", "format": "binary", "url": "..." }
  ],
  "rules": [
    { "label": "ads", "rule_set": ["geosite-category-ads-all"], "action": "reject" },
    { "rule_set": ["geosite-category-ads-all", "anti-ads"], "action": "reject" },
    { "label": ["cn", "lan"], "ip_is_private": true, "outbound": "direct" },
    { "domain_suffix": ["example.com"], "outbound": "proxy" }
  ]
},
"dns": {
  "rules": [
    { "label": "ads", "rule_set": ["geosite-category-ads-all"], "action": "reject" }
  ]
}
```

On every `?method=singbox` request:

- `?no-label=ads,cn` removes every top-level rule in `route.rules` and `dns.rules` that has one of those labels. Labels are matched exactly and case-sensitively; empty entries and unknown labels are ignored.
- A label on a sub-rule of a logical rule removes the whole top-level rule, since dropping just that sub-rule could make the rule match more.
- `?no-label=ads` also removes every entry in `route.rule_set` labeled `ads`, and strips its tag from the `rule_set` match of the remaining `route.rules` and `dns.rules`. A rule whose `rule_set` list ends up empty is dropped entirely, the same as for [WireGuard endpoints](#wireguard-key-pairs). In the example above, the second rule keeps `geosite-category-ads-all`.
- `label` is stripped from every kept rule and rule-set, so sing-box never sees it.

Rules converted from `config.yaml` cannot carry labels.

### Unused Rule-Sets

On every `?method=singbox` request, a `route.rule_set` entry is removed if a rule in `route.rules` or `dns.rules` (including logical sub-rules) referenced it in the base config, but none does after filtering. Rules can be removed by [labels](#rule-labels), [levels](#client-levels), unselected [WireGuard endpoints](#wireguard-key-pairs) or `?tun=false`. This keeps sing-box from downloading rule-sets nothing uses. Rule-sets that the base config never references are left as-is.

### sing-box Rule-Set Serving

Each entry in `singbox.rule_sets` is served at `GET /rule-set/<tag>` as a compiled binary `.srs` file. The server:

1. Fetches the upstream sing-box rule-set source JSON (cached in Redis).
2. Applies local `add` entries (Clash-style rule strings; outbound field is ignored).
3. Applies local `remove` filters — `keyword` strips any rule value containing the substring; `rules` strips exact field+value matches parsed from Clash rule strings.
4. Invokes `sing-box rule-set compile` to produce the binary `.srs` bytes.
5. Returns the bytes as `Content-Type: application/octet-stream`.

Reference the endpoint in a sing-box config as a remote binary rule-set:

```json
{
  "type": "remote",
  "tag": "cn-domain",
  "format": "binary",
  "url": "http://127.0.0.1:23365/rule-set/cn-domain"
}
```

> **Requirement:** `sing-box` must be available on `PATH` for the compilation step.

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

[![](https://www.gnu.org/graphics/agplv3-155x51.png "AGPL v3 logo")](https://www.gnu.org/licenses/agpl-3.0.txt)

Copyright (C) 2023-2026 KunoiSayami

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.