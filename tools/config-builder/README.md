# Profile builder

`build_profiles.py` creates the final `WARPxUNIVERSAL.yaml` and, when enabled, `WARPxALT.yaml`.

It injects:

- a single GitHub `Authorization` header anchor using `CLASH_GITHUB_PAT`;
- private generated/provider URLs pointing to this repository;
- Xbox DNS as the only normal DNS resolver via DoH (`https://xbox-dns.ru/dns-query`);
- Xbox DNS IPv4 addresses only as bootstrap resolvers for the DoH hostname;
- Fake-IP DNS mode;
- TUN + DNS hijack;
- the same Xbox DNS DoH endpoint in WARP remote-DNS settings.

The WARP proxy list is generated from `proxies/` (see below); proxy groups remain template-driven.

MALW non-blocking IP/hosts overrides are disabled by `malw.publish_host_overrides: false` in `settings/build.yaml`; `malw-block` remains active.

## WARP proxies and endpoint sets

The proxy list of every profile is generated from `proxies/*-endpoint.yaml` (one entry = name, server, port) and the obfuscation values in `settings/amnezia.yaml`. Do not edit the `WARP PROXIES` / `AMNEZIA ANCHORS` blocks of a template by hand.

`endpoints:` in `settings/profiles.yaml` chooses the sets of a profile:

| type | marker | source |
|---|---|---|
| `geo` | `[🌍]`, `[🌍 MQ]` | `proxies/geo-endpoint.yaml` (relay servers; `[🌍 MQ]` entries are MASQUE nodes, see below) |
| `origin` | `[⭐]` | `proxies/origin-endpoint.yaml` (the first three `:4500` entries also get `(Alt n)` obfuscation variants) |
| `default` | `[☁️]` | `proxies/default-endpoint.yaml` (~120 address ranges) |
| `masque` | `[🎭]` | `proxies/masque-endpoint.yaml` (rendered with the `*warp-masque` anchor) |

Markers of types a profile does not use are removed from the `filter:` lines of the proxy groups, so a group never lists nodes the profile lacks. The build fails on duplicate proxy names or an invalid filter and warns when a group filter matches no proxy.

To add a node, append it to the matching `proxies/*-endpoint.yaml`. The upstream lists live in `codelabhq/clash-warp-config/proxies/`.

## DNS, core options, WARP account

- `settings/dns.yaml`: `doh_provider` names the DNS-over-HTTPS resolvers of every group except Gemini (currently Cloudflare and Google). With several names Mihomo asks all of them in parallel and uses the first answer, so each resolver sees every query; list one name for a single resolver. The build fails on plain DNS or `fallback`. The bootstrap is DoH by IP too. `ru_resolver` feeds `nameserver-policy` for `category-ru`, `whitelist` and `private-domains`. The same servers are written into the `dns` of every WARP node.
- **Gemini has its own resolver** (`gemini_resolver: xbox` -> `https://xbox-dns.ru/dns-query`). A proxy group cannot carry a DNS server in Mihomo, so it is done in two places: `nameserver-policy` resolves the domains of the `gemini` category with it whenever Mihomo resolves them itself (group `Gemini` set to "Без VPN"), and a node resolves names through its own `dns` inside the tunnel, so the group `Gemini` also offers a copy of every node named `[GM] ...` (`[GM MQ] ...` for masque) whose `dns` is that resolver. Plain nodes stay selectable in the group too (they use the main servers). The copies are invisible to every other group. Remove `gemini_resolver` to switch all of this off. Xbox DNS answers with the address of its own proxy for blocked services; the rest of the Google session (`google-core` -> AI) still resolves normally, so keep both groups on the same node or add `google-core` to the Gemini policy (see the note in the file).
- `settings/core.yaml`: `ipv6`, `unified-delay`, `tcp-concurrent`, `profile`, `sniffer` (GUI clients may override some of them).
- `settings/warp-account.yaml`: WireGuard and MASQUE credentials, rendered into the `warp-common` / `warp-masque` anchors.
- Each profile has `user_rules_dir` (`profiles/<name>/`) with its own `user-exclude.yaml` and `user-geo-block.yaml`; the `templates/profile.yaml` skeleton is shared.
- `make_test_profile.py PROFILE OUT_DIR` writes an offline copy that reads this repository's providers from local files, so `mihomo -t -d OUT_DIR -f OUT_DIR/config.yaml` validates the new generation without the network.

## Nodes and traffic

Every group that a category routes to lists every node (geo, origin, masque), so any node can be picked anywhere, for checks too. Nothing is hidden. Saving traffic is done in the **category assignment**: bulk and static traffic is DIRECT before it can reach a group that may use a geo node (`google-bulk`, `bulk-direct`, see `tools/ruleset-builder/lists/`). Nodes named `TEL` have a traffic limit; only the hidden automatic group `🌍 Авто` skips them (`exclude-filter: "TEL"`), so auto-select never lands on one. A unit test keeps this layout.

## Checking a route offline

`python tools/config-builder/explain_route.py WARPxUNIVERSAL.yaml gemini.google.com www.gstatic.com ...` prints the first matching rule and its group for each domain, from the files of this repository. The mirrored binary `.mrs` lists (`category-ru`, `whitelist`, `private-domains`) cannot be read; they are listed as "not evaluated" because they could take precedence.

## Apps that bypass the VPN (`tun.exclude-package-url`)

`packages/exclude-from-vpn.txt` is a plain list of Android package names, one per line, nothing else (the client reads every line as a package name, so comments are an error). The builder does not copy the names into the profile: it only writes `tun.exclude-package-url` with the raw URL of that file, in the form of the subscription link (`https://OWNER:TOKEN@raw.githubusercontent.com/...`, the token is the `CLASH_GITHUB_PAT` secret). The FlClash family downloads the list itself, so changing the file takes effect without regenerating anything.

- A value already present in `settings/tun.yaml` wins. Use it for a client that cannot authenticate against the private repository: the list is not secret, so a public URL (a gist, a public repository) works. Names of apps and URL are then yours to keep in sync.
- Other clients (Clash Verge Rev, Clash Meta for Android) do not know this key and ignore it; they would need a plain `exclude-package` list in `settings/tun.yaml`.
- Unlike a DIRECT rule, an excluded app bypasses the TUN entirely, so it does not see an active VPN either, which banking and government apps check. Currently: Мой налог (`com.gnivts.selfemployed`), Госуслуги (`ru.rostel`), ЕМИАС (`com.programmisty.emiasapp`).

## MASQUE nodes in any endpoint file

A node whose bracketed marker contains the token `MQ` (`"[🌍 MQ] 🇳🇱 Нидерланды"`, port 443) is rendered with `<<: *warp-masque` (type `masque`, the MASQUE credentials of `settings/warp-account.yaml`); every other node of the file keeps `<<: *warp-common` (WireGuard). Only `server` and `port` (and other per-node keys such as `network`) are written per node. The token must be inside the brackets: `[🌍] MQ-city` is an ordinary WireGuard node. Obfuscation variants (`(Alt n)`) are only generated for WireGuard nodes. Group filters match the `🌍` marker, so `[🌍 MQ]` nodes appear everywhere the plain geo nodes do, and the `🌍 Авто` auto-select group takes them too (still without the traffic-limited `TEL` ones).

