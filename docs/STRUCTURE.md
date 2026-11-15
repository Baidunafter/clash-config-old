# How the repository works

Settings and build logic are kept apart from the generated profiles. Change behaviour in one place; the next run applies it to every profile.

| what | where |
|---|---|
| rule sources, categories, `exclude_domains` | `tools/ruleset-builder/categories.yaml` |
| routing order and category -> proxy group | `settings/rules.yaml` |
| DNS resolvers (DoH only), the separate Gemini resolver, Russian-services resolver, fake-ip filter | `settings/dns.yaml` |
| sniffer, IPv6, other top-level Mihomo options | `settings/core.yaml` |
| TUN | `settings/tun.yaml` |
| Android apps that must bypass the VPN completely (`tun.exclude-package-url`) | `packages/exclude-from-vpn.txt` |
| which endpoints a profile has, its own user lists | `settings/profiles.yaml`, `profiles/<name>/` |
| nodes and obfuscation | `proxies/*-endpoint.yaml`, `settings/amnezia.yaml` |
| WARP keys (single place) | `settings/warp-account.yaml` |
| upstream files copied into this repo | `settings/mirror.yaml` -> `generated/mirror/` |
| pinned Mihomo, safeguards | `settings/build.yaml` |
| the profile skeleton (proxy groups) | `templates/profile.yaml` |

Do not edit `generated/`, `WARPxUNIVERSAL.yaml` or `WARPxALT.yaml` by hand: the daily workflow regenerates them.

Common tasks:

- **Add a service**: add a category to `categories.yaml`, give it a group in `generated_targets` and a place in `ordered_rules` (`settings/rules.yaml`).
- **Personal domains for one profile**: `profiles/<name>/user-exclude.yaml` (DIRECT) and `user-geo-block.yaml` (geoblock group). A device downloads only the files its profile references.
- **Switch the DNS server**: change `doh_provider` in `settings/dns.yaml`.
- **Rotate a WARP key**: edit `settings/warp-account.yaml` (or set the `WARP_WG_PRIVATE_KEY` / `WARP_MASQUE_PRIVATE_KEY` secrets).
- **An upstream list shrank on purpose**: run the workflow manually with the `allow_shrink` input.

Checks run on every update (`.github/workflows/update.yml`): settings validation, unit tests, upstream preflight, aggregation with size guard, generation, and `mihomo -t` against the freshly generated files. A failed scheduled run opens an issue. Details: `tools/ruleset-builder/README.md`, `tools/config-builder/README.md`.
- **Review routing conflicts**: open `generated/meta/conflicts.json` after a run (overlaps with the Russian direct lists and categories that fight over the same domain).
- **Check where a domain goes**: `python tools/config-builder/explain_route.py WARPxUNIVERSAL.yaml example.com`.
- **Nodes** are never hidden from a group. Traffic is saved by category assignment: heavy downloads are DIRECT (`google-bulk`, `bulk-direct`); only the `🌍 Авто` auto-select skips the traffic-limited `TEL` nodes.
- **Google**: one exit for the session (`google-core` -> AI), static and bulk traffic DIRECT (`google-bulk`); see `tools/ruleset-builder/lists/`.
- **Change categories safely**: build before and after, then `python tools/ruleset-builder/routing_diff.py BEFORE AFTER` shows exactly which domains change group. The daily workflow prints the same summary.
- **Video** (`netflix`, `streaming`) has its own proxy group `Видео`; streaming video data and large downloads are DIRECT (`bulk-direct`, `bulk-direct-video` in `tools/ruleset-builder/lists/`).
- **Gemini** has its own group `Gemini`, category `gemini` (`tools/ruleset-builder/lists/gemini.txt`) and its own DNS resolver; copies of the nodes named `[GM] ...` carry that resolver (`settings/dns.yaml`).
