# Aggregated ruleset builder

This builder combines domain/IP data from:

- `hydraponique/roscomvpn-geosite`
- `hydraponique/roscomvpn-geoip` (system IP lists remain upstream providers)
- `itdoginfo/allow-domains`
- `codelabhq/clash-warp-config`
- `blackmatrix7/ios_rule_script` (`rule/Clash/<Name>/<Name>.yaml`, classical format; a bare service name in `categories.yaml` is enough)
- `ImMALWARE/dns.malw.link` hosts

The canonical category map is in `categories.yaml`.

## Output

`generated/domain/*.mrs` are merged domain rulesets.

`generated/ip/*.mrs` are merged service CIDR rulesets.

`generated/classical/<name>-classical.yaml` hold the `DOMAIN-KEYWORD`, `DOMAIN-REGEX` and `PROCESS-NAME[-REGEX]` entries of a category, because MRS cannot represent them. Process rules route an application by its process name on desktop or by its package name on Android (Discord clients and `com.discord`, TikTok `com.zhiliaoapp.musically`). The profile builder adds a provider for each file and a rule with the same target right after the category's own rule.

`generated/meta/manifest.json` contains counts and SHA-256 hashes.

`generated/meta/losses.json` lists upstream lines that could not be represented (`process`, `single_label`, `include`, `unsupported:*`, ...) with up to three examples per reason, plus notes for lines kept with a caveat (`attributes_stripped`, `full_broadened`). Review it after adding a source.

Generated directories are replaced only after the whole run succeeds; a failed run leaves the previous output untouched.

MALW IP mappings are used only to extract domains for configured MALW categories. Non-blocking MALW IP mappings are not published as Mihomo `hosts` overrides. Entries from the `Блокировка` section remain in `malw-block` and are routed to `REJECT`.

The builder fails instead of publishing an empty/partial category if an upstream input required by a category is unavailable.

## MALW IP overrides

`settings/build.yaml` contains `malw.publish_host_overrides: false`. Keep it `false` to use MALW for domain aggregation/blocking without publishing MALW IP mappings as Mihomo `hosts` overrides.

## Options in `categories.yaml`

- `exclude_domains: [a.com]` removes exactly these entries from every source of the category. `exclude_domains: {blackmatrix7: [a.com]}` limits it to one source. Sub-domains are kept (`gemini.google.com` survives when `google.com` is excluded). `x-shared-infra` at the top is a reusable list of parent and CDN domains.
- `optional: true` skips a category whose upstream data disappeared instead of failing the build (its generated files are removed).
- MALW entries: `"Name"` is required, `"?Name"` is optional (warning), `[Name, Alias]` accepts the first existing section.

## Safeguards

`settings/build.yaml` -> `guard`: a category that shrinks by more than `max_shrink_percent` compared with the previous `manifest.json` fails the build. Accept an intended shrink with `build.py --allow-shrink NAME`, the `ALLOW_SHRINK` environment variable (the workflow has an `allow_shrink` input) or `guard.allow_shrink`.

MALW `# Последнее обновление: ...` and `###` lines are not section headings. A warning is printed when the hosts file is older than `malw.max_age_days`.

## Tests

`python -m unittest discover -s tools/ruleset-builder/tests -v` (no network and no Mihomo binary needed).

## Mirror, retries and cache

`settings/mirror.yaml` lists upstream files (roscomvpn `.mrs`, `ru-apps.yaml`) that are copied byte for byte into `generated/mirror/`; profiles load them from this repository. Each file is sanity-checked (zstd magic for `.mrs`, a non-empty `payload` for YAML) and covered by the shrink guard (by size).

Downloads retry with exponential backoff on network errors and HTTP 408/425/429/5xx (never on 404). With `SOURCE_CACHE_DIR` set, `preflight.py` warms an on-disk cache and `build.py` reuses it (`SOURCE_CACHE_TTL`, default 1800 s) and prefetches in parallel.

## Other scripts

- `settings_check.py` validates the YAML settings and cross-references (run first in CI).
- `report.py` writes the job summary and the commit message from the manifest difference.
- `../update_mihomo.py` bumps the pinned Mihomo version, asset and SHA-256 (weekly workflow `update-mihomo.yml` opens a pull request).

## Routing conflict report

`generated/meta/conflicts.json` (informational, with `::warning::` lines in the log):

- `direct_overlap`: domains of proxied categories that are also in the Russian direct lists (`conflicts.direct_lists` in `settings/build.yaml`). They are the first candidates for `exclude_domains`.
- `target_conflicts`: the same entry in several categories whose rules lead to different targets; only the first rule in `settings/rules.yaml` applies (`winner` / `loser`).

Note: itdog's `Categories/*.lst` (`block`, `geoblock`, `news`, `porn`, `anime`, `hodca`) are sites blocked in Russia or blocking Russian addresses. They belong to a proxy group, never to `generated_blocks` (REJECT); a unit test guards this.

## Own lists (`local` source)

`local: [name.txt]` in a category reads `tools/ruleset-builder/lists/name.txt` (the same line format as the roscomvpn lists: `domain:`, `keyword:`, `regexp:`, plain domains). Use it for curated lists that no upstream provides. `google-core.txt` and `google-bulk.txt` are the Google design:

- `google-core` (target `AI`): `google.com`, `googleapis.com`, `recaptcha.net` and Gemini's own domains. They carry the Google session, so they share one exit IP with Gemini; otherwise Google sees one account from two countries and shows the "unusual traffic" page.
- `google-bulk` (DIRECT, matched before YouTube and `google-core`): `gstatic.com`, `googleusercontent.com`, Chrome/Android/Play downloads and Android push. These carry no session and can be large, so they never use a proxy node. YouTube video stays in the YouTube group.
- `google-play` and `google-meet` also go to `AI`, so every session domain of Google leaves through the node chosen in the AI group.
- `gemini` (`lists/gemini.txt`, matched before both) goes to its own group `Gemini` with its own DNS resolver, see `tools/config-builder/README.md`.

## Category cleanup and `routing_diff.py`

`python tools/ruleset-builder/routing_diff.py BEFORE_ROOT AFTER_ROOT` lists the domains whose target changes between two checkouts (the first matching rule of `settings/rules.yaml` decides). The workflow adds it to the job summary for every run (previous commit vs new build), so an automatic update that moves domains between groups is visible. Use it before any change of categories or rule order: a pure cleanup must report no changes.

Conventions kept by the cleanup:

- One category per theme and target. Small lists with the same target are merged into the theme category (`music` = music + Spotify + Tidal + Deezer, `tools` also holds Notion/Canva/Linear, `games` also holds Tarkov/Faceit/Roblox/Supercell, `streaming` also holds HDRezka, `porn` = itdog + codelab).
- Big platform lists stay separate (steam, epic-games, riot, github, apple, microsoft, news, anime) so a profile can drop them with `exclude_rule_providers`.
- Categories that lists such as `google-core` fully cover are removed instead of kept as dead rules (`google-play`, the `google-meet` domain list; the Meet IP set stays).
- `twitch-ads` is a proxy list ("disables ads, raises quality to 1080p+"), routed to `Обход качества Twitch`, never REJECT.
- `exclude_domains: {all: [...]}` removes an entry from every source of a category (`api.github.com` is not an AI host).
- `hodca` goes to `PROXY` while the rest of the blocked-site family goes to `Геоблок`: a deliberate split (hosting providers have their own group selection).

## Bulk downloads and IPv6

- `bulk-direct` (DIRECT, ahead of `apple`, `steam`, `epic-games`): Apple updates, Steam content, Epic downloads. Add hosts you notice in your client's connection list; hosts that may need a proxy (Hugging Face, Docker, vendor downloads) are deliberately not included.
- `IP-CIDR6,::/0,REJECT` stands after Telegram's, private and Russian direct ranges and before every domain category. IPv6 is off in this profile; a connection made straight to an IPv6 address would leave from another exit IP than the IPv4 connections of the same site (Google then sees one session from two addresses). Rejecting it makes the application fall back to IPv4.

## Bulk lists and the video group

- `bulk-direct` also holds software downloads that need no geo exit: Hugging Face model files, Docker image layers, vendor drivers (NVIDIA, Intel, AMD, Dell, HP, Logitech, Oracle, JetBrains, Adobe, Mozilla). Delete a line if a vendor blocks Russian addresses for that host.
- `bulk-direct-video` (DIRECT) holds the video data of streaming services (`nflxvideo.net`). It is a separate list because a service may bind video URLs to the requesting IP; remove the line, or switch it off per profile with `exclude_rule_providers: [bulk-direct-video]`.
- `netflix` and `streaming` route to their own group `Видео`, so video traffic is chosen separately from Gemini, search and other geoblock traffic. The group offers every node like all the others.

