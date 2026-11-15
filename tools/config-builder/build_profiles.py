#!/usr/bin/env python3
"""Build final Clash/Mihomo profiles from templates and generated rulesets."""
from __future__ import annotations

import copy
import os
import re
import sys
import urllib.parse
from pathlib import Path
from typing import Any

import yaml

import warp_proxies

ROOT = Path(__file__).resolve().parents[2]
SETTINGS = ROOT / "settings"
GENERATED = ROOT / "generated"
PROXIES = ROOT / "proxies"
USER_RULESETS = ("user-exclude", "user-geo-block")
PACKAGE_LIST = "packages/exclude-from-vpn.txt"
PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+$")


def load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Expected mapping in {path}")
    return data


def replace_block(text: str, begin: str, end: str, inner: str, legacy_begin: str | None = None) -> str:
    candidates = [begin]
    if legacy_begin:
        candidates.append(legacy_begin)
    for marker in candidates:
        pattern = re.compile(re.escape(marker) + r".*?" + re.escape(end), re.DOTALL)
        if pattern.search(text):
            return pattern.sub(lambda _m: f"{begin}\n{inner}\n{end}", text, count=1)
    raise RuntimeError(f"Template marker block not found: {begin} ... {end}")


def render_yaml_block(data: dict[str, Any]) -> str:
    # safe_dump gives correct quoting/escaping and deterministic output.
    text = yaml.safe_dump(data, allow_unicode=True, sort_keys=False, default_flow_style=False)
    return text.rstrip()


def render_auth(pat: str, scheme: str) -> str:
    # Single YAML anchor. It is referenced by every provider hosted in the
    # private repository, so the PAT is not repeated in every URL.
    safe = pat.replace("'", "''")
    return "\n".join([
        "x-github-auth-header: &github-auth-header",
        "  Authorization:",
        f"    - '{scheme} {safe}'",
    ])


def is_private_url(url: str, private_raw_base: str) -> bool:
    return url.startswith(private_raw_base.rstrip("/") + "/")


def load_package_list(path: Path) -> list[str]:
    """Package names of packages/exclude-from-vpn.txt: one per line, nothing else.

    The client downloads this file itself and reads every line as a package name, so
    comments and malformed lines are errors here instead of silently wrong there.
    """
    if not path.is_file():
        return []
    packages: list[str] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        name = line.strip()
        if not name:
            continue
        if not PACKAGE_RE.match(name):
            raise RuntimeError(f"{path.name}:{number}: '{name}' is not an Android package name (like com.example.app); no comments allowed")
        packages.append(name)
    return packages


def package_list_url(private_raw_base: str, owner: str, token: str, relative_path: str) -> str:
    """Raw URL of a file in the private repository with the credentials of the profile link.

    Same form as the subscription link in the README: https://OWNER:TOKEN@raw.githubusercontent.com/...
    """
    parts = urllib.parse.urlsplit(private_raw_base.rstrip("/") + "/" + relative_path.lstrip("/"))
    netloc = f"{urllib.parse.quote(owner, safe='')}:{urllib.parse.quote(token, safe='')}@{parts.netloc}"
    return urllib.parse.urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def tun_with_package_url(tun: dict[str, Any], url: str | None) -> dict[str, Any]:
    """Add `exclude-package-url` (FlClash family reads the list of apps from it).

    A value already present in settings/tun.yaml wins, e.g. a public URL for a client
    that cannot authenticate against the private repository.
    """
    result = dict(tun)
    if url and not result.get("exclude-package-url"):
        result["exclude-package-url"] = url
    return result


def user_rules_dir(profile: dict[str, Any]) -> str:
    value = str(profile.get("user_rules_dir", "")).strip().strip("/")
    if not value:
        raise RuntimeError("profile is missing user_rules_dir")
    return value


def _main_providers(cfg: dict[str, Any]) -> list[str]:
    value = cfg.get("doh_provider")
    names = [value] if isinstance(value, str) else list(value or [])
    if not names:
        raise RuntimeError("dns.yaml: doh_provider is required (a provider name or a list of them)")
    return names


def gemini_resolver_url(cfg: dict[str, Any]) -> str | None:
    """DoH URL of the Gemini resolver, or None when it is not configured."""
    name = cfg.get("gemini_resolver")
    if not name:
        return None
    providers = cfg.get("providers") or {}
    if name not in providers:
        raise RuntimeError(f"dns.yaml: gemini_resolver '{name}' is not in providers ({', '.join(providers)})")
    return str(providers[name]["doh"])


def resolve_dns(cfg: dict[str, Any], excluded: set[str]) -> tuple[dict[str, Any], list[str]]:
    """Expand settings/dns.yaml into the final `dns:` mapping.

    Enforces the project's rules: DNS over HTTPS only (including bootstrap), no `fallback`.
    `doh_provider` may name several resolvers; Mihomo then asks all of them in parallel and
    uses the first answer. Returns (dns mapping, servers to use inside WARP).
    """
    providers = cfg.get("providers") or {}
    names = _main_providers(cfg)
    for name in names:
        if name not in providers:
            raise RuntimeError(f"dns.yaml: doh_provider '{name}' is not in providers ({', '.join(providers)})")
        if not providers[name].get("bootstrap"):
            raise RuntimeError(f"dns.yaml: provider '{name}' has no bootstrap and cannot be the main resolver")
    main_doh = [providers[n]["doh"] for n in names]
    ru = cfg.get("ru_resolver", "main")
    if ru != "main" and ru not in providers:
        raise RuntimeError(f"dns.yaml: ru_resolver '{ru}' is not 'main' or a provider name")
    gemini = gemini_resolver_url(cfg)
    substitutions: dict[str, list[str]] = {
        "$DOH": main_doh,
        "$BOOTSTRAP": [providers[n]["bootstrap"] for n in names],
        "$RU_DNS": main_doh if ru == "main" else [providers[ru]["doh"]],
        "$GEMINI_DNS": [gemini] if gemini else [],
    }

    def substitute(value: Any) -> Any:
        if isinstance(value, list):  # a placeholder inside a list expands to all of its servers
            result: list[Any] = []
            for item in value:
                if isinstance(item, str) and item in substitutions:
                    result.extend(substitutions[item])
                else:
                    result.append(substitute(item))
            return result
        if isinstance(value, dict):
            return {k: substitute(v) for k, v in value.items()}
        if isinstance(value, str) and value in substitutions:
            return list(substitutions[value])
        return value

    dns = substitute(copy.deepcopy(cfg["dns"]))

    # Drop excluded providers from nameserver-policy keys (an unknown rule-set breaks Mihomo)
    # and policies that have no server (e.g. the Gemini resolver is switched off).
    policy: dict[str, Any] = {}
    for key, value in (dns.get("nameserver-policy") or {}).items():
        if not value:
            continue
        if str(key).startswith("rule-set:"):
            kept = [n for n in str(key)[len("rule-set:"):].split(",") if n not in excluded]
            if not kept:
                continue
            key = "rule-set:" + ",".join(kept)
        policy[key] = value
    if policy:
        dns["nameserver-policy"] = policy
    else:
        dns.pop("nameserver-policy", None)

    if "fallback" in dns:
        raise RuntimeError("dns.yaml: 'fallback' is not supported; list the resolvers in `nameserver`")
    for field in ("default-nameserver", "nameserver", "proxy-server-nameserver"):
        for item in dns.get(field) or []:
            if not str(item).startswith("https://"):
                raise RuntimeError(f"dns.yaml: {field} entry '{item}' is not DNS over HTTPS (https://)")
    for servers in policy.values():
        for item in servers if isinstance(servers, list) else [servers]:
            if not str(item).startswith("https://"):
                raise RuntimeError(f"dns.yaml: nameserver-policy entry '{item}' is not DNS over HTTPS (https://)")
    if not dns.get("nameserver"):
        raise RuntimeError("dns.yaml: at least one nameserver is required")
    return dns, list(dns["nameserver"])


def render_providers(profile: dict[str, Any], settings: dict[str, Any], private_raw_base: str, excluded: set[str]) -> str:
    interval = int(settings["runtime"].get("rule_provider_interval", 86400))
    lines = ["rule-providers:"]

    # Generated domain rulesets.
    for path in sorted((GENERATED / "domain").glob("*.mrs")):
        name = path.stem
        if _provider_is_excluded(name, excluded):
            continue
        lines.extend([
            f"  {name}:",
            "    type: http",
            "    behavior: domain",
            "    format: mrs",
            f"    url: {private_raw_base}/generated/domain/{name}.mrs",
            f"    path: ./ruleset/generated-{name}.mrs",
            "    interval: *default-interval",
            "    header: *github-auth-header",
        ])

    # Generated IP rulesets.
    for path in sorted((GENERATED / "ip").glob("*.mrs")):
        base_name = path.stem
        name = f"{base_name}-ip"
        if _provider_is_excluded(name, excluded):
            continue
        lines.extend([
            f"  {name}:",
            "    type: http",
            "    behavior: ipcidr",
            "    format: mrs",
            f"    url: {private_raw_base}/generated/ip/{path.stem}.mrs",
            f"    path: ./ruleset/generated-{path.stem}-ip.mrs",
            "    interval: *default-interval",
            "    header: *github-auth-header",
        ])

    # Keyword / regex companions of generated domain sets (MRS cannot hold them).
    for path in sorted((GENERATED / "classical").glob("*-classical.yaml")):
        name = path.stem
        if _provider_is_excluded(name, excluded):
            continue
        lines.extend([
            f"  {name}:",
            "    type: http",
            "    behavior: classical",
            "    format: yaml",
            f"    url: {private_raw_base}/generated/classical/{path.name}",
            f"    path: ./ruleset/generated-{path.name}",
            "    interval: *default-interval",
            "    header: *github-auth-header",
        ])

    static = load_yaml(SETTINGS / "rule-providers.yaml").get("static", [])
    for item in static:
        provider_name = item["name"]
        if _provider_is_excluded(provider_name, excluded):
            continue
        lines.extend([
            f"  {provider_name}:",
            f"    type: {item.get('type', 'http')}",
            f"    behavior: {item['behavior']}",
        ])
        if item.get("format"):
            lines.append(f"    format: {item['format']}")
        if item.get("mirror"):
            # Copy of an upstream file kept in this repository (settings/mirror.yaml).
            matches = sorted((GENERATED / "mirror").glob(f"{item['mirror']}.*"))
            if not matches:
                raise RuntimeError(f"Provider '{provider_name}': generated/mirror/{item['mirror']}.* is missing; run build.py first")
            lines.extend([
                f"    url: {private_raw_base}/generated/mirror/{matches[0].name}",
                f"    path: ./ruleset/mirror-{matches[0].name}",
                "    interval: *default-interval",
                "    header: *github-auth-header",
            ])
            continue
        interval_value = item.get("interval")
        interval_text = "*default-interval" if interval_value in (None, "default", 86400) else str(interval_value)
        lines.extend([
            f"    url: {item['url']}",
            f"    path: {item['path']}",
            f"    interval: {interval_text}",
        ])

    # Each profile has its own user rulesets under user_rules_dir; the provider names
    # (user-exclude, user-geo-block) are the same in every profile.
    rules_dir = user_rules_dir(profile)
    slug = Path(rules_dir).name
    for name in USER_RULESETS:
        if _provider_is_excluded(name, excluded):
            continue
        lines.extend([
            f"  {name}:",
            "    type: http",
            "    behavior: classical",
            f"    url: {private_raw_base}/{rules_dir}/{name}.yaml",
            f"    path: ./ruleset/{name}-{slug}.yaml",
            "    interval: *default-interval",
            "    header: *github-auth-header",
        ])

    return "\n".join(lines)


def extract_rule_set_names(value: Any) -> set[str]:
    names: set[str] = set()
    if isinstance(value, str):
        if value.startswith("RULE-SET,"):
            parts = value.split(",")
            if len(parts) >= 2:
                names.add(parts[1])
        return names
    if isinstance(value, list):
        for item in value:
            names.update(extract_rule_set_names(item))
        return names
    if isinstance(value, dict):
        for item in value.values():
            names.update(extract_rule_set_names(item))
    return names


def _provider_is_excluded(name: str, excluded: set[str]) -> bool:
    if name.endswith("-classical"):
        return name in excluded or name[: -len("-classical")] in excluded
    return name in excluded or (name.endswith("-ip") and name[:-3] in excluded)


def render_ordered_rules(excluded: set[str]) -> str:
    cfg = load_yaml(SETTINGS / "rules.yaml")
    domains = cfg.get("generated_targets", {})
    ips = cfg.get("generated_ip_targets", {})
    blocks = set(cfg.get("generated_blocks", []))
    ordered = cfg.get("ordered_rules", [])

    actual_domains = {p.stem for p in (GENERATED / "domain").glob("*.mrs")}
    actual_ips = {p.stem for p in (GENERATED / "ip").glob("*.mrs")}
    suffix = "-classical"
    actual_classical = {p.stem[: -len(suffix)] for p in (GENERATED / "classical").glob(f"*{suffix}.yaml")}
    covered_domains: set[str] = set()
    covered_ips: set[str] = set()
    covered_classical: set[str] = set()
    lines = ["rules:"]

    for item in ordered:
        if isinstance(item, str):
            # Static rules may reference generated providers indirectly (e.g. AND + RULE-SET,discord-ip).
            refs = re.findall(r"RULE-SET,([^,\s\)]+)", item)
            if any(_provider_is_excluded(r, excluded) for r in refs):
                continue
            lines.append(f"  - {item}")
            for r in refs:
                if r.endswith("-ip") and r[:-3] in actual_ips:
                    covered_ips.add(r[:-3])
                elif r in actual_domains:
                    covered_domains.add(r)
            continue

        if not isinstance(item, dict) or len(item) != 1:
            raise RuntimeError(f"Invalid ordered rule entry: {item!r}")
        kind, name = next(iter(item.items()))
        if kind == "block":
            if name in excluded:
                continue
            if name not in blocks:
                raise RuntimeError(f"Unknown generated block provider in rules.yaml: {name}")
            if (GENERATED / "domain" / f"{name}.mrs").exists():
                lines.append(f"  - RULE-SET,{name},REJECT")
                covered_domains.add(name)
                if name in actual_classical:
                    lines.append(f"  - RULE-SET,{name}{suffix},REJECT")
                    covered_classical.add(name)
            continue
        if kind == "domain":
            if name in excluded:
                continue
            if name not in domains:
                raise RuntimeError(f"Generated domain provider {name!r} has no target in settings/rules.yaml")
            if (GENERATED / "domain" / f"{name}.mrs").exists():
                lines.append(f"  - RULE-SET,{name},{domains[name]}")
                covered_domains.add(name)
                # Keywords / regexes of the same category follow the same target.
                if name in actual_classical:
                    lines.append(f"  - RULE-SET,{name}{suffix},{domains[name]}")
                    covered_classical.add(name)
            continue
        if kind == "ip":
            if name in excluded:
                continue
            if name not in ips:
                raise RuntimeError(f"Generated IP provider {name!r} has no target in settings/rules.yaml")
            if (GENERATED / "ip" / f"{name}.mrs").exists():
                lines.append(f"  - RULE-SET,{name}-ip,{ips[name]},no-resolve")
                covered_ips.add(name)
            continue
        raise RuntimeError(f"Unknown generated rule kind: {kind}")

    missing_domains = sorted(actual_domains - covered_domains - set(excluded))
    missing_ips = sorted(actual_ips - covered_ips - set(excluded))
    missing_classical = sorted(actual_classical - covered_classical - set(excluded))
    if missing_domains or missing_ips or missing_classical:
        msg=[]
        if missing_domains: msg.append("domain: " + ", ".join(missing_domains))
        if missing_ips: msg.append("ip: " + ", ".join(missing_ips))
        if missing_classical: msg.append("classical: " + ", ".join(f"{n}{suffix}" for n in missing_classical))
        raise RuntimeError("Generated rulesets are not referenced by settings/rules.yaml: " + "; ".join(msg))

    return "\n".join(lines)


def render_hosts(publish_host_overrides: bool) -> str:
    if not publish_host_overrides:
        # MALW non-blocking IP mappings are intentionally not emitted as Mihomo
        # hosts overrides. MALW blocking domains are still provided by malw-block.
        return "# MALW IP/hosts overrides intentionally disabled; blocking domains remain in malw-block."

    path = GENERATED / "malw/hosts.yaml"
    if not path.exists():
        return "# MALW hosts override source is enabled, but generated/malw/hosts.yaml is missing."
    data = load_yaml(path)
    hosts = data.get("hosts", {})
    if not isinstance(hosts, dict):
        raise RuntimeError(f"{path}: hosts must be a mapping")
    return render_yaml_block({"hosts": hosts})

def validate_profile_yaml(text: str, profile_path: Path, manual_files: list[Path]) -> None:
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise RuntimeError(f"{profile_path}: root YAML value must be a mapping")
    providers = data.get("rule-providers", {})
    if not isinstance(providers, dict):
        raise RuntimeError(f"{profile_path}: rule-providers must be a mapping")
    rules = data.get("rules", [])
    referenced = extract_rule_set_names(rules)
    missing = referenced - set(providers)
    if missing:
        raise RuntimeError(f"{profile_path}: rules reference missing rule-providers: {', '.join(sorted(missing))}")
    policy = (data.get("dns") or {}).get("nameserver-policy") or {}
    for key in policy:
        if str(key).startswith("rule-set:"):
            unknown = [n for n in str(key)[len("rule-set:"):].split(",") if n not in providers]
            if unknown:
                raise RuntimeError(f"{profile_path}: dns.nameserver-policy references missing rule-providers: {', '.join(unknown)}")
    for warning in warp_proxies.check_proxies(data, profile_path.name):
        print(f"::warning::{warning}")
    for path in manual_files:
        if not path.exists():
            raise RuntimeError(f"{profile_path}: required manual ruleset is missing: {path.relative_to(ROOT)}")

def main() -> int:
    repos = load_yaml(SETTINGS / "repositories.yaml")
    build_cfg = load_yaml(SETTINGS / "build.yaml")
    dns_cfg = load_yaml(SETTINGS / "dns.yaml")
    core = load_yaml(SETTINGS / "core.yaml")
    tun_base = load_yaml(SETTINGS / "tun.yaml")["tun"]
    account = warp_proxies.load_warp_account(SETTINGS / "warp-account.yaml")
    profiles_cfg = load_yaml(SETTINGS / "profiles.yaml")
    amnezia = warp_proxies.load_amnezia(SETTINGS / "amnezia.yaml")
    publish_host_overrides = bool(build_cfg.get("malw", {}).get("publish_host_overrides", False))

    pat_env = repos["github"]["pat_env"]
    pat = os.environ.get(pat_env, "").strip()
    if not pat:
        raise RuntimeError(f"Missing required environment variable {pat_env}")

    private_raw_base = repos["github"]["raw_base"].rstrip("/")
    packages = load_package_list(ROOT / PACKAGE_LIST)
    tun = tun_with_package_url(
        tun_base,
        package_list_url(private_raw_base, repos["github"]["owner"], pat, PACKAGE_LIST) if packages else None,
    )
    runtime = profiles_cfg.get("runtime", {})

    for output_name, profile in profiles_cfg["profiles"].items():
        if not profile.get("enabled", True):
            print(f"Skipping disabled profile: {output_name}")
            continue

        template = ROOT / profile["template"]
        if not template.exists():
            raise RuntimeError(f"Enabled profile template not found: {template}")

        text = template.read_text(encoding="utf-8")
        text = replace_block(
            text,
            "# === BEGIN GITHUB AUTH (auto-generated from CLASH_GITHUB_PAT secret — do not edit) ===",
            "# === END GITHUB AUTH ===",
            render_auth(pat, repos["github"].get("authorization_scheme", "token")),
        )
        text = replace_block(
            text,
            "# === BEGIN HOSTS (MALW IP overrides intentionally disabled — do not edit) ===",
            "# === END HOSTS ===",
            render_hosts(publish_host_overrides),
        )
        excluded = set(profile.get("exclude_rule_providers", []))
        dns, warp_dns = resolve_dns(dns_cfg, excluded)
        text = replace_block(
            text,
            "# === BEGIN CORE (auto-generated from settings/core.yaml — do not edit) ===",
            "# === END CORE ===",
            render_yaml_block(core),
        )
        text = replace_block(
            text,
            "# === BEGIN DNS (auto-generated from settings/dns.yaml — do not edit) ===",
            "# === END DNS ===",
            render_yaml_block({"dns": dns}),
        )
        text = replace_block(
            text,
            "# === BEGIN WARP ANCHORS (auto-generated from settings/warp-account.yaml — do not edit) ===",
            "# === END WARP ANCHORS ===",
            warp_proxies.render_warp_anchors(account, warp_dns),
        )
        text = replace_block(
            text,
            "# === BEGIN TUN (auto-generated from settings/tun.yaml — do not edit) ===",
            "# === END TUN ===",
            render_yaml_block({"tun": tun}),
        )
        endpoint_types = warp_proxies.validate_types(list(profile.get("endpoints", list(warp_proxies.TYPES))))
        text = replace_block(
            text,
            "# === BEGIN AMNEZIA ANCHORS (auto-generated from settings/amnezia.yaml — do not edit) ===",
            "# === END AMNEZIA ANCHORS ===",
            warp_proxies.render_amnezia_anchors(amnezia),
        )
        text = replace_block(
            text,
            "# === BEGIN WARP PROXIES (auto-generated from proxies/*.yaml — do not edit) ===",
            "# === END WARP PROXIES ===",
            warp_proxies.render_warp(PROXIES, endpoint_types, amnezia, clone_dns=gemini_resolver_url(dns_cfg)),
        )
        text = warp_proxies.prune_filters(text, endpoint_types)
        text = replace_block(
            text,
            "# === BEGIN RULE-PROVIDERS (auto-generated by tools/config-builder/build_profiles.py — do not edit) ===",
            "# === END RULE-PROVIDERS ===",
            render_providers(profile, profiles_cfg, private_raw_base, excluded),
            legacy_begin="# === BEGIN RULE-PROVIDERS (auto-generated from settings/rule-providers.json — do not edit) ===",
        )
        text = replace_block(
            text,
            "# === BEGIN RULES (auto-generated from settings/rules.yaml — do not edit) ===",
            "# === END RULES ===",
            render_ordered_rules(excluded),
            legacy_begin="# === BEGIN RULES (auto-generated from settings/rules.json — do not edit) ===",
        )

        manual_dir = ROOT / user_rules_dir(profile)
        manual_files = [manual_dir / f"{name}.yaml" for name in USER_RULESETS]
        validate_profile_yaml(text, ROOT / output_name, manual_files)

        output = ROOT / output_name
        old = output.read_text(encoding="utf-8") if output.exists() else None
        if old != text:
            output.write_text(text, encoding="utf-8", newline="\n")
            print(f"Updated {output_name}")
        else:
            print(f"Up to date: {output_name}")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
