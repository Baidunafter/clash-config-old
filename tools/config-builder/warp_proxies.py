#!/usr/bin/env python3
"""Render the WARP proxy list of a profile from proxies/*.yaml.

A profile selects endpoint types with ``endpoints:`` in settings/profiles.yaml.
Proxy names carry a marker (``[🌍]`` geo, ``[⭐]`` origin, ``[☁️]`` default,
``[🎭]`` masque). Proxy-group filters in the template list these markers, so
markers of endpoint types a profile does not use are removed from the filters.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml

# order = order in the generated profile
TYPES: dict[str, dict[str, str]] = {
    "geo": {"file": "geo-endpoint.yaml", "label": "geo-endpoint", "marker": "🌍", "anchor": "warp-common"},
    "origin": {"file": "origin-endpoint.yaml", "label": "origin-endpoint", "marker": "⭐", "anchor": "warp-common"},
    "default": {"file": "default-endpoint.yaml", "label": "default-endpoint", "marker": "☁️", "anchor": "warp-common"},
    "masque": {"file": "masque-endpoint.yaml", "label": "masque", "marker": "🎭", "anchor": "warp-masque"},
}
ALT_VARIANTS = ["alt1", "alt2", "alt3"]
MASQUE_ANCHOR = "warp-masque"
# "[🌍 MQ] ..." marks a MASQUE (QUIC, port 443) node in any endpoint file: it is rendered with the
# warp-masque anchor instead of the warp-common (WireGuard) one of its endpoint type.
_MQ_RE = re.compile(r"^\[[^\]]*\bMQ\b[^\]]*\]")
_MERGE_RE = re.compile(r"^\s*<<:\s*\*warp-(?:common|masque)\s*$", re.MULTILINE)
_FILTER_RE = re.compile(r"^(?P<indent>\s*)filter:\s*(?P<q>['\"])(?P<value>.*)(?P=q)\s*$", re.MULTILINE)


def quote(name: str) -> str:
    return '"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'


def node_anchor(type_key: str, name: str) -> str:
    """YAML anchor a node inherits: masque for `[... MQ]` nodes, else the endpoint type's own."""
    return MASQUE_ANCHOR if _MQ_RE.match(name) else TYPES[type_key]["anchor"]


def alt_name(name: str, n: int) -> str:
    prefix, rest = "", name
    if name.startswith("[") and "] " in name:
        i = name.index("] ") + 2
        prefix, rest = name[:i], name[i:]
    return f"{prefix}(Alt {n}) {rest}"


def validate_types(types: list[str]) -> list[str]:
    unknown = [t for t in types if t not in TYPES]
    if unknown:
        raise RuntimeError(f"Unknown endpoint type(s): {', '.join(unknown)}. Expected: {', '.join(TYPES)}")
    if not types:
        raise RuntimeError("A profile needs at least one endpoint type")
    return [t for t in TYPES if t in types]  # canonical order, duplicates removed


def load_nodes(proxies_dir: Path, type_key: str) -> list[dict[str, Any]]:
    raw = (proxies_dir / TYPES[type_key]["file"]).read_text(encoding="utf-8")
    data = yaml.safe_load(_MERGE_RE.sub("", raw)) or {}
    nodes = data.get("proxies", []) or []
    for node in nodes:
        for key in ("name", "server", "port"):
            if key not in node:
                raise RuntimeError(f"{TYPES[type_key]['file']}: entry without '{key}': {node}")
    return nodes


def load_amnezia(path: Path) -> dict[str, Any]:
    return (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("amnezia", {}) or {}


def render_amnezia_anchors(amnezia: dict[str, Any]) -> str:
    lines = ["amnezia-common: &amnezia-common"]
    for key, value in amnezia.get("base", {}).items():
        lines.append(f"  {key}: {value}")
    lines.append("")
    for variant, data in amnezia.items():
        if variant == "base":
            continue
        for slot in ("i1", "i2"):
            if slot in data:
                lines.append(f"{slot}-{variant}: &{slot}-{variant} {data[slot]}")
    return "\n".join(lines)


_NAME_RE = re.compile(r"^\[(?P<marker>[^\]]*)\]\s*(?P<rest>.*)$")
CLONE_PREFIX = "GM"


def clone_name(name: str) -> str:
    """`[🌍 MQ] 🇳🇱 Нидерланды` -> `[GM MQ] 🇳🇱 Нидерланды`, `[⭐] FRA #1:4500` -> `[GM] FRA #1:4500`.

    The prefix contains none of the endpoint markers, so group filters written for the
    markers never pick a copy up by accident.
    """
    match = _NAME_RE.match(name)
    rest = match.group("rest") if match else name
    masque = bool(match and re.search(r"\bMQ\b", match.group("marker")))
    return f"[{CLONE_PREFIX} MQ] {rest}" if masque else f"[{CLONE_PREFIX}] {rest}"


def _emit(lines: list[str], marker: str, anchor: str, node: dict[str, Any], name: str | None = None,
          amnezia: dict[str, Any] | None = None, variant: str | None = None, dns: list[str] | None = None) -> None:
    name = name if name is not None else str(node["name"])
    if not name.startswith("["):
        name = f"[{marker}] {name}"
    lines.append(f"  - name: {quote(name)}")
    lines.append(f"    <<: *{anchor}")
    lines.append(f"    server: {node['server']}")
    lines.append(f"    port: {node['port']}")
    for key, value in node.items():
        if key not in ("name", "server", "port"):
            lines.append(f"    {key}: {value}")
    if dns:  # an explicit key overrides the dns of the merged anchor
        lines.append("    dns:")
        lines.extend(f"      - {_scalar(item)}" for item in dns)
    if variant is not None:
        lines.append("    amnezia-wg-option:")
        lines.append("      <<: *amnezia-base")
        lines.append(f"      i1: *i1-{variant}")
        if "i2" in (amnezia or {}).get(variant, {}):
            lines.append(f"      i2: *i2-{variant}")


def render_warp(proxies_dir: Path, types: list[str], amnezia: dict[str, Any], clone_dns: str | None = None) -> str:
    lines: list[str] = []
    for type_key in validate_types(types):
        spec = TYPES[type_key]
        lines.append(f"  # ── {spec['label']} ──")
        nodes = load_nodes(proxies_dir, type_key)
        alt_for: dict[int, int] = {}
        if type_key == "origin":  # the first three :4500 nodes also get an obfuscation variant
            for idx, node in enumerate(nodes):
                if len(alt_for) >= len(ALT_VARIANTS):
                    break
                if str(node["name"]).endswith(":4500"):
                    alt_for[idx] = len(alt_for)
        for idx, node in enumerate(nodes):
            anchor = node_anchor(type_key, str(node["name"]))
            _emit(lines, spec["marker"], anchor, node)
            if idx in alt_for and anchor == spec["anchor"]:  # obfuscation variants belong to WireGuard nodes
                n = alt_for[idx]
                _emit(lines, spec["marker"], anchor, node, name=alt_name(str(node["name"]), n + 1),
                      amnezia=amnezia, variant=ALT_VARIANTS[n])
    if clone_dns:
        # A proxy group has no DNS of its own in Mihomo: a node resolves names through the `dns`
        # of its own definition. Copies of the nodes with another `dns` give a group its resolver.
        lines.append(f"  # ── copies with dns {clone_dns} ──")
        for type_key in validate_types(types):
            spec = TYPES[type_key]
            for node in load_nodes(proxies_dir, type_key):
                original = str(node["name"])
                if not original.startswith("["):
                    original = f"[{spec['marker']}] {original}"
                _emit(lines, spec["marker"], node_anchor(type_key, original), node, name=clone_name(original), dns=[clone_dns])
    return "\n".join(lines)


def prune_filters(text: str, types: list[str]) -> str:
    """Drop markers of unused endpoint types from `filter: "a|b|c"` lines."""
    enabled = set(validate_types(types))
    unused = {spec["marker"] for key, spec in TYPES.items() if key not in enabled}

    def repl(match: re.Match[str]) -> str:
        parts = match.group("value").split("|")
        kept = [p for p in parts if p not in unused]
        if kept == parts:
            return match.group(0)
        if not kept:
            raise RuntimeError(f"Filter '{match.group('value')}' matches only endpoint types this profile does not use")
        q = match.group("q")
        return f"{match.group('indent')}filter: {q}{'|'.join(kept)}{q}"

    return _FILTER_RE.sub(repl, text)


def check_proxies(profile: dict[str, Any], profile_name: str) -> list[str]:
    """Hard errors for impossible configs, warnings (returned) for suspicious ones."""
    proxies = profile.get("proxies") or []
    names = [str(p.get("name")) for p in proxies]
    duplicates = sorted({n for n in names if names.count(n) > 1})
    if duplicates:
        raise RuntimeError(f"{profile_name}: duplicate proxy names: {', '.join(duplicates)}")
    warnings: list[str] = []
    for group in profile.get("proxy-groups") or []:
        pattern = group.get("filter")
        if not pattern:
            continue
        try:
            regex = re.compile(pattern)
        except re.error as exc:
            raise RuntimeError(f"{profile_name}: group '{group.get('name')}' has an invalid filter: {exc}") from exc
        if not any(regex.search(n) for n in names):
            warnings.append(f"{profile_name}: group '{group.get('name')}' filter matches no proxy")
    return warnings


def _scalar(value: Any) -> str:
    """YAML text of a scalar or flow list (quotes only where YAML needs them)."""
    text = yaml.safe_dump(value, default_flow_style=True, allow_unicode=True, width=10_000).strip()
    return text[:-4].rstrip() if text.endswith("\n...") else text


def load_warp_account(path: Path, environ: dict[str, str] | None = None) -> dict[str, Any]:
    """Load settings/warp-account.yaml; WARP_*_PRIVATE_KEY env variables override the keys."""
    env = os.environ if environ is None else environ
    account = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    for section, variable in (("wireguard", "WARP_WG_PRIVATE_KEY"), ("masque", "WARP_MASQUE_PRIVATE_KEY")):
        if section not in account:
            raise RuntimeError(f"{path.name}: missing '{section}' section")
        override = (env.get(variable) or "").strip()
        if override:
            account[section]["private-key"] = override
        for key in ("private-key", "public-key", "ip"):
            if not account[section].get(key):
                raise RuntimeError(f"{path.name}: {section}.{key} is empty")
    return account


def render_warp_anchors(account: dict[str, Any], dns: list[str]) -> str:
    """The warp-common / warp-masque anchors, with the profile's DoH servers as `dns`."""
    wg, masque = account["wireguard"], account["masque"]
    dns_lines = ["  dns:"] + [f"    - {_scalar(str(item))}" for item in dns]
    lines = ["warp-common: &warp-common", "  type: wireguard"]
    for key in ("ip", "ipv6", "private-key", "public-key", "reserved"):
        if key in wg:
            lines.append(f"  {key}: {_scalar(wg[key])}")
    lines += ["  allowed-ips: ['0.0.0.0/0', '::/0']", "  udp: true", f"  mtu: {int(wg.get('mtu', 1280))}", "  remote-dns-resolve: true"]
    lines += dns_lines
    lines += ["  amnezia-wg-option: &amnezia-base", "    <<: *amnezia-common", "    i1: *i1-default", "",
              "warp-masque: &warp-masque", "  type: masque"]
    for key in ("sni", "private-key", "public-key", "ip", "ipv6"):
        if key in masque:
            lines.append(f"  {key}: {_scalar(masque[key])}")
    lines += ["  udp: true", "  remote-dns-resolve: true"] + dns_lines
    return "\n".join(lines)
