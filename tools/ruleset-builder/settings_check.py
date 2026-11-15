#!/usr/bin/env python3
"""Validate settings/*.yaml and categories.yaml before anything is downloaded.

Typos in these files otherwise surface halfway through a build (or silently
change routing). Pure Python, no extra dependencies. Run: settings_check.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

import yaml

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "config-builder"))

import warp_proxies  # noqa: E402
from source_utils import LOCAL_SOURCE, RESERVED_CATEGORY_KEYS, SOURCE_KEYS, source_url  # noqa: E402

GROUPS = ("services", "categories", "ip_categories")
RULE_KINDS = {"block", "domain", "ip"}


def _load(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _is_str_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(v, str) for v in value)


def check_categories(categories: dict[str, Any], sources: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    seen: dict[str, str] = {}
    for group in ("services", "categories"):
        for name, mapping in (categories.get(group) or {}).items():
            if name in seen:
                problems.append(f"categories.yaml: '{name}' is defined in both {seen[name]} and {group}")
            seen[name] = group
    for group in GROUPS:
        if not isinstance(categories.get(group) or {}, dict):
            problems.append(f"categories.yaml: '{group}' must be a mapping")
            continue
        for name, mapping in (categories.get(group) or {}).items():
            label = f"categories.yaml {group}/{name}"
            if not isinstance(mapping, dict) or not mapping:
                problems.append(f"{label}: must be a non-empty mapping")
                continue
            for key, value in mapping.items():
                if key == "optional":
                    if not isinstance(value, bool):
                        problems.append(f"{label}: optional must be true/false")
                elif key == "exclude_domains":
                    if isinstance(value, dict):
                        for source, items in value.items():
                            if source not in SOURCE_KEYS and source not in ("all", "malw", LOCAL_SOURCE):
                                problems.append(f"{label}: exclude_domains has unknown source '{source}'")
                            if not _is_str_list(items):
                                problems.append(f"{label}: exclude_domains.{source} must be a list of strings")
                    elif not _is_str_list(value):
                        problems.append(f"{label}: exclude_domains must be a list or a source mapping")
                elif key == "malw":
                    if group == "ip_categories":
                        problems.append(f"{label}: malw is not an IP source")
                    for entry in value or []:
                        if not (isinstance(entry, str) or _is_str_list(entry)):
                            problems.append(f"{label}: malw entries are strings or lists of strings, got {entry!r}")
                elif key == LOCAL_SOURCE:
                    if group == "ip_categories":
                        problems.append(f"{label}: local lists are domain lists, not IP lists")
                    if not _is_str_list(value):
                        problems.append(f"{label}: local must be a list of file names")
                        continue
                    for rel in value:
                        if not (HERE / "lists" / rel).is_file():
                            problems.append(f"{label}: tools/ruleset-builder/lists/{rel} does not exist")
                elif key in SOURCE_KEYS:
                    if not _is_str_list(value):
                        problems.append(f"{label}: {key} must be a list of strings")
                        continue
                    for rel in value:
                        try:
                            source_url(sources, key, rel)
                        except ValueError as exc:
                            problems.append(f"{label}: {exc}")
                elif key not in RESERVED_CATEGORY_KEYS:
                    problems.append(f"{label}: unknown key '{key}'")
    return problems


def check_rules(rules: dict[str, Any], categories: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    targets = rules.get("generated_targets") or {}
    ip_targets = rules.get("generated_ip_targets") or {}
    blocks = rules.get("generated_blocks") or []
    domain_categories = set((categories.get("services") or {})) | set((categories.get("categories") or {}))
    ip_categories = set(categories.get("ip_categories") or {})

    for name, target in targets.items():
        if not isinstance(target, str) or not target:
            problems.append(f"rules.yaml: generated_targets.{name} must be a group name")
        if name not in domain_categories:
            problems.append(f"rules.yaml: generated_targets.{name} is not a category in categories.yaml")
    for name in ip_targets:
        if name not in ip_categories:
            problems.append(f"rules.yaml: generated_ip_targets.{name} is not an ip_category")
    for name in blocks:
        if name not in domain_categories:
            problems.append(f"rules.yaml: generated_blocks entry '{name}' is not a category")

    used: dict[str, set[str]] = {k: set() for k in RULE_KINDS}
    for index, entry in enumerate(rules.get("ordered_rules") or []):
        if isinstance(entry, str):
            continue
        if not (isinstance(entry, dict) and len(entry) == 1 and next(iter(entry)) in RULE_KINDS):
            problems.append(f"rules.yaml: ordered_rules[{index}] must be a string or one of {sorted(RULE_KINDS)}: {entry!r}")
            continue
        (kind, name), = entry.items()
        used[kind].add(name)
        known = {"block": set(blocks), "domain": set(targets), "ip": set(ip_targets)}[kind]
        if name not in known:
            problems.append(f"rules.yaml: ordered_rules[{index}] '{kind}: {name}' has no target in generated_{'targets' if kind == 'domain' else 'ip_targets' if kind == 'ip' else 'blocks'}")
    return problems


BUILTIN_TARGETS = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"}
_RULE_OPTIONS = {"no-resolve", "src"}


def rule_target(rule: str) -> str | None:
    """Target (last field, without no-resolve/src) of a Clash rule string."""
    parts = [p.strip() for p in rule.split(",")]
    while len(parts) > 1 and parts[-1] in _RULE_OPTIONS:
        parts.pop()
    return parts[-1] if len(parts) >= 2 else None


def check_rule_targets(rules: dict[str, Any], groups: set[str]) -> list[str]:
    """A typo in a group name would only fail when Mihomo loads the profile."""
    allowed = groups | BUILTIN_TARGETS
    problems: list[str] = []
    targets = [("generated_targets." + k, v) for k, v in (rules.get("generated_targets") or {}).items()]
    targets += [("generated_ip_targets." + k, v) for k, v in (rules.get("generated_ip_targets") or {}).items()]
    for index, entry in enumerate(rules.get("ordered_rules") or []):
        if isinstance(entry, str) and (target := rule_target(entry)) is not None:
            targets.append((f"ordered_rules[{index}]", target))
    for where, target in targets:
        if target not in allowed:
            problems.append(f"rules.yaml: {where} points at '{target}', which is not a proxy group in the template")
    return problems


def template_groups(profiles_cfg: dict[str, Any], root: Path) -> set[str]:
    groups: set[str] = set()
    for profile in (profiles_cfg.get("profiles") or {}).values():
        path = root / str(profile.get("template", ""))
        if path.is_file():
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            groups |= {str(g.get("name")) for g in data.get("proxy-groups") or []}
    return groups


def check_profiles(profiles_cfg: dict[str, Any], root: Path) -> list[str]:
    problems: list[str] = []
    profiles = profiles_cfg.get("profiles")
    if not isinstance(profiles, dict) or not profiles:
        return ["profiles.yaml: 'profiles' must be a non-empty mapping"]
    for output, profile in profiles.items():
        label = f"profiles.yaml {output}"
        if not output.endswith(".yaml"):
            problems.append(f"{label}: output name must end with .yaml")
        template = root / str(profile.get("template", ""))
        if not template.is_file():
            problems.append(f"{label}: template not found: {profile.get('template')}")
        directory = str(profile.get("user_rules_dir", "")).strip("/")
        if not directory:
            problems.append(f"{label}: user_rules_dir is required")
        else:
            for name in ("user-exclude", "user-geo-block"):
                if not (root / directory / f"{name}.yaml").is_file():
                    problems.append(f"{label}: {directory}/{name}.yaml is missing")
        try:
            warp_proxies.validate_types(list(profile.get("endpoints", list(warp_proxies.TYPES))))
        except RuntimeError as exc:
            problems.append(f"{label}: {exc}")
        if not isinstance(profile.get("exclude_rule_providers", []), list):
            problems.append(f"{label}: exclude_rule_providers must be a list")
    interval = (profiles_cfg.get("runtime") or {}).get("rule_provider_interval", 86400)
    if not isinstance(interval, int) or interval < 300:
        problems.append("profiles.yaml: runtime.rule_provider_interval must be an integer >= 300")
    return problems


def check_mirror(mirror_cfg: dict[str, Any], providers: dict[str, Any], sources: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    mirrors = (mirror_cfg or {}).get("mirror") or {}
    for name, spec in mirrors.items():
        if not isinstance(spec, dict) or "source" not in spec or "path" not in spec:
            problems.append(f"mirror.yaml: '{name}' needs source and path")
            continue
        try:
            source_url(sources, spec["source"], spec["path"])
        except ValueError as exc:
            problems.append(f"mirror.yaml: {name}: {exc}")
    for item in (providers or {}).get("static") or []:
        for key in ("name", "behavior"):
            if key not in item:
                problems.append(f"rule-providers.yaml: static entry without '{key}': {item}")
        if item.get("mirror") and item["mirror"] not in mirrors:
            problems.append(f"rule-providers.yaml: '{item.get('name')}' references unknown mirror '{item['mirror']}'")
        if not item.get("mirror") and not (item.get("url") and item.get("path")):
            problems.append(f"rule-providers.yaml: '{item.get('name')}' needs mirror or url+path")
    return problems


_PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+$")


def check_package_list(path: Path) -> list[str]:
    """packages/exclude-from-vpn.txt is read as is by the client: names only, no comments."""
    if not path.is_file():
        return []
    problems: list[str] = []
    seen: list[str] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        name = line.strip()
        if not name:
            continue
        if not _PACKAGE_RE.match(name):
            problems.append(f"{path.name}:{number}: '{name}' is not an Android package name (comments are not allowed)")
        elif name in seen:
            problems.append(f"{path.name}:{number}: '{name}' is listed twice")
        seen.append(name)
    return problems


def check_build(build_cfg: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    mihomo = build_cfg.get("mihomo") or {}
    for key in ("version", "asset", "sha256"):
        if not mihomo.get(key):
            problems.append(f"build.yaml: mihomo.{key} is required")
    guard = build_cfg.get("guard") or {}
    pct = guard.get("max_shrink_percent", 40)
    if not isinstance(pct, (int, float)) or not 0 < pct <= 100:
        problems.append("build.yaml: guard.max_shrink_percent must be a number in (0, 100]")
    if not isinstance(guard.get("allow_shrink", []), list):
        problems.append("build.yaml: guard.allow_shrink must be a list")
    return problems


# Files and folders that earlier versions of this repository used. A zip or a copy of changed
# files cannot delete anything, so they can linger; nothing reads them any more.
OBSOLETE = (
    "settings/tun-exclude-packages.yaml",  # replaced by packages/exclude-from-vpn.txt
    "templates/WARPxALT.yaml",             # one shared templates/profile.yaml
    "templates/WARPxUNIVERSAL.yaml",
    "ruleset",                             # user lists live in profiles/<name>/
    "ruleset-alt",
)


def obsolete_files(root: Path) -> list[str]:
    return [name for name in OBSOLETE if (root / name).exists()]


def validate_all(root: Path) -> list[str]:
    settings = root / "settings"
    repos = _load(settings / "repositories.yaml")
    sources = repos["sources"]
    categories = _load(root / "tools/ruleset-builder/categories.yaml")
    mirror_path = settings / "mirror.yaml"
    problems: list[str] = []
    problems += check_categories(categories, sources)
    rules = _load(settings / "rules.yaml")
    profiles_cfg = _load(settings / "profiles.yaml")
    problems += check_rules(rules, categories)
    problems += check_rule_targets(rules, template_groups(profiles_cfg, root))
    problems += check_profiles(profiles_cfg, root)
    problems += check_mirror(_load(mirror_path) if mirror_path.exists() else {}, _load(settings / "rule-providers.yaml"), sources)
    problems += check_build(_load(settings / "build.yaml"))
    problems += check_package_list(root / "packages/exclude-from-vpn.txt")
    return problems


def main() -> int:
    root = HERE.parents[1]
    for name in obsolete_files(root):
        # a warning only: the build ignores these, deleting them just removes confusion
        print(f"::warning::{name} is obsolete and unused; delete it (git rm -r {name})")
    problems = validate_all(root)
    if problems:
        print("Settings check FAILED:", file=sys.stderr)
        for problem in problems:
            print(f"- {problem}", file=sys.stderr)
        return 2
    print("Settings check PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
