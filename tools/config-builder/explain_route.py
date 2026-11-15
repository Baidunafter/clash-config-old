#!/usr/bin/env python3
"""Show which rule of a generated profile a domain matches, offline.

    explain_route.py WARPxUNIVERSAL.yaml gemini.google.com accounts.google.com ...

Reads the profile's `rules` in order and the rule sets from the files of this
repository (generated/source, generated/classical, profiles/<dir>, mirrored YAML).
Sets that exist only as binary .mrs (the mirrored roscomvpn lists) cannot be read;
if one of them comes before the match, the answer is marked "uncertain".
No packet is sent and Mihomo is not needed. Domains only (IP rules are skipped).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]


def _suffix_match(domain: str, entry: str) -> bool:
    return domain == entry or domain.endswith("." + entry)


class RuleSets:
    """Domain matchers for the providers of one profile, backed by repository files."""

    def __init__(self, root: Path, profile: dict[str, Any]):
        self.root = root
        self.providers = profile.get("rule-providers") or {}
        self.cache: dict[str, Any] = {}

    def _load(self, name: str) -> Any:
        """Return a callable(domain) -> bool, or None when the set cannot be read."""
        provider = self.providers.get(name)
        if provider is None:
            return None
        if provider.get("behavior") == "ipcidr":
            return lambda domain: False  # IP sets never match a domain lookup
        # Generated domain sets also exist as readable text next to their .mrs.
        text_file = self.root / "generated/source/domain" / f"{name}.txt"
        if text_file.is_file():
            entries = {line[2:] for line in text_file.read_text(encoding="utf-8").splitlines() if line.startswith("+.")}
            return lambda domain: any(_suffix_match(domain, e) for e in entries)
        # Classical YAML lists (keywords, user lists, ru-apps) live in this repository.
        found = re.search(r"/((?:generated|profiles)/.+\.ya?ml)$", str(provider.get("url", "")))
        if found and (self.root / found.group(1)).is_file():
            payload = (yaml.safe_load((self.root / found.group(1)).read_text(encoding="utf-8")) or {}).get("payload") or []
            return lambda domain: any(self._classical(domain, str(item)) for item in payload)
        return None  # mirrored binary .mrs set

    @staticmethod
    def _classical(domain: str, item: str) -> bool:
        kind, _, value = item.partition(",")
        value = value.split(",", 1)[0].strip() if kind.upper() != "DOMAIN-REGEX" else value.strip()
        kind = kind.strip().upper()
        if kind == "DOMAIN-SUFFIX":
            return _suffix_match(domain, value.lower())
        if kind == "DOMAIN":
            return domain == value.lower()
        if kind == "DOMAIN-KEYWORD":
            return value.lower() in domain
        if kind == "DOMAIN-REGEX":
            return re.search(value, domain) is not None
        return False  # IP and PROCESS rules do not apply to a domain lookup

    def matcher(self, name: str) -> Any:
        if name not in self.cache:
            self.cache[name] = self._load(name)
        return self.cache[name]


def explain(profile: dict[str, Any], domain: str, root: Path = ROOT) -> dict[str, Any]:
    domain = domain.strip().lower().rstrip(".")
    sets = RuleSets(root, profile)
    unreadable: list[str] = []
    for index, rule in enumerate(profile.get("rules") or []):
        parts = [p.strip() for p in str(rule).split(",")]
        kind = parts[0].upper()
        target = parts[-1] if parts[-1] not in ("no-resolve", "src") else parts[-2]
        matched = False
        if kind == "RULE-SET":
            matcher = sets.matcher(parts[1])
            if matcher is None:
                unreadable.append(parts[1])
                continue
            matched = matcher(domain)
        elif kind == "DOMAIN-SUFFIX":
            matched = _suffix_match(domain, parts[1].lower())
        elif kind == "DOMAIN":
            matched = domain == parts[1].lower()
        elif kind == "DOMAIN-KEYWORD":
            matched = parts[1].lower() in domain
        elif kind == "MATCH":
            matched = True
        # AND/OR, IP-CIDR, GEOIP, ... cannot be decided from a domain name alone
        if matched:
            return {"domain": domain, "index": index, "rule": rule, "target": target, "uncertain": unreadable}
    return {"domain": domain, "index": None, "rule": None, "target": None, "uncertain": unreadable}


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    profile = yaml.safe_load((ROOT / argv[1]).read_text(encoding="utf-8"))
    unreadable: set[str] = set()
    for domain in argv[2:]:
        result = explain(profile, domain)
        unreadable.update(result["uncertain"])
        print(f"{result['domain']:42} -> {str(result['target']):14} #{result['index']}  {result['rule']}")
    if unreadable:
        print(f"\nNot evaluated (binary .mrs, could take precedence): {', '.join(sorted(unreadable))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
