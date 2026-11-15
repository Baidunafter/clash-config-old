#!/usr/bin/env python3
"""Find routing conflicts between aggregated categories.

Two reports, both informational (warnings, never build failures):

* direct_overlap: domains of a category routed through a proxy group that are also
  in the Russian direct lists (roscomvpn category-ru / whitelist). A broad
  third-party list is the usual source; these are candidates for exclude_domains.
* target_conflicts: the same domain entry in several categories whose rules lead
  to different targets. Only the first rule in `ordered_rules` applies.

Matching is by suffix for the direct lists (a listed parent covers its
sub-domains) and by exact entry between categories.
"""
from __future__ import annotations

from typing import Any

EXAMPLES = 10


def covered_by(domain: str, suffixes: set[str]) -> str | None:
    """Return the entry of ``suffixes`` equal to ``domain`` or one of its parents."""
    parts = domain.split(".")
    for index in range(len(parts) - 1):  # never match a bare TLD
        candidate = ".".join(parts[index:])
        if candidate in suffixes:
            return candidate
    return None


def rule_order(ordered_rules: list[Any]) -> list[tuple[str, str]]:
    """``[(category, kind)]`` in rule order for `domain:` and `block:` entries."""
    order: list[tuple[str, str]] = []
    for entry in ordered_rules:
        if isinstance(entry, dict) and len(entry) == 1:
            (kind, name), = entry.items()
            if kind in ("domain", "block"):
                order.append((name, kind))
    return order


def category_targets(rules: dict[str, Any]) -> dict[str, str]:
    targets = dict(rules.get("generated_targets") or {})
    for name in rules.get("generated_blocks") or []:
        targets[name] = "REJECT"
    return targets


def direct_overlap(domain_sets: dict[str, set[str]], targets: dict[str, str], direct_domains: set[str]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for name, domains in sorted(domain_sets.items()):
        if targets.get(name, "DIRECT") in ("DIRECT", "REJECT"):
            continue
        hits = sorted((d, covered_by(d, direct_domains)) for d in domains if covered_by(d, direct_domains))
        if hits:
            result[name] = {"count": len(hits), "examples": [f"{d} (direct list: {parent})" for d, parent in hits[:EXAMPLES]]}
    return result


def target_conflicts(domain_sets: dict[str, set[str]], order: list[tuple[str, str]], targets: dict[str, str]) -> list[dict[str, Any]]:
    position = {name: index for index, (name, _) in enumerate(order) if name in domain_sets}
    owners: dict[str, list[str]] = {}
    for name in position:
        for domain in domain_sets[name]:
            owners.setdefault(domain, []).append(name)

    pairs: dict[tuple[str, str], list[str]] = {}
    for domain, names in owners.items():
        if len(names) < 2:
            continue
        names.sort(key=position.__getitem__)
        winner = names[0]
        for loser in names[1:]:
            if targets.get(winner) != targets.get(loser):
                pairs.setdefault((winner, loser), []).append(domain)

    rows = [{"winner": w, "loser": l, "winner_target": targets.get(w), "loser_target": targets.get(l),
             "count": len(domains), "examples": sorted(domains)[:5]} for (w, l), domains in pairs.items()]
    return sorted(rows, key=lambda row: (-row["count"], row["winner"], row["loser"]))


def build_report(domain_sets: dict[str, set[str]], rules: dict[str, Any], direct_domains: set[str]) -> dict[str, Any]:
    targets = category_targets(rules)
    return {
        "direct_overlap": direct_overlap(domain_sets, targets, direct_domains),
        "target_conflicts": target_conflicts(domain_sets, rule_order(rules.get("ordered_rules") or []), targets),
    }
