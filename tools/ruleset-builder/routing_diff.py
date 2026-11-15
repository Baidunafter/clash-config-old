#!/usr/bin/env python3
"""Compare where every known domain is routed before and after a change.

    routing_diff.py BEFORE_ROOT AFTER_ROOT [--examples N]

Each root is a repository checkout (or build output) with settings/rules.yaml,
generated/source/domain/*.txt and generated/classical/*.yaml. For every domain
that appears in any generated set or static rule, the first matching rule decides
the target (the order of settings/rules.yaml); the report lists domains whose
target differs, grouped by "before -> after".

Sets that are not generated here (mirrored .mrs lists, user lists) are the same
on both sides and are ignored; they could only take precedence for domains they
contain. IP rules are not evaluated. Use it to prove that a category cleanup
changes only what it is meant to change.
"""
from __future__ import annotations

import argparse
import collections
import re
import sys
from pathlib import Path
from typing import Any, Callable

import yaml

NO_MATCH = "(MATCH)"


def _suffix(domain: str, entry: str) -> bool:
    return domain == entry or domain.endswith("." + entry)


def _covered(domain: str, entries: set[str]) -> bool:
    parts = domain.split(".")
    return any(".".join(parts[i:]) in entries for i in range(len(parts) - 1)) or domain in entries


def load_domain_set(root: Path, name: str) -> set[str]:
    path = root / "generated/source/domain" / f"{name}.txt"
    if not path.is_file():
        return set()
    return {line[2:] for line in path.read_text(encoding="utf-8").splitlines() if line.startswith("+.")}


def load_classical(root: Path, name: str) -> tuple[list[str], list[re.Pattern[str]]]:
    path = root / "generated/classical" / f"{name}-classical.yaml"
    if not path.is_file():
        return [], []
    payload = (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("payload") or []
    keywords = [p.split(",", 1)[1] for p in payload if p.startswith("DOMAIN-KEYWORD,")]
    regexes = [re.compile(p.split(",", 1)[1]) for p in payload if p.startswith("DOMAIN-REGEX,")]
    return keywords, regexes


class Tree:
    """The effective routing table of one checkout."""

    def __init__(self, root: Path):
        rules = yaml.safe_load((root / "settings/rules.yaml").read_text(encoding="utf-8"))
        targets = dict(rules.get("generated_targets") or {})
        for name in rules.get("generated_blocks") or []:
            targets[name] = "REJECT"
        self.matchers: list[tuple[str, str, Callable[[str], bool]]] = []
        self.universe: set[str] = set()
        for entry in rules.get("ordered_rules") or []:
            if isinstance(entry, dict) and len(entry) == 1:
                (kind, name), = entry.items()
                if kind not in ("domain", "block") or name not in targets:
                    continue
                domains = load_domain_set(root, name)
                keywords, regexes = load_classical(root, name)
                self.universe |= domains
                self.matchers.append((name, targets[name], self._set_matcher(domains, keywords, regexes)))
            elif isinstance(entry, str):
                parts = [p.strip() for p in entry.split(",")]
                kind = parts[0].upper()
                if kind in ("DOMAIN-SUFFIX", "DOMAIN") and len(parts) >= 3:
                    value = parts[1].lower()
                    self.universe.add(value)
                    fn = (lambda d, v=value: _suffix(d, v)) if kind == "DOMAIN-SUFFIX" else (lambda d, v=value: d == v)
                    self.matchers.append((f"static:{parts[1]}", parts[2], fn))
                elif kind == "DOMAIN-KEYWORD" and len(parts) >= 3:
                    self.matchers.append((f"static:keyword:{parts[1]}", parts[2], lambda d, v=parts[1].lower(): v in d))
                elif kind == "MATCH":
                    self.matchers.append(("MATCH", parts[1], lambda d: True))

    @staticmethod
    def _set_matcher(domains: set[str], keywords: list[str], regexes: list[re.Pattern[str]]) -> Callable[[str], bool]:
        return lambda d: _covered(d, domains) or any(k in d for k in keywords) or any(r.search(d) for r in regexes)

    def route(self, domain: str) -> tuple[str, str]:
        for label, target, fn in self.matchers:
            if fn(domain):
                return (NO_MATCH if label == "MATCH" else target), label
        return NO_MATCH, "MATCH"


def diff_trees(before: Tree, after: Tree) -> list[dict[str, str]]:
    changes = []
    for domain in sorted(before.universe | after.universe):
        (t0, r0), (t1, r1) = before.route(domain), after.route(domain)
        if t0 != t1:
            changes.append({"domain": domain, "before": t0, "after": t1, "before_rule": r0, "after_rule": r1})
    return changes


def render(changes: list[dict[str, str]], examples: int = 8) -> str:
    if not changes:
        return "No domain changes its target.\n"
    groups: dict[tuple[str, str], list[dict[str, str]]] = collections.defaultdict(list)
    for change in changes:
        groups[(change["before"], change["after"])].append(change)
    lines = [f"{len(changes)} domain(s) change target:", ""]
    for (before, after), items in sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        lines.append(f"{before} -> {after}: {len(items)}")
        for item in items[:examples]:
            lines.append(f"    {item['domain']}   [{item['before_rule']} -> {item['after_rule']}]")
        if len(items) > examples:
            lines.append(f"    ... and {len(items) - examples} more")
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("--examples", type=int, default=8, help="examples listed per group")
    args = parser.parse_args(argv[1:])
    print(render(diff_trees(Tree(args.before), Tree(args.after)), args.examples), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
