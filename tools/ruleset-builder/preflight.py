#!/usr/bin/env python3
"""Validate every external ruleset source referenced by categories.yaml.

The preflight deliberately runs before aggregation so a renamed/missing upstream
file is reported as a mapping problem instead of failing halfway through build.py.
"""
from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import yaml

import common
from source_utils import collect_source_urls, malw_entry_names, malw_heading, source_url

ROOT = Path(__file__).resolve().parents[2]
TOOL_DIR = Path(__file__).resolve().parent


def load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Expected mapping in {path}")
    return data


def fetch(url: str, timeout: int = 30) -> tuple[int, str]:
    """Return (status, body); HTTP errors become a status, network errors raise."""
    try:
        return 200, common.fetch_text(url, timeout=timeout)
    except common.HttpStatusError as exc:
        return exc.status, ""


def url_for(sources: dict[str, Any], source_name: str, rel: str) -> str:
    return source_url(sources, source_name, rel)

def check_url(url: str) -> str:
    status, _ = fetch(url, timeout=20)
    if status == 200:
        return "OK"
    return f"HTTP {status}"


def parse_malw_sections(text: str) -> set[str]:
    sections: set[str] = set()
    for line in text.splitlines():
        name = malw_heading(line)
        if name:
            sections.add(name.casefold())
    return sections


def main() -> int:
    sources = load_yaml(ROOT / "settings/repositories.yaml")["sources"]
    categories = load_yaml(TOOL_DIR / "categories.yaml")
    errors: list[str] = []
    checks = 0

    print("== External ruleset preflight ==")
    print("Public upstream files:")

    refs = collect_source_urls(categories, sources)

    results: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=min(12, max(1, len(refs)))) as pool:
        futures = {pool.submit(check_url, url): url for url in refs}
        for future in as_completed(futures):
            url = futures[future]
            try:
                results[url] = future.result()
            except RuntimeError as exc:
                results[url] = f"ERROR: {exc}"

    for url, entries in sorted(refs.items()):
        result = results[url]
        checks += len(entries)
        for group, category, label in entries:
            source_name, rel = label.split(":", 1)
            print(f"  {result:<8} {group}/{category} <- {label}")
            if result != "OK":
                errors.append(f"{group}/{category} [{source_name}] {rel}: {result} ({url})")

    # MALW is one large hosts file; validate all referenced headings in one request.
    malw_url = sources["malw_hosts"]["url"]
    status, text = fetch(malw_url)
    if status != 200:
        errors.append(f"malw/hosts: HTTP {status} ({malw_url})")
        print(f"  HTTP {status:<4} malw/hosts")
    else:
        sections = parse_malw_sections(text)
        print(f"  OK       malw/hosts ({len(sections)} sections)")
        refs: list[tuple[str, list[str], bool]] = []
        for group in ("services", "categories"):
            for category, mapping in categories.get(group, {}).items():
                for entry in (mapping or {}).get("malw") or []:
                    names, optional = malw_entry_names(entry)
                    refs.append((category, names, optional))
        for category, names, optional in sorted(refs, key=lambda r: (r[0], r[1])):
            checks += 1
            label = " | ".join(names)
            if any(n.casefold() in sections for n in names):
                print(f"  OK       MALW section: {label}")
            elif optional:
                print(f"  WARN     MALW section (optional): {label}")
            else:
                errors.append(f"MALW section missing: {label} (category {category})")
                print(f"  FAIL     MALW section: {label}")

    print(f"\nChecked references: {checks}")
    if errors:
        print("\nPreflight FAILED:", file=sys.stderr)
        for error in sorted(set(errors)):
            print(f"- {error}", file=sys.stderr)
        print("\nUpdate tools/ruleset-builder/categories.yaml instead of silently ignoring an upstream error.", file=sys.stderr)
        return 2

    print("Preflight PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
