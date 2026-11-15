#!/usr/bin/env python3
"""Summarise what a build changed: GitHub job summary and commit message.

Compares the new generated/meta/manifest.json with the one in git HEAD. Upstream
revisions (`git ls-remote`) go to the summary only; committing them would create
a commit every time any upstream repository changes.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = "generated/meta/manifest.json"
KINDS = (("domain", "domains", "domains"), ("ip", "cidrs", "networks"), ("mirror", "bytes", "bytes"))


def diff_manifests(old: dict[str, Any], new: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for kind, field, _ in KINDS:
        before, after = old.get(kind) or {}, new.get(kind) or {}
        for name in sorted(set(before) | set(after)):
            if name not in before:
                rows.append({"kind": kind, "name": name, "status": "added", "before": None, "after": after[name].get(field)})
            elif name not in after:
                rows.append({"kind": kind, "name": name, "status": "removed", "before": before[name].get(field), "after": None})
            elif before[name].get(field) != after[name].get(field) or before[name].get("sha256") != after[name].get("sha256"):
                rows.append({"kind": kind, "name": name, "status": "changed",
                             "before": before[name].get(field), "after": after[name].get(field)})
    return rows


def _delta(row: dict[str, Any]) -> str:
    if row["before"] is None or row["after"] is None:
        return ""
    value = row["after"] - row["before"]
    return f"{value:+d}" if value else "content changed"


def render_markdown(rows: list[dict[str, Any]], revisions: dict[str, str] | None = None) -> str:
    lines = ["## Ruleset update", ""]
    if rows:
        lines += ["| set | status | before | after | change |", "|---|---|---:|---:|---|"]
        for row in rows:
            before = "" if row["before"] is None else row["before"]
            after = "" if row["after"] is None else row["after"]
            lines.append(f"| {row['kind']}/{row['name']} | {row['status']} | {before} | {after} | {_delta(row)} |")
    else:
        lines.append("No ruleset changes.")
    if revisions:
        lines += ["", "### Upstream revisions", "", "| source | revision |", "|---|---|"]
        lines += [f"| {name} | `{rev[:12]}` |" for name, rev in sorted(revisions.items())]
    return "\n".join(lines) + "\n"


def commit_message(rows: list[dict[str, Any]], limit: int = 25) -> str:
    if not rows:
        return "chore: update profiles"
    head = f"chore: update rulesets ({len(rows)} set{'s' if len(rows) != 1 else ''} changed)"
    body = []
    for row in rows[:limit]:
        change = _delta(row)
        suffix = f" ({row['before']} -> {row['after']}{', ' + change if change else ''})" if row["status"] == "changed" else ""
        body.append(f"- {row['status']}: {row['kind']}/{row['name']}{suffix}")
    if len(rows) > limit:
        body.append(f"- ... and {len(rows) - limit} more")
    return head + "\n\n" + "\n".join(body) + "\n"


def parse_ls_remote(output: str) -> str | None:
    for line in output.splitlines():
        parts = line.split()
        if len(parts) == 2 and len(parts[0]) >= 12:
            return parts[0]
    return None


def upstream_revisions(sources: dict[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    for name, spec in sources.items():
        if not (spec.get("repository") and spec.get("branch")):
            continue
        try:
            out = subprocess.run(["git", "ls-remote", spec["repository"], spec["branch"]],
                                 capture_output=True, text=True, timeout=30, check=True).stdout
        except (subprocess.SubprocessError, OSError):
            continue  # informational only
        revision = parse_ls_remote(out)
        if revision:
            result[name] = revision
    return result


def old_manifest_from_git(root: Path) -> dict[str, Any]:
    try:
        text = subprocess.run(["git", "show", f"HEAD:{MANIFEST}"], cwd=root, capture_output=True, text=True, check=True).stdout
        return json.loads(text)
    except (subprocess.SubprocessError, OSError, ValueError):
        return {}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--commit-message-file")
    parser.add_argument("--no-upstream", action="store_true", help="skip git ls-remote")
    args = parser.parse_args(argv)

    new_path = ROOT / MANIFEST
    new = json.loads(new_path.read_text(encoding="utf-8")) if new_path.exists() else {}
    rows = diff_manifests(old_manifest_from_git(ROOT), new)

    revisions: dict[str, str] = {}
    if not args.no_upstream:
        sources = yaml.safe_load((ROOT / "settings/repositories.yaml").read_text(encoding="utf-8")).get("sources", {})
        revisions = upstream_revisions(sources)

    markdown = render_markdown(rows, revisions)
    print(markdown)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(markdown)
    if args.commit_message_file:
        Path(args.commit_message_file).write_text(commit_message(rows), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
