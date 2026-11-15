#!/usr/bin/env python3
"""Make an offline copy of a generated profile for `mihomo -t`.

The production profile loads its rule providers over HTTP from this repository's
`main` branch, which still holds the previous generation while CI validates the new
one (a brand-new category would be a 404). The test copy points every provider that
belongs to this repository at the local files instead, so `mihomo -t` really parses
the freshly generated .mrs / .yaml files and needs no network.

Usage: make_test_profile.py WARPxUNIVERSAL.yaml OUT_DIR   (prints the config path)
Then:  mihomo -t -d OUT_DIR -f OUT_DIR/config.yaml
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
COPIED_DIRS = ("generated", "profiles")


def make_offline_profile(profile: Path, root: Path, out_dir: Path, private_raw_base: str) -> Path:
    data: dict[str, Any] = yaml.safe_load(profile.read_text(encoding="utf-8"))
    base = private_raw_base.rstrip("/") + "/"

    out_dir.mkdir(parents=True, exist_ok=True)
    for name in COPIED_DIRS:
        if (root / name).is_dir():
            shutil.copytree(root / name, out_dir / name, dirs_exist_ok=True)

    remote = []
    for name, provider in (data.get("rule-providers") or {}).items():
        url = str(provider.get("url", ""))
        if not url.startswith(base):
            remote.append(name)  # a third-party provider stays an http provider
            continue
        relative = url[len(base):]
        if not (out_dir / relative).is_file():
            raise RuntimeError(f"provider '{name}' points at {relative}, which does not exist locally")
        provider["type"] = "file"
        provider["path"] = "./" + relative
        for key in ("url", "interval", "header"):
            provider.pop(key, None)
    if remote:
        print(f"note: still remote: {', '.join(remote)}", file=sys.stderr)

    target = out_dir / "config.yaml"
    target.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False, width=10_000), encoding="utf-8")
    return target


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    repos = yaml.safe_load((ROOT / "settings/repositories.yaml").read_text(encoding="utf-8"))
    print(make_offline_profile(ROOT / argv[1], ROOT, Path(argv[2]), repos["github"]["raw_base"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
