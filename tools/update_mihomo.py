#!/usr/bin/env python3
"""Bump the pinned Mihomo release (version, asset, sha256) in settings/build.yaml.

The workflow verifies the SHA-256 of the downloaded archive, so the pin must be
updated together with the version. This script downloads the latest release asset,
hashes it and rewrites the three lines. Exit code 0 always; the result is written to
$GITHUB_OUTPUT (updated=true/false, version=...).
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
import sys
import urllib.request
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
BUILD_YAML = ROOT / "settings/build.yaml"
API = "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest"
ASSET_RE = re.compile(r"^mihomo-linux-amd64-compatible-v\d+(?:\.\d+)*\.gz$")


def version_tuple(tag: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", tag))


def is_newer(candidate: str, current: str) -> bool:
    return version_tuple(candidate) > version_tuple(current)


def pick_asset(release: dict[str, Any]) -> dict[str, Any] | None:
    for asset in release.get("assets") or []:
        if ASSET_RE.match(str(asset.get("name", ""))):
            return asset
    return None


def rewrite_build_yaml(text: str, version: str, asset: str, sha256: str) -> str:
    """Replace version/asset/sha256 inside the `mihomo:` block, keeping comments."""
    block = re.search(r"(?ms)^mihomo:\n(?P<body>(?:[ \t]+.*\n|\n)*)", text)
    if not block:
        raise RuntimeError("settings/build.yaml has no mihomo: block")
    body = block.group("body")
    for key, value in (("version", version), ("asset", asset), ("sha256", sha256)):
        body, count = re.subn(rf"(?m)^([ \t]+{key}:).*$", rf"\g<1> {value}", body, count=1)
        if count != 1:
            raise RuntimeError(f"mihomo.{key} not found in settings/build.yaml")
    return text[: block.start("body")] + body + text[block.end("body"):]


def http_get(url: str, token: str | None = None) -> bytes:
    headers = {"User-Agent": "Baidunafter/clash-config-update-mihomo", "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=120) as response:
        return response.read()


def write_output(**values: str) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    lines = "".join(f"{k}={v}\n" for k, v in values.items())
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(lines)
    print(lines, end="")


def main() -> int:
    current = yaml.safe_load(BUILD_YAML.read_text(encoding="utf-8"))["mihomo"]["version"]
    release = json.loads(http_get(API, os.environ.get("GITHUB_TOKEN")))
    tag = str(release.get("tag_name", ""))
    asset = pick_asset(release)
    if not tag or asset is None:
        print("::warning::latest Mihomo release has no linux-amd64-compatible asset", file=sys.stderr)
        write_output(updated="false")
        return 0
    if release.get("prerelease") or not is_newer(tag, current):
        print(f"Pinned {current} is up to date (latest {tag}).")
        write_output(updated="false")
        return 0

    data = http_get(asset["browser_download_url"])
    try:
        binary = gzip.decompress(data)
    except OSError as exc:
        print(f"::error::downloaded asset is not a valid gzip archive: {exc}", file=sys.stderr)
        return 1
    if not binary.startswith(b"\x7fELF"):
        print("::error::downloaded asset does not contain an ELF executable", file=sys.stderr)
        return 1
    digest = hashlib.sha256(data).hexdigest()
    BUILD_YAML.write_text(rewrite_build_yaml(BUILD_YAML.read_text(encoding="utf-8"), tag, asset["name"], digest), encoding="utf-8")
    write_output(updated="true", version=tag, previous=current)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
