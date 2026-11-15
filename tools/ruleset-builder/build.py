#!/usr/bin/env python3
"""Aggregate public ruleset sources and compile canonical Mihomo MRS files.

Outputs (all under ``generated/``):
  domain/<name>.mrs                domain sets (``+.`` suffix semantics)
  ip/<name>.mrs                    IP-CIDR sets
  classical/<name>-classical.yaml  DOMAIN-KEYWORD / DOMAIN-REGEX / PROCESS-NAME
                                   companions, because MRS cannot represent them
  source/...                       human readable text of every MRS set
  meta/manifest.json               counts and hashes
  meta/losses.json                 source lines that could not be represented

Nothing is published unless the whole run succeeds (atomic publish).
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

import common
import conflicts
from source_utils import (
    LOCAL_SOURCE,
    RESERVED_CATEGORY_KEYS,
    malw_entry_names,
    malw_heading,
    malw_last_update,
    collect_source_urls,
    source_url,
)

ROOT = Path(__file__).resolve().parents[2]
TOOL_DIR = Path(__file__).resolve().parent

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$", re.I)
SINGLE_LABEL_RE = re.compile(r"^[a-z0-9_-]{1,63}$", re.I)
KEYWORD_RE = re.compile(r"^[a-z0-9._-]{1,128}$")
IP_TOKEN_RE = re.compile(r"^(?:IP-CIDR|IP-CIDR6)$", re.I)

PLAIN_SOURCES = {"roscomvpn": "roscomvpn_geosite", "itdog": "itdog_allow_domains"}
CLASSICAL_SOURCES = {"codelab": "codelab_ruleset", "blackmatrix7": "blackmatrix7"}
PROCESS_KINDS = {"PROCESS-NAME", "PROCESS-NAME-REGEX", "PROCESS-PATH", "PROCESS-PATH-REGEX"}
MAX_EXAMPLES = 3

RU_MONTHS = {
    "января": 1, "февраля": 2, "марта": 3, "апреля": 4, "мая": 5, "июня": 6,
    "июля": 7, "августа": 8, "сентября": 9, "октября": 10, "ноября": 11, "декабря": 12,
}


def load_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected mapping in {path}")
    return value


def download_text(url: str, timeout: int = 45) -> str:
    return common.fetch_text(url, timeout=timeout)


def download_bytes(url: str, timeout: int = 60) -> bytes:
    return common.fetch_bytes(url, timeout=timeout)


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------

@dataclass
class Parsed:
    """Result of parsing one or more upstream files."""

    domains: set[str] = field(default_factory=set)
    keywords: set[str] = field(default_factory=set)
    regexes: set[str] = field(default_factory=set)
    processes: set[str] = field(default_factory=set)    # "PROCESS-NAME,x" / "PROCESS-NAME-REGEX,x" lines, kept verbatim
    cidrs: set[str] = field(default_factory=set)
    dropped: Counter = field(default_factory=Counter)   # lines we could not represent
    notes: Counter = field(default_factory=Counter)     # lines kept with a caveat
    examples: dict[str, list[str]] = field(default_factory=dict)

    def drop(self, reason: str, sample: str) -> None:
        self.dropped[reason] += 1
        bucket = self.examples.setdefault(reason, [])
        if len(bucket) < MAX_EXAMPLES:
            bucket.append(sample.strip()[:120])

    def update(self, other: "Parsed") -> None:
        self.domains |= other.domains
        self.keywords |= other.keywords
        self.regexes |= other.regexes
        self.processes |= other.processes
        self.cidrs |= other.cidrs
        self.dropped.update(other.dropped)
        self.notes.update(other.notes)
        for reason, samples in other.examples.items():
            bucket = self.examples.setdefault(reason, [])
            for sample in samples:
                if len(bucket) < MAX_EXAMPLES and sample not in bucket:
                    bucket.append(sample)


def clean_domain(raw: str) -> tuple[str | None, str | None]:
    """Return ``(domain, None)`` or ``(None, reason)``."""
    s = re.sub(r"^(?:https?|tls|quic)://", "", raw.strip(), flags=re.I)
    s = s.split("/", 1)[0].strip().rstrip(".").lower()
    if s.startswith(("*.", "+.")):
        s = s[2:]
    s = s.lstrip(".")
    if not s:
        return None, "invalid"
    try:
        s = s.encode("idna").decode("ascii")
    except UnicodeError:
        return None, "invalid"
    if DOMAIN_RE.fullmatch(s):
        return s, None
    if SINGLE_LABEL_RE.fullmatch(s):
        # TLD-like entries (".ua", "xbox"). Publishing them would match a whole
        # TLD, so they are reported instead of being silently widened.
        return None, "single_label"
    return None, "invalid"


def classify_plain_line(raw: str) -> tuple[str, str, tuple[str, ...]]:
    """Classify one line of a v2fly/itdog style list.

    Returns ``(kind, value, notes)`` where kind is one of
    ``skip | domain | keyword | regex | drop`` (for ``drop`` the value is the reason).
    """
    s = raw.strip().lstrip("\ufeff")
    if not s or s.startswith("#"):
        return "skip", "", ()
    s = s.split("#", 1)[0].strip()
    if not s:
        return "skip", "", ()

    notes: list[str] = []
    tokens = s.split()
    if len(tokens) >= 2:  # hosts format: IP DOMAIN
        try:
            ipaddress.ip_address(tokens[0])
            tokens = tokens[1:2]
        except ValueError:
            pass
    if any(t.startswith("@") for t in tokens):  # v2fly attributes: "domain:x.com @ads"
        notes.append("attributes_stripped")
    core = [t for t in tokens if not t.startswith("@")]
    if not core:
        return "drop", "other", tuple(notes)

    token = core[0]
    low = token.lower()
    if low.startswith("keyword:"):
        value = token[len("keyword:"):].strip().lower()
        if KEYWORD_RE.fullmatch(value):
            return "keyword", value, tuple(notes)
        return "drop", "invalid_keyword", tuple(notes)
    if low.startswith("regexp:"):
        value = token[len("regexp:"):]
        try:
            re.compile(value)
        except re.error:
            return "drop", "invalid_regex", tuple(notes)
        return "regex", value, tuple(notes)
    if low.startswith("include:"):
        return "drop", "include", tuple(notes)
    if low.startswith("full:"):
        notes.append("full_broadened")  # exact match is published as +.domain
        token = token[len("full:"):]
    elif low.startswith("domain:"):
        token = token[len("domain:"):]

    domain, reason = clean_domain(token)
    if domain:
        return "domain", domain, tuple(notes)
    return "drop", reason or "invalid", tuple(notes)


def normalize_domain(raw: str) -> str | None:
    kind, value, _ = classify_plain_line(raw)
    return value if kind == "domain" else None


def parse_plain_list_ex(text: str) -> Parsed:
    out = Parsed()
    for line in text.splitlines():
        kind, value, notes = classify_plain_line(line)
        for note in notes:
            out.notes[note] += 1
        if kind == "skip":
            continue
        if kind == "domain":
            out.domains.add(value)
        elif kind == "keyword":
            out.keywords.add(value)
        elif kind == "regex":
            out.regexes.add(value)
        else:
            out.drop(value, line)
    return out


def parse_plain_list(text: str) -> set[str]:
    return parse_plain_list_ex(text).domains


def parse_classical_yaml_ex(text: str) -> Parsed:
    """Parse a Clash classical rule-provider (``payload:`` list)."""
    data = yaml.safe_load(text) or {}
    payload = data.get("payload") if isinstance(data, dict) else None
    if not isinstance(payload, list):
        raise RuntimeError("classical ruleset has no 'payload' list")

    out = Parsed()
    for item in payload:
        if not isinstance(item, str):
            out.drop("non_string", str(item))
            continue
        kind, _, rest = item.partition(",")
        kind = kind.strip().upper()
        rest = rest.strip()
        if not rest:
            out.drop("malformed", item)
            continue

        if kind in {"DOMAIN", "DOMAIN-SUFFIX"}:
            domain, reason = clean_domain(rest.split(",", 1)[0])
            if domain:
                out.domains.add(domain)
            else:
                out.drop(reason or "invalid", item)
        elif kind == "DOMAIN-KEYWORD":
            value = rest.split(",", 1)[0].strip().lower()
            if KEYWORD_RE.fullmatch(value):
                out.keywords.add(value)
            else:
                out.drop("invalid_keyword", item)
        elif kind == "DOMAIN-REGEX":
            try:
                re.compile(rest)
            except re.error:
                out.drop("invalid_regex", item)
            else:
                out.regexes.add(rest)
        elif IP_TOKEN_RE.fullmatch(kind):
            try:
                out.cidrs.add(str(ipaddress.ip_network(rest.split(",", 1)[0].strip(), strict=False)))
            except ValueError:
                out.drop("invalid_cidr", item)
        elif kind in PROCESS_KINDS:
            # Process / Android package rules cannot live in an .mrs; they go to the classical companion.
            if kind.endswith("-REGEX"):
                try:
                    re.compile(rest)
                except re.error:
                    out.drop("invalid_regex", item)
                    continue
            out.processes.add(f"{kind},{rest}")
        else:
            out.drop(f"unsupported:{kind}", item)
    return out


def parse_classical_yaml(text: str) -> tuple[set[str], set[str]]:
    parsed = parse_classical_yaml_ex(text)
    return parsed.domains, parsed.cidrs


def parse_malw_hosts(text: str) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Parse MALW hosts into domain sections and optional IP mappings.

    The IP mappings are collected separately so the builder can explicitly
    disable their publication as Mihomo `hosts` overrides while still using
    the same source for MALW domain/blocking rules.

    Only real section headings start a new section: file banners (``###``) and
    metadata such as "Последнее обновление" are ignored (see malw_heading).
    """
    sections: dict[str, set[str]] = {"__preamble__": set()}
    redirects: dict[str, set[str]] = {}
    current = "__preamble__"
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            heading = malw_heading(stripped)
            if heading:
                current = heading
                sections.setdefault(current, set())
            continue

        fields = stripped.split()
        if len(fields) < 2:
            continue
        try:
            ip = str(ipaddress.ip_address(fields[0]))
        except ValueError:
            continue

        for raw_domain in fields[1:]:
            domain, _ = clean_domain(raw_domain)
            if not domain:
                continue
            sections[current].add(domain)
            if current.casefold().strip() != "блокировка":
                redirects.setdefault(domain, set()).add(ip)

    return sections, redirects


def lookup_section(sections: dict[str, set[str]], name: str) -> set[str]:
    key = name.casefold().strip()
    for section, values in sections.items():
        if section.casefold().strip() == key:
            return set(values)
    return set()


def resolve_malw_entry(sections: dict[str, set[str]], entry: Any) -> tuple[set[str], str, bool]:
    names, optional = malw_entry_names(entry)
    for name in names:
        found = lookup_section(sections, name)
        if found:
            return found, name, optional
    return set(), " | ".join(names), optional


def malw_age_days(text: str, today: dt.date | None = None) -> int | None:
    phrase = malw_last_update(text)
    if not phrase:
        return None
    match = re.search(r"(\d{1,2})\s+([а-яё]+)\s+(\d{4})", phrase.casefold())
    if not match or match.group(2) not in RU_MONTHS:
        return None
    try:
        updated = dt.date(int(match.group(3)), RU_MONTHS[match.group(2)], int(match.group(1)))
    except ValueError:
        return None
    return ((today or dt.date.today()) - updated).days


# --------------------------------------------------------------------------
# Aggregation
# --------------------------------------------------------------------------

@dataclass
class Aggregate:
    parsed: Parsed
    stats: dict[str, int]
    errors: list[str]
    warnings: list[str]
    excluded: int = 0


def excludes_for(mapping: dict[str, Any], source_name: str) -> set[str]:
    """Exact domain entries to remove for ``source_name`` (sub-domains are kept)."""
    raw = mapping.get("exclude_domains") or []
    # list = every source; mapping = per source, with `all` applying to every source
    items = (list(raw.get("all") or []) + list(raw.get(source_name) or [])) if isinstance(raw, dict) else raw
    result: set[str] = set()
    for item in items:
        domain, _ = clean_domain(str(item))
        if domain:
            result.add(domain)
    return result


def aggregate_domains(mapping: dict[str, Any], sources: dict[str, Any], malw: dict[str, set[str]]) -> Aggregate:
    agg = Aggregate(parsed=Parsed(), stats={}, errors=[], warnings=[])

    for source_name, entries in mapping.items():
        if source_name in RESERVED_CATEGORY_KEYS:
            continue
        entries = entries or []
        if not entries:
            continue

        collected = Parsed()
        if source_name == "malw":
            for entry in entries:
                values, label, optional = resolve_malw_entry(malw, entry)
                if not values:
                    message = f"MALW section '{label}' missing or empty"
                    (agg.warnings if optional else agg.errors).append(message)
                    continue
                collected.domains |= values
        elif source_name in PLAIN_SOURCES:
            for rel in entries:
                collected.update(parse_plain_list_ex(download_text(source_url(sources, source_name, rel))))
        elif source_name in CLASSICAL_SOURCES:
            for rel in entries:
                url = source_url(sources, source_name, rel)
                try:
                    collected.update(parse_classical_yaml_ex(download_text(url)))
                except RuntimeError as exc:
                    raise RuntimeError(f"{exc}: {url}") from exc
        elif source_name == LOCAL_SOURCE:
            # Own curated lists kept in tools/ruleset-builder/lists/ (same format as the roscomvpn lists).
            for rel in entries:
                path = TOOL_DIR / "lists" / rel
                if not path.is_file():
                    raise RuntimeError(f"local list not found: lists/{rel}")
                collected.update(parse_plain_list_ex(path.read_text(encoding="utf-8")))
        else:
            raise ValueError(f"Unknown source type: {source_name}")

        removable = excludes_for(mapping, source_name) & collected.domains
        collected.domains -= removable
        agg.excluded += len(removable)
        agg.stats[source_name] = len(collected.domains)
        agg.parsed.update(collected)

    return agg


def union_cidrs(mapping: dict[str, Any], sources: dict[str, Any]) -> tuple[set[str], dict[str, int]]:
    values: set[str] = set()
    stats: dict[str, int] = {}

    for source_name, entries in mapping.items():
        if source_name in RESERVED_CATEGORY_KEYS:
            continue
        entries = entries or []
        if not entries:
            continue
        count = 0

        if source_name == "itdog":
            for rel in entries:
                url = source_url(sources, "itdog_allow_domains", rel)
                for line in download_text(url).splitlines():
                    line = line.strip().split("#", 1)[0].strip()
                    if not line:
                        continue
                    try:
                        network = ipaddress.ip_network(line.split()[0], strict=False)
                    except ValueError:
                        continue
                    values.add(str(network))
                    count += 1

        elif source_name in CLASSICAL_SOURCES:
            for rel in entries:
                url = source_url(sources, source_name, rel)
                parsed = parse_classical_yaml_ex(download_text(url)).cidrs
                values.update(parsed)
                count += len(parsed)

        else:
            raise ValueError(f"Unknown IP source: {source_name}")

        stats[source_name] = count

    return values, stats


# --------------------------------------------------------------------------
# Output helpers
# --------------------------------------------------------------------------

def write_domain_text(path: Path, domains: set[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"+.{d}\n" for d in sorted(domains)), encoding="utf-8")


def write_ip_text(path: Path, cidrs: set[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{n}\n" for n in sorted(cidrs)), encoding="utf-8")


def write_classical(path: Path, keywords: set[str], regexes: set[str], processes: set[str] | None = None) -> None:
    payload = [f"DOMAIN-KEYWORD,{k}" for k in sorted(keywords)] + [f"DOMAIN-REGEX,{r}" for r in sorted(regexes)]
    payload += sorted(processes or ())
    body = yaml.safe_dump({"payload": payload}, allow_unicode=True, sort_keys=False, default_flow_style=False)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# Generated by tools/ruleset-builder/build.py. Do not edit.\n" + body, encoding="utf-8")


def compile_mrs(mihomo: str, behavior: str, source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([mihomo, "convert-ruleset", behavior, "text", str(source), str(target)], check=True)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def loss_entry(parsed: Parsed) -> dict[str, Any] | None:
    if not parsed.dropped and not parsed.notes:
        return None
    entry: dict[str, Any] = {}
    if parsed.dropped:
        entry["dropped"] = dict(sorted(parsed.dropped.items()))
        entry["examples"] = {reason: parsed.examples[reason] for reason in sorted(parsed.dropped)}
    if parsed.notes:
        entry["notes"] = dict(sorted(parsed.notes.items()))
    return entry


# --------------------------------------------------------------------------
# Safeguards
# --------------------------------------------------------------------------

def collect_allow_shrink(cli_values: list[str], build_cfg: dict[str, Any]) -> set[str]:
    raw = list(cli_values) + [os.environ.get("ALLOW_SHRINK", "")]
    raw += list((build_cfg.get("guard") or {}).get("allow_shrink") or [])
    allowed: set[str] = set()
    for value in raw:
        for part in str(value).split(","):
            if part.strip():
                allowed.add(part.strip())
    return allowed


def check_shrink(prev: dict[str, Any], manifest: dict[str, Any], guard: dict[str, Any], allow: set[str]) -> list[str]:
    """Fail when a set lost most of its entries compared with the last build.

    A renamed or truncated upstream file is still valid text, so only a size
    comparison can catch it.
    """
    limit = float(guard.get("max_shrink_percent", 40))
    min_previous = int(guard.get("min_previous_size", 50))
    errors: list[str] = []
    for kind, counter in (("domain", "domains"), ("ip", "cidrs"), ("mirror", "bytes")):
        for name, old_entry in (prev.get(kind) or {}).items():
            new_entry = (manifest.get(kind) or {}).get(name)
            if new_entry is None:
                continue
            old, new = int(old_entry.get(counter, 0)), int(new_entry.get(counter, 0))
            if old < min_previous or new >= old * (1 - limit / 100):
                continue
            if name in allow or f"{kind}/{name}" in allow:
                continue
            errors.append(
                f"{kind}/{name}: shrank from {old} to {new} entries "
                f"(-{(1 - new / old) * 100:.0f}%, limit {limit:.0f}%). If this is expected, rerun with "
                f"--allow-shrink {name} (or ALLOW_SHRINK={name}) or add it to guard.allow_shrink in settings/build.yaml."
            )
    return errors


def conflict_report(sources: dict[str, Any], build_cfg: dict[str, Any], rules_path: Path,
                    domain_sets: dict[str, set[str]]) -> tuple[dict[str, Any] | None, list[str]]:
    """Informational routing-conflict report; problems become warnings, never errors."""
    if not rules_path.exists():
        return None, []
    warnings: list[str] = []
    direct: set[str] = set()
    for item in (build_cfg.get("conflicts") or {}).get("direct_lists") or []:
        try:
            direct |= parse_plain_list_ex(download_text(source_url(sources, item["source"], item["path"]))).domains
        except (RuntimeError, KeyError, ValueError) as exc:
            warnings.append(f"conflict check: direct list {item} unavailable ({exc})")
    report = conflicts.build_report(domain_sets, load_yaml(rules_path), direct)
    for name, entry in report["direct_overlap"].items():
        warnings.append(f"{name}: {entry['count']} domains are also in the Russian direct lists (see generated/meta/conflicts.json)")
    return report, warnings


def read_previous_manifest(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"  # an .mrs file is one zstd stream


def validate_mirror_file(name: str, path: str, data: bytes) -> str | None:
    """Return a problem description, or None when the downloaded file looks sane."""
    if not data:
        return "empty file"
    suffix = Path(path).suffix.lower()
    if suffix == ".mrs":
        return None if data.startswith(ZSTD_MAGIC) else "not an .mrs (zstd) file"
    if suffix in (".yaml", ".yml"):
        try:
            payload = (yaml.safe_load(data.decode("utf-8")) or {}).get("payload")
        except (UnicodeDecodeError, yaml.YAMLError, AttributeError):
            return "not a valid YAML rule list"
        return None if isinstance(payload, list) and payload else "no payload entries"
    return None


def build_mirror(sources: dict[str, Any], config: dict[str, Any], stage: Path) -> tuple[dict[str, Any], list[str]]:
    entries: dict[str, Any] = {}
    errors: list[str] = []
    for name, spec in sorted((config.get("mirror") or {}).items()):
        try:
            url = source_url(sources, spec["source"], spec["path"])
            data = download_bytes(url)
        except (RuntimeError, KeyError, ValueError) as exc:
            errors.append(f"mirror/{name}: {exc}")
            continue
        problem = validate_mirror_file(name, spec["path"], data)
        if problem:
            errors.append(f"mirror/{name}: {problem} ({url})")
            continue
        target = stage / "mirror" / f"{name}{Path(spec['path']).suffix}"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        entries[name] = {"bytes": len(data), "file": f"generated/mirror/{target.name}",
                         "sha256": hashlib.sha256(data).hexdigest(), "source": url}
    return entries, errors


def publish_dirs(stage: Path, out_root: Path) -> None:
    """Replace generated output directories only after a fully successful run."""
    for rel in ("domain", "ip", "classical", "mirror", "source/domain", "source/ip"):
        target = out_root / rel
        shutil.rmtree(target, ignore_errors=True)
        source = stage / rel
        if source.exists():
            shutil.copytree(source, target)


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mihomo", required=True)
    parser.add_argument("--allow-shrink", action="append", default=[], metavar="NAME[,NAME]",
                        help="accept a large shrink of these categories (also: ALLOW_SHRINK env, guard.allow_shrink)")
    args = parser.parse_args(argv)

    repo = load_yaml(ROOT / "settings/repositories.yaml")
    build_cfg = load_yaml(ROOT / "settings/build.yaml")
    profiles_path = ROOT / "settings/profiles.yaml"
    profiles_cfg = load_yaml(profiles_path) if profiles_path.exists() else {}
    mirror_path = ROOT / "settings/mirror.yaml"
    mirror_cfg = load_yaml(mirror_path) if mirror_path.exists() else {}
    publish_host_overrides = bool(build_cfg.get("malw", {}).get("publish_host_overrides", False))
    max_malw_age = int(build_cfg.get("malw", {}).get("max_age_days", 45))
    allow_shrink = collect_allow_shrink(args.allow_shrink, build_cfg)
    sources = repo["sources"]
    categories = load_yaml(TOOL_DIR / "categories.yaml")

    out_root = ROOT / "generated"
    meta_dir = out_root / "meta"
    meta_dir.mkdir(parents=True, exist_ok=True)
    previous = read_previous_manifest(meta_dir / "manifest.json")

    if common.cache_enabled():  # warm the cache in parallel; per-category fetches then hit it
        urls = list(collect_source_urls(categories, sources)) + [sources["malw_hosts"]["url"]]
        common.prefetch(urls, fetch=download_text)

    malw_text = download_text(sources["malw_hosts"]["url"])
    malw, malw_redirects = parse_malw_hosts(malw_text)
    age = malw_age_days(malw_text)
    warnings: list[str] = []
    if age is not None and age > max_malw_age:
        warnings.append(f"MALW hosts file was last updated {age} days ago (limit {max_malw_age})")

    manifest: dict[str, Any] = {
        "generator": "tools/ruleset-builder/build.py",
        "source_check_interval_hours": int((profiles_cfg.get("runtime") or {}).get("source_check_interval_hours", 24)),
        "malw_last_update": malw_last_update(malw_text),
        "malw_sections": {k: len(v) for k, v in malw.items() if k != "__preamble__"},
        "domain": {},
        "ip": {},
        "mirror": {},
    }

    errors: list[str] = []
    domain_sets: dict[str, set[str]] = {}
    losses: dict[str, Any] = {}
    skipped_optional: list[str] = []

    with tempfile.TemporaryDirectory() as temp_dir:
        tmp = Path(temp_dir)
        stage = tmp / "stage"

        for group in ("services", "categories"):
            for name, mapping in (categories.get(group) or {}).items():
                label = f"{group}/{name}"
                mapping = mapping or {}
                try:
                    agg = aggregate_domains(mapping, sources, malw)
                except RuntimeError as exc:
                    errors.append(f"{label}: {exc}")
                    continue
                errors.extend(f"{label}: {e}" for e in agg.errors)
                warnings.extend(f"{label}: {w}" for w in agg.warnings)
                parsed = agg.parsed

                if not parsed.domains:
                    if mapping.get("optional"):
                        warnings.append(f"{label}: no data upstream, skipped (optional)")
                        skipped_optional.append(name)
                    else:
                        errors.append(f"{label}: resulting domain set is empty")
                    continue

                domain_sets[name] = set(parsed.domains)
                txt = tmp / f"{name}.txt"
                out = stage / "domain" / f"{name}.mrs"
                write_domain_text(txt, parsed.domains)
                compile_mrs(args.mihomo, "domain", txt, out)
                persistent = stage / "source/domain" / f"{name}.txt"
                persistent.parent.mkdir(parents=True, exist_ok=True)
                persistent.write_text(txt.read_text(encoding="utf-8"), encoding="utf-8")

                entry: dict[str, Any] = {
                    "domains": len(parsed.domains),
                    "sources": agg.stats,
                    "sha256": sha256(out),
                    "source_text": f"generated/source/domain/{name}.txt",
                }
                if parsed.keywords or parsed.regexes or parsed.processes:
                    classical = stage / "classical" / f"{name}-classical.yaml"
                    write_classical(classical, parsed.keywords, parsed.regexes, parsed.processes)
                    entry["classical"] = {
                        "keywords": len(parsed.keywords),
                        "regex": len(parsed.regexes),
                        "processes": len(parsed.processes),
                        "file": f"generated/classical/{name}-classical.yaml",
                        "sha256": sha256(classical),
                    }
                if agg.excluded:
                    entry["excluded"] = agg.excluded
                manifest["domain"][name] = entry
                loss = loss_entry(parsed)
                if loss:
                    losses[label] = loss

        for name, mapping in (categories.get("ip_categories") or {}).items():
            try:
                cidrs, stats = union_cidrs(mapping or {}, sources)
            except RuntimeError as exc:
                errors.append(f"ip/{name}: {exc}")
                continue
            if not cidrs:
                errors.append(f"ip/{name}: resulting CIDR set is empty")
                continue

            txt = tmp / f"{name}.txt"
            out = stage / "ip" / f"{name}.mrs"
            write_ip_text(txt, cidrs)
            compile_mrs(args.mihomo, "ipcidr", txt, out)
            persistent = stage / "source/ip" / f"{name}.txt"
            persistent.parent.mkdir(parents=True, exist_ok=True)
            persistent.write_text(txt.read_text(encoding="utf-8"), encoding="utf-8")
            manifest["ip"][name] = {"cidrs": len(cidrs), "sources": stats, "sha256": sha256(out), "source_text": f"generated/source/ip/{name}.txt"}

        manifest["mirror"], mirror_errors = build_mirror(sources, mirror_cfg, stage)
        errors.extend(mirror_errors)

        if not errors:
            errors.extend(check_shrink(previous, manifest, build_cfg.get("guard") or {}, allow_shrink))

        # Never publish an incomplete generation. In particular, a temporary upstream
        # outage must not replace a previously good ruleset with an empty one.
        if errors:
            report = "\n".join(sorted(set(errors))) + "\n"
            (meta_dir / "errors.txt").write_text(report, encoding="utf-8")
            print(report, file=sys.stderr)
            return 2

        publish_dirs(stage, out_root)

    (meta_dir / "errors.txt").unlink(missing_ok=True)

    if skipped_optional:
        manifest["skipped_optional"] = sorted(skipped_optional)
    for warning in warnings:
        print(f"::warning::{warning}")

    report, conflict_warnings = conflict_report(sources, build_cfg, ROOT / "settings/rules.yaml", domain_sets)
    for warning in conflict_warnings:
        print(f"::warning::{warning}")
    conflicts_file = meta_dir / "conflicts.json"
    if report is not None:
        conflicts_file.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    else:
        conflicts_file.unlink(missing_ok=True)

    # Source lines that cannot be expressed in the published formats.
    (meta_dir / "losses.json").write_text(json.dumps(losses, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    # Report cross-category duplicates without changing category contents.
    # Duplicates inside a category are already removed by set() aggregation.
    reverse: dict[str, list[str]] = {}
    for name, values in sorted(domain_sets.items()):
        for domain in values:
            reverse.setdefault(domain, []).append(name)
    cross = {d: sorted(names) for d, names in reverse.items() if len(names) > 1}
    (meta_dir / "duplicates.json").write_text(json.dumps({
        "cross_category_duplicates": len(cross),
        "domains": cross,
        "note": "Duplicates are removed across sources inside each category. Cross-category duplicates are reported but intentionally preserved until semantic category merging is designed."
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    # MALW non-blocking IP mappings are disabled by default. When explicitly
    # enabled, publish them as a native Mihomo hosts block for compatibility.
    stale_hosts = out_root / "malw/hosts.yaml"
    if publish_host_overrides:
        hosts_payload: dict[str, Any] = {}
        for domain, ips in sorted(malw_redirects.items()):
            ordered_ips = sorted(ips, key=lambda value: (":" in value, value))
            hosts_payload[domain] = ordered_ips[0] if len(ordered_ips) == 1 else ordered_ips
        stale_hosts.parent.mkdir(parents=True, exist_ok=True)
        stale_hosts.write_text(
            yaml.safe_dump({"hosts": hosts_payload}, allow_unicode=True, sort_keys=True, default_flow_style=False),
            encoding="utf-8",
        )
    else:
        stale_hosts.unlink(missing_ok=True)

    (meta_dir / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
