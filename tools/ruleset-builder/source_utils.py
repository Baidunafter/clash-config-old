#!/usr/bin/env python3
"""Shared upstream helpers used by preflight and the ruleset builder."""
from __future__ import annotations

import re
from typing import Any

# Accept both the short names used in categories.yaml and the repository keys
# used in settings/repositories.yaml. Keeping this mapping here prevents the
# preflight and builder from ever constructing different URLs for the same ref.
SOURCE_KEYS = {
    "roscomvpn": "roscomvpn_geosite",
    "roscomvpn_geosite": "roscomvpn_geosite",
    "roscomvpn_geoip": "roscomvpn_geoip",
    "itdog": "itdog_allow_domains",
    "itdog_allow_domains": "itdog_allow_domains",
    "codelab": "codelab_ruleset",
    "codelab_ruleset": "codelab_ruleset",
    "blackmatrix7": "blackmatrix7",
}

# Own curated lists in tools/ruleset-builder/lists/ (no download).
LOCAL_SOURCE = "local"

# Keys of a category mapping that are options, not upstream sources.
#   exclude_domains: list (all sources) or {source: [domains]} (per source).
#                    Removes exactly these entries; sub-domains are kept.
#   optional:        true -> an empty result skips the category instead of
#                    failing the whole build.
RESERVED_CATEGORY_KEYS = frozenset({"exclude_domains", "optional"})


def source_url(sources: dict[str, Any], source_name: str, rel: str) -> str:
    try:
        key = SOURCE_KEYS[source_name]
    except KeyError as exc:
        raise ValueError(
            f"Unknown source '{source_name}'. Expected one of: "
            f"{', '.join(sorted(SOURCE_KEYS))}"
        ) from exc

    try:
        base = sources[key]["raw_base"]
    except KeyError as exc:
        raise ValueError(
            f"Source '{source_name}' is missing raw_base in repositories.yaml"
        ) from exc

    rel = rel.lstrip("/")

    # roscomvpn-geosite keeps its plain source files under data/ (compiled sets under release/).
    if key == "roscomvpn_geosite" and not rel.startswith(("data/", "release/")):
        rel = f"data/{rel}"

    # blackmatrix7 stores every service as rule/Clash/<Name>/<Name>.yaml
    # (classical format). A bare service name is expanded to that path.
    if key == "blackmatrix7" and not rel.lower().endswith((".yaml", ".yml")):
        rel = f"{rel}/{rel.rsplit('/', 1)[-1]}.yaml"

    return base.rstrip("/") + "/" + rel


# --------------------------------------------------------------------------
# MALW hosts file helpers
# --------------------------------------------------------------------------

# '#' comment lines that are metadata, not section headings. Treating them as
# headings would silently move the following hosts into a bogus section.
_MALW_META_RE = re.compile(r"^(?:последнее\s+обновление|last\s+updated?|updated)\b", re.I)


def malw_heading(line: str) -> str | None:
    """Return the section name when ``line`` is a MALW section heading."""
    stripped = line.strip()
    if not stripped.startswith("#"):
        return None
    if stripped.startswith("###"):  # file banner: "### dns.malw.link: hosts file"
        return None
    heading = stripped.lstrip("#").strip()
    if not heading or _MALW_META_RE.match(heading):
        return None
    return heading


def malw_last_update(text: str) -> str | None:
    """Return the raw 'last update' phrase from the hosts file, if present."""
    for line in text.splitlines():
        heading = line.strip().lstrip("#").strip()
        if line.strip().startswith("#") and _MALW_META_RE.match(heading):
            return heading.split(":", 1)[-1].strip() or None
    return None


def malw_entry_names(entry: Any) -> tuple[list[str], bool]:
    """Normalise a MALW entry from categories.yaml.

    ``"Name"``            -> required section
    ``"?Name"``           -> optional section (missing is a warning)
    ``["A", "B"]``        -> alternatives, the first non-empty one wins
    Returns ``(names, optional)``.
    """
    items = entry if isinstance(entry, (list, tuple)) else [entry]
    optional = False
    names: list[str] = []
    for item in items:
        text = str(item).strip()
        if text.startswith("?"):
            optional = True
            text = text[1:].strip()
        if text:
            names.append(text)
    return names, optional


def collect_source_urls(categories: dict[str, Any], sources: dict[str, Any],
                        groups: tuple[str, ...] = ("services", "categories", "ip_categories")) -> dict[str, list[tuple[str, str, str]]]:
    """Map every upstream URL to the (group, category, "source:rel") entries using it.

    MALW is a single hosts file and is not part of this map.
    """
    refs: dict[str, list[tuple[str, str, str]]] = {}
    for group in groups:
        for category, mapping in (categories.get(group) or {}).items():
            for source_name, entries in (mapping or {}).items():
                if source_name in RESERVED_CATEGORY_KEYS or source_name in ("malw", LOCAL_SOURCE):
                    continue
                for rel in entries or []:
                    url = source_url(sources, source_name, rel)
                    refs.setdefault(url, []).append((group, category, f"{source_name}:{rel}"))
    return refs
