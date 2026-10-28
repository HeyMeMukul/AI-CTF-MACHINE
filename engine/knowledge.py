"""Verified recipe knowledge: load, retrieve, format, audit.

Only recipes with ``"verified": true`` are retrieved by default.  The legacy
one-line writeup manifests are deliberately not loaded here: they are a
reading list with unknown provenance, not executable technique.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

STOP = set(
    "the a an of to in for on with via and or is are was were be by as at from that this it its "
    "into over under use used using can may will would should".split()
)
_TOKEN_RE = re.compile(r"[A-Za-z0-9_+.-]{2,}")


def _tokens(text: str) -> set[str]:
    return {t.lower() for t in _TOKEN_RE.findall(text or "") if t.lower() not in STOP}


def load_recipes(root: str | Path) -> list[dict]:
    root = Path(root)
    if not root.is_dir():
        return []
    recipes: list[dict] = []
    for path in sorted(root.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            continue
        for item in data:
            if not isinstance(item, dict) or not item.get("id"):
                continue
            item.setdefault("verified", False)
            item.setdefault("source_path", str(path))
            recipes.append(item)
    return recipes


def retrieve(
    query: str,
    root: str | Path,
    domain: str | None = None,
    top_k: int = 2,
    include_unverified: bool = False,
    include_source_verified: bool = False,
) -> list[dict]:
    q = _tokens(query)
    scored: list[tuple[float, dict]] = []
    for recipe in load_recipes(root):
        verified = bool(recipe.get("verified", False))
        source_verified = recipe.get("verification") == "source"
        if not include_unverified and not verified and not (include_source_verified and source_verified):
            continue
        if domain and recipe.get("domain") and recipe.get("domain") != domain:
            # Keep cross-domain recipes in the pool, but at a lower weight.
            domain_bonus = 0.0
        else:
            domain_bonus = 2.0
        text = " ".join(
            [str(recipe.get("title", "")), str(recipe.get("domain", ""))]
            + [str(x) for x in recipe.get("signals", [])]
            + [str(x) for x in recipe.get("steps", [])]
        )
        overlap = len(q & _tokens(text))
        if overlap == 0:
            continue
        score = overlap + domain_bonus + (1.0 if verified else (0.5 if source_verified else 0.0))
        scored.append((score, recipe))
    scored.sort(key=lambda item: (-item[0], str(item[1].get("id", ""))))
    return [recipe for _, recipe in scored[: max(0, top_k)]]


def audit(root: str | Path) -> list[str]:
    problems: list[str] = []
    recipes = load_recipes(root)
    if not recipes:
        problems.append("no recipes found")
    seen: set[str] = set()
    for recipe in recipes:
        rid = str(recipe.get("id", ""))
        if rid in seen:
            problems.append(f"{rid}: duplicate id")
        seen.add(rid)
        for key in ("id", "domain", "title", "steps", "sources", "verified_by", "last_verified"):
            if not recipe.get(key):
                problems.append(f"{rid}: missing {key}")
        if recipe.get("verified") and not recipe.get("fixtures"):
            problems.append(f"{rid}: verified recipe has no fixtures")
        if recipe.get("verification") == "source" and not recipe.get("sources"):
            problems.append(f"{rid}: source-verified recipe has no sources")
        if not isinstance(recipe.get("steps"), list) or len(recipe.get("steps", [])) < 2:
            problems.append(f"{rid}: needs at least two steps")
    return problems


def load_catalog(root: str | Path) -> dict:
    path = Path(root) / "knowledge" / "catalog" / "index.json"
    if not path.is_file():
        return {"entries": [], "total": 0, "counts": {}}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"entries": [], "total": 0, "counts": {}}


def search_catalog(query: str, root: str | Path, top_k: int = 10,
                   domains: list[str] | None = None, include_unmapped: bool = False) -> list[dict]:
    q = _tokens(query)
    if not q:
        return []
    catalog = load_catalog(root)
    scored: list[tuple[float, dict]] = []
    for entry in catalog.get("entries", []):
        if not include_unmapped and entry.get("status") == "unmapped":
            continue
        if domains and not (set(domains) & set(entry.get("domains") or [])):
            continue
        text = " ".join([str(entry.get("name", "")), str(entry.get("description", "")),
                         " ".join(entry.get("domains") or [])])
        overlap = len(q & _tokens(text))
        if overlap == 0:
            continue
        score = overlap + float(entry.get("score") or 0) / 2.0
        if entry.get("status") == "imported":
            score += 2.0
        scored.append((score, entry))
    scored.sort(key=lambda item: (-item[0], str(item[1].get("id", ""))))
    return [entry for _, entry in scored[: max(0, top_k)]]


def catalog_stats(root: str | Path) -> dict:
    catalog = load_catalog(root)
    return {"total": catalog.get("total", 0), "counts": catalog.get("counts", {})}
