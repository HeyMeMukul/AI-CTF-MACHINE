#!/usr/bin/env python3
"""framework_lint.py — structural checks for the CTF framework.

Checks:
  - required files exist
  - every skill has the required frontmatter
  - every imported card carries source/license/status
  - the catalog index is valid and populated
  - slash-command templates only reference files that exist
  - tools mentioned in the core docs exist
  - runtime artifacts are covered by .gitignore

Usage: python3 tools/framework_lint.py [--strict]
Exit 0=pass, 1=errors, 2=warnings (1 with --strict).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

REQUIRED = [
    "README.md", "AGENTS.md", "master_prompt.md", "lead_prompt.md", "worker_prompt.md",
    "challenge_prompt.md", "opencode.json", "state.json", "skills/index.md",
    "skills/_shared/SKILL_CONTRACT.md", "phases/PHASE_ARCHITECTURE.md",
    "docs/HARDENING.md", "docs/LIVE_OPS.md", "docs/SKILL_IMPORTS.md",
    "tools/framework_lint.py", "engine/__init__.py", "engine/cli.py",
    "eval/suites/smoke.json", "config/engine.json",
    "skills/imported/NOTICE.md", "knowledge/catalog/index.json",
]

GITIGNORE_REQUIRED = [
    "__pycache__/",
    ".playwright-mcp/",
    "state.json.bak",
    ".state.lock",
    "challenges/_answer_evidence.json",
]

DOCS = ["README.md", "AGENTS.md", "skills/index.md"]


def _frontmatter(text: str) -> str | None:
    if not text.startswith("---"):
        return None
    try:
        return text.split("---", 2)[1]
    except IndexError:
        return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--strict", action="store_true", help="treat warnings as errors")
    args = parser.parse_args()
    errors: list[str] = []
    warnings: list[str] = []

    for rel in REQUIRED:
        if not (ROOT / rel).is_file():
            errors.append(f"missing required file: {rel}")

    for skill in sorted((ROOT / "skills").glob("*/SKILL.md")):
        text = skill.read_text(encoding="utf-8", errors="replace")
        front = _frontmatter(text)
        if front is None:
            errors.append(f"{skill.relative_to(ROOT)}: missing frontmatter")
            continue
        for key in ("name", "description", "category", "phase"):
            if not re.search(rf"(?m)^{key}\s*:", front):
                warnings.append(f"{skill.relative_to(ROOT)}: frontmatter missing {key}")

    imported = sorted((ROOT / "skills" / "imported").glob("*/SKILL.md"))
    if len(imported) < 20:
        errors.append(f"expected >=20 imported skills, found {len(imported)}")
    for skill in imported:
        text = skill.read_text(encoding="utf-8", errors="replace")
        front = _frontmatter(text)
        if front is None:
            errors.append(f"{skill.relative_to(ROOT)}: missing imported frontmatter")
            continue
        for key in ("name", "description", "source", "license", "ctf_domains", "status"):
            if not re.search(rf"(?m)^{key}\s*:", front):
                errors.append(f"{skill.relative_to(ROOT)}: imported frontmatter missing {key}")
        if "http" not in front:
            errors.append(f"{skill.relative_to(ROOT)}: imported card has no source URL")

    catalog_path = ROOT / "knowledge" / "catalog" / "index.json"
    if catalog_path.is_file():
        try:
            catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
        except ValueError as exc:
            errors.append(f"catalog index is not JSON: {exc}")
            catalog = {}
        entries = catalog.get("entries") or []
        if int(catalog.get("total") or 0) < 2000 or len(entries) < 2000:
            errors.append(f"catalog index too small: total={catalog.get('total')} entries={len(entries)}")
        imported_entries = [e for e in entries if e.get("status") == "imported"]
        if len(imported_entries) < 20:
            errors.append(f"catalog marks only {len(imported_entries)} imported entries")
        for entry in entries[:50]:
            for key in ("id", "name", "url", "status"):
                if not entry.get(key):
                    errors.append(f"catalog entry missing {key}: {entry.get('id')}")
                    break

    try:
        config = json.loads((ROOT / "opencode.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        errors.append(f"opencode.json: {exc}")
        config = {}
    for name, spec in (config.get("command") or {}).items():
        for ref in re.findall(r"`([^`]+\.md)`", str(spec.get("template") or "")):
            if not (ROOT / ref).is_file():
                errors.append(f"opencode command {name}: missing referenced file {ref}")

    for doc in DOCS:
        path = ROOT / doc
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for ref in sorted(set(re.findall(r"tools/([A-Za-z0-9_]+\.py)", text))):
            if not (ROOT / "tools" / ref).is_file():
                errors.append(f"{doc}: references missing tools/{ref}")

    ignore_path = ROOT / ".gitignore"
    ignore = ignore_path.read_text(encoding="utf-8", errors="replace") if ignore_path.is_file() else ""
    for pattern in GITIGNORE_REQUIRED:
        if pattern not in ignore:
            errors.append(f".gitignore is missing the runtime pattern {pattern!r}")

    for warning in warnings:
        print(f"WARN {warning}")
    for error in errors:
        print(f"FAIL {error}")
    print(f"framework_lint: {len(errors)} error(s), {len(warnings)} warning(s), "
          f"{len(imported)} imported skill(s)")
    if errors:
        return 1
    if warnings and args.strict:
        return 1
    return 2 if warnings else 0


if __name__ == "__main__":
    sys.exit(main())
