#!/usr/bin/env python3
"""writeup_generator.py — skeleton writeup from validated artifacts (Lead fills root cause).

Usage: writeup_generator.py --chal CHAL-001 [--out writeups/CHAL-001.md]
Reads: challenges/<domain>/CHAL-001-*/surface.json, profiles/CP-*.profile.yaml,
exploits/EXP-*.confirmed.md, FLAG-*.validated.md, flag.txt (existence only —
value NEVER printed). Emits template with TODO(root-cause) markers for Lead.
Exit 0=skeleton written, 1=missing validated inputs (do NOT write from unvalidated).
"""
import argparse
import glob
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def find_chal(chal):
    hits = glob.glob(os.path.join(ROOT, "challenges", "*", f"{chal}*"))
    hits = [h for h in hits if os.path.isdir(h) and "_inbox" not in h]
    return hits[0] if hits else None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chal", required=True)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    d = find_chal(a.chal)
    if not d:
        print(f"ERROR: no challenge dir for {a.chal}")
        return 1
    val = glob.glob(os.path.join(d, "FLAG-*.validated.md"))
    conf = glob.glob(os.path.join(d, "exploits", "EXP-*.confirmed.md"))
    if not val or not conf:
        print(f"ERROR: need FLAG-*.validated.md + EXP-*.confirmed.md in {d} — refusing")
        return 1
    try:
        surf = json.load(open(os.path.join(d, "surface.json")))
    except (FileNotFoundError, json.JSONDecodeError):
        surf = {}
    flagf = os.path.join(d, "flag.txt")
    flag_ok = os.path.isfile(flagf) and bool(open(flagf, errors="ignore").read().strip())
    exp = os.path.basename(conf[0])
    md = f"""# {a.chal} — {surf.get('title', a.chal)} ({surf.get('category', '?')}, {surf.get('points', '?')} pts)
Flag: see `{os.path.relpath(flagf, ROOT)}` (validated={flag_ok}; chat summary says length only)

## Recon (3 lines)
- Surface: {surf.get('category')} via {surf.get('route')} (confidence {surf.get('confidence')})
- TODO(Lead): key signals (3 max)

## Vulnerability (root cause, 5 lines)
- TODO(Lead): root cause from {exp}

## Exploit (numbered re-runnable steps)
- TODO(Lead): steps + solve.py ref (`exploits/solve.py`, `timeout 120`)

## Dead ends (1 line each, max 3)
- TODO(Lead)

## Lessons (reusable pattern → knowledge_ingest.py --from this file)
- TODO(Lead)

## Provenance
- surface: `{os.path.relpath(os.path.join(d, 'surface.json'), ROOT)}`
- profile(s): {', '.join(sorted(os.path.basename(p) for p in glob.glob(os.path.join(d, 'profiles', 'CP-*.profile.yaml')))) or 'TODO'}
- exploit: `exploits/{exp}`
- proof: `{os.path.basename(val[0])}`
"""
    out = a.out or os.path.join(ROOT, "writeups", f"{a.chal}.md")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    open(out, "w").write(md)
    print(f"skeleton → {out} (fill TODO(root-cause) — never from unvalidated attempts)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
