#!/usr/bin/env python3
"""answer_forge.py — answer-format candidate ledger for answer-style challenges.

Problem it solves: blind guessing with no memory (CHAL-002/004/009 burned 11
submits). This ledger generates RANKED candidates from evidence, records every
tried candidate with verdict, enforces STOP rules, and NEVER invents hex.

Usage:
  answer_forge.py --chal CHAL-002 --evidence "username=cw_afterhours_88" --evidence "kind=handle"
  answer_forge.py --chal CHAL-002 --propose           # prints ranked untried list
  answer_forge.py --chal CHAL-002 --tried "FLAG{x}" --verdict rejected
  answer_forge.py --chal CHAL-002 --log               # tried history + stop status

Rules: max 5 tried per chal without NEW evidence (6th refused, exit 3 → escalate).
Templates expand ONLY from recorded evidence strings; {hex8} slots stay EMPTY
until a hex source is recorded (author-pattern mining feeds evidence, not guesses).
Ledger lives in state.json _submissions (via state_manager log-submit/submits).
Exit 0=ok, 1=error, 3=budget-exhausted.
"""
import argparse
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAX_TRIED = 5

TEMPLATES = [
    ("plain", "FLAG[{s}]"),
    ("under", "FLAG[{a}_{b}]"),
    ("colon", "FLAG[{a}:{b}]"),
    ("space", "FLAG[{a} {b}]"),
    ("hex8", "FLAG[{s}_{h8}]"),  # h8 MUST come from evidence; never invented
]

def sm(*args):
    p = subprocess.run(["python3", os.path.join(ROOT, "tools", "state_manager.py"), *args],
                       capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr

def load_evidence(chal):
    fp = os.path.join(ROOT, "challenges", "_answer_evidence.json")
    try:
        return json.load(open(fp)).get(chal, {})
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_evidence(chal, ev):
    fp = os.path.join(ROOT, "challenges", "_answer_evidence.json")
    try:
        d = json.load(open(fp))
    except (FileNotFoundError, json.JSONDecodeError):
        d = {}
    d.setdefault(chal, {}).update(ev)
    json.dump(d, open(fp, "w"), indent=1)

def tried_list(chal):
    rc, out = sm("submits", chal)
    if rc != 0:
        return []
    try:
        return json.loads(out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return []

def propose(ev):
    vals = [v for v in ev.values() if isinstance(v, str) and v]
    cands = []
    for v in vals:
        cands.append(("plain", f"FLAG[{v}]".replace("[", "{").replace("]", "}")))
    if len(vals) >= 2:
        a, b = vals[0], vals[1]
        for name, t in [("under", f"FLAG[{a}_{b}]"), ("colon", f"FLAG[{a}:{b}]"),
                        ("space", f"FLAG[{a} {b}]")]:
            cands.append((name, t.replace("[", "{").replace("]", "}")))
    if ev.get("hex8"):
        for v in vals:
            if v != ev["hex8"]:
                cands.append(("hex8", f"FLAG[{v}_{ev['hex8']}]".replace("[", "{").replace("]", "}")))
    else:
        cands.append(("hex8-NEEDS-SOURCE", "BLOCKED: no hex8 evidence recorded — mine it first"))
    seen, out = set(), []
    for name, c in cands:
        if c not in seen:
            seen.add(c)
            out.append((name, c))
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chal", required=True)
    ap.add_argument("--evidence", action="append", default=[],
                    help="KEY=VALUE observed fact (repeatable)")
    ap.add_argument("--propose", action="store_true")
    ap.add_argument("--tried", default=None)
    ap.add_argument("--verdict", default="rejected",
                    choices=("rejected", "solved", "error"))
    ap.add_argument("--log", action="store_true")
    a = ap.parse_args()

    if a.evidence:
        ev = {}
        for e in a.evidence:
            if "=" in e:
                k, v = e.split("=", 1)
                ev[k.strip()] = v.strip()
        save_evidence(a.chal, ev)
        print(f"evidence recorded for {a.chal}: {sorted(ev)}")
        if not (a.propose or a.tried or a.log):
            return 0
    if a.propose:
        ev = load_evidence(a.chal)
        tried = {t.get("candidate") for t in tried_list(a.chal)}
        n = 0
        for name, c in propose(ev):
            mark = "TRIED" if c in tried else "fresh"
            print(f"[{name}] {c}  ({mark})")
            n += 1
        print(f"{len(tried)}/{MAX_TRIED} tried")
        return 0
    if a.tried:
        hist = tried_list(a.chal)
        if len(hist) >= MAX_TRIED and a.verdict != "solved":
            print(f"STOP: {len(hist)}/{MAX_TRIED} tried for {a.chal} — escalate, do not guess")
            return 3
        rc, out = sm("log-submit", a.chal, a.tried, a.verdict)
        print(out.strip().splitlines()[-1] if out.strip() else f"recorded {a.verdict}")
        return rc
    if a.log:
        hist = tried_list(a.chal)
        for h in hist:
            print(f"{h.get('at', '?')[:19]} {h.get('verdict', '?'):8s} {h.get('candidate', '')[:70]}")
        print(f"{len(hist)}/{MAX_TRIED} tried")
        return 0
    ap.print_help()
    return 1

if __name__ == "__main__":
    sys.exit(main())
