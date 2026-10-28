#!/usr/bin/env python3
"""race.py — diversified parallel-attempt harness (Veria-style racing, Lead-run).

SOTA basis: racing diverse models/prompts with first-flag-wins + shared bus
won live CTFs outright; single-agent caps at 5-9% live. Full multi-model racing
needs API keys per model; this harness implements what works WITHOUT them:
same-worker diversified restarts (angle x temperature x seed) + shared
findings bus + first-flag-wins merge + per-approach ledger.

Usage:
  race.py --chal CHAL-009 --plan out.json
      Emit N diversified attempt plans (angles x temps) for Lead dispatch.
  race.py --chal CHAL-009 --bus-note "try epoch timestamps" --from worker1
      Append a finding to the shared bus (results/bus/CHAL-009.jsonl).
  race.py --chal CHAL-009 --bus
      Show bus.  race.py --chal CHAL-009 --win "FLAG{...}" --by worker2
      Record winner (length only in ledger; value stays in flag.txt flow).
  race.py --chal CHAL-009 --ledger
      Per-approach win/attempt stats.
Angles rotate: direct/technique-variant/encoding-variant/oracle-variant/
tool-variant. Temps: policy executor 0.7, +0.1 per retry (max 1.0).
Exit 0=ok, 1=error.
"""
import argparse
import datetime
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUSDIR = os.path.join(ROOT, "results", "bus")

ANGLES = ["direct", "technique-variant", "encoding-variant",
          "oracle-variant", "tool-variant"]

def buspath(chal):
    os.makedirs(BUSDIR, exist_ok=True)
    return os.path.join(BUSDIR, f"{chal}.jsonl")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chal", required=True)
    ap.add_argument("--plan", default=None, help="write N diversified plans to JSON")
    ap.add_argument("--lanes", type=int, default=3)
    ap.add_argument("--bus-note", default=None)
    ap.add_argument("--from", dest="frm", default="lead")
    ap.add_argument("--bus", action="store_true")
    ap.add_argument("--win", default=None, help="winning flag VALUE (stored hashed!)")
    ap.add_argument("--by", default=None)
    ap.add_argument("--ledger", action="store_true")
    a = ap.parse_args()

    if a.plan:
        import hashlib
        plans = []
        for i in range(a.lanes):
            plans.append({
                "lane": i + 1, "chal": a.chal,
                "angle": ANGLES[i % len(ANGLES)],
                "temp": round(min(1.0, 0.7 + 0.1 * i), 2),
                "seed_note": f"restart-{i + 1}-not-resume",
                "budget": "15 tool calls, 120s/cmd",
                "rule": "first-flag-wins; share findings via --bus-note; "
                        "never resume a dead lane, start a new angle",
            })
        json.dump(plans, open(a.plan, "w"), indent=1)
        print(f"race plan: {a.lanes} lanes → {a.plan}")
        return 0
    if a.bus_note:
        rec = {"ts": datetime.datetime.utcnow().isoformat() + "Z",
               "from": a.frm, "note": a.bus_note[:300]}
        open(buspath(a.chal), "a").write(json.dumps(rec) + "\n")
        print(f"bus <- [{a.frm}] {a.bus_note[:80]}")
        return 0
    if a.bus:
        try:
            for line in open(buspath(a.chal), errors="ignore"):
                print(line.rstrip()[:200])
        except FileNotFoundError:
            print("bus empty")
        return 0
    if a.win:
        import hashlib
        rec = {"ts": datetime.datetime.utcnow().isoformat() + "Z", "win_by": a.by,
               "flag_sha256": hashlib.sha256(a.win.encode()).hexdigest(),
               "flag_len": len(a.win)}
        open(buspath(a.chal), "a").write(json.dumps(rec) + "\n")
        print(f"winner recorded for {a.chal} by {a.by} (hash only)")
        return 0
    if a.ledger:
        wins, notes = {}, 0
        try:
            for line in open(buspath(a.chal), errors="ignore"):
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                if "win_by" in r:
                    wins[r["win_by"]] = wins.get(r["win_by"], 0) + 1
                else:
                    notes += 1
        except FileNotFoundError:
            pass
        print(f"bus notes={notes} wins={wins or 'none yet'}")
        return 0
    ap.print_help()
    return 1

if __name__ == "__main__":
    sys.exit(main())
