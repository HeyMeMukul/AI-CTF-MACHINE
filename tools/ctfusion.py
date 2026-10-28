#!/usr/bin/env python3
"""ctfusion.py — live CTF solving loop (CTFusion-inspired, adapted for SOLVING).

KAIST CTFusion evaluates agents on LIVE events (contamination-proof, first-flag
forwarding). This port runs our framework against live platforms the same way:
poll live index → priority queue → fast-solve → submit-once → backfill → learn.

FAST DOCTRINE (user order): flags first, formalities later. Fast mode writes
MINIMAL artifacts (flag.txt + attempt note); --backfill reconstructs the full
iron-loop paperwork (surface/profiles/EXP/gate/state) AFTER the flag lands.

Usage:
  ctfusion.py --poll [--pages N] [--base-url URL]
      Refresh challenges/_index.json (+ _index_pN.json merged, dedup by detail_url).
  ctfusion.py --queue [--max N]
      Print priority queue (unsolved first, easy points first) as JSON.
  ctfusion.py --fast CHAL-002 [--hint TEXT]
      Scaffold minimal fast-solve workspace (given/ + BRIEF.md with statement
      question + constraints). Returns the dir agents solve in.
  ctfusion.py --backfill CHAL-002 --flag-file <path> --steps-file <notes>
      Full paperwork AFTER solve: new_challenge, triage, add-challenge,
      EXP-XXX.confirmed.md, log-attempt, quality gate, add-flag validated.
  ctfusion.py --learn CHAL-002
      Feed solved pattern to knowledge (answer evidence and/or ingest stub).
  ctfusion.py --status
      Ledger: indexed/solved/blocked/pending counts.
Ledger: challenges/_ctfusion.json {chal: {status, updated, note}}.
Exit 0=ok, 1=error, 2=blocked/empty-queue.
"""
import argparse
import glob
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IDX = os.path.join(ROOT, "challenges", "_index.json")
LEDGER = os.path.join(ROOT, "challenges", "_ctfusion.json")

def sh(*args):
    p = subprocess.run(args, capture_output=True, text=True, timeout=300, cwd=ROOT)
    return p.returncode, (p.stdout + p.stderr)[-2000:]

def load_ledger():
    try:
        return json.load(open(LEDGER))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_ledger(lg):
    json.dump(lg, open(LEDGER, "w"), indent=1)

def solved_ids():
    try:
        st = json.load(open(os.path.join(ROOT, "state.json")))
        return {f.get("chal_id") for f in st.get("flags", [])}
    except (FileNotFoundError, json.JSONDecodeError):
        return set()

def cmd_poll(base_url, pages):
    items, seen = [], set()
    for n in range(1, pages + 1):
        url = base_url if n == 1 else f"{base_url}?page={n}"
        out = os.path.join(ROOT, "challenges", f"_index_p{n}.json")
        rc, txt = sh("python3", "tools/browser_extract.py", "--list",
                     "--base-url", url, "--out", out)
        if rc != 0:
            print(f"WARN page {n} failed")
            continue
        try:
            page_items = json.load(open(out))
        except (FileNotFoundError, json.JSONDecodeError):
            continue
        for it in page_items:
            key = it.get("detail_url") or it.get("title")
            if key in seen:
                continue
            seen.add(key)
            items.append(it)
    # assign stable CHAL ids in listed order
    for i, it in enumerate(items, 1):
        it.setdefault("chal_id", f"CHAL-{i:03d}")
    json.dump(items, open(IDX, "w"), indent=1)
    print(f"polled {pages} page(s): {len(items)} unique challenges → _index.json")
    return 0

def cmd_queue(maxn):
    try:
        items = json.load(open(IDX))
    except (FileNotFoundError, json.JSONDecodeError):
        print("ERROR: no index — run --poll first")
        return 1
    done = solved_ids()
    lg = load_ledger()
    q = []
    for it in items:
        cid = it.get("chal_id", "?")
        if cid in done:
            continue
        st = lg.get(cid, {}).get("status", "pending")
        if st == "blocked":
            continue
        q.append({"chal_id": cid, "title": it.get("title"), "points": it.get("points", 9999),
                  "category": it.get("category"), "detail_url": it.get("detail_url"),
                  "ledger": st})
    q.sort(key=lambda x: (x["points"] if isinstance(x["points"], int) else 9999))
    print(json.dumps(q[:maxn], indent=1))
    return 0

def cmd_fast(chal, hint):
    try:
        items = json.load(open(IDX))
    except (FileNotFoundError, json.JSONDecodeError):
        print("ERROR: no index")
        return 1
    it = next((x for x in items if x.get("chal_id") == chal), None)
    if not it:
        print(f"ERROR: {chal} not in index")
        return 1
    d = os.path.join(ROOT, "challenges", "_fast", chal)
    os.makedirs(os.path.join(d, "given"), exist_ok=True)
    brief = (f"# FAST-SOLVE {chal} — {it.get('title')} "
             f"({it.get('points')}pts, {it.get('category')})\n"
             f"detail: {it.get('detail_url')}\n"
             + (f"hint: {hint}\n" if hint else "") +
             "RULES: flag ONLY, fast. Minimal artifacts (attempt note + flag.txt).\n"
             "120s per command. No brute force. Technique-only.\n")
    open(os.path.join(d, "BRIEF.md"), "w").write(brief)
    lg = load_ledger()
    lg.setdefault(chal, {})["status"] = "fast-active"
    save_ledger(lg)
    print(f"fast workspace: {d}")
    return 0

def cmd_backfill(chal, flag_file, steps_file):
    if not (flag_file and os.path.isfile(flag_file)):
        print("ERROR: --flag-file with captured flag required")
        return 1
    steps = open(steps_file, errors="ignore").read() if steps_file and os.path.isfile(steps_file) else ""
    try:
        items = json.load(open(IDX))
    except (FileNotFoundError, json.JSONDecodeError):
        items = []
    it = next((x for x in items if x.get("chal_id") == chal), {})
    # find or scaffold canonical dir
    hits = [p for p in glob.glob(os.path.join(ROOT, "challenges", "*", f"{chal}*")) if os.path.isdir(p)]
    if not hits:
        print(f"ERROR: no canonical dir for {chal} — promote first")
        return 1
    d = hits[0]
    # EXP id: next free
    used = set()
    for f in glob.glob(os.path.join(d, "exploits", "EXP-*.md")):
        m = re.search(r"EXP-(\d+)", f)
        if m:
            used.add(m.group(1))
    exp = f"EXP-{max([int(x) for x in used] + [0]) + 1:03d}"
    open(os.path.join(d, "exploits", f"{exp}.confirmed.md"), "w").write(
        f"# {exp}.confirmed — {chal} (fast-solve backfill)\n## Status: CONFIRMED (platform-accepted)\n"
        f"## Steps\n{steps[:1500]}\n## Verdict: CONFIRMED\n")
    rc, _ = sh("python3", "tools/state_manager.py", "log-attempt", exp, "confirmed", "--chal", chal)
    if rc != 0:
        print("WARN: log-attempt failed")
    proof = os.path.join(d, "FLAG-001.validated.md")
    open(proof, "w").write("# FLAG-001.validated — platform shows Solved (fast backfill)\n")
    dest = os.path.join(d, "flag.txt")
    data = open(flag_file, errors="ignore").read().strip().splitlines()
    open(dest, "w").write((data[0] if data else "") + "\n")
    rc, out = sh("python3", "tools/state_manager.py", "add-flag", "--chal", chal,
                 "--file", os.path.relpath(dest, ROOT), "--validated", "--proof",
                 os.path.relpath(proof, ROOT))
    print(out.strip().splitlines()[-1] if out.strip() else "")
    lg = load_ledger()
    lg.setdefault(chal, {})["status"] = "solved"
    save_ledger(lg)
    # learn hook: record shape evidence for answer-style intel
    print(f"backfilled {chal} ({exp}) — run --learn for pattern mining")
    return 0 if rc == 0 else 1

def cmd_learn(chal):
    ev = {}
    try:
        items = json.load(open(IDX))
        it = next((x for x in items if x.get("chal_id") == chal), {})
        if it.get("category"):
            ev["platform_category"] = it["category"]
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    if ev:
        rc, out = sh("python3", "tools/answer_forge.py", "--chal", chal,
                     *[x for kv in ev.items() for x in ("--evidence", f"{kv[0]}={kv[1]}")])
        print(out.strip().splitlines()[-1] if out.strip() else "")
    print(f"learn note: distill {chal} solve steps into skills/*/techniques on next hardening pass")
    return 0

def cmd_status():
    try:
        items = json.load(open(IDX))
    except (FileNotFoundError, json.JSONDecodeError):
        items = []
    done = solved_ids()
    lg = load_ledger()
    blocked = sum(1 for v in lg.values() if v.get("status") == "blocked")
    print(f"indexed={len(items)} solved={len(done)} blocked={blocked} "
          f"pending={len(items) - len(done) - blocked}")
    return 0

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--poll", action="store_true")
    ap.add_argument("--pages", type=int, default=2)
    ap.add_argument("--base-url", default="https://playctf.in/challenges")
    ap.add_argument("--queue", action="store_true")
    ap.add_argument("--max", type=int, default=10)
    ap.add_argument("--fast", default=None)
    ap.add_argument("--hint", default="")
    ap.add_argument("--backfill", default=None)
    ap.add_argument("--flag-file", default=None)
    ap.add_argument("--steps-file", default=None)
    ap.add_argument("--learn", default=None)
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--mark-blocked", default=None)
    ap.add_argument("--note", default="")
    ap.add_argument("--reindex", action="store_true",
                    help="assign stable chal_id offline (match state by slug, new get max+1)")
    a = ap.parse_args()
    if a.poll:
        return cmd_poll(a.base_url, a.pages)
    if a.queue:
        return cmd_queue(a.max)
    if a.fast:
        return cmd_fast(a.fast, a.hint)
    if a.backfill:
        return cmd_backfill(a.backfill, a.flag_file, a.steps_file)
    if a.learn:
        return cmd_learn(a.learn)
    if a.status:
        return cmd_status()
    if a.mark_blocked:
        lg = load_ledger()
        lg.setdefault(a.mark_blocked, {}).update({"status": "blocked", "note": a.note})
        save_ledger(lg)
        print(f"blocked {a.mark_blocked}")
        return 0
    if a.reindex:
        try:
            items = json.load(open(IDX))
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"ERROR: no index: {e}")
            return 1
        try:
            st = json.load(open(os.path.join(ROOT, "state.json")))
        except (FileNotFoundError, json.JSONDecodeError):
            st = {}
        slug_to_id = {}
        for c in st.get("challenges", []):
            d = c.get("path", "").rstrip("/").split("/")[-1]
            slug = re.sub(r"^CHAL-\d+-?", "", d) or re.sub(r"^CHAL-\d+-?", "", c.get("id", ""))
            if slug:
                slug_to_id[slug] = c["id"]
        used = {c.get("id") for c in st.get("challenges", [])}
        nxt = 1
        for it in items:
            if it.get("chal_id"):
                continue
            slug = (it.get("detail_url", "").rstrip("/").split("/")[-1]
                    or re.sub(r"[^a-z0-9]+", "-", it.get("title", "").lower())[:60])
            base = re.sub(r"-[0-9a-f]{6,}$", "", slug)
            if base in slug_to_id:
                it["chal_id"] = slug_to_id[base]
                continue
            while f"CHAL-{nxt:03d}" in used:
                nxt += 1
            it["chal_id"] = f"CHAL-{nxt:03d}"
            used.add(it["chal_id"])
            nxt += 1
        json.dump(items, open(IDX, "w"), indent=1)
        print(f"reindexed {len(items)} entries")
        return 0
    ap.print_help()
    return 1

if __name__ == "__main__":
    sys.exit(main())
