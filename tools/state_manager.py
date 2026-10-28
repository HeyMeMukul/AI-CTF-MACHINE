#!/usr/bin/env python3
"""state_manager.py — CTF session state (single source of truth, Lead-writes-only).

Ported from bugbounty-ai-framework-improved (contracts compatible):
flock + state.json.bak + atomic write + _meta stamp. Exit 0=ok, 1=error,
2=warnings-only (check-* commands).

Usage:
  state_manager.py status
  state_manager.py lock-worker <task-name>            # e.g. tasks/task-003-exploit-CHAL-001.md
  state_manager.py unlock-worker [task-name]
  state_manager.py check-timeouts                     # prune exceeded worker_timeout_minutes
  state_manager.py log-attempt <EXP-ID> <confirmed|negative|partial|blocked> [--chal CHAL-XXX]
  state_manager.py attempts <EXP-ID>
  state_manager.py add-challenge --from <surface.json>
  state_manager.py add-flag --chal <CHAL-XXX> --file <flag.txt> [--validated --proof <FLAG-XXX.validated.md>]
  state_manager.py token-budget [--add-task <phase>] [description]

Hardening additions vs original: per-EXP attempt ledger + retry-budget refusal
(>max_retries_per_hypothesis non-confirmed → exit 1), time-tier tracking on slots.
"""
import argparse, fcntl, json, os, shutil, subprocess, sys, time
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE = os.path.join(ROOT, "state.json")
LOCKF = os.path.join(ROOT, ".state.lock")
BAK = os.path.join(ROOT, "state.json.bak")

TOKEN_ESTIMATES = {
    "triage": 800, "recon": 2000, "analysis_per_target": 2000,
    "exploit_per_hypothesis": 3000, "validation": 1500,
    "flagpath_synthesis": 2000, "writeup": 3000,
    "browser_extract": 2000, "thinking": 1500,
}
VALID_PHASE_STATUSES = {"not_started", "in_progress", "complete"}

def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def load():
    try:
        return json.load(open(STATE))
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"ERROR: state.json unreadable: {e}", file=sys.stderr)
        sys.exit(1)

def save(st, by):
    st["_meta"]["last_updated_by"] = by
    st["_meta"]["last_updated_at"] = now()
    if os.path.exists(STATE):
        shutil.copy2(STATE, BAK)
    tmp = STATE + ".tmp"
    json.dump(st, open(tmp, "w"), indent=2)
    os.replace(tmp, STATE)

def locked(fn):
    with open(LOCKF, "w") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            return fn()
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)

def cmd_status(st):
    c = st["competition"]
    print(f"COMPETITION: {c.get('name')} [{c.get('platform')}] status={c.get('status')} focus={c.get('current_focus')}")
    print(f"CHALLENGES: {len(st.get('challenges', []))}  FLAGS: {len(st.get('flags', []))} "
          f"(validated={sum(1 for f in st.get('flags', []) if f.get('validated'))})")
    for ph in ("triage", "recon", "analysis", "exploiting", "validating", "writeups"):
        print(f"  {ph}: {st.get(ph, {}).get('status')}")
    ex = st.get("exploiting", {})
    print(f"  attempts={ex.get('attempts', 0)} confirmed={ex.get('confirmed', 0)} "
          f"negative={ex.get('negative', 0)} deferred={ex.get('deferred', 0)}")
    cc = st.get("_concurrency", {})
    act = cc.get("active_tasks", {})
    print(f"WORKERS: active={len(act)} (max={st.get('_settings', {}).get('parallel_workers', 2)})")
    for name, info in act.items():
        print(f"  - {name} since {info.get('started_at')}")
    tb = st.get("_token_budget", {})
    print(f"BUDGET: estimated_consumed={tb.get('estimated_consumed', 0)}/{tb.get('context_limit', 800000)}")
    return 0

def cmd_lock(st, task):
    cc = st.setdefault("_concurrency", {})
    act = cc.setdefault("active_tasks", {})
    maxw = st.get("_settings", {}).get("parallel_workers", 2)
    if task in act:
        print(f"ERROR: duplicate slot {task}")
        return 1
    if len(act) >= maxw:
        print(f"ERROR: {len(act)} workers active (max {maxw})")
        return 1
    used = {i.get("slot") for i in act.values()}
    slot = next(s for s in range(1, maxw + 1) if s not in used)
    act[task] = {"started_at": now(), "slot": slot}
    cc["worker_active"] = True
    cc["active_task"] = task
    cc["task_started_at"] = act[task]["started_at"]
    print(f"locked {task} (slot {slot}/{maxw})")
    return 0

def cmd_unlock(st, task):
    cc = st.setdefault("_concurrency", {})
    act = cc.setdefault("active_tasks", {})
    if task:
        if task not in act:
            print(f"[INFO] nothing to unlock for {task}")
            return 0
        del act[task]
    elif act:
        task = sorted(act)[0]
        del act[task]
    else:
        print("[INFO] no active workers")
        return 0
    cc["worker_active"] = bool(act)
    cc["active_task"] = sorted(act)[0] if act else None
    cc["last_completed_task"] = task
    cc["last_completed_at"] = now()
    print(f"unlocked {task}")
    return 0

def cmd_timeouts(st):
    mins = st.get("_settings", {}).get("worker_timeout_minutes", 30)
    cc = st.setdefault("_concurrency", {})
    act = cc.get("active_tasks", {})
    tos = st.setdefault("_timeouts", [])
    fired = []
    for name, info in list(act.items()):
        try:
            start = datetime.strptime(info["started_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except (KeyError, ValueError):
            continue
        el = (datetime.now(timezone.utc) - start).total_seconds() / 60
        if el > mins:
            del act[name]
            tos.append({"task": name, "started_at": info["started_at"],
                        "detected_at": now(), "elapsed_minutes": round(el, 1)})
            fired.append(name)
    cc["worker_active"] = bool(act)
    cc["active_task"] = sorted(act)[0] if act else None
    for f in fired:
        print(f"TIMEOUT evicted: {f}")
    if fired:
        return 1
    print("[INFO] no timeouts")
    return 0

def attempts_for(st, exp):
    return [e for e in st.get("_attempt_log", []) if e.get("exp_id") == exp]

def cmd_log_attempt(st, exp, verdict, chal):
    if verdict not in ("confirmed", "negative", "partial", "blocked"):
        print(f"ERROR: bad verdict {verdict}")
        return 1
    maxr = st.get("_settings", {}).get("max_retries_per_hypothesis", 3)
    prior = [e for e in attempts_for(st, exp) if e.get("verdict") != "confirmed"]
    if verdict != "confirmed" and len(prior) >= maxr:
        print(f"ERROR: retry budget exhausted for {exp} ({len(prior)}/{maxr}) — escalate, do not retry")
        return 1
    st.setdefault("_attempt_log", []).append(
        {"exp_id": exp, "verdict": verdict, "chal": chal, "at": now()})
    ex = st.setdefault("exploiting", {})
    ex["attempts"] = ex.get("attempts", 0) + 1
    if verdict == "confirmed":
        ex["confirmed"] = ex.get("confirmed", 0) + 1
        if exp not in ex.get("tested_exp_ids", []):
            ex.setdefault("tested_exp_ids", []).append(exp)
    elif verdict == "negative":
        ex["negative"] = ex.get("negative", 0) + 1
        if exp not in ex.get("tested_exp_ids", []):
            ex.setdefault("tested_exp_ids", []).append(exp)
    elif verdict == "blocked":
        ex["deferred"] = ex.get("deferred", 0) + 1
    print(f"attempt logged: {exp}={verdict} ({len(prior) + 1}/{maxr})")
    return 0

def cmd_add_challenge(st, surface_path):
    try:
        s = json.load(open(surface_path))
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"ERROR: bad surface.json: {e}")
        return 1
    for req in ("chal_id", "category", "route"):
        if req not in s:
            print(f"ERROR: surface.json missing {req}")
            return 1
    chals = st.setdefault("challenges", [])
    chdir = os.path.dirname(os.path.abspath(surface_path))
    entry = {"id": s["chal_id"], "title": s.get("title", s["chal_id"]),
             "category": s["category"], "domain": s.get("domain", s["category"]),
             "points": s.get("points", 0), "path": os.path.relpath(chdir, ROOT),
             "status": "triaged", "surface": os.path.relpath(surface_path, ROOT),
             "service": s.get("service")}
    for i, c in enumerate(chals):
        if c.get("id") == s["chal_id"]:
            chals[i] = {**c, **entry}  # refresh path/domain on re-triage (keeps flags)
            print(f"[INFO] {s['chal_id']} re-registered at {entry['path']}")
            break
    else:
        chals.append(entry)
        st.setdefault("triage", {})["classified"] = st.get("triage", {}).get("classified", 0) + 1
    print(f"registered {s['chal_id']} ({s['category']} → {s['route']}) at {entry['path']}")
    return 0

def cmd_add_flag(st, chal, flag_file, validated, proof):
    r = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "flag_checker.py"),
                        "--file", flag_file], capture_output=True, text=True)
    if r.returncode != 0:
        print(f"ERROR: flag_checker rejected {flag_file} (no flag-format match)")
        return 1
    if validated and (not proof or not os.path.isfile(proof)):
        print("ERROR: --validated requires an existing FLAG-XXX.validated.md --proof")
        return 1
    flags = st.setdefault("flags", [])
    if any(f.get("chal_id") == chal for f in flags):
        print(f"[INFO] flag for {chal} already recorded")
        return 0
    flags.append({"chal_id": chal, "flag_file": flag_file,
                  "validated": bool(validated), "proof": proof, "at": now()})
    if validated:
        st.setdefault("validating", {})["validated_count"] = \
            st.get("validating", {}).get("validated_count", 0) + 1
        for c in st.get("challenges", []):
            if c.get("id") == chal:
                c["status"] = "solved"
    print(f"flag recorded for {chal} (validated={bool(validated)}) — value stays in file only")
    return 0

def cmd_budget(st, phase, desc):
    if phase and phase not in TOKEN_ESTIMATES:
        print(f"ERROR: unknown phase {phase} (known: {sorted(TOKEN_ESTIMATES)})")
        return 1
    tb = st.setdefault("_token_budget", {})
    if phase:
        est = TOKEN_ESTIMATES[phase]
        tb["estimated_consumed"] = tb.get("estimated_consumed", 0) + est
        tb.setdefault("task_log", []).append(
            {"description": desc or phase, "phase": phase, "tokens_reserved": est, "at": now()})
        print(f"reserved ~{est} for {phase}")
    else:
        lim = tb.get("context_limit", 800000)
        used = tb.get("estimated_consumed", 0)
        pct = 100.0 * used / lim if lim else 0
        print(f"budget: {used}/{lim} ({pct:.1f}%)")
        if pct > 90:
            print("CRITICAL: over 90% — stop dispatching, summarize and handoff")
            return 2
        if pct > 80:
            print("WARN: over 80%")
            return 2
    return 0

def cmd_submits(st, chal):
    hist = [s for s in st.get("_submissions", []) if s.get("chal") == chal]
    print(json.dumps(hist))
    return 0

def cmd_log_submit(st, chal, candidate, verdict):
    if verdict not in ("rejected", "solved", "error", "blocked"):
        print(f"ERROR: bad verdict {verdict}")
        return 1
    st.setdefault("_submissions", []).append(
        {"chal": chal, "candidate": candidate[:120], "verdict": verdict, "at": now()})
    print(f"submit logged: {chal} {verdict} ({len([s for s in st['_submissions'] if s['chal'] == chal])} total)")
    return 0

def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status")
    p = sub.add_parser("lock-worker"); p.add_argument("task")
    p = sub.add_parser("unlock-worker"); p.add_argument("task", nargs="?")
    sub.add_parser("check-timeouts")
    p = sub.add_parser("log-attempt"); p.add_argument("exp_id"); p.add_argument("verdict"); p.add_argument("--chal", default=None)
    p = sub.add_parser("attempts"); p.add_argument("exp_id")
    p = sub.add_parser("add-challenge"); p.add_argument("--from", dest="frm", required=True)
    p = sub.add_parser("add-flag"); p.add_argument("--chal", required=True); p.add_argument("--file", required=True)
    p.add_argument("--validated", action="store_true"); p.add_argument("--proof", default=None)
    p = sub.add_parser("token-budget"); p.add_argument("--add-task", default=None); p.add_argument("desc", nargs="?")
    p = sub.add_parser("submits"); p.add_argument("chal")
    p = sub.add_parser("log-submit"); p.add_argument("chal"); p.add_argument("candidate"); p.add_argument("verdict")
    a = ap.parse_args()
    st = load()

    def run():
        if a.cmd == "status":
            return cmd_status(st)
        if a.cmd == "lock-worker":
            rc = cmd_lock(st, a.task)
            if rc == 0:
                save(st, f"lock-worker {a.task}")
            return rc
        if a.cmd == "unlock-worker":
            rc = cmd_unlock(st, a.task)
            save(st, f"unlock-worker {a.task or ''}")
            return rc
        if a.cmd == "check-timeouts":
            rc = cmd_timeouts(st)
            save(st, "check-timeouts")
            return rc
        if a.cmd == "log-attempt":
            rc = cmd_log_attempt(st, a.exp_id, a.verdict, a.chal)
            if rc == 0:
                save(st, f"log-attempt {a.exp_id}={a.verdict}")
            return rc
        if a.cmd == "attempts":
            hist = attempts_for(st, a.exp_id)
            print(f"{a.exp_id}: {len(hist)} attempts " +
                  str([h["verdict"] for h in hist]))
            return 0
        if a.cmd == "add-challenge":
            rc = cmd_add_challenge(st, a.frm)
            if rc == 0:
                save(st, f"add-challenge {a.frm}")
            return rc
        if a.cmd == "add-flag":
            rc = cmd_add_flag(st, a.chal, a.file, a.validated, a.proof)
            if rc == 0:
                save(st, f"add-flag {a.chal}")
            return rc
        if a.cmd == "token-budget":
            rc = cmd_budget(st, a.add_task, a.desc)
            if rc == 0 and a.add_task:
                save(st, f"token-budget {a.add_task}")
            return rc
        if a.cmd == "submits":
            return cmd_submits(st, a.chal)
        if a.cmd == "log-submit":
            rc = cmd_log_submit(st, a.chal, a.candidate, a.verdict)
            if rc == 0:
                save(st, f"log-submit {a.chal}")
            return rc
        return 1
    return locked(run)

if __name__ == "__main__":
    sys.exit(main())
