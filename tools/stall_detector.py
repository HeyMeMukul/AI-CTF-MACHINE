#!/usr/bin/env python3
"""stall_detector.py — 6-signal loop/stall detector → re-plan or specialist escalation.

Usage:
  python3 tools/stall_detector.py --log results/transcript-NNN.log [--history results/]
  python3 tools/stall_detector.py --cmd-history "cmd1|cmd2|cmd3" [--artifacts challenges/CHAL-001/exploits/]

Signals (any 2+ = STALL):
  S1 repeat-cmd   — same normalized command >=3 times in last 10
  S2 syntax-error — same traceback/error signature >=3 times
  S3 no-artifact  — 0 new files in artifact dir for last N minutes (default 20)
  S4 context-bloat— log grew >200KB with no verdict line (EXP-*.md verdict)
  S5 give-up       — agent emitted give-up language ("impossible", "cannot solve", "give up")
  S6 cost-burn    — attempts >= max_retries_per_hypothesis (default 3) with no new evidence

Exit 0 = PROGRESS (keep going), 1 = STALL (prints recommended action:
  retry-corrected | alternate-method | escalate-specialist | re-plan | operator-gate).
"""
import argparse, os, re, sys, time

GIVEUP_RE = re.compile(r"giving up|give up|impossible to|cannot (be )?solved|no (way|point)", re.I)
ERR_RE = re.compile(r"(Traceback \(most recent call last\)|Error:|error: |FAILED|returned non-zero)", re.I)
VERDICT_RE = re.compile(r"verdict\s*:\s*(confirmed|negative|partial)", re.I)

def norm(cmd):
    return re.sub(r"\s+", " ", cmd.strip().lower())[:160]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", default=None, help="transcript log file")
    ap.add_argument("--cmd-history", default="", help="pipe-separated recent commands")
    ap.add_argument("--artifacts", default=None, help="artifact dir to check for new files")
    ap.add_argument("--since-minutes", type=int, default=20)
    ap.add_argument("--max-retries", type=int, default=3)
    a = ap.parse_args()

    text = open(a.log, errors="ignore").read() if a.log and os.path.isfile(a.log) else ""
    cmds = [c for c in a.cmd_history.split("|") if c.strip()] or \
           re.findall(r"^\$ (.+)$", text, re.M)
    recent = [norm(c) for c in cmds[-10:]]
    signals, detail = [], {}

    if recent and max(recent.count(c) for c in set(recent)) >= 3:
        signals.append("S1 repeat-cmd")
        detail["S1"] = max(set(recent), key=recent.count)[:100]
    errs = ERR_RE.findall(text[-20000:] if len(text) > 20000 else text)
    if len(errs) >= 3:
        signals.append("S2 syntax-error")
        detail["S2"] = f"{len(errs)} error lines in tail"
    if a.artifacts and os.path.isdir(a.artifacts):
        cutoff = time.time() - a.since_minutes * 60
        fresh = [f for f in os.listdir(a.artifacts)
                 if os.path.getmtime(os.path.join(a.artifacts, f)) > cutoff]
        if not fresh:
            signals.append("S3 no-artifact")
            detail["S3"] = f"0 new files in {a.since_minutes}min"
    if len(text.encode(errors="ignore")) > 200_000 and not VERDICT_RE.search(text):
        signals.append("S4 context-bloat")
        detail["S4"] = f"{len(text)//1024}KB, no verdict line"
    if GIVEUP_RE.search(text[-5000:] if len(text) > 5000 else text):
        signals.append("S5 give-up")
        detail["S5"] = "give-up language detected"
    attempts = len(re.findall(r"attempt\s+\d+|retry\s+\d+|EXP-\d+", text, re.I))
    if attempts >= a.max_retries * 3 and not VERDICT_RE.search(text):
        signals.append("S6 cost-burn")
        detail["S6"] = f"{attempts} attempt markers, no verdict"

    print(f"signals: {signals if signals else 'none'}")
    for k, v in detail.items():
        print(f"  {k}: {v}")
    if len(signals) >= 2:
        if "S5 give-up" in signals:
            print("ACTION: re-plan (fresh Worker, new hypothesis — never resume dead thread)")
        elif "S2 syntax-error" in signals:
            print("ACTION: retry-corrected (fix syntax once, then alternate-method)")
        elif "S1 repeat-cmd" in signals:
            print("ACTION: escalate-specialist (route to /pwn /crypto /rev /web /forensics)")
        else:
            print("ACTION: alternate-method (1 different technique, then blocked + continue)")
        return 1
    print("ACTION: continue")
    return 0

if __name__ == "__main__":
    sys.exit(main())
