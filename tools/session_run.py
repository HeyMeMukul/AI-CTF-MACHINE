#!/usr/bin/env python3
"""session_run.py — persistent interactive sessions (tmux-backed gdb/nc/python).

SOTA basis: EnIGMA IATs (+2.5pp, all in stateful pwn/rev). One-shot `bash
gdb -batch` destroys interactive state; this keeps it across Worker turns.

Usage:
  session_run.py spawn --tool gdb|nc|python3 --chal CHAL-001 -- <cmd...>
      e.g. session_run.py spawn --tool gdb --chal CHAL-001 -- gdb -q ./vuln
  session_run.py send <SID> --text "b main" [--enter]
  session_run.py read <SID> [--tail 50] [--timeout 10]
  session_run.py list | kill <SID> | kill-all
Sessions persist in tmux server `ctf-sessions`; transcripts append to
challenges/<domain>/CHAL-*/transcripts/<SID>.log. Registry: /tmp/ctf-sessions.json.
Exit 0=ok, 1=error (dead session, tmux missing, SID unknown).
Rules: send one command per turn (thought→1 action→wait obs); read before next
send; stall_detector watches transcripts; kill sessions at task end.
"""
import argparse
import json
import os
import subprocess
import sys
import time

REG = "/tmp/ctf-sessions.json"
TMUX = "ctf-sessions"

def sh(*args, **kw):
    p = subprocess.run(args, capture_output=True, text=True, timeout=kw.pop("timeout", 30))
    return p.returncode, (p.stdout + p.stderr)[-4000:]

def load():
    try:
        return json.load(open(REG))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save(r):
    json.dump(r, open(REG, "w"), indent=1)

def need_tmux():
    rc, _ = sh("tmux", "-L", TMUX, "list-sessions")
    if rc != 0:
        rc, out = sh("tmux", "-L", TMUX, "new-session", "-d", "-s", "main", "-x", "200", "-y", "60")
        if rc != 0:
            print(f"ERROR: tmux unavailable: {out[-200:]}")
            sys.exit(1)

def logpath(sid, chal):
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    hits = [d for d in [os.path.join(root, "challenges", dom, c)
                        for dom in os.listdir(os.path.join(root, "challenges"))
                        for c in [chal + "*"]] for d in __import__("glob").glob(d)]
    d = hits[0] if hits else os.path.join(root, "challenges")
    tdir = os.path.join(d, "transcripts")
    os.makedirs(tdir, exist_ok=True)
    return os.path.join(tdir, f"{sid}.log")

def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("spawn"); p.add_argument("--tool", required=True)
    p.add_argument("--chal", required=True); p.add_argument("run", nargs="+")
    p = sub.add_parser("send"); p.add_argument("sid"); p.add_argument("--text", required=True)
    p = sub.add_parser("read"); p.add_argument("sid"); p.add_argument("--tail", type=int, default=50)
    p = sub.add_parser("kill"); p.add_argument("sid")
    sub.add_parser("list"); sub.add_parser("kill-all")
    a = ap.parse_args()
    need_tmux()
    reg = load()

    if a.cmd == "spawn":
        sid = f"{a.tool}-{int(time.time()) % 100000}"
        pane = f"main"
        rc, out = sh("tmux", "-L", TMUX, "split-window", "-t", pane, "-P", "-F#{pane_id}",
                     *a.run)
        if rc != 0:
            print(f"ERROR spawn: {out[-300:]}")
            return 1
        pane_id = out.strip().splitlines()[-1]
        reg[sid] = {"pane": pane_id, "tool": a.tool, "chal": a.chal,
                    "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "log": logpath(sid, a.chal)}
        save(reg)
        open(reg[sid]["log"], "a").write(f"$ spawn: {' '.join(a.run)}\n")
        print(f"spawned {sid} (pane {pane_id})")
        return 0
    if a.cmd == "send":
        s = reg.get(a.sid)
        if not s:
            print(f"ERROR: unknown session {a.sid}")
            return 1
        rc, out = sh("tmux", "-L", TMUX, "send-keys", "-t", s["pane"], a.text, "Enter")
        open(s["log"], "a").write(f"$ {a.text}\n")
        time.sleep(1)
        return 0 if rc == 0 else 1
    if a.cmd == "read":
        s = reg.get(a.sid)
        if not s:
            print(f"ERROR: unknown session {a.sid}")
            return 1
        rc, out = sh("tmux", "-L", TMUX, "capture-pane", "-t", s["pane"], "-p", "-S", f"-{a.tail}")
        open(s["log"], "a").write(out + "\n")
        print(out[-3000:])
        return 0
    if a.cmd == "kill":
        s = reg.pop(a.sid, None)
        if s:
            sh("tmux", "-L", TMUX, "kill-pane", "-t", s["pane"])
        save(reg)
        print(f"killed {a.sid}" if s else f"unknown {a.sid}")
        return 0
    if a.cmd == "list":
        for sid, s in reg.items():
            rc, _ = sh("tmux", "-L", TMUX, "list-panes", "-F#{pane_id}")
            alive = s["pane"] in _
            print(f"{sid:24s} {s['tool']:8s} {s['chal']:10s} {'alive' if alive else 'DEAD'}")
        return 0
    if a.cmd == "kill-all":
        sh("tmux", "-L", TMUX, "kill-server")
        save({})
        print("all sessions killed")
        return 0
    return 1

if __name__ == "__main__":
    sys.exit(main())
