#!/usr/bin/env python3
"""writeup_reclass.py — re-verify r3 rows against live ctftime tags.

For each `- [...](.../writeup/N)` row in the given r3 files: fetch the
writeup page, extract its Tags, re-run the FIXED classifier (boundary-aware),
and move the row to the correct category file (rewriting the technique-chain)
when it disagrees. Rows that become unclassified move to misc-pyjail only if
their title smells misc-ish, else they are dropped with a report line.

Usage: writeup_reclass.py <r3file>... [--sleep 1.5] [--apply]
  default is dry-run (report only); --apply rewrites files.
Exit 0=ok. Polite: browser UA + sleep between fetches.
"""
import argparse
import glob
import os
import re
import sys
import time
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
import writeup_harvest as w

UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) CTF-Research/1.0 (technique survey)"}
ROW_RE = re.compile(r"^- \[(?P<label>.*?)\]\((?P<url>.*?)\) \| (?P<diff>\w+) \| (?P<chain>.*)$")
TAGLINE_RE = re.compile(r"Tags:\s*(.*?)\s*Rating:", re.S)
TAGHTML_RE = re.compile(r"<[^>]+>")


def fetch_tags(wid):
    req = urllib.request.Request(f"https://ctftime.org/writeup/{wid}", headers=UA)
    with urllib.request.urlopen(req, timeout=25) as r:
        h = r.read().decode("utf-8", "replace")
    m = TAGLINE_RE.search(re.sub(r"\s+", " ", TAGHTML_RE.sub(" ", h)))
    return (m.group(1).strip().lower() if m else "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--sleep", type=float, default=1.5)
    ap.add_argument("--apply", action="store_true")
    a = ap.parse_args()
    moves = []
    for path in a.files:
        for line in open(path, errors="ignore"):
            m = ROW_RE.match(line.rstrip("\n"))
            if not m:
                continue
            wid = re.search(r"/writeup/(\d+)", m.group("url"))
            if not wid:
                continue
            wid = wid.group(1)
            try:
                tags = fetch_tags(wid)
            except Exception as e:  # noqa: BLE001
                print(f"SKIP {wid}: {type(e).__name__}")
                continue
            label = m.group("label")
            event, _, task = label.partition("/")
            row = {"event": event, "task": task, "tags": tags, "wid": wid}
            newcat = w.classify(row)
            curcat = os.path.basename(path).replace("_manifest_r3.md", "")
            if newcat != curcat:
                chain = w.chain_for(newcat, (tags + " " + task).lower()) if newcat else None
                moves.append({"wid": wid, "from": curcat, "to": newcat, "line": line.rstrip("\n"),
                              "label": label, "diff": m.group("diff"), "chain": chain, "tags": tags[:80]})
                print(f"MOVE {wid} {curcat} -> {newcat} | {label[:70]} | tags: {tags[:80]}")
            time.sleep(a.sleep)
    print(f"\n{moves.__len__()} rows to move")
    if a.apply and moves:
        byfile = {}
        for mv in moves:
            byfile.setdefault(mv["from"], []).append(mv["line"])
            if mv["to"]:
                newline = (f"- [{mv['label']}](https://ctftime.org/writeup/{mv['wid']})"
                           f" | {mv['diff']} | {mv['chain']}\n")
                with open(os.path.join(w.OUT, f"{mv['to']}_manifest_r3.md"), "a") as f:
                    f.write(newline)
        for cur, lines in byfile.items():
            p = os.path.join(w.OUT, f"{cur}_manifest_r3.md")
            keep = [l for l in open(p, errors="ignore") if l.rstrip("\n") not in set(lines)]
            open(p, "w").writelines(keep)
        print("files rewritten")
    return 0


if __name__ == "__main__":
    sys.exit(main())
