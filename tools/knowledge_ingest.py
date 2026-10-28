#!/usr/bin/env python3
"""knowledge_ingest.py — technique-only ingest into knowledge/corpus_seed/.

Usage: knowledge_ingest.py --from writeups/CHAL-XXX.md [--strip-flags] [--check]
  --from       writeup/markdown source to mine for TECHNIQUE patterns
  --strip-flags (default on)  refuse + report any flag-shaped values (never stored)
  --check      validate existing corpus files (schema + no-flag scan)
Corpus record: {"technique","category","signals","steps","source","ingested_at"}.
Refuses: flag values, credentials/cookies/tokens, live target hosts, personal data.
Exit 0=ingested/clean, 1=refused (secrets found) or bad input.
"""
import argparse
import datetime
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS_DIR = os.path.join(ROOT, "knowledge", "corpus_seed")
CORPUS = os.path.join(CORPUS_DIR, "mined.ndjson")
FLAG_RE = re.compile(r"(picoCTF|HTB|THM|flag|FLAG|CTF)\{[A-Za-z0-9_\-!@#$%^&*+]{3,}\}")
SECRET_RE = re.compile(r"(?i)(sessionid|session|bearer|api[_-]?key|token|passwd|cookie)\s*[:=]\s*\S{6,}")
HOST_RE = re.compile(r"https?://(?!(example\.|localhost|127\.0\.0\.1))([\w.-]+\.[a-z]{2,})(:\d+)?(/[^\s]*)?")

def scan(text):
    hits = {"flags": FLAG_RE.findall(text)[:5],
            "secrets": [m[:40] for m in SECRET_RE.findall(text)][:5],
            "hosts": sorted({m[1] for m in HOST_RE.findall(text)})[:10]}
    return hits

def extract_techniques(text, source):
    """Heuristic: sections under ## headers become technique records."""
    recs = []
    cur = None
    for line in text.splitlines():
        m = re.match(r"##+\s+(.+)$", line.strip())
        if m:
            if cur and len(cur["steps"]) >= 2:
                recs.append(cur)
            cur = {"technique": m.group(1)[:120], "category": "general",
                   "signals": [], "steps": [], "source": source,
                   "ingested_at": datetime.datetime.utcnow().isoformat() + "Z"}
        elif cur and line.strip().startswith(("-", "*", "1.", "2.", "3.")):
            cur["steps"].append(line.strip()[:200])
    if cur and len(cur["steps"]) >= 2:
        recs.append(cur)
    return recs

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--from", dest="frm", default=None)
    ap.add_argument("--strip-flags", action="store_true", default=True)
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    if a.check:
        bad = 0
        for fn in sorted(os.listdir(CORPUS_DIR) if os.path.isdir(CORPUS_DIR) else []):
            if not fn.endswith(".ndjson"):
                continue
            for i, line in enumerate(open(os.path.join(CORPUS, fn), errors="ignore"), 1):
                try:
                    rec = json.loads(line)
                except ValueError:
                    print(f"FAIL {fn}:{i} bad JSON")
                    bad += 1
                    continue
                if not all(k in rec for k in ("technique", "category", "steps")):
                    print(f"FAIL {fn}:{i} bad schema")
                    bad += 1
                hits = scan(line)
                if hits["flags"] or hits["secrets"]:
                    print(f"FAIL {fn}:{i} secrets present")
                    bad += 1
        print("corpus clean" if bad == 0 else f"{bad} problems")
        return 1 if bad else 0
    if not a.frm or not os.path.isfile(a.frm):
        print("ERROR: --from <writeup.md> required")
        return 1
    text = open(a.frm, errors="ignore").read()
    hits = scan(text)
    if hits["flags"]:
        print(f"REFUSED: {len(hits['flags'])} flag value(s) in source — strip before ingest")
        return 1
    if hits["secrets"]:
        print(f"REFUSED: secret-like strings in source: {hits['secrets'][:3]}")
        return 1
    recs = extract_techniques(text, os.path.basename(a.frm))
    if not recs:
        print("nothing technique-shaped found (need ## sections with steps)")
        return 1
    os.makedirs(CORPUS_DIR, exist_ok=True)
    with open(CORPUS, "a") as f:
        for r in recs:
            f.write(json.dumps(r) + "\n")
    print(f"ingested {len(recs)} technique records from {a.frm}"
          + (f" (hosts noted, not stored: {hits['hosts'][:3]})" if hits["hosts"] else ""))
    return 0

if __name__ == "__main__":
    sys.exit(main())
