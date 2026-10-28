#!/usr/bin/env python3
"""rag_lookup.py — RAG-lite retrieval over mined writeups + skill patterns.

SOTA basis: CRAKEN Self-RAG/Graph-RAG (+3pp, niche solves). Full vector DB is
overkill here; this is deterministic keyword retrieval with difficulty weighting
and self-grading — no new dependencies, runs offline in milliseconds.

Usage: rag_lookup.py --query "tcache poison libc leak" [--top 5] [--domain pwn] [--json]
Sources: knowledge/writeups_mined/*_manifest.md (technique chains) +
skills/*/SKILL.md + skills/*/techniques/*.md (distilled patterns).
Scores: term overlap x2 for title/technique line + difficulty weight
(hard=3, medium=2, easy=1) + domain match bonus. Self-grade: prints a
0-1 relevance estimate per hit (coverage of query terms); caller re-queries
with refined terms if top score < 0.5 (max 2 rounds — Self-RAG discipline).
Exit 0=hits, 1=no hits.
"""
import argparse
import glob
import json
import math
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STOP = set("the a an of to in for on with via and or is are was were be by as at from that this it its into over under".split())

def terms(q):
    return [t.lower() for t in re.findall(r"[A-Za-z0-9_+-]{3,}", q)
            if t.lower() not in STOP]

def load_manifests(include_unverified=False):
    try:
        policy = json.load(open(os.path.join(ROOT, "knowledge", "writeups_mined", "POLICY.json")))
        if policy.get("strict_verified") and not include_unverified:
            return []
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    docs = []
    for fp in sorted(glob.glob(os.path.join(ROOT, "knowledge", "writeups_mined", "*_manifest.md"))):
        dom = os.path.basename(fp).replace("_manifest.md", "")
        for line in open(fp, errors="ignore"):
            m = re.match(r"-\s*\[(.*?)\]\((.*?)\)\s*\|\s*(\w+)?\s*\|?\s*(.*)$", line.strip())
            if not m:
                continue
            title, url, diff, chain = m.groups()
            docs.append({"kind": "writeup", "domain": dom, "title": title,
                         "url": url, "diff": (diff or "medium").lower(),
                         "text": f"{title} {chain or ''}"})
    return docs

def load_patterns():
    docs = []
    for fp in sorted(glob.glob(os.path.join(ROOT, "skills", "*", "SKILL.md")) +
                     glob.glob(os.path.join(ROOT, "skills", "*", "techniques", "*.md"))):
        dom = fp.split(os.sep)[-3] if "techniques" in fp else fp.split(os.sep)[-2]
        try:
            text = open(fp, errors="ignore").read()
        except OSError:
            continue
        for m in re.finditer(r"^#{2,4}\s+(W\d+[^:\n]*|.*?Playbook.*?|.*?Pattern.*?)$", text, re.M):
            start = m.start()
            chunk = text[start:start + 1500]
            docs.append({"kind": "pattern", "domain": dom, "title": m.group(1).strip()[:100],
                         "url": os.path.relpath(fp, ROOT), "diff": "hard", "text": chunk})
    return docs

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--query", required=True)
    ap.add_argument("--top", type=int, default=5)
    ap.add_argument("--domain", default=None)
    ap.add_argument("--include-unverified", action="store_true",
                   help="read the quarantined mined manifests")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    q = terms(a.query)
    if not q:
        print("ERROR: query has no indexable terms")
        return 1
    docs = load_manifests(a.include_unverified) + load_patterns()
    # TF-IDF over corpus (stdlib only): rare discriminative terms
    # (tcache, coppersmith, ssti) outrank filler (challenge, flag, writeup).
    n = max(1, len(docs))
    df = {}
    doc_terms = []
    for d in docs:
        toks = terms(d["text"])
        seen = set(toks)
        doc_terms.append((d, toks))
        for w in seen:
            df[w] = df.get(w, 0) + 1
    idf = {w: math.log(1 + n / c) for w, c in df.items()}
    scored = []
    for d, toks in doc_terms:
        tf = {}
        for w in toks:
            if w in q:
                tf[w] = tf.get(w, 0) + 1
        if not tf:
            continue
        base = sum((1 + math.log(c)) * idf[w] for w, c in tf.items())
        w = {"hard": 3, "medium": 2, "easy": 1}.get(d["diff"], 2)
        bonus = 2 if a.domain and d["domain"] == a.domain else 0
        score = round(base * w + bonus, 2)
        scored.append((score, len(tf) / len(q), d))
    scored.sort(key=lambda x: -x[0])
    top = scored[:a.top]
    if not top:
        print("NO-HITS — broaden terms or drop --domain")
        return 1
    if a.json:
        print(json.dumps([{"score": s, "relevance": round(r, 2), **d}
                          for s, r, d in top], indent=1)[:4000])
    else:
        for s, r, d in top:
            print(f"[{s:7.2f} rel={r:.2f}] ({d['kind']}/{d['domain']}) {d['title'][:90]}")
            print(f"         {d['url'][:110]}")
        if top[0][1] < 0.5:
            print("SELF-GRADE: top relevance <0.5 — re-query with refined terms (max 2 rounds)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
