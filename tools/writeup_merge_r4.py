#!/usr/bin/env python3
"""writeup_merge_r4.py — merge browser-swarm rows into *_manifest_r4.md.

Reads /tmp/opencode/r4_agent*.md (## <cat> sections, `- [label](url) | diff | chain`
rows), filters junk, dedupes within swarm + against the whole existing corpus,
writes knowledge/writeups_mined/<cat>_manifest_r4.md.

Filters: non-row lines, bad difficulty, placeholder ctftime event/task IDs (<1000),
youtube/video links, bare author-profile URLs (no article slug), overlong chains.
Usage: writeup_merge_r4.py [--stage DIR] [--apply]  (default dry-run counts)
Exit 0=ok.
"""
import argparse
import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "knowledge", "writeups_mined")
ROW_RE = re.compile(r"^-\s*\[(?P<label>.+?)\]\((?P<url>https?://[^)]+)\)\s*\|\s*(?P<diff>easy|medium|hard)\s*\|\s*(?P<chain>.{5,400})$")
HEAD_RE = re.compile(r"^##\s*([a-z0-9\-+]+)")
CATS = {"web-ctf", "pwn", "rev", "crypto", "forensics", "stego", "misc-pyjail",
        "osint", "hardware", "blockchain", "mobile", "ai-ml"}
PLACEHOLDER = re.compile(r"ctftime\.org/(event|task)/(\d+)/?$")


def junk(url, label):
    if "youtube.com" in url or "youtu.be" in url:
        return "video"
    if re.search(r"medium\.com/@[^/]+$", url.rstrip("/")) and "@" in url and url.rstrip("/").count("/") <= 3:
        return "bare-profile"
    m = PLACEHOLDER.search(url)
    if m and int(m.group(2)) < 1000:
        return "placeholder-id"
    if len(label) < 3:
        return "empty-label"
    return None


def corpus_urls():
    urls = set()
    pat = re.compile(r"\((https?://[^)]+)\)")
    for fn in glob.glob(os.path.join(OUT, "*.md")):
        try:
            for l in open(fn, errors="ignore"):
                if not l.startswith("- ["):
                    continue
                for u in pat.findall(l):
                    urls.add(u.rstrip("/"))
        except OSError:
            pass
    return urls


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", default="/tmp/opencode")
    ap.add_argument("--apply", action="store_true")
    a = ap.parse_args()
    corpus = corpus_urls()
    print(f"corpus URLs indexed: {len(corpus)}")
    buckets, stats = {c: [] for c in CATS}, {"rows": 0, "junk": {}, "dup_swarm": 0, "dup_corpus": 0, "badcat": 0}
    seen = set()
    for path in sorted(glob.glob(os.path.join(a.stage, "r4*.md"))):
        cat = None
        for line in open(path, errors="ignore"):
            line = line.strip()
            h = HEAD_RE.match(line)
            if h:
                c = h.group(1).strip().lower().replace(" ", "-")
                cat = c if c in CATS else None
                continue
            m = ROW_RE.match(line)
            if not m or not cat:
                continue
            stats["rows"] += 1
            url = m.group("url").rstrip("/")
            j = junk(url, m.group("label"))
            if j:
                stats["junk"][j] = stats["junk"].get(j, 0) + 1
                continue
            if url in seen:
                stats["dup_swarm"] += 1
                continue
            seen.add(url)
            if url in corpus:
                stats["dup_corpus"] += 1
                continue
            buckets[cat].append(f"- [{m.group('label')}]({m.group('url')}) | {m.group('diff')} | {m.group('chain').strip()}")
    total = sum(len(v) for v in buckets.values())
    print(f"parsed={stats['rows']} junk={stats['junk']} dup_swarm={stats['dup_swarm']} dup_corpus={stats['dup_corpus']}")
    for c in sorted(CATS):
        print(f"  {c}: {len(buckets[c])} new")
    print(f"TOTAL NEW R4: {total}")
    if a.apply and total:
        for c in sorted(CATS):
            rows = buckets[c]
            if not rows:
                continue
            easy = sum(1 for r in rows if "| easy |" in r)
            path = os.path.join(OUT, f"{c}_manifest_r4.md")
            new_file = not os.path.isfile(path)
            with open(path, "a") as f:
                if new_file:
                    f.write(f"# {c} Writeups Mined — Manifest r4, browser-swarm batch ( technique-only, no flags )\n\n"
                            f"Mined 2026-10-17 by 8 reader subagents via real browsers (Playwright snapshots; "
                            f"Medium member-only pieces via medium-unlocker.inulute.com -> Freedium mirror; "
                            f"GitHub/team-blog/pro-research sources). Rows filtered (video/bare-profile/placeholder "
                            f"links dropped) and deduped by URL within the batch and against the full corpus. "
                            f"Difficulty as labeled by readers. Format: `- [source/challenge](URL) | difficulty | "
                            f"technique-chain`. No flag values anywhere.\n")
                f.write(f"\n## batch 2026-10-17-browser-swarm ({len(rows)} rows, {easy} easy)\n\n")
                for r in rows:
                    f.write(r + "\n")
            print(f"wrote {path} (+{len(rows)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
