#!/usr/bin/env python3
"""btabs.py — tab hygiene for the attached operator browser.

Usage: btabs.py list | focus PATTERN | close PATTERN | cleanup
  list             tab index, url, title
  focus PATTERN    bring first matching tab forward
  close PATTERN    close all matching tabs (substring on url)
  cleanup          close blank/404/challenge-platform logout tabs, keep one
                   playctf detail tab + live solve tabs; prints kept/closed
Exit 0 always (informational), 1 on CDP failure.
Rule enforced here: NEVER operate on pages[0] blindly — resolve by URL pattern.
"""
import argparse
import sys

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    print("NEED-PLAYWRIGHT")
    sys.exit(1)

CDP_DEFAULT = "http://127.0.0.1:9222"

def tabs(ctx):
    pages = ctx.pages if isinstance(ctx.pages, list) else ctx.pages()
    return pages

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=("list", "focus", "close", "cleanup"))
    ap.add_argument("pattern", nargs="?", default="")
    ap.add_argument("--cdp", default=CDP_DEFAULT)
    a = ap.parse_args()
    pw = sync_playwright().start()
    try:
        b = pw.chromium.connect_over_cdp(a.cdp)
        ctx = b.contexts[0] if isinstance(b.contexts, list) else b.contexts()
        if a.cmd == "list":
            for i, p in enumerate(tabs(ctx)):
                print(f"[{i}] {p.url[:100]} | {(p.title() or '')[:60]}")
            return 0
        if a.cmd == "focus":
            for p in tabs(ctx):
                if a.pattern in p.url:
                    p.bring_to_front()
                    print(f"focused: {p.url[:100]}")
                    return 0
            print(f"no tab matches {a.pattern!r}")
            return 0
        if a.cmd == "close":
            n = 0
            for p in list(tabs(ctx)):
                if a.pattern in p.url:
                    p.close()
                    n += 1
            print(f"closed {n}")
            return 0
        # cleanup
        kept, closed = [], 0
        for p in list(tabs(ctx)):
            t = (p.title() or "").lower()
            if t in ("", "404 - page not found") or "just a moment" in t:
                p.close()
                closed += 1
            else:
                kept.append(p.url[:80])
        print(f"closed {closed}, kept {len(kept)}")
        for k in kept:
            print("  kept:", k)
        return 0
    except Exception as e:  # noqa: BLE001
        print(f"CDP-FAIL: {type(e).__name__}")
        return 1
    finally:
        pw.stop()

if __name__ == "__main__":
    sys.exit(main())
