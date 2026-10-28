#!/usr/bin/env python3
"""instance.py — challenge-instance lifecycle (spawn/status/refresh).

WHY THIS EXISTS: instance tabs multiplied, dead tabs confused scripts, expired
instances 404'd silently, clearance died on reload without detection.
This tool owns the lifecycle with named-tab discipline.

Usage:
  instance.py --spawn --detail-url <challenge-URL> [--service-file PATH] [--cdp E]
      Clicks Access Challenge, waits for the solve.* tab, prints URL, optionally
      writes it to service.txt. Exit 0=spawned, 2=CF-blocked (operator gate).
  instance.py --status [--cdp E]
      Lists solve.* tabs with clearance state (live/challenged/dead). Exit 0.
  instance.py --close-dead [--cdp E]
      Closes blank/404/challenged solve.* tabs. Exit 0.
"""
import argparse
import sys
import time

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    print("NEED-PLAYWRIGHT")
    sys.exit(1)

CDP_DEFAULT = "http://127.0.0.1:9222"

def ctx_of(b):
    return b.contexts[0] if isinstance(b.contexts, list) else b.contexts()

def pages_of(ctx):
    return ctx.pages if isinstance(ctx.pages, list) else ctx.pages()

def health(p):
    try:
        t = (p.title() or "").lower()
        if "just a moment" in t or not t.strip():
            return "challenged"
        return "live"
    except Exception:  # noqa: BLE001
        return "dead"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--spawn", action="store_true")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--close-dead", action="store_true")
    ap.add_argument("--detail-url", default=None)
    ap.add_argument("--service-file", default=None)
    ap.add_argument("--cdp", default=CDP_DEFAULT)
    ap.add_argument("--timeout", type=int, default=60)
    a = ap.parse_args()
    pw = sync_playwright().start()
    try:
        b = pw.chromium.connect_over_cdp(a.cdp)
        ctx = ctx_of(b)
        if a.status or a.close_dead:
            for p in list(pages_of(ctx)):
                if "solve.playctf.in" not in p.url and "solve." not in p.url:
                    continue
                h = health(p)
                print(f"{h:10s} {p.url[:100]}")
                if a.close_dead and h != "live":
                    p.close()
                    print("  closed")
            return 0
        if a.spawn:
            if not a.detail_url:
                print("ERROR: --spawn needs --detail-url")
                return 1
            pages = pages_of(ctx)
            hit = [p for p in pages if "playctf.in/challenge/" in p.url]
            p = hit[0] if hit else pages[0]
            p.bring_to_front()
            p.goto(a.detail_url, wait_until="domcontentloaded", timeout=30000)
            time.sleep(4)
            if "just a moment" in (p.title() or "").lower():
                print("BLOCKED: CF on detail page — operator gate")
                return 2
            before = {x.url for x in pages_of(ctx)}
            try:
                p.click("button:has-text('Access Challenge')", timeout=10000)
            except Exception:  # noqa: BLE001
                print("NOTE: no Access button (already running?) — checking tabs")
            deadline = time.time() + a.timeout
            while time.time() < deadline:
                time.sleep(5)
                for x in pages_of(ctx):
                    if "solve." in x.url and x.url not in before:
                        print(f"SPAWNED: {x.url}")
                        if a.service_file:
                            open(a.service_file, "w").write(x.url.split("?")[0] + "\n")
                            print(f"service written to {a.service_file}")
                        return 0
            # maybe it reused an existing tab
            for x in pages_of(ctx):
                if "solve." in x.url and health(x) == "live":
                    print(f"REUSED: {x.url}")
                    if a.service_file:
                        open(a.service_file, "w").write(x.url.split("?")[0] + "\n")
                    return 0
            print("FAILED: no instance tab appeared — check manually")
            return 1
        ap.print_help()
        return 1
    except Exception as e:  # noqa: BLE001
        print(f"CDP-FAIL: {type(e).__name__}: {str(e)[:120]}")
        return 1
    finally:
        pw.stop()

if __name__ == "__main__":
    sys.exit(main())
