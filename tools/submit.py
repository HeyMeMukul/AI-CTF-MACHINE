#!/usr/bin/env python3
"""submit.py — paced, gated flag submission (replaces hand-rolled submit scripts).

WHY THIS EXISTS: rapid-fire submits tripped Cloudflare mid-campaign; expired
Turnstile tokens caused a failed registration; verdicts were eyeballed.
This tool enforces: clearance pre-flight, Turnstile presence check, min pacing,
per-challenge submit budget, verdict parsing, ledger recording.

Usage: submit.py --chal CHAL-001 --flag "FLAG{...}" --detail-url <URL>
  [--cdp ENDPOINT] [--pace SECONDS default 10] [--dry-run]
Exit 0=SOLVED (also records solved), 1=REJECTED (recorded), 2=BLOCKED
(CF challenge / unsolved CAPTCHA / session dead — operator gate, no submit fired),
3=BUDGET-EXHAUSTED (>5 submits without new evidence → escalate).
"""
import argparse
import subprocess
import sys
import time

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    print("NEED-PLAYWRIGHT")
    sys.exit(1)

CDP_DEFAULT = "http://127.0.0.1:9222"
MAX_SUBMITS = 5

def sh(*args):
    p = subprocess.run(args, capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chal", required=True)
    ap.add_argument("--flag", required=True)
    ap.add_argument("--detail-url", required=True)
    ap.add_argument("--cdp", default=CDP_DEFAULT)
    ap.add_argument("--pace", type=int, default=10)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    rc, out = sh("python3", "tools/state_manager.py", "submits", a.chal)
    import json as J
    hist = []
    if rc == 0 and out.strip():
        try:
            hist = J.loads(out.strip().splitlines()[-1])
        except ValueError:
            pass
    if len(hist) >= MAX_SUBMITS:
        print(f"STOP: {len(hist)}/{MAX_SUBMITS} submits for {a.chal} — escalate (forum/hint), do not guess")
        return 3
    if any(h.get("candidate") == a.flag and h.get("verdict") == "rejected" for h in hist):
        print(f"STOP: {a.flag[:40]} already rejected — do not resubmit")
        return 3
    if a.dry_run:
        print(f"[dry-run] would submit {a.flag[:20]}... to {a.chal} ({len(hist)}/{MAX_SUBMITS} used)")
        return 0

    time.sleep(a.pace)  # pacing: never burst the platform
    pw = sync_playwright().start()
    try:
        b = pw.chromium.connect_over_cdp(a.cdp)
        ctx = b.contexts[0] if isinstance(b.contexts, list) else b.contexts()
        pages = ctx.pages if isinstance(ctx.pages, list) else ctx.pages()
        from urllib.parse import urlparse
        host = urlparse(a.detail_url).netloc
        hit = [p for p in pages if host and host in p.url]
        p = hit[0] if hit else (pages[0] if pages else ctx.new_page())
        p.bring_to_front()
        p.goto(a.detail_url, wait_until="domcontentloaded", timeout=30000)
        time.sleep(4)
        if "just a moment" in (p.title() or "").lower():
            print("BLOCKED: Cloudflare challenge on detail page — operator gate, no submit fired")
            return 2
        # Turnstile freshness: if an unsolved widget exists, token will fail — stop first.
        unsolved = p.eval_on_selector_all(
            "iframe[src*='challenges.cloudflare.com'], [name=cf-turnstile-response]",
            "els => els.length")
        ts_val = p.eval_on_selector_all(
            "[name=cf-turnstile-response]", "els => els.map(e => (e.value||'').length)")
        if unsolved and not any(ts_val):
            print("BLOCKED: unsolved CAPTCHA widget present — solve in window, then retry")
            return 2
        p.fill("input[name=flag], input[name=submission], textarea[name=flag], "
               "textarea[name=submission]", a.flag)
        time.sleep(1)
        p.click("button:has-text('Submit'), button[type=submit], input[type=submit]")
        time.sleep(5)
        body = p.eval_on_selector("body", "b => b.innerText || ''") or ""
        if "just a moment" in (p.title() or "").lower():
            print(f"BLOCKED: CF challenge swallowed the verdict page for {a.chal} — nothing recorded, retry later")
            return 2
        if "lready solved" in body or ("Solved" in body and "ncorrect" not in body):
            verdict = "solved"
            print(f"SOLVED: {a.chal}")
            rc = 0
        elif "ncorrect" in body:
            verdict = "rejected"
            print(f"REJECTED: {a.chal} {a.flag[:40]}")
            rc = 1
        else:
            verdict = "error"
            print(f"UNCLEAR verdict for {a.chal} — inspect page before retrying")
            rc = 1
        sh("python3", "tools/state_manager.py", "log-submit", a.chal, a.flag, verdict)
        return rc
    except Exception as e:  # noqa: BLE001
        print(f"ERROR: {type(e).__name__}: {str(e)[:150]} (no submit verdict — NOT recorded)")
        return 1
    finally:
        pw.stop()

if __name__ == "__main__":
    sys.exit(main())
