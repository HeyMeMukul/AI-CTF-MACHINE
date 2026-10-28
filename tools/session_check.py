#!/usr/bin/env python3
"""session_check.py — clearance/login health probe for attached browser.

Usage: session_check.py [--url URL] [--cdp ENDPOINT] [--open-new-tab]
No side effects by default (reads current tabs). With --url and no matching tab,
opens a scratch tab (closed afterwards) — scratch tabs may hit CF on gated hosts.
Exit 0=AUTHENTICATED, 2=CHALLENGED (Just-a-moment/CAPTCHA), 3=LOGIN WALL, 1=DOWN.
"""
import argparse
import sys

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    print("NEED-PLAYWRIGHT")
    sys.exit(1)

CDP_DEFAULT = "http://127.0.0.1:9222"

def classify(title, body):
    t = (title or "").lower()
    low = (body or "")[:2000].lower()
    captcha_marks = ("just a moment", "verifying you are", "security verification",
                     "captcha", "recaptcha", "turnstile", "hcaptcha",
                     "are you a robot", "verify you are human", "cf-challenge",
                     "attention required", "cloudflare ray id")
    if any(m in t for m in ("just a moment", "attention required", "security verification")) \
            or any(m in low for m in captcha_marks):
        return 2, "CHALLENGED(captcha/bot-wall: solve MANUALLY in operator Chrome, then re-run)"
    if not (title or "").strip() and len((body or "").strip()) < 50:
        return 2, "CHALLENGED(blank-probable)"
    if any(k in low for k in ("too many requests", "rate limited", "429", "access denied")):
        return 2, "CHALLENGED(rate-limited: wait 10 min, single-probe, never burst)"
    if any(k in low for k in ("log in", "sign in")) and "dashboard" not in low and "logout" not in low:
        return 3, "LOGIN WALL (re-login MANUALLY in operator Chrome)"
    return 0, "AUTHENTICATED"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=None)
    ap.add_argument("--cdp", default=CDP_DEFAULT)
    ap.add_argument("--open-new-tab", action="store_true")
    a = ap.parse_args()
    pw = sync_playwright().start()
    try:
        b = pw.chromium.connect_over_cdp(a.cdp)
        ctx = b.contexts[0] if isinstance(b.contexts, list) else b.contexts()
        pages = ctx.pages if isinstance(ctx.pages, list) else ctx.pages()
        target = None
        if a.url:
            hit = [p for p in pages if a.url.split("?")[0] in p.url]
            target = hit[0] if hit else None
            if target is None and a.open_new_tab:
                target = ctx.new_page()
                target.goto(a.url, wait_until="domcontentloaded", timeout=30000)
        else:
            target = pages[0] if pages else None
        if target is None:
            print("NO-TAB (pass --open-new-tab with --url)")
            return 1
        title = target.title() or ""
        try:
            body = target.eval_on_selector("body", "b => b.innerText || ''") or ""
        except Exception:  # noqa: BLE001
            body = ""
        rc, label = classify(title, body)
        print(f"{label}: {target.url[:100]} | {title[:60]}")
        return rc
    except Exception as e:  # noqa: BLE001
        print(f"DOWN: {type(e).__name__}: {str(e)[:120]}")
        return 1
    finally:
        pw.stop()

if __name__ == "__main__":
    sys.exit(main())
