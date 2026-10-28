#!/usr/bin/env python3
"""browser_extract.py — UNTESTED scaffold (M0). CDP-attached CTF extraction.

Attaches to the operator's dedicated Chrome over CDP; pulls challenge metadata
+ attachments into challenges/_inbox/<slug>/. Never handles credentials; never logs
cookies/tokens/flags; no hardcoded platform URLs (--base-url required).

Usage: browser_extract.py (--check|--list|--pull CHAL-ID|--pull-all) --base-url <URL>
  Extra: [--dry-run] [--out IDX] [--max N] [--only IDS] [--force]
Rules: dedicated --user-data-dir assumed; contexts()[0] only, NEVER new_page();
serial per profile. Exits: 0 ok, 1 tool error, 2 session expired, 3 blocked.
"""
import argparse
import hashlib
import json
import os
import re
import sys
import urllib.request
from datetime import datetime, timezone

CDP_DEFAULT = "http://localhost:9222"
CHAL_RE = re.compile(r"^CHAL-\d{3}$")
SERVICE_RE = re.compile(r"(nc\s+\S+\s+\d+|\b\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}\b|https?://\S+)", re.I)
FLAG_SHAPED = re.compile(r"(picoCTF|HTB|THM|flag|CTF)\{[^}\n]{1,200}\}")
FILE_HREF = re.compile(r"\.(zip|tar|gz|7z|bin|elf|pcap|png|jpg|wav|py|txt|sol|apk)$", re.I)

def log(m):
    print(m, flush=True)

def utcnow():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(65536), b""):
            h.update(c)
    return h.hexdigest()

def sanitize_filename(name):
    base = os.path.basename((name or "attachment").split("?")[0].strip())
    base = re.sub(r"[^A-Za-z0-9._\-+]", "_", base)[:120] or "attachment"
    return "attachment" if base in (".", "..") else base

def sanitize_text(t, limit=6000):
    t = t or ""
    t = FLAG_SHAPED.sub("[FLAG-SHAPED-REDACTED]", t)
    t = re.sub(r"(?i)(sessionid|session|token|bearer)\s*[:=]\s*\S+", r"\1=[REDACTED]", t)
    return t[:limit]

def load_state(p):
    return json.load(open(p))

def save_state(p, s):
    tmp = p + ".tmp"
    json.dump(s, open(tmp, "w"), indent=2)
    os.replace(tmp, p)

def cdp_get(endpoint, path="/json/version", timeout=10):
    with urllib.request.urlopen(endpoint.rstrip("/") + path, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))

def connect_over_cdp(cdp_endpoint):
    """Attach to operator Chrome. Returns (pw, browser, ctx). UNTESTED live."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        log("ERROR: pip install playwright (and playwright install chromium).")
        sys.exit(1)
    pw = sync_playwright().start()
    browser = pw.chromium.connect_over_cdp(cdp_endpoint)
    ctxs = browser.contexts
    if callable(ctxs):  # older playwright: method; 1.64+: property
        ctxs = ctxs()
    # CRITICAL: real profile context only — NEVER browser.new_page().
    assert len(ctxs) >= 1, "no contexts: is dedicated Chrome (--user-data-dir) running?"
    assert ctxs[0].pages is not None, "CDP attach failed: context has no pages"
    return pw, browser, ctxs[0]

def get_page(ctx):
    pages = ctx.pages if isinstance(ctx.pages, list) else ctx.pages()
    if not pages:
        raise RuntimeError("no operator tabs open: open the platform URL in the dedicated "
                           "Chrome window first (never let the agent new_page() a login).")
    p = pages[0]  # operator's visible tab; callers resolve by URL via btabs/session_check
    p.set_default_timeout(30000)
    return p

def check_session(cdp_endpoint, base_url, dry_run=False):
    if dry_run:
        log(f"[dry-run] would probe {cdp_endpoint}/json/version then GET {base_url}")
        return 0
    try:
        ver = cdp_get(cdp_endpoint)
        log("CDP ok: " + sanitize_text(str(ver.get("Browser", "?")), 120))
    except Exception as e:  # noqa: BLE001 - scaffold reports, never leaks
        log(f"CDP unreachable at {cdp_endpoint}: {e}")
        return 1
    pw, _, ctx = connect_over_cdp(cdp_endpoint)
    try:
        page = get_page(ctx)
        page.goto(base_url, wait_until="domcontentloaded")
        body = sanitize_text(page.content(), 4000).lower()
        login_shown = "challenge" not in body and any(
            m in body for m in ("log in", "login", "sign in"))
        if login_shown:
            log("SESSION_EXPIRED: list page shows login, no challenge content.")
            log("GATE: re-login MANUALLY in operator Chrome, then re-run --check. "
                "Never credential-fill from the agent.")
            return 2
        if any(m in body for m in ("too many requests", "captcha", "recaptcha",
                                   "turnstile", "hcaptcha", "just a moment",
                                   "verifying you are", "are you a robot",
                                   "access denied", "attention required")):
            log("RATE/BLOCKED: anti-bot verdict. STOP the batch; solve the CAPTCHA "
                "MANUALLY in the operator window, wait 60-600s, single-probe --check. "
                "Do not rotate stealth tricks to dodge.")
            return 3
        log("session check: authenticated content observed (selectors UNTESTED).")
        return 0
    finally:
        pw.stop()

def _listing_url(base_url):
    """Dashboard listing URL. HITCON serves the list at /dashboard/; a bare
    platform root (no path) maps there. Any other explicit path is kept as-is
    so generic platforms are unaffected."""
    from urllib.parse import urlparse
    path = urlparse(base_url).path.rstrip("/")
    if path in ("", "/"):
        return base_url.rstrip("/") + "/dashboard/"
    return base_url


HITCON_ENTRY_SEL = ".challenge-entry"
HITCON_ID_RE = re.compile(r"challenge-id-(\d+)")

CAT_MAP = {"web exploitation": "web", "web": "web", "cryptography": "crypto", "crypto": "crypto",
           "binary exploitation": "pwn", "pwn": "pwn", "reverse": "rev",
           "digital forensics": "forensics", "forensic": "forensics",
           "forensics": "forensics", "log analysis": "forensics",
           "network security": "forensics", "prompt injection": "ai-ml",
           "ai": "ai-ml", "ml": "ai-ml"}

CAT_RE = re.compile(r"(?i)\b(web exploitation|web|cryptography|crypto|binary exploitation|"
                    r"pwn|reverse|digital forensics|forensics?|log analysis|network security|"
                    r"stego|misc|osint|hardware|blockchain|mobile|prompt injection|ai|ml)\b")


def norm_category(raw):
    m = CAT_RE.search(raw or "")
    cat_raw = m.group(1).lower() if m else "unknown"
    return CAT_MAP.get(cat_raw, cat_raw.strip().lower() or "unknown")


def slugify(title, fallback):
    return re.sub(r"[^a-z0-9]+", "-", (title or "").lower()).strip("-")[:60] or fallback


def _hitcon_items(page):
    """HITCON 2026 dashboard rows: <li class="challenge-entry" id="challenge-id-N"
    @click="openChallenge(challenge)"> with .tititle (title), .tags (category),
    .flag-list li (score; class solved = by us, other-solved = by others).
    Returns None when this layout is absent (generic fallback applies)."""
    try:
        count = page.eval_on_selector_all(HITCON_ENTRY_SEL, "els => els.length")
    except Exception:  # noqa: BLE001 - selector probe failure means "not HITCON"
        return None
    if not count:
        return None
    rows = page.evaluate("""() => Array.from(document.querySelectorAll('.challenge-entry')).map(e => {
      const t = e.querySelector('.tititle');
      const g = e.querySelector('.tags');
      const f = e.querySelector('.flag-list li');
      return {id: e.id || '', title: t ? t.textContent.trim() : '',
              tags: g ? g.textContent.trim() : '',
              score: f ? f.textContent.trim() : '',
              flagClass: f ? f.className : ''};
    })""") or []
    base = (page.url or "").split("#")[0]
    items = []
    for r in rows:
        m = HITCON_ID_RE.search(r.get("id", ""))
        if not m:
            continue
        pid = int(m.group(1))
        title = sanitize_text(r.get("title", ""), 120).strip() or f"challenge-{pid}"
        m_pts = re.search(r"(\d+)", r.get("score", ""))
        classes = (r.get("flagClass", "") or "").split()
        items.append({"platform_id": pid, "chal_id": f"CHAL-{pid:03d}",
                      "slug": slugify(title, f"c-{pid}"),
                      "title": title, "category": norm_category(r.get("tags", "")),
                      "category_raw": sanitize_text(r.get("tags", ""), 60),
                      "points": int(m_pts.group(1)) if m_pts else None,
                      "detail_url": base + f"#challenge-id-{pid}",
                      "solved": "solved" in classes,
                      "other_solved": "other-solved" in classes})
    items.sort(key=lambda x: x["platform_id"])
    return items or None


def parse_challenge_list(page):
    """Row parse from DOM. HITCON 2026 selectors first, generic fallback kept."""
    hitcon = _hitcon_items(page)
    if hitcon is not None:
        return hitcon
    rows = page.eval_on_selector_all("[data-challenge], .challenge, a[href*='challenge']",
        "els => els.map(e => ({text: (e.innerText || '').slice(0,300), href: e.getAttribute('href') || ''}))")
    items = []
    card_re = re.compile(r"^(.+?)\s+(Easy|Medium|Hard|Insane|Very Easy)\s+(.+?)\s+(\d+)\s*pts?\b", re.I)
    for i, r in enumerate(rows, 1):
        text = sanitize_text(r.get("text", ""), 300)
        href = r.get("href", "")
        if re.match(r"^/challenges/?$", href) or re.search(r"^(next|previous|more)\b|→|←$", text.strip(), re.I):
            continue  # nav/pagination noise, not a challenge
        m_pts = re.search(r"(\d{2,4})\s*(?:pts?|points)", text, re.I)
        cat = norm_category(text)
        title = (text.split("\n")[0].strip()[:120] or f"challenge-{i:03d}")
        m_card = card_re.match(" ".join(text.split()))
        if m_card:
            title = m_card.group(3).strip()[:120]
        items.append({"platform_id": i, "chal_id": f"CHAL-{i:03d}",
                      "slug": slugify(title, f"c-{i}"),
                      "title": title, "category": cat,
                      "points": int(m_pts.group(1)) if m_pts else None, "detail_url": r.get("href", ""),
                      "solved": bool(re.search(r"(?i)solved|completed", text))})
    return items

def cmd_list(args):
    if args.dry_run:
        log(f"[dry-run] would list {args.base_url} -> {args.out or 'stdout'}")
        print('[{"slug": "example", "title": "EXAMPLE", "category": "unknown"}]')
        return 0
    pw, _, ctx = connect_over_cdp(args.cdp_endpoint)
    try:
        page = get_page(ctx)
        page.goto(_listing_url(args.base_url), wait_until="networkidle")
        items = parse_challenge_list(page)
        if args.out:
            os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
            json.dump(items, open(args.out, "w"), indent=2)
        print(json.dumps(items, indent=2))
        log(f"listed {len(items)} challenges (hitcon selectors live-tested; generic fallback untested).")
        return 0
    finally:
        pw.stop()

def register_state(state_file, entry):
    st = load_state(state_file)
    chals = st.setdefault("challenges", [])
    for i, c in enumerate(chals):
        if c.get("id") == entry["id"]:
            chals[i] = entry
            break
    else:
        chals.append(entry)
    st.setdefault("triage", {}).update({"status": "in_progress", "total": len(chals)})
    st.setdefault("_meta", {})["last_updated_by"] = "browser_extract.py"
    save_state(state_file, st)

def download_files(page, hrefs, given, detail_url):
    """Click-download via Playwright download events. UNTESTED live."""
    from urllib.parse import urljoin
    out, seen = [], {}
    for href in hrefs:
        url = href if href.startswith("http") else urljoin(detail_url, href)
        name = sanitize_filename(url.split("/")[-1])
        try:
            with page.expect_download(timeout=30000) as dl:
                page.eval_on_selector(f"a[href='{href}']", "e => e.click()")
            tmp = os.path.join(given, ".dl_" + name)
            dl.value.save_as(tmp)
            if os.path.getsize(tmp) == 0:
                os.remove(tmp)
                out.append({"name": name, "status": "missing(empty)"})
                continue
            digest = sha256_file(tmp)
            if digest in seen:  # hash-dedup: keep first copy only
                os.remove(tmp)
                out.append({"name": name, "status": "duplicate", "sha256": digest,
                            "duplicate_of": seen[digest]})
                continue
            final = os.path.join(given, name)
            if os.path.exists(final):
                final += "." + digest[:8]  # same name, new bytes: keep both
            os.replace(tmp, final)
            seen[digest] = os.path.basename(final)
            out.append({"name": os.path.basename(final), "status": "ok",
                        "sha256": digest, "size": os.path.getsize(final)})
        except Exception as e:  # noqa: BLE001 - per-file failure is non-fatal
            out.append({"name": name, "status": "missing(%s)" % type(e).__name__})
    return out

def pull_one(args, chal_id, item=None):
    assert CHAL_RE.match(chal_id), f"bad CHAL-ID {chal_id} (want CHAL-NNN)"
    if not item:
        # resolve from the live index so CLI --pull targets the detail page
        try:
            idx = json.load(open("challenges/_index.json"))
            item = next((x for x in idx if x.get("chal_id") == chal_id), {})
        except (FileNotFoundError, json.JSONDecodeError):
            item = {}
    # Pre-triage staging: category unknown → challenges/_inbox/<slug>/.
    # Lead promotes via: new_challenge --from-inbox + triage + add-challenge.
    slug = item.get("slug") or chal_id.lower()
    dest = os.path.join("challenges", "_inbox", slug)
    given = os.path.join(dest, "given")
    if args.dry_run:
        log(f"[dry-run] would pull {chal_id} -> challenges/_inbox/{slug}/given (+statement/service/state)")
        return 0
    os.makedirs(given, exist_ok=True)
    pw, _, ctx = connect_over_cdp(args.cdp_endpoint)
    try:
        page = get_page(ctx)
        detail = item.get("detail_url") or args.base_url
        if detail.startswith("/"):
            from urllib.parse import urljoin
            detail = urljoin(args.base_url, detail)
        dash = detail.split("#")[0] or _listing_url(args.base_url)
        page.goto(dash, wait_until="networkidle")
        statement, hrefs = "", []
        pid = item.get("platform_id")
        # HITCON 2026: detail opens via JS modal (openChallenge), not href.
        # Click the matching entry once, wait for Alpine/Bootstrap to render.
        if pid is not None:
            try:
                n = page.eval_on_selector_all(f"#challenge-id-{pid}",
                                              "els => els.length")
            except Exception:  # noqa: BLE001 - probe miss falls back to body scrape
                n = 0
            if n:
                try:
                    page.click(f"#challenge-id-{pid}", timeout=15000)
                    page.wait_for_timeout(3000)
                    try:
                        statement = sanitize_text(page.eval_on_selector(
                            "#challenge-modal", "m => m.innerText || ''"))
                    except Exception:  # noqa: BLE001 - modal unreadable, use body
                        statement = ""
                    try:
                        modal_hrefs = (page.eval_on_selector_all(
                            "#challenge-modal a[href]",
                            "els => els.map(e => e.getAttribute('href'))") or [])
                    except Exception:  # noqa: BLE001 - no modal links
                        modal_hrefs = []
                    hrefs = [h for h in modal_hrefs if h and FILE_HREF.search(h)]
                except Exception as e:  # noqa: BLE001 - click failed, body fallback
                    log(f"modal open failed for platform id {pid}: {type(e).__name__}; body fallback")
                    statement, hrefs = "", []
        if not statement or len(statement) < 50:
            # Generic fallback: whole-page scrape (also covers non-modal platforms).
            statement = sanitize_text(page.eval_on_selector("body", "b => b.innerText || ''"))
            if not hrefs:
                hrefs = [h for h in (page.eval_on_selector_all(
                    "a[href]", "els => els.map(e => e.getAttribute('href'))") or [])
                    if h and FILE_HREF.search(h)]
        m = SERVICE_RE.search(statement)
        service = m.group(1) if m else None
        hashes = download_files(page, hrefs, given, dash)
        open(os.path.join(dest, "service.txt"), "w").write((service or "") + "\n")
        qm = re.search(r"Challenge Question\s*(.*?)\s*(Download Challenge File|Access Challenge|Submit Flag)",
                       statement, re.S)
        question = " ".join(qm.group(1).split())[:500] if qm else ""
        head = ["# " + sanitize_text(str(item.get("title", chal_id)), 120),
                "- category: " + sanitize_text(str(item.get("category", "unknown")), 40),
                "- points: %s" % item.get("points"),
                "- service: " + sanitize_text(service or "none", 120)]
        if question:
            head.append("- question: " + question)
        open(os.path.join(dest, "statement.md"), "w").write("\n".join(head) + "\n\n" + statement + "\n")
        meta = {"slug": item.get("slug"), "detail_url": detail,
                "files": hashes, "pulled_at": utcnow()}
        json.dump(meta, open(os.path.join(dest, ".extract.json"), "w"), indent=2)
        register_state(args.state_file, {"id": chal_id, "slug": slug,
                        "title": item.get("title", chal_id), "category": item.get("category", "unknown"),
                        "domain": "_inbox", "path": dest,
                        "points": item.get("points", 0), "service": service,
                        "status": "registered", "signals": ["extracted via browser-ops"],
                        "extract": {"detail_url": detail, "files": len(hashes),
                                    "pulled_at": meta["pulled_at"]}})
        log(f"pulled {chal_id}: {len(hashes)} file(s), service={service or 'none'}")
        return 0
    finally:
        pw.stop()

def cmd_pull_all(args):
    only = [c.strip() for c in (args.only or "").split(",") if c.strip()]
    for c in only:
        assert CHAL_RE.match(c), f"bad --only entry: {c}"
    if args.dry_run:
        log(f"[dry-run] would pull-all {args.base_url} only={only or 'all'} max={args.max}")
        return 0
    registered = {c.get("chal_id") for c in load_state(args.state_file).get("challenges", [])}
    idx = "challenges/_index.json"
    index = json.load(open(idx)) if os.path.isfile(idx) else []
    targets = []
    for i, item in enumerate(index, 1):
        cid = item.get("chal_id") or f"CHAL-{i:03d}"
        if only and cid not in only:
            continue
        if cid in registered and args.skip_registered:
            continue
        targets.append((cid, item))
        if len(targets) >= args.max:
            break
    log(f"pull-all: {len(targets)} target(s)")
    rc = 0
    for cid, item in targets:
        rc = pull_one(args, cid, item) or rc
    return rc

def main():
    ap = argparse.ArgumentParser(description="UNTESTED CDP challenge extraction.")
    ap.add_argument("--base-url", required=True, help="platform URL (explicit, no default)")
    ap.add_argument("--state-file", default="state.json")
    ap.add_argument("--cdp-endpoint", default=CDP_DEFAULT)
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--list", action="store_true", dest="do_list")
    ap.add_argument("--pull", metavar="CHAL-ID")
    ap.add_argument("--pull-all", action="store_true", dest="do_pull_all")
    ap.add_argument("--out", default=None)
    ap.add_argument("--only", default="")
    ap.add_argument("--max", type=int, default=10 ** 9)
    ap.add_argument("--skip-registered", action="store_true", default=True)
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    if args.force:
        args.skip_registered = False
    if not args.base_url.startswith(("http://", "https://")):
        ap.error("--base-url must be http(s) (explicit, never defaulted)")
    if sum([args.check, args.do_list, bool(args.pull), args.do_pull_all]) != 1:
        ap.error("choose exactly one: --check | --list | --pull CHAL-ID | --pull-all")
    if args.check:
        sys.exit(check_session(args.cdp_endpoint, args.base_url, args.dry_run))
    if args.do_list:
        sys.exit(cmd_list(args))
    if args.pull:
        sys.exit(pull_one(args, args.pull))
    sys.exit(cmd_pull_all(args))


if __name__ == "__main__":
    main()
