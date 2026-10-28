#!/usr/bin/env python3
"""new_challenge.py — scaffold the canonical domain/challenge workspace.

Canonical layout:
  challenges/<domain>/<CHAL-XXX-slug>/
    given/ statement.md service.txt surface.json recon/ profiles/
    exploits/ transcripts/ flag.txt FLAG-XXX.validated.md writeup.md
  challenges/_inbox/<slug>/  = browser pulls land here pre-triage (category unknown)

Usage:
  new_challenge.py --domain crypto --chal CHAL-001-vault [--title T] [--points N]
    [--service "nc host 1337"] [--url http://...] [--from-inbox challenges/_inbox/<slug>] [--force]
Exit 0=created, 1=error (bad domain/id, exists without --force).
"""
import argparse, os, re, shutil, sys

DOMAINS = ("web-ctf", "pwn", "rev", "crypto", "forensics", "stego", "misc-pyjail",
           "osint", "hardware", "blockchain", "mobile", "ai-ml")
CHAL_RE = re.compile(r"^CHAL-\d{3}(-[a-z0-9-]{1,60})?$")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUBDIRS = ("given", "recon", "profiles", "exploits", "transcripts")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--domain", required=True, choices=DOMAINS + ("_inbox",))
    ap.add_argument("--chal", required=True)
    ap.add_argument("--title", default="")
    ap.add_argument("--points", type=int, default=0)
    ap.add_argument("--service", default="")
    ap.add_argument("--url", default="")
    ap.add_argument("--from-inbox", default=None)
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args()
    if not CHAL_RE.match(a.chal):
        print(f"ERROR: bad --chal {a.chal} (want CHAL-NNN[-slug])")
        return 1
    dest = os.path.join(ROOT, "challenges", a.domain, a.chal)
    if os.path.exists(dest) and not a.force:
        print(f"ERROR: {dest} exists (use --force to re-scaffold)")
        return 1
    for sub in SUBDIRS:
        os.makedirs(os.path.join(dest, sub), exist_ok=True)
    if a.from_inbox:
        src = a.from_inbox if os.path.isabs(a.from_inbox) else os.path.join(ROOT, a.from_inbox)
        if not os.path.isdir(src):
            print(f"ERROR: inbox dir missing: {src}")
            return 1
        for name in ("given", "statement.md", "service.txt", ".extract.json"):
            s = os.path.join(src, name)
            d = os.path.join(dest, name)
            if not os.path.exists(s):
                continue
            if os.path.isdir(s):
                for f in os.listdir(s):
                    shutil.move(os.path.join(s, f), os.path.join(dest, "given", f))
            else:
                if not os.path.exists(d):
                    shutil.move(s, d)
        print(f"imported inbox {src}")
    else:
        open(os.path.join(dest, "statement.md"), "w").write(
            f"# {a.chal} — {a.title or 'untitled'}\n\n(domain: {a.domain}, points: {a.points})\n")
    svc = a.service or a.url
    if svc and not os.path.isfile(os.path.join(dest, "service.txt")):
        open(os.path.join(dest, "service.txt"), "w").write(svc + "\n")
    print(f"created {dest}")
    for sub in SUBDIRS:
        print(f"  {sub}/")
    print("  statement.md service.txt surface.json(first: triage) flag.txt writeup.md")
    return 0

if __name__ == "__main__":
    sys.exit(main())
