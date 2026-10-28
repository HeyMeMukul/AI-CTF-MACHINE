#!/usr/bin/env python3
"""autosolve.py — quick-win pipeline so no CTF ever returns NOTHING.

Runs BEFORE heavy exploit dispatch on every challenge dir. Cheap, read-only,
offline (2026 training refresh): flag-regex sweep incl. UTF-16, recursive
multi-layer base-family decode loop, single-byte XOR brute, Caesar brute,
JWT-shape detection, whitespace/zero-width anomaly, hash-length identify,
file-type routing hints pointing at each skill's EASY-FIRST ladder.
Writes a per-challenge report + appends candidates to results/quickwins.json.

Usage: autosolve.py [--chal CHAL-ID] [--all] [--given DIR]
Exit 0=ran (even with zero hits), 1=tool error. A hit NEVER auto-submits —
route via tools/submit.py after human/Lead review.
"""
import argparse
import base64
import binascii
import json
import os
import re
import subprocess
import sys

FLAG_RE = re.compile(r"(flag|FLAG|picoCTF|HTB|THM|CTF|SEIZE|GPN|UMD|BlueHens)\{[^}\n]{1,300}\}")
B64_RE = re.compile(r"^[A-Za-z0-9+/]{16,}={0,2}$")
B32_RE = re.compile(r"^[A-Z2-7]{16,}={0,6}$")
HEX_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]{16,}$")
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")
ZW_RE = re.compile(r"[\u200b\u200c\u200d\ufeff\u00a0]")
HASH_LEN = {32: "MD5?", 40: "SHA1?", 64: "SHA256?", 96: "SHA384?", 128: "SHA512?"}


def run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout + r.stderr)[:3000]
    except Exception as e:  # noqa: BLE001
        return f"(skip: {e})"


def printable_ratio(t):
    return sum(c.isprintable() or c.isspace() for c in t) / max(len(t), 1)


def dec_b64(s):
    try:
        raw = base64.b64decode(s.strip(), validate=True)
        t = raw.decode("utf-8", "replace")
        return t if len(t) >= 4 and printable_ratio(t) > 0.85 else None
    except (binascii.Error, ValueError):
        return None


def dec_b32(s):
    try:
        s = s.strip().upper()
        raw = base64.b32decode(s + "=" * (-len(s) % 8))
        t = raw.decode("utf-8", "replace")
        return t if len(t) >= 4 and printable_ratio(t) > 0.85 else None
    except (binascii.Error, ValueError):
        return None


def dec_hex(s):
    s = s.strip().lower().removeprefix("0x")
    if len(s) % 2:
        return None
    try:
        t = bytes.fromhex(s).decode("utf-8", "replace")
        return t if len(t) >= 4 and printable_ratio(t) > 0.85 else None
    except ValueError:
        return None


def multidecode(seed, depth=5):
    """Recursive base-family unwrap: b64/b32/hex layers + b'' wrappers."""
    chain, cur = [], seed.strip().strip("'\"")
    for _ in range(depth):
        nxt = None
        if B64_RE.match(cur) and len(cur) % 4 == 0:
            nxt = dec_b64(cur)
        if nxt is None and B32_RE.match(cur):
            nxt = dec_b32(cur)
        if nxt is None and HEX_RE.match(cur):
            nxt = dec_hex(cur)
        if nxt is None:
            break
        chain.append(nxt[:200])
        cur = nxt.strip().strip("'\"")
        if FLAG_RE.search(cur):
            break
    return chain


def xor_brute(data):
    out = []
    for k in range(1, 256):
        t = bytes(b ^ k for b in data[:120]).decode("utf-8", "replace")
        if FLAG_RE.search(t) or (printable_ratio(t) > 0.95 and "the " in t.lower()):
            out.append({"key": k, "sample": t[:120]})
            if len(out) >= 3:
                break
    return out


def caesar_brute(s):
    out = []
    for shift in range(1, 26):
        t = "".join(chr((ord(c) - 65 + shift) % 26 + 65) if "A" <= c <= "Z"
                    else chr((ord(c) - 97 + shift) % 26 + 97) if "a" <= c <= "z" else c
                    for c in s[:200])
        if FLAG_RE.search(t) or "flag" in t.lower() or " the " in t.lower():
            out.append({"shift": shift, "sample": t[:120]})
    return out[:3]


def route_hint(fname, ftype, txt):
    t = (ftype + " " + txt[:500]).lower()
    if "elf" in t and ("socket" in t or "connect" in t):
        return "pwn EASY-FIRST ladder (ret2win/leak)"
    if "elf" in t:
        return "pwn or rev EASY-FIRST ladder (checksec→offset→win/XRef)"
    if fname.endswith((".pcap", ".pcapng", ".cap")):
        return "forensics EASY-FIRST ladder (tcp-contains + export-objects)"
    if fname.endswith((".img", ".dd", ".raw", ".mem", ".dmp", ".vmem", ".evtx")):
        return "forensics EASY-FIRST ladder (mmls/strings/vol)"
    if fname.endswith((".png", ".jpg", ".jpeg", ".bmp", ".wav", ".mp3", ".flac")):
        return "stego EASY-FIRST ladder (zsteg/steghide/spectrogram)"
    if fname.endswith((".apk", ".ipa")):
        return "mobile EASY-FIRST ladder (apktool/jadx/strings)"
    if fname.endswith(".sol") or "pragma solidity" in t:
        return "blockchain EASY-FIRST ladder (public getters first)"
    if fname.endswith(".py") and ("input(" in t or "eval(" in t):
        return "misc-pyjail EASY-FIRST ladder (chr/getattr/MRO)"
    if "-----begin" in t and "key" in t:
        return "crypto EASY-FIRST ladder (RSA: iroot/gcd/RsaCtfTool)"
    if "random" in t and ("getrandbits" in t or "randint" in t):
        return "crypto EASY-FIRST ladder (RandCrack 624 ints)"
    if any(k in t for k in ("select ", "union", "{{", "flag", "password")) and fname.endswith((".php", ".html", ".js", ".py")):
        return "web-ctf EASY-FIRST ladder (recon→probe trio)"
    if fname.endswith((".zip", ".7z", ".rar")):
        return "misc/forensics EASY-FIRST ladder (zipinfo→comment→zip2john)"
    return ""


def sweep_dir(given):
    hits = {"flag_regex": [], "multidecode": [], "xor": [], "caesar": [],
            "jwt": [], "zero_width": [], "hashlen": [], "file": "",
            "strings": "", "routes": []}
    texts = []
    for root, _, files in os.walk(given):
        for f in sorted(files)[:40]:
            p = os.path.join(root, f)
            try:
                if os.path.getsize(p) > 2_000_000:
                    continue
                data = open(p, "rb").read()[:200_000]
            except OSError:
                continue
            for enc in ("utf-8", "utf-16-le"):
                try:
                    txt = data.decode(enc) if enc != "utf-8" else data.decode("utf-8")
                except (UnicodeDecodeError, ValueError):
                    continue
                if enc != "utf-8" and printable_ratio(txt) < 0.5:
                    continue
                texts.append((f, txt, data))
                break
            else:
                texts.append((f, "", data))
    for f, txt, data in texts:
        for m in FLAG_RE.finditer(txt):
            hits["flag_regex"].append({"file": f, "hit": m.group(0)[:200]})
        file_has_hit = any(h.get("file") == f for h in hits["flag_regex"])
        for m in JWT_RE.finditer(txt):
            hits["jwt"].append({"file": f, "token": m.group(0)[:80],
                                "hint": "try alg:none+empty-sig, then weak secrets"})
        if ZW_RE.search(txt):
            hits["zero_width"].append({"file": f,
                "hint": "invisible chars: xxd + zero-width decode, never re-save"})
        for line in txt.splitlines()[:25]:
            line = line.strip().strip("'\"")
            if 16 <= len(line) <= 2000:
                chain = multidecode(line)
                if chain:
                    hits["multidecode"].append({"file": f, "in": line[:60],
                                                "chain": chain})
                    break
            if re.fullmatch(r"[0-9a-fA-F]{32,128}", line.strip()):
                hl = HASH_LEN.get(len(line.strip()), "?")
                hits["hashlen"].append({"file": f, "len": len(line.strip()),
                                        "guess": hl})
        if data and not file_has_hit:
            xb = xor_brute(data)
            if xb:
                hits["xor"].append({"file": f, "hits": xb})
        if txt.strip() and not file_has_hit and not any(h.get("file") == f for h in hits["multidecode"]):
            cb = caesar_brute(txt.strip())
            if cb:
                hits["caesar"].append({"file": f, "hits": cb})
    if texts:
        fps = [os.path.join(given, f) for f, _, _ in texts[:15]
               if os.path.isfile(os.path.join(given, f))]
        if fps:
            hits["file"] = run(["file"] + fps)
        for f, txt, _ in texts[:15]:
            fp = os.path.join(given, f)
            ftype = run(["file", "-b", fp]).split(",")[0]
            rh = route_hint(f, ftype, txt)
            if rh and rh not in hits["routes"]:
                hits["routes"].append(f"{f}: {rh}")
        first = os.path.join(given, texts[0][0])
        if os.path.isfile(first):
            hits["strings"] = run(["bash", "-c",
                f"strings -n 8 -e l {first!r} 2>/dev/null | grep -E -m5 '(flag|FLAG|picoCTF|HTB|THM|CTF)\\{{' || strings -n 8 {first!r} | grep -E -m5 '(flag|FLAG|picoCTF|HTB|THM|CTF)\\{{' || true"])
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chal", default=None)
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--given", default=None)
    a = ap.parse_args()

    targets = []
    if a.given:
        targets = [(a.chal or "MANUAL", a.given)]
    else:
        try:
            st = json.load(open("state.json"))
        except (FileNotFoundError, json.JSONDecodeError):
            st = {"challenges": []}
        chals = st.get("challenges", [])
        if a.chal:
            chals = [c for c in chals if c.get("id") == a.chal]
        for c in chals:
            g = os.path.join(c.get("path", ""), "given")
            if os.path.isdir(c.get("path", "")):
                targets.append((c.get("id"), g if os.path.isdir(g) else c["path"]))
        if not targets and os.path.isdir("challenges/_inbox"):
            for slug in sorted(os.listdir("challenges/_inbox")):
                g = os.path.join("challenges/_inbox", slug)
                if os.path.isdir(g):
                    targets.append((slug, g))
    os.makedirs("results", exist_ok=True)
    qpath = "results/quickwins.json"
    try:
        prev = json.load(open(qpath)) if os.path.isfile(qpath) else []
    except json.JSONDecodeError:
        prev = []
    for cid, gdir in targets:
        hits = sweep_dir(gdir)
        n = (len(hits["flag_regex"]) + len(hits["multidecode"]) + len(hits["xor"])
             + len(hits["caesar"]) + len(hits["jwt"]) + len(hits["zero_width"]))
        print(f"[{cid}] quickwin: {n} hit(s) in {gdir}")
        for h in hits["flag_regex"][:5]:
            print(f"  FLAG?: {h['file']}: {h['hit'][:120]}")
        for h in hits["multidecode"][:3]:
            print(f"  DECODE[{h['file']}]: {h['in'][:50]} -> {' -> '.join(x[:50] for x in h['chain'][:3])}")
        for h in hits["xor"][:2]:
            print(f"  XOR[{h['file']}]: {h['hits']}")
        for h in hits["caesar"][:2]:
            print(f"  CAESAR[{h['file']}]: {h['hits']}")
        for h in hits["jwt"][:3]:
            print(f"  JWT[{h['file']}]: {h['token'][:40]}... ({h['hint']})")
        for h in hits["zero_width"][:2]:
            print(f"  ZW[{h['file']}]: {h['hint']}")
        for r in hits["routes"][:6]:
            print(f"  ROUTE: {r}")
        prev.append({"chal": cid, "given": gdir, "hits": hits})
    json.dump(prev[-100:], open(qpath, "w"), indent=2)
    print(f"wrote {qpath} ({len(targets)} challenge(s) swept)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
