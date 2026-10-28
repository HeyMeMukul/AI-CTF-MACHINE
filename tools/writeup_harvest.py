#!/usr/bin/env python3
"""writeup_harvest.py — bulk-harvest ctftime writeup index rows into r3 manifests.

Polite crawler: browser UA, ~2.5s sleep between pages, stops on errors.
Parses Event | Task | Tags | Writeup-ID, maps tags+title -> our 12 categories,
assigns a technique-chain 1-liner + easy/medium difficulty, dedupes against
existing manifests, appends NEW rows to knowledge/writeups_mined/<cat>_manifest_r3.md.

Usage: writeup_harvest.py [--pages N] [--start PAGE] [--out DIR] [--dry-run]
  --pages 60 fetches index pages 1..60 (~31 rows each, Oct-2026 backwards).
Exit 0=ok. Prints per-category new-row counts. Technique-only: no flags fetched.
"""
import argparse
import html
import os
import re
import sys
import time
import urllib.request

BASE = "https://ctftime.org/writeups/"
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) CTF-Research/1.0 (technique survey)"}
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "knowledge", "writeups_mined")

ROW_RE = re.compile(r"<tr>(.*?)</tr>", re.S)
CELL_RE = re.compile(r"<td>(.*?)</td>", re.S)
TAG_RE = re.compile(r"<[^>]+>")
WS_RE = re.compile(r"\s+")

CATS = ("web-ctf", "pwn", "rev", "crypto", "forensics", "stego", "misc-pyjail",
        "osint", "hardware", "blockchain", "mobile", "ai-ml")

# (category, [tag/title keywords]) — ordered: specific first.
RULES = [
    ("stego", ["stego", "steganography", "steghide", "zsteg", "spectrogram", "outguess", "[stego]"]),
    ("forensics", ["forensic", "pcap", "pcapng", "memory dump", "volatility", "disk image", "carve", "wireshark", "network forensics", "dfir"]),
    ("blockchain", ["blockchain", "solidity", "smart contract", "reentrancy", "evm", "foundry", "web3", "solana"]),
    ("mobile", ["mobile", "apk", "android", "ios", "frida", "flutter", "[mobile]"]),
    ("ai-ml", ["prompt injection", "prompt-injection", "prompt", "gpt", "chatgpt", "llm", "machine learning", "mcp", "ai agent", "rag", "jailbreak"]),
    ("hardware", ["hardware", "firmware", "uart", "fpga", "verilog", "side channel", "side-channel", "radio", "bluetooth", "jtag"]),
    ("osint", ["osint", "geoguessr", "geolocation", "username", "reconnaissance", "social engineering"]),
    ("crypto", ["crypto", "rsa", "aes", "lattice", "lll", "ecdsa", "ecdlp", "pohlig", "curve", "elliptic", "totp", "hotp", "secp", "ed25519", "discrete", "blockcipher", "lfsr", "stream cipher", "hastad", "wiener", "coppersmith", "padding oracle", "lcg", "mt19937", "otp", "diffie", "elgamal", "paillier", "knapsack", "shamir", "ecc", "rc4", "chacha", "hash", "cipher", "decrypt", "encrypt"]),
    ("pwn", ["pwn", "exploitation", "binary exploitation", "rop", "ret2", "heap", "shellcode", "buffer overflow", "format string", "use-after-free", "race condition"]),
    ("rev", ["rev", "reverse", "reversing", "crackme", "angr", "ghidra", "decompil", "dotnet", "wasm", "golang", "upx", "risc-v", "riscv", "emulat"]),
    ("web-ctf", ["web", "sqli", "sql injection", "xss", "ssti", "lfi", "ssrf", "xxe", "graphql", "jwt", "deserial", "traversal", "upload", "csrf", "redirect", "cookie", "flask", "django", "php", "sqlite"]),
    ("misc-pyjail", ["misc", "jail", "pyjail", "esolang", "brainfuck", "programming", "encoding", "base64", "puzzle", "trivia", "sanity"]),
]

BEGINNER_EVENTS = ("picoctf", "tjctf", "patriotctf", "umdctf", "bluehens", "sekai", "downunder",
                   "n00bz", " angstrom", "midnight", "sunshine", "buckeye", "dawgctf", "uoftctf",
                   "cactuscon", "wolvctf", "vishwa", "zer0pts", "irisctf", "spooky", "halloween")
EASY_TITLE = ("beginner", "baby", "intro", "easy", "warmup", "sanity", "hello", "welcome",
              "101", "tutorial", "first", "starter", "newbie")


def chain_for(cat, blob):
    b = blob
    if cat == "crypto":
        if re.search(r"\brsa\b", b): return "RSA easy route: small-e iroot / shared-n gcd / RsaCtfTool+FactorDB, then standard decrypt (EASY-FIRST ladder)"
        if re.search(r"aes|ecb|cbc|ctr|gcm", b): return "AES mode route: dup-block ECB map / padding-oracle byte-at-a-time / nonce-reuse XOR (EASY-FIRST ladder)"
        if re.search(r"xor|caesar|vigenere|substitution|classical|base64|encoding", b): return "Classical route: CyberChef Magic depth-3 + single-byte XOR brute + Caesar/Vigenere split (EASY-FIRST ladder)"
        if re.search(r"hash|md5|sha", b): return "Hash route: crackstation/hashcat vs length-extension fork by digest length (EASY-FIRST ladder)"
        if re.search(r"jwt", b): return "JWT route: alg:none+empty-sig first, then weak-secret crack, then kid confusion (EASY-FIRST ladder)"
        if re.search(r"random|lcg|mersenne|prng", b): return "PRNG route: collect full outputs, RandCrack clone / LCG algebra, predict-and-confirm (EASY-FIRST ladder)"
        return "Crypto classifier route: lengths+headers first, then family ladder (EASY-FIRST)"
    if cat == "pwn":
        if re.search(r"heap|tcache|uaf|use.after", b): return "Heap intro route: menu-driven overflow/UAF, free+realloc-same-size, print-before-check (EASY-FIRST ladder)"
        if re.search(r"format|fmt|printf", b): return "Format-string route: %p dump (canary+PIE leak) then positional write to GOT/var (EASY-FIRST ladder)"
        if re.search(r"rop|ret2libc|libc", b): return "ROP-lite route: leak puts@got -> libc base -> system(/bin/sh), ret-align for movaps (EASY-FIRST ladder)"
        return "ret2win route: checksec -> cyclic offset -> win+args, local-then-remote (EASY-FIRST ladder)"
    if cat == "rev":
        if re.search(r"wasm", b): return "WASM route: wasm2wat, i32.const/xor/eq grep, DevTools breakpoint verify (EASY-FIRST ladder)"
        if re.search(r"\.net|dotnet|c#|csharp", b): return ".NET route: dnSpy entry point (+de4dot), read check logic, keygen (EASY-FIRST ladder)"
        if re.search(r"python|pyc|pyinstaller", b): return "Python route: pycdc/pycdas (+matching ver), marshal/dis, invert loop (EASY-FIRST ladder)"
        if re.search(r"go\b|golang", b): return "Go route: strings + main.main objdump/golang_renamer, lift constants (EASY-FIRST ladder)"
        return "Native route: file/DIE -> upx -d -> strings/XRef -> Ghidra decompile -> Python invert or angr find/avoid (EASY-FIRST ladder)"
    if cat == "web-ctf":
        if re.search(r"sqli|sql injection|sqlite", b): return "SQLi route: login bypass -> ORDER BY count -> UNION -> sqlite_master/information_schema (EASY-FIRST ladder)"
        if re.search(r"ssti|jinja|twig", b): return "SSTI route: {{7*7}} probe -> class-MRO dump -> Popen read (EASY-FIRST ladder)"
        if re.search(r"lfi|rfi|traversal|include|php", b): return "LFI route: /etc/passwd -> php://filter -> log-poison fallback (EASY-FIRST ladder)"
        if re.search(r"jwt|cookie|session|flask", b): return "Session route: decode-flip-resign / alg:none / flask-unsign with tried secrets (EASY-FIRST ladder)"
        if re.search(r"upload", b): return "Upload route: magic-prefixed shell.png.php, visit direct path with cmd (EASY-FIRST ladder)"
        if re.search(r"ssrf|url|fetch|proxy", b): return "SSRF route: 127.0.0.1 service -> ::1/decimal bypass -> 169.254.169.254 metadata (EASY-FIRST ladder)"
        if re.search(r"xss", b): return "XSS route: probe context (attr/js), escalate to cookie-theft payload via collaborator (EASY-FIRST ladder)"
        if re.search(r"graphql", b): return "GraphQL route: __schema introspection -> field grep flag/admin -> IDOR/batch (EASY-FIRST ladder)"
        if re.search(r"xxe|xml", b): return "XXE route: file:///etc/passwd entity, error/OOB fallback with php://filter (EASY-FIRST ladder)"
        if re.search(r"cmd|command injection|rce|exec", b): return "CMDi route: ;id probe -> ;cat /flag* with 2>&1, blind via sleep (EASY-FIRST ladder)"
        return "Web recon-first route: robots/.git/JS secrets -> reflect trio (SSTI/SQLi/LFI) -> vuln ladder (EASY-FIRST)"
    if cat == "forensics":
        if re.search(r"pcap|pcapng|wireshark|network", b): return "pcap route: strings-flag first, tcp-contains filter, Follow-Stream, export-objects, DNS-label check (EASY-FIRST ladder)"
        if re.search(r"memory|volatility|vmem|dmp|mem\.raw", b): return "Memory route: pslist+cmdline+filescan|flag, strings fallback (EASY-FIRST ladder)"
        if re.search(r"disk|img|dd\b|mmls|fls|icat|autopsy", b): return "Disk route: mmls partition dd, fls/icat deleted, strings -e l/b (EASY-FIRST ladder)"
        return "Forensics strings-first route: file+grep flag-format, then media-specific ladder (EASY-FIRST)"
    if cat == "stego":
        if re.search(r"wav|mp3|flac|audio|sound", b): return "Audio route: spectrogram first (>20kHz), steghide -p '', wavsteg -b 1000 (EASY-FIRST ladder)"
        if re.search(r"jpg|jpeg", b): return "JPEG route: steghide -p '' -> stegseek rockyou -> outguess; filename-as-password first (EASY-FIRST ladder)"
        if re.search(r"png|bmp", b): return "PNG route: zsteg -a, pngcheck/IEND carve, alpha/MSB planes (EASY-FIRST ladder)"
        if re.search(r"qr", b): return "QR route: zbarimg every image incl. spectrograms (EASY-FIRST ladder)"
        return "Stego ordered route: exif+thumb+strings+binwalk, then format-specific tool, never re-save raws (EASY-FIRST)"
    if cat == "misc-pyjail":
        if re.search(r"jail|pyjail|sandbox|eval|exec", b): return "Pyjail route: probe filter chars, chr/getattr concat, named _wrap_close MRO walk (EASY-FIRST ladder)"
        if re.search(r"esolang|brainfuck|befunge", b): return "Esolang route: identify dialect, tape/OOB walk, exec-loader golf (EASY-FIRST ladder)"
        if re.search(r"base64|encoding|decod", b): return "Encoding route: recursive multidecode loop until flag-shape (EASY-FIRST ladder)"
        return "Misc route: file+statement keywords, jail-vs-puzzle fork, quick-win sweep first (EASY-FIRST)"
    if cat == "osint":
        return "OSINT route: exact-quote search -> sherlock+manual verify -> EXIF -> wayback -> crt.sh (EASY-FIRST ladder)"
    if cat == "blockchain":
        return "Blockchain route: read public getters first, tx.origin bounce, reentrancy, solc<0.8 overflow (EASY-FIRST ladder)"
    if cat == "mobile":
        return "Mobile route: apktool/jadx strings, native .so grep, deep links, Frida pinning bypass (EASY-FIRST ladder)"
    if cat == "ai-ml":
        return "AI/ML route: verbatim-repeat leak, paraphrase bypass, indirect tool-output plant, markdown exfil (EASY-FIRST ladder)"
    if cat == "hardware":
        if re.search(r"uart|serial|baud|sigrok|logic", b): return "UART route: sigrok show, 115200/9600 8N1, idle-high check (EASY-FIRST ladder)"
        if re.search(r"firmware|binwalk|squashfs", b): return "Firmware route: binwalk -e, grep creds/keys in extracted tree (EASY-FIRST ladder)"
        return "Hardware route: capture-first, baud-measure, carve-then-grep (EASY-FIRST ladder)"
    return "General route: quick-win sweep then category ladder (EASY-FIRST)"


def difficulty(event, title):
    blob = (event + " " + title).lower()
    if any(k in blob for k in EASY_TITLE) or any(e in event.lower() for e in BEGINNER_EVENTS):
        return "easy"
    return "medium"


def fetch(url):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=25) as r:
        return r.read().decode("utf-8", "replace")


def parse_rows(html_text):
    out = []
    for m in ROW_RE.finditer(html_text):
        cells = CELL_RE.findall(m.group(1))
        if len(cells) != 5:
            continue
        ev = WS_RE.sub(" ", TAG_RE.sub("", cells[0])).strip()
        task = WS_RE.sub(" ", TAG_RE.sub("", cells[1])).strip()
        tags = WS_RE.sub(" ", TAG_RE.sub(" ", cells[2])).strip().lower()
        wid = re.search(r"/writeup/(\d+)", cells[4])
        if not wid or not task or task.lower() in ("task",):
            continue
        out.append({"event": html.unescape(ev), "task": html.unescape(task),
                    "tags": tags, "wid": wid.group(1)})
    return out


# Title-signal tokens (distinctive substrings; checked before tag rules) —
# many authors leave Tags empty or sign them; titles like "Rev: babyre" decide.
TITLE_TOKENS = [
    ("rev", ["rev:", "[rev", "rev-", "rev ", "reverse", "crackme", "crack me", "keygen", "shredded", "babyre", "risc-v", "riscv"]),
    ("pwn", ["pwn:", "[pwn", "pwn-", "ret2", "shellcode", "heap-", "heapster", " bof", "(bof)"]),
    ("web-ctf", ["web:", "[web", "web-", "sqli", "xss", "ssti", "ssrf", "lfi:", "graphql", "casino"]),
    ("crypto", ["crypto", "rsa-", " rsa", "aes-", "cipher", "decrypt", "ecdsa", "symmetry", " otp", "hash-"]),
    ("forensics", ["foren", "pcap", "memory-", "disk-", "carve", "wireshark"]),
    ("stego", ["steg", "spectrogram", "matryoshka", "honeyleaf", "subway", "gridlock", "clearline"]),
    ("misc-pyjail", ["misc", "jail", "jaly", "pyjail", "esolang", "brainf", "trivia", "sanity", "mathtest", "p1ng", "programming", "bounty"]),
    ("osint", ["osint", "geoguess", "investigation", "find me", "where am i", "missing", "ranger", "bday"]),
    ("blockchain", ["blockchain", "solidity", "smart contract", "vault", "casino"]),
    ("mobile", ["mobile", "apk", "android", "waf"]),
    ("ai-ml", ["prompt", "llm", "gpt", "chatbot", "nabi", "copilot", "fog"]),
    ("hardware", ["hardware", "firmware", "uart", "fpga", "driver", "helldriver"]),
]


def split_camel(text):
    return re.sub(r"(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])|(?<=[a-zA-Z])(?=[0-9])|(?<=[0-9])(?=[a-zA-Z])", " ", text)


def tok_hit(text, tok):
    """Boundary-aware keyword match (kills storage->rag, quartet->uart,
    trivial->trivia, reveal->rev, bios->ios). CamelCase is split first so
    HackTheHash/kcipher/SecureHashedDb still resolve."""
    if re.fullmatch(r"[a-z0-9]+", tok):
        if tok == "gpt":
            return re.search(r"gpt\b", text, re.I) is not None
        if tok in ("uart", "rag", "otp", "trivia", "rev", "ios"):
            return re.search(r"\b" + re.escape(tok) + r"\b", text, re.I) is not None
        t2 = split_camel(text)
        return (re.search(r"\b" + re.escape(tok), t2, re.I) is not None
                or re.search(re.escape(tok) + r"\b", t2, re.I) is not None)
    return tok.lower() in text.lower()
    return tok in text


def classify(row):
    tags = row["tags"]
    title = row["task"]
    # 1. informative tags win (author-signature/empty tags fall through)
    for cat, keys in RULES:
        if any(tok_hit(tags, k) for k in keys):
            return cat
    # 2. title conventions backfill untagged rows
    for cat, toks in TITLE_TOKENS:
        if any(tok_hit(title, t) for t in toks):
            return cat
    if re.search(r"\bexe\b|\.exe$|exe$", title):
        return "rev"
    # 3. combined blob last chance (original case: tok_hit splits CamelCase)
    blob = row["tags"] + " " + row["task"]
    for cat, keys in RULES:
        if any(tok_hit(blob, k) for k in keys):
            return cat
    return None


def existing_ids():
    ids = set()
    pat = re.compile(r"/writeup/(\d+)")
    for fn in os.listdir(OUT):
        if fn.endswith(".md"):
            try:
                ids.update(pat.findall(open(os.path.join(OUT, fn), errors="ignore").read()))
            except OSError:
                pass
    return ids


def esc(t):
    return t.replace("[", "\\[").replace("]", "\\]")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pages", type=int, default=60)
    ap.add_argument("--start", type=int, default=1)
    ap.add_argument("--sleep", type=float, default=2.5)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    seen = existing_ids()
    print(f"existing writeup IDs in manifests: {len(seen)}")
    buckets, skipped = {c: [] for c in CATS}, {"unclassified": 0, "dup": 0, "rows": 0}
    for page in range(a.start, a.start + a.pages):
        url = BASE if page == 1 else f"{BASE}?page={page}"
        try:
            rows = parse_rows(fetch(url))
        except Exception as e:  # noqa: BLE001 - polite stop, keep what we have
            print(f"page {page}: FETCH FAIL {type(e).__name__}: {str(e)[:100]} — stopping")
            break
        if not rows:
            print(f"page {page}: no rows — stopping")
            break
        skipped["rows"] += len(rows)
        for r in rows:
            if r["wid"] in seen:
                skipped["dup"] += 1
                continue
            cat = classify(r)
            if not cat:
                skipped["unclassified"] += 1
                continue
            seen.add(r["wid"])
            buckets[cat].append({
                "line": f"- [{esc(r['event'])}/{esc(r['task'])}](https://ctftime.org/writeup/{r['wid']})"
                        f" | {difficulty(r['event'], r['task'])}"
                        f" | {chain_for(cat, (r['tags'] + ' ' + r['task']).lower())}",
                "wid": r["wid"]})
        print(f"page {page}: {len(rows)} rows", flush=True)
        time.sleep(a.sleep)
    total = sum(len(v) for v in buckets.values())
    print(f"\nparsed={skipped['rows']} dup={skipped['dup']} unclassified={skipped['unclassified']}")
    for c in CATS:
        print(f"  {c}: {len(buckets[c])} new")
    print(f"TOTAL NEW: {total}")
    if a.dry_run or total == 0:
        return 0
    for c in CATS:
        rows = buckets[c]
        if not rows:
            continue
        easy = sum(1 for r in rows if "| easy |" in r["line"])
        path = os.path.join(OUT, f"{c}_manifest_r3.md")
        new_file = not os.path.isfile(path)
        with open(path, "a") as f:
            if new_file:
                f.write(f"# {c} Writeups Mined — Manifest r3 ( technique-only, no flags )\n\n"
                        f"Mined 2026-10-17 from ctftime.org writeup index pages (polite crawl: browser UA, "
                        f"2.5s spacing). Method: parsed Event|Task|Tags rows, classified by tag+title keywords "
                        f"into 12 categories, deduped by writeup-ID against r1+r2 manifests, difficulty by "
                        f"beginner-event/title heuristic (easy) else medium. Technique-chains reference the "
                        f"EASY-FIRST ladders in skills/{c}/SKILL.md. Format per line: "
                        f"`- [event/challenge](URL) | difficulty | technique-chain`. No flag values anywhere.\n\n")
            f.write(f"\n## batch 2026-10-17 ({len(rows)} rows, {easy} easy / {len(rows)-easy} medium)\n\n")
            for r in rows:
                f.write(r["line"] + "\n")
        print(f"wrote {path} (+{len(rows)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
