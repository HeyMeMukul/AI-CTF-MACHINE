#!/usr/bin/env python3
"""triage.py — Phase 0 60-120s challenge classifier → surface.json.

Usage:
  python3 tools/triage.py --given challenges/CHAL-001/given --chal-id CHAL-001
      [--service host:port] [--url http://host:port] [--out challenges/CHAL-001/surface.json]

Read-only sweep: file/strings/exiftool/xxd/checksec/capinfos/binwalk-entropy.
Exit 0 = classified (surface.json written), 2 = ambiguous (Lead decides).
"""
import argparse, json, os, re, subprocess, sys

DOMAINS = ("web-ctf", "pwn", "rev", "crypto", "forensics", "stego", "misc-pyjail",
           "osint", "hardware", "blockchain", "mobile", "ai-ml")

FLAG_RE = re.compile(r"(picoCTF|HTB|THM|flag|FLAG|CTF)\{[^}\n]{1,200}\}")

def run(cmd, timeout=15):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (p.stdout + p.stderr)[:4000]
    except FileNotFoundError:
        return ""
    except subprocess.TimeoutExpired:
        return ""

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--given", required=True)
    ap.add_argument("--chal-id", required=True)
    ap.add_argument("--service", default=None)
    ap.add_argument("--url", default=None)
    ap.add_argument("--out", required=True)
    ap.add_argument("--points", type=int, default=0)
    ap.add_argument("--domain", default=None,
                    help="domain dir override; default = category if known, else _inbox")
    a = ap.parse_args()

    files = []
    if os.path.isdir(a.given):
        for n in sorted(os.listdir(a.given)):
            fp = os.path.join(a.given, n)
            if os.path.isfile(fp):
                files.append({"name": n, "type": "", "size": os.path.getsize(fp)})
    signals, blob = [], ""
    for f in files:
        fp = os.path.join(a.given, f["name"])
        f["type"] = run(["file", "-b", fp]).strip().split(",")[0][:80]
        blob += run(["strings", "-n", "8", fp]) + "\n"
        blob += run(["xxd", fp])[:500] + "\n"
    # Challenge-dir context: statement.md/service.txt carry the signal for
    # file-less challenges (live web service, external investigation, etc.)
    outdir = os.path.dirname(os.path.abspath(a.out))
    for extra in ("statement.md", "service.txt"):
        ep = os.path.join(outdir, extra)
        if os.path.isfile(ep):
            try:
                blob += open(ep, errors="ignore").read(4000) + "\n"
                signals.append(f"{extra} ingested")
            except OSError:
                pass
    if not (a.service or a.url):
        try:
            lines = open(os.path.join(outdir, "service.txt"), errors="ignore").read().strip().splitlines()
            if lines and lines[0].strip() and lines[0].strip().lower() != "none":
                a.service = lines[0].strip()
                signals.append("service.txt endpoint")
        except OSError:
            pass
    m = FLAG_RE.search(blob)
    free_win = m.group(0)[:80] if m else None
    has_elf = any("ELF" in f["type"] for f in files)
    has_pcap = any(n.endswith((".pcap", ".pcapng", ".cap")) for n in [f["name"] for f in files])
    has_img = any(n.endswith((".png", ".jpg", ".jpeg", ".bmp", ".wav", ".mp3")) for n in [f["name"] for f in files])
    has_sol = any(n.endswith(".sol") for n in [f["name"] for f in files]) or os.path.exists(os.path.join(a.given, "foundry.toml"))
    has_apk = any(n.endswith((".apk", ".ipa")) for n in [f["name"] for f in files])
    has_py = any(n.endswith(".py") for n in [f["name"] for f in files])
    has_fw = any(n.endswith((".bin", ".hex", ".v", ".uf2", ".bit", ".sv", ".vhd"))
                 for n in [f["name"] for f in files])
    txt = blob.lower()
    has_rsa = ("-----begin" in txt and "key" in txt) or re.search(r"\bn\s*=\s*[0-9]{20,}", txt)
    # LLM challenges need not provide a web URL (offline prompt/config artifacts
    # are common). Require a strong AI-specific signal, not generic "api_key".
    has_prompt = bool(re.search(
        r"system prompt|prompt injection|large language model|\bllm\b|chatbot|gpt[- ]?\d|"
        r"openai|anthropic|langchain|llamaindex|retrieval.?augmented|\brag\b|model endpoint",
        txt, re.I))
    has_diskmem = any(n.endswith((".img", ".dd", ".raw", ".mem", ".dmp", ".vmem")) for n in [f["name"] for f in files])

    checksec = ""
    if has_elf:
        for f in files:
            if "ELF" in f["type"]:
                checksec = run(["checksec", "--file=" + os.path.join(a.given, f["name"])])
                break
    sock = bool(re.search(r"socket|connect|gethostbyname|nc |netcat", txt))

    category, conf, route, notes = None, "LOW", None, []
    if free_win:
        notes.append("free-win strings hit — validate immediately")
    # Binary/file signals FIRST: a URL alone must never shadow ELF/crypto/pcap.
    if has_sol:
        category, conf, route = "blockchain", "HIGH", "/blockchain"
    elif has_apk:
        category, conf, route = "mobile", "HIGH", "/mobile"
    elif has_prompt:
        category, conf, route = "ai-ml", "MEDIUM", "/ai-ml"
    elif has_diskmem:
        category, conf, route = "forensics", "HIGH", "/forensics"
    elif has_pcap:
        category, conf, route = "forensics", "HIGH", "/forensics"
    elif has_elf and sock:
        category, conf, route = "pwn", "HIGH", "/pwn"
        notes.append("socket I/O in ELF")
    elif has_elf:
        # ELF without socket → rev unless unsafe I/O funcs suggest pwn
        if re.search(r"gets|scanf|strcpy|read\(|system|/bin/sh", txt):
            category, conf, route = "pwn", "MEDIUM", "/pwn"
            notes.append("unsafe funcs, no socket seen — confirm I/O")
        else:
            category, conf, route = "rev", "MEDIUM", "/rev"
    elif has_rsa or re.search(r"[0-9a-f]{64,}", txt):
        category, conf, route = "crypto", "MEDIUM", "/crypto"
    elif has_img:
        category, conf, route = "stego", "MEDIUM", "/stego"
    elif has_py and re.search(r"input\(|eval\(|exec\(|raw_input", txt):
        category, conf, route = "misc-pyjail", "MEDIUM", "/misc"
    elif has_fw:
        category, conf, route = "hardware", "MEDIUM", "/hardware"
    elif a.url and re.search(r"https?://", a.url or "") and not files:
        # File-less + live HTTP URL only: web. With files present, URL is
        # context (service/nc), not a category verdict.
        category, conf, route = "web-ctf", "HIGH", "/web"
        notes.append("file-less HTTP service")
    elif a.url and files and re.search(r"php|html|javascript|\bweb\b|http|flask|django|express", txt):
        category, conf, route = "web-ctf", "MEDIUM", "/web"
        notes.append("web framework markers + service URL")
    elif not files:
        # File-less challenge: classify from statement/service text only.
        if re.search(r"php|html|javascript|\bweb\b|http|url|website|page", txt):
            category, conf, route = "web-ctf", "MEDIUM", "/web"
            notes.append("file-less, web keywords in statement")
        elif re.search(r"\brsa\b|\baes\b|decrypt|cipher|encrypt|modulus", txt):
            category, conf, route = "crypto", "LOW", "/crypto"
            notes.append("file-less, crypto keywords in statement")
        elif re.search(r"pcap|packet|wireshark|traffic|capture", txt):
            category, conf, route = "forensics", "LOW", "/forensics"
            notes.append("file-less, traffic keywords in statement")
    elif files and all(f["name"].endswith((".txt", ".md")) for f in files) and \
            re.search(r"username|handle|e-?mail|twitter|discord|instagram|@[a-z0-9]", txt):
        category, conf, route = "osint", "LOW", "/osint"
        notes.append("handle-only text, no code/binary markers")
    elif has_py or any(f["name"].endswith((".zip", ".txt", ".json")) for f in files):
        category, conf, route = "misc-pyjail", "LOW", "/misc"
    if a.service and not category:
        category, conf, route = "pwn", "LOW", "/pwn"
        notes.append("naked service, default pwn probe")

    if free_win and not category:
        category, conf, route = "misc-pyjail", "MEDIUM", "/misc"
    secondary = None
    if category == "pwn" and has_elf:
        secondary = "/rev"
    if category == "stego":
        secondary = "/forensics"

    surface = {
        "chal_id": a.chal_id, "title": a.chal_id,
        "category": category or "unknown", "confidence": conf, "points": a.points,
        "domain": a.domain or (category if category in DOMAINS else "_inbox"),
        "files": files,
        "service": {"endpoint": a.service or a.url} if (a.service or a.url) else None,
        "flag_format_hint": "unknown",
        "flag_format_source": "not stated by the challenge; do not assume a prefix",
        "route": route or "/triage",
        "secondary_route": secondary,
        "signals": notes + (["free_win_candidate"] if free_win else []),
        "estimated_difficulty": "unknown",
        "recommended_skill": f"skills/{(category or 'triage')}/SKILL.md",
    }
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    json.dump(surface, open(a.out, "w"), indent=2)
    print(json.dumps({"category": surface["category"], "confidence": conf,
                      "domain": surface["domain"], "route": surface["route"],
                      "out": a.out, "free_win": bool(free_win)}))
    return 0 if category else 2

if __name__ == "__main__":
    sys.exit(main())
