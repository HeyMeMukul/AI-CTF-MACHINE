---
name: triage
description: 60-second challenge classification across all 14 domains → surface.json + category route
category: triage
phase: 0
---
Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`; separate evidence from inference, preserve scope, validate each link, and label uncertainty.

# TRIAGE — 14-Domain Challenge Classification (Phase 0)

## Mental Model
Classify before analyzing. The router decides everything downstream: wrong route wastes the whole budget.
Cheap wins first: ~30% of easy challenges fall to `strings + exiftool` alone. Triage is read-only and
capped at 60–120s per challenge. When signals conflict, pick the HIGHEST-yield route first and note the
secondary route — never analyze both in triage.

## Workflow

### Phase 1 — Baseline (inventory, read-only)
1. List `given/` (names, sizes, extensions). Record service endpoints (host/port/URL) from the statement.
2. Run the universal sweep (all read-only, each ≤15s):
```bash
file given/*                                   # type per file
strings -n 8 <f> | grep -E -m5 '(flag|FLAG|picoCTF|HTB|THM|CTF)\{'   # free win?
exiftool <f>                                   # comments/history/GPS → hints
xxd <f> | head -n 5                            # header sniff: PEM? ELF? ZIP? SQLite?
```
3. Baseline: what IS this thing (one sentence: "64-bit ELF, socket client, asks for name").

**Reasoning Checkpoint:** inventory complete → file types known → proceed to fingerprint.

### Phase 2 — Confirmation (fingerprint per candidate domain)
Run ONLY the discriminating checks (pick by file/service type):
```bash
# Binary? pwn vs rev signal
checksec --file=./bin                         # NX/PIE/Canary/RELRO
strings -n 6 ./bin | grep -iE 'bin/sh|system|flag|win|socket|connect|scanf|gets' | head
# Web?
curl -sI http://host:port | head -n 15        # headers: Werkzeug? Flask? JWT cookie?
whatweb http://host:port 2>/dev/null | head -n 3
# Crypto?
python3 -c "from Crypto.PublicKey import RSA;k=RSA.import_key(open('key.pub').read());print(k.n.bit_length(),k.e)" 2>/dev/null
grep -rEo 'n = [0-9]+|e = [0-9]+|c = [0-9]+' given/ | head   # RSA params?
# Forensics / stego?
capinfos capture.pcap 2>/dev/null | head -n 5
binwalk -E given/firmware.bin 2>/dev/null | tail -n 5        # entropy: >7.5 = packed/encrypted
# Smart contract?
grep -rlE 'pragma solidity|contract |function ' given/ | head   # → blockchain
# Mobile?
unzip -l app.apk 2>/dev/null | head -n 8      # classes.dex? lib/arm64?
# AI/LLM?
grep -rilE 'system prompt|api_key|OPENAI|temperature|gpt|llama' given/ | head  # → ai-ml
```
Confirm the PRIMARY category with 2+ independent signals.

**Reasoning Checkpoint:** 2+ signals agree → category locked at MEDIUM+ → else mark LOW + secondary route.

### Phase 3 — Negative (rule out lookalikes)
- ELF + socket + `gets/scanf` → pwn, NOT rev (rev = local checker, no I/O loop). If both (network checker),
  route pwn PRIMARY, rev SECONDARY.
- `.py` with `input/eval` → misc-pyjail, NOT crypto (even if it imports hashlib).
- Image with appended ZIP → stego PRIMARY, forensics SECONDARY.
- `prompt.txt` + model endpoint → ai-ml, NOT web (even if HTTP).
- `Dockerfile` + `hardhat/foundry` → blockchain, NOT web.
- Username/handle only, no files → osint, NOT misc.

**Reasoning Checkpoint:** lookalikes eliminated → single primary route → else escalate to Lead.

### Phase 4 — Exploit (gated: write surface.json, no exploitation)
Write `challenges/<domain>/<CHAL>/surface.json` — schema v1 (ALL fields):
```json
{
  "chal_id": "CHAL-001", "title": "vault", "category": "crypto",
  "confidence": "HIGH", "points": 200, "domain": "crypto",
  "files": [{"name": "enc.py", "type": "python", "size": 1234}],
  "service": null,
  "flag_format_hint": "picoCTF{}",
  "route": "/crypto", "secondary_route": null,
  "signals": ["n,e,c present", "PEM pubkey"],
  "estimated_difficulty": "easy",
  "recommended_skill": "skills/crypto/SKILL.md"
}
```
Rules: `category` ∈ {web-ctf, pwn, rev, crypto, forensics, stego, misc-pyjail, osint, hardware,
blockchain, mobile, ai-ml}; `route` = `/<category>` slash command; never write exploit code in triage.

**Reasoning Checkpoint:** surface.json valid JSON → route dispatched → triage done.

### Phase 5 — Validation-handoff
Handoff to Lead: surface.json path, category + confidence, top-3 signals, secondary route (if any),
recommended skill file, attempt count. Lead runs `recon_to_analysis_handoff.py` (M1) to prioritize.

**Reasoning Checkpoint:** handoff complete → Worker releases task → Lead plans analysis.

## Tool Table (exact copy-paste commands)

| Signal | Command |
|---|---|
| Types | `file given/*` |
| Free win | `strings -n 8 <f> \| grep -E -m5 '(flag\|FLAG\|picoCTF\|HTB\|THM\|CTF)\{'` |
| Metadata | `exiftool <f>` |
| Headers | `xxd <f> \| head -n 5` |
| Protections | `checksec --file=./bin` |
| Web fp | `curl -sI URL \| head -n 15`, `whatweb URL` |
| pcap info | `capinfos capture.pcap \| head -n 5` |
| Entropy | `binwalk -E <f> \| tail -n 5` |
| RSA quick | `openssl rsa -pubin -in key.pub -text -noout \| head -n 8` |
| APK list | `unzip -l app.apk \| head -n 8` |
| JS map | `ls given/*.js given/*.map 2>/dev/null` |

## Decision Tree (14-domain router)

```
free-win strings hit? ──yes──→ verify regex → FLAG candidate → validate
no
├─ URL/port + HTTP ──→ web-ctf (SECONDARY: ai-ml if prompt endpoint)
├─ ELF ─┬─ socket I/O + unsafe funcs ──→ pwn (SECONDARY: rev)
│       └─ local checker logic ──→ rev
├─ n,e,c / PEM / ciphers ──→ crypto
├─ .pcap/.pcapng ──→ forensics
├─ disk.img / mem.raw ──→ forensics
├─ png/jpg/wav/mp3 + hidden ──→ stego
├─ .py jail / esolang / QR / zip / code ──→ misc-pyjail
├─ handle/email/domain only ──→ osint
├─ firmware.bin / .hex / .v / UART ──→ hardware
├─ *.sol / foundry.toml / hardhat ──→ blockchain
├─ .apk / .ipa ──→ mobile
└─ prompt.txt / model API / system-prompt ──→ ai-ml
```

## AI Automation Notes
- Triage is the cheapest phase: parallelize across ALL unclassified challenges (independent, read-only).
- `tools/triage.py` wraps this sweep → emits surface.json (exit 0 = classified, 2 = ambiguous → Lead).
- Never skip triage: D-CIPHER auto-prompter gain (+3pp) comes from exploring before planning.
- Timeout: 120s hard cap per challenge; on timeout mark `partial` with signals so far.
