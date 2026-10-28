# AI-CTF-MACHINE

### Autonomous + Interactive AI Framework for Jeopardy-Style CTFs

> One repo, two operating modes: an **interactive Lead/Worker copilot** (OpenCode slash-commands) and a **fully autonomous engine** (CTFd poll → Docker sandbox → oracle-checked submit). Template-first: copy per event, zero cross-event state leakage.

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Engine: stdlib-only](https://img.shields.io/badge/engine-stdlib--only-green.svg)](engine/)
[![Sandbox: Docker](https://img.shields.io/badge/sandbox-docker-blue.svg)](Dockerfile.kali-ctf)
[![Platform: CTFd](https://img.shields.io/badge/platform-CTFd-red.svg)](engine/adapters/)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

---

## Table of Contents

- [Why This Exists](#why-this-exists)
- [Two Modes at a Glance](#two-modes-at-a-glance)
- [Features](#features)
- [Architecture](#architecture)
- [Repository Layout](#repository-layout)
- [Prerequisites](#prerequisites)
- [Quickstart — Interactive Mode](#quickstart--interactive-mode)
- [Quickstart — Autonomous Mode](#quickstart--autonomous-mode)
- [Skills Catalog (19 Core + 32 Imported)](#skills-catalog-19-core--32-imported)
- [Slash Commands](#slash-commands)
- [Tools Reference](#tools-reference)
- [MCP Servers](#mcp-servers)
- [Configuration & API Keys](#configuration--api-keys)
- [Live-Ops Doctrine (Read Before Going Live)](#live-ops-doctrine-read-before-going-live)
- [Safety & Hard Gates](#safety--hard-gates)
- [Verification & Testing](#verification--testing)
- [Knowledge System](#knowledge-system)
- [Writeups](#writeups)
- [Troubleshooting](#troubleshooting)
- [Roadmap / Known Limits](#roadmap--known-limits)
- [Contributing](#contributing)
- [License](#license)

---

## Why This Exists

Most CTF copilots are prompt wrappers. This is a **control plane**:

1. **Evidence-gated** — no claim without an artifact. Every triage/exploit/validate step writes a file with exact command, output, elapsed time, and verdict (`CONFIRMED` / `NEGATIVE` / `PARTIAL`).
2. **Budget-bounded** — max 3 attempts per challenge (corrected retry + one alternate), max 5 submits per challenge, 8–10 s pacing between platform actions.
3. **Oracle-checked** — a task is `solved` only when the local salted hash or the platform API says `correct` / `already_solved`. Regex-shaped strings are candidates, never proof.
4. **Template-isolated** — this folder is pristine. Each event is a filesystem copy, so memory, flags, and browser profiles never leak across CTFs.
5. **Sandboxed** — autonomous tool calls run in Docker (`non-root`, `cap-drop ALL`, `no-new-privileges`, CPU/mem/PID limits), never on your host.

---

## Two Modes at a Glance

| | **Interactive (Lead / Worker)** | **Autonomous (engine/)** |
|---|---|---|
| Entry | `opencode` → `/resume`, `/solve`, `/triage` … | `./run_auto.sh` |
| Brain | `opencode.json` model (`opencode-go/muse-spark-1.3-contributor#xhigh` Lead) | Any OpenAI-compatible LLM (`LLM_BASE_URL` / `LLM_MODEL`) |
| Execution | Bounded Worker subagents, human approves submits | Docker sandbox tool loop (`bash`, `read_file`, `write_file`, `http`, `submit_flag`, `finish`) |
| Queue | `state.json` + `tools/ctfusion.py` | SQLite (`events/<slug>/state.sqlite3`) with EV ordering + leases |
| Submit | Human hard gate via `tools/submit.py` | Auto-submit via CTFd API (only when rules allow) |
| Best for | Hard/creative challenges, live sites with CAPTCHA | Overnight grinding, many parallel challenges |

Both modes share `skills/`, `recipes/`, `knowledge/`, and the same safety doctrine in `docs/LIVE_OPS.md`.

---

## Features

- **19 core skills** with EASY-FIRST ladders + R4 field patterns: triage, web-ctf, pwn, rev, crypto, forensics, stego, misc-pyjail, osint, hardware, blockchain, mobile, ai-ml, sessions, mcp-servers, browser-ops, chaining-flagpath (Lead-only), report-writeup, sequential-thinking.
- **32 imported security skills** (source-verified): libFuzzer/AFL++ harnessing, ASan, constant-time analysis, semgrep, JWT attacks, RESTler API fuzzing, JS deobfuscation, YARA, Volatility/memory, Wireshark/PCAP, MFT/disk recovery, ELF/PDF-Office malware, Windows artifacts, Firebase/APK/Android/iOS, smart-contract/ethereum/solana audits, heap-spray, firmware/binwalk, stego detection, OSINT recon, LLM prompt-injection. Full 2,015-entry catalog searchable via `python3 -m engine knowledge --catalog`.
- **14,416-row writeup-mined technique index** (r1/r2 index mining + r3 ctftime crawl + r4 2,034-row browser-swarm batch) backing the RAG lookup.
- **Governance with exit codes 0/1/2**: state_manager (slots, retry budget, submit ledger), task_validator (single-hypothesis, anti-soliloquy, dedup), result_quality_gate (evidence, flag_checker, stall hook), hypothesis_deduplicator, recon_to_analysis_handoff, stall_detector, flag_checker, skill_lint.
- **Live browser pipeline**: operator-Chrome (CDP attach, persistent profile) → challenge extraction → file download with hash verification. CAPTCHAs pause to a human gate — never auto-solved.
- **Quick-win guarantee**: `tools/autosolve.py` runs first on every challenge so no CTF returns nothing (flag regex, base64/hex, zip EOCD carve).
- **Autonomous engine is stdlib-only** (Python 3.11+, no pip install) — runs on a fresh Kali/WSL box.
- **Flag hygiene**: traces log SHA-256 + length only; accepted flags go to `0600` files; secrets never enter shared knowledge or third-party search.

---

## Architecture

### Interactive loop

```text
Operator ── ./start.sh ──► state.json + operator-Chrome + MCP health
   │ log in + solve CAPTCHA manually
   ▼
opencode (/resume /solve CHAL-xxx)
   ├── Lead (build agent): plan, dispatch, merge, flag-path synthesis — NEVER runs bash/curl/gdb directly
   └── Workers (general agent): /triage → /recon → /analyze → /exploit → /validate
            │ each writes an artifact under results/ or tasks/
            ▼
   human hard gate: /submit → tools/submit.py (paced + ledger + budget)
```

### Autonomous loop

```text
CTFdAdapter.sync() ──► Store (SQLite: tasks, outcomes, EV order)
                          │
                     Daemon loop (ThreadPoolExecutor, --workers 8)
                          │ lease (expiry requeue)
             build_env() ─► DockerEnv (default) / LocalEnv (trusted fixtures only)
                          │
             Solver ──► Provider.chat() ──► tool call (bash/read/write/list/http/note/submit/finish)
                          │                        │
                          └──── observations ◄─────┘
                          │
                    Oracle.check(candidate) ── accepted ──► flags/<task>.txt (0600) + state=solved
                                                rejected ──► continue (bounded submits)
```

Every LLM/tool/verdict event appends to `events/<slug>/runs/<task>-*/attempt-*/trace.jsonl`.

---

## Repository Layout

```text
AI-CTF-MACHINE/
├── start.sh / run_ctf.sh / run_auto.sh / setup_ctf.sh   # bring-up, day-ops, autonomous entry
├── opencode.json          # Lead/Worker models + MCP wiring + 25 slash commands
├── master_prompt.md lead_prompt.md worker_prompt.md challenge_prompt.md
├── phases/                # phase doctrine (triage→recon→analyze→exploit→validate→writeup)
├── skills/                # 19 core + _shared/SKILL_CONTRACT.md + imported/ (32)
├── knowledge/             # writeup-mined manifests, catalog/SELECTION.md, learnings/
├── recipes/               # fixture-tested recipes (verified:true only load into engine)
├── tools/                 # 30+ CLIs: autosolve, triage, ctfusion, submit, browser_extract,
│                          # captcha_gate, instance, answer_forge, race, rag_lookup, mcp_doctor …
├── engine/                # autonomous control plane (stdlib-only): daemon, scheduler,
│                          # solver, sandbox, providers, CTFd adapter, eval_runner
├── eval/tasks/            # 4 offline eval tasks with salted hashes + mock provider
├── config/                # engine.json, model_routes.json, ctf_policy.json
├── docs/                  # AUTONOMOUS, LIVE_OPS, SCORECARD, EVIDENCE, HARDENING,
│                          # BLUEPRINT_V2, SKILL_IMPORTS, FRAMEWORK_REVIEW …
├── scripts/build_image.sh # builds ctf-kali:latest sandbox image
├── Dockerfile.kali-ctf
├── challenges/ results/ tasks/ writeups/ downloads/  # per-event data (EMPTY in template)
├── state.json             # pristine template — start.sh inits it per event
└── tests/                 # 21 engine tests (18 unit + 3 integration)
```

> `challenges/ results/ tasks/ writeups/ .browser-profile/` are real dirs, empty in the template. `events/ runs/ *.sqlite3 flags/` are git-ignored runtime data.

---

## Prerequisites

| Need | Check | Notes |
|---|---|---|
| Python 3.11+ | `python3 --version` | Engine is stdlib-only; extras only for analysis (`playwright`, `volatility3`) |
| Node + npx | `node -v && npx -v` | MCP servers (memory, thinking, cyberchef, crypto-tools) |
| uvx | `uvx --version` | GDB-MCP, CTFd-MCP, ctf-toolkit |
| Chrome | `google-chrome --version` | Operator profile on `:9222`, attach-only via CDP |
| Docker (autonomous) | `docker --version` | Builds `ctf-kali:latest`; sandbox default |
| gdb, file, strings, exiftool | `which gdb file strings exiftool` | Missing tools only degrade their domains |
| opencode | `opencode --version` | Interactive mode |

Optional per domain: `binwalk tshark nmap ffuf gobuster john hashcat`, Ghidra (`GHIDRA_INSTALL_DIR`), Burp Pro + MCP extension.

```bash
pip install --user playwright volatility3
playwright install chromium
```

---

## Quickstart — Interactive Mode

**One script brings the whole rig live. Run once per copied engagement folder.**

```bash
# 1. Clone and enter
git clone https://github.com/HeyMeMukul/AI-CTF-MACHINE.git
cd AI-CTF-MACHINE

# 2. Copy the pristine template per event (never solve inside the template)
cp -r AI-CTF-MACHINE /path/to/<event-slug>/ && cd /path/to/<event-slug>

# 3. Full bring-up: deps check + MCP warm + state init + Chrome + health + self-test
./start.sh "Event Name" https://platform-url

# 4. LOG IN + solve any CAPTCHA MANUALLY in the operator Chrome window.
#    Hammering it with automation deepens the block. Then:
python3 tools/session_check.py --url https://platform-url   # want exit 0

# 5. Open the copilot
opencode
# inside opencode:
#   /resume            # pick up from state.json
#   /solve CHAL-001    # full triage→exploit loop for one challenge

# 6. Day-ops (second terminal)
./run_ctf.sh pull --max 10   # pull unregistered challenges (serial, paced)
./run_ctf.sh quickwins       # cheap offline sweep — never returns nothing
./run_ctf.sh status          # state + ledger + gates in one view
./run_ctf.sh stop            # tidy tabs, stop Chrome, summary
```

Low-level pieces (normally you don't need them): `setup_ctf.sh --init/--status/--build/--browser`, everything under `tools/`.

---

## Quickstart — Autonomous Mode

```bash
cd AI-CTF-MACHINE

# 0. Self-test with NO key, NO docker, NO network (expect 4/4)
python3 -m engine selftest

# 1. Build the sandbox image once (needs Docker)
./scripts/build_image.sh        # → ctf-kali:latest (python + pwntools + gdb + z3 + …)

# 2. Export secrets (CTFd token: profile → Settings → Access Tokens)
export CTFD_URL="https://your-ctf.example"
export CTFD_TOKEN="ctfd_..."
export LLM_BASE_URL="https://api.openai.com/v1"   # or OmniRoute / OpenRouter / vLLM / LM Studio
export LLM_API_KEY="..."
export LLM_MODEL="..."

# optional
export EVENT_SLUG="my-event" WORKERS=8 MAX_HOURS=12 ATTEMPTS=2

# 3. Check the rig
python3 -m engine doctor --ping

# 4. Start the loop (runs until MAX_HOURS or Ctrl-C; Ctrl-C is clean, leases resume)
./run_auto.sh
```

Watch it:

```bash
python3 -m engine status
tail -f events/<slug>/runs/<task>-*/attempt-1/trace.jsonl
```

> Only auto-submit on events whose rules allow API submission with your own token. Otherwise run the sandbox but keep submission manual.

Offline demo (no CTFd at all):

```bash
python3 -m engine daemon --platform local --tasks-dir eval/tasks \
    --provider mock --sandbox local --workers 4 --once
```

---

## Skills Catalog (19 Core + 32 Imported)

Core skills live in `skills/<name>/SKILL.md`; dispatch order is in `skills/index.md`. Every skill obeys `skills/_shared/SKILL_CONTRACT.md` (evidence / scope / validation).

| Phase | Skill | What it does |
|---|---|---|
| 0 | `triage` | 60–120 s classify across 14 domains → `surface.json` + router table (file signals outrank list-page labels) |
| 1–2 | `web-ctf` | recon → SQLi/NoSQLi, XSS, SSTI, LFI/RFI, SSRF, XXE, deserialization, JWT, GraphQL, param pollution, CMDi, upload, logic bugs |
| 1–3 | `pwn` | checksec tree → offset → leak → ROP, fmt-string, heap, skeletons E1–E5 |
| 2–3 | `rev` | Ghidra headless+MCP, r2, angr, Frida, unpacking, .NET/Go/pyc/APK/WASM |
| 1–3 | `crypto` | classifier → RSA matrix + RsaCtfTool, AES oracles, ECC, classical, hashcrack |
| 1–3 | `forensics` | pcap / disk / memory (Volatility 3) / timeline |
| 1–3 | `stego` | ordered pipeline: exiftool → binwalk → zsteg/steghide → spectrogram → QR |
| 1–3 | `misc-pyjail` | pyjails, esolangs, encodings, archives |
| 1–3 | `osint` | sherlock/maigret, theHarvester, crt.sh, Wayback, dorks, metadata (scope-locked) |
| 1–3 | `hardware` | firmware (binwalk/firmwalker), UART/JTAG/SPI, sigrok, side-channels, Verilog |
| 1–3 | `blockchain` | foundry loop, EVM vulns 1–8, cast/anvil, proxies (local fork only) |
| 1–3 | `mobile` | apktool/jadx, manifest, Frida, pinning bypass (never upload APKs/tokens) |
| 1–3 | `ai-ml` | prompt-injection taxonomy, exfil patterns, guardrail probing (synthetic canaries only) |
| all | `sessions` | persistent pwntools-conn + gdb patterns, state machine |
| all | `mcp-servers` | arsenal catalog: always-on vs per-task, exact configs, risk rules |
| all | `browser-ops` | operator-Chrome + CDP attach + challenge/file extraction pipeline |
| Lead | `chaining-flagpath` | multi-step flag-path synthesis (score ≥ 50) |
| 5 | `report-writeup` | writeups from validated flags only, failed approaches with evidence |
| all | `sequential-thinking` | numbered-thought reasoning discipline (`/think`) |

Imported (32, source-verified — see `skills/imported/README.md`, `NOTICE.md`, `docs/SKILL_IMPORTS.md`, `knowledge/catalog/SELECTION.md`):

`libfuzzer · aflpp · harness-writing · address-sanitizer · constant-time-analysis · crypto-test-vectors · dwarf-expert · differential-review · upx-unpack · insecure-defaults · static-analysis-semgrep · jwt-attacks · api-fuzzing-restler · js-deobfuscation · yara-authoring · memory-volatility · pcap-wireshark · disk-mft-recovery · linux-elf-malware · pdf-office-malware · windows-artifacts · firebase-apk-scanner · android-apktool · ios-assessment · smart-contract-audit · ethereum-contracts · solana-audit · heap-spray · firmware-binwalk · stego-detection · osint-recon · llm-prompt-injection`

Search the 2,015-entry index without loading it into the prompt:

```bash
python3 -m engine knowledge --catalog --query "volatility memory forensics"
python3 -m engine knowledge --catalog --query "fuzzing harness"
```

---

## Slash Commands

Defined in `opencode.json` (user args pass through `$ARGUMENTS`, never shell interpolation):

| Command | Agent | Purpose |
|---|---|---|
| `/worker <task>` | general | exactly one bounded framework task, returns evidence artifact |
| `/triage <chal>` | general | Phase 0 classify → `surface.json` (no exploitation) |
| `/recon <target>` | general | bounded in-scope surface expansion |
| `/analyze <chal>` | general | ≤3 ranked falsifiable hypotheses + cheapest test |
| `/exploit <hyp>` | general | ONE hypothesis, minimal reproducer, caps enforced |
| `/validate <repro>` | general | fresh-container rerun vs challenge oracle |
| `/writeup <chal>` | build (Lead) | writeup from validated artifacts only |
| `/solve <CHAL-ID>` | build (Lead) | macro: triage→exploit loop, ≤3 attempts, never submits |
| `/pwn /crypto /rev /web /forensics /stego /misc /osint /hardware /blockchain /mobile /ai-ml` | general | domain specialists |
| `/browser <task>` | general | CDP-attached extraction (never fills creds/CAPTCHA) |
| `/submit <chal: candidate>` | general | **hard gate** — paced, ledgered, explicit operator auth only |
| `/instance <spawn\|status\|close>` | general | challenge-instance lifecycle via `tools/instance.py` |
| `/think <chal>` | build | sequential reasoning for flag-path synthesis |
| `/status` | build | state.json summary (counts, blockers, next action — no flag values) |
| `/resume` | build | inventory state, dispatch next bounded task |

**Discipline (never violated):** Lead plans and dispatches; Workers probe/fuzz/debug/exploit. Lead never runs `bash/curl/nc/gdb/python3 solve.py` directly. Parallelism: 2 workers interactive (8 in the daemon), independent challenges only, unique artifact path per task.

---

## Tools Reference

All under `tools/` (run from repo root):

| Tool | Purpose |
|---|---|
| `autosolve.py` | quick-win sweep FIRST (regex/b64/hex/zip-carve) — `--all` |
| `triage.py` | file-signal classification (fixes all-web-ctf misroute) |
| `browser_extract.py` | CDP challenge + file pull, prominent Question line in `statement.md` |
| `ctfusion.py` | poll / queue / fast / backfill / learn loop, `--status` |
| `submit.py` | ONLY submit path: verdict parse + ledger + `--pace 10` + budget + dup-refuse |
| `answer_forge.py` | evidence → ranked candidates → top-1 submit (refuses 6th blind guess) |
| `captcha_gate.py` | human CAPTCHA gate — agent idles, operator solves |
| `session_check.py` | clearance pre-flight (exit 0 = go, 2 = challenged) |
| `instance.py` | spawn / status / close-dead lifecycle |
| `btabs.py` | tab list/cleanup (resolve by URL substring, never `pages[0]`) |
| `flag_checker.py` | oracle check (hash/API), never regex-alone |
| `state_manager.py` | slots, retry budget, challenges/flags, submit ledger |
| `task_validator.py` | single-hypothesis, anti-soliloquy, dedup |
| `result_quality_gate.py` | evidence + consistency validation |
| `race.py` / `stall_detector.py` / `hypothesis_deduplicator.py` / `recon_to_analysis_handoff.py` | loop guards |
| `zip_forensics.py` | EOCD-first orphan carve |
| `rag_lookup.py` | TF-IDF over mined manifests |
| `model_router.py` | `config/model_routes.json` / `CTF_MODEL_*` — fails `UNCONFIGURED`, never fakes a fleet |
| `rev_ghidra.py` / `ghidra_mcp.sh` | headless decompile CLI |
| `mcp_doctor.py` / `bench.py` | backend health / ~40 offline assertions + engine selftest |
| `writeup_generator.py` | validated-artifact writeups |
| `knowledge_ingest.py` / `artifact_spill.py` | technique distillation (manual review before merging) |
| `operator_ping.sh` | hard-gate notifier (`"<need>" loop`) |

---

## MCP Servers

Configured in `opencode.json` (`enabled: true` = always-on, `false` = per-task opt-in):

| Server | Mode | Purpose | Key needed? |
|---|---|---|---|
| `playwright` | local | full browser control (core, vision, network, pdf) | no |
| `memory` | local | persistent knowledge graph across sessions | no |
| `sequential-thinking` | local | multi-step reasoning | no |
| `cyberchef` | local | bake/search/describe recipes | no |
| `crypto-tools` | local | hash / encode / JWT helpers | no |
| `mdb` | local | GDB sessions (local binaries) | no |
| `filesystem` | local | scoped to `challenges/` + `results/` only | no |
| `volatility` | local | vendored Volatility 3 server | no |
| `ghidra` | local | GhidraMCP headless (28 RE tools) | no |
| `ctfd` | local | list/detail/submit/containers | **yes** — `CTFD_URL` + `CTFD_TOKEN`, enable per CTFd event |
| `htb-ctf` | remote | official HTB CTF MCP | **yes** — Bearer MCP token from HTB profile |
| `ctf-toolkit` | local | 126-tool kit, 14 RCE-class | sandbox-only per task, then disable |
| `burp` | local | Burp Pro (61 tools, Den-Sec) | **yes** — Burp Pro + `BURP_API_URL` + `BURP_API_KEY`, disabled by default |
| `brave-search` | local | OSINT dorking | **yes** — `BRAVE_API_KEY` |
| `github` | local | code search for OSINT | **yes** — `GITHUB_PERSONAL_ACCESS_TOKEN` |

> Never send flags to search MCPs (local-only policy). `tools/mcp_doctor.py` verifies every backend.

---

## Configuration & API Keys

Only export what you actually use. Local MCPs need nothing.

```bash
# CTFd events (also enables the 'ctfd' MCP for this event)
export CTFD_URL="https://ctf.example.com" CTFD_TOKEN="ctfd_..."

# HTB events — Bearer MCP token from HTB profile → enable 'htb-ctf' in opencode.json

# Burp Pro — run Burp + load extension/build, then:
export BURP_API_URL="http://127.0.0.1:8089" BURP_API_KEY="..."

# OSINT dorking / code search
export BRAVE_API_KEY="..."
export GITHUB_PERSONAL_ACCESS_TOKEN="..."

# Autonomous engine LLM (any OpenAI-compatible endpoint)
export LLM_BASE_URL="https://api.openai.com/v1" LLM_API_KEY="..." LLM_MODEL="..."

# Interactive copilot routing (fails UNCONFIGURED until ≥2 distinct routes set)
python3 tools/model_router.py --check
```

Engine defaults live in `config/engine.json` (`${VAR}` expanded from env): `provider.kind` (`openai`/`mock`), `solver.max_steps/max_seconds/max_tokens/max_submits/attempts`, `sandbox.kind` (`docker`/`local`) + `image` + `live_network`, `scheduler.workers/max_attempts`, `knowledge.top_k`. Model restarts require restarting OpenCode. Never put secrets in command text.

---

## Live-Ops Doctrine (Read Before Going Live)

From `docs/LIVE_OPS.md` — every rule cost a failed submit or a block (12 challenges, playctf.in, Oct 2026):

1. **Pacing** — ≥8–10 s between platform actions; `submit.py --pace 10` default; 429/CF back-to-back = stop batch, wait 10 min, single-probe resume.
2. **Clearance pre-flight** — `session_check.py` before ANY platform op; exit 2 → `operator_ping.sh` human solve → re-check.
3. **Tab discipline** — never `pages[0]`; resolve by URL substring; `btabs.py list/cleanup`; one profile = one flow.
4. **Submit discipline** — only via `submit.py`; every verdict lands in `state.json _submissions`; answer-style via `answer_forge.py` first; never invent hex suffixes; never resubmit rejects.
5. **Format intelligence** — after every solve, mine the flag SHAPE (e.g. `tark_suffix=hex8`); two failed formats with no new evidence = blocked, not a third guess.
6. **Vision-first** — view images via Read before pixel forensics; diff-then-zoom on pairs.
7. **Instance lifecycle** — `instance.py --spawn` (writes `service.txt`) → `--status` → work → `--close-dead`; empty 200-byte artifact = platform-side, respawn ONCE then blocked.
8. **Pull-time capture** — verify the Challenge Question line in `statement.md` after every pull.

---

## Safety & Hard Gates

The agent **pauses (never bypasses)** and pings the operator on:

- CAPTCHA / bot-wall / login → `python3 tools/captcha_gate.py --url <target>` (operator solves manually)
- flag submit (interactive) → `/submit` with explicit challenge + candidate authorization
- scope ambiguity, unbounded brute, destructive action → `tools/operator_ping.sh "<need>" loop`

Autonomous exception: the daemon may submit through the CTFd API **only** when event rules allow automated submission. Autonomous tool calls run in Docker; `sandbox.kind=local` is for trusted eval fixtures only — never run platform binaries with it.

---

## Verification & Testing

```bash
./setup_ctf.sh --status
python3 -c "import json; json.load(open('state.json'))"
bash -n setup_ctf.sh && bash -n start.sh && bash -n run_ctf.sh && bash -n run_auto.sh
python3 tools/skill_lint.py
python3 tools/framework_lint.py            # add --strict in CI
python3 tools/bench.py                     # ~40 offline assertions + engine selftest
python3 -m unittest discover -s tests -v   # 21 engine tests
python3 -m engine selftest                 # 4/4 mock eval expected
python3 -m engine doctor --ping            # provider + sandbox + recipes + eval + CTFd
```

Model/config changes require restarting OpenCode. `docs/SCORECARD.md` is evidence-gated: no live benchmark numbers are claimed until run.

---

## Knowledge System

- `knowledge/` — writeup-mined technique manifests (the 14,416-row index), per-event `learnings/` (technique-only lessons, manually distilled).
- `recipes/*.json` (`verified: true`) — the only recipes the engine loads. `recipes/imported-*.json` (`verification: source`) — labeled source-verified.
- `knowledge/writeups_mined/*` — quarantined; never loaded unless `--include-unverified`.
- `python3 -m engine knowledge --catalog --query "..."` searches the full catalog without polluting the prompt.
- Lead merges reviewed `knowledge/learnings/*.md` patterns into `skills/` after review.

---

## Writeups

```bash
# inside opencode
/writeup CHAL-001     # Lead-only, from validated artifacts, cites sources + failed approaches
```

Rules: observed facts vs inference separated; artifact paths cited; flag values redacted from chat and shared knowledge (private per-event writeup only if rules require); never ingest secrets.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `session_check.py` exit 2 | Solve CAPTCHA manually in operator Chrome → re-check; don't hammer |
| Submits rejected / duplicates refused | Check `state.json _submissions` ledger; `answer_forge.py` needs NEW evidence for attempt 6+ |
| `model_router.py --check` → `UNCONFIGURED` | Set ≥2 distinct routes in `config/model_routes.json` or `CTF_MODEL_*`, restart OpenCode |
| MCP cold-start 60 s | `./start.sh` warms backends; `tools/mcp_doctor.py --probe` for detail |
| `run_auto.sh` missing image | `./scripts/build_image.sh` first |
| `doctor --ping` CTFd fail | Verify `CTFD_URL` + token (profile → Settings → Access Tokens) |
| Empty artifact from live instance | Record `EXP.partial`, respawn ONCE, then mark blocked |
| Turnstile submit fails | Solve → submit within SECONDS; re-fill fields wiped by failed submits |
| State confusion | `./run_ctf.sh status`; validate `state.json` parses; template state is intentionally empty |

---

## Roadmap / Known Limits

- HTB / rCTF adapters not implemented (CTFd + local are).
- No semantic verifier / model portfolio yet — scheduler parallelizes tasks and attempts, attempts share one submit ledger.
- Verified recipe set intentionally small; mined manifests stay quarantined until audited.
- Docker image not vendored — `ctf-kali:latest` must be built.
- No egress allowlist yet on sandbox network modes.
- No live benchmark run yet — `docs/SCORECARD.md` numbers are evidence-gated by design.

See `docs/BLUEPRINT_V2.md`, `docs/HARDENING.md`, `docs/FRAMEWORK_REVIEW.md`, `docs/EVIDENCE.md`.

---

## Contributing

1. Fork → per-event pattern applies to dev too: work in a copy/branch, never in a live event folder.
2. One hypothesis per task, one artifact per task, evidence before claims.
3. Run the full gate before PR: `skill_lint` + `framework_lint --strict` + `bench` + `unittest` + `engine selftest`.
4. Technique-only lessons → `knowledge/learnings/`; Lead merges into `skills/` after review.
5. Never commit flags, tokens, `.env`, `events/`, `runs/`, `*.sqlite3`, or browser profiles (see `.gitignore`).

---

## License

MIT — see [LICENSE](LICENSE) (or the license file in your fork). Built for educational CTF play and security research. Only attack in-scope targets you are authorized to test, and respect each event's rules on automation and submission.

---

**Author:** [@HeyMeMukul](https://github.com/HeyMeMukul) — AI-CTF-MACHINE: template-first, evidence-gated, budget-bounded CTF automation.
