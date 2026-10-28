# BROWSER_EXTRACTION_PLAN.md — Undetected-Browser Challenge-Extraction Pipeline

> Version: v0.1.0-m0 (scaffold) · Status: DESIGN + SCAFFOLD (UNTESTED)
> Technique-only. No credentials, cookies, tokens, or flags in repo/logs.
> Verified upstream refs only: `vercel-labs/agent-browser` (github),
> `Kaliiiiiiiiii-Vinyzu/patchright`, `cloakhq/cloakbrowser`.
> No platform URLs are hardcoded anywhere — all targets via `--base-url`.

---

## 0. Goal / Non-goals

### 0.1 Goal

Give the AI CTF solver a **reliable, low-signal, operator-assisted path** from
"challenges live on a web platform behind login" to "each challenge materialized
on disk as `challenges/_inbox/<slug>/`, promoted to `challenges/<domain>/<CHAL>/`,
registered in `state.json`, triaged to `surface.json`" — without getting the operator's account flagged and without
leaking session secrets into the agent loop.

Concretely, after this plan is implemented:

1. Operator launches a **dedicated Chrome profile** once (`setup_ctf.sh --browser`) and logs in manually (SSO/2FA stays human).
2. Agent attaches over CDP to that **already-logged-in** browser — never handles passwords, never types credentials.
3. Agent lists challenges, pulls per-challenge detail (title, category, points, files, service), downloads attachments into `challenges/_inbox/<slug>/given/`, writes `statement.md` + `service.txt`, registers `state.json`, promotes via `new_challenge.py` to `challenges/<domain>/<CHAL>/`, runs `tools/triage.py` → `surface.json`.
4. Session expiry / download / parse failures degrade to a **gated, bounded retry** — never unbounded, never credential handling.

### 0.2 Non-goals (explicitly out of scope)

- No automated login, credential fill, 2FA bypass, or CAPTCHA solving.
- No exploit traffic — extraction is **read-only + download only** (exploits live in category skills).
- No scraping off-platform domains (allowlist, §10); no parallel downloads from one profile (serial rule, §4.7).
- No flags/cookies/tokens in `state.json`, logs, or writeups.

### 0.3 Where this fits in the framework

```
operator-Chrome (logged in, dedicated profile, :9222) → CDP attach (session, never creds)
  → agent-browser CLI/MCP + Playwright MCP (--cdp-endpoint) + raw CDP
  → tools/browser_extract.py (--check/--list/--pull/--pull-all)
  → challenges/_inbox/<slug>/{given/,statement.md,service.txt} → new_challenge.py (promote)
  → challenges/<domain>/<CHAL>/{surface.json,recon/,profiles/,exploits/,flag.txt,writeup.md}
  → state.json (registered → triaged) → Lead dispatch (/triage /solve)
```

Mirrors the sibling framework's Chrome 9222/9223 session pattern and iron loop (`validate → lock → dispatch → unlock → gate`), with `state.json` as registry and `tools/operator_ping.sh` hard gates.

---

## 1. Architecture

### 1.1 Components

| # | Component | Role | Never does |
|---|---|---|---|
| A | **Operator Chrome** (dedicated `--user-data-dir`, port 9222) | Holds the human login session. The only place secrets live (in-memory/profile). | Never driven headless for login; never shares the default profile. |
| B | **CDP endpoint** (`http://localhost:9222`) | Local attach point. `/json/version` = liveness probe; page targets = navigation handles. | Never exposed off-host; never tunneled. |
| C | **agent-browser** (Rust CLI + MCP server, `vercel-labs/agent-browser`) | Reffed snapshots (`snapshot -i` → `@e1` refs), scripted nav/click/download for extraction workers. | Never stores creds; respects `AGENT_BROWSER_DOWNLOAD_PATH`. |
| D | **Playwright MCP** (`--cdp-endpoint=http://localhost:9222`, `--extension` mode) | DOM/JS-heavy pages, login-state reuse (SSO/2FA-safe), download events. | Never `new_page()` on the attached browser (see §1.3). |
| E | **`tools/browser_extract.py`** | Deterministic pipeline: check/list/pull/pull-all + state registration + triage hook. | Never hardcodes platform URLs; never logs cookies/flags. |
| F | **`skills/browser-ops/SKILL.md`** | Worker contract: gated 5-phase extraction per challenge. | Never parallelizes same-profile work. |
| G | **`state.json`** | Single registry: `challenges[]`, triage counters, concurrency slots. | Never stores secrets or flags beyond `flag_format_hint`. |

### 1.2 Why operator-Chrome + CDP (not bot-Chrome + autofill)

CTF platforms typically run **weak anti-bot** (session cookie + maybe a JS check). The biggest real lever is **IP + behavior, not browser fingerprint**. Driving the operator's real Chrome over CDP is inherently low-signal (real profile/history/fonts, human login, human-speed nav). L1–L3 (§3) are opt-in escalation, not the default.

### 1.3 The two CRITICAL invariants (never violate)

1. **Chrome 136+ dedicated-profile rule.** `--remote-debugging-port` does NOT work on the DEFAULT profile. You MUST launch with a DEDICATED `--user-data-dir` (e.g. `~/.ctf-chrome-profile`). Session persists in that dir across restarts.
2. **CDP attach context rule.** Use `browser.contexts()[0]` (real profile context). NEVER `browser.new_page()` — that spawns a fresh logged-out context and everything looks "expired".

### 1.4 Data flow (one challenge)

```
list → snapshot (-i refs) → parse rows → detail → snapshot → parse statement/files/service
  → download to CHAL-XXX/given/ (hash-dedup) → statement.md + service.txt (sanitized)
  → state.json (registered) → tools/triage.py → surface.json → handoff to Lead
```

---

## 2. Setup flow (`setup_ctf.sh --browser`)

Target UX: one command, one manual login, one verify. Idempotent and safe to
re-run (never wipes the profile dir).

### 2.1 Proposed CLI

```bash
./setup_ctf.sh --browser [--port 9222] [--profile-dir ~/.ctf-chrome-profile]
./setup_ctf.sh --browser --status     # verify: /json/version + context check
./setup_ctf.sh --browser --stop       # kill the dedicated Chrome only
```

### 2.2 Step-by-step

1. **Launch dedicated Chrome** (if not already listening):
   ```bash
   google-chrome --user-data-dir="$HOME/.ctf-chrome-profile" --remote-debugging-port=9222 \
     --no-first-run --no-default-browser-check --restore-session-state &
   ```
   Headed window preferred (most human). Never `--headless` here, never the default profile dir.
2. **Operator logs in manually** in the launched window (login/SSO/2FA → challenges page). Agent waits.
3. **Agent verifies (no credentials touched):**
   ```bash
   curl -s http://localhost:9222/json/version | head -c 500
   python3 tools/browser_extract.py --check --base-url "$PLATFORM_URL"
   ```
   Asserts CDP reachable, `contexts()[0]` exists, list page shows authenticated content (not a login redirect).
4. **Pin the session:** record only `browser: {port, profile_dir, verified_at, base_url_host}` (never secrets).
5. **Wire opencode MCP** (one-time, §8): add `--cdp-endpoint`, register agent-browser MCP, restart opencode.

### 2.3 Re-login / profile hygiene

- Session persists in `--user-data-dir` across restarts; on expiry the operator re-logs in manually, then re-run `--check`.
- Never delete the profile dir as a "fix" — that destroys the session. One profile = one platform login; a second platform = second dir + port (e.g. 9223).

---

## 3. Browser choice matrix (stealth ladder L0–L3)

Default is **L0**. Escalate ONLY on evidence (block page, 403-cluster, JS-poisoned
DOM, explicit bot verdict). `playwright-stealth` plugin is DEAD — do not use or
recommend it. Biggest lever remains IP/behavior (rate, timing, parallelism).

| Level | Stack | Fingerprint posture | When to use | Cost / caveat |
|---|---|---|---|---|
| **L0** | Plain CDP-attached REAL Chrome (operator's browser) | Inherently low-signal: real profile/history/fonts/viewport | **Default.** CTF platforms with weak anti-bot; SSO/2FA reuse; all first attempts | Requires headed window + operator login; serial per profile |
| **L1** | Patchright (`Kaliiiiiiiiii-Vinyzu/patchright`, Playwright drop-in, `channel="chrome"`, headed best) | Patched driver + real Chrome channel; removes common automation flags | L0 gets a soft block (one 403/JS-check) but session is valid; need a second scripted browser with same session shape | Extra dep; headed still best — headless re-adds signal |
| **L2** | Camoufox (Firefox fork) | Strong anti-fingerprint defaults | L1 still fingerprinted; target keys on Chromium quirks; need a non-Chromium shape | Slow; headless ~90% but throughput hit; session must be re-established by operator |
| **L3** | nodriver / zendriver (CDP-direct) | Minimal automation surface; zero-blocked in one bench | Prior levels blocked AND task is still read-only extraction (never for brute/exploit) | Thinnest API; hardest to debug; keep as last resort |

### 3.1 Escalation rule

`L0 → blocked? → --check first (rule out session-expiry) → bot-shaped? → L1 (one retry) → still blocked? → L2/L3 (Lead, one retry each) → still blocked → mark blocked, move on (max 3 methods).` Never escalate for **session-expiry** — that is an operator re-login gate (§6.1), not stealth.

### 3.2 CloakBrowser note (docker stealth endpoint)

`cloakhq/cloakbrowser` (`cloakserve`, port 9222) + `agent-browser connect <cdp-port>`: stealth runtime in Docker, agent attaches over CDP as in L0. Login inside CloakBrowser is still manual (agent never types secrets).

---

## 4. Extraction pipeline stages

Canonical per-run order. `--pull-all` is just `--list` then serial `--pull`.

### 4.1 Stage 0 — Pre-flight (`--check`)

Assert CDP reachable (`/json/version`), `contexts()[0]` non-empty, no `new_page()` path taken; list page shows authenticated content (rows or profile marker; login form = `session_expired`). `--dry-run` prints the plan without navigating. Failure → §6.1 gate, not stealth escalation.

### 4.2 Stage 1 — List challenges (`--list`)

Navigate list page in `contexts()[0]`; snapshot (`snapshot -i` → `@eN` refs, or MCP DOM/accessibility tree); parse per row `title`, `category` (as displayed — do NOT invent), `points`, `detail_url`, `solved` flag. Emit JSON to stdout + optional `--out challenges/_index.json`, e.g. `[{"slug":"web-101","title":"...","category":"web","points":100,"detail_url":"/challenges/<id>","solved":false}]`. Assign stable `CHAL-001…` IDs in list order; `slug → CHAL-ID` mapping in the index keeps re-runs stable.

### 4.3 Stage 2 — Per-challenge detail (inside `--pull CHAL-ID`)

Serial, one challenge at a time, same profile: (1) snapshot detail page; (2) parse `title`/`category`/`points`/`files[]`/`service`/`statement` (sanitized); (3) download attachments → `challenges/_inbox/<slug>/given/` (§5); (4) write `statement.md` + `service.txt`; (5) register `state.json` (§7, `registered`, `domain=_inbox`); (6) promote + triage: `tools/new_challenge.py --domain <guess> --chal CHAL-001-<slug> --from-inbox challenges/_inbox/<slug>` then `tools/triage.py --given challenges/<domain>/CHAL-001-<slug>/given --chal-id CHAL-001 [--service H:P] [--url http://H:P] --out challenges/<domain>/CHAL-001-<slug>/surface.json` + `state_manager.py add-challenge --from <surface>`; (7) hand off CHAL-ID + surface path + route to Lead.

### 4.4 Stage 3 — Pull-all (`--pull-all`)

Stage 1 once, then Stage 2 serially per unregistered ID. Honors `--dry-run`, `--only CHAL-001,CHAL-002`, `--skip-registered` (default; `--force` overrides), `--max N` (Lead should batch large events, e.g. `--max 10`).

### 4.5 Artifact layout (per challenge)

Pre-triage staging: `challenges/_inbox/<slug>/`: `given/` (attachments, original names) · `statement.md` (sanitized) · `service.txt` (one endpoint line or empty) · `.extract.json` (slug/detail_url/hashes/pulled_at).
Promoted (canonical): `challenges/<domain>/<CHAL-XXX-slug>/`: everything above + `surface.json` (triage schema v1, incl. `domain`) · `recon/` · `profiles/` · `exploits/` · `transcripts/` · `flag.txt` · `FLAG-XXX.validated.md` · `writeup.md` (see challenge_prompt.md Layout).

### 4.6 What "parse" means (and does not mean)

Parse = visible DOM/text + anchor hrefs only. No JS exploitation, no API reverse-engineering beyond page links. JS-rendered pages: snapshot AFTER network idle, not raw-HTML regex. Empty/poisoned snapshot → §6.3 fallback, not a stealth jump.

### 4.7 Serial-per-profile rule (hard)

Exactly ONE extraction worker per browser profile (iron-loop slot `browser-extract`). Others use different profiles/ports or wait for unlock — concurrent nav in one profile corrupts pages, double-downloads, and looks bot-shaped.

---

## 5. Download handling

### 5.1 Mechanism

- **Playwright path:** `page.expect_download()` / download-event listener; move into `given/` under the ORIGINAL server filename (sanitized basename, no `../`).
- **agent-browser path:** honor `AGENT_BROWSER_DOWNLOAD_PATH`; after each click-download resolve the newest file there and move it.
- Always set per run so downloads never land in `~/Downloads`: `export AGENT_BROWSER_DOWNLOAD_PATH="$PWD/downloads/_staging"`

### 5.2 Integrity + dedup

After each file lands record `size` + `sha256` (dedup key). Same hash → keep one copy, note `duplicate_of` in `.extract.json`. Same name + different hash → keep both, suffix `.<short-hash>` (a changed attachment may mean a fixed challenge — never silently overwrite). Zero-byte/truncated → download failure (§6.2), not success.

### 5.3 Naming + safety

Strip query strings, `basename()` only, reject absolute paths and `..`. Any attachment type is fine (triage types it), but NEVER execute downloads during extraction (no `chmod +x`, no run). Record MIME + size in `.extract.json`.

---

## 6. Failure handling (bounded: diagnose → 1 retry → 1 alternate → blocked)

Framework rule: diagnosis → 1 corrected retry → 1 alternate method → `blocked` after 3 attempts, then continue unblocked work. Pause ONLY for hard gates (operator re-login).

### 6.1 Session expiry (login assertion fails)

Signal: login form / redirect-to-login / 401 / missing rows where `--check` previously passed. Do NOT retry nav, do NOT escalate stealth — immediately `tools/operator_ping.sh "CTF session expired — re-login in dedicated Chrome (port 9222)" loop`. Keep solving pulled challenges while it pings; after confirm, re-run `--check`, resume. Mark affected pulls `blocked(session)`.

### 6.2 Download failure (per file)

Fail 1 (timeout/0-byte/truncated): wait 5s, one corrected retry. Fail 2: one alternate method (swap agent-browser click-download ↔ Playwright download-event; or direct-GET the href in the SAME attached context — never `curl` without session). Fail 3: record `missing` in `.extract.json`, continue; challenge registers `registered(partial)` (statement-only challenges exist — Lead decides).

### 6.3 Parse failure (snapshot unusable)

Empty snapshot / JS-shell / bot verdict / missing fields after 2 strategies → (1) re-snapshot after network-idle + scroll; (2) alternate MCP (swap agent-browser ↔ Playwright) or raw-CDP `DOM.getDocument`; (3) save snapshot to `tasks/<id>/parse_fallback_snapshot.md` + `operator_ping.sh "<slug> needs manual readout" once`, register `registered(unparsed)`. Never invent fields.

### 6.4 Rate / WAF signal

Two consecutive `429` / block pages / CAPTCHAs → STOP immediately (no ladder-dodging). Mark remaining `blocked(rate)`; Lead re-plans smaller batches + delays. Rate is the IP/behavior lever — stealth rungs do not fix it.

---

## 7. state.json integration

### 7.1 Challenge entry (appended/updated by `--pull`)

```json
{"id": "CHAL-001", "slug": "web-101", "title": "Baby Web", "category": "web-ctf",
 "domain": "_inbox", "path": "challenges/_inbox/web-101",
 "points": 100, "service": null, "status": "registered",
 "signals": ["extracted via browser-ops"],
 "extract": {"detail_url": "/challenges/<id>", "files": 2, "pulled_at": null}}
```

After promote + triage + `add-challenge`, the entry is refreshed: `domain=<solve-domain>`, `path=challenges/<domain>/CHAL-001-<slug>`, `status=triaged`.

`status`: `registered` → (triage) `triaged` → downstream (`mapped`/`testing`/`validated`/`blocked`). Partials: `registered(partial)` (files missing), `registered(unparsed)` (parse fallback), `blocked(session|rate)`. Never store cookies, tokens, passwords, flags, or snapshot HTML.

### 7.2 Counters + concurrency

Bump `triage.total` on registration so `/status` reflects pending triage. Hold `_concurrency.active_tasks["browser-extract"]` as the serial slot (lock → dispatch → unlock → gate); a second dispatch while locked waits or takes another profile — never same-profile parallel.

### 7.3 Idempotency

`--pull` with `--skip-registered` (default) is a no-op unless `--force`. `--list` refreshes `challenges/_index.json` without touching registered dirs. Slug→CHAL-ID mapping is append-only.

---

## 8. opencode.json wiring

Add CDP attach to the existing Playwright MCP entry and register agent-browser as a second MCP server (illustrative — adapt versions):

```json
"mcp": {"playwright": {"type": "local", "command": ["npx", "@playwright/mcp@latest",
  "--caps", "core,vision,network", "--viewport-size", "1280x900",
  "--cdp-endpoint=http://localhost:9222"], "enabled": true},
 "agent-browser": {"type": "local", "command": ["agent-browser", "mcp"], "enabled": true}}
```

Notes: `--extension` variant (attach WITH the extension — best for SSO/2FA reuse) is the alternative if plain CDP attach loses extension context; keep whichever preserves the session and verify with `--check`. One-time setup: `npx skills add vercel-labs/agent-browser`. Stealth env only when escalating (§3): `AGENT_BROWSER_STEALTH=1` (or `--stealth`) + `AGENT_BROWSER_DOWNLOAD_PATH="$PWD/downloads/_staging"`. CloakBrowser pairing: `cloakhq/cloakbrowser cloakserve` (CDP :9222, docker) then `agent-browser connect 9222`.

---

## 9. Extraction worker dispatch template (1 challenge = 1 task)

Lead dispatches per challenge (serial per profile — see §4.7):

```
Task: browser-extract CHAL-XXX (slot: browser-extract, profile port 9222)
  Cap: 1 challenge, ≤15 min, ≤40 page actions. Stop: session-expiry | 2x 429/block | 3 fails (→ blocked).
  Artifacts: challenges/_inbox/<slug>/ → challenges/<domain>/CHAL-XXX-<slug>/ (+ tasks/browser-extract-CHAL-XXX.log)
  Steps: read skills/browser-ops/SKILL.md → --check → --pull CHAL-XXX →
    confirm given/ + statement.md + service.txt + state.json(registered) →
    new_challenge --from-inbox → tools/triage.py → surface.json → add-challenge →
    handoff (CHAL-ID, domain, category, route, confidence).
```

`--pull-all` runs are Lead-level batches, not worker-parallel: one worker owns
the profile slot for the whole batch (with `--max` to bound it).

---

## 10. Security

1. **Credentials never in repo/logs.** Operator types passwords/2FA; agent never sees, stores, echoes, or screenshots them. `--check` asserts session WITHOUT dumping cookies/headers; sanitize `statement.md`.
2. **Domain allowlist.** Navigate ONLY to `--base-url` host (+ Lead-approved same-origin attachment CDNs, logged per run). Off-allowlist redirect → stop pull, `blocked(redirect)`, ask Lead. No open-web crawling.
3. **Downloads are untrusted.** Never execute during extraction. Triage sweeps read-only (`file`/`strings`/`exiftool`); execution only in gated exploit sandboxes.
4. **Flags are local-only** (per `config/ctf_policy.json`). Never paste flag-shaped strings into chat/state/memory. `flag_format_hint` only.
5. **CDP stays local.** Never expose 9222 off-host, never tunnel, never commit profile contents; `--user-data-dir` lives outside the repo.
6. **Rate discipline is security.** 2×429/block = stop. Ladder-dodging or parallel profiles against the SAME account risks operator standing — Lead-gated only.

---

## 11. Verification checklist (M0 scaffold)

- [ ] `./setup_ctf.sh --browser --status` contract defined (§2; implementation M1).
- [ ] `python3 -m py_compile tools/browser_extract.py` passes; `--help` lists `--check/--list/--pull/--pull-all/--dry-run/--base-url/--state-file`.
- [ ] `python3 tools/skill_lint.py` shows 0 failures (covers `browser-ops`).
- [ ] No hardcoded platform URLs in the tool; `bash -n setup_ctf.sh` still passes.
- [ ] Line counts reported: this doc 300–450, tool 200–300.

Anything not yet executed against a live platform is marked UNTESTED and must
not be presented as validated. Technique-only: no invented target URLs.

---

## Appendix A — Command quickref (placeholders, not live targets)

```bash
# 1. Launch + verify (operator logs in between)
./setup_ctf.sh --browser --port 9222
curl -s http://localhost:9222/json/version
python3 tools/browser_extract.py --check --base-url "$PLATFORM_URL"

# 2. List + pull (dry-run first on new platforms)
python3 tools/browser_extract.py --list --base-url "$PLATFORM_URL" --dry-run
python3 tools/browser_extract.py --list --base-url "$PLATFORM_URL" \
  --out challenges/_index.json
python3 tools/browser_extract.py --pull CHAL-001 --base-url "$PLATFORM_URL"
python3 tools/browser_extract.py --pull-all --base-url "$PLATFORM_URL" --max 10

# 3. agent-browser attach + snapshot (inside worker, attached browser)
agent-browser connect 9222
agent-browser snapshot -i
export AGENT_BROWSER_DOWNLOAD_PATH="$PWD/downloads/_staging"

# 4. Session-expiry hard gate (never silent standby)
tools/operator_ping.sh \
  "CTF session expired — re-login in dedicated Chrome (port 9222)" loop
```

## Appendix B — Open questions (M1+, resolve against live platforms)

Per-platform list/detail selectors (unknown until first snapshot); `--extension` vs plain `--cdp-endpoint` for SSO persistence (verify with `--check`); attachment CDN allowlist entries (Lead-approved per event); `setup_ctf.sh --browser` implementation (§2 contract); Patchright/Camoufox/nodriver worker images (Dockerfile profiles).

---

*End of BROWSER_EXTRACTION_PLAN.md — scaffold UNTESTED. Validate against a
practice platform before any live event use.*
