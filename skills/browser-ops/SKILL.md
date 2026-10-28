---
name: browser-ops
description: Operator-Chrome CDP-attached challenge extraction — login reuse, list/parse, download-verify, state registration, triage handoff
category: infrastructure
infrastructure: operator-chrome-cdp
phase: pre-0
---
Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`; separate evidence from inference, preserve scope, validate each link, and label uncertainty.

# Browser-Ops Skill (Pre-Phase-0: Extract → Register → Triage → Hand off)

## Mental Model

Extraction is a **read-only pipeline riding a human session**, not a bot driving a login. The operator owns the login (dedicated Chrome profile, port 9222); the agent only borrows the already-authenticated context over CDP. Every failure therefore has exactly one of four shapes — expired session (human gate), failed download (retry + alternate), unparseable page (snapshot + manual), or rate verdict (stop, never dodge) — and the skill routes each without ever touching credentials. One profile means one navigator: parallel workers on the same profile corrupt each other's pages and look bot-shaped, so extraction holds a single iron-loop slot (`browser-extract`) and everything else waits or uses another profile. A challenge is done only when `given/` + `statement.md` + `service.txt` + `state.json(registered)` + `surface.json` all exist; anything less is `registered(partial|unparsed)` or `blocked`, never silently "done".

Core principles:
- Borrow, never log in: no credential fill, no 2FA handling, no session-dumping into logs.
- CAPTCHA = human gate, never an agent bypass: on any captcha/turnstile/CF challenge,
  STOP the batch and run `python3 tools/captcha_gate.py --url "$PLATFORM_URL"` —
  the operator solves MANUALLY in the dedicated window, the agent idles, then
  re-probes. Hammering the page deepens the block. No stealth rotation to dodge.
- `contexts()[0]`, never `new_page()` for auth: the fresh context is logged out and makes healthy sessions look expired.
- Baseline first: prove CDP + authenticated list render before any pull; no claim of "blocked" without a `--check`.
- One challenge per task, serial per profile: `--pull-all` is a Lead-level batch owned by one slot-holder, not worker-parallel.
- Verify downloads by bytes, not clicks: size + sha256 + hash-dedup decide success; a click with no bytes is a failure.
- Negative before label: a login-looking page is expiry until proven bot-shaped, and a bot-shaped page is rate until proven parseable — kill the lookalikes before escalating.

## Workflow

### Phase 1 — Baseline (attach + verify, read-only, ≤60s)

Goal: prove the borrowed session is live before touching any challenge.

1. Confirm the dedicated Chrome is listening (never launch against the default profile):
```bash
curl -s http://localhost:9222/json/version | head -c 500
```
2. Attach the agent layer (pick the one that preserves the session; verify, don't assume):
```bash
agent-browser connect 9222
agent-browser snapshot -i
export AGENT_BROWSER_DOWNLOAD_PATH="$PWD/downloads/_staging"
```
3. Run the deterministic pre-flight (same checks the tool enforces):
```bash
python3 tools/browser_extract.py --check --base-url "$PLATFORM_URL"
python3 tools/browser_extract.py --list --base-url "$PLATFORM_URL" --dry-run
```
4. Baseline: CDP version string, `contexts()[0]` page count, list-page marker (challenge rows or profile/logout element), download staging dir exists and is writable.
5. Operator login flow (human side, agent waits): operator opens the platform URL in the dedicated window, completes login/SSO/2FA, lands on challenges; agent re-runs `--check` only after the operator confirms.

`Reasoning Checkpoint`: baseline evidence (CDP ok + authenticated rows visible + staging writable) -> confidence (HIGH = proceed / LOW = gate, never pull blind) -> next (Phase 2 list-parse, or operator re-login gate).

### Phase 2 — Confirmation (list + parse, ≤40 page actions)

Goal: turn the rendered list into a stable challenge index with real parsed fields.

1. Snapshot the list page with refs and parse rows (title, platform category label, points, detail href, solved flag):
```bash
agent-browser snapshot -i
python3 tools/browser_extract.py --list --base-url "$PLATFORM_URL" --out challenges/_index.json
```
2. Confirm each parsed row against the visible text: title matches row text, points match the `NNN pts` badge, detail href resolves in the same attached context. Do NOT invent categories — use the platform label (map to the 14-domain router later in triage).
3. JS-rendered lists: wait for network idle + scroll once, then re-snapshot. Raw-HTML regex is not confirmation.
4. Record the `slug → CHAL-001…` mapping in `challenges/_index.json` (append-only; re-runs keep IDs stable).

`Reasoning Checkpoint`: confirmation evidence (index rows == visible rows, hrefs resolve) -> confidence (HIGH = pull / MEDIUM = re-snapshot once / LOW = parse-failure path) -> next (Phase 3 negatives, then gated pull).

### Phase 3 — Negative (rule out lookalikes, ≤15 page actions)

Goal: prove a bad-looking page is what you think before labeling it.

1. Login-form control: page shows login AND `--check` previously passed → re-run `--check` once. Still login = `session_expired` (operator gate §6.1 of plan), not a bot verdict.
2. Bot-vs-rate control: valid session (`--check` passes on list) but detail denied / `429` / CAPTCHA → `blocked(rate)`: STOP the run, run `tools/captcha_gate.py --url <detail>` for the human solve, smaller batches later (NO ladder dodge).
3. Bot-vs-parse control: snapshot empty but raw-CDP `DOM.getDocument` (or the OTHER MCP: swap agent-browser ↔ Playwright) shows content → parse-strategy failure (§6.3), not stealth escalation. Both empty + `--check` green → paragliding to L1 is allowed exactly once (Lead decision).
4. Download control: click fired but staging dir unchanged / 0 bytes → download failure (§6.2), never "no attachments". Re-click once, then alternate method, then `missing`.
5. Any control unresolved after the bounded attempts → mark `blocked` with the discriminated reason and continue with unblocked challenges.

`Reasoning Checkpoint`: negative evidence (which controls passed/failed) -> confidence (expiry vs rate vs parse vs download, exactly one label) -> next (gated pull iff session green, else the matching failure path).

### Phase 4 — Pull, gated (ONE challenge per task, ≤15 min, ≤40 actions)

Goal: exactly one `CHAL-XXX` from snapshot to registered + triaged. Never a second pull in the same task.

1. Take the iron-loop slot (`browser-extract` in `_concurrency.active_tasks`); if held, wait or use another profile — never parallelize the same profile.
2. Pull via the tool (serial, same attached context) — lands in PRE-TRIAGE staging (category unknown):
```bash
python3 tools/browser_extract.py --pull CHAL-001 --base-url "$PLATFORM_URL"
# → challenges/_inbox/<slug>/{given/,statement.md,service.txt,.extract.json}
```
3. Download-verify every attachment: file present in `challenges/_inbox/<slug>/given/`, size > 0, sha256 recorded in `.extract.json`, hash-dedup applied (same hash → `duplicate_of`; same name + new hash → keep both with `.<short-hash>` suffix).
4. Confirm `statement.md` (sanitized: flag-shaped text redacted, tokens redacted) + `service.txt` (one endpoint line or empty) + `state.json` entry `status=registered`, `domain=_inbox`.
5. Promote to the canonical domain tree, then triage in the same task (no handoff without it):
```bash
python3 tools/new_challenge.py --domain crypto --chal CHAL-001-vault --from-inbox challenges/_inbox/<slug>
python3 tools/triage.py --given challenges/crypto/CHAL-001-vault/given --chal-id CHAL-001 --out challenges/crypto/CHAL-001-vault/surface.json
python3 tools/state_manager.py add-challenge --from challenges/crypto/CHAL-001-vault/surface.json
```
(`--domain` = best guess from list-page category; triage `--domain` overrides if it disagrees — surface.json is authoritative, state re-registers the final path.)
6. Timer stops at 15 min regardless; on timeout mark `blocked(timeout)` with artifacts so far and release the slot.

`Reasoning Checkpoint`: pull evidence (given/ bytes + hashes + state entry + surface.json valid JSON) -> confidence (registered vs registered(partial|unparsed) vs blocked) -> next (Phase 5 handoff, never a second pull).

### Phase 5 — Validation-handoff (read-only verify, no new pulls)

Goal: package a re-checkable handoff so Lead/validator never re-navigates blind.

1. Re-list artifact dir: `ls -la challenges/crypto/CHAL-001-vault/ challenges/crypto/CHAL-001-vault/given/ | head -n 20`.
2. Re-validate JSON: `python3 -c "import json; d=json.load(open('challenges/crypto/CHAL-001-vault/surface.json')); print(d['domain'], d['category'], d['confidence'], d['route'])"`.
3. Confirm `state.json` shows the CHAL-ID as `triaged` with final `path` (or the partial/blocked variant with reason) and `triage.total` bumped.
4. Session re-verify triggers (re-baseline before any follow-up pull): service restart of Chrome, new profile dir, >20% row-count shift on re-list, 401/403/new-cookie observed.
5. Hand off: CHAL-ID, surface.json path, category + confidence, route + secondary route, recommended skill file, pull log path. Release the `browser-extract` slot.

`Reasoning Checkpoint`: validation evidence (artifacts re-listed + JSON re-parsed + state consistent) -> confidence (handoff clean vs needs re-pull) -> next (Lead dispatch to category skill; worker releases task).

## Tool Table (exact copy-paste commands)

| Purpose | Command |
|---|---|
| CDP liveness | `curl -s http://localhost:9222/json/version \| head -c 500` |
| agent-browser attach | `agent-browser connect 9222` |
| Reffed snapshot | `agent-browser snapshot -i` |
| Stealth run (escalation only) | `agent-browser --stealth snapshot -i` (or `AGENT_BROWSER_STEALTH=1`) |
| CloakBrowser serve | `cloakhq/cloakbrowser cloakserve` (CDP :9222, docker) |
| Skills install (once) | `npx skills add vercel-labs/agent-browser` |
| Download staging | `export AGENT_BROWSER_DOWNLOAD_PATH="$PWD/downloads/_staging"` |
| Pre-flight check | `python3 tools/browser_extract.py --check --base-url "$PLATFORM_URL"` |
| Dry-run list | `python3 tools/browser_extract.py --list --base-url "$PLATFORM_URL" --dry-run` |
| List + index | `python3 tools/browser_extract.py --list --base-url "$PLATFORM_URL" --out challenges/_index.json` |
| Pull one | `python3 tools/browser_extract.py --pull CHAL-001 --base-url "$PLATFORM_URL"` → `challenges/_inbox/<slug>/` |
| Pull dry-run | `python3 tools/browser_extract.py --pull CHAL-001 --base-url "$PLATFORM_URL" --dry-run` |
| Pull batch (Lead) | `python3 tools/browser_extract.py --pull-all --base-url "$PLATFORM_URL" --max 10` |
| Pull filtered | `python3 tools/browser_extract.py --pull-all --base-url "$PLATFORM_URL" --only CHAL-001,CHAL-002` |
| Promote to domain tree | `python3 tools/new_challenge.py --domain crypto --chal CHAL-001-vault --from-inbox challenges/_inbox/<slug>` |
| Triage hook | `python3 tools/triage.py --given challenges/crypto/CHAL-001-vault/given --chal-id CHAL-001 --out challenges/crypto/CHAL-001-vault/surface.json` |
| Triage + service | `python3 tools/triage.py --given challenges/crypto/CHAL-001-vault/given --chal-id CHAL-001 --service H:P --out challenges/crypto/CHAL-001-vault/surface.json` |
| Surface re-check | `python3 -c "import json; d=json.load(open('challenges/crypto/CHAL-001-vault/surface.json')); print(d['domain'], d['category'], d['confidence'], d['route'])"` |
| Session-expiry gate | `tools/operator_ping.sh "CTF session expired — re-login in dedicated Chrome (port 9222)" loop` |
| Manual-readout gate | `tools/operator_ping.sh "CHAL-001 needs manual field readout (title/category/points/files)" once` |
| Hash verify | `sha256sum challenges/crypto/CHAL-001-vault/given/*` |
| Setup verify | `./setup_ctf.sh --browser --status` |
| Clearance pre-flight | `python3 tools/session_check.py --url <target>` (0 only, else gate) |
| Tab hygiene | `python3 tools/btabs.py list|cleanup`; resolve tabs by URL, never pages[0] |
| Gated submit | `python3 tools/submit.py --chal CHAL-001 --flag "FLAG{...}" --detail-url <url>` (pace 10s, budget 5) |
| Answer candidates | `python3 tools/answer_forge.py --chal CHAL-002 --evidence k=v [--propose]` |
| Instance lifecycle | `python3 tools/instance.py --spawn --detail-url <u> --service-file <path>` / `--status` / `--close-dead` |
| Live doctrine | `docs/LIVE_OPS.md` (pacing, tabs, submits, vision-first — read before live ops) |

Env: set `PLATFORM_URL` (list-page URL, explicit per run — never defaulted) before pasting. Sources: `github.com/vercel-labs/agent-browser`, `github.com/Kaliiiiiiiiii-Vinyzu/patchright`. `playwright-stealth` is dead — not listed, do not use.

## Decision Tree

```text
--check green + rows visible ──→ --list → index → negatives pass ──→ --pull ONE → verify bytes → triage → handoff
--check shows login ──→ session_expired ──→ operator_ping(loop) ──→ re-check ──→ resume (NO stealth change)
--check green but detail denied/429/CAPTCHA ──→ blocked(rate) ──→ STOP, smaller batches later (NO ladder dodge)
snapshot empty, other-MCP/CDP has content ──→ parse-strategy fail ──→ retry + alternate + manual readout
snapshot empty everywhere, --check green ──→ L1 once (Lead) ──→ still empty ──→ blocked, move on
click fired, no bytes ──→ re-click once ──→ alternate method ──→ still none ──→ missing + registered(partial)
slot browser-extract held ──→ wait OR other profile/port ──→ NEVER same-profile parallel
```

## AI Automation Notes (script, timeouts, caps)

What to script (worker): `extract_once.sh` — `--check` → `--pull CHAL-XXX` → `ls given/` → `sha256sum` → `triage.py` → surface re-check → state grep. Single straight-line script, `set -euo pipefail`, 15-min `timeout`. Log everything to `tasks/browser-extract-CHAL-XXX.log`.
Timeouts/caps (hard): Phase 1 ≤60s; Phase 2 ≤40 page actions; Phase 3 ≤15 actions; Phase 4 exactly 1 challenge / ≤15 min / ≤40 actions; per-file download 30s then retry path. Stop conditions: login form after green check, 2× `429`/block, 3 failed attempts on one artifact → `blocked`, release slot, continue unblocked work.
Baseline/negative/validation discipline: no pull without green `--check` (baseline); no `blocked` label without the discriminating control (negative); no handoff without re-list + JSON re-parse + state grep (validation).
Dispatch template (1 challenge = 1 task): `Task browser-extract CHAL-XXX [slot=browser-extract, port 9222, cap 15min/40 actions, stop on expiry|2x429|3 fails] → SKILL.md → --check → --pull → verify (size+sha256) → state(registered) → triage.py → surface.json → handoff`. `--pull-all` is Lead-batched, single slot-holder, `--max` bounded.
Technique-only: placeholders `$PLATFORM_URL`, `CHAL-001`, `H:P` in all commands/state; never commit real platform hostnames, session material, or flag-shaped strings. Raw snapshots stay in `tasks/` logs, never in `state.json`.

## References (repos / docs only, no target URLs)

- `github.com/vercel-labs/agent-browser` (README: `snapshot -i` refs, `connect <cdp-port>`, MCP server, `--stealth` / `AGENT_BROWSER_STEALTH`, skills install)
- `github.com/Kaliiiiiiiiii-Vinyzu/patchright` (README: Playwright drop-in, `channel="chrome"`, headed guidance)
- Playwright MCP `--cdp-endpoint=` / `--extension` attach docs (session reuse)
- `docs/BROWSER_EXTRACTION_PLAN.md` (ladder L0–L3, pipeline stages, failure §6, state §7, wiring §8)
- `tools/browser_extract.py --help` (command contract) · `tools/operator_ping.sh` (hard gates) · `skills/_shared/SKILL_CONTRACT.md` (5-phase contract)
