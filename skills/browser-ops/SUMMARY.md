# browser-ops SUMMARY (quickref — CDP-attached extraction)

Borrow, never log in: operator owns dedicated Chrome (`--user-data-dir`, :9222);
agent uses `browser.contexts()[0]`, NEVER `new_page()`.
Baseline: `curl -s http://localhost:9222/json/version` + `--check` green + rows
  visible before ANY pull. `--check` login-form = expiry (gate, not stealth).
Attach: `agent-browser connect 9222` → `agent-browser snapshot -i` (`--stealth`
  or `AGENT_BROWSER_STEALTH=1` only on L1+ escalation, Lead-gated).
Stage: `export AGENT_BROWSER_DOWNLOAD_PATH="$PWD/downloads/_staging"`.
List: `--list --base-url "$PLATFORM_URL" --out challenges/_index.json`
  (refs `@eN`; JS pages: network-idle + scroll + re-snapshot; never invent fields).
Negatives: green-check-then-login = `session_expired`; green-but-denied/429 =
  `blocked(rate)` STOP (no ladder dodge); empty-snapshot-but-CDP-has-content =
  parse-strategy fail (swap MCP → manual readout gate).
Pull ONE per task (slot `browser-extract`, ≤15min, ≤40 actions):
  `--pull CHAL-001 --base-url "$PLATFORM_URL"` (serial; never same-profile parallel).
Verify bytes not clicks: `ls given/` + `sha256sum` + size>0; same-hash =
  `duplicate_of`; same-name-new-hash = keep both `.<short-hash>`; 0-byte =
  retry → alternate → `missing` + `registered(partial)`.
Register: `given/` + `statement.md` (sanitized) + `service.txt` + state.json
  `registered` → `tools/triage.py --given ... --chal-id CHAL-001
  --out .../surface.json` → re-parse surface JSON → handoff.
Gates: expiry → `operator_ping.sh "...re-login...(port 9222)" loop` (keep
  solving pulled work); unparseable → `... "manual field readout" once`.
Batch (Lead only): `--pull-all --max 10` single slot-holder; `--only` filter;
  `--skip-registered` default (`--force` overrides); `--dry-run` first.
Tree: check-green→list→negatives→pull→verify→triage→handoff; any 2x429/STOP;
  3 fails on one artifact → `blocked`, release slot, continue.
Ladder: L0 operator-Chrome default → L1 Patchright (`channel="chrome"` headed)
  → L2 Camoufox → L3 nodriver/zendriver; `playwright-stealth` DEAD, never use.
Cloak: `cloakhq/cloakbrowser cloakserve` (:9222) + `agent-browser connect 9222`.
Setup: `npx skills add vercel-labs/agent-browser`; wiring §8 of plan doc.
Caps: P1 ≤60s, P2 ≤40 actions, P3 ≤15, P4 1 chal/15min/40, file-dl 30s.
Secrets: `$PLATFORM_URL`/`CHAL-XXX` placeholders only; no creds/cookies/flags
  in repo, logs, state, or chat. Snapshots → `tasks/` logs only.
Refs: vercel-labs/agent-browser, Kaliiiiiiiiii-Vinyzu/patchright,
  docs/BROWSER_EXTRACTION_PLAN.md, tools/browser_extract.py --help.
