# LIVE_OPS — Live-operation doctrine (written in burns, not theory)

Every rule below cost a failed submit, a tripped Cloudflare, or a lost hour
during the first live campaign (12 challenges, playctf.in, Oct 2026).

## 1. Pacing (you WILL get gated if you burst)
- Minimum **8–10s between any two platform actions** (nav, submit, pull).
  `submit.py` enforces `--pace` (default 10). Never loop submits without sleeps.
- Max **5 submits per challenge** without NEW evidence (`answer_forge` refuses the 6th).
- Never resubmit a rejected candidate (`submit.py` refuses duplicates).
- Back-to-back 429/CF = STOP the batch, wait 10 min, single-probe to resume.

## 2. Clearance pre-flight (no blind actions)
- Before ANY platform op: `session_check.py --url <target>` (exit 0 only).
- Challenged (exit 2) → `operator_ping.sh` human solve → re-check → proceed.
  Hammering a challenge page NEVER clears it; it deepens the block.
- Turnstile freshness: solve → submit within SECONDS. Tokens expire; a stale
  token fails the whole form. `submit.py` abbsort on unsolved widgets.
- Refill cleared fields: failed submits wipe passwords — always re-fill all fields.

## 3. Tab discipline (wrong-tab bugs burned 3 scripts)
- NEVER `pages[0]` blindly. Resolve tabs by URL substring every time.
- `btabs.py list` before, `btabs.py cleanup` after. Close dead/404/blank solve tabs.
- One profile = one operator flow at a time (serial rule stands).

## 4. Submit discipline
- ONLY via `submit.py` (verdict parsing + ledger + pacing + budget).
- Every submit lands in `state.json _submissions` with verdict.
- Answer-style challenges go through `answer_forge.py` FIRST:
  evidence → ranked candidates → submit top-1 → record → stop at budget.
- NEVER invent hex/random suffixes. `{hex8}` slots stay empty until mined.

## 5. Format intelligence (the 002/004/009 lesson)
- After EVERY solve, mine the flag SHAPE into `answer_forge` evidence
  (e.g. `tark_suffix=hex8`). Shapes predict future answers; guesses don't.
- Check Details/hints + forum BEFORE format-guessing. Two failed formats
  with no new evidence = blocked-pending-insight, not a third guess.
- Placeholder text (`flag{...}`) confirms WRAPPING only, never content.

## 6. Vision-first (the Read-tool lesson)
- Images (screenshots, PNGs, QR, captchas-context) get VIEWED via the Read
  tool FIRST — pixel forensics (zsteg/exif/diff) only after eyes fail.
- Two similar images → view both, THEN diff regions, THEN zoom crops.

## 7. Instance lifecycle
- `instance.py --spawn` (writes service.txt) → `--status` (clearance per tab) →
  work → `--close-dead`. Track expiry ("Expires in Nm" on detail page).
- Empty artifact from a live instance (HTTP 200, 0 bytes) = platform-side:
  record EXP.partial, respawn ONCE, then blocked (do not poll for hours).
- Reloads can kill clearance: prefer in-tab fetch over reload; re-check after.

## 8. Pull-time capture
- `browser_extract.py` writes the **Challenge Question** prominently in
  statement.md (not buried under nav junk) — triage reads it for file-less
  classification. Verify the question line after every pull.

## 9. Live-fire loop (how this doc grows)
bench → operate → every surprise becomes a tool/rule → bench again.
A gap you hit twice is a framework bug, not bad luck.
