# HARDENING — Hard-Challenge Operations (retry / escalation / decontamination)

How this framework attacks challenges rated hard/insane instead of dying on them.

## 1. Retry budget (per hypothesis, HARD rule)

| Attempt | Action |
|---|---|
| 1 | Primary method from skill (exact commands, version-pinned). |
| 2 | Corrected retry: fix the ONE diagnosed fault (syntax/offset/endianness), bounded backoff. |
| 3 | Alternate method: different technique class (e.g. fmt-leak → GOT-leak; Wiener → Coppersmith). |
| 4+ | FORBIDDEN on same hypothesis. Mark `blocked`, continue siblings, or escalate. |

`_settings.max_retries_per_hypothesis = 3` (state.json). `stall_detector.py` S6 enforces.

## 2. Escalation matrix (Lead decides, Worker never self-escalates)

```
2 fails same hypothesis → specialist router (/pwn /crypto /rev /web /forensics /blockchain /mobile ...)
specialist fails → chaining-flagpath (Lead-only: reframe as multi-step path)
path fails → fresh eyes (new Worker, task-tree summary only, NEVER full dead transcript)
fresh fails → time-box spike (15min, insane tier) → operator gate (manual hint? skip challenge?)
```

Never resume a dead thread: new Worker gets summary, not 200KB of failure (S4 rule).

## 3. Stall response (stall_detector.py, any 2+ of 6 signals)

- S5 give-up → re-plan with fresh Worker + new hypothesis.
- S2 syntax-error ×3 → 1 corrected retry, then alternate method.
- S1 repeat-cmd ×3 → escalate-specialist immediately.
- S3/S4/S6 → alternate-method once, then `blocked` + continue other challenges.

Run the detector in the quality gate after every EXP-negative result.

## 4. Decontamination (anti-soliloquy / anti-leak)

- `thought → single action → wait observation`. Multi-observation emits are rejected by task_validator (M1).
- Every answer claim must be supported by REAL tool output and a clean reproduction or explicit challenge oracle. A flag-shaped regex only checks syntax; it does not prove correctness. Use the challenge-stated format, and provide a challenge-specific regex to `flag_checker.py` when needed. Exact-answer challenges require their own documented validator.
- Live evals run no-websearch mode (CTFusion lesson: web search inflates scores 2.4×). Train with search, measure without.
- Knowledge ingest strips flags mechanically; eval-source writeups are excluded from priors.

## 5. Time tiers (global; skills carry per-domain numbers)

easy ≤15min → medium ≤45min → hard ≤3h → insane 15min-spike → escalate-or-skip.
A challenge consuming 2× its tier with zero new evidence is `blocked` by definition.

## 6. Session & environment hardness

- Pwn/web: persistent `sessions/` (conn/dbg) — never one-shot loops for interactive services.
- Validate in FRESH containers; exploit env is guilty until re-proven.
- Browser: serial-per-profile (one attach at a time), session-expiry → `operator_ping.sh` re-login gate, never credential-replay.
- Tool versions snapshotted per session (`tool_versions.txt`); drift guards in every skill re-check `--help` on-box.
