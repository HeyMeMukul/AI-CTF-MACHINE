---
name: report-writeup
description: Flag writeup generation from validated artifacts (Lead only, Phase 5)
category: reporting
phase: writeup
---
Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`; separate evidence from inference, preserve scope, validate each link, and label uncertainty.

# REPORT-WRITEUP — CTF Writeups (Lead ONLY, Phase 5)

## Mental Model
A writeup reproduces the flag from scratch. If a reader cannot re-run it, it is not done.
Writeups are built ONLY from `FLAG-XXX.validated.md` + `EXP-XXX.confirmed.md` + `solve.py` —
never from memory, never from unvalidated attempts.

## Workflow

### Phase 1 — Baseline (collect validated inputs)
Gather: flag.txt (existence only — copy value into writeup file, never chat), solve.py,
transcript, profile refs, service fingerprint. Confirm validation artifact exists.

**Reasoning Checkpoint:** validated inputs present → else do NOT write (dispatch validation).

### Phase 2 — Confirmation (re-run check)
Re-run `solve.py` mentally against the transcript: every command accounted for, outputs match.
Note runtime, tool versions, and any service state required (container started? file downloaded?).

**Reasoning Checkpoint:** reproduction path coherent → draft → else mark gaps.

### Phase 3 — Negative (strip the unproven)
Remove: failed attempts (one line in "Dead ends" max each), unverified claims, tool output dumps
(link `artifacts/` instead), full flags in chat-visible summaries (length only).

**Reasoning Checkpoint:** no unproven claims remain → finalize.

### Phase 4 — Exploit (gated: write ONE writeup per challenge)
Template `writeups/CHAL-XXX-slug.md`:
```markdown
# CHAL-XXX — title (category, points)
Flag: `FLAG{...}` (file only; chat summary says "captured, N chars")
## Recon (3 lines: what it was, key signals)
## Vulnerability (root cause, 5 lines)
## Exploit (numbered re-runnable steps + solve.py ref)
## Dead ends (1 line each, max 3)
## Lessons (reusable pattern for knowledge/)
```

**Reasoning Checkpoint:** template complete → lint (no pasted 500-line dumps).

### Phase 5 — Validation-handoff
Handoff: writeup path, flag validated (yes/no), solve.py re-runnable (yes/no), pattern worth
ingesting to `knowledge/` (technique-only, flags stripped).

**Reasoning Checkpoint:** state.json `writeups.written++` → done.

## Tool Table
| Action | Command |
|---|---|
| Generate skeleton | `python3 tools/writeup_generator.py --chal CHAL-001` (M1) |
| Verify re-runnable | `timeout 120 python3 challenges/<domain>/CHAL-001/exploits/solve.py` (fresh container) |
| Ingest pattern | `python3 tools/knowledge_ingest.py --from writeups/CHAL-001.md --strip-flags` (M1) |

## AI Automation Notes
- HTB "Attack of the Agents" finding: auto-writeups from tool outputs + reasoning work well — keep the
  Lead in the loop for root-cause accuracy.
- Writeups are LOCAL files; never push flags upstream. Knowledge ingest strips flags mechanically.
