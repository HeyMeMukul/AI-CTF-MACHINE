---
name: chaining-flagpath
description: Lead-only multi-step flag-path synthesis from primitives across targets (M9 equivalent)
category: synthesis
phase: analysis
---
Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`; separate evidence from inference, preserve scope, validate each link, and label uncertainty.

# CHAINING-FLAGPATH — Multi-Step Flag Paths (Lead ONLY)

## Mental Model
Single bugs rarely equal flags. Flag paths chain primitives: **Primitive → Amplifier → Impact**.
A LOW info-leak + a MEDIUM write = HIGH flag capture. Like bug-bounty M9, this is Lead-only: only the
Lead sees the full inventory across profiles. Workers report primitives; Lead synthesizes paths.

## Workflow

### Phase 1 — Baseline (inventory all primitives)
Gather from every `CP-XXX.profile.yaml`: leaks (addresses, oracles, error verbosity), writes (fmt,
overflow, SQL write, file write), auth gaps (IDOR, weak JWT, debug endpoints), crypto misuses
(nonce reuse, ECB, small-e). Write `CHAIN-INVENTORY.md` — one line per primitive with
(confidence, chal, location).

**Reasoning Checkpoint:** inventory covers all profiles → else dispatch missing analysis first.

### Phase 2 — Confirmation (each primitive re-verified)
For every candidate primitive, confirm the Worker evidence exists (EXP-XXX or profile section).
Drop anything with only a claim and no baseline diff.

**Reasoning Checkpoint:** only evidenced primitives survive → rest to `Deferred`.

### Phase 3 — Negative (kill impossible chains)
- ASLR on + no leak → no direct-ret chain (needs leak-first path).
- Full RELRO → no GOT-overwrite chain (needs FSOP/IO path).
- Stateless oracle + rate limit → no 128-query-per-byte oracle chain (needs ≤10-query path).
- Wrong service/container → cross-target chains forbidden unless shared backend proven.

**Reasoning Checkpoint:** impossible chains removed with reasons → feasible set remains.

### Phase 4 — Exploit (gated: construct ONE flag path per task)
Build forward (primitive → what does it unlock?) and backward (flag location → what must be true?).
Score: `priority = realism(1-5) × reach(1-5) × compounding(1-5)`; `≥50` outranks single-bug paths.
Emit `FLAGPATH-NNN.hypothesis.md`: steps, per-step primitive ref, per-step Worker task, stop conditions.
ONE path per exploit task — never bundle two paths.

**Reasoning Checkpoint:** path scored ≥50 or best-available → dispatch step 1 → else hold as gadget.

### Phase 5 — Validation-handoff
Handoff per step: expected intermediate proof (leak value shape, file content, session state) so
validators confirm progress, not just the final flag.

**Reasoning Checkpoint:** step proofs defined → dispatch → merge on return.

## Gadget Catalog (cross-domain)
- Leaks: fmt-%p, GOT-dump, error-verbosity, timing-oracle, padding-oracle, DNS-exfil.
- Writes: fmt-%hn, overflow-RIP, SQL-UPDATE, file-upload, storage-slot (EVM), prototype-pollution.
- Amplifiers: ret2plt-loop (re-leak), anvil-fork (replay), Collaborator (blind→visible), unsortedbin (heap→libc).
- Impacts: `cat /flag*`, `forge` win-condition, DB-dump, prompt-exfil, container-escape(note: scope!).

## Scoring Table

| Axis | 1 | 3 | 5 |
|---|---|---|---|
| Realism | needs perfect heap layout | needs one leak | works on first try |
| Reach | same-process only | cross-request | cross-target/backend |
| Compounding | single bug | 2 primitives | 3+ primitives, each verified |

`priority = realism × reach × compounding` (max 125). Ship path if ≥50, else hold best as gadget.
Dispatch ONE path per exploit task: `tasks/task-NNN-exploit-<chal>-<pathNNN>.md`.

## AI Automation Notes
- `chain_automation.py` port (M1): builds inventory from profiles, proposes ranked paths, Lead approves.
- Hold LOWs as gadgets — never report/validate a lone LOW; only as chain steps.
