---
name: sequential-thinking
description: Structured multi-step reasoning via Sequential Thinking MCP for flag-path synthesis
category: infrastructure
phase: all
---
Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`; separate evidence from inference, preserve scope, validate each link, and label uncertainty.

# SEQUENTIAL-THINKING — Structured Reasoning (all phases)

## Mental Model
Hard challenges die in flat chat: plans sprawl, alternatives vanish, confidence
is never tracked. Sequential thinking forces explicit thought numbered steps
with revision — the Lead's scratchpad for chains, exploit plans, and triage.

## Workflow

### Phase 1 — Baseline (state the problem in one block)
Write: goal, known facts (with file refs), unknowns, constraints (timeouts, scope).

**Reasoning Checkpoint:** problem stated → proceed.

### Phase 2 — Confirmation (decompose before solving)
Break into numbered thoughts: each thought = one claim + evidence or one next
action. Mark dependencies (T3 needs T1's leak value).

**Reasoning Checkpoint:** decomposition covers the goal → proceed.

### Phase 3 — Negative (kill branches early)
For each branch list the falsifier: what observation would kill it, and the
cheapest test. Drop branches whose test costs more than their expected value.

**Reasoning Checkpoint:** surviving branches only → proceed.

### Phase 4 — Exploit (gated: ONE reasoning chain per task)
Run the chain via the Sequential Thinking MCP (`sequentialthinking` tool):
thought → revision → conclusion. Cap at 12 thoughts; spill longer chains to
`artifacts/think-NNN.md` and continue from summary.

**Reasoning Checkpoint:** conclusion actionable → dispatch Worker.

### Phase 5 — Validation-handoff
Handoff: conclusion, confidence (HIGH/MEDIUM/LOW), open questions, the exact
Worker task it justifies.

**Reasoning Checkpoint:** handoff typed → done.

## Tool Table

| Purpose | Command |
|---|---|
| MCP reasoning | Sequential Thinking MCP `sequentialthinking` tool |
| Long chains | spill to `artifacts/think-NNN.md`, continue from 10-line summary |
| Chain synthesis | `skills/chaining-flagpath/SKILL.md` (Lead-only consumer) |

## Decision Tree
```
single-step task? → skip this skill, just do it
multi-step / uncertain? → think in numbered thoughts
stuck twice? → fresh chain (never extend a dead chain)
```

## AI Automation Notes
- `/think` command preloads this skill. Lead-only by convention; Workers use
  it only when the task explicitly says so (token cost).
- Every thought ends with either evidence or an action — never pure rumination.
