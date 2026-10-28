# PHASE_ARCHITECTURE.md — evidence-led CTF solve lifecycle

```text
Phase 0 TRIAGE    → inventory + bounded quick wins → surface.json (evidence, confidence, routes, unknowns)
Phase 1 RECON     → in-scope observations → expanded surface + useful negatives
Phase 2 ANALYSIS  → ≤3 ranked, falsifiable hypotheses → profile + priority
Phase 3 EXPLOIT   → one hypothesis/task → minimal reproducer + typed result
Phase 4 VALIDATE  → clean rerun + challenge-specific success oracle → validated answer artifact
Phase 5 WRITEUP   → Lead-only account of validated evidence + reusable technique-only lesson
```

The phases are a control flow, not a requirement to run every expensive phase. A strong static signal may skip broad recon; an offline puzzle may combine triage and analysis. Record why a phase was skipped. Never label a candidate as solved just because it matches a generic regex.

## Workspace layout

```text
challenges/_inbox/<slug>/                 # browser pulls before classification
challenges/<domain>/<CHAL-XXX-slug>/       # domain chosen from evidence
  given/                                   # immutable originals
  statement.md service.txt surface.json
  recon/ profiles/ exploits/ transcripts/
  exploits/solve.py + EXP-XXX.{confirmed,negative,partial}.md
  flag.txt                                 # local-only validated answer, if applicable
  FLAG-XXX.validated.md writeup.md
```

## Data flow and ownership
```text
start.sh (event-local init) → state.json + operator browser + MCP health
→ register/import challenge → worker triage + autosolve → Lead reviews evidence
→ worker recon/analysis → Lead selects one falsifiable hypothesis
→ worker exploit → Lead quality-gates artifact → worker clean validation
→ Lead records validated status/writeup; submit only at operator hard gate
```

- Lead owns `state.json`, shared aggregates, task dispatch/review, validation decision, flag-path synthesis, and writeups.
- Worker owns tactical execution and unique artifacts inside the assigned scope.
- Exactly one writer updates shared state at a time. Do not parallelize the same live service, browser profile, state file, or final validation.
- Failed command/tool, service-down, malformed input, and genuine negative are distinct outcomes. Preserve each as evidence; do not conflate them.
- State changes must reflect artifact-backed observations. A flag-shaped string or syntax-only regex match is not acceptance evidence.
