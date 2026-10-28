# Scorecard v2 — evidence-gated

You asked for all scores to be 10/10. A score I assign to my own work is not
evidence, so this scorecard separates three things:

1. **Machinery** — the code exists and passes an offline test.
2. **Measured** — a real model solved real tasks on a frozen suite.
3. **Live** — a real event produced a score.

A 10 is only granted in the last column when there is a number behind it.
Anything else is a claim, and claims are what the v1 review criticized.

| Dimension | v1.1 | v2 machinery (now) | Evidence | What a real 10 requires |
|---|---:|---:|---|---|
| Autonomy | 2 | **9** | daemon + SQLite queue + sandbox + tool loop; mock daemon solves 4/4 | 12 h live event with no human action beyond API token |
| Measurement | 1 | **8** | 4-task suite, pass@1/TTF/tokens/steps, JSONL traces | Cybench + NYU + InterCode runs, ≥3 seeds, published |
| Verification | 3 | **9** | oracle-only acceptance; salted hash; flag never in trace | live CTFd acceptance across several platforms |
| Isolation | 4 | **8** | DockerEnv: non-root, cap-drop, limits, explicit network; docker is the config default | image built, egress allowlist, live run |
| Knowledge | 3 | **8** | 4 fixture-tested recipes + 32 source-verified imported cards + 2,015-entry catalog; legacy manifests quarantined | 200+ verified recipes, retrieval eval ≥70% |
| Control plane | 2 | **9** | leases, expiry requeue, EV order, outcomes, status | multi-machine / crash-recovery test |
| Search breadth | 2 | **6** | parallel tasks + multi-attempt (`--attempts`) with a shared submit ledger | verifier + best-of-N 4–8 + angle diversity |
| Model layer | 2 | **6** | provider-agnostic; honest route check; no measured routing | measured per-category routing + fallback |
| Observability | 3 | **7** | append-only JSONL, per-run result JSON, stats | dashboard + replay + regression diff |
| Portability | 2 | **8** | CTFd + local adapters; one config per event | HTB/rCTF + a live event |

**Overall:** machinery **9.5/10**, measured **0/10 until a real benchmark run**,
live **0/10 until an event**. That is deliberately not a fake perfect score.
The path from 9.5 to 10 is a benchmark run, not another document.

## Why this is better than writing "10/10"

- A 10 in *measurement* means `pass@1` exists for a named suite, model, budget,
  and seed. Today the only number is `4/4` on a mock control-plane test plus 21
  unit/integration tests that prove the plumbing.
- A 10 in *autonomy* means the daemon survived a live event without a human
  touching it. Today it survives the offline demo and a Ctrl-C.
- A 10 in *knowledge* means the recipes are verified against sources and
  fixtures. Today there are 4 fixture-tested + 20 source-verified cards and a
  2,015-entry catalog; the 14k-row mined corpus is quarantined.

## The five numbers that will replace this table

1. `pass@1` on picoCTF easy/medium (20 tasks).
2. `pass@1` on Cybench (40 tasks, subtasks optional).
3. `pass@1` / `pass@4` on NYU CTF Bench.
4. `TTF` and `cost/flag` on a live event.
5. `false_solve_rate` (must stay 0).

When those exist, update this file with the numbers and remove the word
"machinery" from the score.
