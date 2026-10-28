# Blueprint v2 — from cockpit to contender

**Purpose:** a concrete target architecture and 90-day plan for turning the current CTF framework into a system that can be measured against Cybench / NYU CTF / InterCode-CTF and hold its own in live events.

**Design stance:** keep the domain knowledge and the evidence discipline. Replace the control plane, the execution substrate, the verification layer, the knowledge pipeline, and the measurement layer.

---

## 0. Objective and non-goals

### Objective

> Maximize **expected event score** and **benchmark pass@1** under fixed wall-clock and cost budgets, with a reproducible, auditable process.

Every claim about the system must be backed by a number produced by the harness in §4. "World's best" means: published, reproducible results on at least three public benchmarks, a top-tier live-event placement, and a cost/flag curve that improves release over release.

### Non-goals

- Solving literally every challenge. The tail is unbounded; optimize the distribution.
- Replacing human judgment on scope, event rules, or platform Terms of Service.
- More prose. The repo already has enough doctrine; v2 should add *machinery*.
- A monolith. The core stays small; domains are plug-ins.

---

## 1. Principles

1. **Measure before optimize.** No feature lands without a before/after on the frozen suite.
2. **The environment is the interface.** A challenge is a container with `reset/exec/get/put` and an oracle, not a paragraph.
3. **Search beats one-shot.** Best-of-N, beam over hypotheses, fresh-eyes restarts. One trajectory is a coin flip.
4. **Verification is a first-class role.** A separate verifier checks every claim against a tool-call ID or an oracle verdict.
5. **Knowledge is executable and provenance-tracked.** A recipe without a fixture and a source is a rumor.
6. **Isolation by default.** Untrusted binaries, model-written exploits, and downloaded files never touch the host.
7. **Economy.** Track tokens, seconds, and tool calls per flag; rank work by expected value, not by points alone.
8. **One source of truth.** Append-only event log; state and paperwork are projections.
9. **Human gates only where the platform requires them.** CAPTCHA/login/ToS: yes. Every flag: no, if the event permits API submission.
10. **Small core, pluggable domains.** Adding a category should be a tool pack + a recipe set, not a fork.

---

## 2. Reference architecture

```text
┌────────────────────────────────────────────────────────────────────────────┐
│                             EVENT ADAPTERS                                 │
│  CTFd API · HTB · rCTF · pwn.college · generic HTTP · local benchmark      │
│  discover tasks · spawn instances · submit flags · read scoreboard/rules   │
└───────────────────────────────┬────────────────────────────────────────────┘
                                │ Task + Oracle
┌───────────────────────────────▼────────────────────────────────────────────┐
│                              SCHEDULER                                     │
│  EV ranking · deadline/decay · rate limits · parallel slots · preemption    │
│  durable queue (SQLite/Postgres) · idempotent task states                  │
└───────────────┬───────────────────────────────────┬────────────────────────┘
                │                                   │
┌───────────────▼───────────────┐   ┌───────────────▼────────────────────────┐
│         SOLVER POOL           │   │            TOOL GATEWAY                │
│  Planner (frontier)           │   │  typed tools · timeouts · output caps  │
│  Executor (coder)             │◄──┤  artifact spill · permissions          │
│  Verifier (judge)             │   │  domain packs: pwn/rev/crypto/web/...  │
│  Specialist (per category)    │   └───────────────┬────────────────────────┘
│  Toolsmith (writes reusable   │                   │
│  scripts)                     │   ┌───────────────▼────────────────────────┐
└───────────────┬───────────────┘   │            SANDBOX RUNTIME             │
                │                   │  Docker/Firecracker · non-root         │
┌───────────────▼───────────────┐   │  read-only rootfs · seccomp · cgroups  │
│          BLACKBOARD           │   │  egress allowlist · snapshots          │
│  events.jsonl · artifacts/    │   └────────────────────────────────────────┘
│  hypothesis DAG · task state  │
└───────────────┬───────────────┘
                │
┌───────────────▼───────────────┐   ┌────────────────────────────────────────┐
│           KNOWLEDGE           │   │            OBSERVABILITY               │
│  recipes/ (YAML + fixtures)   │   │  trace viewer · metrics · replay       │
│  casebooks/ (long, on demand) │   │  cost/flag · solve rate · regressions  │
│  index/ (signals + embeddings)│   └────────────────────────────────────────┘
└───────────────────────────────┘
```

**Rule:** no component talks to a challenge directly. Everything goes through the tool gateway and the sandbox. This is what makes traces replayable and permissions enforceable.

---

## 3. Core interfaces

### 3.1 Task, environment, oracle

```python
from dataclasses import dataclass, field
from typing import Literal, Protocol

@dataclass(frozen=True)
class Task:
    id: str
    source: str                  # "cybench:...", "picoctf-2024:...", "ctfd:1234"
    category: str                # pwn/rev/crypto/web/forensics/stego/misc/osint/...
    difficulty: str              # easy/medium/hard/insane/unknown
    files: tuple[str, ...] = ()
    connection: str | None = None
    flag_format: str | None = None   # None = unknown; never assume
    points: int = 0
    time_limit_s: int = 1800
    metadata: dict = field(default_factory=dict)

@dataclass
class ExecResult:
    exit: int
    stdout: str
    stderr: str
    duration_ms: int
    truncated: bool = False
    artifacts: tuple[str, ...] = ()

class Env(Protocol):
    def reset(self) -> None: ...
    def exec(self, cmd: str, *, timeout_s: int = 60,
             stdin: str | None = None) -> ExecResult: ...
    def put(self, local_path: str, remote_path: str) -> None: ...
    def get(self, remote_path: str) -> bytes: ...
    def snapshot(self) -> str: ...
    def close(self) -> None: ...

@dataclass
class Verdict:
    status: Literal["accepted", "rejected", "unknown"]
    source: str                  # "local-sha256", "ctfd-api", "custom-validator"
    detail: str = ""

class Oracle(Protocol):
    def check(self, candidate: str) -> Verdict: ...

class LocalFlagOracle:
    """Offline benchmarks: compare a salted hash, never store the flag in the task."""
    def __init__(self, expected_sha256: str, salt: str = ""):
        self.expected = expected_sha256
        self.salt = salt
    def check(self, candidate: str) -> Verdict:
        import hashlib
        got = hashlib.sha256((self.salt + candidate.strip()).encode()).hexdigest()
        return Verdict("accepted" if got == self.expected else "rejected", "local-sha256")
```

**Migration note:** this replaces `flag_checker.py` as a *proof*. Keep the regex checker as a cheap pre-filter that catches typos before an API submit.

### 3.2 Trace event

Append-only JSONL, one line per observable event. This is the source of truth; `state.json` is a projection.

```json
{"ts":"2026-10-20T10:00:00Z","run":"r-7f3a","task":"CHAL-014","actor":"executor",
 "type":"tool_call","tool":"bash","cmd_sha":"9c1e...","cmd":"checksec --file=./vuln",
 "exit":0,"ms":184,"tokens_in":812,"tokens_out":96,"artifact":"artifacts/CHAL-014/001.txt"}
```

Why JSONL:
- replayable (`eval/replay.py --run r-7f3a`),
- cheap to append under concurrency,
- directly minable for SFT data and failure taxonomy,
- no lock contention, no schema drift mid-event.

### 3.3 Recipe schema

Knowledge that cannot be executed is documentation. A recipe is executable.

```yaml
id: pwn-tcache-poison-safe-link
domain: pwn
version: 3
title: "tcache poison with safe-linking (glibc >= 2.32)"
signals:
  - "glibc >= 2.32"
  - "show-after-free returns 8 bytes"
  - "heap menu with alloc/free/edit/show"
preconditions:
  - "checksec: NX on, PIE/canary as observed"
  - "a heap leak or a way to compute the victim chunk address"
steps:
  - run: "python3 - <<'PY' ... PY"
    expect: "decoded fd points inside the heap mapping"
    timeout_s: 60
  - run: "edit(1, p64(protect(pos, target)))"
    expect: "next alloc returns target"
falsifier: "alloc after poison aborts with 'unaligned tcache chunk'"
pitfalls:
  - "raw p64(target) crashes: safe-link must be encoded with the NEXT field address"
  - "pos must be the address of the fd field, not the chunk base"
fixtures:
  - eval/fixtures/pwn/tcache_safe_link
sources:
  - "https://.../writeup#section"
verified_by: "human:operator"
last_verified: "2026-10-20"
metrics: {attempts: 0, wins: 0}   # filled from traces, not hand-written
```

**Rule:** a recipe is `verified` only if (a) a fixture reproduces it, (b) a human or an entailment judge has checked the source, (c) it has been run successfully in the harness at least once.

---

## 4. Build order (eval first)

### 4.1 The eval harness — week 1

This is the first thing to build. Everything else is guesswork without it.

#### Task layout

```text
eval/tasks/picoctf-2024-ret2win/
  task.yaml
  image/Dockerfile
  image/files/...
  solution/            # reference solve, used only for sanity, never shown to the agent
  expected.sha256      # salted hash of the flag
```

```yaml
# task.yaml
id: picoctf-2024-ret2win
category: pwn
difficulty: easy
points: 100
time_limit_s: 900
network: none
image: image
flag:
  kind: local_sha256
  salt: "eval-v1"
  sha256: "<hash>"
tools: [python3, pwntools, gdb, checksec, file, strings]
```

#### Runner

```python
def run_task(task, agent_factory, budget):
    env = DockerEnv(task.image, network="none", cpus=2, mem="2g", timeout_s=task.time_limit_s)
    oracle = build_oracle(task)
    trace = Trace(run_id=new_run_id(), path=f"runs/{task.id}.jsonl")
    try:
        env.reset()
        agent = agent_factory(task, env, oracle, trace, budget)
        result = agent.run()
        verdict = oracle.check(result.candidate) if result.candidate else Verdict("unknown", "none")
    finally:
        env.close()
    return RunResult(task.id, verdict, result.elapsed_s, result.tokens, result.tool_calls, trace.path)
```

#### Metrics (record all of them, per task and aggregate)

| Metric | Definition |
|---|---|
| `pass@1` | accepted on the first full attempt within budget |
| `pass@k` | accepted within k independent restarts (report k=1,4,8) |
| `TTF` | seconds from reset to accepted flag |
| `tokens/flag` | prompt + completion tokens per accepted flag |
| `cost/flag` | provider cost per accepted flag |
| `tool_calls/solve` | tool calls per accepted flag |
| `false_solve_rate` | runs marked solved whose oracle says rejected (must be 0) |
| `category_matrix` | pass@1 by category × difficulty |
| `tool_error_rate` | tool calls with infra failure / total |
| `context_tokens/task` | max and mean context size |
| `reproducibility` | stddev across N seeds/runs |

#### Suite composition (start small, grow)

| Suite | Size | Why |
|---|---:|---|
| picoCTF 2024 + 2025 easy/medium | 12–20 | broad categories, known flags, offline |
| Cybench | 40 | professional, runnable, has subtasks |
| NYU CTF Bench | ~200 | the standard academic comparison |
| InterCode-CTF | ~100+ | interactive, tool-loop friendly |
| Your own past events | 10–20 | the distribution you actually care about |
| Live events | seasonal | the only true test |

Start with 20 tasks from the first two rows. Add suites as the harness stabilizes.

#### Contamination controls

- No web search during eval; block egress at the sandbox.
- Exclude any task whose writeup is in the knowledge base; hash-compare task statements.
- Use post-model-cutoff events where possible; record the cutoff.
- Private holdout: 20% of tasks never used for prompt/recipe tuning.
- Canary: insert a unique marker in the task statement and grep the model output for verbatim reuse.
- Freeze model versions and temperatures; record them with every run.
- Report mean ± std over ≥3 runs; never a single best run.

#### CI

```yaml
# .github/workflows/eval.yml
on: [pull_request]
jobs:
  smoke:
    runs-on: [self-hosted, ctf-eval]
    steps:
      - run: python -m eval.runner --suite smoke --out runs/pr.json
      - run: python -m eval.report --compare baseline.json runs/pr.json --fail-on-regression 5%
```

A 20-task smoke suite on every PR is enough to catch prompt/tool regressions. The full suite runs nightly.

### 4.2 Sandbox runtime — week 3

- Docker (start) or Firecracker (later) per task; one container per attempt, destroyed after.
- Non-root user, read-only rootfs, writable `/work` tmpfs, no host mounts.
- `--network none` for offline challenges; for live services, a per-task network namespace with an egress allowlist (event host + OOB collaborator only).
- CPU/memory/PID/time limits; kill on timeout; capture the last N KB of output.
- Snapshot/restore for pwn/rev state and for "fresh eyes" restarts.
- Artifact volume mounted at `/artifacts`, synced to the blackboard.

### 4.3 Tool gateway — week 3–4

Every tool is a typed function with:
- a JSON schema for arguments,
- a hard timeout,
- an output cap (e.g., 32 KB) with spill to an artifact file,
- a structured error (`tool_missing`, `timeout`, `nonzero`, `network_blocked`),
- a permission scope (`ro`, `rw-workdir`, `network:event`, `submit`),
- an idempotency key where relevant.

```python
@tool(scope="rw-workdir", timeout_s=120, output_cap_kb=32)
def run_solve(ctx: ToolCtx, script: str, timeout_s: int = 120) -> ToolResult:
    """Execute a solve script inside the sandbox; spill stdout to an artifact."""
```

Do **not** build 100 tools. Build 10–15 high-leverage ones per domain, each with a fixture. Wrappers around CLI tools are cheap; the value is in *structured observations* (offsets, leaks, parsed tables, diffs), not raw stdout.

### 4.4 Scheduler — week 4

```python
def expected_value(task, now, stats):
    p = solve_probability(task, stats)          # learned per category/difficulty
    decay = max(0.2, 1 - elapsed_fraction(task)) # points decay / time pressure
    cost = estimate_cost(task, stats)            # tokens + expected tool seconds
    return (p * task.points * decay) / max(cost, 1)

def schedule(queue, slots, now):
    ranked = sorted(queue, key=lambda t: -expected_value(t, now, stats))
    for task in ranked[:slots]:
        if not rate_limited(task, now):
            dispatch(task)
```

- Durable queue (SQLite is enough; Postgres if multi-machine).
- Idempotent task states: `queued → leased → running → solved|blocked|parked`.
- Lease timeout + heartbeat; a crashed worker's task returns to the queue.
- Preemption: park a hard task when a new easy/high-EV task arrives; do not kill mid-tool-call.
- Category diversity: cap concurrent attempts per category to avoid one rabbit hole.
- Rate limits per platform and per challenge service.
- Deadline awareness: stop starting new hard tasks below a threshold; spend the last hour on near-solves.

### 4.5 Solver — weeks 4–6

**Roles (can be separate models or separate prompts):**

| Role | Job | Context |
|---|---|---|
| Planner | triage, hypothesis DAG, choose next test, budget | task + observations + recipes |
| Executor | one tool call at a time, write artifacts | current hypothesis + last observations |
| Verifier | check every claim against a tool ID or oracle; reject soliloquy | trace + artifact refs |
| Specialist | deep domain loop (pwn/rev/crypto/web/...) | skill router + recipe + sandbox |
| Toolsmith | turn a repeated manual sequence into a script/tool | trace of the repetition |

**Loop:**

1. Observe: read task, files, service, recipe candidates.
2. Hypothesize: ≤3 ranked, each with prediction + falsifier + cost.
3. Choose the cheapest discriminating test (information gain per second/token).
4. Execute one tool call in the sandbox.
5. Verify the observation (artifact exists, exit code, parse).
6. Update the DAG; checkpoint; repeat.
7. On success: oracle check, then record.
8. On stall: apply the failure taxonomy; one corrected retry; one alternate family; fresh-eyes restart with a summary; park.

**Search:**

- Best-of-N: N=4–8 independent attempts with different angles (direct / technique-variant / tool-variant / encoding-variant / oracle-variant), first accepted flag wins, share findings through the blackboard.
- Beam: keep 2–3 hypotheses alive when the oracle is expensive; prune on contradiction.
- MCTS-lite: only when the oracle is cheap (offline flag check), because it needs many rollouts.
- Fresh eyes: a new agent gets a 500-word summary + artifact paths, never the full dead transcript (this is the one place your `HARDENING.md` rule is exactly right).
- Self-consistency: for answer-style challenges, sample 5 candidates and require agreement or an oracle.

**Anti-soliloquy (enforced, not prompted):**

- Every factual claim in a handoff must cite a `tool_call` ID whose artifact exists.
- The verifier rejects claims without a citation.
- The environment returns structured results; a missing tool is an error, not a negative.
- No "I ran X" without a trace line. This is the single most important defense against the failure EnIGMA names.

**Context management:**

- Working set: task statement, current hypothesis, last 5 observations, top 2 recipes.
- Spill full tool output to artifacts; keep a 512-token summary in context.
- Summarize at 70% of the window; drop the oldest observations first, never the task or the flag-format constraints.
- Retrieve skill sections on demand by symptom, not the full 1,100-line file.

### 4.6 Verifier — week 5

Two passes:
1. **Mechanical:** does every claim cite an existing tool call/artifact? Does the flag match the stated format? Does the oracle accept it?
2. **Semantic:** does the evidence actually entail the claim? Ask a judge model with the trace and artifact excerpts; require a `supported|unsupported|insufficient` verdict.

A `CONFIRMED` state requires `oracle=accepted`; a `partial` state requires at least one mechanically verified observation. Nothing else is recorded as solved.

### 4.7 Knowledge system — weeks 7–8

**Three tiers:**

| Tier | Size | Loaded |
|---|---|---|
| Router/strategy | 60–120 lines per domain | always (one domain) |
| Recipes | 20–50 lines each, YAML | top 2 by signal match |
| Casebooks | 200–1,000 lines | only on stall, one at a time |

**Retrieval:** hybrid of exact signals (file type, glibc version, service banner, error string) and embeddings; return `recipe_id`, `why_matched`, `preconditions`, `fixture`. A recipe whose preconditions are not met is returned as a *negative* ("this does not apply because …"), which is often more useful than a maybe.

**Ingestion pipeline (replaces the current manifest mining):**

```text
source URL
  → fetch (cache, hash, timestamp)
  → extract main content (readability)
  → 2–5 sentence technique excerpt
  → LLM judge: "does this excerpt support technique X?" (X proposed separately)
  → human spot-check (10%)
  → fixture: can the steps be executed in a toy environment?
  → publish recipe with verified_by, last_verified, source hash
```

Reject: no excerpt, no fixture, title-only, duplicate `(event, challenge)`, flag-shaped content, or an entailment score below threshold.

**Lifecycle:** every recipe tracks `attempts/wins` from traces. Retire a recipe after 20 attempts with 0 wins and no fixture success. Re-verify when the tool version changes.

**Quarantine now:** mark every `*_r2/r3/r4` row `verified: false`; do not retrieve them until audited. Keep the r5 casebooks as *candidates*; they read as genuine but still need source checks.

### 4.8 Learning loop — weeks 8–12

- **Failure taxonomy:** classify every blocked run (`tool_missing`, `wrong_primitive`, `timeout`, `service_down`, `knowledge_wrong`, `model_reasoning`, `budget`). A weekly report of the top 5 causes drives the next sprint.
- **Trace mining:** solved traces → SFT data (state, action, observation, next action); failed traces → negative recipes and eval tasks.
- **Regression:** every solved challenge becomes an eval case with a time budget. A release that breaks a previously solved task fails CI.
- **Knowledge promotion:** only from a verified recipe with a fixture, reviewed by a human.
- **Model evaluation:** per-category pass@1 and cost for each candidate model; the router uses measured numbers, not names.

---

## 5. Domain tool matrix (highest ROI)

Build the *observation* tools, not just CLI wrappers. The goal is to turn raw output into a fact the planner can use.

| Domain | Must-have harnesses | High-value structured outputs |
|---|---|---|
| pwn | pwntools, gdb/pwndbg, checksec, ROPgadget/ropper, one_gadget, libc-database, seccomp-tools, qemu-user, pwninit | offset, leak values, libc id, gadget list, seccomp allow/deny table |
| rev | Ghidra headless + decompile API, rizin/r2, angr/triton, Frida, UPX/unpackers, pycdc/.NET/Go/APK/WASM extractors | decompiled function, xrefs, string table, symbolic constraints, recovered input |
| crypto | SageMath, fpylll, z3, RsaCtfTool, factordb, hashcat/john, CyberChef, PyCryptodome | parameter table (`n` bits, `e`, block size), attack applicability score, recovered plaintext/key |
| web | HTTP session client, ffuf, sqlmap, Burp, Playwright/CDP, interactsh | input inventory, baseline diff, oracle classification (reflection/time/OOB), confirmed sink |
| forensics | tshark, Volatility 3 + symbol packs, plaso, ewf, foremost/binwalk, registry tools | protocol/stream table, process list, timeline, carved files |
| stego | exiftool, binwalk, zsteg, steghide, sox/spectrogram, zbar, stegsolve | carrier type, embedded-file list, LSB stats, QR payload, audio peaks |
| misc | Python AST/sandbox analyzer, esolang interpreters, z3, pwntools | jail filter map, allowed builtins, satisfiable input, decoded chain |
| blockchain | Foundry/Anvil, cast, Slither, Echidna/Medusa | storage diff, invariant violation, exploit test, fork state |
| mobile | apktool, jadx, Frida, objection | manifest/exported components, hooks, cert pinning status |
| hardware | binwalk/firmwalker, sigrok, Verilator, UART/JTAG tooling | firmware layout, protocol decode, testbench waveform |
| ai-ml | local model endpoints, prompt-injection harness, canary exfil server | injection success, guardrail map, exfil channel |

**Rule:** every tool returns `ToolResult` with `facts` (structured) plus `raw_ref` (artifact). The planner sees `facts`; it can ask for `raw_ref` when it needs detail.

---

## 6. Model portfolio and routing

### Roles

| Role | Candidate class | Why |
|---|---|---|
| Planner | strongest reasoning model | hypothesis quality dominates hard tasks |
| Executor | strongest coding/tool-use model | most tokens are spent here |
| Verifier | strong, cheap, different family | independent judgment; avoid self-confirmation |
| Triage/classify | small fast model | cheap, high volume |
| Embeddings | small embedding model | retrieval |
| Local fallback | 7–32B tool-tuned model | privacy, cost, rate-limit resilience |

### Routing

Do not hardcode names. Measure.

```python
def choose_model(role, task, stats):
    candidates = available_models(role)
    scored = []
    for m in candidates:
        s = stats.for_model(m, task.category, task.difficulty)
        # Thompson sampling on Beta(wins+1, losses+1)
        p = sample_beta(s.wins + 1, s.losses + 1)
        scored.append((p * task.points - s.cost_per_call, m))
    return max(scored)[1]
```

- Start with a uniform prior; update after each run.
- Fallback chain per provider; retry on 429/5xx with jitter; never fail a task because one provider is down.
- Record model + version + temperature in every trace.
- Re-evaluate after every model release; routing tables expire.

### Fine-tuning (weeks 9–12, optional but high leverage)

- Collect 5k–20k successful tool trajectories from traces.
- SFT a 7–32B model on `(state, available_tools, next_action)`; include failures with the correction.
- Distill the planner's decisions into a cheaper model for routine triage.
- Evaluate on the frozen suite; only ship if pass@1 improves at equal or lower cost.
- Do not RL on flags until the reward is dense enough (subtask progress), or you will learn to guess.

---

## 7. Live-event playbook

### T–24h

- Pull all challenges; triage every one; run the offline quick-win sweep.
- Warm containers, tool caches, wordlists, libc database, Ghidra project.
- Build the initial EV queue; identify the 10 easiest and the 5 highest-value.

### T0–T+2h

- Parallel easy sweep across all categories (N=8–16).
- Submit through the API if the event permits; dedupe and pace per platform.
- Keep a human on CAPTCHA/login/ToS gates only.

### T+2h onward

- Re-rank by EV every 15 minutes and on every new observation.
- Park hard tasks after the time box; revisit if a new hint/leak appears.
- Run best-of-N on the top 3 near-solves.
- Keep 20% of slots for "fresh eyes" restarts.

### Submission policy

- If the platform has an API and the rules allow it: auto-submit after oracle acceptance, with dedupe, pacing, and a per-challenge budget.
- Otherwise: queue for human approval with the evidence attached.
- Never auto-submit a candidate that has not passed the oracle. Never submit a format-only guess.

### Post-event

- Generate writeups from traces (not from memory).
- Promote verified recipes; add every solved challenge to the regression suite.
- Publish the scorecard: solves by category, TTF, cost/flag, false-solve rate, top failure causes.

---

## 8. Migration: keep, rewrite, kill

### Keep (and trim)

- `master_prompt.md` / `SKILL_CONTRACT.md`: the evidence discipline is excellent. Trim to fit the new context budget.
- Domain skills: keep the content, split into router + sections + recipes.
- `triage.py`: the file-signal precedence is right; make it a tool, not a CLI.
- `state.json` nouns: slots, attempts, submissions, confidence. Re-implement as projections.
- `LIVE_OPS.md`: keep the platform lessons; split "careful" vs "competitive".
- Browser/CDP extraction: useful for platforms without APIs; isolate it.

### Rewrite

| Component | From | To |
|---|---|---|
| Orchestration | human slash commands | durable scheduler + worker pool |
| Execution | host shell | sandbox runtime + tool gateway |
| Verification | regex + markdown | oracle + verifier agent |
| Knowledge | 14k one-line rows | verified recipes + fixtures + retrieval |
| Model layer | one ID, fake tiers | measured portfolio + fallback |
| State | 3 ledgers | one event log + projections |
| Eval | 8 fixtures | 20–40 task harness, CI, nightly suite |
| Submission | Playctf browser macro | platform adapters (CTFd/HTB/rCTF) + policy |

### Kill

- `model_router.py` until it routes real models (or replace it).
- `race.py --plan` as a "solver"; keep the findings bus only.
- `ctfusion.py --backfill` self-written proof.
- The duplicate `_ctfusion.json` ledger.
- The 3-attempt cap and 30-minute timeout as *global* rules (keep as `careful`-mode defaults).
- Full-skill loading per task.
- Universal 8–10 s pacing (make it per-platform).
- `framework_lint.py` references until the tool exists.
- `npx ...@latest` / `uvx git+...` in production configs.

### Repo layout

```text
ctf-engine/
  core/            # task, env, oracle, trace, budget, errors
  scheduler/       # queue, EV, leases, rate limits
  solver/          # planner, executor, verifier, specialists, toolsmith
  tools/           # gateway + packs/{pwn,rev,crypto,web,forensics,...}
  knowledge/       # recipes/, casebooks/, index/, ingest/
  eval/            # suites/, tasks/, runner.py, report.py, replay.py
  adapters/        # ctfd, htb, rctf, pwncollege, local
  ops/             # dashboard, metrics, replay, postmortem
  tests/           # unit + property + fixture tests

events/<slug>/     # outside the engine repo: state, flags, browser profile, runs
```

---

## 9. 90-day roadmap

| Weeks | Deliverable | Exit criteria |
|---|---|---|
| 1–2 | Eval harness, 20 tasks, baseline; quarantine corpus; permissions; oracle; clean template | A baseline report with pass@1, TTF, cost/flag; no false solves in the harness |
| 3–4 | Sandbox runtime, tool gateway, scheduler, first platform adapter (CTFd) | 16 parallel sandboxes; one test event submitted end-to-end via API |
| 5–6 | Best-of-N, verifier, context management, fresh-eyes | Frozen-suite pass@1 improves over baseline (record the delta) |
| 7–8 | Recipe format, 200 verified recipes, hybrid retrieval, knowledge metrics | Retrieval eval: top-2 contains the right recipe ≥70% on a labeled set |
| 9–10 | Model portfolio, measured routing, fallback, SFT data pipeline | Per-category model table; routing beats single-model baseline at equal cost |
| 11–12 | Live event, post-mortem, regression suite, public report | Published scorecard; every solved challenge in CI; top-5 failure causes fixed or ticketed |

**Do not skip week 1–2.** A team that starts with the scheduler and the sandbox but no harness will build a beautiful system that nobody can prove is better.

---

## 10. Metrics dashboard

Track per release and per event:

| Metric | Target logic |
|---|---|
| `pass@1` on frozen suite | must not regress; report by category |
| `pass@4` / `pass@8` | search efficiency |
| `TTF` p50/p90 | speed |
| `tokens/flag`, `cost/flag` | economy |
| `tool_calls/solve` | loop efficiency |
| `false_solve_rate` | must be 0 |
| `tool_error_rate` | infrastructure health |
| `context_tokens/task` | context discipline |
| `parallel_utilization` | scheduler health |
| `recipe_hit_rate` / `recipe_win_rate` | knowledge quality |
| `regression_delta` vs last release | release gate |

A release is "better" only if it improves `pass@1` at equal or lower cost, or improves cost at equal `pass@1`, without regressing `false_solve_rate`.

---

## 11. Anti-patterns to avoid

1. **More tools without evals.** Tool count is not capability.
2. **More prose in prompts.** Beyond a point, doctrine displaces observations.
3. **Auto-ingesting writeups without entailment.** This is how the current corpus broke.
4. **One model everywhere.** The router must be real or absent.
5. **Regex as an oracle.** Format is not correctness.
6. **Human gates as universal doctrine.** They belong at the platform boundary, not around every flag.
7. **Parallel writes to shared services.** Parallelize challenges, not a single stateful target.
8. **"Solved" from a format match.** A false solve is a regression.
9. **Copy-per-event knowledge.** Fork the state, not the knowledge.
10. **Unpinned dependencies in a live event.** `@latest` is a countdown timer.
11. **SOTA claims without citations or tests.** The docstrings currently claim +2.5pp/+3pp with no source; delete or prove.
12. **Confusing planning artifacts with execution.** A JSON "lane plan" is not a solver.

---

## 12. Definition of done for "world's best"

- **Measured:** reproducible results on Cybench, NYU CTF, InterCode-CTF, plus a live event, with model versions, seeds, budgets, and cost.
- **Honest:** `false_solve_rate = 0`; every "solved" has an oracle verdict and a trace.
- **Fast:** competitive TTF on easy/medium; hard tasks get enough iterations to finish.
- **Economical:** cost/flag and tokens/flag tracked and improving.
- **Isolated:** all untrusted execution in sandboxes; no host escape; pinned dependencies.
- **Learnable:** verified recipes, trace mining, regression suite, and a weekly failure report.
- **Portable:** a new event is a config + adapter, not a fork of the framework.
- **Auditable:** one event log, replayable runs, diffable releases.

That is a realistic definition of "world's best". It is also the only one you can prove.
