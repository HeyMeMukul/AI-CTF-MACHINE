# CTF Engine v2 — autonomous control plane

This is the part the v1 framework was missing: a process that polls a platform,
schedules work, runs an LLM tool loop inside a sandbox, checks the answer against
an oracle, records the result, and keeps going without a human in the loop.

It is deliberately **stdlib-only** (Python 3.11+) so it runs on a fresh Kali/WSL
box with no dependency install. The LLM is OpenAI-compatible, which covers
OpenAI, OmniRoute, OpenRouter, vLLM, LM Studio, and most local gateways.

## 60-second offline demo

```bash
cd CTF

# Unit tests + a 4-task mock eval (no API key, no Docker, no network)
python3 -m engine selftest

# Run the daemon end-to-end against the same local tasks, then exit
python3 -m engine daemon --platform local --tasks-dir eval/tasks \
    --provider mock --sandbox local --workers 4 --once

# Inspect the queue/outcome database
python3 -m engine status
```

Expected: `SELFTEST PASS: 4/4 mock tasks solved`, then the daemon solves the
four local tasks and prints `[solved] ...`.

## Live CTFd

0. Build the sandbox image once (needs Docker):

```bash
./scripts/build_image.sh          # python + pwntools + core CTF tools
```

1. Get a CTFd API token: profile → Settings → Access Tokens.
2. Export the provider and platform settings:

```bash
export CTFD_URL="https://your-ctf.example"
export CTFD_TOKEN="ctfd_..."
export LLM_BASE_URL="https://api.openai.com/v1"   # or OmniRoute/local
export LLM_API_KEY="..."
export LLM_MODEL="..."
export EVENT_SLUG="my-event"                       # optional, default ctf
```

3. Check the rig:

```bash
python3 -m engine doctor --ping
```

4. Start the autonomous loop:

```bash
./run_auto.sh
# or, with explicit flags:
python3 -m engine daemon --platform ctfd --workers 8 --max-hours 12
```

The daemon:

- lists unsolved challenges, fetches details and files;
- enqueues them in SQLite with an expected-value order;
- leases up to `workers` tasks and runs one sandbox per task;
- asks the model for one tool call at a time (`bash`, `read_file`, `write_file`,
  `list_files`, `http`, `note`, `submit_flag`, `finish`);
- submits through the CTFd API and accepts only an oracle `correct` /
  `already_solved`;
- writes the accepted flag to `events/<slug>/flags/<task>.txt` (mode 0600);
- records every event in `events/<slug>/runs/<task>-*/trace.jsonl`;
- requeues expired leases and keeps polling until `--max-hours` or Ctrl-C.

## Configuration

`config/engine.json` is the default. Every `${VAR}` is expanded from the
environment at load time. The important knobs:

| Key | Meaning |
|---|---|
| `provider.kind` | `openai` or `mock` |
| `provider.base_url` / `model` / `api_key_env` | LLM endpoint |
| `solver.max_steps` / `max_seconds` / `max_tokens` / `max_submits` | per-task budget |
| `sandbox.kind` | `docker` (recommended) or `local` (trusted fixtures only) |
| `sandbox.image` | image with your CTF tools, e.g. `ctf-kali:latest` |
| `sandbox.live_network` | `bridge` for live services; `none` for offline |
| `scheduler.workers` | parallel tasks |
| `scheduler.max_attempts` | retries before a task is blocked |
| `knowledge.top_k` | retrieved recipes per task |

### Model routes for the interactive copilot

`tools/model_router.py` is separate from the engine provider. It reads
`config/model_routes.json` or `CTF_MODEL_LEAD/WORKER/FAST`, and `--check` fails
until at least two distinct routes are configured. It no longer pretends to
have a model fleet:

```bash
python3 tools/model_router.py --check     # UNCONFIGURED until you fill routes
python3 tools/model_router.py --task exploit --leaf-tags heap-fengshui
```

### Multi-attempt (fresh eyes)

`solver.attempts` / `--attempts N` runs up to N trajectories for a blocked task.
All attempts share one `SubmitLedger`, so the platform's submission budget is
never multiplied by the number of attempts. Each attempt gets a summary of the
previous one, not the full dead transcript.

## Knowledge tiers

| Tier | Source | Used by the solver |
|---|---|---|
| Fixture-tested | `recipes/*.json`, `verified: true` | yes |
| Source-verified (32 imported) | `recipes/imported-*.json`, `verification: source` | yes, labeled "source-verified (not fixture-tested)" |
| Quarantined | `knowledge/writeups_mined/*` | no, unless `--include-unverified` |

The full 2,015-entry catalog (VoltAgent + Trail of Bits + Anthropic Cybersecurity
Skills) is searchable without entering the prompt:

```bash
python3 -m engine knowledge --catalog --query "volatility memory forensics"
python3 -m engine knowledge --catalog --query "fuzzing harness"
```

See `docs/SKILL_IMPORTS.md` and `knowledge/catalog/SELECTION.md`.

## Architecture

```text
CTFdAdapter.sync() ──> Store (SQLite: tasks, outcomes)
                          │
                     Daemon loop
                          │ lease
                    ThreadPoolExecutor
                          │
             build_env() ──> DockerEnv (default) / LocalEnv
                          │
             Solver ──> Provider.chat() ──> tool call
                          │                        │
                          │                  Toolbox (bash/http/...)
                          │                        │
                          └──── observations <─────┘
                          │
                    Oracle.check(candidate)
                          │
              accepted ──> flags/ + state=solved
              rejected ──> continue (bounded submits)
```

## Safety posture

- **Docker by default** in `config/engine.json`: non-root, `--cap-drop ALL`,
  `no-new-privileges`, CPU/memory/PID limits, read-only rootfs optional, and an
  explicit network mode.
- **No host mounts** beyond the task workdir.
- **Flag values never enter the trace**: submit calls log a SHA-256 and length,
  not the value; the accepted flag is written only to a 0600 file.
- **One oracle, one truth**: `accepted` comes from the local salted hash or the
  platform API. A markdown file cannot mark a task solved.
- **Prompt-injection posture**: the model is told challenge text is untrusted;
  the tool gateway is the only path to execution. This is still an LLM, so keep
  the sandbox boundary real.

## What is implemented now

- CTFd list/detail/download/submit adapter, with a pure parser for tests.
- Durable SQLite queue with EV ordering, leases, expiry requeue, and outcomes.
- Per-task sandbox (`DockerEnv` + `LocalEnv`) and a typed tool gateway.
- Provider-agnostic solver loop with budget, loop guard, context compaction,
  tool-call retry, text-JSON fallback, and oracle-gated submission.
- 4 verified recipes, loaded only when `verified: true`.
- 4 offline eval tasks with salted hashes, a mock provider, and a suite runner.
- `doctor`, `selftest`, `eval`, `run`, `knowledge`, `daemon`, `status`, `ping`.
- 21 tests: 18 unit + 3 integration (fake CTFd, fake OpenAI, and a full
  platform→daemon→flag path).
- `tools/framework_lint.py`, `.gitignore`, CI.

## Known limits (next iterations)

- Multi-attempt fresh-eyes is wired (`solver.attempts` / `--attempts`) with a
  shared submit ledger, so retries cannot exceed the platform submission budget.
- A semantic verifier agent and a model portfolio/router are not wired yet;
  the scheduler parallelizes tasks and attempts, not a semantic debate.
- HTB / rCTF adapters are not implemented (CTFd + local are).
- The Docker image is not built by this repo; `ctf-kali:latest` must exist or
  `sandbox.image` must point at one that does.
- The verified recipe set is intentionally small. The old mined manifests are
  not loaded by the engine; audit them before adding recipes.
- No live benchmark has been run yet. The numbers in `docs/SCORECARD.md` are
  evidence-gated for exactly this reason.

## Tests

```bash
python3 -m unittest discover -s tests -v
python3 -m engine selftest
python3 tools/framework_lint.py --strict
```
