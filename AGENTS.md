# AGENTS.md — CTF Solver Agent Configuration (v2.0 — autonomous engine + interactive model)

Single opencode session. THIS FOLDER IS THE TEMPLATE — no event data lives here.

All models are Muse Spark 1.3 Contributor (provider `opencode-go`). Lead uses the xhigh variant; all other routes use the default variant. If a model is unavailable or rate-limited, switch with `/models` or edit `opencode.json`.

**Autonomous mode:** `./run_auto.sh` starts `engine/` (CTFd poll → queue →
Docker sandbox → oracle-checked submission). See `docs/AUTONOMOUS.md`.
It is separate from the interactive Lead/Worker flow below.
Per CTF: `cp -r CTF /path/to/<event-slug>/ && cd /path/to/<event-slug> && ./start.sh "Name" <url>`.

| Agent | Role | Configured model | How it runs |
|---|---|---|---|
| **Lead** | Strategy: plan, dispatch, merge, flag-path synthesis, writeups, state. | `opencode-go/muse-spark-1.3-contributor#xhigh` (`agent.build`, see `opencode.json`) | Primary agent |
| **Worker** | Tactics: triage/recon/analyze/exploit/validate inside one task. | `opencode-go/muse-spark-1.3-contributor` (`agent.general`, see `opencode.json`) | Via `/triage /analyze /exploit /validate /pwn /crypto /rev /web /forensics` |
| **Fallback** | Optional operator-selected fallback when available. | `opencode-go/muse-spark-1.3-contributor` (`small_model`) | `--model` switch / `config/ctf_policy.json` |

**Autonomous continuation:** after scope is set, Lead dispatches/follows up without waiting for manual slash invocation. Recoverable failures → diagnosis → 1 corrected retry → 1 alternate method → `blocked` after 3 total bounded attempts, continue. Pause only for hard gates (flag submit, CAPTCHA/login, manual interaction, scope ambiguity, unbounded brute, destructive action). Hard gate = `tools/operator_ping.sh "<need>" loop`, keep solving unblocked work.

## Discipline (NEVER VIOLATE)
Lead: plan, dispatch, read Worker results, prioritize, synthesize flag paths, writeups, state. Lead may run framework status/lint/validation tools but delegates tactical target interaction.
Worker: probe, fuzz, debug, exploit, write artifacts.
Lead NEVER runs `bash/curl/nc/gdb/python3 solve.py` directly — delegate tactical execution to a bounded Worker task. Never claim tool output that was not observed.

Bounded parallel: 2 workers default (interactive); the engine daemon uses `scheduler.workers` (default 8). Independent challenges/targets only. Never parallelize shared live service interaction, shared-state writes, or final validation. Each task: request cap + deadline + stop condition + unique artifact path. Slots by task name (M1 `state_manager.py` port).

## Commands
`/triage /recon /analyze /exploit /validate /writeup /solve /pwn /crypto /rev /web /forensics /stego /misc /osint /hardware /blockchain /mobile /ai-ml /browser /submit /instance /think /status /resume /worker`

## File structure
```
opencode.json  master/lead/worker/challenge_prompt.md  setup_ctf.sh  run_ctf.sh
start.sh (full bring-up: deps+MCP+Chrome+health)  phases/  skills/  knowledge/
tools/ (incl. autosolve.py quick-wins, captcha_gate.py human gate)
skills/imported/ (24 imported security cards; see NOTICE.md and docs/SKILL_IMPORTS.md)
engine/ (autonomous control plane: daemon, scheduler, sandbox, CTFd adapter, eval)  eval/  docs/  config/
challenges/ results/ tasks/ writeups/ .browser-profile/  ← REAL dirs, EMPTY in template.
state.json ← pristine template; start.sh inits it per event.
```

## Engagements
- New CTF = copy this whole folder, `cd` in, `./start.sh "Name" <url>`. No shared
  state between events by construction (separate folder = zero memory).
- Technique-only lessons may be distilled to `knowledge/learnings/` manually.
- Lead merges `knowledge/learnings/*.md` patterns into skills/ after review.

## Hard gates (pause, never bypass)
- CAPTCHA / bot-wall / login: `python3 tools/captcha_gate.py --url <target>`
  (operator solves MANUALLY, agent idles). Hammering deepens the block.
- Flag submit, scope ambiguity, unbounded brute: `tools/operator_ping.sh "<need>" loop`.
- Autonomous exception: the engine may submit through the CTFd API only when the event
  rules allow API submission. Otherwise keep the human gate.

## Verification
- `./setup_ctf.sh --status` runs without errors
- `python3 -c "import json; json.load(open('state.json'))"` validates state
- `bash -n setup_ctf.sh` syntax-checks setup
- `python3 tools/skill_lint.py` checks every skill against the shared execution contract
- `python3 tools/framework_lint.py` checks prompts, slash-command references, skill coverage, and template cleanliness
- `python3 tools/bench.py` runs the offline behavior suite
- `python3 -m unittest discover -s tests -v` runs the engine unit suite
- `python3 -m engine selftest` runs the offline mock eval (4/4 expected)
- `python3 -m engine doctor` checks provider, sandbox, recipes, and eval wiring
