# Evidence — autonomous engine v2 (2026-10-20)

These are **offline control-plane results**. They prove the engine, sandbox,
oracle, scheduler, CTFd adapter, provider adapter, and mock eval work. They do
**not** prove a real model's CTF solve rate, and they are not a substitute for
Cybench/NYU/InterCode or a live event.

| Check | Command | Result |
|---|---|---|
| Unit + integration tests | `python3 -m unittest discover -s tests -v` | **21/21 OK** |
| Offline eval | `python3 -m engine selftest` | **4/4 solved**, pass@1=1.00, 0.1 s |
| Daemon demo (host) | `python3 -m engine daemon --platform local --tasks-dir eval/tasks --provider mock --sandbox local --once` | **4/4 solved**, outcomes=4 |
| Daemon demo (Docker) | same with `--sandbox docker` | **4/4 solved**, 0.7 s |
| Fake CTFd + fake OpenAI | `python3 tests/test_daemon_integration.py` | **1/1 solved**, flag file mode `0600` |
| Framework bench | `python3 tools/bench.py` | **53/53 pass** |
| Structural lint | `python3 tools/framework_lint.py --strict` | **0 errors, 0 warnings** |
| Sandbox image | manual `DockerEnv` check | `ctf-kali:latest` 758 MB; gdb 12.1, z3 5.3.1, pwntools installed |
| Docker eval | `base64` task inside `ctf-kali` | **solved**, 0.14 s |
| Imported skills | `python3 -m engine doctor` | **32 cards**, 32 source-verified recipes, 2,015 catalog entries |

## What is proven

- A real CTFd-shaped HTTP API is polled, challenges + files are downloaded,
  tasks are queued, and a submission is sent through the API.
- The daemon leases tasks, runs one Docker sandbox per task, runs an
  OpenAI-compatible tool loop, and writes an accepted flag to a `0600` file.
- The oracle gate is real: a wrong candidate is rejected; only an accepted
  verdict produces `solved`.
- The submit ledger is shared across attempts, so retries cannot exceed the
  platform budget.
- The sandbox blocks host execution by default in the live config; the image
  has the core CTF toolchain.
- The old corpus is quarantined; only `verified: true` recipes are retrieved.

## What is not proven

- **Real model solve rate.** All evals above use a scripted mock or a fake
  OpenAI endpoint. The next measurement is a 20-task picoCTF suite with a real
  model, then Cybench/NYU/InterCode.
- **Real platform compatibility.** The CTFd adapter is tested against a fake
  server that follows the public API shape. Test it against your event's CTFd
  before trusting it with submissions.
- **Hard challenges.** The eval tasks are deliberately easy; they test plumbing,
  not pwn/rev/kernel depth.
- **Egress control.** Live tasks use Docker `bridge`; there is no allowlist yet.

## Next measurement (replace this file's mock numbers)

1. picoCTF 2024/2025: 20 easy/medium tasks, real model, pass@1/TTF/cost.
2. Cybench: 40 tasks, subtasks optional.
3. NYU CTF Bench: pass@1 and pass@4.
4. One live event: score, TTF, cost/flag, false-solve rate (must be 0).

Until those exist, the scorecard stays "machinery 9.5/10, measured 0/10".
