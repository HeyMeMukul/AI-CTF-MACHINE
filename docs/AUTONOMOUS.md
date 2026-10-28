# Autonomous runbook

This is the shortest path from "I have a CTFd URL and a model key" to "the
engine is solving challenges by itself".

## 1. Build the sandbox image (once)

```bash
cd CTF
./scripts/build_image.sh
```

It builds `ctf-kali:latest` from `Dockerfile.kali-ctf`: Python 3, pwntools,
gdb, binutils, netcat, z3, pycryptodome, gmpy2, sympy, and the usual CLI tools.

## 2. Export the four secrets/settings

```bash
export CTFD_URL="https://your-ctf.example"
export CTFD_TOKEN="ctfd_..."          # profile -> Settings -> Access Tokens
export LLM_BASE_URL="https://api.openai.com/v1"
export LLM_API_KEY="..."
export LLM_MODEL="..."
```

Optional:

```bash
export EVENT_SLUG="my-event"          # events/<slug>/
export WORKERS=8
export MAX_HOURS=12
export ATTEMPTS=1                     # fresh-eyes retries per task (shared submit budget)
```

## 3. Check the rig

```bash
python3 -m engine doctor --ping
```

`doctor` checks the provider key/model, the Docker image, recipe integrity, the
eval suite, and (with `--ping`) that the CTFd token can list challenges.

## 4. Start the autonomous loop

```bash
./run_auto.sh
```

What it does, forever until `MAX_HOURS` or Ctrl-C:

1. `CTFdAdapter.sync()` lists unsolved challenges, fetches detail + files.
2. Enqueues them in `events/<slug>/state.sqlite3` with EV ordering.
3. Leases up to `WORKERS` tasks.
4. Starts one Docker sandbox per task.
5. Runs the LLM tool loop (`bash`, files, http, submit, finish).
6. Submits through the CTFd API; only `correct` / `already_solved` counts.
7. Writes the accepted flag to `events/<slug>/flags/<task>.txt` (0600).
8. Appends every LLM/tool/verdict event to
   `events/<slug>/runs/<task>-*/attempt-*/trace.jsonl`.
9. Requeues expired leases; never dies on one bad task.

## 5. Watch it

```bash
python3 -m engine status
tail -f events/<slug>/runs/<task>-*/attempt-1/trace.jsonl
```

## 6. Stop and resume

Ctrl-C stops leases; running tasks finish. Restart with the same command; the
SQLite queue and solved flags are preserved. A task already `solved` is not
re-solved.

## Safety notes

- The daemon submits flags; run it only on events whose rules allow automated
  submission (CTFd API with your own token). If the rules require manual
  submission, run `--sandbox docker` but keep the human submit step.
- The default network is `none` for offline tasks and `bridge` for live tasks.
  There is no egress allowlist yet; treat the sandbox as a boundary, not a
  guarantee.
- Flag values are never written to the trace, only to the 0600 flag file and
  the in-memory oracle call.
- `sandbox.kind=local` is for trusted eval fixtures only. Do not run
  platform-downloaded binaries with it.
