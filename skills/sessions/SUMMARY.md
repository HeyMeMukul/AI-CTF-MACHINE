# SESSIONS — Quickref

**Frontmatter:** name=`sessions` · category=`harness` · phase=`exploit`
**Phases:** 1 Baseline → 2 Confirmation → 3 Negative → 4 Exploit (ONE script ≤120s) → 5 Validation-handoff. Each ends with a `Reasoning Checkpoint` line.

## Golden rule
- NEVER one-shot `echo | nc`: state resets, ASLR re-rolls, leaks die.
- ONE held `conn = remote/process` owns banner→menu→leak→shell.
- `conn` = wire (exploit). `dbg` = microscope (`gdb.debug/attach`, local only).

## Sync pattern
- `sendlineafter(PROMPT, data, timeout=5)` + `recvuntil(next, timeout=5)` — every send paired.
- Desync → drain `recv(timeout=2)`, log raw, re-baseline. Never blind-resend.
- Timeout = data: crash (EOF) vs wrong-prompt vs shell (`$/#` → proof cmd, `interactive()` attended-only).

## Templates (T1–T4 in SKILL.md)
- **T1** menu client: `alloc/free/show/edit` wrappers, frozen prompt bytes, transcript logging.
- **T2** gdb leak: `gdb.debug(..., 'b main\nc', aslr=False)` → `telescope/vmmap`, `corefile + cyclic_find`. Re-run ASLR-on before remote.
- **T3** blind fmt: `AAAA.%i$p` sweep 1..30 → `%p.`×24 dump (canary `..00`, PIE `0x55`, libc `0x7f`).
- **T4** stall-guard: never >3 identical cmds; `recv_classify` (ok/eof-crash/maybe-shell/desync).

## Prompt-table discipline
- Freeze repr prompt bytes in Baseline; all sends via `sendlineafter(frozen, ...)`.
- One off-whitespace probe in Negative; fix the TABLE once, not inline hacks.
- Every script logs timestamped SEND/RECV; leaks in hex with asserts.

## Ops
- `socat TCP-LISTEN:1337,fork EXEC:./vuln` · `pwn template --host --port` · `pkill -f session_exploit`.
- Restart test: stable = fork (brute OK); reroll = need leak.
- ONE script/turn, `timeout 120`, remote tries ≤3, transcript redacted.
- Lead dispatch: target + template + stop-cond + artifact; ≤2 workers, never same service.
- Password gates: ≤3 tries, then hard-gate to Lead (no unbounded brute).
- Close tubes + kill stray gdb in `finally`; no orphan processes.
- Handoff `solved` (shell/marker ×2) or `blocked(...)` with 500B tail + `poll()`.
