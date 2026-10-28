# PWN — Quickref

**Frontmatter:** name=`pwn` · category=`exploitation` · phase=`exploit`
**Phases:** 1 Baseline → 2 Confirmation → 3 Negative → 4 Exploit (ONE step ≤120s) → 5 Validation-handoff. Each ends with a `Reasoning Checkpoint` line.

## Checksec → path
- `checksec --file=./vuln` · `file; ldd` · `nm -D | grep -iE "win|flag|system"`.
- No canary+PIE + `win` → ret2win. NX on → ROP, never stack shellcode.
- Canary/PIE → leak first (fmt `%p`, GOT leak). Never guess/hardcode.

## Offset & gadgets
- `cyclic(512)` → crash → `cyclic_find(core.read(core.rsp,8))` (amd64) / `core.eip` (i386).
- CLI: `pwn cyclic 512` / `pwn cyclic -l <val>`.
- `ROPgadget --binary ./vuln | grep -E "pop rdi|: ret$"`; py: `ROP(elf).find_gadget(['pop rdi','ret'])` + bare `ret` for movaps align.

## Core chains (skeletons E1–E4 in SKILL.md)
- ret2win: `flat({off:[ret,pop_rdi,arg,elf.sym.win]})`.
- ret2libc: leak `puts@GOT` via `puts@PLT` → `main` → `libc.base=leak-sym` → `ret,pop_rdi,binsh,system`. Try `one_gadget` first.
- fmt: `%i$p` sweep 1..30 → `fmtstr_payload(off,writes,'short')` (Partial RELRO only for GOT).
- tcache ≥2.32: `protect(pos,t)=(pos>>12)^t`; decode leak before poison. Unsorted ≥0x90 → `main_arena` leak; 2 leaks for libc-db.

## GDB / pin / matrix
- `gdb.debug(BIN,'b main\nc')` · `vmmap/telescope/bt/search/cyclic -l`.
- Pin: `patchelf --set-interpreter ./ld.so` + `--replace-needed`.
- Fork svc → canary brute/partial-overwrite OK; reroll → must leak.

## Auto rules
- Exploit = ONE `solve.py`, `timeout 120`, retry cap 3, one variable per retry.
- Validate leaks (nonzero, low12); re-run ×2; redact flag in handoff.
- Stall: 3rd identical crash → stop, hand off `blocked` with 500B tail.
- Missing primitive (canary+PIE, no leak) → `blocked(need-leak)`, don't spam.

## Heap triage in 4 checks
1. `show` after `free` prints data → UAF read (heap/libc leak).
2. Free ≥0x90 (or 7× fill) → unsorted `fd` = `main_arena` (version offset!).
3. `edit` after `free` works → poison; decode safe-link first on ≥2.32.
4. No `show` → consider Force/Spirit concepts; ≥2.34 skip FSOP/hooks.

## Hard playbook (§X — gated on ≥1 proven leak)
- Feng Shui: LIFO tcache (last-freed = first-reused); guard chunk vs top; verify head via `tcache` dump.
- FSOP eras: <2.24 forged vtable · 2.24–2.27 in-range `_IO_str_jumps` · ≥2.28 `_IO_wfile_jumps`→unvalidated wide-vtable · ≥2.34 Apple-style (hooks dead). Needs: libc leak + FILE write + flush trigger (`exit`/`abort`).
- ret2dlresolve x86-64: Partial/No RELRO only; `Ret2dlresolvePayload` + `read(0,data_addr)` + `rop.ret2dlresolve(dl)`; needs 2nd input round.
- SROP: `SigreturnFrame` (rax/rdi/rsi/rdx/rip) + ONE `syscall;ret` + sigreturn gadget; pad frame exactly.
- Seccomp ORW: `seccomp-tools dump` first; execve-KILL → `open/openat+read+write` shellcode or ROP; `open` blocked → `openat(257)`; pre-opened fd → brute fds 3,4,5.
- 2-leak libc match: same-run pair (puts+read), delta-match, shipped libc outranks db; confirm via low-risk probe.
- Fork-brute math: fork-without-execve only; canary ≈256×7 probes; PIE low-12 fixed (1/16 per nibble); checkpoint prefix per byte.
- Stack pivot: `leave;ret` + controlled `rbp`; verify `rsp` via `telescope` before stage-2 chain.
- Full RELRO endgames: stack retaddr/app ptrs/`__exit_funcs`/wide-vtable — never GOT/dlresolve.

## Chains / failures / guards / budget
- M1 hardened stack: fmt leak (canary+PIE) → rebase → GOT-leak loop → libc → stage2. M2 heap: UAF heap leak → unsorted libc → tcache→retaddr or FSOP. M3 leakless: 1/16 nibble gamble (fork only) → first hit converts to M2.
- Failures F1–F7: movaps→+`ret` · bad-libc→2nd leak · timeout=fix I/O framing · seccomp-KILL→ORW vs clean-exit→fix path · one_gadget→try-all loop · raw-fd→`protect(pos,t)` · stale-PIE→re-leak same conn.
- Version guards: NO hardcoded offsets — `base=leak-sym` on shipped/matched libc + 2nd-symbol cross-check; era gates 2.24/2.26/2.29/2.32/2.34; pin `pwn version`.
- Tiers: easy ≤20m (skeletons) · medium ≤1h (+fmt/tcache) · hard ≤3h (§X+M chains, hourly checkpoint) · insane → escalate, no grind.
- Escalate: `/rev` for menu/struct ambiguity · `sessions` for persistent dbg · operator via `operator_ping.sh` on hard gates only.

## Writeup patterns W1–W30 (new keys only, see SKILL.md)
- Apple2 (2.34+): vtable=`_IO_wfile_jumps-0x20` + `_wide_data` scratch + `_IO_save_end`=system → `exit`; forged table fails check.
- No-free Orange: shrink top (page-align+PREV_INUSE) → over-request → sysmalloc unsorted leak → M2 (2.35 no-free default).
- Botcake (2.29+): fill-7 → unsorted → consolidate → drain-1 → re-free → overlap → `protect(pos,t)`; naive dup aborts.
- Largebin (2.30+): `p2<p1` + corrupt `bk_nextsize` → sorted-insert writes heap addr to target; nextsize raw (no safe-link).
- Einherjar/Spirit/Lore/Force: OBO-clear-PREV_INUSE + fake `prev_size` → backward overlap; Spirit fake `0x40` (+succ. pre-2.26); Lore `bck->fd==victim`; Force `<2.29` wrap only.
- Hookless finishes: `tcache_perthread` counts/entries → arbitrary; TLS `dtor_list`/`__exit_funcs` forge + clear `fs:0x30`; `l_info[F用途]`/`_rtld_global` pivot; `environ`→stack; `setcontext` mcontext (`rdi`=0 + `setuid(0)` before SUID `system`).
- Leakless/unknown-libc: safe-link bootstrap via `reveal`/z3 nibble; DynELF `write`-loop resolve; ret2csu `rbx=0,rbp=1` when no `pop rdi`; fork partial-overwrite 1/16-nibble low-12 only.
- Fmt/stack hardening: `hn` ascending + `numbwritten`; `exit@GOT`=main loop for round-2; canary chooser fmt/NUL/fork; PIE rebase per-conn (never cache); seccomp KILL-vs-clean + `openat(-100)`/`readv`/`writev`/fd-3/4/5 + charset shellcode (gelcode/palindrome/mov-only).
## Writeup patterns W31–W60 R2 (keys only, bodies in techniques/writeup-patterns-r2-*.md)
- 2.38–2.41 heap: count-7/calloc Tangerine; double-protect z3/nibble; cross-bin stash; largebin smaller-wins; Cat/Emma/Kiwi/Pig/Husk deltas on shipped libc.
- Seccomp/SROP/dlresolve: ORW golf + `openat(-100)` + staged read; notify/ptrace/arch-gap; SROP read-len-15/arm64/UTF8-mprotect; dlresolve data_addr + fake-link_map.
- Fmt/fork/static: ascending-`hn` + exit-GOT round-2 + re-sweep; fork canary 256×7 + PIE 1/16 + pin generation; static ret2syscall + SROP-mprotect (no libc).
- Modern targets: musl-meta/mimalloc-freelist/atexit; custom allocators; io_uring rings concept-only; Rust fat-ptr/drop-glue + no-ret JOP under CET; ROL17 guard forge.
