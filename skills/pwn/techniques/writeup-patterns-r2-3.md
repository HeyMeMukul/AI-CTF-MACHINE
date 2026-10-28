# PWN writeup patterns R2-3 — W51..W60 (fork/static/musl/uring/Rust)

> Technique-only. Bodies for SKILL.md R2 index W51–W60. Signals → steps →
> pwntools snippet → pitfalls → 2–3 R2 manifest sources. No flags.

## W51 — fork PIE partial-overwrite 1/16-nibble + reroll classifier

- Signals: fork-without-execve + PIE on + nearby target (`win`/`main+off`) +
  low-12 page-stable + no leak primitive.
- Steps: (1) verify stability (same byte ×3 reconnects) — `execve`-per-conn
  reroll voids the math; (2) overwrite RIP low 1–2B only (`& 0xfff` stable),
  1/16 per nibble brute to the nearby target; (3) distinguish oracle classes:
  normal response vs crash-close vs 502-worker-crash (Pwn2Own-style); (4) prefer
  partial-overwrite over full-word force (16 probes vs 1792).
- Snippet: `pay = flat({OFF: p8((orig_low & 0xf000) | 0x3)})  # 1 nibble; loop 16 with oracle`.
- Pitfalls: `gets`/`strcpy` truncates `\x00`/`\x0a` nibbles — use `read` alphabet
  or skip; multi-parent pre-fork pools expose several PIE bases — pin probes to
  one generation; third consecutive no-oracle-change = wrong adjacency, re-groom.
- Sources: https://hacktricks.wiki/en/binary-exploitation/common-binary-protections-and-bypasses/stack-canaries/bf-forked-stack-canaries.html · https://blog.beatman.tw/en/articles/69ed65acc3a1bf5c78cef870 · https://jia.je/ctf-writeups/2025-09-12-fortid-ctf-2025/pwn.html

## W52 — static ret2syscall without libc (pop-reg ladder + bss-binsh)

- Signals: statically linked + NX on + no `system`/libc + `read` + `syscall`
  gadget + writable `.bss`/data section + stack overflow.
- Steps: (1) inventory static gadgets (`pop rdi/rsi/rax/rdx`, `syscall`,
  `mov [reg], reg` movers); (2) `read(0, bss, 8)` stages `/bin/sh` into known
  writable memory; (3) set `rax=59, rdi=bss, rsi=rdx=0`; (4) `syscall` →
  execve (or ORW numbers under seccomp — see W41).
- Snippet: `rop += p64(pop_rax_rdx_rbx) + p64(0x3b) + p64(0) + p64(0); rop += p64(pop_rdi) + p64(bss); rop += p64(syscall)`.
- Pitfalls: static movers clobber extra regs (e.g. `mov rax, rdx` + `pop rbx`)
  — account the clobber or the chain shifts; `/bin/sh` string rarely in static
  binary — always stage it via `read` first; `int 0x80` is 32-bit only.
- Sources: https://github.com/alhamrizvi-cloud/Binary-Exploitation/blob/main/09.%20Ret2Syscall%20/README.md · https://hacktricks.wiki/en/binary-exploitation/rop-return-oriented-programing/rop-syscall-execv/index.html · https://ctf-wiki.mahaloz.re/pwn/linux/stackoverflow/basic-rop

## W53 — static SROP + mprotect + read-pivot staging

- Signals: static + NX + almost no call gadgets + `sigreturn` path + `mprotect`
  reachable + need shellcode-stage execution.
- Steps: (1) SROP frame calls `mprotect(page, 0x1000, RWX)` on a known page;
  (2) read-pivot stages shellcode/ORW into the fresh RWX page; (3) pivot `rsp`
  into it; (4) under seccomp use ORW register set in the post-mprotect frame.
- Snippet: `frame.rax = 10; frame.rdi = page & ~0xfff; frame.rsi = 0x1000; frame.rdx = 7; frame.rip = syscall_ret  # then pivot`.
- Pitfalls: `mprotect` addr must be page-aligned or it returns EINVAL; frame pad
  exact (W43); static signal numbers match the ARCH table — verify `__NR_rt_sigreturn`.
- Sources: https://github.com/utsavthakur/agenticskills/blob/main/binary-protection-bypass/PROTECTION_BYPASS_MATRIX.md · https://wiki.athena-ctf.com/docs/pwn/sigreturn-rop · https://github.com/MedjberAbderrahim/CTF-Writeups/blob/main/2025/QnQSecCTF/pwn/notez/writeup.md

## W54 — musl mallocng meta + atexit finish (mimalloc-adjacent)

- Signals: binary linked against musl (not glibc) + heap menu + `LD_PRELOAD`
  or static musl + no tcache/safe-link behavior matching glibc.
- Steps: (1) identify allocator: musl mallocng uses meta structures, not chunk
  headers — OOB read leaks `meta->mem`; (2) arbitrary write redirects allocation
  to controlled address; (3) target `atexit`/`__exit_funcs` (musl layout) +
  `exit` trigger; (4) confirm with musl docs layout, never glibc offsets.
- Snippet: `leak = u64(view(meta_mem_ptr)); alloc_to(atexit_slot, p64(system_wrap))  # musl layout only`.
- Pitfalls: glibc techniques (tcache poison, safe-link, hooks) do NOT transfer
  — check `ldd`/strings for musl first; meta stride differs by size class —
  confirm in debugger, never assume.
- Sources: https://justinapplegate.me/2025/uiuctf-doremi · https://github.com/sigpwny/UIUCTF-2025-Public/blob/main/WRITEUPS.md · https://github.com/ljagiello/ctf-skills/blob/main/ctf-pwn/heap-fsop.md

## W55 — mimalloc fixed-chunk free-list + outside-heap ptr

- Signals: `LD_PRELOAD=libmimalloc` (or linked) + fixed-size notes + UAF +
  free-list head contains non-heap pointers (unlike ptmalloc unsorted).
- Steps: (1) free chunks, read free-list `next` — mimalloc keeps outside-heap
  pointers live from the start; (2) leak data-section/libc-equivalent addrs
  directly (no smallbin grooming needed); (3) plant fake chunk via free-list
  overwrite; (4) allocate to target (`atexit`/retaddr/dispatch table).
- Snippet: `head = u64(show_freed())  # mimalloc free-list ptr (may be non-heap); edit(head_slot, p64(target))`.
- Pitfalls: fixed-size classes only — cross-size grooming is void; security
  mitigations differ per mimalloc version (2.2.x) — confirm free-list encoding
  in debugger; same-run leak discipline still applies (ASLR slides together).
- Sources: https://justinapplegate.me/2025/uiuctf-doremi · https://github.com/sigpwny/UIUCTF-2025-Public/blob/main/WRITEUPS.md · https://github.com/XDSEC/MoeCTF_2025/blob/main/official_writeups/Pwn/MoeCTF%202025%20Pwn%20Writeup.md

## W56 — uclibc / custom-allocator metadata abuse

- Signals: non-ptmalloc allocator (uclibc, talloc pool, nginx pool, game heap)
  + metadata `next/size/is_free` reachable + no safe-link/tcache behavior.
- Steps: (1) map the allocator's own metadata layout from binary/decompile
  (never assume ptmalloc fields); (2) forge pool/chunk header with boundaries
  spanning the target; (3) next allocation returns attacker address; (4) GOT
  read for leak + hook/dispatch overwrite per that allocator's trigger.
- Snippet: `forge_pool(end=target + size); alloc()  # returns target on custom allocators`.
- Pitfalls: ptmalloc-era offsets (main_arena, tcache counts) are fiction here —
  re-derive everything; consolidation rules differ — test free-order in gdb
  before grooming.
- Sources: https://github.com/ljagiello/ctf-skills/blob/main/ctf-pwn/heap-fsop.md · https://github.com/yaklang/hack-skills/blob/main/skills/heap-exploitation/HOUSE_OF_TECHNIQUES.md · https://github.com/utsavthakur/agenticskills/blob/main/binary-protection-bypass/PROTECTION_BYPASS_MATRIX.md

## W57 — io_uring SQ/CQ + restricted-syscall escape concept (userland)

- Signals: userland challenge adjacent to kernel surface (syscall-filtered ROP,
  `io_uring_setup` reachable, or UIUCTF-style Syscalls-2 lineage) + need
  async-syscall oracle concepts.
- Steps: (1) `mmap` shared SQ/CQ rings; (2) get SQE describing the wanted
  syscall, `io_uring_enter` to submit; (3) consume CQE for the result — models
  restricted-syscall bypass as submit/complete rather than direct `syscall`;
  (4) combine with UAF/feel (fdinfo path) only where the challenge exposes it —
  pure CTF userland usually needs just the ring model, not the CVE.
- Snippet: `mmap(0, 0x2000, RW, SHARED|ANON, -1, 0)  # rings; sqe->opcode = WANTED; io_uring_enter(fd, 1, 1, 0)`.
- Pitfalls: CONCEPT-ONLY for most CTF userland — do not import kernel-CVE
  exploit code wholesale; needs `liburing`-matching semantics; kernel <5.1 has
  no io_uring at all — check version first.
- Sources: https://github.com/ysanatomic/io_uring_LPE-CVE-2024-0582/blob/main/exploit.c · https://github.com/ysanatomic/io_uring_LPE-CVE-2023-2598/blob/main/writeup.md · https://github.com/AmesianX/kernel-exploit-dojo/blob/main/2024/UIUCTF_2024/Pwn_Syscalls_2/writeup/writeup01/solve_io_uring.txt

## W58 — Rust fat-ptr / UAF + drop-glue + vtable dispatch

- Signals: Rust binary + heap menu (Vec/slice confusion, use-after-free on
  reborrow, refcount wrap) + `strings` shows `panic`/`.rustc` + no classic
  malloc headers.
- Steps: (1) corrupt fat-pointer metadata (ptr+len) or Vec length to get
  OOB read/write; (2) hijack trait-object vtable or `Drop::drop` glue pointer;
  (3) point dispatch at ROP/`system`-equivalent with controlled first arg;
  (4) 2-byte partial overwrite often suffices (FortiD lineage) — confirm
  return-address adjacency in decompile first.
- Snippet: `corrupt(vec.len, huge); vtable_slot = leak(); overwrite(drop_glue, p64(rop_start))  # Rust dispatch`.
- Pitfalls: Rust layout is compiler-version-specific — never reuse C-heap
  offsets; `panic` paths abort (no flush) — trigger via normal return/drop,
  not `panic`; partial overwrite needs low-12 stability proof first.
- Sources: https://jia.je/ctf-writeups/2025-09-12-fortid-ctf-2025/pwn.html · https://cybersecurityelite.com/ctf-writeups/l3akctf-2026-pwn-writeup · https://github.com/XDSEC/MoeCTF_2025/blob/main/official_writeups/Pwn/MoeCTF%202025%20Pwn%20Writeup.md

## W59 — Rust + CET SHSTK/IBT + no-ret JOP/COP finish

- Signals: Rust or 2025+ binary + `checksec` shows CET/SHSTK/IBT + `ROPgadget`
  finds almost no plain `ret` + need code-reuse without returns.
- Steps: (1) confirm CET: `checksec` + `readelf -n` (CET property);
  (2) switch to JOP/COP: dispatcher gadget + table of function-pointer payloads
  (MoeCTF-noret lineage); (3) or signal-frame path (SROP) which is CET-compatible;
  (4) keep chain to `system`/ORW — JOP tables need the same leak discipline as ROP.
- Snippet: `table = [pop_rdi, binsh, system]; dispatcher = jop_gadget  # no ret used; cf. TGCTF-noret`.
- Pitfalls: `ret`-containing chains fault under SHSTK — the crash looks like
  movaps-misalign but is CET; IBT endbr64 landing pads required — start gadgets
  at `endbr` or the CPU faults.
- Sources: https://github.com/XDSEC/MoeCTF_2025/blob/main/official_writeups/Pwn/MoeCTF%202025%20Pwn%20Writeup.md · https://github.com/utsavthakur/agenticskills/blob/main/binary-protection-bypass/PROTECTION_BYPASS_MATRIX.md · https://github.com/yrudwls/ctf-writeup/blob/main/angstromCTF/2024/pwn/bap/README.md

## W60 — pointer-guard fs:0x30 + mangled exit-funcs ROL17 forge

- Signals: glibc 2.34+ + `__exit_funcs`/`dtor_list` target +
  `__pointer_chk_guard` at `fs:0x30` nonzero + `exit` trigger path.
- Steps: (1) leak guard (`fs:0x30` via arbitrary read or stack disclosure);
  (2) forge `stored = rol(ptr, 0x11) ^ guard` for each func/arg slot, `next =
  NULL` terminator; (3) poison tcache/largebin chunk to the funcs storage;
  (4) `exit` walks the list → controlled call with controlled args.
- Snippet: `mangle = lambda p, g: (((p << 0x11) | (p >> (64 - 0x11))) & 2**64-1) ^ g; write(exit_slot, p64(mangle(system, guard)) + p64(mangle(binsh, guard)))`.
- Pitfalls: guard zero-assumption crashes — always leak, never assume; singly
  linked — chain order matters; offset `tls-0x80+0x28/0x30` varies by version —
  confirm via `vmmap`/shipped libc.
- Sources: https://github.com/todordev/pentesting-skills/blob/main/skills/heap-exploitation/IO_FILE_EXPLOITATION.md · https://github.com/Kur1sulab/blackbox/blob/main/hack-heap-exploitation/IO_FILE_EXPLOITATION.md · https://samuzora.com/posts/fsop/fsop-analysis
