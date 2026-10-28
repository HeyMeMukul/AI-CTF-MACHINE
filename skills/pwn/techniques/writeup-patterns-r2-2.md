# PWN writeup patterns R2-2 — W41..W50 (seccomp/SROP/dlresolve/fmt)

> Technique-only. Bodies for SKILL.md R2 index W41–W50. Signals → steps →
> pwntools snippet → pitfalls → 2–3 R2 manifest sources. No flags.

## W41 — seccomp ORW golf (sub-60B open/read/write + openat)

- Signals: `seccomp-tools dump` shows execve KILL + open/openat+read+write ALLOW
  + tiny shellcode buffer (<80B) or filtered bytes.
- Steps: (1) dump filter first, classify KILL vs clean-empty; (2) if `open`
  blocked but `openat`(257) allowed, use `openat(AT_FDCWD=-100, path, 0)`;
  (3) golf shellcode: push path on stack (position-independent), `open → read →
  write` in minimal bytes; (4) staged variant: 24B part-1 `read(0, buf, big)` +
  jump, part-2 full ORW when buffer too small for path + code.
- Snippet: `sc = asm(shellcraft.openat(-100, path, 0) + shellcraft.read('rax', 'rsp', 0x100) + shellcraft.write(1, 'rsp', 0x100))`.
- Pitfalls: `read` blocked → `pread64`/`readv`; `write` blocked →
  `writev`/`sendfile`; pre-opened-fd tasks skip `open` entirely (brute fds
  3,4,5); wrong path looks like KILL — check exit status/signal first.
- Sources: https://wiki.athena-ctf.com/docs/pwn/shell-code · https://github.com/KorekKayu/IKONA-Security/blob/main/IKONA_HACKSKILLS/sandbox-escape-techniques/SECCOMP_BYPASS.md · https://ctftime.org/writeup/39717

## W42 — seccomp-notify / ptrace / arch-confusion bypass concept

- Signals: seccomp filter ALLOW-list is tight (no open/read/write either) but
  `ptrace`, `io_uring`, or 32/64-bit number-mismatch surface exists + kernel
  version noted.
- Steps: (1) enumerate allowed syscalls beyond ORW (`sendfile`/`splice`/`tee`/
  `process_vm_readv`); (2) if `ptrace` allowed, inject syscalls into a traced
  child; (3) on x86-64 check 32-bit `int 0x80` vs `syscall` number confusion
  gaps; (4) kernel <5.1 = no io_uring — skip uring paths; else model SQ/CQ
  submit as an async-syscall oracle (concept only — see W57).
- Snippet: `sendfile(1, 3, 0, 0x100)  # stdout <- fd3 without read/write pair`.
- Pitfalls: arch-confusion needs matching 32-bit frame — never mix 64-bit regs;
  notify/ptrace needs a child process — single-process targets can't use it;
  always re-dump the filter after each hypothesis change.
- Sources: https://github.com/KorekKayu/IKONA-Security/blob/main/IKONA_HACKSKILLS/sandbox-escape-techniques/SECCOMP_BYPASS.md · https://github.com/AmesianX/kernel-exploit-dojo/blob/main/2024/UIUCTF_2024/Pwn_Syscalls_2/writeup/writeup01/solve_io_uring.txt · https://seclists.org/oss-sec/2024/q2/172

## W43 — SROP read-first + read-len rax=15 (no pop-rax gadget)

- Signals: almost no gadgets (tiny binary, no `pop rax`/`pop rdi`) + `read` +
  `syscall;ret` present + stack overflow.
- Steps: (1) overflow to `read(0, rsp_frame, big)` so the kernel-reported byte
  count lands in `rax`; (2) send exactly 15 bytes first so `rax == 15`
  (sigreturn number) on return; (3) return to `syscall;ret` → kernel restores
  the `SigreturnFrame` lying at known `rsp`; (4) frame sets
  `rax=59/rdi=binsh/rip=syscall` (or ORW numbers under seccomp).
- Snippet: `frame = SigreturnFrame(); frame.rax = 59; frame.rdi = binsh; frame.rip = syscall_ret  # after read-len sets rax=15`.
- Pitfalls: frame must sit at the exact `rsp` the kernel reads — off-by-8 =
  garbage registers; stack must be stable (no further input mid-frame); 15-byte
  read must be exact or `rax != 15`.
- Sources: https://wiki.athena-ctf.com/docs/pwn/sigreturn-rop · https://www.cse.iitb.ac.in/~khushangsingla/blog/writeups/2k23/iitbctf/writeup-iitbctf-round1-srop · https://github.com/MedjberAbderrahim/CTF-Writeups/blob/main/2025/QnQSecCTF/pwn/notez/writeup.md

## W44 — SROP arm64 (x8/x0/pc + svc + vDSO sigreturn)

- Signals: aarch64 binary + `svc #0` + way to set `x8 = 0x8b` (rt_sigreturn) +
  stack overflow + ASLR music (vDSO consideration).
- Steps: (1) overflow to sigreturn-call site (`mov x8, #0x8b; svc #0` in binary
  or leaked vDSO `__kernel_rt_sigreturn` at base+0x7b0); (2) lay arm64
  `SigreturnFrame` with `x8 = SYS_execve`, `x0 = binsh`, `x1 = x2 = 0`,
  `pc = svc_gadget`; (3) recent arm64 kernels are stricter — hand-craft the
  frame via pwntools (never hand-layout); (4) chain SROP→mprotect for
  shellcode-stage when execve is filtered.
- Snippet: `frame = SigreturnFrame(); frame.x8 = constants.SYS_execve; frame.x0 = binsh; frame.pc = svc_call`.
- Pitfalls: x86 `rax/rdi/rip` names do NOT apply — arm64 uses `x8/x0/pc`;
  vDSO base must be leaked under ASLR; env-pointer `/bin/sh` trick needs
  controlled envp when no string in binary.
- Sources: https://hacktricks.wiki/hi/binary-exploitation/rop-return-oriented-programing/srop-sigreturn-oriented-programming/srop-arm64.html · https://book.jorianwoltjer.com/binary-exploitation/return-oriented-programming-rop/sigreturn-oriented-programming-srop · https://github.com/MedjberAbderrahim/CTF-Writeups/blob/main/2025/QnQSecCTF/pwn/notez/writeup.md

## W45 — SROP constrained (UTF8/charset + mov-only + mprotect pivot)

- Signals: SROP-capable but input charset-limited (UTF8/alpha/palindrome/mov-only)
  or NX + no executable staging + `mprotect` reachable.
- Steps: (1) build charset-compliant stage-1 (mov-only/alpha encoder) that issues
  `read` for stage-2; (2) SROP frame calls `mprotect(addr, len, RWX)` instead of
  direct execve; (3) pivot `rsp` to the now-executable stage-2 shellcode/ORW;
  (4) under seccomp prefer ORW register set in the post-mprotect frame.
- Snippet: `frame.rax = 10; frame.rdi = page; frame.rsi = 0x1000; frame.rdx = 7  # mprotect RWX then pivot`.
- Pitfalls: encoder size blows the overflow budget — two-stage is mandatory, not
  optional; `mprotect` addr must be page-aligned; signal-frame pad must be exact
  or `mprotect` args shift.
- Sources: https://github.com/ljagiello/ctf-skills/blob/main/ctf-pwn/advanced-exploits.md · https://wiki.athena-ctf.com/docs/pwn/sigreturn-rop · https://ctftime.org/writeup/39717

## W46 — ret2dlresolve-64 data_addr + reloc-index edge

- Signals: 64-bit + Partial/No RELRO (Full kills it) + stack overflow + write
  primitive (`read`/`gets`) + writable `.bss` + NO leak function.
- Steps: (1) `Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh'])`;
  (2) `rop.read(0, dl.data_addr)` forges Sym/Rel/str into `.bss`;
  (3) `rop.ret2dlresolve(dl)` invokes plt_init with forged reloc offset;
  (4) second input round feeds `dl.payload`; needs loop-back (`main`/vuln) or
  stack-pivot re-entry; (5) `rop.dump()` must show `read` then `[plt_init]`
  with large reloc index.
- Snippet: `dl = Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh']); rop.read(0, dl.data_addr); rop.ret2dlresolve(dl)`.
- Pitfalls: fault at plt_init = bad index alignment — regenerate, never hand-tweak
  struct bytes; `dl.data_addr` must be truly writable (`elf.bss()` + margin);
  Full RELRO detection via `checksec` BEFORE building (saves an hour).
- Sources: https://github.com/JorianWoltjer/practical-ctf/blob/main/binary-exploitation/return-oriented-programming-rop/ret2dlresolve.md · https://github.com/s3mPr1linux/hacktricks-fork/blob/master/binary-exploitation/rop-return-oriented-programing/ret2dlresolve.md · https://hacktricks.wiki/en/binary-exploitation/rop-return-oriented-programing/ret2dlresolve.html

## W47 — fake-link_map dl-resolve (no-plt-init / JMPREL forge)

- Signals: 64-bit + resolver path nonstandard (stripped/custom PLT, XDCTF2015
  lineage) + `.bss` staging + `read` gadget + need `system` without libc leak.
- Steps: (1) forge fake `link_map` (`l_addr` + `DT_JMPREL`/`DT_SYMTAB`/
  `DT_STRTAB` pointers into controlled `.bss`); (2) forge `Rel`/`Sym` with
  `r_offset` = writable addr + `r_info` index 0; (3) ROP `read` writes the map,
  then call `_dl_runtime_resolve(link_map, index)` direct with `/bin/sh` in
  `rdi`; (4) verify with `rop.dump()` — resolution addr should be a callable GOT
  slot, not wild memory.
- Snippet: `linkmap += p64(fake + 0x18)  # JMPREL; linkmap += p64(fake_rel)  # index-0 Rel; rop.call(resolve, [linkmap, 0])`.
- Pitfalls: `DT_*` pointer math is layout-exact — one wrong `+0x8` and resolution
  reads garbage; 32-bit vs 64-bit `Rel`/`Rela` struct sizes differ — never mix
  templates; needs the same second-input-round discipline as W46.
- Sources: https://github.com/XDSEC/MoeCTF_2025/blob/main/official_writeups/Pwn/MoeCTF%202025%20Pwn%20Writeup.md · https://ctf-wiki.org/en/pwn/linux/user-mode/stackoverflow/x86/advanced-rop/ret2dlresolve · https://github.com/BiancaDogareci/Return-to-libc-and-ret2dlresolve-Attacks-on-x86-64/blob/main/Presentation.pdf

## W48 — fmt ascending-hn + numbwritten + exit-GOT two-round loop

- Signals: `printf(user)` + writable GOT (Partial RELRO) + `win`/`system` target
  + 64-bit addrs at buffer end + no loop-back symbol (must CREATE the loop).
- Steps: (1) sweep `%i$p` to fix offset; (2) round-1 overwrites `exit@GOT` with
  `main`/`vuln` (creates the second round) AND leaks canary/PIE/libc;
  (3) round-2 splits 4B/8B values into ascending 2B `hn` writes with cumulative
  `%<n>c` pads in address order via
  `fmtstr_payload(OFF, writes, write_size='short', numbwritten=pad)`;
  (4) re-sweep offset in round-2 — it may shift after the loop rewrite.
- Snippet: `fmtstr_payload(OFF, {elf.got.exit: elf.sym.main}, write_size='short')  # round-1 loop; then fmtstr_payload(OFF2, {elf.got.printf: system}, write_size='short')`.
- Pitfalls: descending writes wrap past `0xffff` — always sort ascending prior
  bytes count toward the pad (`numbwritten`); exit args consumed before flush —
  ensure format reaches before `exit(1)`.
- Sources: https://github.com/yrudwls/ctf-writeup/blob/main/angstromCTF/2024/pwn/bap/README.md · https://www.cnblogs.com/undefined/articles/18827559 · https://github.com/XDSEC/MoeCTF_2025/blob/main/official_writeups/Pwn/MoeCTF%202025%20Pwn%20Writeup.md

## W49 — fmt 1B/2B precision + wrap-avoid + post-loop offset re-sweep

- Signals: fmt write with tight value deltas (wrap risk) + 64-bit + Partial
  RELRO + second-round offset instability after GOT-loop rewrite.
- Steps: (1) compute all target shorts, sort ascending, pad cumulatively;
  (2) prefer 1B (`hhn`) writes where high bytes already match to avoid
  `0xffff` wrap; (3) after round-1 loop creation, re-run the `%i$p` sweep
  (stack layout shifts); (4) confirm each write with a read-back (`%s`/GOT
  dump) before chaining to ROP.
- Snippet: `fmtstr_payload(OFF2, {got: val & 0xffff}, write_size='short')  # ascending; re-swept OFF2`.
- Pitfalls: single unsorted write corrupts all later pads; `%hhn` vs `%hn`
  confusion overwrites neighbors — match write-size to the true delta;
  `gets`-terminated input truncates `\x0a` bytes in packed addrs — pad around.
- Sources: https://github.com/yrudwls/ctf-writeup/blob/main/angstromCTF/2024/pwn/bap/README.md · https://github.com/binneko/ctf-writeups/blob/main/2025/umdctf/pwn/gambling2/README.md · https://www.cnblogs.com/undefined/articles/18827559

## W50 — fork canary 256x7 + NUL-ABI + checkpoint/resume

- Signals: forking service (fork-without-execve) + canary + overflow + oracle
  (continue-vs-`stack smashing` / close / 502) + no fmt leak.
- Steps: (1) verify fork-stability: same leaked byte stable across 3 reconnects;
  (2) LSB known `0x00` first on amd64; brute remaining 7 bytes one at a time
  (worst ~1792 probes); (3) checkpoint known-good prefix to
  `artifacts/<task>/prefix.bin` every byte; (4) budget `probes × RTT` vs tier —
  1792 × 0.2s ≈ 6 min OK, × 2s ≈ 60 min hard-tier-only with resume.
- Snippet: `for guess in range(0x100): r = connect(); r.send(prefix + canary + p8(guess)); ok = b'MARKER' in r.clean(timeout=0.5)  # oracle`.
- Pitfalls: `gets`/`strcpy` alphabet truncates `\x00`/`\x0a` — skip them or use
  `read`/`recv`; `execve`-per-connection rerolls the canary (math void — must
  leak instead); pre-fork pools expose several canaries — pin to one worker
  generation and re-test the full prefix periodically.
- Sources: https://hacktricks.wiki/en/binary-exploitation/common-binary-protections-and-bypasses/stack-canaries/bf-forked-stack-canaries.html · https://blog.beatman.tw/en/articles/69ed65acc3a1bf5c78cef870 · https://ctf-wiki.org/pwn/linux/user-mode/mitigation/canary
