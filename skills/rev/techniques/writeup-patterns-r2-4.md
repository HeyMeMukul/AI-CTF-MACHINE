# R2 patterns W57–W64 — firmware, LLM decomp, anti-analysis diaries (bodies; index in SKILL.md)

## W57 — Firmware blob crypto (binwalk carve + key carve, offline decrypt)
- Signals: raw blob (no ELF magic), `binwalk` shows `squashfs`/`uImage`/`TRX`, crypto strings (`AES`, `ChaCha`, `S-box`) in bootloader, UART/firmware-update task shape.
- Steps: 1) `binwalk -e` carve, `strings` per stage 2) carve key/ciphertext blobs (high-entropy ranges adjacent to crypto calls) 3) re-impl decrypt offline (library, never hand-roll) 4) verify by re-encrypt byte-exact + boot-check string.
- Commands: `binwalk -e ./fw.bin -C ./fw_out` ; `strings -n 8 ./fw_out/* | grep -m10 -i 'aes\|chacha\|key\|decrypt'` ; `python3 -c "from Crypto.Cipher import AES; print(AES.new(k, AES.MODE_ECB).decrypt(ct)[:32])"`.
- Pitfalls: wrong endianness on carved key; compressed-before-encrypted order (carve after decompress); bootloader vs app key confusion.
- Sources: [24437](https://ctftime.org/writeup/24437) · [24452](https://ctftime.org/writeup/24452) · [24476](https://ctftime.org/writeup/24476)

## W58 — Bootloader stage decrypt (multi-stage, dump-at-handoff)
- Signals: stage1 decrypts stage2 at fixed RAM addr, `strace`-equivalent is UART log, static view is stage1 only by design.
- Steps: 1) emulate stage1 in Unicorn/QEMU to handoff addr (cap insns) 2) dump stage2 from emulated RAM at handoff 3) analyze stage2 offline (normal loop) 4) never fight stage1 crypto statically.
- Commands: `qemu-system-arm -M <board> -kernel ./stage1.bin -s & gdb -ex 'target remote :1234' -ex 'break *<handoff>'` (then `dump memory stage2.bin <start> <end>`) ; `file ./stage2.bin`.
- Pitfalls: dumping pre-handoff (still encrypted); load-addr vs file-offset confusion; peripheral MMIO reads stalling emulator (stub them).
- Sources: [24437](https://ctftime.org/writeup/24437) · [24452](https://ctftime.org/writeup/24452) · [29593](https://ctftime.org/writeup/29593)

## W59 — LLM-assisted decompilation (draft + human verify, never blind trust)
- Signals: huge function (10k+ lines decompile), time-boxed hard rev, Ghidra output compiles but unreadable, Flare-On-12-style LLM pipeline available.
- Steps: 1) Ghidra headless dump the target function only 2) LLM rename/retype pass (one function, temperature 0) 3) human verify every branch against disasm (LLM invents bounds) 4) solve verified output, cite model+prompt in notes.
- Commands: `$GHIDRA/support/analyzeHeadless /tmp/gproj CTFproj -process chal -noanalysis -scriptPath ./scripts -postScript DumpOne.py <addr>` ; LLM pass on dump file, then `diff -u dump.orig dump.llm | head -n 60` (verify-only).
- Pitfalls: LLM-hallucinated constants (always diff); whole-binary LLM (context overflow, garbage); solving LLM output without binary-agree check (3+ probes required).
- Sources: [01-DrillBabyDrill](https://github.com/expend20/flare-on-12-llm-solution/tree/master/01-DrillBabyDrill) · [06-ChainOfDemands](https://github.com/expend20/flare-on-12-llm-solution/tree/master/06-ChainOfDemands) · [writeup.md](https://github.com/ZhangZhuoSJTU/ctf-collection/blob/main/ctf-rev/flareon12_2025_chain_of_demands/writeup.md)

## W60 — LLM variable-structure recovery (structs + vtables from stripped C++)
- Signals: stripped C++ with vtables, `new`/`delete` patterns, Ghidra shows `this+0x18` everywhere, class hierarchy recoverable from ctor order.
- Steps: 1) list ctors/vtables (`afl` + `vtable` grep) 2) LLM propose struct layouts from ctor stores 3) apply ONE layout, re-decompile, check field use 4) iterate once, then solve (cap 2 rounds).
- Commands: `r2 -A -q -c 'afl~ctor,vtbl; iz' ./chal | head -n 20` ; LLM struct pass, then Ghidra `Edit Data Type` apply.
- Pitfalls: vtable order vs ctor order mismatch (multiple inheritance); LLM over-merging distinct structs; endless refine loop (cap 2).
- Sources: [03-pretty_devilish_file](https://github.com/expend20/flare-on-12-llm-solution/tree/master/03-pretty_devilish_file) · [04-UnholyDragon](https://github.com/expend20/flare-on-12-llm-solution/tree/master/04-UnholyDragon) · [writeup.md](https://github.com/ZhangZhuoSJTU/ctf-collection/blob/main/ctf-rev/buckeye_2025_befuddled/writeup.md)

## W61 — Timing + CPUID + TracerPid ordered bypass (one-at-a-time diary)
- Signals: `clock_gettime`/`rdtsc` deltas bracket compare + `cpuid` hypervisor-bit check + `/proc/self/status` `TracerPid` string, instrumented runs fail but native passes.
- Steps: 1) prove each: `strace` clock deltas, `cpuid` in disasm, `TracerPid` string 2) bypass singly in discovery order (freeze clock → patch CPUID branch on COPY → fake TracerPid via `open` hook) 3) re-test after EACH, log before/after 4) dump-then-offline if combined still fails.
- Commands: `./chal <<< TEST; echo ---; strace -f -e trace=clock ./chal <<< TEST 2>&1 | head` ; `grep -a -m3 'TracerPid' ./chal` ; Frida `clock_gettime->fixed`, `open(TracerPid)->fake` hooks one-at-a-time.
- Pitfalls: stacking all bypasses (hides real check); `rdtsc` in VM (native timing differs); patching original.
- Sources: [30886](https://ctftime.org/writeup/30886) · [36907](https://ctftime.org/writeup/36907) · [29593](https://ctftime.org/writeup/29593)

## W62 — Fork-watchdog + signal bypass (parent kills traced child)
- Signals: `fork`/`clone` + `waitpid`/`kill` in `strace -f`, child dies only under trace, `SIGALRM`/`SIGTRAP` handlers in disasm.
- Steps: 1) `strace -f` to map parent/child roles 2) Frida spawn with child-gating (follow child) or `gdb 'handle SIGALRM ignore'` + `catch syscall ptrace` zero 3) fix in discovery order (ptrace first, signal second) 4) one retry, then dump-then-offline.
- Commands: `strace -f -e trace=process,signal ./chal <<< TEST 2>&1 | grep -m10 'clone\|fork\|kill\|ptrace'` ; `gdb -q ./chal -ex 'catch syscall ptrace' -ex 'handle SIGALRM ignore' -ex run -ex 'set $rax=0' -ex continue`.
- Pitfalls: attaching to parent when checker is in child (wrong proc); signal to wrong thread under `-f`; watchdog timer (must dump fast, `timeout 20`).
- Sources: [36907](https://ctftime.org/writeup/36907) · [30886](https://ctftime.org/writeup/30886) · [29593](https://ctftime.org/writeup/29593)

## W63 — Debugger-fed keys part 2: CPUID/timing-fed derivation (not just ptrace)
- Signals: `cpuid`/`rdtsc` output flows INTO key schedule (not just gate), patched run yields half-readable output (see W17 for ptrace flavor).
- Steps: 1) clean vs instrumented diff (delta bytes = environment-fed key material) 2) force clean values under instrumentation (hook `cpuid`/`rdtsc` to clean-trace values) 3) re-derive with forced values 4) verify on native binary x2.
- Commands: `LD_PRELOAD=./fake.so ./chal` vs `./chal` (diff outputs) ; Frida `Interceptor.replace(cpuid...)` / `rdtsc->fixed` to clean values.
- Pitfalls: solving under instrumentation (bakes wrong bytes); assuming env-check is gate-only (read dataflow, not just branch).
- Sources: [30886](https://ctftime.org/writeup/30886) · [36907](https://ctftime.org/writeup/36907) · [36292](https://ctftime.org/writeup/36292)

## W64 — Anti-emulation / sandbox-evasion triage (is-VM → is-sandbox → real logic)
- Signals: `cpuid` hypervisor bit + `IsDebuggerPresent` + registry/VMware strings + sleep-skips, Frida detected (process exits on hook).
- Steps: 1) map all env checks (strings + imports) before hooking 2) emulate offline (Unicorn, no hooks to detect) or patch checks on COPY 3) Frida only after env checks pass (late-attach, `-p` after startup) 4) dump-then-offline if Frida still detected.
- Commands: `strings ./chal | grep -m10 -i 'vmware\|vbox\|qemu\|sandbox\|debug'` ; `frida -p <pid>` (late-attach, not `-f` spawn) ; Unicorn offline lift as fallback.
- Pitfalls: spawn-hook (detected at startup); patching original; cloud-sandbox network check (external, pivot).
- Sources: [36907](https://ctftime.org/writeup/36907) · [29593](https://ctftime.org/writeup/29593) · [README.md](https://github.com/BYU-CSA/BYUCTF-2026/blob/main/rev/rcaas/README.md)
