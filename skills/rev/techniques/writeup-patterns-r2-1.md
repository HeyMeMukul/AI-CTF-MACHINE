# R2 patterns W33–W40 — VM deep-dives + Themida/VMProtect (bodies; index in SKILL.md)

## W33 — Handler devirtualization via trace-diff (concrete pair + per-opcode semantics)
- Signals: custom VM with numbered handlers (5–60 opcodes), dispatcher `switch(vpc)` + handler table, bytecode blob in `.rodata`, two runs on `AAAA` vs `BBBB` diverge at 1–3 handlers.
- Steps: 1) recover handler table addrs (`pxq` in r2) + bytecode range 2) Frida Stalker trace on two known inputs, diff handler sequences 3) implement each executed handler in Python (one function per opcode, assert on concrete pair) 4) lift only the accept-path, z3 over lifted ops.
- Commands: `r2 -A -q -c 'pxq 64 @ <table>' ./chal` ; `frida -q -l trace_vm.js -f ./chal -- <<< 'AAAA' 2>&1 | cut -d: -f1 | sort | uniq -c` (repeat `BBBB`, diff) ; `python3 vm_lift.py AAAA` (must agree with binary on 3+ probes).
- Pitfalls: full-VM symbolic (state explosion); handler with implicit flags (carry/zero) missed; vpc increment vs handler-local jump confusion; endianness on multi-byte immediates.
- Sources: [32557](https://ctftime.org/writeup/32557) · [607be4ea33c5d45ca9489659](https://crackmes.one/solution/607be4ea33c5d45ca9489659) · [5ab950ba33c5d422feed87a5](https://crackmes.one/solution/5ab950ba33c5d422feed87a5)

## W34 — Bytecode disassembler-first (opcode table → asm listing before solve)
- Signals: VM blob + handler count stable, no crypto names, handlers map cleanly to `mov/add/xor/jcc/exit`.
- Steps: 1) dump table + blob 2) write `vm_dis.py` printing `offset: OP args` 3) eyeball disasm for checker shape (compare loop, Feistel rounds) 4) re-impl/invert the disasm, never the raw handlers.
- Commands: `objdump -s -j .rodata ./chal | head -n 60` ; `python3 vm_dis.py ./blob.bin | head -n 100` ; `python3 -c "import vm_dis; vm_dis.run(b'AAAA')"` (trace-agree check).
- Pitfalls: variable-length bytecode mis-split (one wrong length cascades); immediate-vs-register operand confusion; self-modifying bytecode (dump after unpack, not static).
- Sources: [36907](https://ctftime.org/writeup/36907) · [5ab950ba33c5d422feed8790](https://crackmes.one/solution/5ab950ba33c5d422feed8790) · [5ab950c133c5d422feed89c1](https://crackmes.one/solution/5ab950c133c5d422feed89c1)

## W35 — Nested (matryoshka) VM: outer handler runs inner bytecode
- Signals: handler body itself contains a second dispatcher loop; two bytecode blobs; single-step trace shows dispatch-inside-dispatch.
- Steps: 1) lift outer to identify `INNER_RUN` handler 2) carve inner blob (argument to that handler) 3) dis the inner VM separately 4) solve inner first, feed result as outer key.
- Commands: `frida -q -l trace_vm.js -f ./chal -- 2>&1 | grep -c 'dispatch'` (nested = 2 levels) ; `python3 outer_dis.py | grep -m5 INNER` ; `python3 inner_solve.py` (then outer).
- Pitfalls: solving outer before inner (key dependency reversed); inner vpc reset per outer step missed; shared register file clobbered.
- Sources: [62e45a1133c5d44a934e9a3d](https://crackmes.one/solution/62e45a1133c5d44a934e9a3d) · [5ab950b833c5d422feed86fd](https://crackmes.one/solution/5ab950b833c5d422feed86fd) · [32557](https://ctftime.org/writeup/32557)

## W36 — VM-embedded Feistel/SPN round invert (crypto inside the VM)
- Signals: VM handlers include S-box + rotate + round-key schedule; lifted dis shows 8/16/32 repeated rounds with half-swap.
- Steps: 1) lift to round function `R(L,R,k)` 2) prove Feistel (one half passes through) 3) invert rounds backward from ciphertext with round keys in reverse 4) verify by re-encrypting forward byte-exact.
- Commands: `python3 -c "from Crypto.Cipher import AES; print('sbox-hit' if bytes in blob else 'custom')"` (S-box ID first) ; `python3 feistel_inv.py` (round-reverse, then forward-check).
- Pitfalls: custom S-box mistaken for AES; round-key order (forward vs reverse); half-swap on last round (sometimes omitted).
- Sources: [36292](https://ctftime.org/writeup/36292) · [29043](https://ctftime.org/writeup/29043) · [6a392adf6840520e01b21f2d](https://crackmes.one/solution/6a392adf6840520e01b21f2d)

## W37 — Dispatcher concretization (patch dispatch to linear trace)
- Signals: flattened VM loop where dispatcher dominates runtime; symbolic stalls but concrete runs fast.
- Steps: 1) trace one accept + one reject path concretely 2) NOP the dispatcher back-edges on a COPY so the traced path is linear 3) run angr/z3 over the linearized copy 4) validate candidate on ORIGINAL.
- Commands: `cp ./chal ./chal.lin` ; `python3 - <<'EOF'
d=bytearray(open('./chal.lin','rb').read()); d[off]=0x90*3  # dispatcher jmp on copy only
open('./chal.lin','wb').write(d)
EOF` ; `timeout 120 python3 solve_angr.py ./chal.lin` (then `./chal <<< "$CAND"` x2).
- Pitfalls: patching original; linear path overfit to one input (must include branch on input); ASLR shifting patch offset.
- Sources: [32472](https://ctftime.org/writeup/32472) · [31246](https://ctftime.org/writeup/31246) · [32557](https://ctftime.org/writeup/32557)

## W38 — Themida OEP via API-break (VirtualAlloc/mprotect bracket + dump)
- Signals: Themida markers (`Themida`, `.themida`, `VMProtect` strings), tiny imports, `strace` shows `mprotect(RWX)` + `mmap` bursts pre-prompt, `upx -d` fails.
- Steps: 1) `strace -f -e trace=memory` to bracket unpacker 2) Frida break on `mprotect` return, Stalker until RIP leaves stub into fresh RX (OEP) 3) dump ELF range at OEP, re-import to Ghidra 4) resume normal loop on dump, validate on original.
- Commands: `strace -f -e trace=memory,process ./chal <<< 'TEST' 2>&1 | grep -m10 'mprotect\|mmap'` ; `diec ./chal 2>/dev/null || die ./chal` ; Frida OEP-dump (Playbook B scaffold) then `file ./dump.elf`.
- Pitfalls: dumping too early (pre-decrypt); broken IAT treated as failure (fine for reading); fighting stub statically.
- Sources: [1504](https://ctftime.org/writeup/1504) · [1531](https://ctftime.org/writeup/1531) · [5ab950bb33c5d422feed87d0](https://crackmes.one/solution/5ab950bb33c5d422feed87d0)

## W39 — VMProtect handler trace + devirt-lite (commercial VM handlers)
- Signals: `VMProtect` section names, handler table with 100+ entries, dispatcher with `pushfq/rtdsc` anti-trace, valid license-check shape.
- Steps: 1) OEP dump first (W38) 2) trace handlers on COPY under emulation (Unicorn) to dodge anti-trace 3) lift executed handlers only (5–15 used of 100+) 4) re-impl checker from lift.
- Commands: `rabin2 -S ./dump.elf | head -n 20` ; `python3 unicorn_trace.py` (cap 2M insns, stop at fresh-RX) ; `python3 lift_used.py` (executed-only).
- Pitfalls: full-devirt of 100+ handlers (weeks); anti-trace `rdtsc` deltas misread as logic; license-server network read (external secret, pivot).
- Sources: [5ab950ba33c5d422feed8792](https://crackmes.one/solution/5ab950ba33c5d422feed8792) · [5ab950b833c5d422feed8700](https://crackmes.one/solution/5ab950b833c5d422feed8700) · [36907](https://ctftime.org/writeup/36907)

## W40 — IAT rebuild concept for runnable dumps (Scylla-style, only if dump must run)
- Signals: OEP dump analyses fine in Ghidra but segfaults when run (broken imports, `call [iat+off]` to garbage).
- Steps: 1) confirm analysis-OK/run FAIL split 2) list runtime-resolved imports via Frida `Module.enumerateImports` at OEP 3) rebuild IAT on COPY (Scylla/hook concept) only if you must execute the dump 4) prefer solving ORIGINAL past OEP (no rebuild) when possible.
- Commands: `frida -q -l iat.js -f ./chal -- 2>&1 | grep -m20 'resolve'` ; `rabin2 -i ./dump.elf | head` (compare vs live).
- Pitfalls: rebuilding IAT to run when static solve suffices (wasted hour); original-vs-dump addr confusion in handoff.
- Sources: [1504](https://ctftime.org/writeup/1504) · [5ab950bb33c5d422feed87d1](https://crackmes.one/solution/5ab950bb33c5d422feed87d1) · [1531](https://ctftime.org/writeup/1531)
