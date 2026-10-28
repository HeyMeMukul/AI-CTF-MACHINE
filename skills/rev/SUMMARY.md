# rev SUMMARY (quickref)

Triage (<=5m): `file; strings|grep; rabin2 -I/-S; nm -D; upx -t; entropy`.
Classify: checker | VM/crypto | packed | .NET/Go/pyc/APK/WASM.

x64 SysV args `rdi,rsi,rdx,rcx,r8,r9` ret `rax`; Win64 `rcx,rdx,r8,r9`.
`cmp/test+jcc` = branch; `bl`=call `bx lr`=ret ARM, args `r0-r3`.
Checker signs: strcmp/memcmp, XOR loop, b64 table `+/=`, S-box.

Ghidra: `analyzeHeadless /tmp/gproj CTFproj -import ./chal`;
re-run `-process chal -noanalysis -postScript X.py`.
MCP: `decompile_function(main)` first, then `search_symbols_by_name`,
`search_code(xor)`, `list_xrefs`, `rename_function`.
r2: `r2 -A; s main; pdf; afl; axt <addr>; iz`.
Dynamic: `ltrace -s200 -o t.log ./chal <<<'AAAA'` (strcmp args?);
`strace -f -o s.log` (ptrace? mprotect RWX = packer?).
rodata: `objdump -s -j .rodata ./chal|head -60` (key/ciphertext blob?).

angr template: BVS stdin/argv, printable `0x20-0x7e`,
hook scanf, `sim.explore(find=WIN, avoid=FAIL)`, `timeout 120`.
Frida: hook strcmp/memcmp log + `ptrace->0` bypass, `frida -q -l hook.js -f ./chal --`.
Unpack: `upx -d -o out`; else Frida dump at OEP (mprotect RWX signal).

Tracks: .NET=dnSpy/ilspycmd; Go=`main.main`; pyc=uncompyle6/pycdc;
APK=`apktool d`+`jadx`; WASM=`wasm2c`.
Obfuscation: opaque preds->dynamic only; runtime XOR->Frida dump/brute;
timing->fake clock; flattening->trace executed blocks.
Patch: `cp chal chal.patch`, `je(0x74)->jmp(0xEB)`, run, restore orig.
Negatives: stable ltrace 2nd arg = plaintext; changing = hash/rand.
No .rodata blob + file/net reads = external secret, pivot out.
angr fails: verify find/avoid addrs (`r2 'pd 10 @ <addr>'`), scanf hook, N.

Gates: 1 Baseline triage | 2 Confirm decompile+ltrace |
3 Negative (plaintext? packed? lying CFG?) |
4 ONE exploit <=120s (angr|frida|patch|reimpl) |
5 Validate: re-run x2, sha256, handoff JSON (method+addrs+cmd).
3 fails -> blocked. Technique-only, no real flags.

Hard playbook: VM=dispatcher+handler-table+bytecode blob, trace-once
then lift traced path only (never symbolic over whole VM loop).
Packer=OEP hunt via last mprotect(RWX)->fresh-RX landing, Frida/Unicorn
dump, re-import; IAT rebuild only if dump must run.
Anti-debug: ptrace->0, freeze clock_gettime, 0xCC->nop on copy,
TracerPid fake, IsDebuggerPresent->0; bypass ONE at a time.
Deobf: z3-prove opaque preds (sampling first), avoid= dead arm.
Go=pclntab recovery->main.main (ptr,len) slices; Rust=demangle+
panic-string xref, solve ONE monomorphized instance.
WASM=wasm2c->grep check, wat export map, wasmtime round-trip.
Unicorn=map segments, cap 2M insns, stop at RIP-in-fresh-RX.
Decoder-reuse: Frida hook decoder exit, log all plaintexts.

Chains: packed->dump->lift->keygen (validate on ORIG);
VM->map->lift(equiv on 3+ probes)->solve; crypto->reuse consts->reimpl
(re-encrypt byte-exact) ->verify.
Failures F1-F7: stripped=entry->libc_start_main; angr boom=halve N+
avoid; spawn beats attach; Ghidra clear+redefine; UPX-magic=dynamic
dump; hash->never angr; arch/convention re-check.
Drift: backup ghidra_proj, pin angr/claripy/frida-server versions,
ship tool_versions.txt.
Tiers: easy<=20m medium<=1h hard<=3h insane=30m recon->operator.
Escalate: /pwn runtime secret+overflow; /crypto Feistel/RSA;
operator OEP-failed-x2/GUI/driver (include F-nums+artifacts).

Writeup patterns W1-W32 (see SKILL.md, mined from 572 writeups):
capstone array-lift->slice-z3 (W1); flag-suffix known-plaintext (W2);
CFG+Dijkstra mazes (W3); loads-only layered-py unwrap (W4); gate-is-key (W5);
Unicorn CRT-inits-first (W6); S-box source-ID (W7); per-byte no-diffusion (W8);
RSRC-LZMA carve (W9); decoy-vs-dead-code (W10); strace-FD inner-ELF dump (W11);
Rust resym-first (W12); ptrace-fed keys (W17); layered ptrace+signal order (W19);
manual-UPX break-at-OEP (W20); EIP-as-key (W23); XMM-shuffle model (W25);
WASI triage (W27); JS-wasm memory bridge (W28); compare-arg intercept (W29);
method-reuse over re-impl (W30); dual-runtime triage (W31); state-var deflat (W32).
R2 W33-W64 (491 NEW hard, 0% overlap; bodies in techniques/writeup-patterns-r2-*.md):
VM trace-diff/disas/nested/Feistel/linearize (W33-W37); Themida-OEP/VMProtect-lite/IAT/stolen (W38-W41);
angr-z3 handoff/solver-first/Unicorn-assist/veritesting (W42-W45); MBA/CFF-hybrid/bogus-slice (W46-W48);
Il2Cpp/Confuser/Blazor/PYZ-native (W49-W52); Flutter-snap/Dart-AOT/EVM-disasm/storage (W53-W56);
fw-carve/stage-dump (W57-W58); LLM-decompile/struct (W59-W60); timing-CPUID-TracerPid/fork/env-fed/anti-emu (W61-W64).
