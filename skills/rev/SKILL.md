---
name: rev
description: Reverse-engineer CTF binaries via Ghidra headless + r2 + angr + Frida patch-and-run loop
category: rev
phase: 2-3
---
Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`; separate evidence from inference, preserve scope, validate each link, and label uncertainty.

# Rev Skill — Reverse Engineering for CTFs

## Mental Model

> A rev challenge is a checker program: it takes your input,
> transforms it, and compares it to a secret. Your job is to
> recover the transform and invert it — not to "understand everything".

Three archetypes cover ~90% of CTF rev:

1. **Checker** — `input -> transform -> compare -> win/lose`. Invert or patch.
2. **VM / custom crypto** — bespoke bytecode/cipher. Re-implement in Python.
3. **Stripped / obfuscated / packed** — hidden logic. Unpack first.

Core loop: **triage -> decompile (Ghidra) -> dynamic confirm
(ltrace/strace/Frida) -> solve (angr OR re-impl OR patch)**.
Flag path is usually within 2 hops of `main`; never start with full
manual disassembly. Budget: triage 5m, decompile 15m, dynamic 10m,
solve 15m. Stuck after 45m -> switch method, not more staring.

## Workflow

### Phase 1 — Baseline (static triage, read-only, <=5 min)

Goal: arch? stripped? packed? checker family? runtime? where is `main`?

```bash
file ./chal
checksec --file=./chal 2>/dev/null || true
strings -n 6 ./chal | head -n 80
strings -n 6 ./chal | grep -Ei -m20 'flag|correct|wrong|success|fail|password|key| Congrat'
rabin2 -I ./chal 2>/dev/null | head -n 30       # arch/bits/stripped/protections
rabin2 -S ./chal 2>/dev/null | head -n 30       # UPX? giant RWX?
nm -D ./chal 2>/dev/null | head -n 40           # strcmp? ptrace?
python3 -c "import math,collections; d=open('./chal','rb').read(); e=-sum(c/len(d)*math.log2(c/len(d)) for c in collections.Counter(d).values()); print(f'entropy={e:.2f} size={len(d)}')"
```

Packed detection (combine signals, none is definitive):

- `strings` tiny (<20 lines) + entropy >7.4 = packed.
- `UPX0`/`UPX1` sections, one giant RWX section, or
  `diec ./chal` reporting UPX/MPRESS/Themida.
- Imports only `LoadLibrary`/`GetProcAddress`/`mmap`/`mprotect` = hiding.
- Entry jumps into high-entropy blob before `main`.

Language/runtime signals: `.NET`=`PE32 Mono/.Net`+`mscorlib`;
Go=`main.main`+`runtime.gopanic`+`.gopclntab`; pyc=`0x0D0D` magic or
`PyEval_`/`PYZ`; APK=`classes.dex`; WASM=`\0asm` magic.

x86/x64 essentials:

- SysV x64 args `rdi,rsi,rdx,rcx,r8,r9`, ret `rax`; Win64 args
  `rcx,rdx,r8,r9` + 32B shadow space. First-arg register differs.
  x86 cdecl: stack args, caller cleans; stdcall: `ret N` cleans.
- `cmp a,b; jcc` / `test r,r; jz/jnz`. `test eax,eax; je fail` =
  null check. `cmp byte [rax+i],0x41; jne fail` = byte-check loop.
- `push rbp; mov rbp,rsp; sub rsp,N` frame; `[rbp-X]` locals.
  `read(0,buf,0x40)` into stack buf = pwn overlap.
- `lea rax,[rel sym]` = PIC; `call rax` after resolve = hidden import.

ARM basics: args `r0-r3`/`x0-x7`, ret `r0`/`x0`; `bl`=call,
`bx lr`=return, `cbz/cbnz`=branch-on-zero. Checker loops look like
`ldrb w8,[x0],#1; cmp w8,w1`. Garbage disasm -> flip Thumb/ARM variant.

Checker recognition cheat-sheet:

| Pattern in decompile/strings | Meaning | Invert method |
|---|---|---|
| `strcmp(input, "...")` / `memcmp` loop | plaintext compare | read rodata directly |
| `for i: out[i]=in[i]^K[i%N]` | repeating-XOR | `bytes(a^b)` with key from rodata |
| `ABCDEFGHIJKLMNOP...+/=` table | base64 | `base64.b64decode` (+ custom alphabet remap) |
| `S-box[256]` + key schedule loop | AES/RC4-ish | identify S-box bytes, re-impl decrypt |
| `rol/ror`, `a*31+c`, `md5/sha` names | hash check | brute small space or angr |
| `ptrace(PTRACE_TRACEME)` / `IsDebuggerPresent` | anti-debug | Frida bypass (see library) |

`Reasoning Checkpoint`: file type + arch + packed? + checker family + main located? If packed/VM/language-runtime -> jump to matching track below; else proceed to Phase 2 with `main` address.

### Phase 2 — Confirmation (decompile + dynamic behaviour, <=15 min)

Goal: confirm the checker hypothesis with ONE decompiler view
plus ONE dynamic trace. No blind guessing.

Ghidra headless workflow (server-less, scriptable):

```bash
export GHIDRA=/opt/ghidra
$GHIDRA/support/analyzeHeadless /tmp/ghidra_proj CTFproj \
  -import ./chal -postScript DumpDecompile.py 2>&1 | tail -n 30
# re-run script on existing import:
$GHIDRA/support/analyzeHeadless /tmp/ghidra_proj CTFproj \
  -process chal -noanalysis -scriptPath ./scripts -postScript ListStrings.py 2>&1 | tail -n 30
# batch import: -import ./given -recursive -analysisTimeoutPerFile 300
```

Inside Ghidra: open `main` (stripped? entry -> first
`__libc_start_main` arg). Decompile, rename `FUN_xxx` to
`check`/`win`/`fail`; `Retype Variable` (`char *`) fixes 50% of
garbage; string `References To` finds the checker; dump `.rodata`
via Memory Map or `getMemoryBlocks()` for Python re-impl.

GhidraMCP mapping: `decompile_function(main)` FIRST, then
`search_symbols_by_name("strcmp|check|win|fail|main")`,
`search_code("xor")`, `list_xrefs(addr)`,
`rename_function(old,new)`. Only drill into callees on the
success path. Cap ~10 MCP calls; fall back to headless dump.

radare2 / rizin quick commands:

```bash
r2 -A ./chal
s main; pdf             # seek main, print function
afl; axt 0x00402000; iz # functions, xrefs-to, strings
pdf @ sym.check         # disassemble checker
# rizin: same syntax under `rizin -A`
```

Dynamic confirmation (pick one):

```bash
ltrace -s 200 -o trace.log ./chal <<< 'TESTINPUT'   # strcmp args?
strace -f -e trace=process,read,write -o st.log ./chal <<< 'TEST'  # ptrace? files?
```

`Reasoning Checkpoint`: decompiled `main` path identified (input fn -> check fn -> win/fail addrs) + dynamic trace agrees (same compare observed)? Record `success_addr` (win branch) + `fail_addr` for angr/Frida. If decompile contradicts trace -> re-analyze (wrong `main`, Thumb mode, or packed) before Phase 3.

### Phase 3 — Negative testing (kill bad hypotheses, <=10 min)

Goal: disprove the two most common wrong turns before exploit budget.

1. **Plaintext compare?** `ltrace` 2nd arg stable across `AAAA` runs ->
   yes. Changes per run -> hash/randomized, not plaintext.
2. **Statically recoverable?** `.rodata` 16-64B blob -> key/ciphertext.
   No blob + file/network reads -> external secret, pivot out.
3. **Packed despite looking clean?** Zero libcalls pre-prompt, or
   `mprotect(RWX)` in strace = stub. Confirm `upx -t`.
4. **Decompiler lying?** Opaque preds / flattened `switch(state)` ->
   distrust CFG, go dynamic (Frida).

Quick negative probes:

```bash
echo AAAA | ltrace -s 300 ./chal 2>&1 | grep -i -m5 'strcmp\|memcmp\|strncmp'
objdump -s -j .rodata ./chal | head -n 40
rabin2 -z ./chal 2>/dev/null | grep -Ei -m10 'flag|key|enc|correct' || true
upx -t ./chal 2>&1 | head -n 5
```

`Reasoning Checkpoint`: which hypotheses survived? State explicitly:
"plaintext-compare CONFIRMED/DENIED because ...; packed YES/NO because ...".
Only surviving hypothesis enters Phase 4. If all denied -> escalate
to VM/obfuscation track, do not brute-force blindly.

### Phase 4 — Exploit, gated (ONE step, <=120s wall-clock)

Goal: run exactly ONE solve primitive. ONE step per gate — on fail,
return to Phase 3; no chained fallbacks inside Phase 4.

Option A — angr (small checker, hash-free, win/fail addrs known):

```bash
timeout 120 python3 solve_angr.py
```

Option B — Frida dump (obfuscated/self-modifying/runtime-XOR/anti-debug):

```bash
timeout 120 frida -q -l hook.js -f ./chal -- 2>&1 | tail -n 20
```

Option C — patch-and-run (`if (!check()) exit(1)` gate, need `win()` output):

```bash
cp ./chal ./chal.patch && printf '\x90\x90' | dd of=./chal.patch bs=1 seek=$((0x12ab)) conv=notrunc 2>/dev/null
timeout 20 ./chal.patch <<< 'anything'; echo exit=$?
```

Option D — Python re-impl (XOR/b64/RC4 fully understood):

```bash
timeout 60 python3 solve_reimpl.py
```

Pick ONE. Timer enforced by `timeout`. Record stdout to artifact.

`Reasoning Checkpoint`: which option ran, exit code, output contained
flag-pattern? If timeout/fail -> diagnose (wrong addrs? scanf hook
missing? see AI notes) then ONE corrected retry allowed.

### Phase 5 — Validation-handoff (prove it, package it)

Goal: reproducible flag capture + writeup inputs.

1. Re-run artifact from clean state (fresh `/tmp`, orig `chal` untouched).
2. Capture command + stdout + exit code + binary sha256.
3. Confirm flag format per challenge; never hardcode guesses.
4. Write `results/rev_<id>.json`; restore orig binary if patched.

```bash
sha256sum ./chal | tee results/rev_sha.txt
timeout 30 ./chal <<< "$SOLVED_INPUT" | tee results/rev_out.txt; echo exit=$?
# angr/frida solves: re-run script twice, outputs must match (deterministic)
timeout 120 python3 solve_angr.py | tee results/rev_out.txt
```

Handoff JSON:

```json
{"chal_id":"REV-001","method":"angr|frida|patch|reimpl",
 "artifact":"solve_angr.py","success_addr":"0x4012ab","avoid_addr":"0x4012c0",
 "command":"timeout 120 python3 solve_angr.py","output_sha256":"...","notes":"..."}
```

`Reasoning Checkpoint`: reproduced twice? original binary untouched?
handoff JSON written with method + addrs + command? If yes -> done;
Lead may `/validate`. If flaky -> mark `needs-retest`, do not claim flag.

## Tool Table (exact copy-paste commands)

| Task | Command |
|---|---|
| File + arch | `file ./chal; rabin2 -I ./chal` |
| Strings triage | `strings -n 6 ./chal \| head -n 80` |
| Flag-hint grep | `strings -n 6 ./chal \| grep -Ei -m20 'correct\|wrong\|success\|fail\|Congrat'` |
| Sections/pack | `rabin2 -S ./chal; upx -t ./chal; diec ./chal 2>/dev/null \|\| die ./chal` |
| Entropy | `python3 -c "import math,collections; d=open('./chal','rb').read(); e=-sum(c/len(d)*math.log2(c/len(d)) for c in collections.Counter(d).values()); print(f'{e:.2f}')"` |
| Imports | `nm -D ./chal \| head; rabin2 -i ./chal 2>/dev/null \| head` |
| rodata dump | `objdump -s -j .rodata ./chal \| head -n 60` |
| Ghidra import | `/opt/ghidra/support/analyzeHeadless /tmp/gproj CTFproj -import ./chal` |
| Ghidra re-script | `/opt/ghidra/support/analyzeHeadless /tmp/gproj CTFproj -process chal -noanalysis -scriptPath ./scripts -postScript Dump.py` |
| r2 analyze | `r2 -A ./chal -c 'afl; s main; pdf; q'` |
| rizin strings+xref | `rizin -A -q -c 'iz; axt 0x402000; q' ./chal` |
| Trace libcalls | `ltrace -s 200 -o t.log ./chal <<< 'AAAA'; grep -m10 strcmp t.log` |
| Trace syscalls | `strace -f -o s.log ./chal <<< 'AAAA'; grep -m10 'read\|ptrace\|mprotect' s.log` |
| UPX unpack | `upx -d -o ./chal.unpacked ./chal` |
| Go symbols | `go_parser ./chal 2>/dev/null \| head; strings ./chal \| grep -m3 'main.main'` |
| pyc decompile | `uncompyle6 -o ./src ./chal.pyc` / `pycdc ./chal.pyc \| head -n 100` |
| APK unpack | `apktool d app.apk -o ./apk_out; jadx -d ./jadx_out app.apk` |
| WASM to C | `wasm2c app.wasm -o app.c; grep -n 'check\|compare' app.c \| head` |
| Frida spawn | `frida -q -l hook.js -f ./chal --` |
| angr run | `timeout 120 python3 solve_angr.py` |

## Code / Payload Library

angr symbolic template (stdin checker; argv variant: put BVS in
`args=[BIN, arg]` instead of `stdin=`):

```python
import angr, claripy
BIN = "./chal"
SUCCESS = 0x4012ab  # win branch (from Phase 2)
FAIL    = 0x4012c0  # fail branch
N = 24              # input length (from read() size / buffer)

inp = claripy.BVS("inp", 8*N)
p = angr.Project(BIN, auto_load_libs=False)
st = p.factory.full_init_state(args=[BIN], stdin=inp)
for c in inp.chop(8):
    st.solver.add(c >= 0x20, c <= 0x7e)  # printable
# scanf family reads via unconstrained symbolic — hook to feed stdin:
p.hook_symbol("__isoc99_scanf", angr.SIM_PROCEDURES["libc"]["scanf"]())
sim = p.factory.simgr(st)
sim.explore(find=SUCCESS, avoid=FAIL)
assert sim.found, "no state reached SUCCESS - check addrs/length"
print(sim.found[0].posix.dumps(0).decode())
```

Frida strcmp/memcmp logger + anti-debug bypass:

```js
// hook.js — log comparisons, neutralize ptrace
const cmp = [["strcmp","int",["pointer","pointer"]],
             ["strncmp","int",["pointer","pointer","int"]],
             ["memcmp","int",["pointer","pointer","int"]]];
cmp.forEach(([n, r, a]) => {
  try {
    Interceptor.attach(Module.getExportByName(null, n), {
      onEnter(args) {
        this.a = args[0].readCString() || "";
        try { this.b = args[1].readCString() || ""; } catch(e){ this.b="<bin>"; }
      },
      onLeave(ret) {
        if (this.a.length < 200)
          console.log(`[${n}] '${this.a}' vs '${this.b}' -> ${ret.toInt32()}`);
      }
    });
  } catch(e) {}
});
try {
  Interceptor.replace(Module.getExportByName(null, "ptrace"), new NativeCallback(
    () => ptr(0), "int", ["int","int","pointer","int"])); // ptrace->0
  console.log("[*] ptrace bypass installed");
} catch(e) { console.log("[-] no ptrace: "+e); }
```

Run: `frida -q -l hook.js -f ./chal --` (or `-p <pid>` to attach).

String-XOR brute (paste blob from objdump, printable test):

```python
blob = bytes.fromhex("3a1f0b...".replace(" ",""))  # paste from objdump
for k in range(256):
    pt = bytes(b ^ k for b in blob)
    if all(32 <= c < 127 or c in (10,13) for c in pt):
        print(hex(k), pt[:80])
```

IHDR-style height/CRC note lives in stego skill; rev analogue is
patching `je fail` -> `jne win`:

```bash
# find branch: r2 'pd 20 @ main+0xAB' shows 'je 0x4012c0'
# patch one byte: 0x74 (je) -> 0xEB (jmp) at file offset
python3 - <<'EOF'
off = 0x12ab  # file offset of jcc opcode (rabin2 -S vaddr->offset math)
d = bytearray(open("./chal.patch","rb").read())
assert d[off] == 0x74, hex(d[off])
d[off] = 0xEB
open("./chal.patch","wb").write(d)
print("patched je->jmp")
EOF
```

## Decision Tree

```text
file ./chal
+-- PE .NET / mscorlib strings? --> dnSpy track: open assembly, search flag/Compare
+-- Go (main.main)? --> find main.main in Ghidra, args are (ptr,len) slices
+-- .pyc / PYZ? --> uncompyle6/pycdc, read checker python directly
+-- APK/dex? --> jadx GUI or apktool + grep smali for xor/compare
+-- WASM? --> wasm2c, grep output C for check function
+-- ELF + UPX/packed? --> upx -d; still packed? -> Frida dump at OEP (see below)
+-- ELF clean?
    +-- ltrace shows strcmp+stable 2nd arg? --> read rodata / Frida log = solved
    +-- XOR/b64/S-box loop in main? --> Python re-impl (fastest)
    +-- hash (md5/sha) + short input? --> brute; long input? --> angr (may still fail: hash unsolvable symbolically -> brute only)
    +-- obfuscated CFG / opaque preds? --> Frida runtime dump, never static-only
    +-- ptrace / IsDebuggerPresent? --> Frida ptrace->0 first, then analyze
    +-- win() reachable behind check()? --> patch je->jmp, run, read output
+-- no main / firmware blob? --> strings+binwalk; likely not pure rev -> hand to forensics/misc
```

Unpacking (OEP dump, when `upx -d` fails): `strace` spots `mprotect(RWX)`
= unpacker; Frida-break at return-to-unpacked-code, `Memory.scan` for
`ELF`/`MZ` magic, `File.write` out, re-import to Ghidra. Never fight
custom packers statically — dump-then-analyze.

Obfuscation counters: opaque preds -> run concretely (dead branch never
fires); runtime string-XOR -> Frida dump at decode exit or 1-byte brute;
timing checks -> fake `clock_gettime` or patch; CFG flattening -> trace
executed blocks only (Frida Stalker / r2 `dcu` to `win`).

.NET / Go / pyc / APK / WASM one-liners: .NET `dnspy app.exe` (search
Check/Compare); Go `main.main` (ptr,len slices); pyc `uncompyle6` else
`pycdc` (`pyi-archive_viewer` for bundles); APK `apktool d` + `jadx -d`
(grep smali `xor|equal`); WASM `wasm2c app.wasm -o app.c`, re-impl.

## AI Automation Notes

- Lead plans, Worker runs Phase commands, returns addrs + artifacts.
- GhidraMCP: `decompile_function(main)` first, `rename_function` +
  `list_xrefs`, cap ~10 calls, else headless dump script.
- angr top failures: (1) off-by-one find/avoid — verify
  `r2 'pd 10 @ <addr>'`; (2) missing scanf hook; (3) wrong N
  (`read(0,buf,0x20)` => N=0x20). `auto_load_libs=False` + printable +
  `timeout 120`; empty `found` -> switch method, never extend.
- Frida: spawn `-f` beats attach; `sleep(200)` if early strcmp missed;
  `-o frida.log`. Patch: `cp` first, record offset + orig bytes.
- Stop: 3 failed Phase-4 attempts -> `blocked` + partials to `results/`.
  Handoff needs method + addrs + command + sha256, else not reviewable.

## Advanced / Hard-Challenge Playbook

For challenges surviving Phases 1-4 (VM, custom pack, anti-debug,
language runtimes). Rule: never fight the protector statically — dump,
trace, or emulate first, then run the normal loop on the artifact.

### A. VM-based obfuscation (handler-table reconstruction, bytecode lifting)

Signals: one giant `switch(state)` / indirect-jump dispatcher loop,
hundreds of tiny basic blocks that all return to one address, no
recognizable checker near `main`, bytecode-like blob in `.rodata`
(high-entropy array indexed by a virtual program counter).

Concept (technique-only):

1. **Find the dispatcher** — Ghidra function with the highest in-loop
   indirect-jump count (`jmp rax` / `jmp [table+rcx*8]` in a loop).
2. **Reconstruct the handler table** — `rabin2 -S` for base, then
   `pxq <n> @ <table_addr>` in r2; label entries `vm_add`, `vm_xor`,
   `vm_jcc`, `vm_exit`.
3. **Capture the bytecode** — the blob the virtual program counter
   walks (`objdump -s -j .rodata`, or Frida
   `Memory.readByteArray(bytecode_ptr, len)` at VM entry).
4. **Lift the traced path only** — trace ONE known input (`AAAA...`)
   via Frida Stalker / `r2 dcu`, re-implement that handler sequence in
   Python. Full lifting is a last resort.
5. **Solve the lift** — usually plain XOR/arithmetic: Phase-4 re-impl or
   angr symbolic over the *lifted* Python, never over the VM loop
   (state explosion guaranteed).

```bash
r2 -A ./chal
afl; pdf @ sym.vm_loop                 # confirm dispatcher shape
pxq 64 @ <handler_table_addr>          # dump handler pointers
objdump -s -j .rodata ./chal | head -n 60   # candidate bytecode blob
frida -q -l trace_vm.js -f ./chal -- <<< 'AAAA' 2>&1 | head -n 50  # trace handlers only
```

`Reasoning Checkpoint`: dispatcher + table + blob recorded, traced path
lifted? Dispatcher unfound after 30m -> fully dynamic, never hand-enumerate.

### B. Custom packers (OEP hunting, IAT rebuild concept)

Signals: `upx -d` fails or reports modified magic, imports table
near-empty, entry section writable+executable, `strace` shows
`mprotect(RWX)` then a jump to freshly-written memory.

OEP hunt — dynamic, never static:

1. `strace -f -e trace=memory` — last `mprotect(PROT_WRITE|PROT_EXEC)`
   before the first `read`/`puts` brackets the unpacker; the jump out
   of that region lands near the OEP.
2. Frida: break on `mprotect` return, Stalker-trace until RIP leaves the
   unpacker section into fresh RX — that landing addr is the OEP.
3. Dump at OEP: scan for `ELF` magic (`7f 45 4c 46`), `File.write` the
   segment range, re-import to Ghidra, resume at Phase 2.

```bash
strace -f -e trace=memory,process ./chal <<< 'TEST' 2>&1 | grep -m10 'mprotect\|mmap'
upx -d -o ./chal.unpacked ./chal 2>&1 | head -n 5   # try first; else Frida OEP dump (Stalker.follow past mprotect-RWX, dump ELF range)
```

IAT rebuild concept: packers resolve imports at runtime, so dumps have
broken import tables — still enough for Ghidra analysis. Rebuild stubs
only if you must *run* the dump; else solve the original past the OEP.

`Reasoning Checkpoint`: `upx -d` output logged? `mprotect(RWX)`
CONFIRMED packer? OEP addr + dump re-imported? Dump failed twice ->
escalate (operator GUI unpacker), never hand-patch the stub.

### C. Anti-debug menagerie (detect + bypass each)

| Check | Detection | Bypass (concept) |
|---|---|---|
| `ptrace(PTRACE_TRACEME)` | `strace` shows `ptrace`; `nm -D` imports it | Frida `Interceptor.replace(ptrace -> 0)` (library); or `LD_PRELOAD` stub |
| Timing (`clock_gettime`/`rdtsc` deltas) | clock reads bracket compare; instrumented runs fail, native pass | hook `clock_gettime` to fixed increments; or run natively and dump instead of tracing |
| `int3` / `0xCC` traps | `cc` bytes in code; debugger detaches at fixed addr | use Frida (no INT3), or patch `0xCC -> 0x90` on a *copy* |
| `CPUID` hypervisor-bit checks | `cpuid` in disasm; bare-metal vs VM behavior differs | patch the branch on a copy, or hook under emulation |
| TracerPid / `IsDebuggerPresent` | strings show `/proc/self/status`/`TracerPid`; import present | fake `TracerPid: 0` via `open` hook; replace `IsDebuggerPresent -> 0` |
| `fork` + parent-watchdog | `strace -f` shows `clone`/`fork` + `waitpid`/`kill` | Frida spawn with child-gating, or patch `fork` out on a copy |

Add ONE bypass at a time to `hook.js` and re-test — e.g. one
`Interceptor.replace(... -> 0)` per check (see the ptrace pattern in the
library). Stacking hides which check was real and breaks processes.

`Reasoning Checkpoint`: each check proven (strace/string quote)?
Bypassed singly with before/after noted? Native passes but instrumented
fails -> timing/Frida-detection CONFIRMED, go dump-then-offline.

### D. Symbolic-assisted deobfuscation (angr + z3 on opaque predicates)

Opaque predicates (`x*(x+1)%2==0`-style MBA junk, always-true/false)
poison disassemblers, not solvers: prove each suspicious branch constant
with z3, then ignore the dead arm.

```python
# opaque-predicate prover (paste branch expr from decompile)
import claripy
x = claripy.BVS("x", 32)
cond = ((x * (x + 1)) % 2) == 1   # example junk shape
print("can-be-true:", claripy.Solver(cond).satisfiable())
print("can-be-false:", claripy.Solver(claripy.Not(cond)).satisfiable())
# both sat -> real branch; one sat -> opaque: avoid= the dead arm.
```

Workflow: list suspicious branches, cap 5 min per predicate, mark proven-
opaque arms `avoid=` in angr or NOP on a *copy*. Slice the predicate out
first — never execute symbolically *through* MBA junk. Cheap pre-pass:
`claripy.simplify(expr)` + sampling on 256 random inputs kills ~90% of
CTF opaque preds in seconds.

`Reasoning Checkpoint`: predicates listed, sampling before heavy solve?
Dead arms avoided, original untouched? z3 timeout -> branch is real, go dynamic.

### E. Go binaries (pclntab recovery, `main.main`, slice calling)

Go binaries are huge but searchable — runtime metadata survives `strip`.
Never read runtime functions; find `main.main`, follow strings into it.

1. Confirm: `strings ./chal | grep -m3 'go1\.\|main\.main\|runtime\.gopanic'`.
2. Recover names via a pclntab reader (GoReSym family / Ghidra Golang
   analyzer): pclntab maps PCs to names, restoring `main.main`, `main.check`.
3. Ghidra Symbol Tree -> `main.*`: strings/slices pass as `(ptr, len)`
   pairs, so the checker is `main.check(ptr, len)` — follow the pair.
4. Solve the checker body with the normal loop (re-impl, or angr on
   `main.check` with `(ptr,len)` bound to your symbolic buffer).

```bash
strings ./chal | grep -m3 -E 'go1\.|main\.main|runtime\.gopanic'
go version ./chal 2>/dev/null || true
rabin2 -z ./chal 2>/dev/null | grep -Ei -m10 'wrong|fail|incorrect|flag' || true
```

`Reasoning Checkpoint`: Go CONFIRMED (version + pclntab)? `main.main`
found, checker via string xref? Empty output -> try Ghidra Golang analyzer.

### F. Rust binaries (monomorphized symbols, panic-string signposts)

Rust default builds keep mangled symbols — demangle and follow panic
strings. Monomorphization duplicates each generic (`check::<u8>`,
`check::<u32>`...) — solve ONE instance.

1. Demangle (`rustfilt` on `nm`/`rabin2 -s`, or Ghidra demangle view):
   `_ZN4chal5check17h...E` -> `chal::check::...`.
2. `strings ./chal | grep -m20 'panicked|assert|unwrap|expect'` — the
   surrounding bytes point at input-validation functions.
3. Slice/str args are `(ptr, len)`; `Option`/`Result` checks compile to
   discriminant compares (`cmp byte ..., 0/1`) = win/fail branches for
   angr find/avoid. Ignore the other monomorphized copies.

```bash
rabin2 -s ./chal 2>/dev/null | grep -i -m20 'check\|verify\|flag' || true
strings -n 8 ./chal | grep -m20 -E 'panicked|unwrap|expect|assert|incorrect|wrong' || true
```

`Reasoning Checkpoint`: demangled check/verify names found, panic xref
lands in exactly one instance? That instance is the Phase-2 target.

### G. WASM binaries (`wat2wasm` / `wasm2c` loop)

WASM rev is a compile-target problem: convert to readable C, then run
the normal loop. Never read raw WASM bytecode past triage.

1. Confirm `\0asm` magic (`head -c4 app.wasm | xxd`).
2. `wasm2c app.wasm -o app.c`, then grep the C for the check function.
3. Map func indices (`$func12`) via `wasm2wat` export section.
4. Round-trip: run original under `wasmtime`/`node` on a known input to
   confirm behavior. Opaque `wasm2c` output -> checker may live in the
   accompanying JS glue.

```bash
head -c 4 ./app.wasm | xxd
wasm2wat ./app.wasm -o ./app.wat 2>/dev/null && grep -n -m20 'export\|(func' ./app.wat | head -n 20
wasm2c ./app.wasm -o ./app.c 2>/dev/null && grep -n -m20 'check\|compare\|xor' ./app.c | head -n 20
wasmtime ./app.wasm <<< 'TEST' 2>&1 | head -n 10
```

`Reasoning Checkpoint`: checker func index mapped? `wasm2c` logic
readable? Round-trip matches original on `AAAA`?

### H. Unicorn emulation for unpacking (controlled detonation)

When Frida is detected or the stub needs kernel behavior Frida cannot
fake, emulate just the unpacker with Unicorn and dump from emulated
memory (bounded, scriptable):

1. Map segments at real vaddrs (`rabin2 -S` -> `mem_map`/`mem_write`).
2. Grant RWX in-emulator at the stub's `mprotect`/`mmap` sites instead
   of executing the syscalls.
3. Emulate from entry with a hard cap (2M insns); stop when RIP reaches
   a freshly-written region (OEP landing) — dump that region to Ghidra.
   Never emulate the full program (syscalls/threads kill time).

```python
# unicorn OEP-dump sketch (fill addrs/sizes from rabin2 -S)
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
emu = Uc(UC_ARCH_X86, UC_MODE_64)
# mem_map + mem_write segments; hook code to stop on RIP-in-fresh-RX
# emu.emu_start(entry, 0, count=2_000_000); dump region at stop-RIP
```

Cap instructions AND wall-clock (`timeout 120`); snapshot memory first
for instant restart. Stub does threading/`ptrace`/network -> wrong tool:
back to Frida dump or escalate.

`Reasoning Checkpoint`: vaddrs match `rabin2 -S`, stop = RIP-in-fresh-RX,
dump re-imported with `main` found? No landing in cap -> one retry, escalate.

### I. String-decryption routine reuse (call the binary's own decoder)

Hard binaries decrypt strings at runtime with their own routine
(`decode(ptr,len,key)` in a startup loop). Instead of reversing the
cipher, CALL it via Frida:

1. Identify the decoder: the single callee shared by all string-setup
   sites (Ghidra xrefs converge on it).
2. Hook decoder exit, log plaintexts (`readCString`/`readByteArray`) —
   one run dumps every string incl. checker constants. Or call it
   yourself via `NativeFunction(decoder_addr, ...)` on dumped blobs.

```js
// decode-reuse logger (adapt signature from decompile)
try {
  const dec = Module.getBaseAddress(null).add(<decoder_offset>);
  Interceptor.attach(dec, {
    onEnter(args) { this.p = args[0]; },
    onLeave(ret) { try { console.log("[dec] " + this.p.readCString()); } catch(e) {} }
  });
} catch(e) {}
```

`Reasoning Checkpoint`: decoder found by convergent xrefs? One run
dumps readable checker constants? Still binary -> wrong signature (len
vs key order); one decompile re-check, one retry.

## Multi-Step Chains

Hard rev is a pipeline, not one trick. ABSTRACT patterns (technique-only).
Steps run in order; each ends with an artifact the next step consumes.

### Chain 1 — packed -> dump -> deobfuscate -> keygen (4 hops)

1. **Dump** (Playbook B/H). Artifact: `chal.unpacked` + OEP addr. Gate:
   dump re-imports, `main` decompiles; else stop.
2. **Deobfuscate** (Playbook A/D): trace-once + lift executed path.
   Artifact: `lifted_check.py` replicating the transform.
3. **Keygen**: invert the lift (reverse each op) or constrain it in
   z3/angr. Artifact: `solve_keygen.py` printing a candidate.
4. **Validate** on the ORIGINAL packed binary
   (`timeout 20 ./chal <<< "$CAND"`), twice. Two matches -> handoff.

`Reasoning Checkpoint`: hops gated on artifacts (no dump -> no lift ->
no keygen -> no claim). A hop failing twice -> switch that hop's method
only, keep the rest.

### Chain 2 — VM -> lift -> solve (3 hops)

1. **Map** (Playbook A 1-3). Artifact: table addrs + blob range. Gate:
   handler trace stable across two `AAAA` runs (deterministic VM).
2. **Lift** traced sequence to `vm_lift.py` (accept/reject). Gate: agrees
   with the binary on 3+ probes (incl. one reject).
3. **Solve**: constrain `vm_lift.py` inputs in z3 (printable +
   accept==True) or brute-force short fields. Verify on original x2.

```bash
python3 vm_lift.py AAAA; echo lift=$?
./chal <<< 'AAAA'; echo real=$?     # must agree on 3+ probes incl. one reject
```

`Reasoning Checkpoint`: lift-binary agreement on 3+ probes? Disagree ->
fix ONE handler semantics, re-probe; never solve on a wrong lift.

### Chain 3 — runtime-crypto -> reuse-or-reimpl -> verify (3 hops)

1. **Reuse first** (Playbook I): dump runtime constants
   (hash/ciphertext/key) via the binary's own decoder. Artifact:
   `runtime_consts.txt`.
2. **Re-implement** encrypt-then-compare in Python, invert to a
   candidate (standard cipher names in strings -> use a library, never
   hand-roll). Artifact: `solve_reimpl.py`.
3. **Verify**: candidate into original binary AND re-encrypt(candidate)
   == dumped ciphertext byte-for-byte. Both required.

`Reasoning Checkpoint`: byte-exact re-encryption match + binary accept?
Without both, crypto-chain claims are LOW confidence.

## Failure-Mode Catalog + Recovery

| # | Failure | Detection | Recovery (bounded) |
|---|---|---|---|
| 1 | Stripped + no symbols (no `main`, `FUN_` everywhere) | `nm` empty, `rabin2 -s` empty, Ghidra Symbol Tree bare | Entry -> first `__libc_start_main` arg = `main`; string-xref into callers finds checker; never rename blindly — rename only on the win path |
| 2 | angr state explosion (find never reached, states balloon) | `sim.active` grows unbounded, memory climbs, 120s timeout with zero `found` | Constrain: halve input N, fix known prefix bytes concretely, add printable + length constraints, hook `scanf`, set `avoid=` on fail; if still exploding -> drop angr for re-impl/Frida (one switch, not longer timeouts) |
| 3 | Frida spawn vs attach mismatch (early strcmp missed / attach refused) | Spawned run logs comparisons but attached run shows none (or `Failed to attach`) | Prefer spawn (`-f`) for startup checks; add `sleep`/early-hook via `Process.enumerateModules` wait; use `-o frida.log` to confirm hook install order; attach only for long-running/persistent targets |
| 4 | Ghidra mis-analyzed function (garbage decompile, wrong signature) | Decompile contradicts `ltrace` (args/returns disagree); ` call rax` bonsai | `Clear With Options` on the function + `Disassemble` + `Create Function` + `Retype Variable` (`char *`, `(ptr,len)` for Go/Rust); toggle Thumb/ARM variant on ARM; one re-analyze, then trust dynamic output over decompile |
| 5 | Packed UPX with modified magic (`upx -d` fails: `NotPackedException` / bad magic) | `upx -t` fails but entropy >7.4 + `UPX!`-like strings + tiny imports persist | Do NOT hex-patch magic blindly on the original — copy first, try `upx -d` on copy; else dynamic OEP dump (Playbook B); `diec` second opinion to confirm family before manual magic repair |
| 6 | Hash-based checker fed to angr (unsolvable symbolically: `md5/sha` names + no plaintext blob) | Strings show hash names, `.rodata` has 16/32/64B digest not plaintext, angr `found` empty regardless of N | Stop symbolic: pivot to brute (short input) or Frida-dump the digest + offline crack (bounded wordlist) or re-impl-then-invert if salt known; never extend angr timeout on hashes |
| 7 | Thumb/ARM mode or calling-convention misread (garbage CFG, args shifted) | `bl`/`bx lr` patterns with nonsense decompile; x64 args read from wrong registers (SysV vs Win64) | Confirm arch via `file` + `rabin2 -I` first; flip Thumb in Ghidra/r2 (`ahi`/`.arm`); re-map args per convention table (Phase 1); verify with one `ltrace`/Frida arg log before solving |

General rule: ONE diagnosis + ONE corrected retry + ONE alternate method
per failure, then `blocked` with partials. Log the F-number in handoff
notes so the validator skips the dead path.

`Reasoning Checkpoint`: failure numbered (F1-F7) with quoted detection
evidence, recovery in order (fix -> retry -> alternate)? Alternate
failed -> `blocked`, no fourth method without Lead approval.

## Version-Drift Guards

Toolchains drift; pins beat debugging. Check versions at session start
and never auto-upgrade mid-challenge.

- **Ghidra project upgrades (backup first).** Migration is one-way:
  `cp -r /tmp/ghidra_proj /tmp/ghidra_proj.bak` before opening in a new
  version; keep project + scripts under the creating version. Changed
  headless output after upgrade -> re-run from backup first.
- **angr / claripy API drift.** Template targets `BVS(name, bits)` +
  `explore(find=, avoid=)`. On `AttributeError`/`TypeError`: `pip show
  angr claripy` first, read installed docstrings
  (`python3 -c "import angr; help(p.factory.simgr)"`), adapt ONE call —
  never rewrite against internet docs for another version.
- **Frida-server ABI match.** Client and `frida-server` must share the
  major version or injection fails with protocol errors — compare
  `frida --version` vs server version before remote sessions.
- **Record versions in handoff.** One `tool_versions.txt` (ghidra, angr,
  claripy, frida) next to every solve script for validator drift-checks.

```bash
# session-start version snapshot (paste into tool_versions.txt)
/opt/ghidra/support/analyzeHeadless 2>&1 | head -n 2
python3 -c "import angr,claripy; print('angr', angr.__version__); print('claripy', claripy.__version__)"
frida --version; frida-server --version 2>/dev/null || echo 'frida-server: local-only'
```

`Reasoning Checkpoint`: versions snapshotted pre-solve, no mid-challenge
upgrades, `tool_versions.txt` in handoff? Validator mismatch -> compare
versions before re-diagnosing.

## Time-Budget Tiers

Pick the tier at triage; it sets the method-switch clock (Phases 1-5
unchanged — only switch timing changes).

| Tier | Budget | Method-switch rule | Stop rule |
|---|---|---|---|
| Easy (plaintext/XOR/b64, symbols present) | <=20 min | one method, one retry (10m) | 20m no flag-path -> re-triage once, then escalate to medium playbook |
| Medium (stripped/packed-stock/obfuscated-light, Go/Rust/WASM) | <=1 h | switch method every ~20m (max 3 methods) | 1h no solve -> request second Worker trace OR escalate per triggers below |
| Hard (VM/custom-pack/anti-debug-heavy, multi-hop chains) | <=3 h | switch method every ~45m; chain hops gated individually | per-hop cap 1h; 2 hops blocked -> full `blocked` + partials + operator ping |
| Insane (novel protector, kernel/driver, multi-binary) | escalate | 30m recon only (characterize + artifact), no solve attempts | after recon -> operator ping with evidence; never solo-burn >30m |

Enforcement: `timeout` on every Phase-4 run; wall-clock checked at each
`Reasoning Checkpoint`. A method past its clock with no new evidence is
abandoned even if "almost working".

`Reasoning Checkpoint`: tier declared with reason, elapsed vs budget
stated, switch/stop applied (never deferred)? Over budget -> escalate or
`blocked`, never a silent fourth method.

## Escalation Triggers

Call the right specialist early — a timely handoff beats a late heroics
attempt. Include evidence + artifacts listed, or the handoff bounces.

- **-> `/pwn` (runtime leak / memory primitive).** Checker reads a
  runtime secret (canary-like, ASLR/heap value) static/dynamic rev cannot
  recover; or an overflow (`read(0,buf,0x40)` into 0x20 buf) guards the
  flag path. Hand over: sha256, offset (if known), win-addr, Frida trace
  of the secret's use site.
- **-> `/crypto` (custom cipher inside).** Lifted checker is Feistel/SPN,
  custom S-box + key schedule, or RSA/ECC with embedded params (not
  XOR/b64/RC4). Hand over: `lifted_check.py` + `runtime_consts.txt` + 2+
  known pairs from Frida traces — never the raw packed binary alone.
- **-> operator (manual GUI unpacker / interactive).** OEP dump failed
  twice (B+H exhausted); GUI unpacker / driver / license-server needed;
  or Insane recon complete. Ping with: tier, elapsed, methods tried
  (F-numbers), artifacts (`chal.unpacked` tries, traces, versions).
- **No evidence, no escalation.** Bare "VM, help" without dispatcher +
  handler trace, or "packed, help" without `upx -d` + `mprotect` lines,
  returns for one more gated rev pass.

`Reasoning Checkpoint`: trigger + quoted evidence, artifacts present,
correct target (pwn vs crypto vs operator)? No match -> stay in rev,
declare next single method.

## Worked End-to-End Example (abstracted, technique-only)

Generic binary `chal` (ELF x86-64, illustrative — no challenge data).
Medium-hard composite: packed + runtime-XOR strings + checker in `main`.

1. **Baseline (5m).** ELF 64-bit; tiny `strings` + entropy 7.8 = packed
   (probe 3 CONFIRMED); one `mprotect(RWX)` pre-prompt = stub. Tier:
   medium. Packed YES -> stock-unpack first, dynamic dump fallback.
2. **Unpack (15m).** `upx -d -o chal.unpacked` succeeds here (else
   Playbook B). Dump re-import: `main` -> `check_input` -> `win`/`fail`;
   no `strcmp` on the dump (not plaintext); `.rodata` 32B blob + XOR
   loop = repeating-XOR family. Original kept untouched.
3. **Negative (10m).** Plaintext DENIED (no stable 2nd arg); hash DENIED
   (no `md5/sha` names). XOR loop is inline -> direct re-impl beats
   Frida reuse (Playbook I skipped with reason). Surviving: XOR vs 32B
   blob -> Phase 4 Option D.
4. **Exploit (<=120s).** Blob via `objdump -s -j .rodata`, key shape via
   library String-XOR brute, `solve_reimpl.py` inverts
   `out[i]=in[i]^key[i%N]` -> candidate. ONE run, `timeout 60`.
5. **Validation-handoff.** `timeout 20 ./chal <<< "$CAND"` x2 from clean
   state, accept-pattern both runs; `sha256sum`; `results/rev_<id>.json`
   (method=`reimpl`, addrs, command, versions). Done -> `/validate`.

Failure branches (illustrative): stock-unpack fail -> F5 OEP dump; brute
shows no printable key -> Phase 3 once (hash family), then F6 pivot
(Frida dump + bounded crack).

---

*Technique-only reference. No real flags contained. Tool syntax verified
  2026-10 against Ghidra analyzeHeadless README, rizin/r2 help, angr API,
  Frida JS API, upx/apktool/jadx/uncompyle6 man pages.*

## Writeup-Distilled Patterns (W1..W32)

Mined from 572 reversing writeups (`knowledge/writeups_mined/rev_manifest.md`).
Each pattern is NEW vs the playbooks above: a recognition trigger plus the exact
move that solved it. Cite sources when reusing a move.

### W1 — Capstone array-op lift (straight-line checker to IR, then z3)
- Signals: megabyte `.text` of near-identical `mov`-family ops; Ghidra shows one giant function, no calls, no branches.
- Steps: 1) `capstone` disasm the code range 2) classify into 2-3 op shapes (e.g. `A[X]=Y`, `cl=A[X] <op> A[Y]`) 3) emit Python IR 4) z3 over SLICES of the state (outputs only), fix bit-order once.
- Commands: `python3 -c "from capstone import *; cs=Cs(CS_ARCH_X86,CS_MODE_64); [print(i.mnemonic,i.op_str) for i in cs.disasm(open('./chal','rb').read()[0x1290:0xed854],0)]" | sort | uniq -c | sort -rn | head`
- Pitfalls: full-state z3 stalls for 30m+ (slice first); big-vs-little-endian bit load flips every constraint; Ghidra-first wastes the budget.
- Sources: [corCTF 2024 digest-me](https://maplebacon.org/2024/07/corctf-digest-me) · [DiceCTF 2021 dice-is-you](https://ctftime.org/writeup/32295) · [PatriotCTF 2023 reduced-instruction-set-2](https://ctftime.org/writeup/37874)

### W2 — Flag-suffix known-plaintext key recovery
- Signals: fixed flag format (`...@domain`, `...}`) + XOR/add/RC4-style cipher + ciphertext visible in binary or output.
- Steps: 1) align KNOWN suffix bytes to ciphertext tail 2) `keystream = ct ^ pt` 3) check repetition (single-byte? repeating? position-shifted?) 4) decrypt full blob with derived stream.
- Commands: `python3 -c "ct=bytes.fromhex('...'); known=b'@flare-on.com'; print(bytes(a^b for a,b in zip(ct[-len(known):],known)))"` (repeat-byte => single-byte key)
- Pitfalls: position-dependent shift breaks naive repeat assumption; multibyte stream needs per-offset alignment, not one key.
- Sources: [Flare-On 11 SuperFashi](https://gmo-cybersecurity.com/blog/flare-on-11-write-up/) · [Flare-On 8 myrdyr](https://github.com/myrdyr/ctf-writeups/blob/master/flareon8/README.md) · [Flare-On 6 HomeSen](https://no-sec.net/posts/write-up-flare-on-6)

### W3 — GOTO-maze shortest-path (CFG + Dijkstra, no crypto)
- Signals: dense `goto`/jump maze, input steers path, win = reaching an address; no cipher in sight.
- Steps: 1) angr CFG recovery from `main` 2) export directed graph to networkx 3) `shortest_path(start,end)` 4) map edge decisions back to input bytes.
- Commands: `python3 -c "import angr,networkx as nx; p=angr.Project('./chal',auto_load_libs=False); cfg=p.analyses.CFGFast(); g=nx.DiGraph(cfg.graph); print(nx.shortest_path(g, start_addr, end_addr))"`
- Pitfalls: indirect jumps truncate the graph (resolve or concretize first); start/end addrs off-by-one invalidate the path.
- Sources: [BYUCTF 2026 angr_management](https://github.com/BYU-CSA/BYUCTF-2026/blob/main/rev/angr_management/writeup.md) · [FooBar CTF 2023 Formless](https://ctftime.org/writeup/36457)

### W4 — Layered Python unpack with loads-only (never exec)
- Signals: `.py` with `zlib`/`base85`/`marshal` blobs ending in `exec(...)`; "do not run" warning.
- Steps: 1) replace `exec` with `marshal.loads` + `dis` per layer 2) unwrap outside-in, saving each layer 3) pin the EXACT interpreter version for disasm (marshal opcodes drift).
- Commands: `python3 -c "import zlib,marshal,dis; code=marshal.loads(zlib.decompress(open('./chal.py','rb').read().split(b'decompress(')[1]))" ` then `python3.12 -m dis layer2.marshal`
- Pitfalls: wrong-version dis prints garbage (`BINARY_OP` soup); one accidental `exec` runs the payload — work on copies, loads-only.
- Sources: [Flare-On 12 project_chimera](https://github.com/expend20/flare-on-12-llm-solution/blob/master/02-project_chimera/README.md) · [TJCTF 2022 boxed-python](https://ctftime.org/writeup/34126)

### W5 — Gate-is-key (comparison constant doubles as cipher key)
- Signals: `if (input == CONST) decrypt(blob, input)` — the checked value feeds the decryptor.
- Steps: 1) extract CONST (the gate) 2) use it directly as the key (RC4/XOR `decrypt(blob, CONST)`) 3) never brute-force the gate separately.
- Commands: `python3 -c "from Crypto.Cipher import ARC4; print(ARC4.new(GATE).decrypt(open('./blob','rb').read()))"`
- Pitfalls: reordered KSA vs PRGA in hand-rolled RC4; gate encoding (login-name vs bytes) mismatch.
- Sources: [Flare-On 12 project_chimera](https://github.com/expend20/flare-on-12-llm-solution/blob/master/02-project_chimera/README.md)

### W6 — Unicorn slice emulation: run CRT/static inits FIRST
- Signals: emulator returns plausible-but-wrong output (e.g. repeated key bytes); tables built by static initializers.
- Steps: 1) emulate `CRT init` / static-init functions before the target 2) feed controlled inputs (`range(256)`, zero-key) 3) read out per-byte algebra 4) only then attack real blobs.
- Commands: `emu.emu_start(crt_init_addr, 0); emu.emu_start(target_addr, ret_addr)` (two starts, inits first — see Playbook H scaffold)
- Pitfalls: zero tables silently produce keystream-instead-of-plaintext; jumping straight at the function is the #1 time sink.
- Sources: [Flare-On 12 TheBossNeedsHelp](https://github.com/expend20/flare-on-12-llm-solution/blob/master/07-TheBossNeedsHelp/README.md) · [hxp CTF 2020 restless](https://ctftime.org/writeup/36221)

### W7 — Static-init S-box table reuse (identify the source table)
- Signals: 256-byte table built at startup from a 256-byte `.rodata` source; `TABLE[c]` in the hot loop.
- Steps: 1) dump the SOURCE bytes 2) match against AES (inverse) S-box 3) derived table = forward S-box (or inverse) 4) chosen-input emulation yields the full per-byte formula.
- Commands: `python3 -c "src=open('./chal','rb').read()[off:off+256]; from Crypto.Cipher.AES import ...; print('INVSBOX' if src==INVSBOX else 'unknown')"`
- Pitfalls: forward vs inverse confusion; missing position-shift term (`-(i+1)`) after the S-box lookup.
- Sources: [Flare-On 12 TheBossNeedsHelp](https://github.com/expend20/flare-on-12-llm-solution/blob/master/07-TheBossNeedsHelp/README.md)

### W8 — No-diffusion cipher: solve per byte, never jointly
- Signals: `out[i] = f(in[i], key[i%k], i)` — each output byte touches exactly one input byte (substitution + shift + repeating XOR).
- Steps: 1) prove no-diffusion (vary one input byte, one output byte changes) 2) solve each position independently (256 tries) 3) skip z3/angr entirely.
- Commands: `for i in range(n): pt[i] = next(c for c in range(256) if f(c)==ct[i])` (per-position brute, `n*256` total)
- Pitfalls: reaching for a joint solver on a trivially separable cipher; misreading the shift as diffusion.
- Sources: [Flare-On 12 TheBossNeedsHelp](https://github.com/expend20/flare-on-12-llm-solution/blob/master/07-TheBossNeedsHelp/README.md) · [Flare-On 11 frog](https://cloud.google.com/blog/topics/threat-intelligence/flareon-11-challenge-solutions?hl=en)

### W9 — Resource-embedded LZMA self-extractor (FPACK-style)
- Signals: tiny PE, ~6 imports (`LoadLibraryA`+`GetProcAddress` only), giant high-entropy `.rsrc`; `Detect It Easy` says packer.
- Steps: 1) list RCDATA resources 2) check for LZMA-alone magic (`5D 00 00`) + 8-byte size 3) decompress to payload PE 4) reverse the PAYLOAD, ignore the stub.
- Commands: `7z l ./chal.exe; python3 -c "import lzma; d=open('./chal.exe','rb').read(); open('./payload.exe','wb').write(lzma.decompress(d[d.find(bytes.fromhex('5D00001000')):]))"`
- Pitfalls: attributing stub API calls (`VirtualProtect` relocator) to anti-debug; brute-forcing the packed stub instead of carving.
- Sources: [Evasive crackme](https://github.com/alvin-ramsammy/crackme-writeups/tree/main/evasive-crackme-writeup) · [SEETF 2022 susware](https://ctftime.org/writeup/34319)

### W10 — Dead-code flag vs decoy output (decode BOTH, trust neither)
- Signals: binary writes a file/prints a string AND contains an unused decoded buffer; author taunts dynamic-only solvers.
- Steps: 1) decode every candidate buffer (used AND discarded) 2) classify taunt vs real by content 3) confirm by re-derivation, not by running.
- Commands: `python3 -c "a=bytes(open('./chal','rb').read()[o:o+n]); print(bytes(b^0x60 for b in a))"` (then eyeball: taunt or structured secret?)
- Pitfalls: submitting the decoy the program willingly prints; assuming "runs fine" means "analyzed".
- Sources: [Evasive crackme](https://github.com/alvin-ramsammy/crackme-writeups/tree/main/evasive-crackme-writeup)

### W11 — strace-write FD dump of the inner binary
- Signals: packed Rust/Go binary; `strace` shows burst `write()` of ELF bytes to a pipe/file; run-then-die behavior.
- Steps: 1) `strace -e trace=write --write=FD` to capture the FD stream 2) `grep ' | '` hexdump lines 3) strip + `xxd -r -p` to `inner.elf` 4) `file inner.elf` to confirm.
- Commands: `strace -e trace=write --write=3 -o dump.txt ./chal; grep " | " dump.txt | cut -c 11- | rev | cut -c 21- | rev | xxd -r -p > inner.elf; file inner.elf`
- Pitfalls: SIGINT truncation (dump dies mid-write); wrong FD (capture all write FDs, pick the ELF-magic one).
- Sources: [HackDay 2025 Rusty_rev](https://ctftime.org/writeup/39837) · [0CTF/TCTF 2020 J](https://ctftime.org/writeup/36239)

### W12 — Stripped-Rust resymbolize before reading (never raw)
- Signals: stripped Rust blob, megabyte static link, garbage decompile, `main` unfindable.
- Steps: 1) run a Rust resymbolizer (Cerberus-class) FIRST 2) demangle 3) model strings as wide `(ptr,len)` pairs 4) only then read the checker.
- Commands: `nm ./inner.elf | rustfilt | grep -i -m20 'check\|verify\|main' ; strings -n 8 ./inner.elf | grep -m5 'panicked\|unwrap'`
- Pitfalls: trusting ~60%-match symbols blindly (verify the checker by xref); C-string assumptions on Rust slices.
- Sources: [HackDay 2025 Rusty_rev](https://ctftime.org/writeup/39837) · [UTCTF 2021 Algorithm](https://ctftime.org/writeup/27398) · [SunshineCTF 2021 Useless VM](https://ctftime.org/writeup/30421)

### W13 — ltrace-first anti-debug discovery (behavior delta under trace)
- Signals: binary misbehaves ONLY under `ltrace`/`gdb` (wrong-password message, fake error strings).
- Steps: 1) run clean, then under `ltrace`, then under `strace` 2) diff the outputs — the delta NAMES the check 3) bypass that check before any analysis.
- Commands: `./chal <<< TEST; echo ---; ltrace ./chal <<< TEST 2>&1 | head; echo ---; strace -f -e trace=process ./chal <<< TEST 2>&1 | grep -m5 'ptrace\|clone\|kill'`
- Pitfalls: strace-only misses libc-level checks; assuming the binary is broken instead of defended.
- Sources: [HackDay 2025 Rusty_rev](https://ctftime.org/writeup/39837) · [AmateursCTF 2023 flagchecker](https://ctftime.org/writeup/37724)

### W14 — jne-to-jmp serial bypass (keygen alternative in one byte)
- Signals: `lstrcmp(user_input, generated)` + `jne fail`; generation algorithm looks long.
- Steps: 1) locate the compare + branch 2) on a COPY flip `jne` (`0x75`/`0x0F85`) to `jmp` (`0xEB`/`0xE9`) 3) run with any input 4) still write the keygen if time permits (bypass proves reachability).
- Commands: `python3 - <<'EOF'
d=bytearray(open('./c.patch','rb').read())
o=d.find(bytes.fromhex('0F85'))  # jne rel32 near the lstrcmp call
d[o:o+1]=bytes([0xE9]); open('./c.patch','wb').write(d)
EOF`
- Pitfalls: patching the original; short-vs-near jump encoding mismatch (`0x75`->`0xEB`, `0x0F85`->`0xE9`).
- Sources: [LaFarge CrackMe2 keygen](https://github.com/JulianOzelRose/LaFarge-CrackMe2-Keygen) · [Try and patch me](https://crackmes.one/solution/65b9d424eef082e477ff6444)

### W15 — Multi-stage XOR key arrays (carve all arrays first)
- Signals: stacked XOR loops over the username/serial with several hardcoded byte arrays + numeric tail math.
- Steps: 1) carve EVERY const array before reading logic 2) apply stages in reverse order 3) handle the numeric tail (div/mod + ASCII + reverse) last.
- Commands: `r2 -A -q -c 'iz; px 64 @ <array_addr>' ./chal` (repeat per array; keep stage order in notes)
- Pitfalls: stage-order reversal; username-derived offsets (first char skipped); `0x406xxx` immediates hiding as code.
- Sources: [LaFarge CrackMe2 keygen](https://github.com/JulianOzelRose/LaFarge-CrackMe2-Keygen) · [LaFarge natitati keygen](https://crackmes.one/solution/642e059033c5d439389124c7)

### W16 — Index-mask password derivation (code bytes as alphabet index)
- Signals: tiny loop (`N` iterations), table + mask (`& 7`), compare per byte; `inc`/`cmp`/`jne` shape.
- Steps: 1) read loop bound (= password length) 2) dump table + index bytes 3) `pw[i] = table[idx[i] & mask]` directly — no reversing needed.
- Commands: `python3 -c "t=b'BGOTHXIY'; idx=bytes.fromhex('48 8D 05 F9 FF FF FF 48 89 C6 48 8D 0D'); print(''.join(chr(t[b&7]) for b in idx))"`
- Pitfalls: index bytes that are actually code bytes (verify length == loop bound); off-by-one on the mask width.
- Sources: [raxer Simple Crackme](https://github.com/v0idMrK/CrackMe-challenge-writeup-1)

### W17 — Debugger-dependent key material (ptrace feeds the crypto)
- Signals: `ptrace` return value flows INTO key derivation (not just an exit check); patched binary yields half-readable output.
- Steps: 1) run clean vs patched, diff outputs 2) the delta bytes are debugger-dependent key material 3) re-derive with the CLEAN-trace value forced.
- Commands: `gdb -q ./chal -ex 'catch syscall ptrace' -ex run -ex 'set $rax=0' -ex continue` (observe) vs `LD_PRELOAD=./ptrace0.so ./chal` (compare)
- Pitfalls: solving entirely under the debugger bakes in wrong key bytes; assuming anti-debug is only a gate.
- Sources: [ASIS 2016 Catch Me](https://ctftime.org/writeup/3317) · [Cyber Heroines Mary Combs](https://ctftime.org/writeup/37898)

### W18 — Environment-staged keys (getenv as key schedule)
- Signals: `getenv("NAME")` + fixed-size takes + XOR chains into a validation buffer.
- Steps: 1) list all `getenv` names 2) `export NAME=$(python3 -c 'print(...)')` probes of exact lengths 3) solve each staged compare independently.
- Commands: `strings ./chal | grep -m10 -i 'getenv\|ctf\|asis'; export CTF=$(python3 -c 'print("\x0a\xda\xf2\x4f")'); ./chal`
- Pitfalls: shell mangling binary env bytes (use `python3 -c` + `env`); length-gated stages (`strncmp` N).
- Sources: [ASIS 2016 Catch Me](https://ctftime.org/writeup/3317)

### W19 — Layered ptrace-plus-signal (fix in discovery order)
- Signals: `ptrace` bypass alone still dies (SIGALRM/signal); layered menagerie in `main` prologue.
- Steps: 1) `catch syscall ptrace` + zero `$rax` 2) `handle SIGALRM ignore` (or next signal) 3) re-run; each newly-survived stage names the next check.
- Commands: `gdb -q ./chal -ex 'catch syscall ptrace' -ex 'handle SIGALRM ignore' -ex run -ex 'set $rax=0' -ex continue`
- Pitfalls: stacking all bypasses at once hides which check was real; signal delivered to the wrong thread under `-f`.
- Sources: [BalCCon2k20 shallweplayagame](https://ctftime.org/writeup/24049) · [SECCON 2016 Anti-Debugging](https://ctftime.org/writeup/5001)

### W20 — Manual UPX break-at-OEP (when `upx -d` is refused)
- Signals: `UPX0`/`UPX1` sections (`peparser`/`rabin2 -S`), `upx -d` warns or is known-fragile for this sample.
- Steps: 1) DO NOT fight `upx -d` 2) run in a debugger, break after the unpack loop (tail-jump/section-hop) 3) dump process memory 4) carve code from the dump.
- Commands: `peparser.py -f ./chal | grep -A1 IMAGE_SECTION; upx -t ./chal 2>&1 | head -n 3` (then debugger-break at unpacked state, dump, re-import)
- Pitfalls: broken IAT in the dump (fine for READING; rebuild only to RUN); `UPX!` string alone is not proof.
- Sources: [Flare-On Timzen ch4](https://www.tophertimzen.com/blog/flareOn) · [Flare-On 6 Dnschess dump](https://no-sec.net/posts/write-up-flare-on-6) · [PoliCTF John the Packer](https://ctftime.org/writeup/1496)

### W21 — Full process-memory dump for staged loaders
- Signals: loader decrypts files/code at runtime (chess/VM/game assets); static view is incomplete by design.
- Steps: 1) run to the fully-loaded state 2) dump the whole process (TaskManager/`gcore`/procdump) 3) carve the decrypted asset from the dump 4) analyze OFFLINE.
- Commands: `gcore -o dump $(pidof chal); strings -n 8 dump.* | grep -m10 -i 'flag\|password\|key'`
- Pitfalls: dumping too early (pre-decrypt); ASLR-shifted pointers in the dump treated as file offsets.
- Sources: [Flare-On 6 Dnschess dump](https://no-sec.net/posts/write-up-flare-on-6) · [Flare-On 8 docker layers](https://github.com/myrdyr/ctf-writeups/blob/master/flareon8/README.md)

### W22 — .NET staged-code assembly (follow the parts, then build the key)
- Signals: WinForms/`VictoryForm`, public string members, per-stage codes combined into one key.
- Steps: 1) ILSpy/dnSpy, open the victory/form load path 2) recover EACH stage code (one may itself be XORed) 3) assemble the full key in stage order 4) decrypt once.
- Commands: `ilspycmd -o ./decompiled ./chal.exe; grep -rn -m20 'XOR\|xored\|Arsenal\|Victory' ./decompiled | head`
- Pitfalls: stage-2 re-encryption with a static key applied on top; reading stages out of order.
- Sources: [Flare-On 6 Memecat](https://no-sec.net/posts/write-up-flare-on-6) · [BSides Delhi A Log of Work](https://ctftime.org/writeup/24109) · [Equinor EPT1911](https://ctftime.org/writeup/38181)

### W23 — Saved-register-as-key (entry call pushes key bytes)
- Signals: entry `call` leaves pushed bytes on the stack; later popped into the decrypt loop as key material.
- Steps: 1) trace the entry sequence to the pop-into-register 2) dump the pushed bytes 3) feed them as the decryption key in a re-impl.
- Commands: `r2 -A -q -c 's entry0; pd 40' ./chal` (note pushed immediates / saved EIP region, then follow the pop)
- Pitfalls: stack-layout shifts under different runs; confusing saved return address with key bytes (verify by decryption success).
- Sources: [Flare-On Timzen ch2](https://www.tophertimzen.com/blog/flareOn)

### W24 — Keyspace-size triage (brute-first threshold rule)
- Signals: single-byte (256) or small (<=2^16) keyspace with an eyeball-able plaintext (flag format / English).
- Steps: 1) estimate keyspace BEFORE reversing 2) if tiny, brute all keys and eyeball output 3) only reverse if brute fails.
- Commands: `python3 -c "ct=bytes.fromhex('...'); [print(hex(k), bytes(b^k for b in ct[:24])) for k in range(256)]" | grep -i -m3 'flag\|flare\|ctf\|the'`
- Pitfalls: repeating-key mistaken for single-byte (eyeball garbage ≠ proof); non-printable plaintext needs scoring, not eyeballing.
- Sources: [Flare-On 11 frog](https://gmo-cybersecurity.com/blog/flare-on-11-write-up/) · [1337UP Obfuscation](https://ctftime.org/writeup/38240)

### W25 — SSE/XMM-obfuscated compare (model the shuffle, then SMT)
- Signals: `movaps`/`pshufd`/`psadbw`/`andps` inside the checker; tiny binary (512B MBR-class) or hand-rolled SIMD.
- Steps: 1) QEMU+gdb remote, break at the check loop 2) record `xmm` regs per iteration 3) decode the shuffle immediate 4) SMT-invert the per-lane constraints.
- Commands: `qemu-system-i386 -drive format=raw,file=./chal -s & gdb -ex 'target remote localhost:1234' -ex 'break *0x7c6f' -ex continue` (then `p $xmm0`)
- Pitfalls: shuffle-immediate bit layout (lanes, not bytes); passing the first `cmp` (e.g. `flag` prefix) before observing.
- Sources: [CSAW 2017 realism](https://github.com/TechSecCTF/writeups/blob/master/CSAWQuals2017/realism/README.md)

### W26 — One-off custom-ISA emulator (spec + example pair first)
- Signals: unknown mnemonics doc + register file (e.g. `TRX`) + ONE worked example (in/out pair).
- Steps: 1) implement `mov`/`xor`/`reverse`-class ops in Python 2) validate the emulator on the worked example 3) init regs with the TARGET string 4) run to decrypt.
- Commands: `python3 emu.py` where `emu.py` maps each ISA line to a 5-line handler; assert example-pair output before touching the target.
- Pitfalls: operand order (dest/src) flipped; string-vs-bytes XOR length rules.
- Sources: [Tenable 2021 We Need an Emulator](https://ctftime.org/writeup/26147) · [SunshineCTF 2021 Useless VM](https://ctftime.org/writeup/30421)

### W27 — WASI import triage (map syscalls before reading logic)
- Signals: `wasi_snapshot_preview1` imports + `_start` export; heap-style challenge compiled to wasm.
- Steps: 1) `wasm2wat --generate-names --fold-exprs` 2) list `fd_read`/`fd_write`/`proc_exit` call sites 3) model linear-memory allocator 4) exploit or re-impl at the allocator level.
- Commands: `wasm2wat app.wasm -o app.wat --generate-names --fold-exprs --inline-exports; grep -n -m20 'fd_read\|fd_write\|_start\|memory' app.wat | head -n 20`
- Pitfalls: linear-memory offsets vs host pointers; WASI-vs-embedded (browser glue) confusion.
- Sources: [BCACTF Wasm Notetaker](https://ctftime.org/writeup/34226) · [UIUCTF 2021 wasmcloud](https://ctftime.org/writeup/29642) · [TJCTF 2025 garfield-lasagna-monday](https://ctftime.org/writeup/40308)

### W28 — JS-glue plus wasm-memory bridge (constrain the shared buffer)
- Signals: `main.mjs` + `module.wasm`, `exports.memory`, `exports.check()` contract, length pre-check in JS.
- Steps: 1) read the glue for the TRUE contract (length, export names) 2) map exported funcs via `wasm2wat` 3) decompile the checker 4) z3 over the shared-memory bytes.
- Commands: `node -e "console.log(Object.keys(await WebAssembly.instantiate(await Bun.file('./module.wasm').arrayBuffer())).instance.exports)"` (or read `main.mjs` imports); then z3 over `memory[idx]` cells.
- Pitfalls: JS-side length gate rejected before wasm runs (satisfy it first); memory-growth shifting offsets.
- Sources: [AmateursCTF 2025 wasm-checker](https://github.com/CysecAES/wasm-checker-challenge-writeup-amateursCTF-2025) · [osu!gaming 2024 wysi-revenge](https://ctftime.org/writeup/38726)

### W29 — Compare-arg intercept (read the secret, skip the cipher)
- Signals: native lib performs `strcmp`/`memcmp`/`strncmp` against the real secret (possibly post-decode).
- Steps: 1) spawn under Frida (never attach for startup checks) 2) hook the compare family, log both args 3) submit once — the log IS the answer 4) fall back to decoder-exit hooks if args are still encoded.
- Commands: `frida -q -l hook.js -f ./chal -- 2>&1 | grep -m10 'strcmp\|memcmp'` (hook.js = strcmp logger from the library above)
- Pitfalls: attach-vs-spawn race misses early compares; encoded 2nd arg means one more hook (decoder exit), not defeat.
- Sources: [frida-labs 0x8](https://github.com/brnpl/CTF-writeups/blob/master/android/frida-labs/0x8.md) · [UUTCTF 2019 Weird Application](https://ctftime.org/writeup/15084) · [HTB Dirty Money Mr Abilgate](https://ctftime.org/writeup/34878)

### W30 — Call-their-decrypt (APK method reuse over re-impl)
- Signals: obfuscated checker but reachable decrypt/verify methods; Frida works on the app.
- Steps: 1) enumerate classes/methods (jadx + `Java.enumerateMethods`) 2) hook the WIN path to control args, or invoke the decrypt method directly 3) recover the secret without reversing the cipher.
- Commands: `frida -U -f com.target.app -l reuse.js --no-pause` with `Java.use('com.target.Checker').decrypt.call(...)` inside `Java.perform`
- Pitfalls: instance vs static invocation; missing `Context`/activity args; ProGuard-renamed targets (find by string xref first).
- Sources: [InterIUT 2020 Jankenpon](https://ctftime.org/writeup/25122) · [RaziCTF Chasing a lock](https://ctftime.org/writeup/24617) · [CSR CSRunner](https://ctftime.org/writeup/31581)

### W31 — Multi-runtime binary triage (Go plus .NET in one file)
- Signals: BOTH `main.main`/`gopclntab` AND `mscorlib`/assembly markers; huge binary; checker could live in either runtime.
- Steps: 1) `strings` for BOTH runtimes before choosing tools 2) GoReSym + dnSpy in parallel (one worker each, read-only) 3) follow the string xrefs — the runtime holding the flag strings owns the checker.
- Commands: `strings ./chal | grep -m3 -E 'go1\.|main\.main'`; `strings ./chal | grep -m3 -i 'mscorlib\|AssemblyTitle'` (runtime with flag-adjacent strings wins)
- Pitfalls: full-Ghidra on a dual-runtime binary (hours lost); Go `{ptr,len}` misread as C strings in the .NET half.
- Sources: [HTB Business 2021 Ghost](https://ctftime.org/writeup/29391) · [ToH CTF 2025 PPC64LEL](https://ctftime.org/writeup/40347) · [SekaiCTF 2023 Teyvat Travel Guide](https://ctftime.org/writeup/37834)

### W32 — State-variable-anchored deflattening (no full emulation)
- Signals: single `switch(state)` dispatcher, one state variable, OLLVM/Tigress shape; full symbolic blows up.
- Steps: 1) find the state variable + its constant assignments 2) map `state value -> handler block` statically 3) rebuild the CFG from the constant flow 4) D-810/GOOMBA pass for MBA/opaque residue only.
- Commands: `r2 -A -q -c 'pdf @ <dispatcher>~mov.*state,switch,jmp' ./chal` then record each `state=CONST` site and its successor block.
- Pitfalls: state updates through arithmetic (not constants) need one concrete trace to resolve; opaque residue re-flattens naive rebuilds.
- Sources: [BSides Mumbai 2022 Reverse/Warmup](https://ctftime.org/writeup/36038) · [DaVinciCTF 2022 Mine Game](https://ctftime.org/writeup/32580) · [0CTF 2021 fea](https://ctftime.org/writeup/29116)

## Writeup-Distilled Patterns R2 (W33..W64) — index only; bodies in techniques/
Mined from 491 NEW hard rev writeups (`knowledge/writeups_mined/rev_manifest_r2.md`, 0% overlap vs R1). Each body has signals → steps → commands → pitfalls → 2–3 R2 URLs.

| ID | Pattern (signals → move) | Body |
|---|---|---|
| W33 | Handler devirt via trace-diff (VM table+blob, AAAA vs BBBB) | techniques/writeup-patterns-r2-1.md |
| W34 | Bytecode disassembler-first (opcode table → asm listing) | techniques/writeup-patterns-r2-1.md |
| W35 | Nested matryoshka VM (dispatch-inside-dispatch) | techniques/writeup-patterns-r2-1.md |
| W36 | VM-embedded Feistel/SPN round invert | techniques/writeup-patterns-r2-1.md |
| W37 | Dispatcher concretization (linearize traced path on COPY) | techniques/writeup-patterns-r2-1.md |
| W38 | Themida OEP via API-break (mprotect bracket + dump) | techniques/writeup-patterns-r2-1.md |
| W39 | VMProtect handler trace + devirt-lite (executed-only) | techniques/writeup-patterns-r2-1.md |
| W40 | IAT rebuild concept (Scylla-style, runnable dumps only) | techniques/writeup-patterns-r2-1.md |
| W41 | Stolen-bytes / API-redirection (live-byte fix on COPY) | techniques/writeup-patterns-r2-2.md |
| W42 | angr-to-z3 handoff (concrete prologue, symbolic tail) | techniques/writeup-patterns-r2-2.md |
| W43 | z3-first then angr (solver-first, one switch) | techniques/writeup-patterns-r2-2.md |
| W44 | Unicorn-assist for angr (concretize inits, symbolize checker) | techniques/writeup-patterns-r2-2.md |
| W45 | Veritesting / loop-bounded angr (N-cap + timeout) | techniques/writeup-patterns-r2-2.md |
| W46 | MBA/opaque residue strip (simplify + prover after deflat) | techniques/writeup-patterns-r2-2.md |
| W47 | CFF + opaque hybrid (state-map + prover in one pass) | techniques/writeup-patterns-r2-2.md |
| W48 | OLLVM bogus-CFG slice-out (Stalker exec-only, avoid rest) | techniques/writeup-patterns-r2-2.md |
| W49 | Il2CppDumper + GameAssembly (Unity native checker) | techniques/writeup-patterns-r2-3.md |
| W50 | .NET Reactor/ConfuserEx deobf (de4dot on COPY, then dnSpy) | techniques/writeup-patterns-r2-3.md |
| W51 | Blazor/dotnet-WASM (DLLs, not wasm2c) | techniques/writeup-patterns-r2-3.md |
| W52 | PyInstaller bundle + native ext (PYZ + .so checker) | techniques/writeup-patterns-r2-3.md |
| W53 | Flutter/Dart snapshot (libapp.so, mobile triage) | techniques/writeup-patterns-r2-3.md |
| W54 | Dart AOT disasm (snapshot_instructions, tagged ptrs) | techniques/writeup-patterns-r2-3.md |
| W55 | EVM bytecode decompile (runtime vs creation, selectors) | techniques/writeup-patterns-r2-3.md |
| W56 | EVM storage-slot key recovery (SLOAD map, local verify) | techniques/writeup-patterns-r2-3.md |
| W57 | Firmware blob crypto (binwalk carve + offline decrypt) | techniques/writeup-patterns-r2-4.md |
| W58 | Bootloader stage decrypt (emulate to handoff, dump stage2) | techniques/writeup-patterns-r2-4.md |
| W59 | LLM-assisted decompilation (draft + human verify) | techniques/writeup-patterns-r2-4.md |
| W60 | LLM struct/vtable recovery (cap 2 rounds) | techniques/writeup-patterns-r2-4.md |
| W61 | Timing+CPUID+TracerPid ordered bypass (one-at-a-time) | techniques/writeup-patterns-r2-4.md |
| W62 | Fork-watchdog + signal bypass (parent/child, discovery order) | techniques/writeup-patterns-r2-4.md |
| W63 | CPUID/timing-fed keys (env-fed derivation, not gate-only) | techniques/writeup-patterns-r2-4.md |
| W64 | Anti-emulation triage (is-VM → sandbox → late-attach) | techniques/writeup-patterns-r2-4.md |

## EASY-FIRST ladder (2026 training refresh — run BEFORE any W-pattern, ≤20 min)
1. `file; DIE; strings -n4 chal | grep -iE 'flag|CTF|Correct|Wrong|key'` — identify lang first (UPX / Python / .NET / Go / WASM).
2. Unpack/decompile: `upx -d`; `.pyc` → `pycdc` else `pycdas` (+matching Python ver); `.NET` → dnSpy entry point; `.wasm` → `wasm2wat` + grep `i32.const|xor|eq`.
3. XRef from `Correct/Wrong` string to the check function; lift the const array/key bytes.
4. Single-byte loop → brute `for k in range(256)`; if output garbage, re-read asm for `+i`/`rol` (position-dependent, invert as `(b^K)-i`).
5. Multi-constraint crackme, no crypto → `angr explore(find=win, avoid=fail)` with `auto_load_libs=False` + printable-stdin constraints.
6. Feed recovered input back into the binary and confirm `Correct` before submitting.

## R4 field patterns (browser-swarm 2026 — from 182 new writeups)
- angr discipline: use it to REACH the hash input (`find`), then invert manually outside the solver — never grind SHA256/AES constraints symbolically.
- Electron AppImage: `--appimage-extract` → asar unpack → patch JS → repack (fails only if signature-checked).
- Solana: diff Anchor IDL against eBPF disassembly — account-substitution bugs live in the divergence, not the source.
- Go garble: fix `pclntab` first, mem-dump, then AES-GCM/`shstrtab` carve for the flag.
- angr maze/VM stall → `find`+`avoid` per basic block + `veritesting off`; concrete DFS first for mazes.
- Ternary/custom-ISA: write the trit emulator + disassembler before touching z3.

Deep-read bodies (15 complete articles): techniques/r5-deep-reads.md.
