# R2 patterns W49–W56 — .NET/Unity, Flutter/Dart, EVM (bodies; index in SKILL.md)

## W49 — Il2CppDumper + GameAssembly (Unity native checker)
- Signals: `libil2cpp.so` + `global-metadata.dat`, `GameAssembly.dll` missing (native), Unity strings, checker in C++ not C#.
- Steps: 1) `Il2CppDumper` on `libil2cpp.so` + `global-metadata.dat` → `dump.cs` + `script.py` 2) grep `dump.cs` for `Check/Verify/Flag` → method addr 3) Ghidra at `GameAssembly+offset`, follow `(ptr,len)` args 4) re-impl or Frida hook the method.
- Commands: `Il2CppDumper ./libil2cpp.so ./global-metadata.dat ./out` ; `grep -rn -m20 -i 'check\|verify\|flag' ./out/dump.cs | head` ; `frida -U -f com.target.app -l hook.js --no-pause` (method hook).
- Pitfalls: metadata version mismatch (wrong Il2CppDumper ver); `dump.cs` offsets vs ASLR (add base); C# names vs native mangling.
- Sources: [38248](https://ctftime.org/writeup/38248) · [36505](https://ctftime.org/writeup/36505) · [36292](https://ctftime.org/writeup/36292)

## W50 — .NET Reactor / ConfuserEx deobf (de4dot-style before dnSpy)
- Signals: `.NET` PE but dnSpy shows `ConfusedBy`, control-flow junk, string-encryptor calls, `ilspycmd` output garbage.
- Steps: 1) detect packer (`diec`, `Detect-It-Easy` → Reactor/Confuser) 2) deobf on COPY (`de4dot` family / UnpacMe concept) 3) dnSpy on CLEANED assembly 4) staged-code assembly (W22) on cleaned output.
- Commands: `diec ./chal.exe | head` ; `de4dot -f ./chal.exe -o ./chal.clean.exe 2>&1 | head` (COPY only) ; `ilspycmd -o ./dec ./chal.clean.exe`.
- Pitfalls: deobf on original (backup first); string-decryptor not run (need live dump, W21); version-specific deobf (wrong unpacker ver).
- Sources: [38248](https://ctftime.org/writeup/38248) · [36528](https://ctftime.org/writeup/36528) · [36757](https://ctftime.org/writeup/36757)

## W51 — Blazor / dotnet-WASM (checker in .NET inside wasm)
- Signals: `dotnet.wasm` + `blazor.boot.json`, `_framework/` dir, `mono_wasm` imports, checker in C# compiled to wasm.
- Steps: 1) list `_framework` assemblies (`blazor.boot.json`) 2) `ilspycmd` on `*.dll` (not `wasm2c`) 3) follow `Check` method, re-impl 4) JS-glue length gate first (W28).
- Commands: `cat ./_framework/blazor.boot.json | python3 -c "import json,sys; print(json.load(sys.stdin)['resources']['assembly'].keys())"` ; `ilspycmd -o ./dec ./_framework/App.dll`.
- Pitfalls: `wasm2c` on `dotnet.wasm` (wrong layer — logic is in DLLs); AOT vs interpreted (different dump path).
- Sources: [36505](https://ctftime.org/writeup/36505) · [36528](https://ctftime.org/writeup/36528) · [38248](https://ctftime.org/writeup/38248)

## W52 — PyInstaller / bundle + native ext (PYZ + .so checker)
- Signals: `PyInstaller` strings, `PYZ` archive, `_MEI` temp dir, checker imports a native `.so` (not pure Python).
- Steps: 1) `pyi-archive_viewer` extract PYZ → `uncompyle6` Python layer 2) find native ext import (`import _check`) 3) reverse the `.so` with normal loop (checker lives there) 4) reuse-or-reimpl the `.so` function.
- Commands: `pyi-archive_viewer ./chal 2>&1 | head -n 20` ; `python3 -m uncompyle6 -o ./src ./extracted/check.pyc` ; `nm -D ./_check.so | head`.
- Pitfalls: Python-only solve when logic is native (wasted); `_MEI` cleanup deleting evidence (copy first).
- Sources: [29593](https://ctftime.org/writeup/29593) · [27588](https://ctftime.org/writeup/27588) · [36292](https://ctftime.org/writeup/36292)

## W53 — Flutter/Dart snapshot (libapp.so + snapshot reverse)
- Signals: `Flutter` strings, `libapp.so`, `libflutter.so`, `kDartIsolateSnapshot` sections, no `main.main`, Dart kernel blob.
- Steps: 1) confirm Flutter (`strings | grep -m3 Flutter`) 2) extract Dart snapshot (`libapp.so` `.rodata` + `reFlutter`/`Dart` tools) 3) locate checker via string xref in snapshot 4) Frida hook Dart entry or re-impl the check function.
- Commands: `strings ./libapp.so | grep -m5 -i 'flutter\|dart'` ; `python3 -m reflutter ./app.apk 2>&1 | head` (or `blutter` for snapshot) ; `frida -U -f com.target -l dart_hook.js --no-pause`.
- Pitfalls: `jadx` on Flutter APK (Java layer is trampoline only); snapshot version pin (engine ver must match); AOT vs JIT snapshot confusion.
- Sources: [33430](https://ctftime.org/writeup/33430) · [33429](https://ctftime.org/writeup/33429) · [README.md](https://github.com/BYU-CSA/BYUCTF-2026/blob/main/rev/back_and_forth/README.md)

## W54 — Dart AOT disasm (gen_snapshot Artifact → assembly)
- Signals: Flutter AOT (`snapshot_data`, `snapshot_instructions`), checker compiled to ARM/x64, no Dart source, `dartaotruntime` strings.
- Steps: 1) split `snapshot_instructions` from `libapp.so` 2) dis with Dart-aware tool (AOT disassembler) or Ghidra at snapshot base 3) string-xref to checker, model Dart objects (tagged pointers) 4) hook at runtime to dump args.
- Commands: `rabin2 -S ./libapp.so | grep -i -m5 'snapshot\|dart'` ; `objdump -d --start-address=<snap> ./libapp.so | head -n 40`.
- Pitfalls: tagged-pointer misread (low bits are tags, not addr); GC moving objects (hook, don't hardcode addrs).
- Sources: [24487](https://ctftime.org/writeup/24487) · [31524](https://ctftime.org/writeup/31524) · [README.md](https://github.com/BYU-CSA/BYUCTF-2026/blob/main/rev/back_and_forth/README.md)

## W55 — EVM bytecode decompile (dispatcher + decompiler before logic)
- Signals: `0x60806040` prologue, `evm`/`web3` strings, `.sol` missing, `contract.json` with `bytecode`, runtime vs creation code.
- Steps: 1) split creation vs runtime (`bin` → `runtime` after `CODECOPY`) 2) `evm disasm` / `heimdall` decompile 3) map function selectors (`sighash` → name) 4) storage-map the flag check (see W56).
- Commands: `heimdall decompile --target ./contract.bin --output ./dec 2>&1 | head -n 40` ; `evm disasm ./runtime.bin | grep -m10 'SSTORE\|SLOAD\|CALLDATALOAD'` ; `cast selectors ./runtime.bin 2>/dev/null | head`.
- Pitfalls: creation-code analyzed as runtime (off by init); proxy/delegatecall (logic in impl contract, not proxy); optimizer reordering (source-line mismatch).
- Sources: [32557](https://ctftime.org/writeup/32557) · [5ab950ba33c5d422feed87a5](https://crackmes.one/solution/5ab950ba33c5d422feed87a5) · [607be4ea33c5d45ca9489659](https://crackmes.one/solution/607be4ea33c5d45ca9489659)

## W56 — EVM storage-slot key recovery (SLOAD/SSTORE map, no exploit)
- Signals: decompiled EVM shows `SLOAD(slot)` compared against `CALLDATALOAD`, `SSTORE` in constructor sets secret, no external calls.
- Steps: 1) list `SSTORE` slots from deployment trace 2) read slots via `eth_getStorageAt` (local `anvil`/`cast`) 3) use stored secret as key (gate-is-key, EVM flavor) 4) verify by local call, never mainnet.
- Commands: `cast storage <addr> 0 --rpc-url http://localhost:8545` (per slot) ; `heimdall cfg --target ./runtime.bin | grep -m10 'SLOAD'`.
- Pitfalls: hashed mapping slots (`keccak(key||slot)` — need preimage, not slot index); proxy storage collision (read impl, not proxy).
- Sources: [32557](https://ctftime.org/writeup/32557) · [5ab950ba33c5d422feed8790](https://crackmes.one/solution/5ab950ba33c5d422feed8790) · [36907](https://ctftime.org/writeup/36907)
