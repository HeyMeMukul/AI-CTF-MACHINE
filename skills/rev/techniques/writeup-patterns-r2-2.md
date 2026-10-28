# R2 patterns W41–W48 — stolen-bytes, hybrid symbolic, deobfuscation (bodies; index in SKILL.md)

## W41 — Stolen-bytes / API-redirection (Themida stolen OEP bytes)
- Signals: dump at OEP starts mid-function, entry bytes missing, calls redirect through stub trampolines, `.text` first bytes zeroed.
- Steps: 1) compare dump entry vs live memory (`Memory.readByteArray` at OEP) 2) copy stolen bytes from live into dump COPY 3) fix redirected calls (stub → real target from trace) 4) re-analyze COPY, solve, validate on original.
- Commands: `frida -q -l dump.js -f ./chal -- 2>&1 | tail` (live bytes) ; `python3 -c "d=bytearray(open('./dump.elf','rb').read()); d[0:32]=bytes.fromhex('...live...'); open('./dump.fix','wb').write(d)"`.
- Pitfalls: executing the unfixed dump (crash misread as packer-fail); stealing wrong byte count (function alignment).
- Sources: [1504](https://ctftime.org/writeup/1504) · [5ab950bb33c5d422feed87d2](https://crackmes.one/solution/5ab950bb33c5d422feed87d2) · [1531](https://ctftime.org/writeup/1531)

## W42 — angr-to-z3 handoff (concrete prefix, symbolic suffix)
- Signals: checker has long concrete prologue (decompress/unpack) + short symbolic tail (compare), angr stalls in prologue but flies in tail.
- Steps: 1) run concretely to tail entry (Frida/unicorn), dump tail state 2) start angr at tail addr with symbolic input only 3) export constraints to z3 for final invert 4) prepend concrete prologue bytes (usually fixed header) to candidate.
- Commands: `timeout 120 python3 solve_angr.py --start-addr <tail>` (angr `project.factory.blank_state(addr=TAIL)`) ; `python3 tail_z3.py` (z3 over tail constraints).
- Pitfalls: symbolic from entry (prologue explosion); tail addr off-by-one (verify `pd 10 @ <tail>`); prologue input-dependence missed.
- Sources: [36249](https://ctftime.org/writeup/36249) · [32557](https://ctftime.org/writeup/32557) · [36907](https://ctftime.org/writeup/36907)

## W43 — z3-first then angr for path-heavy tails (solver-first method)
- Signals: checker is arithmetic-heavy with few branches (hash/XOR/linear), angr overhead dominates, constraints extractable by eye.
- Steps: 1) translate checker to z3 directly (no angr), solve 2) if z3 UNSAT/timeout → mark path-heavy, switch to angr on that branch only 3) one switch, not interleaved.
- Commands: `python3 solve_z3.py` (direct `Solver()`, `BitVec`s, `solver.check()`) ; fallback `timeout 120 python3 solve_angr.py` (one alternate).
- Pitfalls: angr-first on pure arithmetic (10x slower); z3 bit-width mismatch (8 vs 32); printable constraints forgotten.
- Sources: [36249](https://ctftime.org/writeup/36249) · [32557](https://ctftime.org/writeup/32557) · [607be4ea33c5d45ca9489659](https://crackmes.one/solution/607be4ea33c5d45ca9489659)

## W44 — Unicorn-assist for angr (concretize noisy inits, symbolize only checker)
- Signals: angr returns plausible-but-wrong (zero tables, repeated bytes) — static inits not executed (see W6).
- Steps: 1) emulate CRT/static inits in Unicorn, snapshot tables 2) inject tables into angr via `mem_write` / `hook` 3) symbolic only the checker region 4) compare Unicorn-concrete vs angr-symbolic on `AAAA`.
- Commands: `emu.emu_start(crt_init,0); emu.mem_read(table,len)` (Unicorn) then `p.loader.memory.write(addr,bytes)` (angr preload) ; `python3 solve_hybrid.py`.
- Pitfalls: Unicorn/angr addr mismatch (base/PIE); stale snapshot (re-init per run); full-program Unicorn (syscall death).
- Sources: [29593](https://ctftime.org/writeup/29593) · [27588](https://ctftime.org/writeup/27588) · [36907](https://ctftime.org/writeup/36907)

## W45 — Veritesting / loop-bounded angr on hardened checkers (input-length cap + timeout)
- Signals: checker loops over input (N=24–64) with per-byte branches, naive angr forks N times, `sim.active` balloons.
- Steps: 1) cap N from `read()` size, fix known prefix concretely 2) enable veritesting/loop-bounding (`angr` veritesting option), `avoid=` fail per iteration 3) `timeout 120`, halve N on explosion 4) drop to re-impl on second explosion.
- Commands: `timeout 120 python3 solve_angr.py` with `p.factory.simgr(st, veritesting=True)` ; `grep -m5 'read(0' st.log` (N source).
- Pitfalls: unbounded N (read-until-newline misread as fixed); veritesting on hash (still unsat); extending timeout instead of halving N.
- Sources: [36249](https://ctftime.org/writeup/36249) · [32557](https://ctftime.org/writeup/32557) · [32472](https://ctftime.org/writeup/32472)

## W46 — MBA/opaque residue strip (D-810/GOOMBA-style pass after deflat)
- Signals: deflattened CFG still has `x*(x+1)%2`, `(a^b)*c` junk, Ghidra shows arithmetic but behavior is `mov`-equivalent.
- Steps: 1) state-var deflat first (W32) 2) run MBA-simplify pass (`claripy.simplify` + 256-sample) per block 3) prove opaque with z3 prover (Playbook D snippet) 4) NOP dead arms on COPY, re-analyze.
- Commands: `python3 -c "import claripy; print(claripy.simplify(expr))"` ; sampling loop over 256 inputs (kill 90% cheap) ; z3 prover for remainder.
- Pitfalls: simplifying before deflat (re-flatten); 5-min-per-predicate cap ignored (rabbit hole); original patched.
- Sources: [32472](https://ctftime.org/writeup/32472) · [24437](https://ctftime.org/writeup/24437) · [24452](https://ctftime.org/writeup/24452)

## W47 — CFF + opaque hybrid (state-var map + prover in one pass)
- Signals: OLLVM CFF (dispatcher + state) PLUS opaque preds inside handlers, either alone leaves CFG broken.
- Steps: 1) map `state->block` statically 2) sample-prove each handler branch (concrete 256 first) 3) rebuild CFG from surviving edges only 4) solve rebuilt CFG (angr on COPY or re-impl).
- Commands: `r2 -A -q -c 'pdf @ <dispatcher>' ./chal | grep -m20 'mov.*state'` ; `python3 prove_all.py` (sample+z3 per branch).
- Pitfalls: handler arithmetic state updates (need one concrete trace); dead-arm re-added by re-analysis (freeze COPY).
- Sources: [32472](https://ctftime.org/writeup/32472) · [24437](https://ctftime.org/writeup/24437) · [5ab950b033c5d422feed845d](https://crackmes.one/solution/5ab950b033c5d422feed845d)

## W48 — OLLVM bogus-CFG slice-out (sample-then-avoid, never full deflat)
- Signals: bogus control flow (fake blocks with `ud2`/never-taken), real path is short, full deflat overkill.
- Steps: 1) Frida Stalker trace on `AAAA` (executed blocks only) 2) mark unexecuted blocks `avoid=` in angr or NOP on COPY 3) solve sliced CFG 4) validate on original.
- Commands: `frida -q -l stalker.js -f ./chal -- <<< 'AAAA' 2>&1 | sort -u > exec.txt` ; `timeout 120 python3 solve_angr.py --avoid-file exec.txt`.
- Pitfalls: single-trace overfit (trace accept + reject, union); `ud2` block treated as real (crash misread).
- Sources: [32472](https://ctftime.org/writeup/32472) · [31246](https://ctftime.org/writeup/31246) · [32557](https://ctftime.org/writeup/32557)
