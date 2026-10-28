# PWN writeup patterns R2-1 — W31..W40 (glibc 2.38-2.41 heap + post-Apple IO)

> Technique-only. Bodies for SKILL.md R2 index W31–W40. Each pattern: signals →
> steps → pwntools snippet → pitfalls → 2–3 R2 manifest sources. No flags.

## W31 — glibc 2.39 tcache-count-7 + calloc path (Tangerine variant)

- Signals: protections any + shipped libc 2.39 (Ubuntu 24.04) + heap menu where
  `calloc` is reachable + tcache poison goal but counts look "wrong" after calloc.
- Steps: (1) leak heap + libc via unsorted/UAF; (2) saturate target bin counts to
  7 with filler frees; (3) account that `calloc` decrements the same `counts[]`
  byte — plan one extra fill or use count-7 saturation to force the unsorted-bin
  path explicitly; (4) poison `entries[]` with `protect(pos, target)` and allocate
  through `calloc` to land the arbitrary chunk.
- Snippet: `for _ in range(7): free(filler[_])  # saturate; counts==7 forces unsorted`
  then `edit(vuln, p64(protect(pos, target)))  # calloc path respects same counts`.
- Pitfalls: forgetting calloc shares counts[] breaks the groom (chunk lands in
  tcache instead of unsorted); 2.39 still needs heap leak for safe-link encode;
  guard chunk required so consolidation never swallows the victim.
- Sources: https://github.com/HyggeHalcyon/CTFs/blob/main/2024/%C3%A5ngstrom/heapify/exploit.py · https://github.com/shellphish/how2heap/blob/master/glibc_2.39/tcache_stashing_unlink_attack.c · https://ctftime.org/writeup/40715

## W32 — safe-link double-protect + z3/nibble bootstrap (2.38-2.41)

- Signals: glibc ≥2.32 (esp. 2.38/2.39/2.41) + mangled `fd` observed via UAF show
  + no direct heap pointer + fork server or z3 available.
- Steps: (1) read mangled `enc`; (2) if low-12 of heap known, iterative
  `reveal(pos, enc) = (pos >> 12) ^ enc`; else z3
  `(res >> 12) ^ res == leak` constrained to heap range, or 1/16 nibble brute with
  oracle; (3) verify decoded value in `vmmap` heap range; (4) `protect(pos, t)`
  for poison — and check `tcache` dump for double-protect (some paths apply
  protect twice).
- Snippet: `reveal = lambda pos, enc: (pos >> 12) ^ enc` /
  `s.add((res >> 12) ^ res == leak); s.add((res >> 24) >= 0x55, (res >> 24) <= 0x57)`.
- Pitfalls: single-nibble 1/16 gamble must be parallelized + checkpointed; raw
  `p64` without encode aborts with `unaligned tcache chunk`; double-protect paths
  look like "correct encode but wrong head" in `tcache` dump.
- Sources: https://github.com/SleepTheGod/HackTheBoxWriteups/blob/main/Heapify.md · https://github.com/HyggeHalcyon/CTFs/blob/main/2024/%C3%A5ngstrom/heapify/exploit.py · https://ctftime.org/writeup/40715

## W33 — cross-bin smallbin-to-tcache stashing unlink (calloc, 2.39)

- Signals: glibc 2.29-2.39 + smallbin + tcache interaction + `calloc` reachable +
  size-change primitive (1B overflow) or unsorted/smallbin chunk to manipulate.
- Steps: (1) change a freed chunk's size so it lands in a different bin than
  expected (e.g. shrink 0x118→0x20); (2) free so smallbin holds victim + fake;
  (3) `calloc` same-size triggers stashing unlink moving smallbin→tcache with
  attacker fd; (4) poisoned tcache entry returns arbitrary chunk; verify head via
  `tcache` dump before committing.
- Snippet: `edit(a, b'A'*off + p16(0x20))  # shrink; free(a)  # lands tcache-0x20 via stash`.
- Pitfalls: size must stay valid + aligned or malloc asserts; consolidation
  swallows victim without a guard chunk; 2.39 calloc count interaction (W31)
  must be accounted or the stash never fires.
- Sources: https://github.com/shellphish/how2heap/blob/master/glibc_2.39/tcache_stashing_unlink_attack.c · https://ctftime.org/writeup/40715 · https://github.com/HyggeHalcyon/CTFs/blob/main/2024/%C3%A5ngstrom/heapify/exploit.py

## W34 — largebin bk_nextsize sorted-insert edge (2.30+, smaller-wins)

- Signals: large sizes ≥0x400 + UAF/overflow into largebin chunk + tcache
  full/isolated + Full RELRO + shipped 2.38/2.39 libc.
- Steps: (1) groom p1 > p2 into the same largebin; (2) libc leak via unsorted fd;
  (3) corrupt p1 `bk_nextsize`/`fd_nextsize` to `target-0x20`; (4) allocate p2
  (smaller) so sorted-insert writes p1's heap address to target (`_IO_list_all`,
  TLS, or struct); (5) confirm branch taken — inserted chunk MUST be smaller or
  the 2.30+ integrity check kills the path.
- Snippet: `p2_bk_nextsize = target - 0x20  # insert writes p1 addr; require size(p2) < size(p1)`.
- Pitfalls: larger-than-smallest path aborts post-2.30 — size order is load-bearing;
  nextsize pointers are raw (no safe-link) but offsets must come from the SHIPPED
  libc; needs both heap + libc leaks first.
- Sources: https://ctftime.org/writeup/40715 · https://www.roderickchan.cn/zh-cn/house-of-apple-%E4%B8%80%E7%A7%8D%E6%96%B0%E7%9A%84glibc%E4%B8%ADio%E6%94%BB%E5%87%BB%E6%96%B9%E6%B3%95-1 · https://github.com/yaklang/hack-skills/blob/main/skills/heap-exploitation/HOUSE_OF_TECHNIQUES.md

## W35 — House-of-Cat all-version IO finish (2.35 + 2.39 deltas)

- Signals: heap + libc leaks + arbitrary alloc/write + `exit`/return path +
  hooks dead + need TLS-guard-free IO endgame (works across 2.35→2.39 with
  adjusted forge).
- Steps: (1) resolve real `_IO_wfile_jumps` from shipped libc (never forge the
  table — passes `_IO_vtable_check`); (2) build fake FILE + wide-data per the
  version's forge-process table (2.35 vs 2.39 field deltas checked against shipped
  libc); (3) plant via largebin/tcache poison to `_IO_list_all`/`_chain`;
  (4) trigger `exit`/abort/main-return and ride the want-function path.
- Snippet: `fs.vtable = libc.sym._IO_wfile_jumps - 0x20; fs._wide_data = scratch  # version-adjusted forge`.
- Pitfalls: 2.35 vs 2.39 IO-structure deltas break copy-paste FILE blobs — always
  re-derive against SHIPPED libc; wrong trigger (return vs exit) looks identical
  to wrong FILE; `_wide_data` NULL kills the wide path silently.
- Sources: https://bbs.kanxue.com/thread-273895.htm · https://xz.aliyun.com/news/15379 · https://samuzora.com/posts/fsop/fsop-analysis

## W36 — House-of-Emma cookie-write + pointer-mangle (2.34+)

- Signals: glibc ≥2.34 + FILE write primitive + libc leak + need code-exec via
  `_IO_cookie` path + pointer-guard present.
- Steps: (1) target `_IO_cookie_jumps`-family slot with attacker-controlled
  write; (2) handle `PTR_DEMANGLE` on the callback (x86-64 ROL17 encoding —
  needs `__pointer_chk_guard` at `fs:0x30` leaked or zeroed path); (3) set
  `codecvt`/cookie slot to `system`-equivalent or `setcontext` pivot;
  (4) trigger flush (`exit`/abort) with `fp` = attacker bytes so first arg lands
  controlled.
- Snippet: `stored = rol(ptr, 0x11) ^ guard  # forge; need guard leak from fs:0x30`.
- Pitfalls: guard unknown = crash, not shell — leak `fs:0x30` first or pick a
  guard-free house (Cat/Apple2); 2.24+ vtable check still applies to the main
  vtable — point at a real table.
- Sources: https://github.com/Mistyovo/pwn-rag-kb/blob/master/heap/house-of-emma.md · https://xz.aliyun.com/news/12380 · https://github.com/yaklang/hack-skills/blob/main/skills/heap-exploitation/HOUSE_OF_TECHNIQUES.md

## W37 — House-of-Kiwi malloc_assert + fflush(stderr) trigger

- Signals: glibc 2.29+ sandboxed heap + `stderr` reachable + ability to shrink top
  or corrupt size + need an `exit`-free IO trigger.
- Steps: (1) shrink top size below MINSIZE / clear pre_inuse / misalign old_top
  to arm `__malloc_assert` on next malloc-family call; (2) hijack
  `_IO_helper_jumps+0xA0/0xA8` (ORW/ret pair) and `_IO_file_jumps+0x60`
  (`_IO_file_sync`) per the Kiwi template; (3) next `malloc/calloc/realloc`
  fires assert → `fflush(stderr)` → hijacked `__sync` → `setcontext+61` stack
  migration → ROP/ORW.
- Snippet: `top.size = 0x10  # < MINSIZE arms assert; next malloc → fflush(stderr) → __sync hijack`.
- Pitfalls: deprecated on newest glibc vtable checks — main vtable must be real;
  needs 2 write primitives (helper slots + sync slot) or one largebin + one UAF;
  wrong top-corrupt value asserts differently (clean abort, no flush).
- Sources: https://4xura.com/binex/heap/house-of-kiwi · https://github.com/Mistyovo/pwn-rag-kb/blob/master/heap/house-of-kiwi.md · https://1uckyc.github.io/2023/09/03/house-of-wiki%E5%AD%A6%E4%B9%A0%E4%BB%A5%E5%8F%8A%E5%A4%8D%E7%8E%B0

## W38 — House-of-Pig str_overflow + stash unlink (2.31+)

- Signals: glibc 2.31+ + largebin attack available + `_IO_list_all` reachable +
  tcache-stash path open + hooks dead.
- Steps: (1) largebin attack writes heap address to `_IO_list_all`; (2) forge
  `_IO_FILE` calling `_IO_str_overflow` (malloc/memcpy gadgetry) on flush;
  (3) the inner malloc triggers tcache-stashing unlink for arbitrary write;
  (4) overwrite `__free_hook`-era equivalent (`__exit_funcs`/stack retaddr on
  modern) and trigger.
- Snippet: `largebin_attack(_IO_list_all, heap_addr); fake_FILE._overflow = _IO_str_overflow  # stash follows`.
- Pitfalls: needs largebin + FILE + stash triple — missing any one, pick
  Apple2/Cat instead; `_IO_str_overflow` malloc size must be tcache-eligible or
  the stash never fires.
- Sources: https://samuzora.com/posts/fsop/fsop-analysis · https://github.com/yaklang/hack-skills/blob/main/skills/heap-exploitation/HOUSE_OF_TECHNIQUES.md · https://github.com/todordev/pentesting-skills/blob/main/skills/heap-exploitation/IO_FILE_EXPLOITATION.md

## W39 — House-of-Husk double-largebin + printf_table (2.35)

- Signals: glibc 2.35 + double-largebin primitives + `__printf_function_table`
  reachable + need stack-wash ROP/ORW finish.
- Steps: (1) groom two largebin chunks; (2) corrupt nextsize chain to hijack
  `__printf_function_table`; (3) trigger printf-family path with attacker table;
  (4) stack-wash into ROP/ORW (execve-blocked → ORW variant).
- Snippet: `hijack(__printf_function_table, fake_table); printf("%s", controlled)  # table dispatch`.
- Pitfalls: table offset is version-specific — derive from shipped libc; needs
  BOTH heap + libc leaks; printf trigger args must be controlled or dispatch
  lands on garbage.
- Sources: https://github.com/yaklang/hack-skills/blob/main/skills/heap-exploitation/HOUSE_OF_TECHNIQUES.md · https://github.com/todordev/pentesting-skills/blob/main/skills/heap-exploitation/IO_FILE_EXPLOITATION.md · https://github.com/Kur1sulab/blackbox/blob/main/hack-heap-exploitation/IO_FILE_EXPLOITATION.md

## W40 — House-of-Tangerine/Muney count-saturation bridge (2.39)

- Signals: glibc 2.39 + tcache + unsorted-bin both reachable + no direct
  overflow into fd + `calloc` present.
- Steps: (1) fill target bin counts toward 7; (2) bridge tcache↔unsorted via
  Muney-style count + unsorted variant (corrupt unsorted `bk` to `target-0x10`
  while counts saturate); (3) allocation returns attacker address without a
  direct fd overwrite; (4) finish via FILE/retaddr per W35/W31.
- Snippet: `fill_to_7(bin); corrupt(unsorted.bk, target-0x10)  # bridge without fd overwrite`.
- Pitfalls: count math off-by-one routes the chunk to the wrong bin — verify
  with `bins`/`tcache` dumps; consolidation risk without guard chunk.
- Sources: https://github.com/shellphish/how2heap/blob/master/glibc_2.39/tcache_stashing_unlink_attack.c · https://github.com/HyggeHalcyon/CTFs/blob/main/2024/%C3%A5ngstrom/heapify/exploit.py · https://github.com/ljagiello/ctf-skills/blob/main/ctf-pwn/heap-fsop.md
