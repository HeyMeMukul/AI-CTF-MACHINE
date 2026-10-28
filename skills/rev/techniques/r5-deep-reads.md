# R5 deep reads — rev (14 complete articles, browser-read 2026-10-17)

## 1. TetCTF cache_v1/v2 + SimpleSystem
- READ: MurmurHash2 `INV_MAGIC 0x5f7a0ea7e59b19bd`, colliding hex pair `c2c48614…`; seccomp allows only open/read/write/close/brk/mmap/exit; v2 `refCount uint8_t` wraps at 256.
- CHAIN: collide.py → create colliding + victim chunks → OOB read heap/libc → erase victims → tcache-poison `__free_hook` with ROP-in-name; v2: duplicate 256× to wrap refcount → UAF exposes `tcache_perthread_struct`; SimpleSystem: 8 sleeping threads + filler notes to land arena chunk.
- GOTCHA: v2 check never reachable without wrap; SimpleSystem needs exact heap layout via thread/filler grooming.
- REUSE: Hash-collision/refcount-wrap primitives → stage heap precisely, leak both bases via OOB, then tcache-poison under seccomp.

## 2. OMHCTF FlagSaver (GRUB)
- READ: `.scr` is .NET (ILSpy/DNspy): `LCG(seed=51966,mod=128/65537,a=57005,c=48879)`; 1920×1080 pieces 120×120 column-major; `grub.cfg` regex `^p4\{([0-9A-Q]{54})\}$`.
- CHAIN: mount iso → read grub.cfg → reimplement `ShuffleArray` double-swap in Python (Pillow + reversed LCG) → map a(54)→b(162)→c(81) → z3 ordering+uniqueness → map back.
- GOTCHA: Unknown pieces count, layout, tick (brute 1–10 both layouts); GRUB regex semantics from GNU manual.
- REUSE: Jigsaw/regex-VM: extract PRNG constants, regenerate swap list, invert by reverse replay + SMT.

## 3. AeroCTF Dummyper (live-memory dump)
- READ: `.text`-to-heap dump via `/proc/self/mem` + `/dev/urandom` stream; `endbr64 F3 0F 1E FA` cribs first 4 key bytes at file offset `0x4ba74` (len 0x20, xors 896B); kokke/tiny-AES-C with KeyExpansion deep-copy.
- CHAIN: known-opcode XOR cribbing → search dump for key → malduck/IDA patch bytes → collect 16B strings appearing twice as key/IV candidates → AES-CBC decrypt.
- GOTCHA: Assumed malloc; chunks were contiguous data-section allocs; key/IV found via duplicate-scan (RoundKey+Iv copy appear twice).
- REUSE: Live-memory dumps: known-opcode crib for stream key; struct deep-copy duplication locates hidden crypto material.

## 4. GoogleCTF weather (printf VM)
- READ: `register_printf_function('W'/'P'/…)` 16 custom converters; `parse_fmt` + `execute/disass` emulator (`load32/store32`, MEM@5080/REGS@70A0); entry `%52C`; first byte from `37=='%'` xor.
- CHAIN: parse `%…M/C` → build disassembler + emulator → disassemble MEM blocks → 27× 32-bit BitVec at MEM[200], force-True + constraint at check → run binary with solved 28B input.
- GOTCHA: 8-bit BitVec truncates 32-bit VM arithmetic (hours lost); 32-bit vectors + entry at decrypted block.
- REUSE: Custom printf formats = VM ISA; disassembler+emulator first, symbolic input at real entry, constrain only at final check.

## 5. SekaiCTF TheBidding (Solana PDA collision)
- READ: Anchor `CreateProduct seeds=[name,id]`; server mints/bids huge amounts; win check `user==product.owner`.
- CHAIN: CPI bid to lead → CPI create_product with attacker-chosen seeds colliding victim `BidInfo` PDA (`find_program_address([auction,rich_boi])`) → victim re-init fails → `EndAuction` crowns low bidder.
- GOTCHA: Direct outbid impossible (1B vs 100T); early EndAuction blocked; PDA-collision DoS on `init` instead.
- REUSE: Seeds including victim pubkeys + free seed choice elsewhere = pre-create collision to fail victim init.

## 6. DiceCTF BabySolana (Otterworld)
- READ: Signed `NUMBER=i64`; `zero_copy` + `Option<>` non-Pod UB; `load_init` rejects set discriminator; pool math `x+=amt; x+=fee*x/100`; Otterworld password = first 4 bytes `osec`.
- CHAIN: `AuthFee::set_fee(-100)` via garbage non-None fee_manager + expired timestamp → `swap(-1000000)` zeroes pool via fee term; Otterworld: pubkey from `osec`*28 → GetFlag inits flag PDA.
- GOTCHA: Re-init takeover blocked by discriminator check; abused zero_copy+Option UB to satisfy auth without ownership.
- REUSE: `zero_copy`+`Option/Vec` = audit priority for type-confusion auth bypass; signed-amount+fee formulas = zeroing primitives.

## 7. justCTF debug_me (ptrace Nanomites + REmap)
- READ: Supervisor fork+`PTRACE_TRACEME`; markers `0xCC/0x1337BABE/0xFEEDC0DE`; `secret_key` grammar `0→j=2j+1…` + trailing `\n`; PyInstaller `python38.dll` + remapped opcodes (`EXTENDED_ARG=109`).
- CHAIN: `LD_PRELOAD` hook logging `POKETEXT/SETREGS` (minus base) + IDA NOP-patch script → reverse-walk key builder; REmap: `pyinstxtractor` → mapping from `opcode_mapped.pyc` consts → recursive `co_code` rewrite + header fix → `decompyle3`.
- GOTCHA: Parent re-encrypts on return (first appearance only); two misplaced opcodes needed hard-fix; trailing newline not NUL.
- REUSE: Nanomites: hook, don't reverse cipher; remapped-Python: recover mapping from bundled consts, recursive rewrite.

## 8. picoCTF be-quick-or-be-dead-3 (DP + timer)
- READ: `calc(0x19965)` DP recurrence mod 2³²; 3-second SIGALRM; result `0x9e22c98e`.
- CHAIN: Ghidra identify calc → Python iterative DP table → gdb `handle SIGALRM ignore; break calc+9; set $eax=result; jump past call`.
- GOTCHA: Recursion exceeds time/limits; memoised iterative DP + debugger skip of calc call.
- REUSE: Exponential overlapping recursion → bottom-up DP with word masking, patch return in debugger past anti-speed timer.

## 9. PeaCTF mixed set
- READ: `coffeetime.jar` (`BigInteger(2000,random).pow(10000)` + sleep gate); `song_of_my_people.zip` password `violin` (zip2john+rockyou); PNG `PLTE` len fixed `0x48454C50`→`0x1C5` after pngcheck; `E.xtr` magic `89 58 54 52`.
- CHAIN: jd-gui → zip2john → 7z → exiftool/pngcheck chunk repair → morse/Bacon/substitution by bold hints; `XTR`→`PNG` magic swap.
- GOTCHA: mp3 red herring (empty spectrograms); PNG EOF needs manual chunk math.
- REUSE: Multi-format chain order: file/unzip → stegsolve planes → pngcheck/exiftool repair → archive-password crack before audio/SDR.

## 10. rainpwn UD2 (chunked strncmp)
- READ: CET `endbr64`; `sigaction(SIGILL)` + `invalidInstructionException`; four `lea RIP+` to `0x201b/1f/23/27`, each `strncmp` len 3.
- CHAIN: probe → strings → `objdump -D` + `objdump -s -j .rodata` → gdb `x/s` each lea target → assemble 12B → run → formatted flag.
- GOTCHA: Dynamic stepping hits SIGILL/ud2 trap; purely static rodata + lea cross-ref instead.
- REUSE: Fixed-size strncmp chunks via lea → dump rodata, resolve targets with memory-read only.

## 11. algoatson angr crackme
- READ: `claripy.BVS("flag",8*16)` + `0x20–0x7e` constraints; `full_init_state(stdin=flag)`; `explore(find="correct",avoid="nope")`; `posix.dumps(0)`.
- CHAIN: objdump leaves → `Project(auto_load_libs=False)` → symbolic stdin + charset constraints → explore → solver assignment is key.
- GOTCHA: Loop branches explode (`2^16`); SHA/AES unsolvable; `SimProcedure` hooks, `call_state` into check, stub syscalls/rdtsc/threads.
- REUSE: angr as scalpel on single check fn with find/avoid; charset constraints up front; abandon on crypto-hash.

## 12. jorianwoltjer angr book
- READ: Hook template (`@project.hook(addr)` → dump stdin → terminate); PIE fix `Ghidra−0x100000`; XOR loop + interdependent-byte-equation examples.
- CHAIN: Ghidra post-check address → PIE-adjust → hook-print-dump template → run until hook fires → feed dumped stdin to binary.
- GOTCHA: angr-fit judgment is feel-based; reference `docs.angr.io/examples` + Cave System patterns.
- REUSE: One-file hook-to-win template with PIE-adjusted address + stdin dump for scanf→transform→memcmp binaries.

## 13. angr-docs examples map
- READ: Buckets Intro/Reversing/VulnDisc/Exploitation; `little_engine` stdin+Unicorn; `whitehat_crypto400` crackme-assist; `zwiebel` self-modifying + Unicorn; `strcpy_find`, `seccon ropsynth` (angrop).
- CHAIN: Match shape → example solve.py → Unicorn + self-mod for unpackers → hook static funcs / constrain stdin / filesystem model → explore or trace-guided stepping.
- GOTCHA: Symbolic unpacking without concrete Unicorn too slow; crypto halves need keyspace reduction.
- REUSE: Cheatsheet: concrete-Unicorn for packers, summaries for static-link, CFG-guided for multi-check-to-memcpy.

## 14. bitsCTF babyrev (predicate parse)
- READ: Giant `&&` chain `param_1[4]=='C'`, `[0xd]=='m'`, `[0x13]=='r'` … 23 slots to `[0x16]=='}'`; mixed decimal + hex indices.
- CHAIN: Ghidra decompile → copy predicate string → strip parens → split on `&&` → conditional base-16 parse → indexed array → join.
- GOTCHA: Mixed `[4]`/`[0xd]` breaks naive `int()`; `find("[")/find("]")/find("'")` extraction + conditional base.
- REUSE: Position-permuted equality checks: script split-parse-place into array, join — never manual reorder.

## 15. SKIPPED — ctftime 40347 (HTTP 500, no body)
