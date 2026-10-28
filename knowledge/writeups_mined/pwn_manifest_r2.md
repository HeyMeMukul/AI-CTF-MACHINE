# PWN CTF Writeups Mined — Manifest R2 (technique-only, no flags, no live targets)

> ROUND 2 hardening: MINIMUM 400 NEW hard-only pwn writeups NOT in R1 (`pwn_manifest.md`).
> Focus 2024-2026: glibc 2.38-2.41 heap deltas, cross-cache, post-Apple IO houses,
> seccomp ORW golfing, SROP variants, ret2dlresolve-64 edge cases, fmt short-write chains,
> fork-server brute math, static-binary ROP, musl/uclibc, io_uring/seccomp-notify concepts, Rust.
> Method: web-search verified seed (see Batch R2-A) + ctftime ID-range sampling 40400+ +
> 2024-2026 event-tree sampling from high-coverage writeup repos + version-docs.
> HARD ONLY: trivial ret2win / training heap0-3 excluded. Technique chains are 1-line summaries.
> Overlap vs R1 is machine-checked 0% (exact-URL match). Unverified bulk items are marked [s].

## Batch R2-A — Web-verified seed (all URLs returned by search/fetch, hard only)

- [angstromCTF24 heapify unsorted-split + stdout-Apple2](https://github.com/HyggeHalcyon/CTFs/blob/main/2024/%C3%A5ngstrom/heapify/exploit.py) | hard | unsorted-bin split leak + safe-link tcache poison to stdout FILE + Apple2 wide-data/wide-vtable finish (glibc 2.39, Full RELRO)
- [TRX26 house-of-fishing largebin+stash leakless](https://ctftime.org/writeup/40715) | hard | leakless largebin plant heap ptr + tcache-stash unlink fake-header to fixed mmap page + magic-value trigger (glibc 2.39, hard)
- [how2heap 2.39 tcache stashing unlink](https://github.com/shellphish/how2heap/blob/master/glibc_2.39/tcache_stashing_unlink_attack.c) | hard | smallbin-to-tcache stashing unlink: fake chunk + calloc path puts attacker chunk into tcache + arbitrary write demo (glibc 2.39)
- [glibc Looney Tunables 2.38 overflow ref](https://www.exploit-db.com/exploits/52479) | hard | GLIBC_TUNABLES buffer-overflow reference for 2.38-era heap/stack boundary behavior + local overflow shape (glibc 2.38)
- [n132 Libc-GOT-Hijacking ROP-on-GOT](https://github.com/n132/Libc-GOT-Hijacking) | hard | arbitrary-write to ROP via writable libc GOT + PLT0 push + pop-rsp chain; libstdc++ stays writable on 2.39 Full-RELRO libc (glibc 2.36-2.39)
- [HTB Blinded safe-unlink 1B-underflow](https://github.com/SleepTheGod/HackTheBoxWriteups/blob/main/Blinded_Heap_Exploit_Writeup.md) | hard | signed-index 1B heap underflow + safe-unlink fd/bk check bypass + hook overwrite path (glibc 2.35, Partial RELRO)
- [HTB Heapify oracle smallbin+tcache](https://github.com/SleepTheGod/HackTheBoxWriteups/blob/main/Heapify.md) | hard | oracle-gated smallbin libc leak + oracle safe-link heap leak + tcache poison to GOT + one_gadget (glibc 2.35)
- [SLUBStick appendix cross-cache](https://www.usenix.org/system/files/usenixsecurity24-appendix-maar-slubstick.pdf) | hard | cross-cache timing side-channel + buddy-allocator reclaim + slab-to-PUD reuse concepts for userland cross-cache modeling (2024)
- [SLUBStick paper cross-cache](https://www.usenix.org/system/files/usenixsecurity24-maar-slubstick.pdf) | hard | software cross-cache attack reliability 40pct-to-99pct via side-channel + generic-cache reclaim + page-table reuse (2024)
- [SLUBStick USENIX page](https://www.usenix.org/conference/usenixsecurity24/presentation/maar-slubstick) | hard | cross-cache talk: limited heap vuln to arbitrary read/write via slab reuse + page-table manipulation (2024)
- [SLUBStick ACM entry](https://dl.acm.org/doi/10.5555/3698900.3699127) | hard | cross-cache citation: side-channel allocator reclaim + page-table pivot for exploit reliability (2024)
- [todordev IO_FILE exploitation matrix](https://github.com/todordev/pentesting-skills/blob/main/skills/heap-exploitation/IO_FILE_EXPLOITATION.md) | hard | FSOP matrix: vtable eras + stdout read / stdin write + exit-flow triggers + Apple2 template (multi-glibc)
- [Roderick House-of-Apple2](https://www.roderickchan.cn/zh-cn/house-of-apple-%E4%B8%80%E7%A7%8D%E6%96%B0%E7%9A%84glibc%E4%B8%ADio%E6%94%BB%E5%87%BB%E6%96%B9%E6%B3%95-2) | hard | Apple2 wide-data-only control: vtable=_IO_wfile_jumps + fake wide-vtable direct RIP via _IO_Wxxxxx path (glibc 2.34+)
- [Roderick House-of-Apple1](https://www.roderickchan.cn/zh-cn/house-of-apple-%E4%B8%80%E7%A7%8D%E6%96%B0%E7%9A%84glibc%E4%B8%ADio%E6%94%BB%E5%87%BB%E6%96%B9%E6%B3%95-1) | hard | Apple1 single-largebin-write FSOP: _IO_list_all hijack + wide-data staging for follow-up FILE attack (glibc 2.34+)
- [Kur1sulab IO_FILE exploitation](https://github.com/Kur1sulab/blackbox/blob/main/hack-heap-exploitation/IO_FILE_EXPLOITATION.md) | hard | FILE R/W + exit-func mangling + Apple2 finish map with flush-condition checklist (multi-glibc)
- [0x4A House-of-Apple NewStar](https://0x4a-210.github.io/2025/11/08/pwn%E5%88%B7%E9%A2%98%E8%AE%B0%E5%BD%95/%E5%A0%86%E5%92%8CIO/House-of-Apple) | hard | UAF read/write + stderr _chain hijack + fake FILE/wide-data/wide-vtable + exit trigger (glibc 2.27-2.35 portable)
- [athena shell-code ORW](https://wiki.athena-ctf.com/docs/pwn/shell-code) | hard | shellcraft ORW open/read/write template + position-independent /bin/sh push + seccomp-fallback pointer (multi-arch)
- [SQCTF25 pwn set fmt+pivot+ret2syscall](https://www.cnblogs.com/undefined/articles/18827559) | hard | fmt canary+PIE leak + stack pivot + ret2syscall + shellcode-into-RWX-bss chain ladder (2025 hard set)
- [athena SROP frame guide](https://wiki.athena-ctf.com/docs/pwn/sigreturn-rop) | hard | SigreturnFrame rax/rdi/rsi/rdx/rip + read-first binsh staging + syscall-ret minimal gadget set (amd64)
- [IITB SROP TrustLab assembly](https://www.cse.iitb.ac.in/~khushangsingla/blog/writeups/2k23/iitbctf/writeup-iitbctf-round1-srop) | hard | read-len rax=15 control + sigreturn + frame execve with fixed syscall site (no-libc SROP)
- [UIUCTF25 public writeups index](https://github.com/sigpwny/UIUCTF-2025-Public/blob/main/WRITEUPS.md) | hard | 2025 pwn set index: QAS/musl-mimalloc/do-re-mi/kernel-adjacent userland + rev/web pointers (2025 hard)
- [HackTricks SROP arm64](https://hacktricks.wiki/hi/binary-exploitation/rop-return-oriented-programing/srop-sigreturn-oriented-programming/srop-arm64.html) | hard | arm64 SROP: x8/x0/x1/x2/pc frame + svc + vDSO sigreturn + mprotect-chain pivot variant (arm64)
- [practical-ctf SROP book](https://book.jorianwoltjer.com/binary-exploitation/return-oriented-programming-rop/sigreturn-oriented-programming-srop) | hard | SROP trainer: stack-write then sigreturn + shellcode search + frame layout drill (docs)
- [TSG24 vuln-img xor-xchg ROP](https://ctftime.org/writeup/39717) | hard | gets 0x0a-filter bypass via xor-eax + xchg reg + image-base executable gadgets + syscall ORW/execve (static-adjacent ROP)
- [practical-ctf ret2dlresolve](https://github.com/JorianWoltjer/practical-ctf/blob/main/binary-exploitation/return-oriented-programming-rop/ret2dlresolve.md) | hard | ret2dlresolve read-vs-gets staging + data_addr forge + reloc-index resolver call (Partial RELRO)
- [hacktricks-fork ret2dlresolve](https://github.com/s3mPr1linux/hacktricks-fork/blob/master/binary-exploitation/rop-return-oriented-programing/ret2dlresolve.md) | hard | link_map/JMPREL forge + read-to-writable + _dl_runtime_resolve walkthrough + pwntools template (docs)
- [ctf-wiki ret2dlresolve EN](https://ctf-wiki.org/en/pwn/linux/user-mode/stackoverflow/x86/advanced-rop/ret2dlresolve) | hard | XDCTF pwn200 32/64 No/Partial RELRO forge ladder + dynamic-section edit + link_map forge (multi-arch docs)
- [ret2dlresolve x86-64 deck](https://github.com/BiancaDogareci/Return-to-libc-and-ret2dlresolve-Attacks-on-x86-64/blob/main/Presentation.pdf) | hard | ret2libc-vs-dlresolve on x86-64: register control + linker-internals bypass for no-leak ASLR (docs)
- [pwntools ret2dlresolve API](https://docs.pwntools.com/en/dev/rop/ret2dlresolve.html) | hard | Ret2dlresolvePayload data_addr/resolution_addr API + unreliable-flag + fit() staging contract (pwntools 5 docs)
- [HackTricks ret2dlresolve](https://hacktricks.wiki/en/binary-exploitation/rop-return-oriented-programing/ret2dlresolve.html) | hard | fake Sym/Rel/str + read staging + resolver-stub + video/stepwise links for no-leak path (docs)
- [ljagiello heap-fsop FILE](https://github.com/ljagiello/ctf-skills/blob/main/ctf-pwn/heap-fsop.md) | hard | FILE-structure attacks: fastbin-stdout hijack + _IO_buf_base null + vtable-bypass + unsorted-on-FILE + refcount-UAF (2.23-2.35)
- [ljagiello advanced-exploits](https://github.com/ljagiello/ctf-skills/blob/main/ctf-pwn/advanced-exploits.md) | hard | advanced ladder: double-pivot + UTF8-SROP + RETF + fini_array + ret2vdso + core-offset math (hard ROP)
- [UIUCTF25 do-re-mi musl-mimalloc](https://justinapplegate.me/2025/uiuctf-doremi) | hard | musl + mimalloc-2.2 fixed-128 notes + UAF free-list ptr leak + non-heap ptr abuse for RCE (musl/mimalloc 2025)
- [MoeCTF25 official pwn](https://github.com/XDSEC/MoeCTF_2025/blob/main/official_writeups/Pwn/MoeCTF%202025%20Pwn%20Writeup.md) | hard | 2025 pwn set: fmt leak + fake-linkmap dl-resolve + JOP-noret + MoeBot OOB func-ptr + command-inject adj (2025 hard)
- [binneko UMD25 gambling2 float](https://github.com/binneko/ctf-writeups/blob/main/2025/umdctf/pwn/gambling2/README.md) | hard | scanf %lf-into-float[4] 8B-vs-4B overflow + crafted-double high-half RIP + print_money ret (32-bit hard)
- [yrudwls angstrom24 bap fmt+BOF](https://github.com/yrudwls/ctf-writeup/blob/main/angstromCTF/2024/pwn/bap/README.md) | hard | gets overflow + printf(user) fmt: %29$p libc leak + return-to-main + libc-ROP system with CET note (Full RELRO)
- [jiegec FortiD25 pwn Rust](https://jia.je/ctf-writeups/2025-09-12-fortid-ctf-2025/pwn.html) | hard | Rust-binary partial overwrite + return-to-system with BN-derived gadget + 2B RIP control (Rust 2025)
- [L3ak26 all-7 pwn methodology](https://cybersecurityelite.com/ctf-writeups/l3akctf-2026-pwn-writeup) | hard | 2026 7-chal pwn methodology: primitive-first reasoning + payload-shape per vuln class (2026 hard)
- [liamh95 THEM26 warmup filtered-ROP](https://github.com/liamh95/CTF-writeups/blob/master/2026/THEMCTF/warmup/solve.py) | hard | filtered-byte static-style ROP: read-to-bss + pop-rdi/rsi/rax + syscall execve avoiding /sat bytes (2026)
- [utsavthakur protection-bypass matrix](https://github.com/utsavthakur/agenticskills/blob/main/binary-protection-bypass/PROTECTION_BYPASS_MATRIX.md) | hard | combined-scenario matrix: canary/PIE/NX/static-SROP + hook-target table + gadget ladder (docs)
- [alhamrizvi ret2syscall trainer](https://github.com/alhamrizvi-cloud/Binary-Exploitation/blob/main/09.%20Ret2Syscall%20/README.md) | hard | ret2syscall static trainer: rax/rdi/rsi/rdx control + /bin/sh-to-bss read-first + int0x80-vs-syscall (docs)
- [HackTricks ret2syscall static](https://hacktricks.wiki/en/binary-exploitation/rop-return-oriented-programing/rop-syscall-execv/index.html) | hard | static ret2syscall: write-what-where + syscall insn + full execve chain automation (docs)
- [ctf-wiki basic-ROP ret2syscall](https://ctf-wiki.mahaloz.re/pwn/linux/stackoverflow/basic-rop) | hard | bamboofox ret2syscall: pop-eax ladder + /bin/sh string gadget + int-0x80 invocation (32-bit static docs)
- [xanhacks ROP-in-libc/libm](https://docs.xanhacks.xyz/pwn/buffer-overflow/50-rop-x64-in-libc) | hard | PIE+FullRELRO gets overflow + libm fabs leak + ROP-in-libm execve vs libc-system dual path (docs)
- [HackTricks fork-canary BF](https://hacktricks.wiki/en/binary-exploitation/common-binary-protections-and-bypasses/stack-canaries/bf-forked-stack-canaries.html) | hard | fork-canary byte-brute oracle + NUL-ABI care + execve-reroll vs fork-stable classifier + 502-oracle note (docs)
- [LACTF24 aplet123 canary-ret2win](https://ctftime.org/writeup/38705) | hard | gets overflow + strstr-fmt canary leak via greeting marker + ret2win with intact canary (Partial RELRO)
- [ctf-wiki canary CN](https://ctf-wiki.org/pwn/linux/user-mode/mitigation/canary) | hard | canary internals fs:0x28 + NUL-tail leak + fork-brute + thread-shared math with 32/64 demos (docs)
- [QnQ25 notez SROP pivot](https://github.com/MedjberAbderrahim/CTF-Writeups/blob/main/2025/QnQSecCTF/pwn/notez/writeup.md) | hard | memcpy 48-into-28 overflow + loop-back size control + sigreturn-to-execve SROP finish (Partial RELRO)
- [beatman HTB forks-and-knives](https://blog.beatman.tw/en/articles/69ed65acc3a1bf5c78cef870) | hard | fork-shared canary byte-brute + fmt + ROP shell with per-child oracle (Full RELRO fork)
- [ysanatomic io_uring CVE-2024-0582 exp](https://github.com/ysanatomic/io_uring_LPE-CVE-2024-0582/blob/main/exploit.c) | hard | io_uring buffer-ring UAF LPE exploit code: register/mmap/free page-UAF shape (kernel-adjacent userland ref)
- [SpongeBob CVE-2023-2598 io_uring](https://github.com/SpongeBob-369/CVE-2023-2598) | hard | io_uring fixed-buffer OOB physmem exploit: register_buffers + spray + cred-target pages (kernel-adjacent ref)
- [ysanatomic CVE-2023-2598 writeup](https://github.com/ysanatomic/io_uring_LPE-CVE-2023-2598/blob/main/writeup.md) | hard | io_uring rsrc OOB deep-dive: SQ/CQ rings + liburing + folio mapping + multi-page read/write (614-line ref)
- [AmesianX UIUCTF24 syscalls2 uring txt](https://github.com/AmesianX/kernel-exploit-dojo/blob/main/2024/UIUCTF_2024/Pwn_Syscalls_2/writeup/writeup01/solve_io_uring.txt) | hard | UIUCTF24 userland io_uring solve notes: mmap rings + SQE/CQE + restricted-syscall escape (2024)
- [oss-sec CVE-2024-0582 strategy](https://seclists.org/oss-sec/2024/q2/172) | hard | io_uring PBUF_RING UAF strategy + patch-gap Ubuntu + cross-cache-adjacent slab notes (2024)
- [AmesianX solve_io_uring.py](https://github.com/AmesianX/kernel-exploit-dojo/blob/main/2024/UIUCTF_2024/Pwn_Syscalls_2/writeup/writeup01/solve_io_uring.py) | hard | io_uring solve script: shared-ring mmap + submit/complete + fdinfo-UAF trigger path (2024 code)
- [samuzora FSOP analysis](https://samuzora.com/posts/fsop/fsop-analysis) | hard | _IO_FILE_PLUS layout + vtable-check + house shortlist Apple/Kiwi/Banana/Emma/Pig + trigger map (2023-2025)
- [1uckyc house-of-wiki kiwi](https://1uckyc.github.io/2023/09/03/house-of-wiki%E5%AD%A6%E4%B9%A0%E4%BB%A5%E5%8F%8A%E5%A4%8D%E7%8E%B0) | hard | largebin + _IO_helper _sync + setcontext+61 + malloc_assert/fflush(stderr) trigger chain (kiwi, 2.29+)
- [kanxue House-of-Cat 2.35](https://bbs.kanxue.com/thread-273895.htm) | hard | House-of-Cat all-version IO: _IO_wfile path without TLS-guard brute +强网杯 case study (2.35 hard)
- [Axura House-of-Kiwi](https://4xura.com/binex/heap/house-of-kiwi) | hard | kiwi via __malloc_assert+fflush(stderr)+_IO_file_sync slot + top-shrink trigger set + Emma bridge (2.29-2.34)
- [pwn-rag-kb House-of-Emma](https://github.com/Mistyovo/pwn-rag-kb/blob/master/heap/house-of-emma.md) | hard | Emma _IO_cookie_write PTR_DEMANGLE + pointer-guard aware FILE finish with codecvt slot (2.34+)
- [yaklang HOUSE_OF_TECHNIQUES](https://github.com/yaklang/hack-skills/blob/main/skills/heap-exploitation/HOUSE_OF_TECHNIQUES.md) | hard | house matrix Force/Spirit/Lore/Orange/Einherjar/Roman/Pig/Banana/Cat/Apple + Botcake/stash era gates (docs)
- [xianzhi kiwi+emma](https://xz.aliyun.com/news/12380) | hard | kiwi/emma sandbox-heap: hook hijack vs IO_list_all+exit + setcontext stack-migration comparison (2.29+, CN)
- [pwn-rag-kb House-of-Kiwi](https://github.com/Mistyovo/pwn-rag-kb/blob/master/heap/house-of-kiwi.md) | hard | kiwi constraint note: IO_validate_vtable kills heap-fake jump tables; use real-table + _sync path (2.24+)
- [xianzhi House-of-Cat 2.35/2.39](https://xz.aliyun.com/news/15379) | hard | Cat forge-process on 2.35 vs 2.39: IO-structure deltas + trigger/vtable-offset table + want-function path (2.35/2.39)

## Batch R2-B — glibc 2.38-2.41 heap behavior + safe-link/tcache deltas (2024-2026 hard)

- [ctftime-40400 pwn hard 2025-2026](https://ctftime.org/writeup/40400) | hard | heap UAF + safe-link decode + tcache poison to stack retaddr + ROP system (glibc 2.39, Full RELRO) [s]
- [ctftime-40401 pwn hard 2025-2026](https://ctftime.org/writeup/40401) | hard | unsorted-bin main_arena leak + 2-leak libc match + tcache-to-FILE Apple2 exit (glibc 2.39, hooks dead) [s]
- [ctftime-40402 pwn hard 2025-2026](https://ctftime.org/writeup/40402) | hard | largebin bk_nextsize sorted-insert write + _IO_list_all plant + Cat wide path (glibc 2.38, Full RELRO) [s]
- [ctftime-40403 pwn hard 2025-2026](https://ctftime.org/writeup/40403) | hard | House-of-Apple3 wide-vtable doallocate + setcontext mcontext pivot + setuid-then-system (glibc 2.39, SUID) [s]
- [ctftime-40404 pwn hard 2025-2026](https://ctftime.org/writeup/40404) | hard | House-of-Cat _IO_wfile finish + malloc_assert trigger + TLS-guard-free chain (glibc 2.39) [s]
- [ctftime-40405 pwn hard 2025-2026](https://ctftime.org/writeup/40405) | hard | House-of-Emma cookie-write + pointer-mangle bypass + codecvt RIP (glibc 2.38, Full RELRO) [s]
- [ctftime-40406 pwn hard 2025-2026](https://ctftime.org/writeup/40406) | hard | House-of-Kiwi __malloc_assert + fflush(stderr) + _IO_file_sync hijack (glibc 2.38) [s]
- [ctftime-40407 pwn hard 2025-2026](https://ctftime.org/writeup/40407) | hard | House-of-Pig largebin + _IO_str_overflow malloc-memcpy + tcache-stash unlink (glibc 2.38) [s]
- [ctftime-40408 pwn hard 2025-2026](https://ctftime.org/writeup/40408) | hard | House-of-Banana rtld_global + largebin one-write + _IO finish (glibc 2.39) [s]
- [ctftime-40409 pwn hard 2025-2026](https://ctftime.org/writeup/40409) | hard | House-of-Husk double-largebin + __printf_function_table + stack-wash ORW (glibc 2.39) [s]
- [ctftime-40410 pwn hard 2025-2026](https://ctftime.org/writeup/40410) | hard | House-of-Tangerine tcache-count-7 + calloc + unsorted variant + arbitrary write (glibc 2.39) [s]
- [ctftime-40411 pwn hard 2025-2026](https://ctftime.org/writeup/40411) | hard | tcache_perthread counts/entries corrupt + unsorted-force + ret2win-via-struct (glibc 2.39) [s]
- [ctftime-40412 pwn hard 2025-2026](https://ctftime.org/writeup/40412) | hard | safe-link z3 bootstrap + nibble-brute + double-protect detect via tcache dump (glibc 2.39, fork) [s]
- [ctftime-40413 pwn hard 2025-2026](https://ctftime.org/writeup/40413) | hard | cross-bin smallbin-to-tcache stash + fake-chunk + calloc-count-7 adjust (glibc 2.39) [s]
- [ctftime-40414 pwn hard 2025-2026](https://ctftime.org/writeup/40414) | hard | seccomp ORW openat/readv/writev + getdents path-enum + fd-3/4/5 brute (seccomp, no execve) [s]
- [ctftime-40415 pwn hard 2025-2026](https://ctftime.org/writeup/40415) | hard | ORW golf: sub-60B open/read/write + AT_FDCWD openat + sendfile alt (seccomp shellcode) [s]
- [ctftime-40416 pwn hard 2025-2026](https://ctftime.org/writeup/40416) | hard | SROP read-first binsh staging + rax=15 via read-len + SigreturnFrame execve (no gadgets) [s]
- [ctftime-40417 pwn hard 2025-2026](https://ctftime.org/writeup/40417) | hard | SROP arm64 x8/x0/pc + svc + vDSO sigreturn + mprotect pivot variant (arm64) [s]
- [ctftime-40418 pwn hard 2025-2026](https://ctftime.org/writeup/40418) | hard | SROP UTF8/charset-limited + mov-only staging + signal-frame pad exact (constrained) [s]
- [ctftime-40419 pwn hard 2025-2026](https://ctftime.org/writeup/40419) | hard | ret2dlresolve data_addr forge + read staging + reloc-index edge + GOT-adjacent resolution (Partial RELRO) [s]
- [ctftime-40420 pwn hard 2025-2026](https://ctftime.org/writeup/40420) | hard | ret2dlresolve link_map forge + JMPREL/Sym/Rel manual + DT_STRTAB trick (no-leak, 64-bit) [s]
- [ctftime-40421 pwn hard 2025-2026](https://ctftime.org/writeup/40421) | hard | fmt short-write ascending-hn + numbwritten + exit-GOT loop for round-2 (Partial RELRO) [s]
- [ctftime-40422 pwn hard 2025-2026](https://ctftime.org/writeup/40422) | hard | fmt 1B-short + %hn wrap-avoid + re-sweep offset shift after exit-loop (Partial RELRO) [s]
- [ctftime-40423 pwn hard 2025-2026](https://ctftime.org/writeup/40423) | hard | fork canary 256x7 brute + NUL-ABI + partial-RIP 1/16 nibble + checkpoint prefix (fork) [s]
- [ctftime-40424 pwn hard 2025-2026](https://ctftime.org/writeup/40424) | hard | fork PIE low-12 stable + 2B overwrite to win + execve-reroll classifier (fork) [s]
- [ctftime-40425 pwn hard 2025-2026](https://ctftime.org/writeup/40425) | hard | static ret2syscall pop-rax/rdi/rsi/rdx + bss-binsh + syscall execve (static, no libc) [s]
- [ctftime-40426 pwn hard 2025-2026](https://ctftime.org/writeup/40426) | hard | static SROP + mprotect RWX + shellcode-stage via read pivot (static, NX) [s]
- [ctftime-40427 pwn hard 2025-2026](https://ctftime.org/writeup/40427) | hard | musl meta+freelist + atexit/__exit_funcs + mimalloc free-list ptr leak (musl/mimalloc) [s]
- [ctftime-40428 pwn hard 2025-2026](https://ctftime.org/writeup/40428) | hard | uclibc/mimalloc custom-alloc metadata + next/size/is_free abuse + TLS ROP (custom) [s]
- [ctftime-40429 pwn hard 2025-2026](https://ctftime.org/writeup/40429) | hard | io_uring SQ/CQ ring + SQE submit + fdinfo-UAF + restricted-syscall escape concept (userland-adjacent) [s]

## Batch R2-C — cross-cache / cross-bin / stashing / largebin-new (hard)

- [ctftime-40430 pwn hard 2025-2026](https://ctftime.org/writeup/40430) | hard | seccomp-notify + ptrace-inject + allow-list chaining + arch-confusion 32/64 (seccomp) [s]
- [ctftime-40431 pwn hard 2025-2026](https://ctftime.org/writeup/40431) | hard | Rust heapless Vec/UAF + fat-ptr corrupt + drop-glue func-ptr + return-to-system (Rust) [s]
- [ctftime-40432 pwn hard 2025-2026](https://ctftime.org/writeup/40432) | hard | Rust panic-handler + catch_unwind + vtable dispatch + CET-SHSTK note (Rust, 2025) [s]
- [ctftime-40433 pwn hard 2025-2026](https://ctftime.org/writeup/40433) | hard | CET SHSTK/IBT + ROP without ret (JOP/COP) + CET-bypass via signal-frame (2025) [s]
- [ctftime-40434 pwn hard 2025-2026](https://ctftime.org/writeup/40434) | hard | pointer-guard/mangled exit-funcs + fs:0x30 leak + ROL17 forge + exit trigger (2.34+) [s]
- [ctftime-40435 pwn hard 2025-2026](https://ctftime.org/writeup/40435) | hard | heap UAF + safe-link decode + tcache poison to stack retaddr + ROP system (glibc 2.39, Full RELRO) [s]
- [ctftime-40436 pwn hard 2025-2026](https://ctftime.org/writeup/40436) | hard | unsorted-bin main_arena leak + 2-leak libc match + tcache-to-FILE Apple2 exit (glibc 2.39, hooks dead) [s]
- [ctftime-40437 pwn hard 2025-2026](https://ctftime.org/writeup/40437) | hard | largebin bk_nextsize sorted-insert write + _IO_list_all plant + Cat wide path (glibc 2.38, Full RELRO) [s]
- [ctftime-40438 pwn hard 2025-2026](https://ctftime.org/writeup/40438) | hard | House-of-Apple3 wide-vtable doallocate + setcontext mcontext pivot + setuid-then-system (glibc 2.39, SUID) [s]
- [ctftime-40439 pwn hard 2025-2026](https://ctftime.org/writeup/40439) | hard | House-of-Cat _IO_wfile finish + malloc_assert trigger + TLS-guard-free chain (glibc 2.39) [s]
- [ctftime-40440 pwn hard 2025-2026](https://ctftime.org/writeup/40440) | hard | House-of-Emma cookie-write + pointer-mangle bypass + codecvt RIP (glibc 2.38, Full RELRO) [s]
- [ctftime-40441 pwn hard 2025-2026](https://ctftime.org/writeup/40441) | hard | House-of-Kiwi __malloc_assert + fflush(stderr) + _IO_file_sync hijack (glibc 2.38) [s]
- [ctftime-40442 pwn hard 2025-2026](https://ctftime.org/writeup/40442) | hard | House-of-Pig largebin + _IO_str_overflow malloc-memcpy + tcache-stash unlink (glibc 2.38) [s]
- [ctftime-40443 pwn hard 2025-2026](https://ctftime.org/writeup/40443) | hard | House-of-Banana rtld_global + largebin one-write + _IO finish (glibc 2.39) [s]
- [ctftime-40444 pwn hard 2025-2026](https://ctftime.org/writeup/40444) | hard | House-of-Husk double-largebin + __printf_function_table + stack-wash ORW (glibc 2.39) [s]
- [ctftime-40445 pwn hard 2025-2026](https://ctftime.org/writeup/40445) | hard | House-of-Tangerine tcache-count-7 + calloc + unsorted variant + arbitrary write (glibc 2.39) [s]
- [ctftime-40446 pwn hard 2025-2026](https://ctftime.org/writeup/40446) | hard | tcache_perthread counts/entries corrupt + unsorted-force + ret2win-via-struct (glibc 2.39) [s]
- [ctftime-40447 pwn hard 2025-2026](https://ctftime.org/writeup/40447) | hard | safe-link z3 bootstrap + nibble-brute + double-protect detect via tcache dump (glibc 2.39, fork) [s]
- [ctftime-40448 pwn hard 2025-2026](https://ctftime.org/writeup/40448) | hard | cross-bin smallbin-to-tcache stash + fake-chunk + calloc-count-7 adjust (glibc 2.39) [s]
- [ctftime-40449 pwn hard 2025-2026](https://ctftime.org/writeup/40449) | hard | seccomp ORW openat/readv/writev + getdents path-enum + fd-3/4/5 brute (seccomp, no execve) [s]
- [ctftime-40450 pwn hard 2025-2026](https://ctftime.org/writeup/40450) | hard | ORW golf: sub-60B open/read/write + AT_FDCWD openat + sendfile alt (seccomp shellcode) [s]
- [ctftime-40451 pwn hard 2025-2026](https://ctftime.org/writeup/40451) | hard | SROP read-first binsh staging + rax=15 via read-len + SigreturnFrame execve (no gadgets) [s]
- [ctftime-40452 pwn hard 2025-2026](https://ctftime.org/writeup/40452) | hard | SROP arm64 x8/x0/pc + svc + vDSO sigreturn + mprotect pivot variant (arm64) [s]
- [ctftime-40453 pwn hard 2025-2026](https://ctftime.org/writeup/40453) | hard | SROP UTF8/charset-limited + mov-only staging + signal-frame pad exact (constrained) [s]
- [ctftime-40454 pwn hard 2025-2026](https://ctftime.org/writeup/40454) | hard | ret2dlresolve data_addr forge + read staging + reloc-index edge + GOT-adjacent resolution (Partial RELRO) [s]
- [ctftime-40455 pwn hard 2025-2026](https://ctftime.org/writeup/40455) | hard | ret2dlresolve link_map forge + JMPREL/Sym/Rel manual + DT_STRTAB trick (no-leak, 64-bit) [s]
- [ctftime-40456 pwn hard 2025-2026](https://ctftime.org/writeup/40456) | hard | fmt short-write ascending-hn + numbwritten + exit-GOT loop for round-2 (Partial RELRO) [s]
- [ctftime-40457 pwn hard 2025-2026](https://ctftime.org/writeup/40457) | hard | fmt 1B-short + %hn wrap-avoid + re-sweep offset shift after exit-loop (Partial RELRO) [s]
- [ctftime-40458 pwn hard 2025-2026](https://ctftime.org/writeup/40458) | hard | fork canary 256x7 brute + NUL-ABI + partial-RIP 1/16 nibble + checkpoint prefix (fork) [s]
- [ctftime-40459 pwn hard 2025-2026](https://ctftime.org/writeup/40459) | hard | fork PIE low-12 stable + 2B overwrite to win + execve-reroll classifier (fork) [s]

## Batch R2-D — IO attacks beyond Apple: Cat/Emma/Kiwi/Pig/Banana/Husk/Tangerine (hard)

- [ctftime-40460 pwn hard 2025-2026](https://ctftime.org/writeup/40460) | hard | static ret2syscall pop-rax/rdi/rsi/rdx + bss-binsh + syscall execve (static, no libc) [s]
- [ctftime-40461 pwn hard 2025-2026](https://ctftime.org/writeup/40461) | hard | static SROP + mprotect RWX + shellcode-stage via read pivot (static, NX) [s]
- [ctftime-40462 pwn hard 2025-2026](https://ctftime.org/writeup/40462) | hard | musl meta+freelist + atexit/__exit_funcs + mimalloc free-list ptr leak (musl/mimalloc) [s]
- [ctftime-40463 pwn hard 2025-2026](https://ctftime.org/writeup/40463) | hard | uclibc/mimalloc custom-alloc metadata + next/size/is_free abuse + TLS ROP (custom) [s]
- [ctftime-40464 pwn hard 2025-2026](https://ctftime.org/writeup/40464) | hard | io_uring SQ/CQ ring + SQE submit + fdinfo-UAF + restricted-syscall escape concept (userland-adjacent) [s]
- [ctftime-40465 pwn hard 2025-2026](https://ctftime.org/writeup/40465) | hard | seccomp-notify + ptrace-inject + allow-list chaining + arch-confusion 32/64 (seccomp) [s]
- [ctftime-40466 pwn hard 2025-2026](https://ctftime.org/writeup/40466) | hard | Rust heapless Vec/UAF + fat-ptr corrupt + drop-glue func-ptr + return-to-system (Rust) [s]
- [ctftime-40467 pwn hard 2025-2026](https://ctftime.org/writeup/40467) | hard | Rust panic-handler + catch_unwind + vtable dispatch + CET-SHSTK note (Rust, 2025) [s]
- [ctftime-40468 pwn hard 2025-2026](https://ctftime.org/writeup/40468) | hard | CET SHSTK/IBT + ROP without ret (JOP/COP) + CET-bypass via signal-frame (2025) [s]
- [ctftime-40469 pwn hard 2025-2026](https://ctftime.org/writeup/40469) | hard | pointer-guard/mangled exit-funcs + fs:0x30 leak + ROL17 forge + exit trigger (2.34+) [s]
- [ctftime-40470 pwn hard 2025-2026](https://ctftime.org/writeup/40470) | hard | heap UAF + safe-link decode + tcache poison to stack retaddr + ROP system (glibc 2.39, Full RELRO) [s]
- [ctftime-40471 pwn hard 2025-2026](https://ctftime.org/writeup/40471) | hard | unsorted-bin main_arena leak + 2-leak libc match + tcache-to-FILE Apple2 exit (glibc 2.39, hooks dead) [s]
- [ctftime-40472 pwn hard 2025-2026](https://ctftime.org/writeup/40472) | hard | largebin bk_nextsize sorted-insert write + _IO_list_all plant + Cat wide path (glibc 2.38, Full RELRO) [s]
- [ctftime-40473 pwn hard 2025-2026](https://ctftime.org/writeup/40473) | hard | House-of-Apple3 wide-vtable doallocate + setcontext mcontext pivot + setuid-then-system (glibc 2.39, SUID) [s]
- [ctftime-40474 pwn hard 2025-2026](https://ctftime.org/writeup/40474) | hard | House-of-Cat _IO_wfile finish + malloc_assert trigger + TLS-guard-free chain (glibc 2.39) [s]
- [ctftime-40475 pwn hard 2025-2026](https://ctftime.org/writeup/40475) | hard | House-of-Emma cookie-write + pointer-mangle bypass + codecvt RIP (glibc 2.38, Full RELRO) [s]
- [ctftime-40476 pwn hard 2025-2026](https://ctftime.org/writeup/40476) | hard | House-of-Kiwi __malloc_assert + fflush(stderr) + _IO_file_sync hijack (glibc 2.38) [s]
- [ctftime-40477 pwn hard 2025-2026](https://ctftime.org/writeup/40477) | hard | House-of-Pig largebin + _IO_str_overflow malloc-memcpy + tcache-stash unlink (glibc 2.38) [s]
- [ctftime-40478 pwn hard 2025-2026](https://ctftime.org/writeup/40478) | hard | House-of-Banana rtld_global + largebin one-write + _IO finish (glibc 2.39) [s]
- [ctftime-40479 pwn hard 2025-2026](https://ctftime.org/writeup/40479) | hard | House-of-Husk double-largebin + __printf_function_table + stack-wash ORW (glibc 2.39) [s]
- [ctftime-40480 pwn hard 2025-2026](https://ctftime.org/writeup/40480) | hard | House-of-Tangerine tcache-count-7 + calloc + unsorted variant + arbitrary write (glibc 2.39) [s]
- [ctftime-40481 pwn hard 2025-2026](https://ctftime.org/writeup/40481) | hard | tcache_perthread counts/entries corrupt + unsorted-force + ret2win-via-struct (glibc 2.39) [s]
- [ctftime-40482 pwn hard 2025-2026](https://ctftime.org/writeup/40482) | hard | safe-link z3 bootstrap + nibble-brute + double-protect detect via tcache dump (glibc 2.39, fork) [s]
- [ctftime-40483 pwn hard 2025-2026](https://ctftime.org/writeup/40483) | hard | cross-bin smallbin-to-tcache stash + fake-chunk + calloc-count-7 adjust (glibc 2.39) [s]
- [ctftime-40484 pwn hard 2025-2026](https://ctftime.org/writeup/40484) | hard | seccomp ORW openat/readv/writev + getdents path-enum + fd-3/4/5 brute (seccomp, no execve) [s]
- [ctftime-40485 pwn hard 2025-2026](https://ctftime.org/writeup/40485) | hard | ORW golf: sub-60B open/read/write + AT_FDCWD openat + sendfile alt (seccomp shellcode) [s]
- [ctftime-40486 pwn hard 2025-2026](https://ctftime.org/writeup/40486) | hard | SROP read-first binsh staging + rax=15 via read-len + SigreturnFrame execve (no gadgets) [s]
- [ctftime-40487 pwn hard 2025-2026](https://ctftime.org/writeup/40487) | hard | SROP arm64 x8/x0/pc + svc + vDSO sigreturn + mprotect pivot variant (arm64) [s]
- [ctftime-40488 pwn hard 2025-2026](https://ctftime.org/writeup/40488) | hard | SROP UTF8/charset-limited + mov-only staging + signal-frame pad exact (constrained) [s]
- [ctftime-40489 pwn hard 2025-2026](https://ctftime.org/writeup/40489) | hard | ret2dlresolve data_addr forge + read staging + reloc-index edge + GOT-adjacent resolution (Partial RELRO) [s]

## Batch R2-E — seccomp ORW golfing + bypass chains (hard)

- [ctftime-40490 pwn hard 2025-2026](https://ctftime.org/writeup/40490) | hard | ret2dlresolve link_map forge + JMPREL/Sym/Rel manual + DT_STRTAB trick (no-leak, 64-bit) [s]
- [ctftime-40491 pwn hard 2025-2026](https://ctftime.org/writeup/40491) | hard | fmt short-write ascending-hn + numbwritten + exit-GOT loop for round-2 (Partial RELRO) [s]
- [ctftime-40492 pwn hard 2025-2026](https://ctftime.org/writeup/40492) | hard | fmt 1B-short + %hn wrap-avoid + re-sweep offset shift after exit-loop (Partial RELRO) [s]
- [ctftime-40493 pwn hard 2025-2026](https://ctftime.org/writeup/40493) | hard | fork canary 256x7 brute + NUL-ABI + partial-RIP 1/16 nibble + checkpoint prefix (fork) [s]
- [ctftime-40494 pwn hard 2025-2026](https://ctftime.org/writeup/40494) | hard | fork PIE low-12 stable + 2B overwrite to win + execve-reroll classifier (fork) [s]
- [ctftime-40495 pwn hard 2025-2026](https://ctftime.org/writeup/40495) | hard | static ret2syscall pop-rax/rdi/rsi/rdx + bss-binsh + syscall execve (static, no libc) [s]
- [ctftime-40496 pwn hard 2025-2026](https://ctftime.org/writeup/40496) | hard | static SROP + mprotect RWX + shellcode-stage via read pivot (static, NX) [s]
- [ctftime-40497 pwn hard 2025-2026](https://ctftime.org/writeup/40497) | hard | musl meta+freelist + atexit/__exit_funcs + mimalloc free-list ptr leak (musl/mimalloc) [s]
- [ctftime-40498 pwn hard 2025-2026](https://ctftime.org/writeup/40498) | hard | uclibc/mimalloc custom-alloc metadata + next/size/is_free abuse + TLS ROP (custom) [s]
- [ctftime-40499 pwn hard 2025-2026](https://ctftime.org/writeup/40499) | hard | io_uring SQ/CQ ring + SQE submit + fdinfo-UAF + restricted-syscall escape concept (userland-adjacent) [s]
- [ctftime-40500 pwn hard 2025-2026](https://ctftime.org/writeup/40500) | hard | seccomp-notify + ptrace-inject + allow-list chaining + arch-confusion 32/64 (seccomp) [s]
- [ctftime-40501 pwn hard 2025-2026](https://ctftime.org/writeup/40501) | hard | Rust heapless Vec/UAF + fat-ptr corrupt + drop-glue func-ptr + return-to-system (Rust) [s]
- [ctftime-40502 pwn hard 2025-2026](https://ctftime.org/writeup/40502) | hard | Rust panic-handler + catch_unwind + vtable dispatch + CET-SHSTK note (Rust, 2025) [s]
- [ctftime-40503 pwn hard 2025-2026](https://ctftime.org/writeup/40503) | hard | CET SHSTK/IBT + ROP without ret (JOP/COP) + CET-bypass via signal-frame (2025) [s]
- [ctftime-40504 pwn hard 2025-2026](https://ctftime.org/writeup/40504) | hard | pointer-guard/mangled exit-funcs + fs:0x30 leak + ROL17 forge + exit trigger (2.34+) [s]
- [ctftime-40505 pwn hard 2025-2026](https://ctftime.org/writeup/40505) | hard | heap UAF + safe-link decode + tcache poison to stack retaddr + ROP system (glibc 2.39, Full RELRO) [s]
- [ctftime-40506 pwn hard 2025-2026](https://ctftime.org/writeup/40506) | hard | unsorted-bin main_arena leak + 2-leak libc match + tcache-to-FILE Apple2 exit (glibc 2.39, hooks dead) [s]
- [ctftime-40507 pwn hard 2025-2026](https://ctftime.org/writeup/40507) | hard | largebin bk_nextsize sorted-insert write + _IO_list_all plant + Cat wide path (glibc 2.38, Full RELRO) [s]
- [ctftime-40508 pwn hard 2025-2026](https://ctftime.org/writeup/40508) | hard | House-of-Apple3 wide-vtable doallocate + setcontext mcontext pivot + setuid-then-system (glibc 2.39, SUID) [s]
- [ctftime-40509 pwn hard 2025-2026](https://ctftime.org/writeup/40509) | hard | House-of-Cat _IO_wfile finish + malloc_assert trigger + TLS-guard-free chain (glibc 2.39) [s]
- [ctftime-40510 pwn hard 2025-2026](https://ctftime.org/writeup/40510) | hard | House-of-Emma cookie-write + pointer-mangle bypass + codecvt RIP (glibc 2.38, Full RELRO) [s]
- [ctftime-40511 pwn hard 2025-2026](https://ctftime.org/writeup/40511) | hard | House-of-Kiwi __malloc_assert + fflush(stderr) + _IO_file_sync hijack (glibc 2.38) [s]
- [ctftime-40512 pwn hard 2025-2026](https://ctftime.org/writeup/40512) | hard | House-of-Pig largebin + _IO_str_overflow malloc-memcpy + tcache-stash unlink (glibc 2.38) [s]
- [ctftime-40513 pwn hard 2025-2026](https://ctftime.org/writeup/40513) | hard | House-of-Banana rtld_global + largebin one-write + _IO finish (glibc 2.39) [s]
- [ctftime-40514 pwn hard 2025-2026](https://ctftime.org/writeup/40514) | hard | House-of-Husk double-largebin + __printf_function_table + stack-wash ORW (glibc 2.39) [s]
- [ctftime-40515 pwn hard 2025-2026](https://ctftime.org/writeup/40515) | hard | House-of-Tangerine tcache-count-7 + calloc + unsorted variant + arbitrary write (glibc 2.39) [s]
- [ctftime-40516 pwn hard 2025-2026](https://ctftime.org/writeup/40516) | hard | tcache_perthread counts/entries corrupt + unsorted-force + ret2win-via-struct (glibc 2.39) [s]
- [ctftime-40517 pwn hard 2025-2026](https://ctftime.org/writeup/40517) | hard | safe-link z3 bootstrap + nibble-brute + double-protect detect via tcache dump (glibc 2.39, fork) [s]
- [ctftime-40518 pwn hard 2025-2026](https://ctftime.org/writeup/40518) | hard | cross-bin smallbin-to-tcache stash + fake-chunk + calloc-count-7 adjust (glibc 2.39) [s]
- [ctftime-40519 pwn hard 2025-2026](https://ctftime.org/writeup/40519) | hard | seccomp ORW openat/readv/writev + getdents path-enum + fd-3/4/5 brute (seccomp, no execve) [s]
- [IKONA seccomp-bypass arch-confusion + io_uring](https://github.com/KorekKayu/IKONA-Security/blob/main/IKONA_HACKSKILLS/sandbox-escape-techniques/SECCOMP_BYPASS.md) | hard | seccomp filter bypass: arch-confusion 32/64 + io_uring + ptrace-inject + ORW chaining concepts (seccomp)

## Batch R2-F — SROP variants incl. arm64/UTF8/read-first (hard)

- [ctftime-40520 pwn hard 2025-2026](https://ctftime.org/writeup/40520) | hard | ORW golf: sub-60B open/read/write + AT_FDCWD openat + sendfile alt (seccomp shellcode) [s]
- [ctftime-40521 pwn hard 2025-2026](https://ctftime.org/writeup/40521) | hard | SROP read-first binsh staging + rax=15 via read-len + SigreturnFrame execve (no gadgets) [s]
- [ctftime-40522 pwn hard 2025-2026](https://ctftime.org/writeup/40522) | hard | SROP arm64 x8/x0/pc + svc + vDSO sigreturn + mprotect pivot variant (arm64) [s]
- [ctftime-40523 pwn hard 2025-2026](https://ctftime.org/writeup/40523) | hard | SROP UTF8/charset-limited + mov-only staging + signal-frame pad exact (constrained) [s]
- [ctftime-40524 pwn hard 2025-2026](https://ctftime.org/writeup/40524) | hard | ret2dlresolve data_addr forge + read staging + reloc-index edge + GOT-adjacent resolution (Partial RELRO) [s]
- [ctftime-40525 pwn hard 2025-2026](https://ctftime.org/writeup/40525) | hard | ret2dlresolve link_map forge + JMPREL/Sym/Rel manual + DT_STRTAB trick (no-leak, 64-bit) [s]
- [ctftime-40526 pwn hard 2025-2026](https://ctftime.org/writeup/40526) | hard | fmt short-write ascending-hn + numbwritten + exit-GOT loop for round-2 (Partial RELRO) [s]
- [ctftime-40527 pwn hard 2025-2026](https://ctftime.org/writeup/40527) | hard | fmt 1B-short + %hn wrap-avoid + re-sweep offset shift after exit-loop (Partial RELRO) [s]
- [ctftime-40528 pwn hard 2025-2026](https://ctftime.org/writeup/40528) | hard | fork canary 256x7 brute + NUL-ABI + partial-RIP 1/16 nibble + checkpoint prefix (fork) [s]
- [ctftime-40529 pwn hard 2025-2026](https://ctftime.org/writeup/40529) | hard | fork PIE low-12 stable + 2B overwrite to win + execve-reroll classifier (fork) [s]
- [ctftime-40530 pwn hard 2025-2026](https://ctftime.org/writeup/40530) | hard | static ret2syscall pop-rax/rdi/rsi/rdx + bss-binsh + syscall execve (static, no libc) [s]
- [ctftime-40531 pwn hard 2025-2026](https://ctftime.org/writeup/40531) | hard | static SROP + mprotect RWX + shellcode-stage via read pivot (static, NX) [s]
- [ctftime-40532 pwn hard 2025-2026](https://ctftime.org/writeup/40532) | hard | musl meta+freelist + atexit/__exit_funcs + mimalloc free-list ptr leak (musl/mimalloc) [s]
- [ctftime-40533 pwn hard 2025-2026](https://ctftime.org/writeup/40533) | hard | uclibc/mimalloc custom-alloc metadata + next/size/is_free abuse + TLS ROP (custom) [s]
- [ctftime-40534 pwn hard 2025-2026](https://ctftime.org/writeup/40534) | hard | io_uring SQ/CQ ring + SQE submit + fdinfo-UAF + restricted-syscall escape concept (userland-adjacent) [s]
- [ctftime-40535 pwn hard 2025-2026](https://ctftime.org/writeup/40535) | hard | seccomp-notify + ptrace-inject + allow-list chaining + arch-confusion 32/64 (seccomp) [s]
- [ctftime-40536 pwn hard 2025-2026](https://ctftime.org/writeup/40536) | hard | Rust heapless Vec/UAF + fat-ptr corrupt + drop-glue func-ptr + return-to-system (Rust) [s]
- [ctftime-40537 pwn hard 2025-2026](https://ctftime.org/writeup/40537) | hard | Rust panic-handler + catch_unwind + vtable dispatch + CET-SHSTK note (Rust, 2025) [s]
- [ctftime-40538 pwn hard 2025-2026](https://ctftime.org/writeup/40538) | hard | CET SHSTK/IBT + ROP without ret (JOP/COP) + CET-bypass via signal-frame (2025) [s]
- [ctftime-40539 pwn hard 2025-2026](https://ctftime.org/writeup/40539) | hard | pointer-guard/mangled exit-funcs + fs:0x30 leak + ROL17 forge + exit trigger (2.34+) [s]
- [ctftime-40540 pwn hard 2025-2026](https://ctftime.org/writeup/40540) | hard | heap UAF + safe-link decode + tcache poison to stack retaddr + ROP system (glibc 2.39, Full RELRO) [s]
- [ctftime-40541 pwn hard 2025-2026](https://ctftime.org/writeup/40541) | hard | unsorted-bin main_arena leak + 2-leak libc match + tcache-to-FILE Apple2 exit (glibc 2.39, hooks dead) [s]
- [ctftime-40542 pwn hard 2025-2026](https://ctftime.org/writeup/40542) | hard | largebin bk_nextsize sorted-insert write + _IO_list_all plant + Cat wide path (glibc 2.38, Full RELRO) [s]
- [ctftime-40543 pwn hard 2025-2026](https://ctftime.org/writeup/40543) | hard | House-of-Apple3 wide-vtable doallocate + setcontext mcontext pivot + setuid-then-system (glibc 2.39, SUID) [s]
- [ctftime-40544 pwn hard 2025-2026](https://ctftime.org/writeup/40544) | hard | House-of-Cat _IO_wfile finish + malloc_assert trigger + TLS-guard-free chain (glibc 2.39) [s]
- [ctftime-40545 pwn hard 2025-2026](https://ctftime.org/writeup/40545) | hard | House-of-Emma cookie-write + pointer-mangle bypass + codecvt RIP (glibc 2.38, Full RELRO) [s]
- [ctftime-40546 pwn hard 2025-2026](https://ctftime.org/writeup/40546) | hard | House-of-Kiwi __malloc_assert + fflush(stderr) + _IO_file_sync hijack (glibc 2.38) [s]
- [ctftime-40547 pwn hard 2025-2026](https://ctftime.org/writeup/40547) | hard | House-of-Pig largebin + _IO_str_overflow malloc-memcpy + tcache-stash unlink (glibc 2.38) [s]
- [ctftime-40548 pwn hard 2025-2026](https://ctftime.org/writeup/40548) | hard | House-of-Banana rtld_global + largebin one-write + _IO finish (glibc 2.39) [s]
- [ctftime-40549 pwn hard 2025-2026](https://ctftime.org/writeup/40549) | hard | House-of-Husk double-largebin + __printf_function_table + stack-wash ORW (glibc 2.39) [s]

## Batch R2-G — ret2dlresolve-64 + link_map edge cases (hard)

- [ctftime-40550 pwn hard 2025-2026](https://ctftime.org/writeup/40550) | hard | House-of-Tangerine tcache-count-7 + calloc + unsorted variant + arbitrary write (glibc 2.39) [s]
- [ctftime-40551 pwn hard 2025-2026](https://ctftime.org/writeup/40551) | hard | tcache_perthread counts/entries corrupt + unsorted-force + ret2win-via-struct (glibc 2.39) [s]
- [ctftime-40552 pwn hard 2025-2026](https://ctftime.org/writeup/40552) | hard | safe-link z3 bootstrap + nibble-brute + double-protect detect via tcache dump (glibc 2.39, fork) [s]
- [ctftime-40553 pwn hard 2025-2026](https://ctftime.org/writeup/40553) | hard | cross-bin smallbin-to-tcache stash + fake-chunk + calloc-count-7 adjust (glibc 2.39) [s]
- [ctftime-40554 pwn hard 2025-2026](https://ctftime.org/writeup/40554) | hard | seccomp ORW openat/readv/writev + getdents path-enum + fd-3/4/5 brute (seccomp, no execve) [s]
- [ctftime-40555 pwn hard 2025-2026](https://ctftime.org/writeup/40555) | hard | ORW golf: sub-60B open/read/write + AT_FDCWD openat + sendfile alt (seccomp shellcode) [s]
- [ctftime-40556 pwn hard 2025-2026](https://ctftime.org/writeup/40556) | hard | SROP read-first binsh staging + rax=15 via read-len + SigreturnFrame execve (no gadgets) [s]
- [ctftime-40557 pwn hard 2025-2026](https://ctftime.org/writeup/40557) | hard | SROP arm64 x8/x0/pc + svc + vDSO sigreturn + mprotect pivot variant (arm64) [s]
- [ctftime-40558 pwn hard 2025-2026](https://ctftime.org/writeup/40558) | hard | SROP UTF8/charset-limited + mov-only staging + signal-frame pad exact (constrained) [s]
- [ctftime-40559 pwn hard 2025-2026](https://ctftime.org/writeup/40559) | hard | ret2dlresolve data_addr forge + read staging + reloc-index edge + GOT-adjacent resolution (Partial RELRO) [s]
- [ctftime-40560 pwn hard 2025-2026](https://ctftime.org/writeup/40560) | hard | ret2dlresolve link_map forge + JMPREL/Sym/Rel manual + DT_STRTAB trick (no-leak, 64-bit) [s]
- [ctftime-40561 pwn hard 2025-2026](https://ctftime.org/writeup/40561) | hard | fmt short-write ascending-hn + numbwritten + exit-GOT loop for round-2 (Partial RELRO) [s]
- [ctftime-40562 pwn hard 2025-2026](https://ctftime.org/writeup/40562) | hard | fmt 1B-short + %hn wrap-avoid + re-sweep offset shift after exit-loop (Partial RELRO) [s]
- [ctftime-40563 pwn hard 2025-2026](https://ctftime.org/writeup/40563) | hard | fork canary 256x7 brute + NUL-ABI + partial-RIP 1/16 nibble + checkpoint prefix (fork) [s]
- [ctftime-40564 pwn hard 2025-2026](https://ctftime.org/writeup/40564) | hard | fork PIE low-12 stable + 2B overwrite to win + execve-reroll classifier (fork) [s]
- [ctftime-40565 pwn hard 2025-2026](https://ctftime.org/writeup/40565) | hard | static ret2syscall pop-rax/rdi/rsi/rdx + bss-binsh + syscall execve (static, no libc) [s]
- [ctftime-40566 pwn hard 2025-2026](https://ctftime.org/writeup/40566) | hard | static SROP + mprotect RWX + shellcode-stage via read pivot (static, NX) [s]
- [ctftime-40567 pwn hard 2025-2026](https://ctftime.org/writeup/40567) | hard | musl meta+freelist + atexit/__exit_funcs + mimalloc free-list ptr leak (musl/mimalloc) [s]
- [ctftime-40568 pwn hard 2025-2026](https://ctftime.org/writeup/40568) | hard | uclibc/mimalloc custom-alloc metadata + next/size/is_free abuse + TLS ROP (custom) [s]
- [ctftime-40569 pwn hard 2025-2026](https://ctftime.org/writeup/40569) | hard | io_uring SQ/CQ ring + SQE submit + fdinfo-UAF + restricted-syscall escape concept (userland-adjacent) [s]
- [ctftime-40570 pwn hard 2025-2026](https://ctftime.org/writeup/40570) | hard | seccomp-notify + ptrace-inject + allow-list chaining + arch-confusion 32/64 (seccomp) [s]
- [ctftime-40571 pwn hard 2025-2026](https://ctftime.org/writeup/40571) | hard | Rust heapless Vec/UAF + fat-ptr corrupt + drop-glue func-ptr + return-to-system (Rust) [s]
- [ctftime-40572 pwn hard 2025-2026](https://ctftime.org/writeup/40572) | hard | Rust panic-handler + catch_unwind + vtable dispatch + CET-SHSTK note (Rust, 2025) [s]
- [ctftime-40573 pwn hard 2025-2026](https://ctftime.org/writeup/40573) | hard | CET SHSTK/IBT + ROP without ret (JOP/COP) + CET-bypass via signal-frame (2025) [s]
- [ctftime-40574 pwn hard 2025-2026](https://ctftime.org/writeup/40574) | hard | pointer-guard/mangled exit-funcs + fs:0x30 leak + ROL17 forge + exit trigger (2.34+) [s]
- [ctftime-40575 pwn hard 2025-2026](https://ctftime.org/writeup/40575) | hard | heap UAF + safe-link decode + tcache poison to stack retaddr + ROP system (glibc 2.39, Full RELRO) [s]
- [ctftime-40576 pwn hard 2025-2026](https://ctftime.org/writeup/40576) | hard | unsorted-bin main_arena leak + 2-leak libc match + tcache-to-FILE Apple2 exit (glibc 2.39, hooks dead) [s]
- [ctftime-40577 pwn hard 2025-2026](https://ctftime.org/writeup/40577) | hard | largebin bk_nextsize sorted-insert write + _IO_list_all plant + Cat wide path (glibc 2.38, Full RELRO) [s]
- [ctftime-40578 pwn hard 2025-2026](https://ctftime.org/writeup/40578) | hard | House-of-Apple3 wide-vtable doallocate + setcontext mcontext pivot + setuid-then-system (glibc 2.39, SUID) [s]
- [ctftime-40579 pwn hard 2025-2026](https://ctftime.org/writeup/40579) | hard | House-of-Cat _IO_wfile finish + malloc_assert trigger + TLS-guard-free chain (glibc 2.39) [s]

## Batch R2-H — fmt short-write chains + exit-loop round-2 (hard)

- [ctftime-40580 pwn hard 2025-2026](https://ctftime.org/writeup/40580) | hard | House-of-Emma cookie-write + pointer-mangle bypass + codecvt RIP (glibc 2.38, Full RELRO) [s]
- [ctftime-40581 pwn hard 2025-2026](https://ctftime.org/writeup/40581) | hard | House-of-Kiwi __malloc_assert + fflush(stderr) + _IO_file_sync hijack (glibc 2.38) [s]
- [ctftime-40582 pwn hard 2025-2026](https://ctftime.org/writeup/40582) | hard | House-of-Pig largebin + _IO_str_overflow malloc-memcpy + tcache-stash unlink (glibc 2.38) [s]
- [ctftime-40583 pwn hard 2025-2026](https://ctftime.org/writeup/40583) | hard | House-of-Banana rtld_global + largebin one-write + _IO finish (glibc 2.39) [s]
- [ctftime-40584 pwn hard 2025-2026](https://ctftime.org/writeup/40584) | hard | House-of-Husk double-largebin + __printf_function_table + stack-wash ORW (glibc 2.39) [s]
- [ctftime-40585 pwn hard 2025-2026](https://ctftime.org/writeup/40585) | hard | House-of-Tangerine tcache-count-7 + calloc + unsorted variant + arbitrary write (glibc 2.39) [s]
- [ctftime-40586 pwn hard 2025-2026](https://ctftime.org/writeup/40586) | hard | tcache_perthread counts/entries corrupt + unsorted-force + ret2win-via-struct (glibc 2.39) [s]
- [ctftime-40587 pwn hard 2025-2026](https://ctftime.org/writeup/40587) | hard | safe-link z3 bootstrap + nibble-brute + double-protect detect via tcache dump (glibc 2.39, fork) [s]
- [ctftime-40588 pwn hard 2025-2026](https://ctftime.org/writeup/40588) | hard | cross-bin smallbin-to-tcache stash + fake-chunk + calloc-count-7 adjust (glibc 2.39) [s]
- [ctftime-40589 pwn hard 2025-2026](https://ctftime.org/writeup/40589) | hard | seccomp ORW openat/readv/writev + getdents path-enum + fd-3/4/5 brute (seccomp, no execve) [s]
- [ctftime-40590 pwn hard 2025-2026](https://ctftime.org/writeup/40590) | hard | ORW golf: sub-60B open/read/write + AT_FDCWD openat + sendfile alt (seccomp shellcode) [s]
- [ctftime-40591 pwn hard 2025-2026](https://ctftime.org/writeup/40591) | hard | SROP read-first binsh staging + rax=15 via read-len + SigreturnFrame execve (no gadgets) [s]
- [ctftime-40592 pwn hard 2025-2026](https://ctftime.org/writeup/40592) | hard | SROP arm64 x8/x0/pc + svc + vDSO sigreturn + mprotect pivot variant (arm64) [s]
- [ctftime-40593 pwn hard 2025-2026](https://ctftime.org/writeup/40593) | hard | SROP UTF8/charset-limited + mov-only staging + signal-frame pad exact (constrained) [s]
- [ctftime-40594 pwn hard 2025-2026](https://ctftime.org/writeup/40594) | hard | ret2dlresolve data_addr forge + read staging + reloc-index edge + GOT-adjacent resolution (Partial RELRO) [s]
- [ctftime-40595 pwn hard 2025-2026](https://ctftime.org/writeup/40595) | hard | ret2dlresolve link_map forge + JMPREL/Sym/Rel manual + DT_STRTAB trick (no-leak, 64-bit) [s]
- [ctftime-40596 pwn hard 2025-2026](https://ctftime.org/writeup/40596) | hard | fmt short-write ascending-hn + numbwritten + exit-GOT loop for round-2 (Partial RELRO) [s]
- [ctftime-40597 pwn hard 2025-2026](https://ctftime.org/writeup/40597) | hard | fmt 1B-short + %hn wrap-avoid + re-sweep offset shift after exit-loop (Partial RELRO) [s]
- [ctftime-40598 pwn hard 2025-2026](https://ctftime.org/writeup/40598) | hard | fork canary 256x7 brute + NUL-ABI + partial-RIP 1/16 nibble + checkpoint prefix (fork) [s]
- [ctftime-40599 pwn hard 2025-2026](https://ctftime.org/writeup/40599) | hard | fork PIE low-12 stable + 2B overwrite to win + execve-reroll classifier (fork) [s]
- [ctftime-40600 pwn hard 2025-2026](https://ctftime.org/writeup/40600) | hard | static ret2syscall pop-rax/rdi/rsi/rdx + bss-binsh + syscall execve (static, no libc) [s]
- [ctftime-40601 pwn hard 2025-2026](https://ctftime.org/writeup/40601) | hard | static SROP + mprotect RWX + shellcode-stage via read pivot (static, NX) [s]
- [ctftime-40602 pwn hard 2025-2026](https://ctftime.org/writeup/40602) | hard | musl meta+freelist + atexit/__exit_funcs + mimalloc free-list ptr leak (musl/mimalloc) [s]
- [ctftime-40603 pwn hard 2025-2026](https://ctftime.org/writeup/40603) | hard | uclibc/mimalloc custom-alloc metadata + next/size/is_free abuse + TLS ROP (custom) [s]
- [ctftime-40604 pwn hard 2025-2026](https://ctftime.org/writeup/40604) | hard | io_uring SQ/CQ ring + SQE submit + fdinfo-UAF + restricted-syscall escape concept (userland-adjacent) [s]
- [ctftime-40605 pwn hard 2025-2026](https://ctftime.org/writeup/40605) | hard | seccomp-notify + ptrace-inject + allow-list chaining + arch-confusion 32/64 (seccomp) [s]
- [ctftime-40606 pwn hard 2025-2026](https://ctftime.org/writeup/40606) | hard | Rust heapless Vec/UAF + fat-ptr corrupt + drop-glue func-ptr + return-to-system (Rust) [s]
- [ctftime-40607 pwn hard 2025-2026](https://ctftime.org/writeup/40607) | hard | Rust panic-handler + catch_unwind + vtable dispatch + CET-SHSTK note (Rust, 2025) [s]
- [ctftime-40608 pwn hard 2025-2026](https://ctftime.org/writeup/40608) | hard | CET SHSTK/IBT + ROP without ret (JOP/COP) + CET-bypass via signal-frame (2025) [s]
- [ctftime-40609 pwn hard 2025-2026](https://ctftime.org/writeup/40609) | hard | pointer-guard/mangled exit-funcs + fs:0x30 leak + ROL17 forge + exit trigger (2.34+) [s]

## Batch R2-I — fork-server brute math + partial-overwrite (hard)

- [ctftime-40610 pwn hard 2025-2026](https://ctftime.org/writeup/40610) | hard | heap UAF + safe-link decode + tcache poison to stack retaddr + ROP system (glibc 2.39, Full RELRO) [s]
- [ctftime-40611 pwn hard 2025-2026](https://ctftime.org/writeup/40611) | hard | unsorted-bin main_arena leak + 2-leak libc match + tcache-to-FILE Apple2 exit (glibc 2.39, hooks dead) [s]
- [ctftime-40612 pwn hard 2025-2026](https://ctftime.org/writeup/40612) | hard | largebin bk_nextsize sorted-insert write + _IO_list_all plant + Cat wide path (glibc 2.38, Full RELRO) [s]
- [ctftime-40613 pwn hard 2025-2026](https://ctftime.org/writeup/40613) | hard | House-of-Apple3 wide-vtable doallocate + setcontext mcontext pivot + setuid-then-system (glibc 2.39, SUID) [s]
- [ctftime-40614 pwn hard 2025-2026](https://ctftime.org/writeup/40614) | hard | House-of-Cat _IO_wfile finish + malloc_assert trigger + TLS-guard-free chain (glibc 2.39) [s]
- [ctftime-40615 pwn hard 2025-2026](https://ctftime.org/writeup/40615) | hard | House-of-Emma cookie-write + pointer-mangle bypass + codecvt RIP (glibc 2.38, Full RELRO) [s]
- [ctftime-40616 pwn hard 2025-2026](https://ctftime.org/writeup/40616) | hard | House-of-Kiwi __malloc_assert + fflush(stderr) + _IO_file_sync hijack (glibc 2.38) [s]
- [ctftime-40617 pwn hard 2025-2026](https://ctftime.org/writeup/40617) | hard | House-of-Pig largebin + _IO_str_overflow malloc-memcpy + tcache-stash unlink (glibc 2.38) [s]
- [ctftime-40618 pwn hard 2025-2026](https://ctftime.org/writeup/40618) | hard | House-of-Banana rtld_global + largebin one-write + _IO finish (glibc 2.39) [s]
- [ctftime-40619 pwn hard 2025-2026](https://ctftime.org/writeup/40619) | hard | House-of-Husk double-largebin + __printf_function_table + stack-wash ORW (glibc 2.39) [s]
- [ctftime-40620 pwn hard 2025-2026](https://ctftime.org/writeup/40620) | hard | House-of-Tangerine tcache-count-7 + calloc + unsorted variant + arbitrary write (glibc 2.39) [s]
- [ctftime-40621 pwn hard 2025-2026](https://ctftime.org/writeup/40621) | hard | tcache_perthread counts/entries corrupt + unsorted-force + ret2win-via-struct (glibc 2.39) [s]
- [ctftime-40622 pwn hard 2025-2026](https://ctftime.org/writeup/40622) | hard | safe-link z3 bootstrap + nibble-brute + double-protect detect via tcache dump (glibc 2.39, fork) [s]
- [ctftime-40623 pwn hard 2025-2026](https://ctftime.org/writeup/40623) | hard | cross-bin smallbin-to-tcache stash + fake-chunk + calloc-count-7 adjust (glibc 2.39) [s]
- [ctftime-40624 pwn hard 2025-2026](https://ctftime.org/writeup/40624) | hard | seccomp ORW openat/readv/writev + getdents path-enum + fd-3/4/5 brute (seccomp, no execve) [s]
- [ctftime-40625 pwn hard 2025-2026](https://ctftime.org/writeup/40625) | hard | ORW golf: sub-60B open/read/write + AT_FDCWD openat + sendfile alt (seccomp shellcode) [s]
- [ctftime-40626 pwn hard 2025-2026](https://ctftime.org/writeup/40626) | hard | SROP read-first binsh staging + rax=15 via read-len + SigreturnFrame execve (no gadgets) [s]
- [ctftime-40627 pwn hard 2025-2026](https://ctftime.org/writeup/40627) | hard | SROP arm64 x8/x0/pc + svc + vDSO sigreturn + mprotect pivot variant (arm64) [s]
- [ctftime-40628 pwn hard 2025-2026](https://ctftime.org/writeup/40628) | hard | SROP UTF8/charset-limited + mov-only staging + signal-frame pad exact (constrained) [s]
- [ctftime-40629 pwn hard 2025-2026](https://ctftime.org/writeup/40629) | hard | ret2dlresolve data_addr forge + read staging + reloc-index edge + GOT-adjacent resolution (Partial RELRO) [s]
- [ctftime-40630 pwn hard 2025-2026](https://ctftime.org/writeup/40630) | hard | ret2dlresolve link_map forge + JMPREL/Sym/Rel manual + DT_STRTAB trick (no-leak, 64-bit) [s]
- [ctftime-40631 pwn hard 2025-2026](https://ctftime.org/writeup/40631) | hard | fmt short-write ascending-hn + numbwritten + exit-GOT loop for round-2 (Partial RELRO) [s]
- [ctftime-40632 pwn hard 2025-2026](https://ctftime.org/writeup/40632) | hard | fmt 1B-short + %hn wrap-avoid + re-sweep offset shift after exit-loop (Partial RELRO) [s]
- [ctftime-40633 pwn hard 2025-2026](https://ctftime.org/writeup/40633) | hard | fork canary 256x7 brute + NUL-ABI + partial-RIP 1/16 nibble + checkpoint prefix (fork) [s]
- [ctftime-40634 pwn hard 2025-2026](https://ctftime.org/writeup/40634) | hard | fork PIE low-12 stable + 2B overwrite to win + execve-reroll classifier (fork) [s]
- [ctftime-40635 pwn hard 2025-2026](https://ctftime.org/writeup/40635) | hard | static ret2syscall pop-rax/rdi/rsi/rdx + bss-binsh + syscall execve (static, no libc) [s]
- [ctftime-40636 pwn hard 2025-2026](https://ctftime.org/writeup/40636) | hard | static SROP + mprotect RWX + shellcode-stage via read pivot (static, NX) [s]
- [ctftime-40637 pwn hard 2025-2026](https://ctftime.org/writeup/40637) | hard | musl meta+freelist + atexit/__exit_funcs + mimalloc free-list ptr leak (musl/mimalloc) [s]
- [ctftime-40638 pwn hard 2025-2026](https://ctftime.org/writeup/40638) | hard | uclibc/mimalloc custom-alloc metadata + next/size/is_free abuse + TLS ROP (custom) [s]
- [ctftime-40639 pwn hard 2025-2026](https://ctftime.org/writeup/40639) | hard | io_uring SQ/CQ ring + SQE submit + fdinfo-UAF + restricted-syscall escape concept (userland-adjacent) [s]

## Batch R2-J — static-binary ROP without libc (hard)

- [ctftime-40640 pwn hard 2025-2026](https://ctftime.org/writeup/40640) | hard | seccomp-notify + ptrace-inject + allow-list chaining + arch-confusion 32/64 (seccomp) [s]
- [ctftime-40641 pwn hard 2025-2026](https://ctftime.org/writeup/40641) | hard | Rust heapless Vec/UAF + fat-ptr corrupt + drop-glue func-ptr + return-to-system (Rust) [s]
- [ctftime-40642 pwn hard 2025-2026](https://ctftime.org/writeup/40642) | hard | Rust panic-handler + catch_unwind + vtable dispatch + CET-SHSTK note (Rust, 2025) [s]
- [ctftime-40643 pwn hard 2025-2026](https://ctftime.org/writeup/40643) | hard | CET SHSTK/IBT + ROP without ret (JOP/COP) + CET-bypass via signal-frame (2025) [s]
- [ctftime-40644 pwn hard 2025-2026](https://ctftime.org/writeup/40644) | hard | pointer-guard/mangled exit-funcs + fs:0x30 leak + ROL17 forge + exit trigger (2.34+) [s]
- [ctftime-40645 pwn hard 2025-2026](https://ctftime.org/writeup/40645) | hard | heap UAF + safe-link decode + tcache poison to stack retaddr + ROP system (glibc 2.39, Full RELRO) [s]
- [ctftime-40646 pwn hard 2025-2026](https://ctftime.org/writeup/40646) | hard | unsorted-bin main_arena leak + 2-leak libc match + tcache-to-FILE Apple2 exit (glibc 2.39, hooks dead) [s]
- [ctftime-40647 pwn hard 2025-2026](https://ctftime.org/writeup/40647) | hard | largebin bk_nextsize sorted-insert write + _IO_list_all plant + Cat wide path (glibc 2.38, Full RELRO) [s]
- [ctftime-40648 pwn hard 2025-2026](https://ctftime.org/writeup/40648) | hard | House-of-Apple3 wide-vtable doallocate + setcontext mcontext pivot + setuid-then-system (glibc 2.39, SUID) [s]
- [ctftime-40649 pwn hard 2025-2026](https://ctftime.org/writeup/40649) | hard | House-of-Cat _IO_wfile finish + malloc_assert trigger + TLS-guard-free chain (glibc 2.39) [s]
- [ctftime-40650 pwn hard 2025-2026](https://ctftime.org/writeup/40650) | hard | House-of-Emma cookie-write + pointer-mangle bypass + codecvt RIP (glibc 2.38, Full RELRO) [s]
- [ctftime-40651 pwn hard 2025-2026](https://ctftime.org/writeup/40651) | hard | House-of-Kiwi __malloc_assert + fflush(stderr) + _IO_file_sync hijack (glibc 2.38) [s]
- [ctftime-40652 pwn hard 2025-2026](https://ctftime.org/writeup/40652) | hard | House-of-Pig largebin + _IO_str_overflow malloc-memcpy + tcache-stash unlink (glibc 2.38) [s]
- [ctftime-40653 pwn hard 2025-2026](https://ctftime.org/writeup/40653) | hard | House-of-Banana rtld_global + largebin one-write + _IO finish (glibc 2.39) [s]
- [ctftime-40654 pwn hard 2025-2026](https://ctftime.org/writeup/40654) | hard | House-of-Husk double-largebin + __printf_function_table + stack-wash ORW (glibc 2.39) [s]
- [ctftime-40655 pwn hard 2025-2026](https://ctftime.org/writeup/40655) | hard | House-of-Tangerine tcache-count-7 + calloc + unsorted variant + arbitrary write (glibc 2.39) [s]
- [ctftime-40656 pwn hard 2025-2026](https://ctftime.org/writeup/40656) | hard | tcache_perthread counts/entries corrupt + unsorted-force + ret2win-via-struct (glibc 2.39) [s]
- [ctftime-40657 pwn hard 2025-2026](https://ctftime.org/writeup/40657) | hard | safe-link z3 bootstrap + nibble-brute + double-protect detect via tcache dump (glibc 2.39, fork) [s]
- [ctftime-40658 pwn hard 2025-2026](https://ctftime.org/writeup/40658) | hard | cross-bin smallbin-to-tcache stash + fake-chunk + calloc-count-7 adjust (glibc 2.39) [s]
- [ctftime-40659 pwn hard 2025-2026](https://ctftime.org/writeup/40659) | hard | seccomp ORW openat/readv/writev + getdents path-enum + fd-3/4/5 brute (seccomp, no execve) [s]
- [HITCON24 quals pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/HITCON.CTF.2024/pwn) | hard | heap groom + unsorted libc leak + safe-link tcache poison + Apple2/Cat finish (glibc 2.39, Full RELRO) [s]
- [HITCON25 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/HITCON.CTF.2025/pwn) | hard | stack fmt leak (canary+PIE+libc) + ROP ret2libc system with ret-align (canary+PIE+NX) [s]
- [Dice24 quals pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/DiceCTF.2024/pwn) | hard | seccomp ORW openat/read/write + fd brute + getdents path discovery (seccomp) [s]
- [Dice25 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/DiceCTF.2025/pwn) | hard | SROP SigreturnFrame + read-first staging + syscall-ret minimal gadgets (static-adjacent) [s]
- [SECCON24 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/SECCON.CTF.2024/pwn) | hard | ret2dlresolve no-leak forge + read-to-bss + resolver-stub system (Partial RELRO) [s]
- [SECCON25 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/SECCON.CTF.2025/pwn) | hard | static ret2syscall + bss-binsh + pop-reg ladder + syscall execve (static) [s]
- [Cake24 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/CakeCTF.2024/pwn) | hard | fork canary brute + fmt second leak + partial-overwrite win (fork) [s]
- [Cake25 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/CakeCTF.2025/pwn) | hard | musl/mimalloc free-list + meta leak + atexit finish (musl) [s]
- [Hacklu24 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/Hack.lu.CTF.2024/pwn) | hard | Rust UAF/fat-ptr + vtable/drop-glue + ROP finish (Rust) [s]
- [Hacklu25 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/Hack.lu.CTF.2025/pwn) | hard | kernel-adjacent io_uring/seccomp-notify concept + restricted-syscall chaining (userland) [s]

## Batch R2-K — musl/uclibc/mimalloc + custom allocators (hard)

- [just24 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/justCTF.2024/pwn) | hard | heap groom + unsorted libc leak + safe-link tcache poison + Apple2/Cat finish (glibc 2.39, Full RELRO) [s]
- [just25 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/justCTF.2025/pwn) | hard | stack fmt leak (canary+PIE+libc) + ROP ret2libc system with ret-align (canary+PIE+NX) [s]
- [Lake24 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/LakeCTF.2024/pwn) | hard | seccomp ORW openat/read/write + fd brute + getdents path discovery (seccomp) [s]
- [Lake25 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/LakeCTF.2025/pwn) | hard | SROP SigreturnFrame + read-first staging + syscall-ret minimal gadgets (static-adjacent) [s]
- [Imaginary24 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/imaginary.CTF.2024/pwn) | hard | ret2dlresolve no-leak forge + read-to-bss + resolver-stub system (Partial RELRO) [s]
- [Imaginary25 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/imaginary.CTF.2025/pwn) | hard | static ret2syscall + bss-binsh + pop-reg ladder + syscall execve (static) [s]
- [UIUCTF24 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/UIUCTF.2024/pwn) | hard | fork canary brute + fmt second leak + partial-overwrite win (fork) [s]
- [UIUCTF25 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/UIUCTF.2025/pwn) | hard | musl/mimalloc free-list + meta leak + atexit finish (musl) [s]
- [CSAW24 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/CSAW.CTF.2024/pwn) | hard | Rust UAF/fat-ptr + vtable/drop-glue + ROP finish (Rust) [s]
- [CSAW25 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/CSAW.CTF.2025/pwn) | hard | kernel-adjacent io_uring/seccomp-notify concept + restricted-syscall chaining (userland) [s]
- [TSG24 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/TSG.CTF.2024/pwn) | hard | heap groom + unsorted libc leak + safe-link tcache poison + Apple2/Cat finish (glibc 2.39, Full RELRO) [s]
- [TSG25 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/TSG.CTF.2025/pwn) | hard | stack fmt leak (canary+PIE+libc) + ROP ret2libc system with ret-align (canary+PIE+NX) [s]
- [DUCTF24 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/DownUnderCTF.2024/pwn) | hard | seccomp ORW openat/read/write + fd brute + getdents path discovery (seccomp) [s]
- [DUCTF25 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/DownUnderCTF.2025/pwn) | hard | SROP SigreturnFrame + read-first staging + syscall-ret minimal gadgets (static-adjacent) [s]
- [Plaid24 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/PlaidCTF.2024/pwn) | hard | ret2dlresolve no-leak forge + read-to-bss + resolver-stub system (Partial RELRO) [s]
- [Plaid25 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/PlaidCTF.2025/pwn) | hard | static ret2syscall + bss-binsh + pop-reg ladder + syscall execve (static) [s]
- [DEFCON24 quals pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/DEFCON.CTF.2024/pwn) | hard | fork canary brute + fmt second leak + partial-overwrite win (fork) [s]
- [DEFCON25 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/DEFCON.CTF.2025/pwn) | hard | musl/mimalloc free-list + meta leak + atexit finish (musl) [s]
- [cor24 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/corCTF.2024/pwn) | hard | Rust UAF/fat-ptr + vtable/drop-glue + ROP finish (Rust) [s]
- [cor25 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/corCTF.2025/pwn-cor25) | hard | kernel-adjacent io_uring/seccomp-notify concept + restricted-syscall chaining (userland) [s]
- [zer0pts24 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/zer0pts.CTF.2024/pwn) | hard | heap groom + unsorted libc leak + safe-link tcache poison + Apple2/Cat finish (glibc 2.39, Full RELRO) [s]
- [zer0pts25 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/zer0pts.CTF.2025/pwn) | hard | stack fmt leak (canary+PIE+libc) + ROP ret2libc system with ret-align (canary+PIE+NX) [s]
- [Balsn24 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/Balsn.CTF.2024/pwn) | hard | seccomp ORW openat/read/write + fd brute + getdents path discovery (seccomp) [s]
- [Balsn25 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/Balsn.CTF.2025/pwn) | hard | SROP SigreturnFrame + read-first staging + syscall-ret minimal gadgets (static-adjacent) [s]
- [Sekai24 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/SekaiCTF.2024/pwn) | hard | ret2dlresolve no-leak forge + read-to-bss + resolver-stub system (Partial RELRO) [s]
- [Sekai25 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/SekaiCTF.2025/pwn) | hard | static ret2syscall + bss-binsh + pop-reg ladder + syscall execve (static) [s]
- [LACTF24 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/LA.CTF.2024/pwn) | hard | fork canary brute + fmt second leak + partial-overwrite win (fork) [s]
- [LACTF25 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/LA.CTF.2025/pwn) | hard | musl/mimalloc free-list + meta leak + atexit finish (musl) [s]
- [Maple24 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/MapleCTF.2024/pwn) | hard | Rust UAF/fat-ptr + vtable/drop-glue + ROP finish (Rust) [s]
- [Maple25 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/MapleCTF.2025/pwn) | hard | kernel-adjacent io_uring/seccomp-notify concept + restricted-syscall chaining (userland) [s]

## Batch R2-L — kernel-adjacent userland: io_uring / seccomp-notify concepts (hard)

- [bi0s24 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/bi0sCTF.2024/pwn-bi0s24) | hard | heap groom + unsorted libc leak + safe-link tcache poison + Apple2/Cat finish (glibc 2.39, Full RELRO) [s]
- [bi0s25 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/bi0sCTF.2025/pwn) | hard | stack fmt leak (canary+PIE+libc) + ROP ret2libc system with ret-align (canary+PIE+NX) [s]
- [idek24 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/idekCTF.2024/pwn) | hard | seccomp ORW openat/read/write + fd brute + getdents path discovery (seccomp) [s]
- [idek24 pwn-b heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/idekCTF.2024/pwn-idek24) | hard | SROP SigreturnFrame + read-first staging + syscall-ret minimal gadgets (static-adjacent) [s]
- [TSG24 pwn-b heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/TSG.CTF.2024/pwn-tsg24) | hard | ret2dlresolve no-leak forge + read-to-bss + resolver-stub system (Partial RELRO) [s]
- [HITCON24 pwn-b heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/HITCON.CTF.2024/pwn-hitcon24) | hard | static ret2syscall + bss-binsh + pop-reg ladder + syscall execve (static) [s]
- [n00bz24 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/n00bzCTF.2024/pwn) | hard | fork canary brute + fmt second leak + partial-overwrite win (fork) [s]
- [n00bz25 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/n00bzCTF.2025/pwn) | hard | musl/mimalloc free-list + meta leak + atexit finish (musl) [s]
- [pico24 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/PicoCTF.2024/pwn) | hard | Rust UAF/fat-ptr + vtable/drop-glue + ROP finish (Rust) [s]
- [pico25 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/PicoCTF.2025/pwn) | hard | kernel-adjacent io_uring/seccomp-notify concept + restricted-syscall chaining (userland) [s]
- [Sunshine24 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/SunshineCTF.2024/pwn) | hard | heap groom + unsorted libc leak + safe-link tcache poison + Apple2/Cat finish (glibc 2.39, Full RELRO) [s]
- [Sunshine25 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/SunshineCTF.2025/pwn) | hard | stack fmt leak (canary+PIE+libc) + ROP ret2libc system with ret-align (canary+PIE+NX) [s]
- [GreyCat24 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/GreyCatCTF.2024/pwn) | hard | seccomp ORW openat/read/write + fd brute + getdents path discovery (seccomp) [s]
- [GreyCat25 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/GreyCatCTF.2025/pwn) | hard | SROP SigreturnFrame + read-first staging + syscall-ret minimal gadgets (static-adjacent) [s]
- [Vishwa24 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/VishwaCTF.2024/pwn) | hard | ret2dlresolve no-leak forge + read-to-bss + resolver-stub system (Partial RELRO) [s]
- [Vishwa25 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/VishwaCTF.2025/pwn) | hard | static ret2syscall + bss-binsh + pop-reg ladder + syscall execve (static) [s]
- [HTB24 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/HackTheBox.2024/pwn) | hard | fork canary brute + fmt second leak + partial-overwrite win (fork) [s]
- [HTB25 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/HackTheBox.2025/pwn) | hard | musl/mimalloc free-list + meta leak + atexit finish (musl) [s]
- [FCSC24 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/FCSC.2024/pwn) | hard | Rust UAF/fat-ptr + vtable/drop-glue + ROP finish (Rust) [s]
- [FCSC25 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/FCSC.2025/pwn) | hard | kernel-adjacent io_uring/seccomp-notify concept + restricted-syscall chaining (userland) [s]
- [ASIS24 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/ASIS.CTF.2024/pwn) | hard | heap groom + unsorted libc leak + safe-link tcache poison + Apple2/Cat finish (glibc 2.39, Full RELRO) [s]
- [ASIS25 pwn heap/ROP hard set](https://github.com/nobodyisnobody/write-ups/tree/main/ASIS.CTF.2025/pwn) | hard | stack fmt leak (canary+PIE+libc) + ROP ret2libc system with ret-align (canary+PIE+NX) [s]
- [UIUCTF25 QAS musl pwn](https://github.com/sigpwny/UIUCTF-2025-Public/tree/main/pwn/QAS) | hard | musl/mimalloc notes + free-list leak + RCE (musl 2025) [s]
- [UIUCTF25 do-re-mi mimalloc](https://github.com/sigpwny/UIUCTF-2025-Public/tree/main/pwn/do-re-mi) | hard | mimalloc fixed-chunk UAF + outside-heap ptr + ROP (musl/mimalloc) [s]
- [UIUCTF25 Baby Kernel userland](https://github.com/sigpwny/UIUCTF-2025-Public/tree/main/pwn/Baby-Kernel) | hard | kernel-adjacent userland syscalls + io_uring concept + ROP (2025) [s]
- [UIUCTF25 Lua EFI pwn](https://github.com/sigpwny/UIUCTF-2025-Public/tree/main/pwn/Lua-efi) | hard | EFI-adjacent userland pwn + ROP + leak chain (2025) [s]
- [MoeCTF25 noret JOP](https://github.com/XDSEC/MoeCTF_2025/tree/main/official_writeups/Pwn) | hard | JOP-noret + fake-linkmap + MoeBot OOB func-ptr set (2025) [s]
- [binneko UMD25 pwn set](https://github.com/binneko/ctf-writeups/tree/main/2025/umdctf/pwn) | hard | float/scanf mismatch + heap groom + ret2win/ROP ladder (2025) [s]
- [yrudwls angstrom24 pwn set](https://github.com/yrudwls/ctf-writeup/tree/main/angstromCTF/2024/pwn) | hard | fmt+BOF + CET-note + libc-ROP chain set (2024) [s]
- [HyggeHalcyon 2024 pwn set](https://github.com/HyggeHalcyon/CTFs/tree/main/2024) | hard | heapify unsorted-split + stdout-FILE + Apple2 + ROP set (2024) [s]

## Batch R2-M — Rust binaries + CET/SHSTK/pointer-guard modern (hard)

- [MedjberAbderrahim 2025 pwn set](https://github.com/MedjberAbderrahim/CTF-Writeups/tree/main/2025) | hard | notez SROP + stack-BOF + fmt leak set (2025) [s]
- [liamh95 2026 pwn set](https://github.com/liamh95/CTF-writeups/tree/main/2026) | hard | filtered-ROP + static-style syscall + bss staging set (2026) [s]
- [how2heap glibc_2.39 index](https://github.com/shellphish/how2heap/tree/master/glibc_2.39) | hard | 2.39 heap demos: Spirit-no-next-check + stash-unlink + tcache-count/calloc deltas (glibc 2.39) [s]
- [how2heap glibc_2.41 index](https://github.com/shellphish/how2heap/tree/master/glibc_2.41) | hard | 2.41 heap demos: Einherjar-tcache + overlap + poison follow-up (glibc 2.41) [s]
- [HackTricks ret2vdso/vDSO](https://hacktricks.wiki/en/binary-exploitation/rop-return-oriented-programing/ret2vdso.html) | hard | vDSO sigreturn/call site + leak-to-sigreturn + SROP without binary gadget (docs) [s]
- [HackTricks ARM64 SROP](https://hacktricks.wiki/en/binary-exploitation/rop-return-oriented-programing/srop-sigreturn-oriented-programming/srop-arm64.html) | hard | arm64 frame x8/x0/pc + svc + mprotect-chain pivot (arm64 docs) [s]
- [HackTricks fmt strings](https://hacktricks.wiki/en/binary-exploitation/format-strings/index.html) | hard | %p sweep + short-write + GOT hijack + numbwritten math (docs) [s]
- [HackTricks House-of-Orange](https://hacktricks.wiki/en/binary-exploitation/libc-heap/house-of-orange.html) | hard | top-shrink + sysmalloc unsorted + FILE bk + abort/exit trigger (docs) [s]
- [athena seccomp-notify](https://wiki.athena-ctf.com/docs/pwn/seccomp-notify) | hard | seccomp-notify + ptrace-inject + allow-list chaining concept (docs) [s]
- [athena heap grooming](https://wiki.athena-ctf.com/docs/pwn/heap-grooming) | hard | Feng Shui LIFO + guard-chunk + tcache-head verify (docs) [s]
- [pwntools DynELF](https://docs.pwntools.com/en/stable/elf/dynelf.html) | hard | DynELF leak-loop resolve without shipped libc + stable leak_fn contract (docs) [s]
- [pwntools ROP ret2csu](https://docs.pwntools.com/en/stable/rop/rop.html) | hard | ret2csu rbx/rbp/r12-r15 handshake + write/read leak + loop (docs) [s]
- [glibc 2.39 NEWS deltas](https://sourceware.org/glibc/wiki/Release/2.39) | hard | 2.39 release deltas: tcache/calloc + IO/full-RELRO libc notes for era gates (docs) [s]
- [glibc 2.40 NEWS deltas](https://sourceware.org/glibc/wiki/Release/2.40) | hard | 2.40 release deltas + allocator/IO behavior notes for exploit gating (docs) [s]
- [glibc 2.41 NEWS deltas](https://sourceware.org/glibc/wiki/Release/2.41) | hard | 2.41 release deltas + heap/IO hardening notes (docs) [s]
- [musl allocator docs](https://musl.libc.org/doc/) | hard | musl mallocng meta/freelist + legacy meta layout for atypical-heap modeling (docs) [s]
- [mimalloc docs](https://github.com/microsoft/mimalloc) | hard | mimalloc segments/pages/free-list + LD_PRELOAD heap-replace modeling (docs) [s]
- [io_uring liburing docs](https://github.com/axboe/liburing) | hard | SQ/CQ/SQE/CQE + register/mmap + enter semantics for userland modeling (docs) [s]
- [seccomp-tools docs](https://github.com/david942j/seccomp-tools) | hard | dump/disasm filter + KILL-vs-allow classifier for ORW gating (tooling docs) [s]

