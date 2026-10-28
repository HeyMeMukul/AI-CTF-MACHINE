# R5 deep reads — pwn (14 complete articles, browser-read 2026-10-17)

Full distillations. Format per entry: proof-of-read, chain, gotcha, reuse rule.
Technique-only; no flags.

## 1. samuzora FSOP-analysis
- READ: `_IO_FILE_plus.vtable` at 0xd8; glibc>2.23 `IO_validate_vtable` checks offset-in-section or `_IO_vtable_check()` fatals.
- CHAIN: arb-write FILE → keep vtable inside `__libc_IO_vtables` → abuse legit `IO_wfile_jumps` fields (`_IO_write_ptr/_IO_buf_base/_flags`) via House-of-Apple/Kiwi/Banana/Emma/Pig → RCE without fake vtable.
- GOTCHA: Fake vtable outside section fatals; reuse existing vtables + corrupt FILE data pointers/flags instead.
- REUSE: Post-2.23 FSOP = never forge vtable; forge FILE fields around whitelisted vtable.

## 2. lkmidas kernel-pwn part 2 (SMEP/SMAP/KPTI)
- READ: `native_write_cr4=0xffffffff814443e0`; clearing `0x100000` trips `cr_pinning` (`pinned CR4 bits changed`).
- CHAIN: save_state + cookie leak → `pop rdi;0;prepare_kernel_cred` → cmp/mov chain → `commit_creds` → `swapgs;iretq` or `kpti_trampoline+22` with full `RIP|CS|RFLAGS|SP|SS`; truncated overflow → `mov esp,IMM` + mmaped fake stack.
- GOTCHA: `iretq` unfindable via ROPgadget (`objdump -j .text -d vmlinux | grep iretq`); `signal(SIGSEGV,get_shell)` alt for KPTI.
- REUSE: Never clear CR4 (pinned); default full ROP prepare/commit + KPTI-trampoline; pivot via `mov esp,IMM`.

## 3. lkmidas kernel-pwn part 3 (FG-KASLR)
- READ: Per-function randomization; unaffected `_text..__x86_retpoline_r15(+0x400dc6)`, `ksymtab@_text+0xf85198` with REL32 `value_off`.
- CHAIN: leak cookie + `image_base` → stage1 resolve `commit_creds` via `ksymtab value_offset` → save to `tmp_store` → stage `prepare(0)` → `commit(cred)` across multiple iretq returns.
- GOTCHA: Single `commit(prepare(0))` chain lacks `rax→rdi` gadget in unaffected region; split into 4 stages.
- REUSE: Under FG-KASLR use only non-randomized gadgets + ksymtab oracle; split privesc across returns.

## 4. lkmidas modprobe_path
- READ: `modprobe_path` default `/sbin/modprobe`; `call_usermodehelper_setup` fires on unknown magic via `request_module`.
- CHAIN: leak kbase → 8-byte write `/tmp/x` path string into `modprobe_path` → KPTI return → drop script + `\xff\x04` trigger file → execute.
- GOTCHA: Needs writable path + valid write size; two 4-byte ioctl writes if needed; repair unsorted-bin size after.
- REUSE: Prefer `modprobe_path` overwrite over commit_creds when arb-write + KASLR-bypass exists.

## 5. smallkirby kernel-rop (hxp 2020)
- READ: `file vmlinux: too many section (36140)` = FGKASLR; `hackme_read/write` copies `$rsp-0x98`, canary at `$rbp-0x18`; wrote `neorop++` wrapper.
- CHAIN: read 0x1a0 → canary + `kbase=rbuf[38]-0xa157` → ksymtab resolve commit/prepare → `go-home` gadget chain → NIRUGIRI `execve(/bin/sh)`.
- GOTCHA: Short `write 0x130` truncates `user_ss`; full `RIP|CS|RFLAGS|SP|SS` + asm `save_state()` (mov cs/ss/rsp + pushf).
- REUSE: Hunt stack pointer at fixed offset for non-randomized kbase; automate FGKASLR-safe gadget search.

## 6. pwn2ooown HFT unintended (House-of-Cat)
- READ: glibc-2.35 no-free `malloc(sz);gets(&pkt->data)`; `safe_linking(a,b)=(a>>12)^b`; `stderr=libc+0x21A860`.
- CHAIN: `malloc(0x18,…0xD51)` shrink top → `malloc(0x1000)` frees top (House-of-Orange) → tcache-poison → unsorted libc leak → overwrite `stderr` with fake `_IO_FILE(mode=1)` → shrink top + `malloc` triggers `__malloc_assert→fflush(stderr)` → RCE.
- GOTCHA: `gets` NULL byte blocks leaks + corrupted unsorted-bin size aborts; leak via ECHO mode print; fix bin size with padding alloc.
- REUSE: No-free heap = shrink-top to free top; then tcache-poison + `_IO_FILE` assert chain when hooks gone.

## 7. eth007 HFT intended (mmap + TLS)
- READ: Hint `size>mp_.mmap_threshold`; mmap chunk sits below TLS holding `tcache_perthread_struct`; `setcontext32` endgame.
- CHAIN: free top → unsorted heap leak → fake tcache counts → overflow into TLS `tcache_ptr` → arbitrary alloc → libc → second hijack `dest=got` + `setcontext32` payload → shell.
- GOTCHA: Unsorted-bin attack patched + hooks gone + one-gadgets fail; control `tcache_perthread_struct` + full-register `setcontext`.
- REUSE: mmap overflow reaching TLS → overwrite `tcache_perthread_struct` for arbitrary alloc; `setcontext` for post-libc RCE.

## 8. zellic V8CTF CVE-2025-2135
- READ: `InferMapsUnsafe()` misses alias check on `TransitionElementsKindOrCheckMap`; SMI→DOUBLE→ELEMENTS kind confusion via `f0(v1,v1)` alias.
- CHAIN: `%PrepareFunctionForOptimization` + alias call + `%OptimizeFunctionOnNextCall` → mis-inferred double → double-as-tagged-ptr fakeObj → forge `JSArray` in buffer → arb R/W via elements pointer → OOB length.
- GOTCHA: IR side-effects unmodeled; patch = `kUnreliableMaps` on alias mismatch.
- REUSE: TurboFan ElementsKind bugs: force alias (same obj, two params) + transition + side-effect call, then double-to-ptr fakeObj.

## 9. UIUCTF Baby-Kernel (tty reclaim)
- READ: 60-line exploit; `K1_TYPE 0xB9`, `modprobe_path` offset `0x1b3f600`, `kbase=*(buf+32)-0x1285100`.
- CHAIN: `ALLOC/FREE` UAF → `open(/dev/ptmx)` reclaim as `tty_struct` → `USE_READ` leak → `USE_WRITE` hijack `tty->ops->ioctl` with `mov [rdx],rsi` gadget → two 4-byte writes of `/tmp/pv` path → trigger script.
- GOTCHA: ioctl cmd size forces two 4-byte writes (`/tmp` + `/pv` at +4).
- REUSE: UAF + ptmx/tty reclaim → `tty_operations` overwrite = 8-byte arb write → modprobe_path.

## 10. TsukuCTF easy_kernel (seq_ops)
- READ: `/dev/vuln` cmds ALLOC/WRITE/FREE, `buf[0x20]` = kmalloc-32, no KASLR/SMEP.
- CHAIN: save_state → alloc;free (dangling, no NULL) → `open(/proc/self/stat)` reclaim as `seq_operations` → overwrite `start` with privesc fn → `read()` triggers → `commit_creds(init_cred);swapgs;iretq` → shell.
- GOTCHA: Direct `start=userland` fails if SMEP on; use `mov esp` pivot + kernel ROP there.
- REUSE: kmalloc-32 UAF + `/proc/self/stat` spray = classic `seq_operations->start` hijack; always save_state first.

## 11. corCTF zenerational-aura (crash oracle)
- READ: Custom `syscall(corctf_crash,func,arg)` = call rax(rdi); KASLR via `prefetchnta/prefetcht2` timing sweep; crash log leaks `RCX` qword.
- CHAIN: prefetch sweep for kbase (mapped=fast) → `syscall(mov_rcx_[rdi], flag_addr)` → deliberate crash → read `RCX` from kernel log → slide `flag+8` per crash for full dump. No privesc/ROP at all.
- GOTCHA: Crash wipes state; predict view-addr pattern + loop single-qword oracle per crash.
- REUSE: `call rax(rdi)` + reg-leaking crash log = skip SMEP/SMAP/ROP; prefetch KASLR bypass + crash-oracle exfil.

## 12. SKIPPED — justCTF tape (repo index only, no solver content returned)

## 13. r3ctf pewpew (Windows UAF + NtContinue)
- READ: Win2025 remote; PoW sha256-28bit; pilot/scout `0x50`; vtable = tap-scan(read)+readline(write)+WriteFile(socket).
- CHAIN: spray scouts → alloc/free pilot (dangling) → scout reuse leaks EXE+heap → vtable hijack → leak ntdll/kernel32 → `readline`-laid `CONTEXT`+ROP → `NtContinue` pivot → `NtQueryInformationProcess(PEB)` → steal `CurDir HANDLE` → `NtOpenFile("flag.txt")+NtReadFile+WriteFile` in-connection.
- GOTCHA: `WinExec(cmd /c type)` async + no socket inherit = silent; `0x0a/0x0d` kill `readline`; in-process NtOpen/NtRead + reconnect on bad bytes.
- REUSE: Windows remote exfil = never spawn child; steal `CurDir HANDLE` from PEB, open relative; `NtContinue` for arg control.

## 14. faraz ROP-Emporium series
- READ: ret2win off 44(x86)/40(x64); `split` sys addresses; `callme` pop3 gadgets (x86 `0x080488a9` / x64 `0x401ab0`); `write4` mov+pop pair; `.data` plant addresses.
- CHAIN: `A*off + ret2win` → x86 `system+BBBB+bin_cat` / x64 `pop_rdi+str+system` → chained callme_one/two/three → `write4` plant `/bin/sh ` in `.data` → `system(.data)` (x64: pad `pop r14/r15` for mov gadget).
- GOTCHA: x64 `RIP>0x7fffffffffff` faults hide offset; `fgets` newline + 8-byte alignment; write `/bin/sh ` with trailing space.
- REUSE: Leak-less ROP template: pop-args + pop-mov `.data` plant + system.

## 15. hack.lu LOKALTAL (ALPC UAF)
- READ: `AlpcpCreateView` patch moved `AlpcpReferenceBlob` after insert → delete-race; `SetProcessAffinityMask` (all threads) vs per-thread bug killed spray tuning.
- CHAIN: create port + section → predict view addr → deleter thread + sender thread race `ExposeViewAttribute` → WNF spray fake `KALPC_VIEW/BLOB` → `receive+RELEASE_MESSAGE` unlink arb-write → leak + privesc.
- GOTCHA: Immediate-drop path BSoDs (`ref0`); use message-attribute holder path + `SetThreadAffinityMask` pinning.
- REUSE: Refcount-move bugs: use persistent-holder path, verify affinity API scope before tuning races.
