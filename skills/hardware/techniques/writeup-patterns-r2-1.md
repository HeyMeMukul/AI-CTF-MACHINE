# Hardware Writeup Patterns — R2 File 1 (W33..W43)

Companion to `../SKILL.md` → `## Writeup-Distilled Patterns (W33..W64)`.
Index table lives in SKILL.md; bodies live here (W33..W43), in
`writeup-patterns-r2-2.md` (W44..W54) and `writeup-patterns-r2-3.md`
(W55..W64). Same contract: technique-only, placeholders only, every URL
verified in `knowledge/writeups_mined/hardware_manifest_r2.md`.

### W33. ESP32 secure-boot section-overwrite (CVE-2018-18558 shape)

- **Signals:** ESP-IDF 2nd-stage bootloader ≤ v3.1-rc2; QEMU + `flash-base`
  harness; `iram_loader_seg` region; app-image `load_addr` fields.
- **Steps:** 1. Diff vulnerable vs fixed `esp_image_format.c`
  (`process_segment`). 2. Locate post-verify branch in own debug build
  (FID-match the stripped loader). 3. Append segment aimed at that
  branch, fix checksum/hash, attach fake signature block. 4. Upload,
  poll QEMU serial for flash-read behavior.
- **Commands:**
  ```bash
  esptool.py image_info app.bin
  python3 add_segment.py --target <branch-addr> --out evil.bin
  qemu-system-xtensa -machine esp32 -drive file=flash.bin,if=mtd,format=raw 2>&1 | tee uart.log
  ```
- **Pitfalls:** image bytes are RAM-obfuscated until after verify — the
  payload need not be precise, the *address* must be; `load_addr` range
  checks differ per IDF rev, diff first.
- **Sources:**
  https://www.elttam.com/blog/ductf24-especially-secure-boot
  https://github.com/elttam/DUCTF-ESPecially-secure-boot/blob/main/solution/exploit.py
  https://ctf.bugku.com/challenges/detail/id/2862.html

### W34. ESP32-C3/C6 voltage-FI buffer overflow to shellcode

- **Signals:** RISC-V ESP32-C3/C6 Boot ROM ELFs (public); `check_condCOUNTER`
  re-verify loops; `ets_loader_map_range` + fixed-size stack buffer.
- **Steps:** 1. RE the ROM for map-then-copy sequences with short length
  immediates. 2. Tune crowbar (offset/width) at the length-load insn.
  3. Overflow into adjacent pointer, pivot `memcpy` to arbitrary write.
  4. Drop ≤128 B shellcode via first flash block; dump rest over UART.
- **Commands:**
  ```bash
  riscv64-unknown-elf-objdump -d bootrom.elf | grep -A6 'ets_loader_map_range'
  python3 fi_sweep.py --trigger qspi --offset-start 0 --offset-stop 9000 --widths 20,40,80 --log shots.csv
  ```
- **Pitfalls:** naive branch-glitch dies on the counter re-checks — target
  the *length* path instead; MMU maps 64 KiB per request regardless of
  asked size, size the overflow accordingly.
- **Sources:**
  https://courk.cc/esp32-c3-c6-fault-injection
  https://courk.cc/breaking-flash-encryption-of-espressif-parts

### W35. ESP32-V3 single-glitch CRC-to-PC redirect

- **Signals:** FI-hardened V3 + eFuses (Secure Boot, Flash Encrypt, Release);
  ROM CRC print on UART; SPI-CS observable; DevKitC-class board.
- **Steps:** 1. Enable features one-by-one (manual eFuse order). 2. Craft
  encrypted images steering recomputed CRC32 to a chosen ROM address.
  3. EM-glitch the CRC-move into PC (CS-triggered window). 4. Land in
  ROM Download Mode in Normal state → read cleartext flash.
- **Commands:**
  ```bash
  espefuse.py burn_efuse SECURE_BOOT_EN
  python3 crc_steer.py --target 0x40008ceb --images 33 --out imgs/
  python3 taofi_plot.py --in shots.csv --around 73000 --unit ns
  ```
- **Pitfalls:** needs ≥33 programmed images per address attempt — pipeline
  the flash loop; success shows as exception text first (`0x41…` probe),
  only then switch the pointer to shellcode.
- **Sources:**
  https://www.usenix.org/system/files/woot24-delvaux.pdf
  https://raelize.com/blog/espressif-systems-esp32-using-a-crowbar-glitch-to-bypass-encrypted-secure-boot/

### W36. RP2350 multi-vector secure-boot challenge

- **Signals:** RP2350 + OTP secret row + locked debug; RCP + glitch
  detectors at max; published ROM; Hextree-style test PCB.
- **Steps:** 1. Map boot stages (power-state machine → verify → USB
  reboot API → OTP lock). 2. Pick one vector: OTP-VDD drop, reboot-type
  confusion, QSPI-pointer laser fault, double-EMFI OTP lock, FIB
  antifuse read. 3. Calibrate trigger (QSPI/USB activity) around RCP
  random delays. 4. Chain to OTP-secret exfil.
- **Commands:**
  ```bash
  picotool otp read --raw otp.bin
  python3 rcp_profile.py --runs 200 --out delay_hist.csv
  openocd -f interface/cmsis-dap.cfg -f target/rp2350.cfg -c 'init; scan_chain; exit'
  ```
- **Pitfalls:** detectors punish wide pulses — localize (laser/EM) rather
  than widen; RCP delays make cycle-exact timing a distribution, sweep
  it, do not assume it.
- **Sources:**
  https://www.usenix.org/system/files/woot25-muench.pdf
  https://courk.cc/rp2350-challenge-laser
  https://www.keysight.com/blogs/en/tech/nwvs/2025/03/26/security-highlight-rp2350-hardware-attacks

### W37. OP-TEE secure-storage ladder rebuild (HUK→SSK→TSK→FEK)

- **Signals:** QEMU `virt,secure=on` + `bl1.bin` + `tee.elf`; `data/tee/`
  blobs without `dirf.db`; constant-HUK platform note.
- **Steps:** 1. Derive SSK from stub HUK + chip ID, TSK from SSK + TA
  UUID. 2. Populate a fresh tree (create objects), swap in target blob.
  3. NOP the tree-verify (keep root-verify intact). 4. Read back via
  session API and decrypt FEK→data offline.
- **Commands:**
  ```bash
  qemu-system-aarch64 -machine virt,secure=on -cpu cortex-a57 -bios bl1.bin -kernel Image -initrd rootfs.cpio.gz -nographic
  python3 ssk_tsk.py --huk <hex> --chip-id <hex> --uuid <ta-uuid> --blob data/tee/2
  ```
- **Pitfalls:** killing root-verify corrupts the program — bypass only the
  *tree* check; FEK is per-file random, TSK alone never suffices.
- **Sources:**
  https://ctftime.org/writeup/32101
  https://bestwing.me/RWCTF-4th-TrustZone-challenge-Writeup.html

### W38. OP-TEE TA stack-BOF → secure-object ROP reader

- **Signals:** signed TA with `memmove`-into-stack + `TEE_*Object` calls;
  32-bit secure ASLR (~7 bits); ldelf fixed base; secure-UART logs.
- **Steps:** 1. Overflow to saved `x29/x30`. 2. ROP with mid-function
  entry (spilled callee-saved regs carry args). 3. Pivot to stack-top
  (param pages reject syscalls). 4. Chain
  alloc→start→next-enum→open→read→memmove-out.
- **Commands:**
  ```bash
  gdb-multiarch -ex 'target remote :1234' -ex 'b *0xe100000'
  aarch64-linux-gnu-ropper --file ta.elf --search 'ldp x29, x30, \[sp\],'
  ```
- **Pitfalls:** `x0-x3` load gadgets are rare — reuse spilled `x19+`
  instead; stack and `.text` share the ASLR base, one leak breaks both.
- **Sources:**
  https://ctftime.org/writeup/32100
  https://github.com/vdehors/writeups/blob/master/ph0wn2019/pwn/securefs/README.md

### W39. OP-TEE kernel UAF → privileged-SMC hijack

- **Signals:** custom `tee.elf` + `sas_do_smc_healthcheck` gate
  (`0xC2001338` vs other); hash-op tables with function pointers;
  TA-buildable `hello_world` skeleton.
- **Steps:** 1. Build benign TA, map syscall surface. 2. Free + reuse
  `crypto_hash_ctx` via alloc/digest-final sequences. 3. Plant fake
  `crypto_hash_ops` with `final=sas_do_smc_healthcheck`. 4. Invoke with
  non-health ID, shuttle output buffer back to CA.
- **Commands:**
  ```bash
  repo init -u https://github.com/OP-TEE/manifest.git -m qemu_v8.xml -b 4.5.0 && repo sync
  make -C build -j$(nproc)
  ```
- **Pitfalls:** production TA-signing blocks custom TAs — the UAF must be
  reachable from the *shipped* TA; output buffer must be TA-owned memory
  or the copy-out faults.
- **Sources:**
  https://ctftime.org/writeup/40255
  https://pwn.report/2026/03/15/sasctf2025-optee-exploitation.html

### W40. Open-TEE param-type confusion → GOT redirect

- **Signals:** Open-TEE (non-isolated twin) TA; `paramTypes` unchecked;
  `value`/`memref` union overlap; partial-RELRO + `TEE_MemMove` in PLT.
- **Steps:** 1. Leak via Shared-Memory index confusion. 2. Derive
  `grade_ta.so` base via mmap-relativity from libc leak. 3. Send VALUE
  where MEMREF expected → raw pointer control in `TEE_MemMove`.
  4. Overwrite GOT entry → `system("chmod …flag…")`, then `cat`.
- **Commands:**
  ```bash
  sed -n 's/.*TEEC_InvokeCommand.*//p' engine.log | head
  python3 mmap_rel.py --libc-leak <addr> --offset 0x228000
  ```
- **Pitfalls:** `memref.size` zeroes under confusion — length comes from
  the constant, not your input; TOCTOU on shared buffers cuts both
  ways, copy-then-validate.
- **Sources:**
  https://chalkiadakis.me/posts/lakectf23/trust-mee/

### W41. QEMU PCI MMIO OOB → ops/opaque escape

- **Signals:** custom PCI device (`BAR0` + `memory_region_init_io`);
  `CMD/SRC/DST/CNT/TRIGGER` or `OFFSET/DATA` registers; `cnt`-checked
  but offset-free DMA; `MemoryRegionOps` + `opaque` in reach.
- **Steps:** 1. Map `resource0`, build 8 B R/W helpers (4 B halves where
  needed). 2. Negative-offset leak (`opaque` = device ptr; `ops` = PIE).
  3. Plant fake-ops (`read=system`, keep `write`), string (`/bin/sh`)
  in `dma_buf`. 4. Overwrite `mmio.ops`/`opaque`, trigger read.
- **Commands:**
  ```bash
  fd=open('/sys/devices/pci0000:00/0000:00:04.0/resource0','r+b'); mem=mmap.mmap(fd.fileno(),0x1000)
  python3 qemu_esc.py --mmio-base <addr> --mode offset-data
  busybox devmem 0x<bar+off> w 0x<val>   # no-compiler fallback path
  ```
- **Pitfalls:** access-size clamps (1/4 B) split every 8 B op — script the
  halves; stack alignment kills bare `system`, route via an aligning
  call gadget.
- **Sources:**
  https://ret2school.github.io/post/cloudinspect/
  https://kioreo.github.io/posts/CTF-SECCON-CTF-2024-Qauls-BabyQemu-Write-Up/
  https://diegoaltf4.com/quememu-writeup/

### W42. QEMU DMA-reentrancy UAF chain

- **Signals:** NVMe + rtl8139 + HDA in one guest; DMA-write-to-MMIO
  capable devices; freed CQ/SQ assertion text on crash.
- **Steps:** 1. Program NVMe IO-mgmt-recv with `dptr` aimed at rtl8139
  TX poll. 2. Loopback rtl8139 RX into NVMe reset register. 3. Time the
  second MMIO to land inside the first's DMA window → CQ UAF.
  4. Reclaim with HDA BDL allocs → tcache-poison → arbitrary write.
- **Commands:**
  ```bash
  lspci -vv | grep -A3 -i 'nvme\|8139\|hda'
  cat /proc/iomem | grep -i 'nvme\|hda'
  ```
- **Pitfalls:** reentrancy windows are device-order dependent — fix the
  MMIO layout first (`/proc/iomem`), then tune lengths; assertion text
  names the freed object, read it before guessing.
- **Sources:**
  https://u1f383.github.io/ctf/2024/07/18/hitcon-ctf-qual-2024-pwn-challenge-part-2-reEscape.html
  https://ctftime.org/writeup/37935

### W43. NIC-descriptor DMA → arbitrary-phys primitive

- **Signals:** PCIe NIC driver with MMIO-bar map IOCTL + mode/registry
  gate; TX/RX ring + loopback mode; user-PFN allocator.
- **Steps:** 1. Pass the mode gate (flag/registry preconditions).
  2. Map BAR into process VA. 3. Program rings in loopback with attacker
  PFNs. 4. Read/write phys via descriptor completion → escalate.
- **Commands:**
  ```bash
  lspci -nn | grep -i -E 'realtek|ethernet'
  python3 dma_phys.py --pfns phys_list.txt --mode loopback --rw test
  ```
- **Pitfalls:** link must be UP for descriptor processing — set it before
  debugging rings; mapping IOCTLs often need a restart after first run
  (stale register state).
- **Sources:**
  https://github.com/catforgor/realtek-dma-poc
  https://github.com/xchglabs/Qemu-guest-to-host
