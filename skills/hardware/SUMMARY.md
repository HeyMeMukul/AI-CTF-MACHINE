# hardware SUMMARY (quickref)

Triage: `file`, `binwalk`, `binwalk -E`, `strings|grep uart|baud|squashfs|shadow`,
`ent` for entropy shape.

Extract: `binwalk -e firmware.bin` → `ls -R _*.extracted/` → secret sweep:
`grep -rEi 'password|secret|BEGIN.*PRIVATE|flag\{' _*.extracted/`.

Filesystems: `unsquashfs -s`, `unsquashfs -f -d /tmp/opencode/rootfs`,
`ubireader_list_images`; startup: `rcS|inittab|*.sh`, `etc/shadow`.

Crypto-in-fw: `yara -r rules/crypto_const.yar` (AES S-box `63 7C 77 7B…`,
inverse S-box, RSA `00 01 FF` pad); cut `dd` ±4KB → `/crypto` handoff.

Bootloader: `bootdelay|autoboot|bootcmd|U-Boot|signature OK|bad magic`;
interrupt → allowlist bypass → verify-gap → env injection, one gated cmd.

eFuse/OTP: config-word model only; snapshot before toggling; never blow
real fuses; record bit addr + pre/post.

Ghidra: find base first (`FLASH 0x08000000` STM32-class), Memory Map rebase,
then analyze. No-ELF default 0x0 breaks xrefs.

UART (live endpoint only): brute `115200→57600→38400→19200→9600`,
`picocom -b $b /dev/ttyUSB0`. JTAG: `openocd … 'init; scan_chain; exit'`
(EXTEST/SAMPLE/BYPASS/IDCODE; record TAPs + raw IDCODE hex).
Pins: UART TX/RX/GND; JTAG TCK/TMS/TDI/TDO; SPI SCK/MOSI/MISO/CS; I2C SCL/SDA.

SPI: needs CS column; `0x9F` JEDEC anchor, `0x03` read (addr+data),
`0x0B` fast-read; reassemble by addr before `binwalk`; `flashrom` dump
twice + `cmp` hashes.

Glitch: params offset/width/extent (+depth/phase); trigger-anchored coarse
grid → zoom at FAULT-OTHER borders; >200 blind trials = stop, static
NOP-the-check twin first. CPA: HW `HW(SBOX(pt^k))` / HD register model,
align (xcorr-shift) before correlate, per-byte MTD; partial key → crypto.

RTL: state-reg = `localparam` + `case(state)` in clocked always; backward
walk from flag state → sequence; TB loop reset→stimulus→monitor, polarity
check first; `gtkwave dump.vcd` confirm.

Captures: `sigrok-cli -i capture.sr -P uart:baudrate=115200 -A uart`, else
CSV sketch. Traces (`*.npy`): CPA Hamming-weight correlation, offline only.

RTL: read FSM states first, `iverilog -o sim.out top.v tb.v && vvp sim.out`,
`gtkwave dump.vcd`.

Gates: 1 Baseline → 2 Confirmation (`-Me` depth-capped) → 3 Negative
(encrypted? live-HW? traces?) → 4 ONE gated step ≤120s → 5 validate +
`results/hw_<id>/` bundle.

Dead-end pivots: service binary → web/pwn; crypto blob → crypto skill.
Local-only for creds/keys; never paste flags into hosted models.

Failures: F1 base→string-xref rebase; F2 baud→brute+autodetect; F3 FS→
squashfs→ubifs→jffs2 order; F4 glitch→widen once→static; F5 sim→reset
polarity; F6 header-strip→decryptor hunt; F7 JTAG-lock→SPI/static. 1 retry
+ 1 alternate → `blocked`.

Drift: record `ghidra/openocd/sigrok/binwalk/yara/iverilog --version`;
Ghidra notes (base+script, no `.gpr`); openocd `-f` pair; sigrok `-P` list.

Tiers: easy ≤20min (extract only) / medium ≤1h (1 gated step) / hard ≤3h
(≤3 branches, ~45min each, ≤200 glitch trials) / insane → escalate at 3h.
Escalate: ELF→`/rev`; blob/key→`/crypto`; banner→web/pwn; live pins or
fuse→operator gate; >3h/conflict→Lead with `results/hw_<id>/` bundle.

Chains: fw→extract→rebase→key→crypto; capture→decode→console→secret;
RTL→sim→sequence→unlock. Extraction solves ~80%; glitch stays conceptual
unless traces/simulator shipped.

Writeup-mined (W1..W32, see SKILL.md index + techniques/writeup-patterns-1.md):
ESP32 quad-boot via espressif-QEMU; U-Boot passphrase-adjacency + `md.b`
dump; Unicorn decrypt-emu + `vmlinux-to-elf`; ECP5 prjtrellis→yosys→UART
harness; TEA adder-pair + round-key brute; `.sal`/`.sr` baud-lock decode;
BLE GATT replay; MIFARE nested+UID-spoof; SFDP-hidden partition; JTAG
IR/DR unlock loop; glitch-lab dialog; DPA-means→CPA→template ladder;
on-device-ADC CPA; OT `.sal`+pcap cross-check. Manifest: 411 entries.
R2 (W33..W64, index + techniques/writeup-patterns-r2-{1,2,3}.md): ESP32-seg-overwrite/C3-C6-FI/V3-CRC-PC/RP2350-5way; OP-TEE ladder/TA-BOF/kernel-UAF/Open-TEE-confusion; QEMU-MMIO-OOB/DMA-reentrancy/NIC-DMA; SMM-ROP/NVRAM-2call/LogoFAIL/BMC-Redfish; JavaCard-timing/PhiAttack/GP-enum; PUF-ladder/XOR-boundary/TRNG-EM/CW-course; EMFI-bench/laser-SRAM/TMDS-TEMPEST; CAN-UDS/LoRa-Meshtastic/newFPGA-HAL; USB-HID/SPI-rewrite/I2C-dual/BLE-fuzz. Manifest R2: 445 entries.
