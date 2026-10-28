---
name: hardware
description: Hardware, embedded, firmware, UART/JTAG, side-channel, fault-injection, and RTL CTF triage to exploit
category: hardware
phase: 1-3
---
Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`; separate evidence from inference, preserve scope, validate each link, and label uncertainty.

# Hardware / Embedded / Firmware Skill

## Mental Model

Firmware CTFs are file-format puzzles wearing a hardware costume. The
flag path is almost always one of five shapes:

1. **Secret in the image** — hardcoded credential, key, or flag string left
   in squashfs/ubifs, NVRAM defaults, or a debug script. Solved by extraction,
   not by hardware.
2. **Service on emulated device** — web/telnet shell reachable after
   extracting the root filesystem. Pivot to `web-ctf` / `pwn` skills.
3. **Protocol capture** — UART/SPI/I2C dump, logic-analyzer CSV, or Saleae
   capture to decode into bytes.
4. **Crypto constant in firmware** — AES/DES/RSA constants compiled into a
   binary; extract the blob and attack the crypto, not the board.
5. **RTL / Verilog puzzle** — an FSM or netlist file where the flag is a
   reachable state; solved by reading + simulating, not by soldering.

Default hypothesis order: static extraction first, dynamic emulation second,
protocol decode third, side-channel/fault theory last. Real glitching almost
never appears in remote CTFs; when it does, the challenge ships traces or a
simulator, so the work is analysis of data, not bench hardware.

Key abstractions: a firmware image is bootloader + kernel + filesystem(s);
`binwalk` finds boundaries, entropy separates compressed/encrypted regions
from plain. UART = async serial (TX/RX/GND); JTAG = sync debug
(TCK/TMS/TDI/TDO); SPI/I2C = clock + data buses — in CTFs you decode
captures, rarely touch pins. Side-channel = secret-dependent leakage
(power/timing/EM); fault injection = perturbing execution (voltage/clock
glitch) to skip a check — know both to classify traces/simulators, not to
run a bench. Verilog flags hide behind FSM states; compile with `iverilog`.

Scope guard: technique-only, read-only first. No real flags/addresses.
Emulation (firmadyne concept) is informational; never attack hardware
you do not own.

## Workflow

### Phase 1 — Baseline (read-only triage, ≤120s)

Goal: identify image type, ISA, and fastest secret path.

Steps:

1. Record size, hash, `file` output; signature + entropy scans (read-only).
2. `strings` sweep for UART hints, credentials, flag-format markers.
3. Check for Verilog (`*.v`), VCD/CSV captures, or ELF binaries (route:
   RTL vs firmware vs protocol vs crypto-blob).
4. Note: compression? encrypted region? Linux paths? bootloader strings?

Commands (all read-only):

```bash
file firmware.bin
sha256sum firmware.bin; ls -la firmware.bin
binwalk firmware.bin
binwalk -E firmware.bin
strings -n 8 firmware.bin | grep -Ei -m 30 'uart|baud|console=|ttyS|ttyAMA|uboot|u-boot|squashfs|ubifs|cramfs|/etc/(passwd|shadow)|admin|password|aes|des|rsa|private key|BEGIN.*KEY'
strings -n 8 firmware.bin | grep -E -m 10 'flag\{|FLAG|CTF\{|picoCTF|HTB\{'
ent firmware.bin
ls -la given/
file given/*
```

Verilog / capture branch:

```bash
file top.v capture.csv capture.sr 2>/dev/null
head -n 30 top.v 2>/dev/null; head -n 10 capture.csv 2>/dev/null
xxd firmware.bin | head -n 10
```

`Reasoning Checkpoint`: image type + entropy shape + strings evidence →
route (extract filesystem vs decode capture vs read RTL vs crypto-constant
hunt) → next phase input.

### Phase 2 — Confirmation (bounded extraction + identification)

Goal: confirm the filesystem / protocol / RTL structure with one bounded
extraction pass.

Steps:

1. Extract with `binwalk -e` (or `-Me` depth-capped); list tree, name the
   filesystem (squashfs/ubifs/jffs2/cpio/ext).
2. Firmwalker-style secret sweep (keys, passwords, scripts).
3. Extraction fails + entropy ~8.0 everywhere → encrypted branch: find the
   decryptor (update script, header key, companion ELF).
4. Captures: confirm protocol (UART 8N1 vs SPI vs I2C) from timing/columns.

```bash
binwalk -e firmware.bin
binwalk -Me firmware.bin
ls -R _firmware.bin.extracted/ 2>/dev/null | head -n 60
grep -rEi -m 40 'password|secret|api[_-]?key|flag\{|BEGIN.*PRIVATE' _firmware.bin.extracted/ 2>/dev/null
grep -rEi -m 15 'baud|115200|console|ttyS|telnetd|dropbear' _firmware.bin.extracted/ 2>/dev/null
find _firmware.bin.extracted/ -name '*.sh' -o -name 'rcS' -o -name 'inittab' 2>/dev/null | head -n 10
cat _firmware.bin.extracted/squashfs-root/etc/shadow 2>/dev/null
fdisk -l firmware.bin 2>/dev/null | head -n 10
```

`Reasoning Checkpoint`: extracted tree (or failure mode) + secret-grep hits +
protocol confirmation → proceed to negative testing or exploit branch.

### Phase 3 — Negative (rule out rabbit holes before burning time)

Goal: explicitly kill dead ends before burning time.

1. **Encrypted?** Entropy ~8.0 + no signatures → stop re-running binwalk;
   hunt the decryptor (companion ELF, update script, header key).
2. **Live hardware?** `.bin` only, no endpoint/traces → pinout work out of
   scope; stay static.
3. **Side-channel?** No `.npy`/`.csv` traces or timing oracle → skip CPA
   tooling. Verilog must compile (`iverilog`) before FSM theory.

```bash
ent firmware.bin | head -n 8
ls *.npy *.csv *.sr *.vcd *.v 2>/dev/null
iverilog -o sim.out top.v tb.v 2>&1 | head -n 15
yara -r rules/crypto_const.yar firmware.bin 2>&1 | head -n 10
strings -n 6 firmware.bin | grep -Ei -m 5 '0x[48]0[0-9a-f]{5,}|flash|ram'
```

`Reasoning Checkpoint`: which branches are dead (encrypted / live-HW /
side-channel / broken-RTL) with one line of evidence each → single live
hypothesis into gated exploit.

### Phase 4 — Exploit (GATED: one step, ≤120s, reversible)

Gate: proceed only with a confirmed target (file path, function, signal,
or FSM state). One bounded action, then stop and evaluate. Never parallelize
live-service interaction or shared-state writes.

Pick exactly ONE:

**A. Filesystem secret pull (most common):**

```bash
cat _firmware.bin.extracted/squashfs-root/etc/shadow 2>/dev/null
grep -rEi -m 10 'flag' _firmware.bin.extracted/squashfs-root/ 2>/dev/null
```

**B. UART baud brute (only with a live serial endpoint + authorization):**

```bash
for b in 115200 57600 38400 19200 9600; do echo "=== $b ==="; timeout 5 picocom -b $b /dev/ttyUSB0 2>&1 | head -n 5; done
```

**C. JTAG/OpenOCD probe (authorized bench only):**

```bash
openocd -f interface/ftdi.cfg -f target/stm32f1x.cfg -c 'init; scan_chain; exit' 2>&1 | head -n 20
```

**D. RTL simulation to flag state (offline, safe):**

```bash
iverilog -o sim.out top.v tb.v && vvp sim.out | head -n 30
```

**E. Crypto-constant cut-out (offline):**

```bash
python3 cut_aes_blob.py firmware.bin --sbox-offset 0x1234 --out blob.bin
```

Stop condition: one artifact (credential file, console banner, simulation
flag-state print, or crypto blob). If it fails, do ONE corrected retry,
then ONE alternate method, then mark `blocked` and continue elsewhere.

`Reasoning Checkpoint`: gated action + observed output + flag-path verdict
(success → validation; fail → retry/alternate/blocked).

### Phase 5 — Validation-handoff (prove it, package it)

Goal: confirmit is the flag path and hand a reproducible bundle to Lead.

Steps:

1. Re-verify the artifact (credential works / console banner captured /
   simulation reaches flag state deterministically).
2. Record exact byte offset or file path + extraction command that
   reproduces it.
3. Note base address used for any Ghidra work, baud rate for UART, or
   top-module + stimulus for Verilog.
4. Write finding to `results/` with tool versions; never paste real flags
   into hosted models (local-only per policy).

Commands:

```bash
echo "artifact: <path:offset>" > results/hardware_finding.txt
binwalk firmware.bin > results/binwalk_scan.txt
sha256sum firmware.bin >> results/hardware_finding.txt
```

`Reasoning Checkpoint`: evidence → reproducible steps → handoff (finding
file + next skill if pivot needed, e.g. web/pwn/crypto).

## Tool Table (exact copy-paste commands)

| Task | Command |
|---|---|
| Signature scan | `binwalk firmware.bin` |
| Extract (recursive: `-Me`) | `binwalk -e firmware.bin` |
| Entropy graph / numbers | `binwalk -E firmware.bin; ent firmware.bin` |
| File type | `file firmware.bin` |
| Strings + UART hints | `strings -n 8 firmware.bin \| grep -Ei -m 30 'uart\|baud\|console=\|ttyS\|squashfs\|ubifs'` |
| Flag-string sweep | `strings -n 8 firmware.bin \| grep -E -m 10 'flag\{|FLAG\|CTF\{'` |
| Filesystem secret sweep | `grep -rEi -m 40 'password\|secret\|api[_-]?key\|BEGIN.*PRIVATE' _firmware.bin.extracted/` |
| Startup scripts | `find _firmware.bin.extracted/ -name '*.sh' -o -name 'rcS' -o -name 'inittab' \| head` |
| Squashfs info / extract | `unsquashfs -s squashfs-root; unsquashfs -f -d /tmp/opencode/rootfs squashfs-root` |
| Strings on ELF in fw | `strings -n 8 extracted.elf \| grep -Ei -m 20 'flag\|password\|key'` |
| YARA crypto scan | `yara -r rules/crypto_const.yar firmware.bin` |
| Serial brute sketch | `for b in 9600 19200 38400 57600 115200; do timeout 5 picocom -b $b /dev/ttyUSB0; done` |
| OpenOCD scan | `openocd -f interface/ftdi.cfg -f target/stm32f1x.cfg -c 'init; scan_chain; exit'` |
| Sigrok UART decode | `sigrok-cli -i capture.sr -P uart:baudrate=115200 -A uart` |
| Verilog compile | `iverilog -o sim.out top.v tb.v && vvp sim.out` |
| Waveform view | `gtkwave dump.vcd` |
| Hex head | `xxd firmware.bin \| head -n 20` |
| Hash + size | `sha256sum firmware.bin; ls -la firmware.bin` |

Firmwalker concept: heuristic secret sweep over the extracted tree
(passwords, keys, startup scripts, SUID files) — the `grep`/`find` rows
above are its working equivalent. Firmadyne concept: full-system Linux
emulation for dynamic testing; informational in CTFs — static extraction
solves faster, emulate only if a network service must be reached.

## Code / Payload Library

### 1. UART baud brute sketch (authorized serial only)

```python
import serial, sys
port = sys.argv[1] if len(sys.argv) > 1 else "/dev/ttyUSB0"
for baud in [115200, 57600, 38400, 19200, 9600]:
    try:
        s = serial.Serial(port, baud, timeout=2); s.write(b"\n")
        print(f"--- {baud}: {s.read(200)!r}"); s.close()
    except Exception as e: print(f"--- {baud}: error {e}")
```

### 2. Crypto-constant YARA sketch (AES S-box + DES tables)

```yara
rule aes_sbox {
    strings:
        $sbox = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }
    condition:
        $sbox
}
rule des_ip {
    strings:
        $ip = { 3A 32 2E 0A 06 0A 1A 02 0E 02 1C 06 3E 0A 26 0E }
    condition:
        $ip
}
```

Run: `yara -r rules/crypto_const.yar firmware.bin`

### 3. Logic-analyzer CSV UART quick-check

```python
import csv
rows = list(csv.DictReader(open("capture.csv")))
print(f"samples={len(rows)} cols={list(rows[0].keys()) if rows else None}")
print("transitions=", sum(1 for a, b in zip(rows, rows[1:]) if a != b))
# Prefer sigrok-cli -P uart for .sr files; use this only for raw CSV framing checks.
```

### 4. Power-trace AES correlation + timing concept (offline traces only)

```python
import numpy as np
SBOX = [...]  # 256-entry AES S-box
def hw(x): return bin(x).count("1")
traces = np.load("traces.npy"); pts = np.load("plaintexts.npy")
best = max(((k, max(abs(np.corrcoef([hw(SBOX[p ^ k]) for p in pts[:, 0]], traces[:, t])[0, 1])
    for t in range(traces.shape[1]))) for k in range(256)), key=lambda kv: kv[1])
print("best key byte guess:", best)
# Correct guess maximizes HW correlation (timing twin: early-exit compare leaks one byte at a time).
```

### 5. Fault-injection concept (simulators, not benches)

Voltage glitch (VCC dip at `CMP/BEQ`) or clock glitch (short edge →
skipped fetch) flips an auth decision. CTF form is a Python simulator
with `delay/width` knobs — fuzz those; Ghidra NOP-the-check is the
static twin.

### 6. Verilog FSM testbench sketch

```verilog
// tb.v — drive reset, then stimulus, watch for flag_state
`timescale 1ns/1ps
module tb;
  reg clk = 0, rst = 1; reg [7:0] din = 0; wire unlocked;
  top dut(.clk(clk), .rst(rst), .din(din), .unlocked(unlocked));
  always #5 clk = ~clk;
  initial begin
    $dumpfile("dump.vcd"); $dumpvars(0, tb);
    #20 rst = 0; din = 8'h41; #10; din = 8'h42; #10;
    $display("unlocked=%b", unlocked); $finish;
  end
endmodule
```

```bash
iverilog -o sim.out top.v tb.v && vvp sim.out
```

Read the FSM first: list states (`localparam`), find which asserts the
flag/unlock output, trace transitions backward to inputs.

### 7. JTAGulator concept

JTAGulator automates pin-discovery (IDCODE scan for JTAG, baud/TX detect
for UART) — replicate the sweep in software against a simulator/netlist puzzle.

### 8. EEPROM dump parser sketch

```python
data = open("eeprom.bin", "rb").read()
runs, cur = [], b""
for b in data:
    if 32 <= b < 127: cur += bytes([b])
    elif len(cur) >= 8: runs.append(cur); cur = b""
print(b"\n".join(runs[:40]))
# TLV heuristic: [tag len value...]
i = 0
while i + 2 < len(data):
    tag, ln = data[i], data[i+1]
    if 0 < ln <= 64 and i + 2 + ln <= len(data):
        print(f"off={i:#x} tag={tag:#x} val={data[i+2:i+2+ln]!r}"); i += 2 + ln
    else: i += 1
```

### 9. Ghidra firmware rebase notes

No ELF headers → Ghidra loads at 0x0 and xrefs break. Find base from
datasheet strings or pointer runs (`0x08xxxxxx` ⇒ STM32-class `0x08000000`):
`Window → Memory Map → Set Base`, then re-run analysis.

## Decision Tree

```text
file says data + binwalk hits?
  YES -> binwalk -e -> squashfs/ubifs tree?
    secrets found -> VALIDATE (Phase 5)
    service binary (httpd/telnetd) -> pivot web-ctf/pwn
    no tree -> encrypted? -> find decryptor ELF/script
  NO stable signatures?
    high entropy everywhere -> encrypted branch (header key? companion tool?)
    *.v / tb present -> read FSM -> iverilog simulate
    *.csv/*.sr/*.vcd present -> sigrok decode (uart/spi/i2c?)
    *.npy traces present -> CPA/timing sketch (offline)
    ELF with crypto constants -> YARA + cut blob -> crypto skill
    strings show /dev/ttyS baud -> UART note (live endpoint only)
```

Common pinouts (verify vs challenge docs; never probe live HW unauthorized):
UART TX/RX/GND (8N1, idles high) · JTAG TCK/TMS/TDI/TDO/GND · SWD SWDIO/SWCLK/GND · SPI SCK/MOSI/MISO/CS/GND · I2C SCL/SDA/GND. Baud: 115200 → 57600 → 38400 → 19200 → 9600.

## AI Automation Notes

- ONE worker per image (shared `_*.extracted/` dir; never parallelize
  writes). Loop: scan → extract → secret-grep → (secret? validate : one
  pivot). Cap: `-e` then `-Me` depth 3, then stop. Template matrix for strings: `uart|baud|console|tty|ubi|squash|shadow|
  passwd|BEGIN.*KEY|aes|des|rsa` × `{strings, grep -r on tree, yara}`.
  Diff hits vs empty; empty + high entropy = encrypted branch.
- Auto-classifier snippet:

```bash
if binwalk firmware.bin | grep -qi 'squashfs\|ubifs\|cramfs\|gzip\|lzma'; then echo ROUTE=extract;
elif ls *.v 2>/dev/null | grep -q .; then echo ROUTE=rtl;
elif ls *.sr *.csv *.vcd 2>/dev/null | grep -q .; then echo ROUTE=protocol;
elif ls *.npy 2>/dev/null | grep -q .; then echo ROUTE=sidechannel; else echo ROUTE=crypto-constants; fi
```

- Artifact paths unique per task (`results/hw_<chalid>/`). Stop: secret
  found, banner decoded, FSM flag state, or 3 failed methods → `blocked`.
- OPSEC: local-only for images with real creds; never paste keys/flags
  into hosted models.

## Advanced / Hard-Challenge Playbook

Hard hardware CTFs chain 2-4 primitives. This playbook covers the
theory you need when Phase 2-3 routing points at glitch / side-channel /
JTAG / SPI / Verilog / crypto-constant / bootloader targets. All work is
offline (traces, captures, images, HDL) unless an authorized bench gate
has passed. Technique-only; no real flag values.

### A1. Glitching theory (voltage / clock)

Goal: skip or corrupt one security-critical operation (password compare
early-exit, signature-check branch, loop-counter increment, firmware
auth `BEQ/BNE`).

- **Voltage glitch:** brief VCC dip at target window (too shallow = no
  effect; too deep = reset/hang; knobs = depth + duration).
- **Clock glitch:** one short cycle → skipped/mis-decoded fetch (knobs =
  edge timing + pulse width).
- **EM glitch (concept):** localized pulse; same logic + spatial (X/Y +
  power) — in CTFs a simulator with X/Y knobs, not a bench probe.
- Where it applies in CTFs: Python fault simulators with
  `delay/width` knobs, ChipWhisperer-style trace+glitch bundles, or a
  `check-then-unlock` ELF extracted from firmware. Static twin is always
  Ghidra NOP-the-check; try it first (seconds) before any glitch search.

Glitch parameters (use these exact names so retries are comparable):
**offset** (delay from trigger to glitch onset), **width** (pulse
duration), **extent/count** (cycles covered; repeat count for loop-abort),
plus optional **depth** (mV below nominal), **phase** (clock edge),
**cooldown** (reset delay).

Search strategy (bounded, offline-first): anchor a stable trigger first
(serial char, GPIO, simulator call — no trigger = stop). Coarse grid:
`offset` in 10-20 large steps, `width` at 2-3 values; classify every shot
as `OK / RESET / HANG / FAULT-OTHER / TARGET-FAULT`. Zoom only around
`FAULT-OTHER` borders (halve step twice max, one parameter at a time).
Stop: no `FAULT-OTHER` after full grid → widen `width` once, then pivot.

```bash
# Abstract glitch-sweep log shape (simulator or ChipWhisperer-style rig)
python3 glitch_sweep.py --trigger serial-tx --offset-start 0 --offset-stop 5000 --offset-step 250 --widths 5,10,20 --trials 3 --log results/hw_<id>/glitch_grid.csv
```

### A2. CPA / DPA basics (Hamming-weight model, ChipWhisperer concept, alignment)

Use when the challenge ships power/EM traces (`*.npy`, `*.csv`,
ChipWhisperer-style bundles) plus known plaintexts/ciphertexts.

- **Leakage model:** CMOS power correlates with bits that flip or are
  held. Two standard models:
  - Hamming weight (HW): `HW(SBOX(pt ^ k_guess))` — best for software
    AES (value loaded onto a bus).
  - Hamming distance (HD): `HD(prev_state, next_state)` — best for
    hardware registers (9th→10th round overwrite in AES).
- **CPA in one paragraph:** for each key-byte guess `k` (0-255),
  predict the intermediate (`SBOX(pt ^ k)`), map through HW/HD, then
  Pearson-correlate the prediction vector against every time sample
  across N traces. The guess with the highest peak correlation is the
  key-byte candidate. DPA is the older difference-of-means twin (split
  traces by one predicted bit, subtract means); CPA subsumes it but
  DPA is cheaper to sanity-check.
- **ChipWhisperer concept:** open capture + analysis stack (board +
  target + Python API). In CTFs reuse its concepts: sync sampling clock,
  trigger on crypto-start, fixed-vs-random sets, `(n_traces, n_samples)`
  `.npy` layout. Never buy the board mid-event.
- **Trace alignment (where hard challenges are won/lost):** jitter kills
  naive CPA. Pipeline: plot mean+stddev (rounds = repeated humps) →
  cross-correlate each trace to a reference and integer-shift → elastic
  resync only if needed (never low-pass before aligning) → re-plot
  variance (sharp peaks = aligned).
- **Measurements-to-disclosure (MTD):** traces until the correct subkey
  rank stays #1. Track per-byte MTD; partial recovery still routes to
  `/crypto` for completion. Tuning core = Code Library entry 4.

```bash
python3 -c "import numpy as np; t=np.load('traces.npy'); p=np.load('plaintexts.npy'); print(t.shape, p.shape)"
python3 cpa_quick.py --traces traces.npy --pts plaintexts.npy --model hw --byte 0 --plot results/hw_<id>/cpa_byte0.png
# Core loop = Code Library entry 4 (HW prediction + per-sample Pearson max).
```

### A3. JTAG boundary-scan (EXTEST / SAMPLE, openocd tap discovery)

Use when given: JTAG capture, SVF/XSVF file, tap IDs, or an authorized
bench with a debug header.

- **Concepts:** JTAG (IEEE 1149.1) shifts IR then DR through a TAP
  (TCK/TMS/TDI/TDO): `BYPASS` (chain-length), `IDCODE` (tap ID),
  `SAMPLE/PRELOAD` (snapshot), `EXTEST` (drive; bench only),
  `INTEST/DEBUG` (halt + reg read).
- **Tap discovery:** `openocd -f interface/... -f target/... -c 'init;
  scan_chain; exit'` enumerates TAPs + IDCODEs. Unknown chain → one TAP
  at a time, then two-TAP with `EXPECTED-ID` disabled. SVF via
  `svf <file> -tap <tapname> -quiet`.
- **Record:** full `scan_chain` output, adapter+target `.cfg` names +
  versions, halting TAP. IDCODE: document raw hex (low 12 mfr, next 16
  part, top 4 rev); never guess silicon.

```bash
openocd -f interface/ftdi.cfg -f target/stm32f1x.cfg -c 'init; scan_chain; exit' 2>&1 | tee results/hw_<id>/scan_chain.txt
# Halt + sanity read (authorized bench only):
# telnet localhost 4444 -> 'halt; mdw 0x08000000 16; dump_image fw_dump.bin 0x08000000 0x100000'
```

### A4. SPI flash parsing (opcode 0x03 reads, JEDEC ID)

Use when given: SOIC-8 dump, logic capture with SCK/MOSI/MISO/CS, or a
`flashrom`-style directory.

- **Wire facts:** SCK + MOSI + MISO + CS (active-low frame). Captures
  MUST include CS or boundaries are unrecoverable. **Opcodes** (MOSI first
  byte after CS falls): `0x9F` JEDEC ID → 3-byte response (anchor here);
  `0x03` read (addr + data); `0x0B` fast read (+dummy); `0x06`/`0x02`
  write-enable/page-program; `0xD8`/`0x20` erase; `0x05` status.
- **Parsing loop:** split by CS → opcode → if `0x03`, next 3 bytes =
  big-endian addr, rest = data. Reassemble sparse reads by address, then
  `binwalk`. **JEDEC:** record all 3 raw bytes; capacity = `2^N` bytes.

```bash
flashrom -p ch341a_spi -r dump1.bin 2>&1 | tee results/hw_<id>/flashrom_probe.txt
sha256sum dump1.bin; flashrom -p ch341a_spi -r dump2.bin 2>&1 | tail -n 3; sha256sum dump2.bin
cmp dump1.bin dump2.bin && echo DUMPS-MATCH || echo DUMPS-DIFFER-RESAT-CLIP
binwalk dump1.bin | tee results/hw_<id>/binwalk_spi.txt
sigrok-cli -i spi_capture.sr -P spi:mosi=MOSI:miso=MISO:sck=SCK:cs=CS -A spi 2>&1 | head -n 40
```

```python
# Opcode 0x03 reassembly (CS-split frames as (mosi, miso) byte strings)
def reassemble(frames):
    img = {}
    for mosi, miso in frames:
        if not mosi or mosi[0] == 0x9F: print(f"JEDEC: {bytes(miso[:3]).hex()}")
        elif mosi[0] in (0x03, 0x0B):
            off = 4 if mosi[0] == 0x03 else 5
            img[int.from_bytes(mosi[1:4], "big")] = bytes(miso[off:off+len(mosi)-off])
    return img
```

### A5. Verilog FSM reversing (state-register identification, iverilog loop)

Use when given `*.v` / `*.sv`, netlists, or VCD waveforms.

1. **Inventory:** top module, clk/rst names, input widths, unlock output.
2. **State-register ID:** `localparam` encodings + `case (state)` inside
   `always @(posedge clk)` — that register is the state register. List
   states + which asserts the flag output. 3. **Backward walk:** from the
   flag state read its guard and walk predecessors to reset → required
   input sequence, no brute force. 4. **iverilog loop:** reset → stimulus
   → monitor (polarity check first, then derived sequence, then nibble
   fuzz). Confirm with `gtkwave` that the state register visits the flag
   state. TB skeleton = Library 6.

```bash
grep -nE 'localparam|case *\(|always *@\(posedge|unlocked|flag_valid' top.v | head -n 40
iverilog -o sim.out top.v tb.v && vvp sim.out | tee results/hw_<id>/sim.log
```

### A6. Firmware crypto-key hunting (YARA rules for AES / RSA constants)

Use when Phase 1 strings show `aes|des|rsa|BEGIN.*KEY` but no filesystem
secret.

- **AES:** forward S-box `63 7C 77 7B F2 6B 6F C5 ...`, inverse S-box,
  Rcon. Hit + key-schedule xref = cut-out candidate. **DES:** IP/FP
  tables; **SHA2:** K-constants; **RSA:** high-entropy blob near
  `modulus|exponent` or `00 01 FF` PKCS#1 padding.
- **Method:** YARA hit → offset → `dd` ±4KB window → disassemble →
  confirm (require ≥2 tables or code xrefs; single 16B hits in compressed
  data are usually false positives). **Handoff:** blob + offset + type.

```bash
yara -r rules/crypto_const.yar firmware.bin | tee results/hw_<id>/yara_hits.txt
dd if=firmware.bin of=results/hw_<id>/blob.bin bs=1 skip=$((0x1234-4096)) count=8192
```

```yara
rule aes_sbox_full {
    strings: $sbox = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }
             $inv = { 52 09 6A D5 30 36 A5 38 BF 40 A3 9E 81 F3 D7 FB }
             $pad = { 00 01 FF FF FF FF FF FF }
    condition: 2 of them
}
```

### A7. Bootloader logic bugs

Bootloaders (U-Boot-style, UART menus, OTA updaters) are the densest
logic-bug surface. Hunt in order: **boot-delay interrupt** (`bootdelay`,
`autoboot` → shell with `md/mw/loady`); **allowlist bypass** (`?`,
`help all`, `;`, `${var}` in every field); **verify gap** (CRC-checked
but not signature-checked, or fail-open branch); **env injection**
(`bootcmd=` + writable NVRAM → hijack). Record banner + prompt first.

```bash
strings -n 6 firmware.bin | grep -Ei -m 20 'bootdelay|autoboot|bootcmd|bootargs|U-Boot|press any key|signature OK|bad magic|CRC OK|verify'
```

### A8. eFuse / OTP concept

- **What:** one-time-programmable bits (secure-boot, debug-lock, key
  slots). Blown = permanent. CTFs model as config word / JSON field /
  `SECURE_BOOT` parameter — never a live fuse to blow.
- **Shapes:** `SECURE_BOOT=0` default → flip in emulation; key-slot
  `LOCKED` bit → simulator ordering bug reads before lock; inverted
  `if (otp_debug_lock)` check skipped under glitch. Snapshot before
  toggling; record bit addr + pre/post values.

## Multi-Step Chains (abstract patterns)

Hard challenges never end at extraction. Use these chains as templates;
substitute the challenge's actual paths/offsets.

### Chain 1 — firmware → extract → Ghidra rebase → key → crypto handoff

1. `binwalk -Me` yields a filesystem + one service ELF (e.g. an update
   verifier). Secret-grep is empty → route to binary.
2. `file` gives ISA; raw flash cut-outs load at `0x0`. Find base from
   pointer runs (`0x08xxxxxx` → STM32-class `0x08000000`) or `FLASH/RAM`
   strings, rebase in Ghidra (`Memory Map`), re-analyze, confirm xrefs.
3. YARA S-box hit → xref to key-schedule → extract key from `.rodata`
   or stack-init blob. 4. Hand blob + offset + cipher guess to `/crypto`.
   Record: image hash, base, function, blob offset, rule name.

### Chain 2 — logic-capture → UART/SPI decode → console → secret

1. Given `.sr`/`.csv` + no filesystem: confirm protocol from timing
   (async 8N1 = UART; CS-framed groups = SPI; 9-bit addr+data = I2C).
   Require CS for SPI; idle-high + start-bit for UART.
2. `sigrok-cli -P uart:baudrate=<b>` per baud (or `-P spi/...`); correct
   baud gives printable runs + `console=/login:` markers.
3. Transcript → credentials / bootloader menu → Chain 1 (firmware too)
   or `web-ctf`/`pwn` pivot (service banner). Save raw + decoded in
   `results/hw_<id>/`.

### Chain 3 — RTL → sim → unlock-sequence → firmware unlock (hybrid)

1. Verilog FSM guards a keypad/code input; state graph yields the
   unlock sequence (Section A5 backward walk).
2. Simulate to confirm (`vvp` prints unlock). That sequence is then a
   credential for a firmware console or a glitch-trigger value in a
   companion simulator. Never brute-force the sequence live; derive it
   from the graph, confirm once in sim, use once at the gated step.

`Reasoning Checkpoint` (chains): each hop names its artifact
(tree path / base address / baud / state path) → next hop or handoff
skill (`/rev` for binaries, `/crypto` for blobs, `web-ctf`/`pwn` for
services).

## Failure-Mode Catalog + Recovery

| # | Failure (detection) | Recovery (one corrected retry + alternate) |
|---|---|---|
| F1 | Wrong base address in Ghidra: imports red, string xrefs dead, functions at `0x0`-relative. Detection: <5% string xrefs resolve. | String-xref rebase: harvest pointer-table runs (`0x08xxxxxx`/`0x00xxxxxx`), guess vendor base, `Memory Map → Set Base`, re-analyze, re-check xref %. One retry per base; alternate: `ghidra_rebase.py` script loop over 2 candidate bases max. |
| F2 | Unknown baud: UART decode is gibberish at every tried rate. Detection: no printable runs >8 chars at any of 9600-115200. | Brute 9600→115200 + autodetect: loop `9600 19200 38400 57600 115200` via `sigrok-cli -P uart:baudrate=$b`, score printable ratio, keep best; alternate: measure narrowest bit interval from waveform → `baud ≈ 1/bit_time`. |
| F3 | Compressed FS unknown: `binwalk -e` yields blobs but no mountable tree. Detection: `ls _*.extracted/` has `.gz/.lzma` chunks, no `squashfs-root`. | Try `squashfs → ubifs → jffs2 → cpio/ext` in order: `unsquashfs`, `ubireader_extract_images` + `ubidump`, `jefferson`, `binwalk -Me` depth-capped; stop after ordered pass, then encrypted branch. |
| F4 | Glitch no-effect: full coarse grid returns only `OK` (no RESET/HANG/FAULT). Detection: outcome histogram has 1 class. | Widen search grid once: double `width` range + extend `offset` window past trigger edge; confirm trigger actually fires (scope/log). Alternate: abandon bench, Ghidra NOP-the-check static twin. |
| F5 | Verilog sim mismatch: sim hangs in reset or outputs `x`. Detection: `$monitor` shows `state=xx` or never leaves reset. | Check reset polarity first (`rst=0` vs `rst=1` release), then clock connectivity (`always #5 clk`), then timescale/`$dumpvars` scope. One polarity flip retry; alternate: minimal TB driving only clk+rst to isolate DUT. |
| F6 | Encrypted-looks-compressed: entropy ~8.0 but actually zlib/lzma with no magic due to header strip. Detection: `binwalk -E` flat-high + `strings` has `inflate/deflate/lzma` nearby. | Try `binwalk --opcodes`, `firmware-mod-kit` unsquash variants, and header-prepend carve (`dd` window → prepend `hsqs`/`gzip` magic test is last resort, bounded to one window). Alternate: hunt decryptor ELF per Phase 3. |
| F7 | JTAG locked / no TAP: `scan_chain` empty or `IR capture error`. Detection: openocd exits with `TAP communication error`. | Re-check wiring/config drift (Section Version-Drift), try reduced clock (`adapter speed 100`), one TAP at a time; alternate: declare locked, pivot to SPI-dump or static-only route. |

General rule: each failure gets exactly one corrected retry plus one
alternate method, then `blocked` for that branch. Never loop a failing
branch more than twice; switch branches (extract ↔ decode ↔ RTL ↔
crypto-constants).

## Version-Drift Guards

- **Ghidra upgrades** invalidate `.gpr` caches — keep import script +
  base in `results/hw_<id>/ghidra_notes.txt` (`import → set base →
  auto-analyze`); note version per finding. Never commit `.gpr`.
- **openocd drift:** `.cfg` names move (`interface/ftdi.cfg` vs
  `interface/ftdi/...`). Record `openocd --version` + full `-f` paths;
  pin working pair in `openocd_cmd.txt`; re-run `scan_chain` after upgrades.
- **sigrok drift:** decoder options change (`uart:baudrate=` vs `baud=`).
  Record `--version` + `-P` list; probe `-P uart -A uart` help first;
  fall back to CSV sketch (Library 3) if the `.sr` driver is missing.
- **General:** `binwalk`, `yara`, `iverilog`, `flashrom` versions go in
  every `results/hw_<id>/finding.txt` header (`tool --version` one-liners).
  If a command from this skill errors with `unknown option`, run the
  `--help` variant first and adapt — never force-install mid-CTF
  without Lead approval.

```bash
ghidra --version 2>&1 | head -n 2; openocd --version 2>&1 | head -n 2
sigrok-cli --version 2>&1 | head -n 2; binwalk --version 2>&1 | head -n 2
yara --version 2>&1 | head -n 2; iverilog -V 2>&1 | head -n 2
```

## Time-Budget Tiers

| Tier | Budget | Scope | Stop rule |
|---|---|---|---|
| Easy | ≤20 min | Strings + `binwalk -e` + secret-grep only. | Secret or banner found → validate; else route (never open sim/glitch tooling). |
| Medium | ≤1 h | + recursive extract, YARA sweep, one capture decode or one TB sim. | One gated exploit attempt; fail → one retry + one alternate, then `blocked` + handoff. |
| Hard | ≤3 h | + full playbook: rebase+Ghidra, CPA alignment, JTAG/SPI parse, FSM backward walk, bootloader review. | Max 3 branches; per-branch cap ~45 min; no blind glitch sweeps >200 trials. |
| Insane | escalate | Beyond 3 h or needs bench hardware / >10k-trace CPA / netlist-scale REV. | Stop solo work at 3 h; package partials (blobs, transcripts, state graphs) and escalate to Lead for `/rev`+`/crypto` split or operator gate. |

- Start a visible timer per task; log phase transitions in
  `results/hw_<id>/timeline.txt` (`date +%H:%M:%S` + phase name).
- Easy/medium never touch voltage/clock benches or eFuse toggles.
- Hard may use simulators + authorized benches only; insane always
  requires Lead sign-off before any physical interaction.
- Any tier: 3 failed methods on one branch → `blocked`, switch branch
  or hand off. No sunk-cost loops.

## Escalation Triggers

- **→ `/rev` (firmware binary):** extracted ELF with stripped crypto,
  bootloader verification routine, or update-parser bug. Package: ELF
  path + ISA + base address + YARA hits + target function strings.
- **→ `/crypto` (extracted keys/ciphers):** cut-out blob with S-box /
  RSA constants, partial CPA key (≥4 bytes with MTD notes), or OTA
  ciphertext + nonce. Package: blob file + offset + cipher guess +
  plaintext/ciphertext pairs if any.
- **→ `web-ctf` / `pwn`:** emulated or live service banner (httpd /
  telnetd / dropbear) from extracted tree or decoded console. Package:
  banner text + port + creds (local-only) + startup script path.
- **→ operator (physical hardware gate):** any step needing live pins,
  fuse blows, high-voltage glitch, or disassembly of someone else's
  device. Hard gate: run the operator-ping helper with the exact need,
  keep solving unblocked offline work meanwhile. Never probe, power, or
  desolder without explicit authorization.
- **→ Lead (insane-tier):** >3 h spent, multi-branch chains with
  partials in ≥2 stages, or conflicting evidence (e.g. CPA says one key
  byte, static says another). Package: timeline + per-branch verdicts +
  `results/hw_<id>/` bundle.

## Worked End-to-End Example (abstracted, technique-only)

Scenario: a challenge ships one file named like `device_update.bin`
(placeholder name; substitute the real filename). No real flag values
appear anywhere below; `<flag-pattern>` denotes where a flag regex
would match.

1. **Baseline (2 min):** `file` says data; `binwalk` shows header +
   compressed region; `strings` shows `console=ttyS0` + U-Boot banner +
   AES-adjacent strings. Route: extract → bootloader → crypto-constant.
2. **Confirmation (8 min):** `binwalk -Me` yields tree + verifier ELF;
   secret-grep empty; `yara` fires AES S-box inside the ELF; startup
   script references the verifier.
3. **Negative (3 min):** `unsquashfs` succeeds → not encrypted. No
   `.npy` → skip CPA. No `.v`/`.sr` → skip RTL/protocol. Hypothesis:
   verifier ELF hides a key.
4. **Exploit, gated (10 min):** ISA via `file`; rebase if raw cut-out
   (A6/F1); xref S-box to key-schedule; `dd` window to `blob.bin`.
5. **Validation-handoff:** re-run `yara` on `blob.bin`; record hash, ELF
   path, base, offset, rule in `finding.txt`; hand blob to `/crypto`.
   Flag regex matches only on real solver output — never invented here.

This example uses generic placeholders (`device_update.bin`,
`results/hw_<id>/`, `<flag-pattern>`) precisely so it transfers to any
firmware challenge without leaking or inventing challenge-specific data.

## Writeup-Distilled Patterns (W1..W64)

Mined from `knowledge/writeups_mined/hardware_manifest.md` (411 verified
entries) + `hardware_manifest_r2.md` (445 verified entries, 0% overlap).
Technique-only; placeholders only, never real flag/key values.
Full detail for W13..W32 lives in `techniques/writeup-patterns-1.md`;
W33..W43 in `techniques/writeup-patterns-r2-1.md`, W44..W54 in
`techniques/writeup-patterns-r2-2.md`, W55..W64 in
`techniques/writeup-patterns-r2-3.md`.

| # | Pattern | Lives |
|---|---|---|
| W1 | ESP32 flashdump partition carve + QEMU-xtensa boot | SKILL.md |
| W2 | U-Boot passphrase-adjacency + `md.b` exfiltration | SKILL.md |
| W3 | Unicorn decrypt-emu + `vmlinux-to-elf` kernel twin | SKILL.md |
| W4 | Lattice ECP5 bitstream → Verilog → UART harness | SKILL.md |
| W5 | TEA-in-FPGA adder-pair ID + round-key brute | SKILL.md |
| W6 | PS/2-LED video side-channel via bitstream FSM | SKILL.md |
| W7 | SecureEEPROM I2C emulator abuse (attacker usercode) | SKILL.md |
| W8 | ATtiny85 USB-OTP token: simavr + USB trace | SKILL.md |
| W9 | Custom RISC-V/MMIO flag-device timing oracle | SKILL.md |
| W10 | STM32 GPIO-init RE + static/sim twin | SKILL.md |
| W11 | Saleae `.sal` Async-Serial baud hunt | SKILL.md |
| W12 | Sigrok `.sr` narrowest-pulse baud measure | SKILL.md |
| W13 | Gerber-layer flag rebuild | writeup-patterns-1.md |
| W14 | Waveform-letter transcription | writeup-patterns-1.md |
| W15 | BLE GATT handle-enum + write-replay | writeup-patterns-1.md |
| W16 | MIFARE nested/hardnested + UID-spoof + rewrite | writeup-patterns-1.md |
| W17 | DESFire SPI wiretap aligned to firmware | writeup-patterns-1.md |
| W18 | USB keystroke + CCID UID + AES-pipe decrypt | writeup-patterns-1.md |
| W19 | OOK burst demod via GRC twin pipelines | writeup-patterns-1.md |
| W20 | URH ASK split + sync-strip + ASCII recode | writeup-patterns-1.md |
| W21 | QPSK satellite Doppler-correct + beacon vote | writeup-patterns-1.md |
| W22 | JTAG IR/DR unlock-key + word-loop rebuild | writeup-patterns-1.md |
| W23 | SPI SFDP vendor-table hidden partition | writeup-patterns-1.md |
| W24 | Glitch-lab dialog loop (observe→trigger→token) | writeup-patterns-1.md |
| W25 | Remote power-lab fault search (Speck-verify) | writeup-patterns-1.md |
| W26 | White-box AES tracefile + last-round attack | writeup-patterns-1.md |
| W27 | DPA difference-of-means sanity + budgets | writeup-patterns-1.md |
| W28 | Template attack SNR→POI→profile→score | writeup-patterns-1.md |
| W29 | Cycle-accurate trace↔assembly overlay | writeup-patterns-1.md |
| W30 | On-device ADC cross-domain CPA | writeup-patterns-1.md |
| W31 | Power-glitch + offline code-search twin | writeup-patterns-1.md |
| W32 | OT dual-capture (`.sal` + control-write pcap) | writeup-patterns-1.md |
| W33 | ESP32 secure-boot section-overwrite | writeup-patterns-r2-1.md |
| W34 | ESP32-C3/C6 voltage-FI buffer overflow | writeup-patterns-r2-1.md |
| W35 | ESP32-V3 CRC-to-PC redirect | writeup-patterns-r2-1.md |
| W36 | RP2350 multi-vector challenge | writeup-patterns-r2-1.md |
| W37 | OP-TEE storage ladder rebuild | writeup-patterns-r2-1.md |
| W38 | OP-TEE TA BOF to object ROP | writeup-patterns-r2-1.md |
| W39 | OP-TEE kernel UAF to SMC hijack | writeup-patterns-r2-1.md |
| W40 | Open-TEE param-type confusion | writeup-patterns-r2-1.md |
| W41 | QEMU PCI MMIO OOB escape | writeup-patterns-r2-1.md |
| W42 | QEMU DMA-reentrancy UAF | writeup-patterns-r2-1.md |
| W43 | NIC-descriptor DMA phys primitive | writeup-patterns-r2-1.md |
| W44 | SMM CommBuffer to SMRAM ROP | writeup-patterns-r2-2.md |
| W45 | Double-GetVariable NVRAM overflow | writeup-patterns-r2-2.md |
| W46 | LogoFAIL DXE parser chain | writeup-patterns-r2-2.md |
| W47 | BMC Redfish/IPMI bypass to RCE | writeup-patterns-r2-2.md |
| W48 | JavaCard PIN timing oracle | writeup-patterns-r2-2.md |
| W49 | JavaCard type-confusion EEPROM read | writeup-patterns-r2-2.md |
| W50 | GlobalPlatform INSTALL/LOAD enum | writeup-patterns-r2-2.md |
| W51 | PUF ML-modeling ladder | writeup-patterns-r2-2.md |
| W52 | XOR-APUF chosen-challenge attack | writeup-patterns-r2-2.md |
| W53 | RO-TRNG EM map plus lock | writeup-patterns-r2-2.md |
| W54 | ChipWhisperer fault-course ladder | writeup-patterns-r2-2.md |
| W55 | EMFI bench loop | writeup-patterns-r2-3.md |
| W56 | Budget laser plus SRAM map | writeup-patterns-r2-3.md |
| W57 | HDMI TMDS plus TEMPEST | writeup-patterns-r2-3.md |
| W58 | CAN UDS plus ISO-TP rebuild | writeup-patterns-r2-3.md |
| W59 | LoRa to Meshtastic decrypt | writeup-patterns-r2-3.md |
| W60 | New-family FPGA bitstream RE | writeup-patterns-r2-3.md |
| W61 | USB HID/BadUSB rebuild | writeup-patterns-r2-3.md |
| W62 | SPI remote-service rewrite | writeup-patterns-r2-3.md |
| W63 | I2C/SPI dual-capture rebuild | writeup-patterns-r2-3.md |
| W64 | BLE GATT fuzz plus draw loop | writeup-patterns-r2-3.md |

### W1. ESP32 flashdump partition-table carve + QEMU-xtensa boot

- **Signals:** `0xE9` image magic past leading `0xFF` pad; `0xAA50` partition
  magic; `bootloader`, `nvs`, `phy_init`, `factory` labels; Xtensa ELF strings.
- **Steps:** 1. `xxd` head to confirm pad→magic layout. 2. Parse partition
  table (offset/size per entry). 3. Carve app partition. 4. `strings` triage
  for anti-clone/emulation hints. 5. Boot full image in Espressif QEMU fork.
- **Commands:**
  ```bash
  xxd firmware.bin | head -n 5
  esptool.py --port /dev/ttyACM0 read_flash 0 0x400000 full.bin
  ./configure --target-list=xtensa-softmmu --enable-slirp --enable-gcrypt && ninja qemu-system-xtensa
  qemu-system-xtensa -nographic -machine esp32 -drive file=firmware.bin,if=mtd,format=raw 2>&1 | tee results/hw_<id>/uart.log
  ```
- **Pitfalls:** mainline QEMU has no ESP32 machine — must use the Espressif
  fork `esp-develop` branch; erased first flash page needs a fresh
  bootloader reflash before a physical board will boot; do not trust
  `binwalk` alone (ESP32 magic needs the custom signature set).
- **Sources:**
  https://github.com/Am1ron/CTF-Writeups/blob/main/HackTheBox/Labs/Hardware/Espresso/writeup.md
  https://ctftime.org/writeup/39209
  https://github.com/espressif/qemu

### W2. U-Boot autoboot-passphrase adjacency + `md.b` exfiltration

- **Signals:** `Press passphrase to stop autoboot` / `autoboot` strings;
  `bootcmd=go <addr>`; `fwaddr=`/`fwsize=` env entries; `Boot completed`
  banner with hex blob.
- **Steps:** 1. `strings` the U-Boot binary; read the ~40 random bytes
  immediately before the passphrase prompt as the passphrase candidate.
  2. Time its delivery at the autoboot window to land a `=>` shell.
  3. `printenv` for load address + size. 4. `md.b <addr> <len>` the region,
  save hex, convert to binary. 5. Hunt key-words (little-endian) near the
  banner, decrypt offline.
- **Commands:**
  ```bash
  strings -n 6 u-boot.bin | grep -Ei -m 20 'passphrase|autoboot|bootcmd|fwaddr|fwsize'
  python3 -c "import socket,time; s=socket.create_connection((HOST,PORT)); s.sendall(b'\n'); time.sleep(0.5); s.sendall(PASSPHRASE+b'\n')"
  # at => prompt: printenv  |  md.b 0x40200000 0xB30
  xxd -r -p memdump.hex fw.bin
  ```
- **Pitfalls:** ARM stores words little-endian — read dump words byte-swapped
  before judging key material; the prompt window is seconds — script the
  send, do not type; one gated dump at a time, then work offline.
- **Sources:**
  https://github.com/ANormalStick/CTF-Writeups/blob/main/HeroCTF%20v7/Bootloader/README.md
  https://github.com/hax1ng/HeroCTF2025-Writeups/blob/main/Misc/bootloader.md
  https://www.synacktiv.com/publications/i-hack-u-boot

### W3. Unicorn decrypt-emu + `vmlinux-to-elf` kernel twin

- **Signals:** bootloader + encrypted kernel + encrypted squashfs trio;
  flat-high entropy on kernel/romfs but structured bootloader; given load
  bases; `block_aes_decrypt`-shaped routine names.
- **Steps:** 1. Entropy-triage which files are encrypted. 2. Load bootloader
  in Ghidra at the given base (file-offset = end of leading zeroes via
  `hexdump`). 3. Port the decrypt routine into Unicorn (map code + input +
  output pages, hook for tracing). 4. Decrypt kernel, run `vmlinux-to-elf`.
  5. Repeat emu on the kernel's key-init routines for the romfs key.
- **Commands:**
  ```bash
  binwalk -E dhboot.bin.img kernel.img romfs-x.squashfs.img
  hexdump -C dhboot.bin.img | head -n 50
  python3 emu_decrypt.py --base 0x21000000 --in kernel.img --out kernel.dec
  vmlinux-to-elf kernel.dec kernel.elf
  ```
- **Pitfalls:** base address and file-offset must both be right or every
  xref is garbage — verify with string-xref resolve rate before trusting
  output; map Unicorn pages RWX-large enough; never re-run binwalk on
  confirmed-encrypted regions.
- **Sources:**
  https://github.com/YeoJongHan/CTF_WriteUps/blob/main/2025/cddc-finals/decrypting-firmware.md
  https://www.shielder.com/blog/2022/03/reversing-embedded-device-bootloader-u-boot-p.1/
  https://github.com/Salman0x01/ctf-ai-agent-skills/blob/main/instructions/hardware/firmware-analysis.md

### W4. Lattice ECP5 bitstream → Verilog → UART harness

- **Signals:** `chal.bit`-style file; header part ID (e.g. LFE5U family);
  `8N1 at N clocks per symbol` UART-echo description; mid-CTF tool updates.
- **Steps:** 1. `xxd` header for the exact part. 2. Decompile with the
  matching toolchain (prjtrellis `ecpunpack` or VoidMercy decompiler —
  check the update date). 3. `yosys` synth/flatten/opt/clean to shrink.
  4. Schematic view to tag clock/reset/UART pins. 5. Verilator/pyverilator
  harness with a software UART byte pump; brute the service.
- **Commands:**
  ```bash
  xxd chal.bit | head -n 5
  ecpunpack chal.bit chal_out.config
  yosys -p 'read_verilog chal.v; synth; flatten; opt; clean; opt_clean; write_verilog chal_opt.v'
  verilator --cc --exe tb.cpp chal_opt.v && make -C obj_dir -f Vchal_opt.mk
  ```
- **Pitfalls:** wrong decompiler revision silently yields garbage — match
  the tool to the bitstream era; never start brute force before the echo
  service demonstrably runs in sim (else you burn hours on a dead model).
- **Sources:**
  https://ctftime.org/writeup/30866
  https://ctftime.org/writeup/30816
  https://github.com/wiresboy/ctf-writeups/tree/main/PBCTF2021/LLLattice

### W5. TEA-in-FPGA adder-pair ID + round-key brute

- **Signals:** UART oracle encrypting fixed-size blocks back (ECB shape);
  ~32 clock-cycle encrypt latency; two 32-bit adders visible between
  stages in the schematic.
- **Steps:** 1. Confirm ECB (equal inputs → equal outputs). 2. Measure
  rounds via timeline (Vivado/`gtkwave`); 64-bit/32-round points at TEA.
  3. Statistically map flip-flops to round bits for the first two rounds.
  4. Extract two consecutive round data-words, brute-force the key halves.
  5. Decrypt the companion `flag.enc`-style file offline.
- **Commands:**
  ```bash
  iverilog -o sim.out chall_tb.v && vvp sim.out > trace.log
  gtkwave dump.vcd &
  python3 tea_round_extraction.py --rounds 0,1 --out samples.bin
  ./tea_round_attack samples.bin
  ```
- **Pitfalls:** round counts from jittery sims mislead — cross-check
  latency three ways (timeline, counter, oracle); only the first two
  rounds need mapping, full-netlist RE is a time sink.
- **Sources:**
  https://ctftime.org/writeup/36236
  https://github.com/berndoJ/revenge-of-lllattice-writeup
  https://github.com/berndoJ/revenge-of-lllattice-writeup/blob/master/files/verilog/testbench.v

### W6. PS/2-LED video side-channel via bitstream FSM

- **Signals:** FPGA bitstream + board schematic + video of LEDs while a
  secret is typed; PS/2 keyboard wiring on the schematic.
- **Steps:** 1. Map LED nets to FPGA pins via schematic + constraint file.
  2. Reverse the bitstream to the LED-display FSM (LUT/register walk).
  3. Decode each video frame's LED pattern to the displayed nibble/char.
  4. Replay the typing sequence through the FSM model to recover input.
- **Commands:**
  ```bash
  yosys -p 'read_verilog design.v; synth_ice40; write_verilog synth.v'
  python3 led_decode.py --video flag.mkv --map pins.json --out sequence.txt
  ```
- **Pitfalls:** LED polarity (active-high vs low) inverts every bit —
  calibrate on a known banner char first; frame drops duplicate or skip
  symbols, so require the FSM transition per frame, not raw sampling.
- **Sources:**
  https://ctftime.org/writeup/32923
  https://par.nsf.gov/servlets/purl/10536731
  https://harris2024.mpi-sp.org/event/threats_of_fpga_reverse_engineering_1711554969.pdf

### W7. SecureEEPROM I2C emulator abuse (attacker usercode)

- **Signals:** MCU firmware source + secure-memory HDL (SystemVerilog);
  XDATA/SFR handshake addresses; emulator accepts attacker `usercode`.
- **Steps:** 1. Co-read firmware + HDL to learn the exact transaction
  ritual (stage data → raise flag → wait-for-clear). 2. Write minimal
  usercode that follows the ritual but addresses the secret region.
  3. Run under the provided emulator; dump words out over the debug port.
- **Commands:**
  ```bash
  grep -nE 'XDATA|SFR|I2C_STATE|0xfe00|0xfc' firmware.c seeprom.sv | head -n 30
  iverilog -o emu.out firmware_tb.v seeprom.sv && vvp emu.out
  ```
- **Pitfalls:** the wait-for-clear bit must be polled, not assumed — busy
  loops without timeout hang the emu; keep usercode strictly to the
  documented ritual or the model rejects the transaction.
- **Sources:**
  https://ctftime.org/writeup/15834
  https://github.com/leesh3288/CTF/blob/master/2019/GoogleCTF_Quals/flagrom/flagrom_writeup.md
  https://github.com/swisskyrepo/HardwareAllTheThings/blob/main/docs/protocols/rfid-nfc/hf-mifare-desfire.md

### W8. ATtiny85 USB-OTP token: simavr + USB trace

- **Signals:** tiny-AVR target + USB capture + flash-page decrypt loop +
  watchdog references; TOTP-shaped message/key handling.
- **Steps:** 1. Add the exact MCU register map (patch `avr.cfg`-style
  definitions). 2. Extract firmware, model the page-decrypt loop.
  3. Emulate under simavr with the USB trace as stimulus. 4. Source the
  message (time) and key (device secret) separately, then recompute.
- **Commands:**
  ```bash
  simavr -m attiny85 -f 8000000 fw.elf 2>&1 | tee results/hw_<id>/sim.log
  tshark -r dump.pcapng -Y usb -T fields -e usb.data_fragment > usb_frames.txt
  ```
- **Pitfalls:** the watchdog resets the model mid-decrypt — service or
  disable it in emu or every run dies at the same page; repeated identical
  outputs per address mean you are re-reading the wait loop, not progress.
- **Sources:**
  https://ctftime.org/writeup/17977
  https://github.com/G33KatWork/token_of_hxp_writeup
  https://github.com/G33KatWork/token_of_hxp_writeup/blob/master/simavr.patch

### W9. Custom RISC-V/MMIO flag-device timing oracle

- **Signals:** custom-CPU challenge with firmware-upload + memory-mapped
  flag device; per-byte timing deltas on crafted loads.
- **Steps:** 1. Upload a minimal reader firmware. 2. Build a timing
  harness (fixed trials, median filter). 3. Recover byte-at-a-time by
  maximizing the outlier delta. 4. Re-run the full prefix to confirm.
- **Commands:**
  ```bash
  python3 upload_fw.py --elf reader.elf --verify
  python3 time_oracle.py --trials 200 --median --out timings.csv
  ```
- **Pitfalls:** network/emu jitter swamps single samples — never decide on
  fewer than ~100 trials per candidate; increase-then-confirm each byte
  (accept, re-measure, then advance).
- **Sources:**
  https://ctftime.org/writeup/22376
  https://ethanwu.dev/blog/2020/07/16/chujowy-ctf-ford-cpu/
  https://github.com/JorianWoltjer/practical-ctf/blob/main/cryptography/timing-attacks.md

### W10. STM32 GPIO-init RE + static/sim twin

- **Signals:** STM32-class firmware dump + schematic; `SYSCTL_RCGCGPIO`,
  `DIR`/`DEN` register writes; keypad/UART peripheral mix.
- **Steps:** 1. Static pass: map clock-enable → direction → digital-enable
  to learn which pins are inputs vs outputs. 2. Find the init-sequence
  table (password/lock words). 3. Confirm with a dynamic-simulation twin
  before submitting anything to hardware.
- **Commands:**
  ```bash
  strings -n 6 lock.bin | grep -Ei -m 20 'GPIO|UART|baud|password|lock'
  arm-none-eabi-objdump -m arm -b binary -D lock.bin | grep -A3 -B3 'RCGC' | head -n 40
  ```
- **Pitfalls:** input-vs-output confusion flips the whole attack — trust
  the DEN/DIR bits, not names; pin numbers differ per port letter, so
  record `<PORT_LETTER><PORT_NUMBER>` exactly.
- **Sources:**
  https://ctftime.org/writeup/18647
  https://ctftime.org/writeup/22222
  https://xuanxuanblingbling.github.io/iot/2020/07/08/stm32/

### W11. Saleae `.sal` Async-Serial baud hunt

- **Signals:** `.sal` file (ZIP: `digital-*.bin` + `meta.json`); one or two
  active channels (RX/TX); challenge name hints at serial.
- **Steps:** 1. Unzip-list the `.sal` to confirm channels. 2. Open in
  Saleae Logic 2, attach Async-Serial to the active channel. 3. Sweep
  9600→115200; keep the rate with zero framing errors + printable runs.
  4. Read the terminal view; export raw + decoded transcripts.
- **Commands:**
  ```bash
  unzip -l capture.sal
  python3 -c "import json; print(json.load(open('meta.json'))['devices'])"
  # Logic 2: Analyzers → Async Serial → baud sweep 9600,19200,38400,57600,115200
  ```
- **Pitfalls:** attaching the analyzer to an idle channel yields clean
 -looking garbage — verify transitions exist first; a second channel may
  be the TX echo, decode both before concluding direction.
- **Sources:**
  https://github.com/sbencoding/htb_ca2023_writeups/blob/master/hardware/debug/README.md
  https://ctftime.org/writeup/36000
  https://ctfbase.com/writeup/20260129_hackthebox_debug

### W12. Sigrok `.sr` narrowest-pulse baud measure

- **Signals:** `.sr` session file; single digital channel; `8N1`-style
  framing with start-bit (low) + stop-bit (high).
- **Steps:** 1. Open in PulseView. 2. Cursor-measure the narrowest pulse
  (≈8.6 µs → 115200; ≈104 µs → 9600). 3. Add the UART decoder with that
  rate, 8 data bits, no parity, ASCII format. 4. Zoom out, read the stream.
- **Commands:**
  ```bash
  pulseview capture.sr &
  sigrok-cli -i capture.sr -P uart:baudrate=115200 -A uart 2>&1 | head -n 40
  sigrok-cli --version; sigrok-cli -P 2>&1 | head -n 20
  ```
- **Pitfalls:** decoder option names drift by version (`baudrate=` vs
  `baud=`) — probe `-P` help first; wrong polarity inverts everything,
  so confirm idle-high + start-bit-low before trusting output.
- **Sources:**
  https://github.com/MageBreak/CTF-Writeups/blob/main/UART.md
  https://ctftime.org/writeup/10363
  https://github.com/swisskyrepo/HardwareAllTheThings/blob/main/docs/gadgets/logic-analyzer.md

(End of SKILL.md patterns W1..W12 — W13..W32 continue in
`techniques/writeup-patterns-1.md`, W33..W64 in `techniques/writeup-patterns-r2-{1,2,3}.md`; index table above covers all 64.)

## EASY-FIRST ladder (2026 training refresh — ≤20 min)
1. Logic capture: `sigrok-cli -i cap.sr --show` → UART 8N1, try 115200 then 9600 (narrowest pulse 8.6µs=115200, 104µs=9600); confirm idle-high + start-bit-low.
2. Firmware: `binwalk -e fw.bin` → `grep -R 'ssid|password|root:|BEGIN.*KEY' _fw.bin.extracted/`.
3. Locked zip: `7z l -slt` (method/encrypted?) → `unzip -z` comment for password → `zip2john + john rockyou` / `fcrackzip -u -D -p rockyou`; corrupt EOCD → `zip -FF --out fixed.zip`; nested → loop `7z x` with password from `strings`.
4. Decoder option names drift (`baudrate=` vs `baud=`) — probe `-P` help first; wrong polarity inverts everything.

## R4 field patterns (browser-swarm 2026 — from 23 new writeups)
- ESP32 fast path: `esptool` UART download + `espefuse.py` secure-boot status before any glitching; MQTT wildcard `mosquitto_sub -t '#'` for creds.
- qsort-comparator side channel: sort-based XOR decrypt — reimplement comparator, undo nibble-swap/ROL chain in reverse order.
- Cheap-Yellow-Display/web-flash: published firmware ports beat reverse engineering; single-wire bus for panel control.

Deep-read bodies (5 complete articles): techniques/r5-deep-reads.md.
