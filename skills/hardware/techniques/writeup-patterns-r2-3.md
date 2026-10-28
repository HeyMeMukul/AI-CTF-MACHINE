# Hardware Writeup Patterns — R2 File 3 (W55..W64)

Companion to `../SKILL.md` → `## Writeup-Distilled Patterns (W33..W64)`.
W33..W43 live in `writeup-patterns-r2-1.md`; W44..W54 in
`writeup-patterns-r2-2.md`. Same contract: technique-only, placeholders
only, every URL verified in
`knowledge/writeups_mined/hardware_manifest_r2.md`.

### W55. EMFI bench loop (ChipSHOUTER + PicoEMP + Husky trigger)

- **Signals:** CW308 + STM32F-class target; ChipSHOUTER coil + Husky
  glitch-out; PicoEMP + 3D-printer stage; RDP/verify-dip trigger.
- **Steps:** 1. Baseline with voltage glitch + power-trace overlay.
  2. Port coordinates to EM stage (X/Y/Z + pulse shape). 3. Grid-scan
  for OTHER-class borders. 4. Freeze placement, automate collection,
  visualize per-position success.
- **Commands:**
  ```bash
  python3 emfi_scan.py --x 0,20,1 --y 0,20,1 --pulse 120,200,20 --trigger verify-dip --log grid.csv
  python3 emfi_plot.py --in grid.csv --out heatmap.png
  ```
- **Pitfalls:** EM adds probe-shape/placement variables — change one at
  a time; aggressive pulses damage targets, start low and bracket up.
- **Sources:**
  https://forum.newae.com/t/chipshouter-fault-attack/5787
  https://ringzer0.training/glitching-in-3d-low-cost-emfi-attacks/
  https://chipwhisperer.readthedocs.io/en/latest/Capture/ChipWhisperer-Husky.html

### W56. Budget laser FI + SRAM word-map + persistent fault

- **Signals:** decapped/backside-open MCU; SRAM address map known;
  laser driver + delay generator; CW308 carrier; hash-chain-length or
  verify-window target.
- **Steps:** 1. Device analysis: SRAM block locate (stack-end mapping).
  2. Wide-pulse grid scan for word placement. 3. Narrow to single-bit
  SRAM faults at target word. 4. For unpowered flash, characterize
  persistent-fault model, then run PFA.
- **Commands:**
  ```bash
  python3 sram_scan.py --base 0x2000f000 --words 256 --pulse-ns 1600 --zoom 20x
  python3 laser_sweep.py --delay-start 0.0 --delay-stop 2.5 --step 0.5 --trials 32
  ```
- **Pitfalls:** substrate thickness kills focus — measure RST per device;
  timing windows are seconds-wide here, do not over-constrain the
  trigger before scanning space first.
- **Sources:**
  https://courk.cc/rp2350-challenge-laser
  https://eprint.iacr.org/2025/2096.pdf
  https://tches.iacr.org/index.php/TCHES/article/view/11798

### W57. HDMI TMDS decode + TEMPEST EM recovery

- **Signals:** HDMI source + capture (grabber/FPGA/gnuradio); 3-lane
  TMDS + pixel clock; EM antenna + SDR near cable; static test image.
- **Steps:** 1. Word-align (10 candidates, control-symbol hunt) →
  10b8b/TERC4 state machine → pixels. 2. For EM: tune to pixel-clock
  harmonic, complex-resample to integer pixels/line. 3. Phase-track +
  complex frame-average. 4. Project to brightness (or CNN-inverse) and
  read text.
- **Commands:**
  ```bash
  python3 tmds_decode.py --in dump.raw --lanes 3 --out frame.png
  python3 tempest_tune.py --pixel-mhz 25.2 --harmonic 3 --rate 64e6
  ```
- **Pitfalls:** control symbols only appear in blanking — align there,
  not in video; AM-demod discards color phase, keep complex samples
  for low-contrast pairs.
- **Sources:**
  https://github.com/tgorochowik/hdmi-sniffer-fpga
  https://github.com/ljagiello/ctf-skills/blob/main/ctf-forensics/signals-and-hardware.md
  https://arxiv.org/html/2407.09717

### W58. CAN UDS seed-key + ISO-TP firmware rebuild

- **Signals:** CAN log + SavvyCAN/cantools; `0x7E2/0x7E8`-style tester/ECU
  pair; `0x27` seed/key + `0x34/0x36/0x37` transfer services; DBC files.
- **Steps:** 1. ISO-TP decode, isolate tester↔ECU pair. 2. Reassemble
  `Transfer-Data` blocks (minus SID/block bytes) → size-check vs
  `Request-Download`. 3. RE `0x27` handler (XOR/backdoor/RSA-textbook).
  4. Compute key, unlock, reflash-aware verify bypass (stale-flag,
  incomplete-upload) where present.
- **Commands:**
  ```bash
  candump vcan0 > can.log
  python3 isotp_rebuild.py --in can.log --tx 0x7E2 --rx 0x7E8 --out fw.bin
  python3 uds_key.py --seed <hex> --algo xor --const 0x42
  ```
- **Pitfalls:** FF-frame length includes SID+block bytes — subtract 2 or
  every block misaligns; session-gating blocks `0x11`-style levels,
  climb `0x01`→extended first.
- **Sources:**
  https://dparnishchev.github.io/posts/vcc_2025_password_change_policy/
  https://icanhack.nl/blog/blockharbor-ctf-2025-writeup/
  https://harjulianto.com/writeup-can-bus-implant-espilonctf-hardware/

### W59. LoRa PHY → Meshtastic AES-CTR decrypt chain

- **Signals:** sub-GHz IQ/wav + flash dump; 8-up/2-down chirps;
  `LONG_FAST`-style preset in config protobuf; channel PSK in `channels`.
- **Steps:** 1. Inspectrum chirp-confirm. 2. Demod with two gr-lora
  variants (keep CRC-valid frames). 3. Strip 3 B LoRa header.
  4. Rebuild nonce (packet-ID + zeros + source) → AES-CTR with channel
  key → protobuf-decode payload.
- **Commands:**
  ```bash
  inspectrum capture.complex64 &
  gnuradio-companion lora_rx.grc &
  python3 meshtastic_dec.py --key <hex> --frames frames.bin --protos protobufs/
  ```
- **Pitfalls:** LoRa ≠ LoRaWAN — parse Meshtastic framing, not MAC
  commands; nonce field order is endianness-sensitive, verify against
  one known-plaintext frame first.
- **Sources:**
  https://blog.nanax.fr/post/2024-01-28-hardware-longrange2/
  https://sec.gd/blog/en/posts/long-distance-2/
  https://penthertz.com/blog/testing-LoRa-with-SDR-and-handy-tools.html

### W60. New-family FPGA bitstream RE (Nexus/Gowin/Xilinx + HAL)

- **Signals:** bitstream for Nexus/Gowin/7-series/MachXO2; F4PGA-family
  DB project; HAL plugins; Starbleed-era encrypted bitstreams.
- **Steps:** 1. Pick DB backend (Oxide/Apicula/X-Ray/Trellis) + pack
  tool. 2. Bitstream→netlist convert. 3. HAL dataflow + SMT passes
  (datapath, FSM, S-box detect). 4. For encrypted parts, Starbleed-style
  manipulation → plaintext recovery → standard flow.
- **Commands:**
  ```bash
  nextpnr-himbaechel --device <part> --json design.json --pcf pins.pcf --fasm out.fasm
  gowin_pack -d <device> -o pack.fs out.config
  python3 hal_fsm.py --netlist design.v --out states.json
  ```
- **Pitfalls:** DB coverage is per-device — confirm part support before
  planning; encrypted-bitstream attacks need the exact family errata,
  do not port blindly.
- **Sources:**
  https://github.com/YosysHQ/nextpnr
  https://doi.org/10.1145/3658644.3690235
  https://hardwear.io/trainings/fpga-security-and-reverse-engineering/

### W61. USB HID/BadUSB descriptor → keystroke rebuild

- **Signals:** USB pcap with descriptor + `URB_INTERRUPT`/`URB_BULK`
  traffic; HID keyboard/mouse badges; Ducky `inject.bin`; CircuitPython
  `adafruit_hid` firmware.
- **Steps:** 1. ID device from GET-DESCRIPTOR strings. 2. Filter by
  transfer type + length + source. 3. `tshark`-extract `usbhid.data`/
  `capdata`. 4. Scancode-map (mind AZERTY), or mouse-delta accumulate;
  carve embedded PNG/file leftovers in bulk.
- **Commands:**
  ```bash
  tshark -r usb.pcap -Y 'usb.transfer_type==0x01' -T fields -e usbhid.data > hid.txt
  perl ducky-decode.pl -f inject.bin > decoded.txt
  ```
- **Pitfalls:** idle `00…` reports flood the capture — strip them before
  mapping; keyboard layout inverts letters, confirm with a known typed
  word first.
- **Sources:**
  https://writeups.cycomhackingconference.com/posts/2024/010-mechantusb/
  https://sherer.io/2024/11/02/huntress-ctf-2024-keyboard-junkie/
  https://ctftime.org/writeup/39990

### W62. SPI-flash remote service: JEDEC → key → CRC-aware rewrite

- **Signals:** `client.py`-style `exchange()` oracle; W25Q128-class
  chip; `log_event.c`-shaped struct+CRC+XOR layout; `0x48` security
  registers; `FLAG_ADDRESS`-style readback hint.
- **Steps:** 1. `0x9F` JEDEC confirm. 2. `0x03`-read full image.
  3. `0x48`-read OTP key at coded offset; confirm via timestamp-XOR.
  4. Per-record decrypt (CRC untouched), patch target field, recompute
  CRC, re-encrypt. 5. Sector-erase + page-program back, verify, read
  flag address.
- **Commands:**
  ```bash
  python3 client.py  # exchange([0x9F],3) -> JEDEC; exchange([0x03,0,0,0],N) -> dump
  python3 spi_rewrite.py --key-off 0x1052 --struct '<I B B H B B H' --patch uid=<id>
  ```
- **Pitfalls:** flash writes need erase-before-write at sector granularity
  — rewrite whole sectors, never single bytes; `Write-Enable` lapses
  after each op, send it every time.
- **Sources:**
  https://firmextract.com/posts/htb_writeup
  https://www.sleepyponylabs.com/blog/htb_ctf_2024_rids
  https://log-s.xyz/posts/hackthebox-cyberapocalypse-2024/

### W63. I2C-EEPROM / SPI-display dual capture rebuild

- **Signals:** `.sal` with SDA/SCL + SPI (CS/DC/RST) channels; I2C
  keyboard address; e-paper/display driver library; CSV export path.
- **Steps:** 1. Analyzer per bus (I2C addr filter; SPI mode-0). 2. Export
  CSV, split command vs data (DC line). 3. Replay driver calls in order
  (height/voltage/LUT preamble). 4. Rebuild framebuffers (`buf_a/b →
  black/red`) and render.
- **Commands:**
  ```bash
  sigrok-cli -i cap.sr -P i2c -A i2c | grep -m 5 -E 'Start|Address'
  python3 inky_rebuild.py --csv inky_spi.csv --width 136 --height 250 --out img.png
  ```
- **Pitfalls:** CS-less SPI is unframeable — require the CS column;
  little-endian height words arrive low-byte-first, assemble before
  sizing buffers.
- **Sources:**
  https://sevcankazdag.com.tr/cisa-ics-ctf-2024-write-up-series-spy-by-wire-1/
  https://mwlik.github.io/2024-08-05-crewctf-2024-sniff-challenge/
  https://blog.quantumlyconfused.com/ctf/2024/05/25/nsec2024-badgelife-addon/

### W64. BLE GATT fuzz + notify/mouse-draw loop

- **Signals:** ESP32/nRF GATT server; notify/indicate handles; MTU
  events; HCI-H4 mouse pcap; WHAD/bleak harness.
- **Steps:** 1. Enum characteristics, script read/write/notifies.
  2. Fuzz Prepare-Write/Execute sequences + MTU/MAC edges. 3. For HID
  draws: accumulate signed deltas, gate strokes on button bit, invert
  Y, stretch aspect. 4. For auth: rebuild token math (CRC+rand) then
  overflow length-unchecked melody/TLV buffers.
- **Commands:**
  ```bash
  gatttool -b <MAC> --characteristics
  gatttool -b <MAC> --char-write-req -a <H> --value <hex> --listen
  python3 ble_mouse.py --pcap mouse.pcap --handle 0x0028 --out draw.png
  ```
- **Pitfalls:** MTU is negotiated-not-enforced on some stacks — trigger
  the *event*, do not assume the size; notify vs indicate differ on ACK,
  listen on the paired handle the hint names.
- **Sources:**
  https://blog.quarkslab.com/bluetooth-low-energy-gatt-fuzzing.html
  https://ctf.zeba.dev/2025/ecsc/misc/blue-mouse/writeup/
  https://www.balda.ch/posts/2025/Apr/12/chipolo-one/
