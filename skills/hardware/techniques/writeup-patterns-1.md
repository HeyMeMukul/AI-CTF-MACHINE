# Hardware Writeup Patterns — File 1 (W13..W32)

Companion to `../SKILL.md` → `## Writeup-Distilled Patterns (W1..W32)`.
Index table lives in SKILL.md; W1..W12 live there; W13..W32 live here.
Same contract: technique-only, placeholders only, every URL verified in
`knowledge/writeups_mined/hardware_manifest.md`.

### W13. Gerber-layer flag rebuild

- **Signals:** `.gbr`/`.gerber` file set; multi-layer PCB views; split
  glyphs across layers.
- **Steps:** 1. Open the set in a Gerber viewer. 2. Toggle layers
  one-by-one, screenshotting each. 3. Reassemble split glyphs in order.
  4. Watch for look-alike final symbols and confirm against format.
- **Commands:**
  ```bash
  gerbv *.gbr &
  ls -la *.gbr; file *.gbr | head -n 20
  ```
- **Pitfalls:** hidden layers default off — enumerate, do not eyeball;
  visually similar glyphs (e.g. `@` vs `a`) need a second-layer confirm.
- **Sources:**
  https://github.com/sbencoding/htb_ca2023_writeups/blob/master/hardware/critical_flight/README.md
  https://github.com/swisskyrepo/HardwareAllTheThings/blob/main/docs/other/electronic-components.md

### W14. Waveform-letter transcription

- **Signals:** logic-capture whose traces visibly draw letters; very-easy
  tier; no decoder yields text.
- **Steps:** 1. Open in the vendor tool (Logic 2 / PulseView). 2. Zoom to
  glyph scale. 3. Transcribe letters channel by channel into a text file.
  4. Sanity-check against the expected format shape.
- **Commands:**
  ```bash
  unzip -l timed.sal; saleae-logic2 timed.sal &
  ```
- **Pitfalls:** mirrored/rotated glyphs — flip axes before concluding;
  confirm each letter at two zoom levels to avoid trace-aliasing reads.
- **Sources:**
  https://github.com/sbencoding/htb_ca2023_writeups/blob/master/hardware/timed_transmission/README.md
  https://github.com/swisskyrepo/HardwareAllTheThings/blob/main/docs/gadgets/logic-analyzer.md

### W15. BLE GATT handle-enum + write-replay

- **Signals:** BLE pcap (`btatt`/`btsmp`); `esptool` MAC/partition output;
  Just-Works pairing hints; handle + value write pairs.
- **Steps:** 1. Filter pcap for ATT writes (`btatt.opcode == 0x12`-style).
  2. Pair with any code, enumerate characteristics/handles. 3. Replay the
  observed write to the target handle. 4. Read back the score/secret
  characteristic and decode hex to bytes.
- **Commands:**
  ```bash
  tshark -r capture.pcapng -Y btatt -T fields -e btatt.handle -e btatt.value | head -n 30
  bluetoothctl -- pair <MAC>  # accept any code for Just-Works
  gatttool -b <MAC> --char-write-req --handle=<H> --value=<hex-no-0x>
  gatttool -b <MAC> --char-read --handle=<H2> | cut -d' ' -f3- | xxd -r -p
  ```
- **Pitfalls:** GATT values take bare hex (no `0x` prefix) or the write
  silently mangles; re-pair state matters — `remove` the device between
  runs or stale bonds skew results.
- **Sources:**
  https://github.com/mullerdavid/ctf_writeups/blob/master/cyberquest24/Finals_Hardware_It_will_Just_Work/WRITEUP.md
  https://github.com/pauloborges/bluez/blob/bc704506e69ae30b0770aac32504e89cf2dc9ddf/attrib/utils.c#L117
  https://ctftime.org/writeup/27676

### W16. MIFARE nested/hardnested + UID-spoof + rewrite

- **Signals:** MIFARE Classic card + reader (ACR122U-class); partial dump
  with `??` blocks; sector-key counts; balance/UID fields.
- **Steps:** 1. `mfoc` dump (raise probe count on stubborn sectors).
  2. Nonce-weakness recovery for unread sectors. 3. Flip UID with a
  rewritable card for identity stages. 4. Rewrite value blocks for
  balance stages; emulate on Flipper-class hardware where handy.
- **Commands:**
  ```bash
  mfoc -P 500 -O dump.mfd
  nfc-mfsetuid <new-uid>
  nfc-mfclassic w b current.mfd new.mfd f
  ```
- **Pitfalls:** Block-0 write-once card types brick after first use —
  match card type (CUID/FUID/UFUID) to the stage; Flipper partial reads
  are normal, transfer the dump and continue on desktop tooling.
- **Sources:**
  https://yun.ng/c/ctf/2025-athack-ctf/hardware/rfid/
  https://www.okiok.com/northsec-2025-challenge-writeup-vending-machine-nfc
  https://github.com/swisskyrepo/HardwareAllTheThings/blob/main/docs/protocols/rfid-nfc/hf-mifare-classic.md

### W17. DESFire SPI wiretap aligned to firmware

- **Signals:** reader board (MCU + NFC frontend); `.logicdata` SPI
  captures of genuine transactions; unstripped MCU firmware; known card UID.
- **Steps:** 1. Reverse firmware for the crypto call-graph. 2. Split SPI
  captures by CS; tag reader-vs-card frames. 3. Align wiretap bytes to
  firmware buffers. 4. Break the session crypto with known-UID anchors.
- **Commands:**
  ```bash
  sigrok-cli -i capture.logicdata -P spi:mosi=MOSI:miso=MISO:sck=SCK:cs=CS -A spi | head -n 60
  strings -n 8 fw.elf | grep -Ei -m 20 'uid|desfire|session|nonce|cmac'
  ```
- **Pitfalls:** captures without CS are unframeable — require the CS
  column before any decode; crypto direction (reader vs card) flips the
  key schedule, verify with the first known-UID frame.
- **Sources:**
  https://ctf.hack.cert.pl/challenge/card-reader
  https://github.com/swisskyrepo/HardwareAllTheThings/blob/main/docs/protocols/rfid-nfc/hf-mifare-desfire.md
  https://github.com/swisskyrepo/HardwareAllTheThings/blob/main/docs/protocols/spi.md

### W18. USB keystroke + CCID UID + AES-pipe decrypt

- **Signals:** USB capture with keyboard + smartcard-reader + camera;
  MIFARE UID shown by reader tooling; AES-encrypted file on removable media.
- **Steps:** 1. Extract keystrokes via the HID lookup table. 2. Recover
  the exact UID display spacing the on-device command expects. 3. Pipe
  UID bytes through the documented cut/dd transform into the AES key.
  4. Decrypt the target camera frame/file.
- **Commands:**
  ```bash
  tshark -r usb.pcapng -Y usb -T fields -e usb.data_fragment > hid.txt
  python3 hid_decode.py --table hid_table.json --in hid.txt --out keys.txt
  ```
- **Pitfalls:** UID display spacing (multiple blanks, double-spaced hex)
  must be byte-exact or the derived key is wrong; isolate the right frame
  number first, then decrypt only that slice.
- **Sources:**
  https://jwgoerlich.com/write-up-of-the-29c3-ctf-whats-this-challenge
  https://github.com/G33KatWork/token_of_hxp_writeup/blob/master/dump.pcapng

### W19. OOK burst demod via GRC twin pipelines

- **Signals:** recorded IQ bursts (`.iq`/`.u8`); OOK hint in the title;
  fixed bit-length bursts; known sample rate + sample type.
- **Steps:** 1. Load in GNU Radio Companion as complex and as real twin
  pipelines. 2. Envelope/amplitude chain to slice symbols. 3. Demod one
  burst, verify bit-length, submit raw bits.
- **Commands:**
  ```bash
  python3 -c "import numpy as np; d=np.fromfile('off.iq',dtype=np.uint8); print(len(d))"
  gnuradio-companion ook_demod.grc &
  ```
- **Pitfalls:** treating the stream with the wrong sample type shifts
  every symbol — confirm dtype/rate from the brief before building the
  flowgraph; demod one burst fully before batching the rest.
- **Sources:**
  https://ctftime.org/writeup/28045
  https://github.com/cscosu/ctf-writeups/blob/master/2021/utctf/rf_is_spOOKy/README.md
  https://github.com/jopohl/urh

### W20. URH ASK split + sync-strip + ASCII recode

- **Signals:** `signal.dat`-style capture; URH autodetect finds ASK with
  multiple (e.g. eight) signals; bit-counts one short of a multiple of 8.
- **Steps:** 1. URH autodetect parameters. 2. Protocol-diff to cluster
  identical signals (keep one per cluster). 3. Strip the sync preamble
  (~24 bits). 4. Pad to a multiple of 8, map to ASCII, apply the outer
  recode.
- **Commands:**
  ```bash
  python3 - <<'EOF'
  data = open('bits.txt').read().strip()
  sync, payload = data[:24], data[24:]
  payload = '0' + payload  # align to 8-bit boundary
  print(''.join(chr(int(payload[i:i+8], 2)) for i in range(0, len(payload), 8)))
  EOF
  ```
- **Pitfalls:** the missing alignment bit must be padded, not truncated —
  truncation garbles every later byte; confirm cluster reduction with the
  diff view before decoding (else you decode the same signal N times).
- **Sources:**
  https://github.com/leony/CTF/blob/master/Radio%20Frequency/Signal.dat_Writeup.md
  https://github.com/hamedlotfaly/urh-rtl-sdr
  https://ctf-2023.gnuradio.org/

### W21. QPSK satellite Doppler-correct + beacon vote

- **Signals:** `.cf32` complex IQ; pass-duration sample count; baud + rate
  framing (e.g. 10 samples/symbol); repeating-beacon structure.
- **Steps:** 1. Load IQ, confirm duration math. 2. Correct Doppler in
  short windows. 3. Mid-symbol sampling → quadrant→dibit map.
  4. Reassemble bytes, vote across repeated beacons.
- **Commands:**
  ```bash
  python3 - <<'EOF'
  import numpy as np
  d = np.fromfile('sat.cf32', dtype=np.complex64)
  print(f'samples={len(d)} seconds={len(d)/48000:.1f}')
  EOF
  ```
- **Pitfalls:** uncorrected Doppler rotates the whole constellation —
  window the correction, never fit one offset to a full pass; nail the
  dibit mapping per quadrant empirically (four rotations to try, vote
  decides).
- **Sources:**
  https://github.com/hax1ng/EschatonCTF2026/blob/master/signal_writeup.md
  https://pubs.gnuradio.org/index.php/grcon/article/download/57/40
  https://people.ece.ubc.ca/~edc/7860.jan2024/lab2.pdf

### W22. JTAG IR/DR unlock-key + word-loop rebuild

- **Signals:** simulated or bench JTAG with reset/ir/dr/state verbs;
  IDCODE resembling a Cortex-M part; locked-debug status word.
- **Steps:** 1. Reset TAP, read IDCODE (record raw hex). 2. Brute-force
  the small IR space for the unlock instruction; send candidate keys.
  3. Confirm `UNLOCKED` state. 4. MEM_READ instruction + address-then-data
  DR pairs per word; LE-rebuild to ASCII.
- **Commands:**
  ```bash
  openocd -f interface/ftdi.cfg -f target/stm32f1x.cfg -c 'init; scan_chain; exit' 2>&1 | tee scan.txt
  # sim bench: reset | ir 1 | dr 00000000 32 | ir <unlock> | dr <key> <bits> | state
  python3 jtag_dump.py --start 0x1000 --words 64 --le --out mem.bin
  ```
- **Pitfalls:** two-DR-transaction reads (address, then data) — sending
  one merged DR silently returns stale words; record the exact IR codes
  that worked, they differ per challenge build.
- **Sources:**
  https://github.com/EspilonOrg/EspilonCTF-2026-Writeups/blob/main/Hardware/Phantom_JTAG/solve/solve.md
  https://github.com/swisskyrepo/HardwareAllTheThings/blob/main/docs/debug-interfaces/jtag.md
  https://github.com/swisskyrepo/HardwareAllTheThings/blob/main/docs/enumeration/jtag.md

### W23. SPI SFDP vendor-table hidden partition

- **Signals:** SPI-flash service with CS/RDID/SFDP verbs; JEDEC ID of a
  common vendor; partition table that does not explain full capacity.
- **Steps:** 1. Assert CS, read JEDEC ID, record all 3 bytes. 2. Read SFDP
  header → parameter-table count. 3. Walk the vendor table for hidden
  offsets. 4. `0x03`-read the hidden range; header-check, then keyed
  decrypt.
- **Commands:**
  ```bash
  flashrom -p ch341a_spi -r dump1.bin && flashrom -p ch341a_spi -r dump2.bin && cmp dump1.bin dump2.bin
  sigrok-cli -i spi.sr -P spi:mosi=MOSI:miso=MISO:sck=SCK:cs=CS -A spi | grep -m 5 -E '9[Ff]|03|5[Aa]'
  ```
- **Pitfalls:** `0x0B` fast-read inserts a dummy byte that shifts every
  address if parsed as `0x03` — branch on opcode first; capacity byte is
  `2^N` bytes, cross-check against dump length before trusting a hidden
  offset.
- **Sources:**
  https://github.com/EspilonOrg/EspilonCTF-2026-Writeups/blob/main/Hardware/Wired_SPI_Exfil/solve/solve.md
  https://github.com/swisskyrepo/HardwareAllTheThings/blob/main/docs/protocols/spi.md
  https://github.com/swisskyrepo/HardwareAllTheThings/blob/main/docs/gadgets/ch341a.md

### W24. Glitch-lab dialog loop (observe→trigger→token)

- **Signals:** network glitch bench (`observe`/`set_delay`/`set_width`/
  `arm`/`trigger`/`read_console` verbs); signature-verify cycle window;
  SKIPPED-vs-crash outcomes.
- **Steps:** 1. Observe and note the verify window. 2. Delay to window
  middle, narrow width. 3. Arm, trigger, classify
  (OK/RESET/HANG/OTHER/TARGET). 4. Zoom at OTHER borders only. 5. Read
  console for the maintenance token.
- **Commands:**
  ```bash
  python3 glitch_client.py --host <H> --port <P> --observe --out boot_windows.txt
  python3 glitch_client.py --delay <mid> --widths 10,20,30 --trials 3 --log grid.csv
  ```
- **Pitfalls:** width too wide browns out (HANG), too narrow recovers
  (OK) — change one knob at a time, max two zoom halvings; no
  OTHER-class after a full grid means widen once, then take the static
  twin (patch-the-check) instead of burning trials.
- **Sources:**
  https://github.com/EspilonOrg/EspilonCTF-2026-Writeups/blob/main/Hardware/Glitch_The_Wired/solve/solve.md
  https://github.com/inwpu/Cyber-Apocalypse-CTF-2026/blob/main/A%20Fault%20in%20the%20Cinder%20%E2%80%94%20Writeup.md
  https://github.com/newaetech/chipwhisperer/blob/develop/docs/source/Capture/ChipWhisperer-Husky.md

### W25. Remote power-lab fault search (Speck-verify)

- **Signals:** remote-lab client + verify-routine source (Speck-shaped);
  fault-injection endpoint; secret-vs-reject oracle.
- **Steps:** 1. Read the verify routine for the compare location.
  2. Baseline the clean transcript. 3. Sweep fault timing across the
  compare; classify every shot. 4. Freeze the bypass setting, extract.
- **Commands:**
  ```bash
  python3 remote_lab_client.py --baseline --out clean.log
  python3 remote_lab_client.py --sweep start=0,stop=5000,step=250 --trials 3 --log sweep.csv
  ```
- **Pitfalls:** blind wide sweeps waste the session budget — anchor on
  the compare first (source-given here); >200 no-change trials means
  stop and pivot to logic analysis.
- **Sources:**
  https://ctftime.org/writeup/25066
  https://blog.cryptohack.org/side-channels-remote-lab-glitching-aes-donjon-ctf-writeup
  https://github.com/Salman0x01/ctf-ai-agent-skills/blob/main/instructions/hardware/side-channel-glitch.md

### W26. White-box AES tracefile + last-round attack

- **Signals:** white-box AES binary + control-flow-flattening;
  sample-trace format (hex lines); last-round relationship hint.
- **Steps:** 1. Strip/deobfuscate control flow first. 2. Build the
  tracefile in the attack tool's expected layout. 3. Recover the last
  round key statistically. 4. Invert the schedule to the master key.
- **Commands:**
  ```bash
  python3 build_tracefile.py --samples samples/ --out tracefile
  python3 -c "import phoenixAES; phoenixAES.crack_file('tracefile', [], True, False, 3)"
  ```
- **Pitfalls:** attacking before deobfuscation mixes rounds and fails —
  order is strip → trace → last-round → invert; keep candidates
  plaintext-aligned per the tool's assumption (constant-vs-varied).
- **Sources:**
  https://github.com/hkcert-ctf/CTF-Challenges/blob/main/CTF-2025/findkey/writeup/writeup.md
  https://ctftime.org/writeup/31921
  https://github.com/SideChannelMarvels/JeanGrey/blob/master/phoenixAES/phoenixAES/__init__.py

### W27. DPA difference-of-means sanity + budgets

- **Signals:** power-trace set + known data; 8-bit vs 32-bit target
  variants; DPA-then-CPA ladder.
- **Steps:** 1. Run cheap difference-of-means DPA first. 2. Compare
  trace budgets across bus widths (32-bit needs more). 3. Escalate only
  failures to full CPA.
- **Commands:**
  ```bash
  python3 -c "import numpy as np; t=np.load('traces.npy'); print(t.shape, t.dtype)"
  python3 dpa_means.py --traces traces.npy --data plaintexts.npy --bit 0
  ```
- **Pitfalls:** jumping to CPA first burns time when DPA already
  separates; unaligned traces fake-fail both — mean/STD plot check first.
- **Sources:**
  https://eprint.iacr.org/2020/1008
  https://github.com/OfekSharon1/chipwhisperer-side-channel-attacks/blob/main/notebooks/DPA_attack.ipynb
  https://arxiv.org/pdf/1801.00932

### W28. Template attack SNR→POI→profile→score

- **Signals:** profiling (clone-device) access + attack traces; SNR
  curves; per-byte accuracy plots.
- **Steps:** 1. Compute SNR per sample, pick POIs. 2. Build per-value
  templates on profiling traces. 3. Score attack traces, track
  accuracy-vs-trace-count. 4. Finish remaining bytes with CPA if needed.
- **Commands:**
  ```bash
  python3 snr_poi.py --traces profiling.npy --byte 0 --plot snr_b0.png
  python3 template_score.py --poi poi.json --attack attack.npy
  ```
- **Pitfalls:** too many POIs overfit noise — start minimal (top-SNR
  handful), add only on plateau; profiling and attack setups must match
  (gain/clock drift invalidates templates).
- **Sources:**
  https://github.com/OfekSharon1/chipwhisperer-side-channel-attacks/blob/main/notebooks/Template_attack.ipynb
  https://eprint.iacr.org/2023/1891
  https://github.com/newaetech/chipwhisperer-datasets

### W29. Cycle-accurate trace↔assembly overlay

- **Signals:** MCU/FPGA target + trigger-anchored traces + sampler code
  (Gaussian/PQC-shaped); suspect sign-flip-style routine.
- **Steps:** 1. Fix trigger timing (fast GPIO toggle, no wrapper skew).
  2. Overlay trace with disassembly per cycle. 3. Pin leakage to exact
  instructions. 4. Propose/test hardened rewrite, re-measure.
- **Commands:**
  ```bash
  python3 overlay.py --trace t.npy --asm target.S --trigger fast --out overlay.html
  ```
- **Pitfalls:** compiler reordering moves trigger code — verify placement
  in disassembly, never trust C-line mapping; default vendor wait-states
  change leakage vs real firmware, match the real config.
- **Sources:**
  https://eprint.iacr.org/2022/903
  https://csrc.nist.gov/CSRC/media/Presentations/power-based-side-channel-attack-analysis-on-pqc-al/images-media/session-4-kamucheka-power-based-side-channel-attack.pdf
  https://dl.acm.org/doi/abs/10.1109/TVLSI.2024.3390601

### W30. On-device ADC cross-domain CPA

- **Signals:** TrustZone-M-class device (secure HW crypto engine);
  unsecure-world code-exec; on-board ADC readable across domains.
- **Steps:** 1. Trigger encryptions from unsecure code. 2. Capture with
  the on-board ADC (no external probe). 3. CPA the HW-engine traces.
  4. Report sampling-rate tolerance explicitly.
- **Commands:**
  ```bash
  python3 adc_capture.py --samples 20000 --rate low --out adc_traces.npy
  python3 cpa_quick.py --traces adc_traces.npy --model hw --byte 0
  ```
- **Pitfalls:** assuming high sample rate is required — test low rates
  deliberately (attacks survive well below clock); TrustZone gives no
  SCA resistance by itself, do not let the boundary stop the test.
- **Sources:**
  https://tches.iacr.org/index.php/TCHES/article/view/8347
  https://eprint.iacr.org/2019/689.pdf
  https://www.kernel.org/doc/html/v5.17/security/tpm/tpm_ftpm_tee.html

### W31. Power-glitch + offline code-search twin

- **Signals:** sealed device (no destructive open); desolder-able MCU;
  scope-visible verify dip; encrypted filesystem + short code gate.
- **Steps:** 1. Scope-triggered voltage dip at the verify dip. 2. Dump
  the filesystem once. 3. Brute-force the short gate fully offline.
- **Commands:**
  ```bash
  python3 glitch_scope.py --trigger verify-dip --depth-mv 200 --width-ns 80 --log shots.csv
  python3 offline_search.py --dump fs.bin --space numeric-4 --workers 8
  ```
- **Pitfalls:** live-attempt limits do not apply offline — never burn
  limited tries on-device after the dump; stabilize WP/HOLD rails first
  or every shot is noise.
- **Sources:**
  https://www.ledger.com/academy/series/enter-the-donjon/episode-4-power-glitch-attack
  https://blog.cryptohack.org/side-channels-remote-lab-glitching-aes-donjon-ctf-writeup
  https://github.com/newaetech/chipwhisperer/blob/develop/docs/source/ChipSHOUTER/ChipSHOUTER.md

### W32. OT dual-capture (`.sal` + control-write pcap)

- **Signals:** OT challenge shipping BOTH a logic capture and a network
  capture (BACnet/Modbus/DNP3); `.sal` + `.pcap` pair.
- **Steps:** 1. Decode the `.sal` for the physical-layer truth.
  2. Dissect the pcap for function codes/point maps. 3. Cross-check
  register IDs between both. 4. Issue the minimal control-write.
- **Commands:**
  ```bash
  unzip -l ot_capture.sal; tshark -r ot.pcap -Y modbus -T fields -e modbus.func_code -e modbus.reg | sort | uniq -c
  sigrok-cli -i ot_capture.sal -P modbus:baudrate=9600 -A modbus 2>&1 | head -n 20
  ```
- **Pitfalls:** single-capture tunnel vision — the answer usually needs
  the cross-check (IDs differ between layers); one gated write only,
  then observe the process state.
- **Sources:**
  https://github.com/EspilonOrg/EspilonCTF-2026-Writeups/blob/main/OT/Cyberia_Grid/solve/solve.md
  https://github.com/EspilonOrg/EspilonCTF-2026-Writeups/blob/main/OT/Tachibana_SCADA/solve/solve.md
  https://github.com/swisskyrepo/HardwareAllTheThings/blob/main/docs/protocols/modbus.md
