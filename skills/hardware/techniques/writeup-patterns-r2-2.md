# Hardware Writeup Patterns — R2 File 2 (W44..W54)

Companion to `../SKILL.md` → `## Writeup-Distilled Patterns (W33..W64)`.
W33..W43 live in `writeup-patterns-r2-1.md`; W55..W64 in
`writeup-patterns-r2-3.md`. Same contract: technique-only, placeholders
only, every URL verified in
`knowledge/writeups_mined/hardware_manifest_r2.md`.

### W44. UEFI SMM CommBuffer overflow → SMRAM ROP

- **Signals:** EDK2 + QEMU OVMF; `EFI_SMM_COMMUNICATE_HEADER` (GUID + data
  + len); `SmmCopyMemToSmram`-shaped copy; canary + func-ptr globals;
  `SMM_CODE_CHK_EN`/ASLR in hard tiers.
- **Steps:** 1. Forge communicate-header pointing at flag-MMIO (SMM-only
  readable). 2. Overflow message into adjacent func-ptr (canary math
  first in tier-1). 3. Pivot stack → clear `CR0.WP` → patch SMRAM `.text`
  with stage-2 (PTE-present + read). 4. Leak `LocateProtocol` pointer to
  defeat ASLR before gadget math.
- **Commands:**
  ```bash
  strings -n 6 SmmCowsay.efi | grep -Ei -m 10 'Canary|CowsayFunc|Communicate'
  gdb -ex 'target remote :1234' -ex 'b *<CowsayFunc-callsite>'  # icebp-word path
  python3 smm_rop.py --leak <proto-ptr> --drv PiSmmCpuDxeSmm --out chain.bin
  ```
- **Pitfalls:** executing outside SMRAM trips code-check — ROP inside
  SMRAM only; CHAR16 vs CHAR8 doubles every leak (zip odd/even halves).
- **Sources:**
  https://ctftime.org/writeup/34883
  https://pagabuc.me/blog/smm-cowsay-1-and-2-uiuctf-2022
  https://blog.quarkslab.com/for-science-using-an-unimpressive-bug-in-edk-ii-to-do-some-fun-exploitation.html

### W45. UEFI double-GetVariable NVRAM stack overflow

- **Signals:** DXE driver calling `GetVariable` twice on same name;
  attacker-writable variable; `EFI_BUFFER_TOO_SMALL` size-update path;
  `efivars` FS on the Linux side.
- **Steps:** 1. Spot get→resize→get idiom in driver. 2. Grow the variable
  (clear immutable flag, set attributes) past the stack buffer.
  3. Reboot into DXE → overflow saved return. 4. No-ASLR/no-NX: direct
  shellcode after the return slot.
- **Commands:**
  ```bash
  chattr -i /sys/firmware/efi/efivars/<VarName>-<guid>
  printf '<payload>' > /sys/firmware/efi/efivars/<VarName>-<guid>
  qemu-system-x86_64 -bios OVMF.fd -debugcon file:debug.log -global isa-debugcon.iobase=0x402
  ```
- **Pitfalls:** variable attributes gate runtime-vs-boot visibility — set
  them to match the driver's phase; first call only *reports* size, the
  overflow lands on the *second* call's stack frame.
- **Sources:**
  https://www.ctfiot.com/157564.html
  https://www.sentinelone.com/labs/zen-and-the-art-of-smm-bug-hunting-finding-mitigating-and-detecting-uefi-vulnerabilities/
  https://www.binarly.io/blog/efixplorer-hunting-uefi-firmware-nvram-vulnerabilities

### W46. LogoFAIL DXE image-parser chain

- **Signals:** logo-customization path (ESP/BMP/GIF/JPEG/PNG/PCX/TGA);
  IBV parser + DXE driver advisories; supply-chain patch gaps.
- **Steps:** 1. Identify reachable parser via ESP logo variable.
  2. Fuzz dimensions/offsets for int-overflow → OOB. 3. Corrupt DXE
  protocol entry → event-callback hijack. 4. Stage shellcode via NVRAM
  + second-stage loader.
- **Commands:**
  ```bash
  uefi-firmware-parser -e firmware.bin -o fw_out/
  python3 logofail_fuzz.py --parser bmp --corpus logos/ --out crashes/
  chipsec_main -m common.uefi.access_uefispec
  ```
- **Pitfalls:** vendor "fixed" builds often patch one format only — retest
  every parser, especially PCX/TGA/GIF; disabling customization kills
  the whole class, check that control first.
- **Sources:**
  https://www.binarly.io/blog/inside-logofail-poc-integer-overflow-to-code-execution
  https://www.binarly.io/blog/finding-logofail-dangers-of-image-parsing-system-boot
  https://22222483.fs1.hubspotusercontent-na1.net/hubfs/22222483/Reports/Binarly_LogoFAIL%20REsearch%20Report%206.20.24.pdf

### W47. BMC Redfish/IPMI auth-bypass → RCE chain

- **Signals:** AMI MegaRAC/OpenBMC; Redfish host-interface + `AuthNone`;
  `host-interface-support-module.lua`; IPMI RAKP session IDs; weak
  `GetValue`-style web handlers.
- **Steps:** 1. Fingerprint Redfish vs IPMI surface. 2. Try header-spoof
  (`X-Server-Addr` regex-extract) or session-ID predict + downgrade.
  3. Create account via `AccountService`, or POST dynamic-extension
  code. 4. Persist below OS (firmware implant), mind patch-lag per OEM.
- **Commands:**
  ```bash
  curl -sk https://<bmc>:8443/redfish/v1/Systems | head -c 400
  ipmitool -I lanplus -H <bmc> -U <user> -P <pass> user list 1
  python3 redfish_spoof.py --host <bmc> --spoof 169.254.0.17: --create-user
  ```
- **Pitfalls:** lighttpd *appends* to spoofed headers — the regex reads
  up to the first colon, craft accordingly; host-interface vs external
  interface behave differently, test both.
- **Sources:**
  https://eclypsium.com/research/bmcc-lights-out-forever/
  https://eclypsium.com/blog/ami-megarac-vulnerabilities-bmc-part-3/
  https://kb.cert.org/vuls/id/163057

### W48. JavaCard PIN timing oracle + APDU rebuild

- **Signals:** JavaCard applet source with `OwnerPIN`-style check;
  VERIFY/GET_FLAG INS bytes; per-byte delay growth; logic-analyzer
  ISO7816 tap points.
- **Steps:** 1. Map CLA/INS/P1/P2/Lc from source. 2. Time VERIFY per
  prefix → recover PIN bytes one at a time. 3. Authenticate, then issue
  oversized-`Le` GET_FLAG read. 4. Carve returned blob (image/ASN.1).
- **Commands:**
  ```bash
  python3 apdu_time.py --cla 80 --ins 20 --prefix <hex> --trials 5 --out timings.csv
  gp -list  # GlobalPlatformPro: confirm applet/AID surface first
  ```
- **Pitfalls:** secure-channel jitter buries small deltas — median over
  trials, compare lengths first (length leaks loudest); `Le` is two
  bytes on extended APDUs, size it from source constants.
- **Sources:**
  https://github.com/s1lver-lining/ctf-writeups/blob/main/ECW2024%20Quals/Course%20hipPIN/README.md
  https://blog.quarkslab.com/how-a-security-anomaly-was-accidentally-found-in-an-eal6-javacard.html

### W49. JavaCard type-confusion EEPROM read (PhiAttack shape)

- **Signals:** `cref` simulator + CAP upload + verifier; `Object` vs
  `byte[]` handle model; `aaload/saload/baload` type checks; secret in
  class EEPROM.
- **Steps:** 1. Enable EEPROM dump in simulator. 2. Build confusion via
  congruent export/import split (phi pattern) to reinterpret `Object`
  as oversized `byte[]`. 3. `arrayCopyNonAtomic` past bounds into APDU
  buffer. 4. Slide window to cover victim applet region.
- **Commands:**
  ```bash
  wine cref_t1.exe -nobanner -nomeminfo &
  java -cp <sim> com.sun.javacard.apdutool.Main -nobanner script.apdu
  python3 eeprom_carve.py --dump eeprom.bin --start <off> --len 0x85
  ```
- **Pitfalls:** off-card verifier rejects naive casts — keep export
  files congruent; `baload` refuses short/int/Object arrays, read
  through byte-typed views only.
- **Sources:**
  https://kitctf.de/writeups/rwctf2023-happycard
  https://hacktricks.wiki/en/generic-hacking/esim-javacard-exploitation.html

### W50. GlobalPlatform card-management enum + INSTALL/LOAD

- **Signals:** ISD keys (default/`mother`-key candidates); GET-STATUS /
  GET-DATA tags; `INSTALL [for load]` / `LOAD` / `INSTALL [for install]`
  sequences; OTA/SMS-PP or SCP02/03 transport.
- **Steps:** 1. Authenticate (try default keysets). 2. `GET STATUS`
  applets + keys. 3. `verifycap` the CAP offline first (packaging vs
  target-side failures). 4. LOAD blocks then INSTALL-selectable;
  confirm SELECT before exploit APDUs.
- **Commands:**
  ```bash
  java -jar gp.jar -list
  java -jar gp.jar -install applet.cap
  verifycap -v applet.cap
  ```
- **Pitfalls:** a failed SCP02 is not proof LOAD is closed — retry over
  SCP03/S8/S16; OTA replay counters reject replays, bump `cntr` policy
  deliberately.
- **Sources:**
  https://stackoverflow.com/questions/56743468/list-content-of-globalplatform-smartcard-with-apdu
  https://globalplatform.org/wp-content/uploads/2025/05/GPC_CardSpecification_v2.3.1.49_PublicRvw.pdf

### W51. PUF ML-modeling ladder (arbiter → XOR → dynamic)

- **Signals:** CRP datasets (simulated + FPGA Artix-7/Zynq); 64-bit
  stages; reliability side-channel availability; majority-vote or
  scrambling wrappers.
- **Steps:** 1. Baseline LR on raw CRPs. 2. Escalate RF/NN for XOR depth.
  3. If static-scambled, run influence-sort descramble first. 4. For
  voted/dynamic PUFs switch to reliability (LDHF) or MoPE generic
  models. 5. Validate on disjoint silicon CRPs.
- **Commands:**
  ```bash
  python3 puf_model.py --arch xor --stages 64 --xor-size 6 --crps 1000000 --model mlp
  python3 doss_descramble.py --crps crps.csv --out order.json
  ```
- **Pitfalls:** simulated CRPs flatter real bias — always confirm on
  silicon CRPs; fixed-pattern scrambles fall to divide-and-conquer,
  dynamic ones do not.
- **Sources:**
  https://doi.org/10.1109/isvlsi61997.2024.00159
  https://link.springer.com/article/10.1007/s41635-024-00157-3
  https://doi.org/10.48550/arxiv.2403.00464

### W52. XOR-APUF chosen-challenge boundary attack

- **Signals:** reliable or access-controlled XOR-APUF; challenge-choice
  oracle; neighboring-challenge flip visibility; FPGA twin optional.
- **Steps:** 1. Sample centroid + 1-bit neighbors in `Psi` space.
  2. Estimate per-centroid flip probability → distance-to-boundary.
  3. Pearson-correlate flips to isolate single APUFs. 4. Model each
  APUF, compose to full XOR response.
- **Commands:**
  ```bash
  python3 flip_probe.py --centroids 2000 --radius 1 --out flips.csv
  python3 divide_conquer.py --flips flips.csv --xors 9
  ```
- **Pitfalls:** multi-APUF simultaneous flips look like noise — use
  correlation, not single samples; reliability-blocking interfaces do
  not stop this (no repeats needed).
- **Sources:**
  https://doi.org/10.48550/arxiv.2312.01256
  https://eprint.iacr.org/2019/566.pdf

### W53. RO-TRNG EM map + injection-lock analysis

- **Signals:** RO-TRNG on FPGA/MCU + AES running nearby; EM probe +
  PSD flow; voltage/temperature knobs; common-mode current probe.
- **Steps:** 1. Differential PSD at two voltages → RO frequencies pop.
  2. Spatial scan at those bins → localize + sampling-rate (peak
  spacing). 3. Sweep injected sine 10–100 MHz, watch lock signatures.
  4. Confirm bias (DFT fail) at lock bands; model countermeasures
  (filtering/isolation) last.
- **Commands:**
  ```bash
  python3 em_cartography.py --v1 1.5 --v2 1.7 --grid 20x20 --out maps/
  python3 ro_lock.py --sweep 10e6,100e6 --observe common-mode --out lock.csv
  ```
- **Pitfalls:** the cipher drowns RO lines in raw PSD — differential only;
  lock bands are per-device (variation), never reuse a profiled band
  blindly.
- **Sources:**
  https://ujm.hal.science/ujm-00833822/document
  https://lirias.kuleuven.be/retrieve/539752
  https://digital-library.theiet.org/doi/10.1049/PBCS032E_ch14

### W54. ChipWhisperer fault-course ladder (sim → HW)

- **Signals:** `chipwhisperer-jupyter` courses tree; TINYAES target;
  Husky/Lite + CW308; fault201 `Lab 1_1A` simulation notebooks.
- **Steps:** 1. Run S-box-skip simulation (16×256 collapse math).
  2. Port to clock-glitch lab (password bypass first). 3. Escalate to
  voltage-glitch dump, then AES loop-skip/DFA labs. 4. For EMFI, keep
  target + trigger identical, swap glitch source for ChipSHOUTER.
- **Commands:**
  ```bash
  jupyter lab courses/fault201/Lab_1_1A_-_Introduction_to_AES_Fault_Attacks.ipynb
  python3 cw_glitch.py --target tinyaes --mode clock --offset-start 0 --offset-stop 3000
  ```
- **Pitfalls:** jumping to HW DFA before sim wastes days — the sim tells
  you the *required* fault model; Husky gain/phase drift fakes
  failures, clear ADC errors first.
- **Sources:**
  https://github.com/newaetech/chipwhisperer-jupyter/blob/main/courses/fault201/Lab%201_1A%20-%20Introduction%20to%20AES%20Fault%20Attacks.ipynb
  https://github.com/newaetech/chipwhisperer-jupyter/tree/main/courses
  https://rtfm.newae.com/
