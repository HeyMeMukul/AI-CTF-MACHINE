# Forensics R2 patterns B — W43..W52 (FileVault, ADB/Android, UBIFS, FDE, timestomp)

Technique-only distillations from `knowledge/writeups_mined/forensics_manifest_r2.md`
(topic lines). Signals → steps → commands → pitfalls → sources.

### W43 — FileVault/T2 key-recovery ladder (escrow-first, brute-last)
- Signals: APFS dmg/image asking password, `kcpassword` present, FileVault
  recovery-key escrow hints (MDM/iCloud/Keychain), T2/Apple-silicon hardware.
- Steps: 1. Hunt escrow first: Keychain files, iOS backups, MDM consoles
  (managed keys almost always exist somewhere). 2. Auto-login path: `kcpassword`
  `xxd -p` + default-XOR-key decode -> Chainbreaker keychain dump ->
  Secure-Note create-time. 3. Live-mem path: memory image taken while mounted
  yields the volume key (no brute). 4. No key anywhere: T2/Silicon internal
  storage is ciphertext off-machine — take decrypted logical acquisition from
  the live unlocked system, document scope. Brute force is the last resort.
- Commands: `xxd -p /etc/kcpassword` + `python3 -m chainbreaker login.keychain-db --password-prompt --dump-all` + `fdesetup status; diskutil apfs list`
- Pitfalls: password resets can strip secure tokens and kill FileVault access;
  T2 Target-Disk-Mode still needs the FileVault layer removed with a valid key.
- Sources: https://medium.com/@itsGir/ctf-write-up-maclock-certified-cyber-defenders-b0fef014e96f
  https://blog.passware.com/from-filevault-to-t2-how-to-deal-with-native-apple-encryption/
  https://graymanre.github.io/ctf/btlo_thekey.html

### W44 — ADB triage extraction (no-root live pull)
- Signals: unlocked Android, `adb devices` paired, no full-dump exploit,
  `android_triage`-style option menu (bugreport/dumpsys/backup/pull).
- Steps: 1. Pair + `adb devices` confirm. 2. Live commands first:
  `dumpsys usagestats` (sees deleted apps), `dumpsys account`, `bugreport`
  (huge — grep, don't read). 3. Pull `/sdcard` + `/system`, APK list from
  `/data` (no APK install/uninstall side effects). 4. Content providers for
  calendar/contacts/sms (`content query --uri ...`). 5. `adb backup -all
  -shared -system -apk` only with on-device confirmation; note per-app
  `allowBackup=false` gaps. 6. JTAG/chip-off dumps go the binwalk route (W44b:
  7zip split -> `binwalk -D` header/footer carve).
- Commands: `adb devices; adb shell dumpsys usagestats | head -n 40` + `adb backup -all -shared -system -apk -f backup.ab` + `adb pull /sdcard ./sdcard/`
- Pitfalls: backup silently skips `allowBackup=false` apps (downgrade path needs
  reinstall discipline); bugreport contains PII — scope and hash it.
- Sources: https://blog.digital-forensics.it/2021/03/triaging-modern-android-devices-aka.html
  https://thamizhiniyancs.gitbook.io/writeups/ctf/2024/hackctf/forensics/dumped.md

### W45 — Android dump-in-depth (DB ladder: accounts -> comms -> media)
- Signals: full `/data` dump, ALEAPP report + raw DBs, APK from Downloads,
  AES-encrypted gallery, Telegram/SMTP exfil code.
- Steps: 1. ALEAPP folder-process first (Chrome Downloads names the APK).
  2. Identity: `accounts_ce.db` (`type LIKE '%google%'`), telephony
  `siminfo`, `roles.xml` default apps. 3. Comms: app DBs (Twitter/Gmail
  snippets, chat coords), `recent_tasks` + `snapshots/*.jpg` for last-session
  proof. 4. APK: JADX package hunt -> exfil protocol/host (SMTP host, Telegram
  endpoint) -> AES key location (b64 in code vs runtime log). 5. Media:
  `media/0/Pictures` (+ `.aux` doubles), EXIF GPS via exiftool.
- Commands: `sqlite3 accounts_ce.db "SELECT name FROM accounts WHERE type LIKE '%google%';"` + `exiftool PXL_*.jpg | grep -i gps` + `jadx-gui evil.apk`
- Pitfalls: ALEAPP misses app-specific DBs — always hand-check `/data/data/<pkg>/databases`;
  encrypted-gallery keys are b64-wrapped (decode before use, CyberChef `From Base64`).
- Sources: https://sarahosborn.com/4n6/posts/MVS_CTF_2024_Android_Writeup/
  https://medium.com/@itsGir/ctf-write-up-androidbreach-certified-cyber-defenders-c9f068caac0d
  https://medium.com/@sshekhar01/belkactf-7-stranger-dfings-writeup-e9f29561926c

### W46 — UBIFS/JFFS2 deep carve (ECC-strip + journal recovery)
- Signals: NAND dumps, `UBI#` magic, `jffs2`/`ubifs` binwalk hits, spare/OOB
  interleaving, camera/router/IoT narratives.
- Steps: 1. binwalk map all images; read partition tables (`partition*.txt`)
  for ground truth. 2. NAND with OOB: strip spare bytes (e.g. every `0x40` per
  `0x400`) before tools. 3. JFFS2: jefferson, else mtdram+mtdblock kernel
  mount. 4. UBIFS: ubireader/ubidump on the UBI region (cut at first `UBI#`);
  nandsim+ubiformat+ubiattach for stubborn images. 5. Deleted files: UBIFS
  journal + ORPH/DENT nodes (UBIFT recovers what ubireader cannot).
- Commands: `binwalk -eM -C out fw.bin` + `jefferson root.jffs2 -d jffs2_root` + `ubireader_extract_files -o ubifs_root image.ubi` + `python3 -c "d=open('nand','rb').read()" # strip OOB stride first`
- Pitfalls: mounting raw NAND with OOB intact fails CRCs (strip first);
  TSK/Autopsy do NOT parse UBIFS — don't conclude "empty" from them.
- Sources: https://www.hacktivesecurity.com/blog/2024/12/18/not-all-roads-lead-to-pwn2own-firmware-reverse-engineering-part-2/
  https://habr.com/ru/companies/bizone/articles/768904/
  https://www.unibw.de/digfor/publikationen/pdf/2024_dfrws_eu_deutschmann_ubi_fs.pdf

### W47 — ESP32/SPIFFS flash carve (partition-table-first)
- Signals: `flashdump.bin` = `data`, HTML/strings hint Espressif, Arduino/IDF
  build stamps, OTA app0/app1 + spiffs + coredump layout.
- Steps: 1. Stock binwalk misses ESP32: add ESP-IDF magic defs, re-run.
  2. Partition table at `0x8000` gives label/offset/size map (nvs/otadata/app0
  /app1/spiffs/coredump). 3. Load app image in Ghidra with ESP32 flash-loader
  plugin (entry address from header). 4. Target HTML-writer/XOR-loop functions;
  carve heap/irom regions for the two XOR sections.
- Commands: `binwalk baby_flashdump.bin -m esp32.magic` + `dd if=dump bs=1 skip=$((0x10000)) count=$((0x140000)) of=app0.bin`
- Pitfalls: Xtensa disassembly misaligns (strings vs code) — clean before
  decompile; OTA slots mean TWO app copies (check both).
- Sources: https://ctftime.org/writeup/39209

### W48 — LUKS live-key recovery (LUKS1 vs LUKS2 fork)
- Signals: LUKS header (`cryptsetup luksDump`), running system, deleted
  keyfile, kernel keyring (LUKS2) vs dmsetup table (LUKS1).
- Steps: 1. `luksDump` to confirm version/slots. 2. LUKS1: `dmsetup table`
  shows the volume key directly. 3. LUKS2: key lives in kernel keyring (not
  exportable by design) — take a RAM dump (LiME `insmod`, path+format params),
  run findaes/aeskeyfind, convert hex hits to binary, trial `luksAddKey`.
  4. Rotate immediately (`reencrypt`) since the dump now holds key material.
- Commands: `cryptsetup luksDump /dev/<dev> | head -n 30` + `insmod lime.ko "path=/root/mem.lime format=raw"` + `findaes mem.lime | head`
- Pitfalls: rebooting loses LUKS2 keys (no on-disk copy); testing a candidate
  with `luksAddKey` mutates a slot — use a throwaway slot, document it.
- Sources: https://jfr.im/blog/2025/03/recovering-luks-keys/

### W49 — BitLocker FVEK-from-RAM fork (plugin vs wordlist vs escrow)
- Signals: BitLocker `.dd`/`.img` + optional `.mem`, `FVEK` challenge text,
  `-Vide`/`-k` dislocker hints, VSS/shadow copies nearby.
- Steps: 1. Weak-password fork: `bitlocker2john -i img` -> hashcat `-m 22100`
  (or john) on hinted slice -> `dislocker -V img -u<pass>`. 2. Strong-password
  fork: Vol2 `bitlocker --dislocker` on RAM (Vol3 lacks the plugin — switch
  versions) -> `dislocker -V img -k <FVEK>`. 3. Escrow fork: VSS/shadow or
  photo/document recovery-key hunt -> `manage-bde -unlock -RecoveryPassword`.
  4. Mount via loop + ntfs-3g; hexdump fallback if mount fails.
- Commands: `bitlocker2john -i bitlocker.dd > h.txt; hashcat -m 22100 -a 0 h.txt rockyou.txt` + `vol.py -f mem --profile=<P> bitlocker --dislocker ./dumps` + `dislocker -V bitlocker.dd -k dumps/<id>.fvek -- /mnt/dislocker`
- Pitfalls: recovery-key hashes in the john file are NOT the weak target (use
  the user-password hash); vol3-only shops stall — keep a Vol2 path ready.
- Sources: https://blog.cbarkr.com/ctf/picoCTF/2025/Bitlocker-2
  https://infoseciitr.in/ctf-writeups/byu-ctf/not_again/
  https://qiaonpc.github.io/post/lock/

### W50 — Partial-key brute force (known-segment recovery keys)
- Signals: photographed/redacted recovery key with visible segments, 48-digit
  grouping, mount-unlock loop tooling (`manage-bde`/dislocker scriptable).
- Steps: 1. Fix known groups, brute the unknown group range only
  (e.g. last-5-digits window from a visible prefix digit). 2. Script
  unlock-attempt loop with FTK-mounted image; stop on first success.
  3. Immediately `manage-bde -off`/decrypt to a working copy; hash both.
- Commands: `for i in $(seq 40000 49999); do manage-bde -unlock E: -RecoveryPassword <g1-g7>-0${i}; done` (batch loop; gate by hint scope)
- Pitfalls: unbounded 48-digit brute is infeasible — scope must come from the
  visible fragment; each attempt is slow (seconds) — narrow first, loop second.
- Sources: https://triettran2222.gitbook.io/dfir-writeups/bitlocked-why2025-ctf

### W51 — VSS + E01 mount ladder for escrowed keys
- Signals: E01 with extra volumes (D/E/F/G), encrypted volume + plaintext
  volume with shadow copies, `BitLocker`-named Hins (Bit.TXT), white-text
  stego in documents.
- Steps: 1. Mount E01 read-write-capable (Arsenal online mode) to enumerate
  real volumes. 2. `vssadmin list shadows` per candidate volume; `mklink /D`
  to the shadow device. 3. Harvest escrow (`Bit.TXT` recovery key), unlock the
  encrypted volume, then work the inner leads (CID white-text creds,
  security-QA password combos). 4. Select-all / recolor pass on every doc.
- Commands: `vssadmin list shadows /for=E:` + `mklink /D C:\vssrestore \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\`
- Pitfalls: offline E01 browsers hide VSS (mount online); empty D/G drives are
  normal — the shadow lives on the data volume, verify per-volume.
- Sources: https://graymanre.github.io/ctf/btlo_thekey.html

### W52 — Timestomp proof pack (SI/FN + $J + LSN + precision tell)
- Signals: "real time" narratives, same-dir timestamp mimicry, `time_stomp`
  tooling in Prefetch/PS-history, E01 with MFT+$LogFile+$J.
- Steps: 1. MFTECmd both `$MFT` and `$J`; compare Created/Modified 0x10 vs
  0x30 per file (bulk-copy skew is ms-level; stomps are exact-matches to a
  NEIGHBOR file). 2. Confirm in `$J`: `BASIC_INFO_CHANGE`+`CLOSE` at capture
  time vs claimed-old MACE. 3. LSN outlier sort (`istat` per inode): stomped
  file's LSN dwarfs neighbors. 4. Precision tell: stomped stamps truncated to
  whole seconds (`.0000000`) vs natural sub-second. 5. Corroborate tool run:
  Prefetch `STOMP_*.pf` + ConsoleHost_history + EID2 (Sysmon) previous-vs-new.
- Commands: `MFTECmd.exe -f '$MFT' --csv mft/; MFTECmd.exe -f '$J' --csv j/` + `for i in $(fls -o OFF img | awk '{print $2}' | cut -d: -f1); do istat -o OFF img $i; done | grep -B2 -A6 'LogFile Sequence' | sort`
- Pitfalls: unzip/copy also skews 0x10/0x30 — require $J/EID2/tool corroboration;
  $FN updates on rename/move — scope the claim to $SI-only tools.
- Sources: https://mahmoud-shaker.gitbook.io/dfir-notes/timestomp-challenge-eg-ctf-2025-forensics-write
  https://diablo666.medium.com/timestomp-eg-cert-ctf-2025-forensics-write-up-ea248ab20ba4
  https://medium.com/@matchadonutforensics/determining-time-stomping-activities-with-usn-journal-usnjrnl-3c797c1dbf4a
