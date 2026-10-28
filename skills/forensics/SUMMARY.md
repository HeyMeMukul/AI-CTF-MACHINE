# forensics SUMMARY (quickref)

Pick toolchain by type: pcap->tshark, disk->SleuthKit+carvers, mem->Vol3.
Read-only: work on `./work/` copies, `mount -o ro,loop,noexec`.

Pcap: `capinfos`; `tshark -q -z io,stat,0 / conv,ip / io,phs`.
Fields: `tshark -r c.pcap -Y dns -T fields -e dns.qry.name | sort|uniq -c|sort -rn`.
Follow: `tshark -q -z follow,tcp,ascii,0` (udp likewise).
Filters: `http`, `dns.qry.name contains`, `icmp.data.len>32`, `smb2`, `ftp-data`.
Export: `tshark -r c.pcap --export-objects http,./work/http` (+smb/ftp).
TLS: `-o tls.keylog_file:./sslkey.log` only if keylog given.
Covert: scapy carve DNS labels (hex/b32) + ICMP Raw concat + timing-bit median check.

Disk: `mmls`; `fls -r -p -o OFF`; `fls -d` deleted; `icat -o OFF img inode>out`
(`-r` for deleted); `fsstat/istat`; `mount -o ro,loop,offset=$((OFF*512))`.
OFF = Start sector from `mmls`. Root inode: 5 (NTFS) / 2 (ext).
Carve: `binwalk -e -C ./work/carve`; `foremost -i img -o ./work/foremost`;
VeraCrypt `veracrypt --mount --readonly` (hinted pw only).

Mem (Vol3): `vol.py -f mem.raw windows.info` first (!), then
`pslist|pstree|cmdline|netscan|filescan|hashdump|lsadump|memmap --pid P --dump`.
Linux: `linux.pslist|linux.bash|linux.procmaps`.
`psscan+malfind` if pslist lies; GIMP-raw RGB w=1024 visual trick.
Logs: `fls -m />body; mactime -b body -d`; grep fail/404/denied.

MCP: `vol_info` first, then ps/pstree/cmdline/net/files/hash/lsa/memmap_dump;
cap ~8 calls, CLI re-run for full rows.
Negatives: TLS strings = certs (need keylog); `icat -r` garbage = overwritten;
`pslist`!=`psscan` = hidden proc.
`timeout 120` everything; `binwalk -e` can explode — quota dir + `du -sh`.

Gates: 1 Baseline inventory | 2 Confirm (stream/inode/PID/window) |
3 Negative (encoding? overwritten? plugin lie?) |
4 ONE extraction <=120s | 5 Validate: sha256 src+out, re-run identical,
handoff JSON (etype+filter/target+cmd+timeline).
Carved img/audio->stego, EXE->rev.

Hard-playbook: TLS1.3 needs keylog/mem keys (RSA key alone fails);
resumption w/o handshake = stop, hunt mem labels. USB: 8B boot report
(mod,res,key1-6), pin usb.src, edge-detect + Shift/Caps. BLE GATT reuses
HID decode; no LTK = stop. ADS: `istat` extra $DATA + `icat ino-128-id`.
UsnJrnl:$J exposes timestomp (BASIC_INFO_CHANGE vs MACE); WAL: copy trio
first, query copy only (commit order, no wall time). VMEM: diff ps/netscan.
Frag files: `istat` run order + `blkcat`, never numeric. RAID: metadata
first, never brute stripe.
Chains: pcap+mem->keylog->decrypt->export | disk del-zip->hint-crack->pcap |
db-wal del-row->host filter->stream (one gate each, re-baseline between).
Fail-fast: endian near-miss->fix OFF; Vol mismatch->info/linux/banners;
encrypted->hint-hunt then /crypto; GB pcap->fields+head never -V;
mix UTC+local->normalize epoch.
Drift: Vol3 `windows.*` (Vol2 imageinfo/profiles dead); tshark `-Y` + lower
`tls.keylog_file`; SIK `-o` = sectors.
Tiers: easy<=15m (no carve) | med<=45m (2 gates) | hard<=2h (one branch) |
insane=15m spike then escalate. Esc: media->/stego, encrypted->/crypto,
EXE->/rev, >2GB/mount->operator (hashes+cmd+timeline attached).
W-mined: keylog pairing (random-in-ClientHello match) before decrypt; coredump session-ID-anchored master-key carve.
W-mined: USB descriptor-census + direction-gate first; HID state-machine (edge/BS/Caps); AZERTY remap; steno-chord=Plover.
W-mined: mouse relative-vs-absolute (VM trap), velocity stroke-split, OSK-click overlay; bulk-outlier carve + matryoshka; iso-audio.
W-mined: BLE challenge-response live-replay; crackle TK/LTK (+DLT fork); A2DP SBC 0x9c carve; ADV color-craft.
W-mined: MFT entry*1024 resident carve; Parent-Path unzip-chain; MotW HostUrl + EID15 + rename-survival.
W-mined: $J/$LogFile sequencing (crdownload pair, entry-link moves); 0x10/0x30 + EID2 timestomp proof.
W-mined: $I/$R receipt + LNK cross-check + bursts; RAID missing-slot + order-permute; TestDisk + magic-graft.
W-mined: TrueCrypt mem-password ladder + tcrypt; VeraCrypt 137XY + Chrome-DPAPI; BitLocker john/FVEK/dislocker.
W-mined: SQLite WAL-commit-order (no wall time) + WebKit epoch; DNS order-uniq + b32-padding tell + 9B strip.
W-mined: metadata channels (len/TTL/rsvd-bits, modulo-bucket); WiFi EAPOL->prefs->inner (RDP/pyrdp, PFX-mimikatz).
W-mined: SMB3 session-key chain + reversed-sessid + hostname-swap trap; EVTX Sysmon/Kerberos ladders (4768/4769/5140).
W-mined: ICS funcCode/register-index/S7-BCD + spec AES-halves; EML sed-range carve; LNK-args to pcap-replay.
R2-mined (W33-62, detail in techniques/writeup-patterns-r2-a|b|c.md): QUIC decrypts like TLS but carve via
http3-headers column + Reassembled-QUIC (no Export-Objects); mem-carved keylog feeds decrypt-then-VNC-keystroke chains.
R2 cloud: CloudTrail SQL AssumeRole-session pivot; GCP protoPayload principal-volume hunt; SA-key pair = persistence.
R2 cont: `docker save` layer walk + `.wh.` whiteout lower-layer reads; overlayfs mount leaks; k8s verb/objectRef RBAC climb + CRIU checkpoints.
R2 Apple: `log collect` > sysdiagnose (TTL myth); APFS snapshots first (mount -s), carve last; FileVault escrow->kcpassword->Chainbreaker.
R2 mobile/FW: ALEAPP->JADX->Frida AES hooks + accounts_ce.db ladder; JTAG/binwalk; UBIFS OOB-strip + journal/ORPH; ESP32 partition-first.
R2 FDE/time: Vol2-FVEK/LUKS-LiME+findaes/bitlocker2john-22100/VSS-escrow/partial-key-window forks; timestomp = 0x10/0x30 + $J + LSN-outlier + trunc-tell.
R2 hunts: chainsaw-full/hayabusa-timeline first, rule-hits as index, raw-EID confirm, UTC quote; Sigma authoring = stable selectors + category-first.
R2 chains: Havoc deadbeef CTR; MQTT-b85->macro->pyc->tx-timing; staged-blob script-order join + hash-gate; APK Frida over static; EKS IMDS-triple.
