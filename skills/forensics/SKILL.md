---
name: forensics
description: Pcap + disk + memory forensics via tshark, SleuthKit, Volatility3 with timeline handoff
category: forensics
phase: 1-3
---
Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`; separate evidence from inference, preserve scope, validate each link, and label uncertainty.

# Forensics Skill — Pcap / Disk / Memory

## Mental Model

> Forensics = find the needle without breaking the haystack.
> Mount read-only, carve copies, build a timeline, then extract.

Three evidence types, three toolchains — pick by file type:

1. **Pcap** (`*.pcap*`) — tshark first, Wireshark GUI only for Follow confirm.
2. **Disk** (`*.dd/*.E01/*.vmdk`/firmware) — SleuthKit + carvers on a copy.
3. **Memory** (`*.raw/*.vmem/*.dmp`) — Volatility3 `windows.info` first.

Order: **identify -> inventory -> timeline -> carve -> extract**.
Timeline before carving prevents tunnel vision.
Read-only: originals never written; work in `./work/`; mounts
`-o ro,loop,noexec`; Vol cache `./work/symbols`.

## Workflow

### Phase 1 — Baseline (identify + inventory, read-only)

Goal: what evidence type? size? OS/profile? how many streams/files/procs?

Pcap baseline:

```bash
file capture.pcap*; ls -l capture.pcap*
capinfos capture.pcap
tshark -r capture.pcap -q -z io,stat,0 2>&1 | head -n 20
tshark -r capture.pcap -T fields -e frame.number -e ip.src -e ip.dst -e dns.qry.name 2>/dev/null | head
```

Disk baseline:

```bash
file disk.dd; ls -l disk.dd
mmls disk.dd
fls -r -p disk.dd 2>/dev/null | head -n 40
fsstat disk.dd 2>/dev/null | head -n 30
binwalk disk.dd 2>/dev/null | head -n 20
```

Memory baseline (Volatility3 — profile auto-detects via symbols):

```bash
python3 vol.py -f mem.raw windows.info 2>&1 | head -n 30
python3 vol.py -f mem.raw windows.pslist 2>&1 | head -n 20
python3 vol.py -f mem.raw linux.info 2>&1 | head -n 10  # if windows.info fails
```

Log/timeline baseline (if `*.log`, `*.evtx` given):

```bash
ls -l logs/; file logs/*; head -n 20 logs/*.log 2>/dev/null
```

`Reasoning Checkpoint`: evidence type locked (pcap/disk/mem/log) + count
(streams/files/procs) + OS hint recorded? If mixed bundle (pcap+mem),
rank by size/signal (pcap with DNS/ICMP anomalies first) and queue
others. No extraction in Phase 1.

### Phase 2 — Confirmation (timeline + targeted view)

Goal: confirm WHERE the anomaly is with a timeline or stream list
before carving bytes.

Pcap confirmation — conversations, protocol hierarchy, DNS/ICMP outliers:

```bash
tshark -r capture.pcap -q -z conv,ip 2>&1 | head -n 30
tshark -r capture.pcap -q -z io,phs 2>&1 | head -n 30
tshark -r capture.pcap -Y dns -T fields -e dns.qry.name | sort | uniq -c | sort -rn | head -n 20
tshark -r capture.pcap -Y icmp -T fields -e frame.number -e ip.src -e data.len | head -n 20
tshark -r capture.pcap -Y 'http contains flag or ftp or smb2' -T fields -e frame.number -e http.host -e http.request.uri -e ftp.request.command | head -n 20
```

Follow TCP/UDP stream (CLI Wireshark Follow):

```bash
tshark -r capture.pcap -q -z follow,tcp,ascii,0 2>&1 | head -n 60
tshark -r capture.pcap -Y 'tcp.stream==0' -T fields -e tcp.payload | head -n 10
```

Display filters (`-Y`): `http` / `http.file_data contains flag` /
`dns.qry.name contains exfil` / `dns.txt.length > 50` /
`icmp.data.len > 32` / `ftp-data` / `smb2.filename contains .` /
`tls.handshake` / `tcp.port==4444` / `ip.addr==10.0.0.5`

Disk confirmation — partition walk + deleted + timeline:

```bash
mmls disk.dd
fls -r -m / -o 2048 disk.dd 2>/dev/null | head -n 20  # adjust -o from mmls Start
fls -d -p -o 2048 disk.dd 2>/dev/null | head -n 20    # deleted only
istat -o 2048 disk.dd 5 2>/dev/null | head -n 20      # root inode detail
```

Memory confirmation — process tree + cmdline + net:

```bash
python3 vol.py -f mem.raw windows.pstree 2>&1 | head -n 30
python3 vol.py -f mem.raw windows.cmdline 2>&1 | head -n 30
python3 vol.py -f mem.raw windows.netscan 2>&1 | head -n 20
python3 vol.py -f mem.raw windows.filescan 2>&1 | grep -Ei -m10 'flag|secret|password' || true
```

Log/timeline confirmation:

```bash
fls -r -m / disk.dd > body.txt 2>/dev/null; mactime -b body.txt -d | head -n 40
grep -Ei -m20 'fail|attack|404| denied|unauthor' logs/*.log 2>/dev/null
```

`Reasoning Checkpoint`: anomaly localized (stream N / inode M /
PID P / log window T)? Evidence quoted (one filter hit, one file path,
one process)? If multiple anomalies, rank by flag-pattern proximity,
queue rest. Only localized target enters Phase 3.

### Phase 3 — Negative testing (rule out red herrings)

Goal: kill the three classic traps before extraction.

1. **Encoding, not hidden?** `strings` hit inside TLS/compressed = often
   cert/template. Export + `file` must show coherent type.
2. **Overwritten, not deleted?** `icat -r` garbage = overwritten;
   switch to `blkls`/carver.
3. **Plugin lying?** `pslist` vs `psscan` mismatch = hidden proc,
   trust `psscan`+`malfind`. `netscan` empty but `cmdline` shows
   sockets = short-lived, pivot to pcap.

Negative probes:

```bash
tshark -r capture.pcap --export-objects http,./work/http 2>&1; file ./work/http/* 2>/dev/null | head
fls -d -p disk.dd | head; icat -r -o 2048 disk.dd <inode> > ./work/del.bin 2>/dev/null; file ./work/del.bin
python3 vol.py -f mem.raw windows.psscan 2>&1 | head -n 20
python3 vol.py -f mem.raw windows.malfind 2>&1 | head -n 20
```

TLS red herring: TLS traffic + no keylog -> `strings` hits are certs.
Need `SSLKEYLOGFILE` (Phase 4) or memory-carved keys. Do NOT claim.

`Reasoning Checkpoint`: false positives named and excluded with
evidence (file-type mismatch / overwritten / plugin disagreement)?
Surviving target is carve-ready? If all denied -> re-triage (wrong
evidence type or need stego skill for image payload).

### Phase 4 — Exploit, gated (ONE extraction step, <=120s)

Goal: run exactly ONE extraction. No chains inside the gate.

Pick ONE by evidence type:

Option A — pcap object export (HTTP/SMB/FTP):

```bash
mkdir -p ./work/http ./work/smb
timeout 120 tshark -r capture.pcap --export-objects http,./work/http
ls -l ./work/http
```

Option B — covert channel carve (DNS exfil / ICMP data via scapy):

```bash
timeout 120 python3 carve_covert.py capture.pcap ./work/
```

Option C — disk file carve (`icat` single inode OR carver single pass):

```bash
timeout 120 icat -o 2048 disk.dd <inode> > ./work/target.bin
# OR: timeout 120 binwalk -e --run-as=root -C ./work/carve disk.dd
```

Option D — memory dump single plugin (process memmap OR hashdump):

```bash
timeout 120 python3 vol.py -f mem.raw windows.memmap --pid <PID> --dump --dump-dir ./work/dump
```

ONE command only. `timeout 120` mandatory. Output to `./work/`.
TLS decrypt (only with `SSLKEYLOGFILE` alongside pcap):

```bash
tshark -r capture.pcap -o tls.keylog_file:./sslkey.log -Y http -T fields -e http.file_data | head
```

`Reasoning Checkpoint`: extraction exit code + `file ./work/*` type +
flag-pattern grep hit? If miss -> diagnose (wrong stream/inode/PID?)
then ONE corrected retry. No second method inside this gate.

### Phase 5 — Validation-handoff (prove provenance, package)

Goal: chain-of-custody + reproducibility.

1. `sha256sum` evidence + artifact; re-run from pristine copy, byte-identical?
2. `file` + flag-pattern grep on artifact, quoted.
3. Timeline snippet (stream/file/PID + time); handoff JSON to `results/`.

```bash
sha256sum capture.pcap disk.dd mem.raw 2>/dev/null | tee results/forensics_src.sha
sha256sum ./work/* 2>/dev/null | tee results/forensics_out.sha
file ./work/* | tee results/forensics_file.txt
grep -E -o -m3 'flag\{[^}]*\}|FLAG\{[^}]*\}|picoCTF\{[^}]*\}' -r ./work/ 2>/dev/null | tee results/forensics_grep.txt || true
```

Handoff JSON:

```json
{"chal_id":"FOR-001","etype":"pcap|disk|mem|log",
 "source_sha256":"...","method":"export-objects|scapy-carve|icat|vol-memmap",
 "filter_or_target":"tcp.stream==3 | inode 42 | PID 1337",
 "artifact":"work/target.bin","artifact_sha256":"...",
 "command":"timeout 120 tshark -r capture.pcap --export-objects http,./work/http",
 "timeline_note":"..."}
```

`Reasoning Checkpoint`: source + artifact hashes recorded? re-run
identical? command + target quoted? If yes -> done; Lead `/validate`.
If artifact empty/garbled -> `blocked` with timeline attached.

## Tool Table (exact copy-paste commands)

| Task | Command |
|---|---|
| Pcap summary | `capinfos capture.pcap` |
| Pcap stats | `tshark -r capture.pcap -q -z io,stat,0` |
| Conversations | `tshark -r capture.pcap -q -z conv,ip` |
| Proto hierarchy | `tshark -r capture.pcap -q -z io,phs` |
| Field extract | `tshark -r capture.pcap -Y dns -T fields -e dns.qry.name \| sort \| uniq -c \| sort -rn \| head` |
| Follow TCP | `tshark -r capture.pcap -q -z follow,tcp,ascii,0` |
| Follow UDP | `tshark -r capture.pcap -q -z follow,udp,ascii,0` |
| Export HTTP | `tshark -r capture.pcap --export-objects http,./work/http` |
| Export SMB | `tshark -r capture.pcap --export-objects smb,./work/smb` |
| Export FTP | `tshark -r capture.pcap --export-objects ftp,./work/ftp` |
| TLS w/ keylog | `tshark -r capture.pcap -o tls.keylog_file:./sslkey.log -Y http` |
| DNS exfil list | `tshark -r capture.pcap -Y dns -T fields -e dns.qry.name -e txt.length` |
| ICMP carve fields | `tshark -r capture.pcap -Y icmp -T fields -e data.data -e frame.time_epoch` |
| Partition layout | `mmls disk.dd` |
| List files | `fls -r -p -o 2048 disk.dd \| head -n 40` |
| Deleted only | `fls -d -p -o 2048 disk.dd \| head` |
| Inode cat | `icat -o 2048 disk.dd <inode> > ./work/out.bin` |
| Inode cat deleted | `icat -r -o 2048 disk.dd <inode> > ./work/del.bin` |
| FS detail | `fsstat -o 2048 disk.dd \| head -n 30` |
| Inode detail | `istat -o 2048 disk.dd <inode> \| head` |
| Mount ro | `mkdir -p ./mnt && mount -o ro,loop,noexec -t auto -o offset=$((2048*512)) disk.dd ./mnt` |
| Carve binwalk | `binwalk -e -C ./work/carve disk.dd` |
| Carve foremost | `foremost -i disk.dd -o ./work/foremost` |
| Carve photorec | `photorec /log /d ./work/recover /cmd disk.dd fileopt,everything,enable,search` |
| VeraCrypt mount | `veracrypt --mount --readonly --pim 0 --password-file ./pw.txt container.hc ./mnt` |
| Vol info | `python3 vol.py -f mem.raw windows.info` |
| Vol pslist | `python3 vol.py -f mem.raw windows.pslist` |
| Vol pstree | `python3 vol.py -f mem.raw windows.pstree` |
| Vol cmdline | `python3 vol.py -f mem.raw windows.cmdline` |
| Vol netscan | `python3 vol.py -f mem.raw windows.netscan` |
| Vol filescan | `python3 vol.py -f mem.raw windows.filescan` |
| Vol hashdump | `python3 vol.py -f mem.raw windows.hashdump` |
| Vol lsadump | `python3 vol.py -f mem.raw windows.lsadump` |
| Vol memmap dump | `python3 vol.py -f mem.raw windows.memmap --pid <PID> --dump --dump-dir ./work/dump` |
| Vol linux ps | `python3 vol.py -f mem.raw linux.pslist` |
| Vol linux bash | `python3 vol.py -f mem.raw linux.bash` |
| Vol linux maps | `python3 vol.py -f mem.raw linux.procmaps --pid <PID>` |
| Timeline body | `fls -r -m / -o 2048 disk.dd > body.txt; mactime -b body.txt -d \| head` |

## Code / Payload Library

Scapy covert-channel carver (DNS exfil + ICMP carve + timing-bit):

```python
# carve_covert.py — usage: python3 carve_covert.py in.pcap outdir/
import sys, base64
from scapy.all import rdpcap, DNS, DNSQR, ICMP, Raw
pcap, outdir = sys.argv[1], sys.argv[2].rstrip("/")
pkts = rdpcap(pcap)

# 1. DNS exfil: longest / most-frequent queries first
seen = {}
for p in pkts:
    if p.haslayer(DNS) and p.getlayer(DNS).qr == 0 and p.haslayer(DNSQR):
        q = p[DNSQR].qname.decode(errors="ignore").strip(".")
        seen[q] = seen.get(q, 0) + 1
cands = sorted(seen, key=lambda q: (-len(q), -seen[q]))[:20]
open(f"{outdir}/dns_queries.txt", "w").write("\n".join(f"{seen[q]} {q}" for q in cands))
with open(f"{outdir}/dns_decoded.txt", "w") as f:
    for q in cands:
        first = q.split(".")[0]
        for dec, name in ((lambda s: bytes.fromhex(s), "hex"),
                          (lambda s: base64.b32decode(s.upper()), "b32")):
            try:
                f.write(f"{name}: {dec(first)!r}\n")
                break
            except Exception:
                continue

# 2. ICMP covert channel: concatenate Raw payloads in order
icmp_bytes = b"".join(bytes(p[Raw].load) for p in pkts if p.haslayer(ICMP) and p.haslayer(Raw))
open(f"{outdir}/icmp.bin", "wb").write(icmp_bytes)
print(f"[*] icmp bytes={len(icmp_bytes)}")

# 3. Timing-bit sketch: slow delta=1, fast=0 (VERIFY threshold manually)
times = [float(p.time) for p in pkts if p.haslayer(ICMP)]
if len(times) > 8:
    deltas = [b - a for a, b in zip(times, times[1:])]
    med = sorted(deltas)[len(deltas)//2]
    open(f"{outdir}/timing_bits.txt", "w").write("".join("1" if d > med * 1.5 else "0" for d in deltas) + "\n")
```

Volatility MCP usage notes (when Volatility MCP server attached):

- Prefer MCP `vol_info` first (== `windows.info`) to lock OS/symbols;
  cache dir `./work/symbols` shared across calls.
- Map: `vol_pslist` -> `windows.pslist`, `vol_pstree`, `vol_cmdline`,
  `vol_netscan`, `vol_filescan`, `vol_hashdump`, `vol_lsadump`,
  `vol_memmap_dump(pid)` (writes to work dir, returns path).
- Always pass absolute `-f` path + `kernel` hint from `vol_info`.
- Cap at ~8 plugin calls; `psscan`+`malfind` only when `pslist` looks
  clean but challenge hints persistence/rootkit.
- MCP returns truncated rows — re-run CLI with `grep` for full carve.

GIMP-raw visual trick (hidden pixels in dumps): GIMP Open mem.raw as
Raw RGB width 1024 (try 512/2048); text/QR pops from noise. Batch:

```bash
python3 - <<'EOF'
from PIL import Image
d = open("./work/dump/proc.bin","rb").read()
for w in (512, 1024, 2048):
    h = len(d)//(w*3)
    Image.frombytes("RGB", (w, h), d[:w*h*3]).save(f"./work/raw_w{w}.png")
print("saved raw_w*.png - inspect visually")
EOF
```

Log/timeline mini-template:

```bash
fls -r -m / -o 2048 disk.dd > ./work/body.txt
mactime -b ./work/body.txt -d > ./work/timeline.csv
grep -Ei -m20 'passwd|shadow|flag|secret|\.ssh|mimikatz|nmap' ./work/timeline.csv || true
```

## Decision Tree

```text
given files?
+-- *.pcap*? 1-5 flows->follow,tcp ascii; DNS-long->scapy DNS; ICMP data->scapy ICMP;
|   HTTP/SMB/FTP->--export-objects; TLS+keylog->decrypt; TLS alone->find keys, NO brute
+-- *.dd/*.E01? partitions->fls+icat; no-FS->binwalk+foremost; VeraCrypt->mount ro (hinted pw only);
|   deleted->icat -r, garbage->blkls/photorec
+-- *.raw/*.vmem? windows.info->pslist/pstree/cmdline/netscan/filescan; linux.info->pslist/bash/procmaps;
|   evil proc->hashdump/lsadump+memmap --dump; clean-but-hinted->psscan+malfind+GIMP-raw
+-- *.log/*.evtx? grep fail/404/denied, correlate with pcap times
+-- mixed? pcap anomalies first, then mem procs, then disk files
```

## AI Automation Notes

- Worker runs ONE toolchain per task; never two writers in one `./work/`.
- Volatility: `windows.info` (else `linux.info`) first; `filescan|grep`
  early; `VOL_SYMBOL_PATH=./work/symbols`. MCP: `vol_info` first, cap 8.
- tshark: single-quote `-Y`; `-T fields -e` for machines, `-z follow`
  for humans; `mkdir -p` dest before `--export-objects`.
- `timeout 120` everything; `binwalk -e`/`foremost` can explode — quota dir + `du -sh`.
- Stop: 3 diagnosed failures -> `blocked` + timeline. No TLS/VeraCrypt brute beyond hints.
- Handoff: src+artifact sha256, filter/target, ONE timeline line, command.
- Escalate: carved image/audio -> `stego`; carved EXE -> `rev`.

## Advanced / Hard-Challenge Playbook

> Hard challenges are never one tool. They are one timeline
> across two evidence types plus one carve you have not done yet.
> If Phase 2 did not localize, do NOT carve — go advanced-identify first.

### A1 — TLS decryption with SSLKEYLOGFILE (TLS 1.2 vs 1.3)

When: `tshark -Y tls.handshake` shows ClientHello/ServerHello but
`-Y http` shows only `tls.app_data`. Bundle has `sslkey*`/`keylog*`
alongside pcap, OR a paired `*.raw/*.vmem` (keys in memory).

Key facts (SSLKEYLOGFILE line format `LABEL <rand_hex> <secret_hex>`):
TLS 1.2 = `CLIENT_RANDOM`; TLS 1.3 = `CLIENT_/SERVER_HANDSHAKE_TRAFFIC_SECRET`,
`CLIENT_/SERVER_TRAFFIC_SECRET_0`, `EXPORTER_SECRET`. Order/interleave
does not matter; cipher suite comes from the handshake. TLS 1.3 has
forward secrecy: RSA private key alone CANNOT decrypt. Session tickets /
PSKs reuse the first full-handshake secrets; mid-capture (no ClientHello)
with keys alone is NOT enough.

```bash
awk '{print $1}' sslkey.log | sort | uniq -c | sort -rn; wc -l sslkey.log
tshark -r capture.pcap -o tls.keylog_file:./sslkey.log -Y http -T fields -e frame.number -e http.host -e http.request.uri | head -n 20
tshark -r capture.pcap -o tls.keylog_file:./sslkey.log --export-objects http,./work/http_dec
tshark -r capture.pcap -Y 'tls.handshake.type==2' -T fields -e frame.number -e tls.session_id -e tls.handshake.ciphersuite | head
```

- Full handshake + matching label version -> expect cleartext. Still
  `app_data` only = wrong log, truncated log, or ECH inner hello.
- No ClientHello -> flag `resumption-without-handshake`, pivot to
  memory-key hunt. ECH/QUIC: same labels, need handshake; note and
  escalate, never brute.

Memory key hunt (paired memdump, no keylog file):

```bash
strings -n 8 mem.raw | grep -E '^(CLIENT_RANDOM|CLIENT_TRAFFIC_SECRET_0|SERVER_TRAFFIC_SECRET_0|CLIENT_HANDSHAKE_TRAFFIC_SECRET|SERVER_HANDSHAKE_TRAFFIC_SECRET)' | head
strings -n 16 mem.raw | grep -Ei 'master secret|key expansion|traffic secret' | head -n 20
```

Carve 64+ hex-char blobs on the same 4 KB page as each label hit,
rebuild `LABEL rand secret` lines to `./work/candidate_keylog.txt`,
trial-decrypt once per set. HKDF label fragments (`c hs traffic` style)
mark the derivation function, not the key — use them only to locate the
page, then carve adjacent high-entropy blobs.

`Reasoning Checkpoint`: label set (1.2 vs 1.3) + handshake presence +
decrypt hit/miss quoted? Miss -> wrong-log vs mid-capture vs ECH first.

### A2 — USB HID keystroke decode (HID usage tables)

When: pcap has `usb`/`usbhid`/`usb.capdata` frames. NOT network traffic.
Boot report (8 bytes): byte 0 modifier bitmap (Shift test `mod & 0x22`),
byte 1 reserved `00`, bytes 2-7 up to six usage IDs (`04`=a ... `1D`=z,
`1E`=1, `28`=Enter, `2C`=Space, `2A`=Backspace, `00`=empty). IDs are
physical positions, not glyphs (layout-dependent).

Isolate keyboard first — composites mix mouse/storage:

```bash
tshark -r usb.pcap -Y 'usb.data_len==8' -T fields -e usb.src -e usb.capdata 2>/dev/null | sort | uniq -c | sort -rn | head
tshark -r usb.pcap -Y 'usb.capdata && usb.data_len==8 && usb.src==1.5.1' -T fields -e usb.capdata > ./work/hid_hex.txt
```

Valid keyboard: 8-byte reports, byte 1 `00`, idle all-zero frames present,
key bytes within `00-E7`. Pin `usb.src` tuple before decoding. Prefer
`usbhid.data` when dissected, else `usb.capdata`. Non-8/missing-reserved
reports have a report-ID prefix — strip via offset, never force 8-byte map.

Decode with edge detection (emit only newly-pressed vs previous report):

```python
# hid_decode.py — python3 hid_decode.py work/hid_hex.txt
import sys
HID={0x04:'a',0x05:'b',0x06:'c',0x07:'d',0x08:'e',0x09:'f',0x0a:'g',0x0b:'h',0x0c:'i',0x0d:'j',0x0e:'k',0x0f:'l',0x10:'m',0x11:'n',0x12:'o',0x13:'p',0x14:'q',0x15:'r',0x16:'s',0x17:'t',0x18:'u',0x19:'v',0x1a:'w',0x1b:'x',0x1c:'y',0x1d:'z',0x1e:'1',0x28:'\n',0x2c:' ',0x2a:'<BS>',0x39:'<CAPS>'}
SH={'1':'!','2':'@','3':'#','4':'$','5':'%','6':'^','7':'&','8':'*','9':'(','0':')','-':'_','=':'+'}
last=set();caps=False;out=[]
for line in open(sys.argv[1]):
    h=line.strip().replace(':','')
    if len(h)<16: continue
    raw=bytes.fromhex(h[:16]);mod,keys=raw[0],[b for b in raw[2:] if b]
    if 0x39 in keys and 0x39 not in last: caps=not caps
    for k in keys:
        if k in last: continue
        g=HID.get(k,f'<{k:02x}>')
        if g=='<BS>': out.pop() if out else None; continue
        if len(g)==1 and g.isalpha(): g=g.upper() if (bool(mod&0x22)^caps) else g.lower()
        elif bool(mod&0x22) and g in SH: g=SH[g]
        out.append(g)
    last=set(keys)
print(''.join(out))
```

### A3 — Bluetooth / BLE capture basics

When: `btatt`/`btle`/`bthci` protocols or sniffer exports.

```bash
tshark -r bt.pcap -Y btatt -T fields -e frame.number -e btatt.handle -e btatt.value | head -n 20
tshark -r bt.pcap -Y btle -T fields -e frame.number -e btle.advertising_address | head -n 20
```

- BLE HID keyboards tunnel over GATT: dump `btatt.value` per handle,
  reuse the HID decoder on the 8-byte-report handle. Classic file/audio
  via `btavdtp`/`obex` carve (`-e data.data`, frame order). Encrypted BLE
  with missing LTK = stop, no brute (same rule as TLS without keys).

### A4 — NTFS ADS + journal ($LogFile / $UsnJrnl) carving

ADS (`file.txt:hidden`) is invisible to `fls`. `istat` lists `$DATA`
attributes; extras beyond `(unnamed)` are ADS candidates:

```bash
istat -o 2048 disk.dd <inode> 2>/dev/null | head -n 40
icat -o 2048 disk.dd <inode>-128-3 > ./work/ads.bin 2>/dev/null; file ./work/ads.bin
```

`$Extend/$UsnJrnl:$J` survives deletion and exposes timestomp
(`BASIC_INFO_CHANGE` at capture time vs claimed-old MACE = manipulation):

```bash
fls -r -p -o 2048 disk.dd 2>/dev/null | grep -Ei -m10 'UsnJrnl|LogFile' || true
icat -o 2048 disk.dd <usnjrnl-inode> > ./work/usnjrnl.bin
strings -n 6 ./work/usnjrnl.bin | grep -Ei -m20 '\.zip|\.pcap|\.txt|\.exe' || true
```

Journal rolls (tens of MB, recent only); carving rolled-over records from
unallocated is slow — gate behind Phase-2 filename need. `$LogFile`
replays recent metadata ops: `strings` + filename grep first, full parse
only on a hit.

### A5 — Deleted-file reassembly across fragments

`icat -r` garbage/truncated = fragmented or overwritten. Drop to block
level, do NOT re-run `icat`:

```bash
istat -o 2048 disk.dd <inode> 2>/dev/null | grep -Ei -A30 'sector|block|run' | head -n 40
```

Reassemble in `istat` run order (`blkcat -o OFF disk.dd <blk> >> out.bin`
per run), NOT numeric order. Endianness trap: headers (`PK`, `%PDF`)
read little-endian — a byte-swapped header means a wrong offset, never
byte-swap the file. Validate by `file` + structure (`unzip -l`), not
`strings`. Overwritten first block + intact tail = graft a same-version
header and note the graft.

### A6 — RAID / stripe reassembly concept

Suspect when `mmls` shows no partitions but `binwalk` magic repeats at
regular intervals, or members named (`disk0.dd`, `disk1.dd`). Never brute
stripe size — read hints/`mdadm --examine`/LVM metadata first. Concept: N
disks, stripe S, row-major interleave; reassemble chunks in stripe order,
then `mmls` the logical image (copies only). No metadata + no hint =
`blocked` with interval evidence (insane-tier sink, not a carve).

### A7 — Memory C2 extraction (netscan to strings to config)

Pattern: odd process + foreign socket + encoded blob. Fixed order — net,
then process, then strings (never strings-first on GB dumps):

```bash
python3 vol.py -f mem.raw windows.netscan 2>&1 | head -n 30
python3 vol.py -f mem.raw windows.cmdline 2>&1 | grep -Ei -m10 'powershell|rundll|svchost|python|curl|wget' || true
python3 vol.py -f mem.raw windows.memmap --pid <PID> --dump --dump-dir ./work/c2dump
strings -n 6 ./work/c2dump/* | grep -Ei -m30 'http|beacon|sleep|jitter|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -n 30
```

Linux: `linux.sockstat` + `linux.netstat` + `linux.envars --pid` (env
often holds the URL/token). TIME_WAIT without live PID = terminated C2 —
correlate port/time with pcap. Encrypted config without key -> `/crypto`
with blob + context, not the whole dump.

### A8 — Process-hollowing indicators (malfind to dump to strings)

Hollowing = legitimate name, alien body. `pslist` clean, memory truthful:

```bash
python3 vol.py -f mem.raw windows.psscan 2>&1 | head -n 20
python3 vol.py -f mem.raw windows.malfind --pid <PID> --dump --dump-dir ./work/malfind 2>&1 | head -n 30
python3 vol.py -f mem.raw windows.ldrmodules --pid <PID> 2>&1 | head -n 20
strings -n 6 ./work/malfind/* | grep -Ei -m30 'MZ|http|powershell|VirtualAlloc|CreateRemote' | head -n 30
```

`malfind` RWX-without-file = injection; `ldrmodules` all-False = stealth
DLL; PEB ImageBase != VAD image = hollowed. Confirm by `.text` vs on-disk
PE (header/SizeOfImage/entry-point mismatch), then `strings`/YARA on the
dump only. 32-on-64 needs matching symbols — mismatch mimics hollowing.

### A9 — SQLite WAL recovery (deleted rows live in -wal / -journal)

Live `.db` looks empty because deletes live in sidecars. Opening the
original CHECKPOINTS and destroys evidence — work ONLY on `./work/` copies:

```bash
cp victim.db ./work/victim.db; cp victim.db-wal ./work/victim.db-wal 2>/dev/null; cp victim.db-journal ./work/victim.db-journal 2>/dev/null
sqlite3 ./work/victim.db "SELECT name FROM sqlite_master WHERE type='table';"
```

No `-wal` but `-journal` present: journal holds the BEFORE-image of the last
transaction (inverse of WAL) — diff vs live db. No sidecars: carve freelist /
freeblocks (`strings -t d`). WAL has NO wall-clock time, only commit sequence —
order by commit, take times from `mactime`/pcap, never invent them.

### A10 — VMEM snapshot diffing

Two snapshots (`before`/`after`): diff, do not analyze twice.

```bash
python3 vol.py -f before.vmem windows.pslist 2>&1 | sort > ./work/ps_before.txt
python3 vol.py -f after.vmem windows.pslist 2>&1 | sort > ./work/ps_after.txt
diff -u ./work/ps_before.txt ./work/ps_after.txt | head -n 40
python3 vol.py -f before.vmem windows.netscan 2>&1 | sort > ./work/net_before.txt
python3 vol.py -f after.vmem windows.netscan 2>&1 | sort > ./work/net_after.txt
diff -u ./work/net_before.txt ./work/net_after.txt | head -n 40
```

New PID + new socket in `after` only = implant window; dump only the delta
PID. Tool-dumped RAM smears (threads writing mid-dump) mimics hiding —
re-run `psscan` before claiming a rootkit.

`Reasoning Checkpoint`: advanced trigger named (no-cleartext / usb frames /
ADS hint / WAL trio / snapshot pair) + one targeted command? No trigger ->
back to Phase 2, no advanced carve.

## Multi-Step Chains (abstract patterns — technique only)

Each arrow is ONE gated Phase-4 step with its own validate. Re-baseline
between arrows; never chain inside one command.

### Chain 1 — pcap + memdump to TLS keys to exfil file

`capture.pcap (TLS only) + mem.raw (same host) -> keylog -> decrypt -> file`

1. Pcap: TLS dominance, handshake present, no cleartext. Mem:
   `windows.netscan` shows same endpoint/port (else STOP, unpaired).
2. Negative: `app_data` `strings` = certs until proven otherwise.
3. Gate 1 — carve keylog candidates from mem to
   `./work/candidate_keylog.txt`. Gate 2 — trial decrypt
   (`-o tls.keylog_file:`) + `--export-objects`. Gate 3 — `file` +
   pattern grep on export only. 2 bad sets -> re-confirm pairing;
   3rd miss -> `blocked`. Never brute suites.

### Chain 2 — disk to deleted zip to inner pcap

`disk.dd (deleted archive) -> icat/blkls -> crack (hinted) -> inner pcap`

1. Gate 1 — `icat -r` (or `blkls`-ordered rebuild if fragmented) to
   `./work/stage.zip`; `file` + `unzip -l` must validate BEFORE any crack
   (`unzip -l` fails = overwritten/false header, back to carver).
2. Gate 2 — crack ONLY hinted scope (wordlist slice / hinted token).
   Zip-bomb guard: check `unzip -l` sizes + quota dir first.
3. Gate 3 — inner pcap covert carve (DNS/ICMP path). `sha256sum` per gate.

### Chain 3 — disk SQLite to deleted row to pcap stream

`disk.dd (.db + -wal) -> deleted URL row -> pcap stream`

1. Gate 1 — WAL-aware query on the COPY recovers deleted host/token row.
2. Gate 2 — hostname becomes pcap filter; follow + export that stream.
3. Validate commit order vs pcap time order (UTC-normalized). No WAL and
   no freelist hits -> close chain, pivot to journal/USN or escalate.

## Failure-Mode Catalog + Recovery

| # | Failure | Detection | Recovery |
|---|---|---|---|
| F1 | Wrong endianness / offset in carve | Header near-miss (`K\x03\x04P`, `%DPF`), `file` says `data`, sizes absurd | Re-check `fsstat` block size + `mmls` Start; `blkcat` one block and hexdump before bulk carve. Never byte-swap output to force a match. |
| F2 | Vol profile / symbol mismatch | `windows.info` errors, empty `pslist` on a known-good dump, `ISF` / symbol warnings | Fallback ladder: `windows.info` -> `linux.info` -> `banners` plugin -> `VOL_SYMBOL_PATH=./work/symbols` refresh -> CLI re-run with absolute `-f`. Never hand-edit symbol JSON. Cap 3 attempts, then note mismatch in handoff. |
| F3 | Encrypted volume (BitLocker/LUKS/VeraCrypt) | `file` says `data`, `binwalk` flat, `fls` fails on all offsets, LUKS header / VeraCrypt salt visible in hexdump | Key-hunt checklist (in order): challenge text/hints, companion memdump `strings` (BitLocker recovery key / LUKS passphrase / `.hc` password), `hashdump`/`lsadump` output, `cmdline`/`bash` history, sidecar `*.txt/*.log`. Hinted password only; no brute beyond hint scope. Still stuck -> `/crypto` with header bytes + hunt log. |
| F4 | Huge pcap (GBs) kills analysis | `capinfos` shows millions of packets / GB size; full `-V` or Wireshark GUI hangs | Field-first, never full `-V`: `capinfos`, `-z io,stat`, `-z conv,ip`, `-T fields` with `head`, per-stream `tcp.stream==N`. `timeout 120` + `head -n` on every pass. Split by `editcap -c` only when a stream range is proven. |
| F5 | Timezone confusion in timelines | `mactime -d` vs pcap `frame.time_epoch` vs log timestamps disagree by hours; correlation looks off-by-N | Normalize to UTC epoch everywhere: `mactime -b body -d` + `tshark -e frame.time_epoch`, convert logs with explicit zone (`date -u -d`). Quote the zone in every timeline note. Never mix local + UTC in one diff. |
| F6 | Mixed USB devices decoded as one | Decoded text is gibberish despite valid HID table; multiple `usb.src` values present | Split by `usb.src` tuple first, decode per-device files separately. Re-check `usbhid.data` vs `usb.capdata` field choice and report-ID offset. |
| F7 | SQLite opened in place, WAL lost | `-wal` shrank to 0 after opening original; deleted rows unrecoverable | Restore from pristine copy (hence pre-copy hashes), redo on `./work/` copy with `PRAGMA query_only=ON` or `wal_checkpoint` on copy only. Record checkpoint state in handoff. |

Each failure: ONE corrected retry with the recovery command,
then ONE alternate method max. Third strike -> `blocked` with
detection evidence attached (error line + command + hash).

## Version-Drift Guards

Volatility 2 vs 3 — never mix syntax:

| Task | Volatility 2 (legacy) | Volatility 3 (current) |
|---|---|---|
| Identify | `imageinfo` + `--profile=Win7SP1x64` | `windows.info` (auto symbols), `linux.info` / `banners` |
| Processes | `pslist`, `pstree`, `psscan` | `windows.pslist`, `windows.pstree`, `windows.psscan` |
| Net | `netscan`, `connections` | `windows.netscan`, `windows.netstat` |
| Creds/inject/files | `hashdump`, `malfind`, `filescan` | `windows.hashdump`, `windows.malfind`, `windows.filescan` |
| Linux | `linux_pslist`, `linux_bash` | `linux.pslist`, `linux.bash`, `linux.procmaps`, `linux.envars` |

Vol3 needs `VOL_SYMBOL_PATH=./work/symbols`; `windows.info` failure usually
means Linux image or bad dump — try `linux.info` first. `--profile` errors
on a Vol3 binary = wrong version, not a bad image.

tshark drift: display filter is `-Y` (not dead `-R`); keylog pref is `-o
tls.keylog_file:<path>` (old `ssl.` spelling fails quiet); `--export-objects`
needs pre-created dir (`mkdir -p`, then `ls -l`); if `-e <field>` is empty,
list with `tshark -G fields | grep -i <proto>` (`usb.capdata` vs `usbhid.data`
depends on dissector).

SleuthKit: `-o` takes sectors (bytes need `$((OFF*512))` for mount);
`icat -r` flag = deleted; `mmls` Start is decimal sectors (GPT backup may
shift by 1 on truncated images). On flag errors (not data errors): paste
`tshark -v; fls -V; vol.py --help | head` versions into the handoff.

## Time-Budget Tiers

Carving is slow; timeline is cheap.

- Easy (single evidence, <=15 min): baseline 3 -> confirm 5 -> 1 extraction
  5 -> handoff 2. 1 retry max. No carvers/WAL/RAID. Miss -> re-triage once,
  then `blocked`.
- Medium (paired/covert, <=45 min): baseline 10 -> confirm+negatives 15 ->
  up to 2 gated extractions 15 -> handoff 5. 2 retries max. Carvers single
  pass with quota dir.
- Hard (TLS+mem, fragmented, USB, <=2 h): identify 20, timeline 30,
  carve/decrypt 45, validate 15, buffer 10. ONE advanced branch at a time
  (ranked by Phase-2 signal). Full-disk `photorec`/`blkls` only here with
  `timeout` + `du -sh`. 3 diagnosed failures -> `blocked`.
- Insane (multi-GB, RAID, custom crypto, keyless ECH): 15-min spike proving
  or killing ONE hypothesis, then escalate with spike log. Never burn 2 h
  on unbounded carve/brute.

Stop rules: timebox hit with no localized target (stream/inode/PID/row) =
stop and report the timeline. Same `timeout 120` exceeded twice = input too
big for this tier; split or escalate.

## Escalation Triggers

- To `/stego`: carved artifact is image/audio/video AND shows trailing blob,
  appended zip, or GIMP-raw structure. Hand over file path + sha + carve
  command, never the whole disk. No steg tools here.
- To `/crypto`: coherent encrypted blob (high entropy, ZIP-crypto/OpenSSL/
  LUKS header) AND F3 key-hunt log exhausted. Hand over blob path + header
  hex + hint scope. No brute beyond hint slice.
- To operator: input >2 GB, upload/egress needed, interactive password mount,
  or `photorec` exploding past quota. Ping with size + `du -sh` + hashes +
  exact need. Keep solving unblocked work.
- To `/rev`: carved ELF/PE with C2-ish strings. Hand over path + strings +
  owning PID/stream. Do NOT execute.
- Every escalation: chal id, evidence hashes, timeline line, commands run,
  stop reason, artifact path.

## Worked End-to-End Example (abstracted, technique-only)

Synthetic: `capture.pcap` (DNS-heavy) + `disk.dd` (one deleted archive).
Technique only, no flag values.

1. Baseline (5 min): `capinfos` 90% DNS, one bursty pair; `mmls`/`fls -d`
   one deleted `stage.zip`. Hash both. Rank pcap-first (DNS anomaly).
2. Confirm (10 min): `tshark -Y dns -T fields -e dns.qry.name | sort |
   uniq -c | sort -rn` isolates long-label host; scapy sketch decodes one
   encoding (other fails closed). `istat` shows contiguous runs.
3. Negative (5 min): labels are length/frequency outliers (not noise);
   `unzip -l` on `icat -r` output sane (not overwritten); no TLS confusion.
4. Exploit, gated: Gate 1 — `timeout 120 python3 carve_covert.py
   capture.pcap ./work/`; re-baseline. Gate 2 — `timeout 120 icat -o
   <OFF> disk.dd <inode> > ./work/stage.zip` + `unzip -l` (fragmented ->
   `blkls`-ordered rebuild, still one gate).
5. Validate: `sha256sum` + `file`, pattern-match count only, UTC timeline
   (`frame.time_epoch` + `mactime -d`), handoff JSON, re-run byte-identical.
   Miss at any gate returns to its own Phase-2 slice, never restarts all.

---

*Technique-only reference. No real flags contained. Tool syntax verified
 2026-10 against tshark/capinfos man pages, SleuthKit mmls/fls/icat docs,
 Volatility3 windows-tutorial, scapy API.*

## Writeup-Distilled Patterns (W1..W32)

> Mined from `knowledge/writeups_mined/forensics_manifest.md` (400+ HARD-first
> writeups, 2022-2026). Each pattern adds what Phases/A1-A10 do NOT cover.
> Technique-only: recognition signals -> exact steps -> commands -> pitfalls.

### W1 — Keylog/handshake pairing proof (TLS)
- Signals: keylog file present BUT decrypt still shows `app_data`; or two candidate logs.
- Steps: 1. Histogram labels (`awk '{print $1}' | sort | uniq -c`) to lock 1.2 vs 1.3. 2. Confirm the log's `CLIENT_RANDOM` values appear in `tls.handshake.random` of the pcap. 3. Only then trial-decrypt; else flag wrong-log vs mid-capture vs ECH.
- Commands: `tshark -r c.pcap -Y tls.handshake -T fields -e tls.handshake.random | sort -u > hello.txt` + `cut -d' ' -f2 log | sort -u > keys.txt` + `grep -F -f hello.txt keys.txt | head`
- Pitfalls: order/interleave of log lines is irrelevant; cipher comes from handshake; mid-capture without ClientHello is unrecoverable from log alone.
- Sources: https://qiaonpc.github.io/post/call-for-protocols/ https://sayonara.gitbook.io/writeups/ctf/cybercoliseum-ii-ctf-2023/forensics/encrypted-traffic https://ctftime.org/writeup/38682

### W2 — Session-ID-anchored master-key carve (coredump/mem)
- Signals: pcap + coredump/memdump pair, TLS only, no keylog file.
- Steps: 1. Read Session-ID from ClientHello/ServerHello. 2. Byte-search dump for it. 3. In OpenSSL `ssl_session_st`, `master_key[48]` sits immediately BEFORE `session_id[32]` — read 48 prior bytes. 4. Emit `RSA Session-ID:<hex> Master-Key:<hex>` trial log.
- Commands: `tshark -r c.pcap -Y 'tls.handshake.type==2' -T fields -e tls.handshake.session_id | head -1` + `python3 -c "d=open('core','rb').read();i=d.find(bytes.fromhex('SID'));open('k','wb').write(d[i-48:i])"`
- Pitfalls: struct layout is version-specific; one bad anchor poisons every trial set — verify by decrypt-hit, never by eyeball.
- Sources: https://github.com/ljagiello/ctf-skills/blob/HEAD/ctf-forensics/network.md https://ctftime.org/writeup/38682

### W3 — RSA-key decrypt scope gate (TLS)
- Signals: `BEGIN PRIVATE KEY` alongside TLS pcap.
- Steps: 1. Check negotiated suite (`tls.handshake.ciphersuite`): RSA-kx only decrypts with the key; ECDHE/DHE suites NEVER will. 2. RSA-kx path: load via RSA-keys-list, follow stream. 3. Weak-cert path: extract cert, factor modulus, rebuild key, then step 2.
- Commands: `tshark -r c.pcap -Y tls.handshake -T fields -e tls.handshake.ciphersuite | sort | uniq -c | sort -rn | head`
- Pitfalls: TLS 1.3 + RSA key = guaranteed miss; do not brute suites.
- Sources: https://tribbletron.gitbook.io/cyber/ctfs/us-cybergames-iv-2024/uscg-iv-forensics https://andrejtopalov.medium.com/ctf-challenge-writeup-picoctf-webnet1-8e76a3e3f926

### W4 — Descriptor census + direction gate (USB)
- Signals: any USB pcap before HID decode is attempted.
- Steps: 1. Enumerate devices via GET DESCRIPTOR responses (`idVendor/idProduct/bString`) — keyboard vs mouse vs storage vs BT. 2. Pin `usb.src` tuple. 3. Filter direction: keyboard-to-host only (`URB_COMPLETE` / device-to-host interrupt), drop empty polls later at decode.
- Commands: `tshark -r u.pcap -Y 'usb.bDescriptorType==1' -T fields -e usb.src -e usb.idVendor -e usb.idProduct -e usb.product | sort -u`
- Pitfalls: decoding before census mixes mouse/storage frames into keyboard text; `Leftover Capture Data` vs `Hidden Data` field names differ by dissector.
- Sources: https://medium.com/@polygonben/hackthebox-blue-team-track-logger-19525940794a https://sutharnisarg.medium.com/umdctf-2022-write-ups-c45cdef017bb

### W5 — HID state-machine decode (press/release/BS/Caps)
- Signals: keyboard HID stream isolated.
- Steps: 1. Edge-detect: emit only newly-pressed usages vs previous report; all-zero = release, ignore. 2. Apply Backspace-pop, CapsLock-toggle, Shift-symbol map. 3. Collapse key-repeat runs only when no release frame intervenes.
- Commands: `tshark -r u.pcap -Y 'usb.capdata && usb.data_len==8' -T fields -e usb.capdata | sed 's/../:&/g2' > hid.txt` then parser per A2.
- Pitfalls: holding a key re-emits same usage (doubles output); `0x2a` mid-flag deletes a real char if mishandled; `-` vs `_` style fixes are layout bugs, not flag bugs.
- Sources: https://skillbit.com/blogs/flash-ctf-key-evidence https://rajindu0x.github.io/posts/Logger/ https://0xh4lpy.medium.com/keyboard-junkie-writeup-huntress-ctf-2024-ab8cbec6a687

### W6 — Layout-aware + BadUSB-behavior read (USB)
- Signals: decoded text near-miss on punctuation; or keyboard types fast, executable-like lines.
- Steps: 1. Swap HID table to victim layout (e.g. AZERTY position map) and re-decode. 2. Treat typed download+exec lines as BEHAVIOR: fetch the referenced payload out-of-band, hash it (`md5sum`), answer from payload properties.
- Commands: `tshark -r u.pcap -Y usbhid.data -T fields -e usbhid.data > k.txt` + layout-table re-run.
- Pitfalls: usage IDs are positions, not glyphs; Shift-layer differs per layout; never execute the payload, only hash/inspect.
- Sources: https://writeups.cycomhackingconference.com/posts/2024/010-mechantusb/ https://encient.github.io/ctf/2023/gctf-2023/kb/

### W7 — Steno-chord recognition (USB HID)
- Signals: MANY simultaneous usages per report (6-key rollover peaks), sinusoidal press pattern, not typing rhythm.
- Steps: 1. Extract per-report key SETS (not sequences). 2. Split overfull strokes via arpeggiate rule (hardware 6-key cap splits one logical chord). 3. Translate via Plover/st­eno dictionary, mapping Backspace/Space/Enter to word ops.
- Commands: `tshark -r u.pcap -Y 'usb.transfer_type==1' -T fields -e usb.capdata > chords.txt`
- Pitfalls: typing-decoders produce garbage here by design; `TPR*BG`-style closers need dictionary lookup, not guessing.
- Sources: https://nightxade.github.io/ctf-writeups/writeups/2024/UT-CTF-2024/forensics/gibberish.html https://github.com/ljagiello/ctf-skills/blob/HEAD/ctf-forensics/network.md

### W8 — Mouse-draw recovery (relative vs absolute)
- Signals: USB mouse/pen/gamepad movement frames; or undecoded "HID data" with button bytes.
- Steps: 1. Determine report geometry: relative deltas (signed x/y accumulate) vs ABSOLUTE (VM/tablet: LE-u16 nibble fields, pen-down/pen-up sentinel frames gate drawing). 2. Integrate deltas (signed!) or plot absolutes (/N downscale). 3. Stroke-split by velocity threshold; color-code strokes; flip Y if mirrored.
- Commands: `tshark -r m.pcap -T fields -e usbhid.data -Y usbhid.data > mouse.txt` then PIL/matplotlib accumulate-and-plot.
- Pitfalls: unsigned-delta math mirrors/shears the drawing; always-on-button drags connect separate strokes; controller sticks need center-offset + button-gate, not raw plot.
- Sources: https://ctftime.org/writeup/33625 https://merzoug-rayane.com/cyber/writeups/eh4x_CTF/painter https://github.com/barrettotte/cyber-archive/blob/master/ctf/patriot-ctf-2024/forensics/unsolved/secret-note/README.md https://ctftime.org/writeup/33279 https://snakectf.org/writeups/2023/misc/black-rat

### W9 — USB bulk-file carve + matryoshka recursion
- Signals: USB pcap with one giant packet (bulk OUT/IN) or Leftover Data with magic (`%PDF`, gzip, 7z, pcapng).
- Steps: 1. Length-sort packets, export the outlier's bytes, trim to magic..EOF. 2. Identify layer, extract, REPEAT (gzip->pcapng->7z->tar->zip chains); trim trailing garbage per layer. 3. `file` + structural open per layer before next carve.
- Commands: `tshark -r u.pcap -T fields -e usb.capdata > bulk.txt` + `binwalk -D='.*' layer.pcapng` fallback.
- Pitfalls: carving the wrong layer's tail corrupts every deeper layer; verify each layer opens before descending.
- Sources: https://blog.reinom.com/ctf/404ctf/2025/forensics/USB-51 https://ctftime.org/writeup/40404 https://ctftime.org/writeup/39364 https://warlocksmurf.github.io/posts/crewctf2024/

### W10 — USB isochronous audio + matrix-keyboard decode
- Signals: `URB_ISOCHRONOUS` packets (audio/video class) or vendor HID with command bytes + matrix maps.
- Steps: 1. Audio: carve `usb.iso.data`, concat, `xxd -r -p`, import raw into Audacity, tune rate, listen. 2. Matrix-kb: map command-ID (e.g. vendor SET_TRAVAL) + row_mask bit-matrix through device keymap (check vendor QMK/firmware sources).
- Commands: `tshark -r t.pcap -T fields -e usb.iso.data | tr -d '\n' | xxd -r -p > audio.raw`
- Pitfalls: wrong Audacity import rate = chipmunks, not evidence; matrix decode without the vendor map is guessing.
- Sources: https://metactf.com/blog/flash-ctf-talk-to-me/ https://github.com/dbissell6/DFIR/blob/main/WalkThroughs/BuckeyeCTF2024.md

### W11 — OSK-click overlay (mouse-as-keyboard)
- Signals: mouse-only capture + "typed" narrative + gaming-mouse device.
- Steps: 1. Decode movement to CSV (relative deltas accumulate). 2. Take falling edges of left-hold as clicks. 3. Overlay click sequence on on-screen-keyboard image; scale/rotate to fit; honor Shift-state rows for capitals/symbols.
- Commands: USB-Mouse-Pcap-Visualizer pcap-to-CSV, then matplotlib fade-plot over OSK image.
- Pitfalls: relative coords need an anchor (flag-prefix row); Shift-clicks cluster in corners — expected, not noise.
- Sources: https://metactf.com/blog/flash-ctf-huntandpeck/ https://github.com/WangYihang/USB-Mouse-Pcap-Visualizer

### W12 — BLE GATT challenge-response + live replay
- Signals: tiny BLE pcap (reads/writes on handles like 0x2a/0x48/0x39) + reachable device.
- Steps: 1. Map handles: nonce-read, response-write, result-read (value handle = decl+1). 2. Derive response from nonce (observed: MD5(nonce) byte-reversed). 3. Replay against LIVE device: read fresh nonce, compute, write, read result.
- Commands: `gatttool -b MAC -I --sec-level=high` + `char-read-hnd` / `char-write-req` cycle.
- Pitfalls: pcap nonces are stale — replaying pcap bytes fails; strip ATT opcode/handle prefix bytes before hashing.
- Sources: https://cryptax.github.io/hardweario2022-bele/ https://siunam321.github.io/ctf/BuckeyeCTF-2022/Misc/keyboardwarrior/ https://lessonsec.com/posts/walkthrough-ble-ctf/

### W13 — BLE encrypted-link crack (crackle) + DLT fix
- Signals: encrypted BLE connection, TK/LTK unknown.
- Steps: 1. Try `crackle -i in.pcapng -o out.pcap` (TK=0 first). 2. On `Frames inside PCAP not supported (BLUETOOTH_LE_LL)`, switch to the fork supporting that DLT and re-run. 3. Read LTK from output, open decrypted pcap, hunt `btatt` value/offset rebuilds.
- Commands: `crackle -i BLE.pcapng -o dec.pcap` + `tshark -r dec.pcap -Y 'btatt.opcode==0x16' -T fields -e btatt.value -e btatt.offset`
- Pitfalls: pairingUpdSc `Missing Mrand/Srand/LL_ENC_REQ` = uncrackable capture, stop; `strings` the decrypted pcap before deep parse.
- Sources: https://blog.jloh02.dev/ctf/stack-the-flags-2022/ https://sumygg.com/2023/05/06/mi-ctf-2023-writeup/index.html https://ctftime.org/writeup/30871

### W14 — BLE audio + advertiser/att-handle carve
- Signals: HCI/L2CAP-only capture (handsfree/audio narrative) or ADV_IND + att-handle writes (bulb/IoT narrative).
- Steps: 1. Audio: `Decode As BT A2DP`, confirm SBC layers + `0x9c` syncwords, tshark-extract frames per connection-id, strip per-packet header, concat `.sbc`, `ffmpeg` to wav, listen. 2. IoT: fix `DLT_USER=btle` decode, ADV_IND device-name, `btatt.handle==X` color-write hunt, rebuild command + recompute checksum.
- Commands: `tshark -r bt.pcap -x -T json -n <conn-filter> >> sbc.json` then python frame-join.
- Pitfalls: wrong profile decode = plausible-looking garbage; verify incrementing RTP/time fields before carving.
- Sources: https://www.botanica.software/blog/unraveling-the-bluetooth-enigma-extracting-the-flag-from-bsides-tlv-2022-ctf https://blog.0x7d0.dev/writeups/hackfest-ctf-2022/internet-of-torments-2-0/ https://medium.com/@anantniteshjain/bluetooth-for-the-win-shunya-ctf-arambha-writeup-c5d1134e78f0

### W15 — MFT resident carve via entry-arithmetic + unzip-chain grouping
- Signals: raw `$MFT` + staged archives (Drive-link zip -> zip -> zip -> stager).
- Steps: 1. MFTECmd -> CSV -> Timeline Explorer; group by Parent Path to rebuild the unzip chain; `Zone.Identifier` HostUrl = download IOC. 2. For sub-~900B files: `offset = EntryNumber * 1024`, hex-jump, carve inline bytes (bat/zip reconstructible). 3. Over-size files absent from MFT = expected, pivot to disk.
- Commands: `MFTECmd.exe -f '$MFT' --csv out` + `python3 -c "open('f','wb').write(open('MFT','rb').read()[ENTRY*1024:ENTRY*1024+SIZE])"`
- Pitfalls: Created0x10 vs 0x30 skew is normal for unzipped files, not proof of anything alone; ADS `IsAds` rows double-count filename hits.
- Sources: https://0xdf.gitlab.io/2024/04/17/htb-sherlock-bft.html https://tmechen.me/posts/ctf/sherlock/hyperfiletable/ https://prajshete17.medium.com/writeup-htb-sherlocks-nuts-medium-4748c61804f1

### W16 — Zone.Identifier/MotW as download evidence
- Signals: downloaded stager + "where did it come from" question.
- Steps: 1. Read `ZoneIdContents` (ZoneId=3 internet + HostUrl) from MFT/ADS. 2. Corroborate with Sysmon EID15 (FileCreateStreamHash = MotW attach moment). 3. Remember renames PRESERVE the stream — hunt old names via Zone-Id-Contents filter.
- Commands: `Get-Item file -Stream *` / `more < file:Zone.Identifier` (cmd) or MFT `ZoneIdContents` column filter.
- Pitfalls: Zone data is hit-and-miss per content type — absence is not alibi; FAT/exfil copies strip all streams.
- Sources: https://www.dariocruz.dev/blog/Unit42-Sherlock https://forum.hackthebox.com/t/rapid-triage-examination-and-analysis-tool/307539

### W17 — ADS/EA split-file rebuild at scale
- Signals: NTFS image, N decoy files, "hidden part" narrative, per-file hex fragments.
- Steps: 1. Mount with streams visible (`-o stream_interfaces=windows`) or 7z-extract to Windows. 2. Enumerate per-file streams (`Get-Item * -Stream *` / `getfattr -d`). 3. Concat fragments in index order, strip newlines, hex-decode to file, validate by open/render.
- Commands: `mount -t ntfs -o stream_interfaces=windows img /mnt; for i in $(seq -w 0 99); do getfattr -d /mnt/flag$i.txt; done`
- Pitfalls: Linux without stream_interfaces shows decoys only; `strings`-only path skips ordering and breaks on newline-sensitive payloads.
- Sources: https://github.com/TCP1P/TCP1P-CTF-2023-Challenges/tree/main/Forensic/hide%20and%20split/writeup https://ctftime.org/writeup/38010

### W18 — Journal sequencing ($J/$LogFile + entry links)
- Signals: download/move/delete timeline questions on NTFS.
- Steps: 1. Parse `$MFT` + `$J` (MFTECmd) and `$LogFile` (tracker). 2. Download window = `.crdownload`/`.tmp` birth..rename pair. 3. Moves = EntryNumber/ParentEntryNumber chain walk. 4. Deletion = `$J` record time. 5. Cross-check `WordWheelQuery` for user-typed corroboration.
- Commands: `MFTECmd.exe -f '$J' --csv J` + filter `RenameOldName`/crdownload/tmp in Timeline Explorer.
- Pitfalls: Created-times within milliseconds = bulk copy, not human action; journal rolls — old events are gone, say so.
- Sources: https://hackmd.io/@M4shl3/ISITDTU-CTF-2024-Official-Forensics-Writeups https://medium.com/@mrfa3i/uoftctf-forensics-writeup-40fdf89b38f0 https://0xdf.gitlab.io/2024/07/23/htb-sherlock-tracer.html

### W19 — Timestomp proof (0x10 vs 0x30 + EID2 + LSN)
- Signals: "identify the real time" / manipulated-timestamp narrative.
- Steps: 1. Compare 0x10 vs 0x30 Created/Modified per file; same-dir mimicry = stomped. 2. Confirm via Sysmon EID2 (explicit time-change, shows previous vs new). 3. Tie with Prefetch execution of the stomper + `$LogFile` sequence number of the record.
- Commands: MFTECmd CSV `Timestomped`/`uSecZeros` columns + `jq 'select(.EventId==2)' sysmon.json`
- Pitfalls: unzip/copy naturally skews 0x10 vs 0x30 — require EID2 or tool-execution corroboration before claiming malice.
- Sources: https://ctftime.org/writeup/38464 https://medium.com/@atamam204/ieee-forensics-challenges-82db4f246ecf https://www.ztz0.com/writeups/2024/questcon/forensics/the-timestamp/

### W20 — Recycle-Bin receipt chain ($I/$R + cross-artifacts)
- Signals: deleted-file questions on Windows.
- Steps: 1. Parse `$I` (path+size+UTC deletion time) and pair with `$R` content. 2. SID folder = who. 3. Cross-check LNK `Target Created` and JumpLists for pre-delete opens; `$J` FILE_DELETE for emptying time. 4. Bursts before incident milestones = intent signal.
- Commands: `RBCmd.exe -d RecycleBin_C --csv out` / `rifiuti2 $Ixxxx` + MFT orphan-`$I` grep when emptied.
- Pitfalls: Shift+Delete/`del`/NukeOnDelete bypass the bin entirely — check the registry value before concluding "never deleted".
- Sources: https://sutharnisarg.medium.com/umdctf-2022-write-ups-c45cdef017bb

### W21 — RAID missing-slot + order/permutation discipline
- Signals: N disk images, no/odd partitions, magic repeating at intervals, undersized member.
- Steps: 1. Size-outlier member = `missing` candidate. 2. Assemble with `mdadm --create --assume-clean --level=5 --raid-devices=N` over `losetup -fP` loops, permuting order; validate by mountable FS + coherent file. 3. Honor hinted block/order/mode (XOR-doc, mount-order clues, RAID0-vs-5 note).
- Commands: `losetup -fP disk1.img; mdadm --create /dev/md0 --level=5 --raid-devices=3 --assume-clean /dev/loopX missing /dev/loopY; mount /dev/md0 /mnt/raid`
- Pitfalls: contiguity assumption kills stripe arrays (offset/stripes matter); never `--create` on originals — loops on copies only.
- Sources: https://ctftime.org/writeup/33900 https://pwnjournal.github.io/Intergalactic-Recovery-CA-2022-HTB-CTF-Forensics-RAID-5-recovery/ https://blog.reinom.com/ctf/404ctf/2022/forensics/sos-raid/1 https://github.com/daffainfo/ctf-writeup/blob/main/BxMCTF%202023/RAID%20Safety%20Assays%2C%20But%20Fixed

### W22 — Deleted-partition + header-graft + LUKS/Timeshift ladder
- Signals: `file`=data, `mmls` empty, single odd-extension file, crypto_LUKS mount error, snapshot dir present.
- Steps: 1. TestDisk Analyse + Quick Search + P-list + extract (no writes to original). 2. Broken image magic: hex-compare vs spec, graft canonical header bytes only. 3. LUKS: exhaust hint ladder (screenshot/text, mem strings, cmdline/history) before any crack; open via cryptsetup. 4. BTRFS/Timeshift: diff snapshot vs live (`pam_unix.so`-style single-file diff) for planted changes.
- Commands: `testdisk img` (Analyse/Quick Search/P) + `cryptsetup luksOpen /dev/loop0p2 data` + `diff -qr live/ snap/@/ | grep -v '^Only in live'`
- Pitfalls: writing the partition table to the evidence image destroys the puzzle — extract, don't repair in place; grafted headers must be DISCLOSED in handoff.
- Sources: https://ctftime.org/writeup/39452 https://ctftime.org/writeup/39406 https://spikeroot.re/croissants https://metactf.com/blog/flash-ctf-till-delete-do-us-part/

### W23 — TrueCrypt mem-password ladder + tcrypt mount
- Signals: TrueCrypt/VeraCrypt process or container + memdump.
- Steps: 1. `pslist` for the crypto process. 2. Vol2 ladder: `truecryptsummary` (password+offset) else `truecryptmaster` (master key + MKDecrypt) else `truecryptpassphrase`. 3. `cryptsetup --type tcrypt open` + mount; handle inner encoding ladders (e.g. repeated-b64) after mount.
- Commands: `vol.py --profile=P -f m.raw truecryptsummary` + `sudo cryptsetup --type tcrypt open flag flag; sudo mount -o uid=1000 /dev/mapper/flag /mnt/flag`
- Pitfalls: `truecrypt2john`+john verifies the SAME password — use it as confirmation, not discovery, when mem already yields it.
- Sources: https://ctftime.org/writeup/37415 https://siunam321.github.io/ctf/CrewCTF-2023/Forensics/Encrypt10n/ https://nxb1t.neocities.org/blg/2022-05-05 https://motasemhamdan.medium.com/memory-forensics-with-volatility-searching-for-encrypted-files-hackthebox-truesecrets-0dcc5d2dc944

### W24 — VeraCrypt hashcat + DPAPI/Chrome side quest
- Signals: high-entropy container, `veracrypt` search hits, no mem password.
- Steps: 1. `dd` first 512B -> `hashcat -m 137XY` (default 13722 first; 150 H/s reality — only hinted/weak passes). 2. Mount, then pivot to app artifacts: Chrome `Local State` `os_crypt` key -> DPAPI-Protected decrypt scripts; GPG-wrapped EMLs; keyfile-second-mount volumes.
- Commands: `dd if=container of=hash.tc bs=1 count=512` + `hashcat -a 0 -m 13722 hash.tc rockyou.txt`
- Pitfalls: wrong 137XY mode = silent eternal miss — confirm PIM/KDF from container hints first; bruteforce is last resort, not plan A.
- Sources: https://0xmaz.me/posts/Haboob-Blue-CTF-2023/ https://medium.com/@malik.ubaidullah16/digital-cyber-security-hackathon-2023-forensics-container-writeup-f0c566155b8d https://mrpropz.medium.com/btlo-veriarty-writeup-19c0812a57ea https://github.com/HHousen/NCS-Competition/blob/master/Forensics/FM03/README.md

### W25 — BitLocker weak-pass vs FVEK-from-RAM fork
- Signals: BitLocker image (+ optional memdump + vol plugin hint).
- Steps: 1. Weak-pass fork: hash-extract + wordlist, dislocker-mount. 2. Strong-pass fork: vol2 `bitlocker --dislocker` on RAM dump -> FVEK file -> `dislocker -k`. 3. Mount-fail fallback: `hexdump -C dislocker-file | grep` for direct strings.
- Commands: `vol.py -f mem.mem --profile=P bitlocker --dislocker ./dump` + `dislocker -V /dev/loop0 -k ./dump/KEY.fvek -- /mnt/bitlocker`
- Pitfalls: vol3 lacks the bitlocker plugin — version-switch, don't re-derive; loop device must target the right partition.
- Sources: https://medium.com/@akumar54/picoctf-2025-forensics-track-a-complete-walkthrough-15f998b88f3d https://zenn.dev/tetsurou/articles/d232c9075e318e https://medium.com/@mustafa-alzaareer/picoctf-2025-forensics-writeup-ff3eb54eeec5

### W26 — SQLite WAL/journal/freelist + epoch discipline
- Signals: `.db` + `-wal`/`-journal`/`-shm` trio, browser History/ActivitiesCache/Login-Data targets.
- Steps: 1. COPY trio first; `PRAGMA query_only=ON` on copies. 2. Live-query tables, then carve: freelist pages, in-page freeblocks, uncheckpointed WAL frames, rollback-journal before-image. 3. Convert Chrome WebKit epoch (`/1000000-11644473600`); WAL gives COMMIT ORDER only, times come from mactime/pcap. 4. Cross-check IndexedDB dirs + `$MFT`/`$UsnJrnl` History-tamper flags.
- Commands: `cp History* ./work/; sqlite3 ./work/History "SELECT datetime(last_visit_time/1000000-11644473600,'unixepoch'),url FROM urls;"` + `strings History | grep -Ei 'verify|captcha|invalid'`
- Pitfalls: opening the ORIGINAL checkpoints the WAL and destroys evidence; `secure_delete`/`VACUUM` = truly gone, say so and pivot.
- Sources: https://www.synapse-consulting.eu/labs/challenge-09-browser-history.html https://ioi-framework.github.io/cases/af-002/ https://github.com/SecurityRonin/sqlite-forensic https://samiko.me/dfir-investigation https://encient.github.io/ctf/2023/gctf-2023/history/

### W27 — DNS exfil canon (order + encoding tell + framing)
- Signals: long-label queries, `data.<domain>` fixed suffix, dnscat-labeled traffic.
- Steps: 1. Pin exfil domain; extract qry names WITHOUT `sort -u` (order is data; `uniq` only). 2. Strip C2 header bytes (dnscat 9B) + domain + dots. 3. Encoding tell: `=` padding abuse -> base32, not base64; hex-then-b64 stacks need layered decode. 4. Honor start/end sentinel queries for framing.
- Commands: `tshark -r e.pcap -T fields -e dns.qry.name | grep data.exfil | uniq | cut -d. -f1 | tr -d '\n' | base32 -d > out`
- Pitfalls: alphabetical sort corrupts multi-packet payloads; out-of-order captures need seq-aware reassembly, not blind concat.
- Sources: https://medium.com/@bryan.suarez.sec/dods-cyber-sentinel-skills-challenge-exfil-walkthrough-61398aaa5432 https://medium.com/@Sahan0710/litter-sherlocks-hack-the-box-dnscat-decoding-wireshark-data-exfiltration-and-tunneling-ac372663c98b https://ctftime.org/writeup/35743 https://medium.com/@nobaraa/walkthrough-wireshark-challenge-recover-stolen-data-exfiltrated-via-dns-c1bf3da29242

### W28 — Metadata-channel exfil (length/TTL/flags/UDP-loss)
- Signals: uniform small packets with length/TTL/flag anomalies; `data:N:M` ICMP framing; UDP "unreliable" narratives.
- Steps: 1. Histogram per-packet metadata FIRST (`icmp.data_len`, TTL, TCP reserved bits, UDP payload presence). 2. Length==ASCII path: concat per-packet lens as chars. 3. Framed path: seq/total/checksum-trailer reassembly with loss-bucket OR-merge (`i % LEN` slots, nonzero-wins). 4. Reserved-bit path: paired-packet prefix prepend per hints.
- Commands: `tshark -r c.pcap -Y icmp -T fields -e data.len | sort | uniq -c | sort -rn | head` + `tshark -r c.pcap -Y 'icmp.type==8' -T fields -e data | tr -d '\n'`
- Pitfalls: content-decoders on metadata channels waste the whole budget; lossy channels need the modulo-bucket, never naive concat.
- Sources: https://cristi075.github.io/posts/tenablectf-2022-data-exfil-forensics/ https://ctftime.org/writeup/33623 https://blog.jloh02.dev/ctf/stack-the-flags-2022/ https://ctftime.org/writeup/36278 https://warlocksmurf.github.io/posts/ritsecctf2024/

### W29 — WiFi EAPOL-to-inner-protocol ladder
- Signals: 802.11/monitor-mode pcap, EAPOL 4-way present.
- Steps: 1. SSID from beacons; `eapol` filter confirms handshake. 2. `aircrack-ng -w rockyou` (pcapng->pcap convert if needed). 3. Inject `wpa-pwd` key (prefs or `tshark -o`) and re-read INNER protocol: HTTP GETs, RDP-TLS (cert-carve + RSA-decrypt + pyrdp replay + cliprdr), PFX (mimikatz-default-pass first). 4. Custom-crypto APs: reimplement MIC check per descriptor-version, hunt constant GTKs.
- Commands: `aircrack-ng -w rockyou.txt cap.pcap` + `tshark -r cap.pcap -w dec.pcap -o wlan.enable_decryption:TRUE -o 'uat:80211_keys:"wpa-pwd","PASS:SSID"'`
- Pitfalls: hashcat needs converted hashes, aircrack takes pcap directly; monitor-mode + wrong keytype = silent garbage.
- Sources: https://blog.raw.pm/en/TryHackMe-The-Return-of-the-Yeti-write-up/ https://eyexion.fr/posts/thm_aoc_2023_sq1/ https://www.supernetworks.org/pages/blog/spr-turtles-march https://mystickev.github.io/wi-the-fi https://404unfound.com/writeups/hack@ac_24/hackme/

### W30 — SMB3 session-key chain + NTLM-pcap crack
- Signals: encrypted SMB3 + LSASS dump and/or NTLMSSP exchange in pcap.
- Steps: 1. pypykatz/mimikatz LSASS -> NT hashes; john/crack user-1. 2. Harves NTLMSSP fields (user/domain/NTProofStr/EncSessionKey + session-id). 3. Derive: NTLM-hash -> ResponseKeyNT -> KeyExchangeKey -> RC4 -> RandomSessionKey (SP800-108 for SMB3.1.1). 4. Wireshark SMB2 prefs with REVERSED-endian session-id; Export-SMB objects. 5. Uncrackable user: rerun chain with `-ph` hash-direct mode. 6. NTLM-over-HTTP variant: self-forge CHALLENGE+AUTH hash, crack, mind hostname-vs-domain swap.
- Commands: `pypykatz lsa minidump lsass.DMP` + `python3 decryptsmb.py -u U -d D -p P -n PROOF -k ENCKEY` + prefs session-id `4100000000100000`-style reversed.
- Pitfalls: forward session-id never decrypts; domain field is sometimes the hostname — swap and retry before declaring defeat.
- Sources: https://cyberjagadeesh.github.io/posts/block/writeup/ https://medium.com/@T0pN0xch/tryhackme-block-writeup-4d1cdcae17d0 https://archtrmntorr.github.io/posts/TryHackMe-Block-Writeup/ https://lfgberg.org/2024/04/07/ctfs/swamp-24/ https://blog.grace.sh/posts/swampctf2025_muddywater/

### W31 — EVTX mega-chain (chainsaw/hayabusa + Sysmon + Kerberos)
- Signals: `.evtx` bundles, Sysmon Operational, DC Security logs, triage dirs (KAPE/Collection).
- Steps: 1. Canon: `chainsaw hunt -s sigma/ --mapping ...` (+ custom yaml for tool X) or `hayabusa csv-timeline` (7GB-scale) or `EvtxECmd --json` + `jq`. 2. Sysmon ladder: EID1 process-create -> EID11 file-create -> EID22 DNS -> EID3 net -> EID2 time-stomp -> EID5 terminate; EID15 = MotW moment. 3. Kerberos triple: 4768 (+PreAuth0/RC4-0x17 = roast) / 4769 (+RC4 service = kerberoast) / 5140 share-access for source-user. 4. Endpoint anchors: 4624/4625 spray-then-success, 4688 open-time, 4698 task-XML, 4719 audit, 4720 user-add + 4627 groups, 4104 ScriptBlock (b64 thirds), 4616 time-change count (PS-filtered!), 1116/1117 Defender detect+action, 1102 log-clear, 1149 RDP, SmartScreen-Debug tool-run, MPLog `strings -e l` timestomp, 5007 exclusion.
- Commands: `chainsaw hunt Logs/ -s sigma_rules/ --mapping mappings/sigma-event-logs-all.yml` + `hayabusa csv-timeline -d evtx/ -o t.csv` + `jq -c 'select(.EventId==4768 and .PayloadDataX==0)' out.json`
- Pitfalls: UTC-vs-local skew (2s fails answers — normalize to epoch); Event-Viewer display TZ lies — quote the zone; 4625-spray must PRECEDE the 4624 you claim.
- Sources: https://shibudocs.gitbook.io/htb-writeups/hack-the-boo-2023/valhalloween https://0xdf.gitlab.io/2024/05/16/htb-sherlock-logjammer.html https://0xdf.gitlab.io/2024/04/11/htb-sherlock-unit42.html https://0xdf.gitlab.io/2024/06/24/htb-sherlock-campfire-1.html https://0xdf.gitlab.io/2024/07/26/htb-sherlock-campfire-2.html https://nozyzy.github.io/posts/soc-simulator/ https://pr1m3dctf.github.io/writeups/2023/cyber-apocalypse-2023/forensics/packet_cyclone/

### W32 — ICS/SCADA + EML + LNK-to-pcap replay triple
- Signals: port-502/S7 traffic, `.eml` attachments, `.lnk` + pcap pairs.
- Steps: 1. ICS: filter `modbus`/`s7comm`, per-funcCode carve (register-indexed chars, startAddr arrays, S7 BCD-datetime, coil ON/OFF bitmap); proprietary specs: split AES halves across packets then struct-decode; live-query only hinted endpoints. 2. EML: `sed`-range body/attach split + `dos2unix` + b64, unescape `%`-JS second stages. 3. LNK: exiftool args -> PS downloader -> re-fetch URL FROM THE PCAP (dead links live there) -> apply embedded transform (xor-0x1d etc) for stage 2.
- Commands: `tshark -r t.pcap -Y modbus.func_code==16 -T fields -e modbus.reference_num -e modbus.regval_uint16` + `sed -nEe '/^PGh/,/^DQo/p' mail.eml | base64 -d > a.html` + `exiftool evil.lnk`
- Pitfalls: ICS coil/register endianness flips bits silently — validate against known-plaintext headers; EML body is often the decoy, the ATTACHMENT is the stage.
- Sources: https://d415k.github.io/ctf/writeups/HTB_Business_CTF_2023/Scada_Intrusion https://ctftime.org/writeup/38540 https://zer0cket.hatenablog.com/entry/2024/09/08/142738 https://forbytten.gitlab.io/blog/htb-cyber-apocalypse-writeups-2024/urgent/ https://blog.0x7d0.dev/writeups/hack-the-boo-2023/trick-or-treat/ https://www.matthewdfurtado.com/blog/forensics_tangledheist/

## Writeup-Distilled Patterns R2 (W33..W62)

> Mined from `knowledge/writeups_mined/forensics_manifest_r2.md` (451 HARD-only
> writeups, 2024-2026 preferred). Bodies in `techniques/writeup-patterns-r2-{a,b,c}.md`.
> Index only here (line-budget discipline). Technique-only, no flag values.
### W33 — QUIC/HTTP3 keylog-decrypt + header-column carve
- Add: decrypt like TLS; `http3.headers.header.value` column + CSV export; DOT-packet Reassembled-QUIC hex carve. Export-Objects misses HTTP3.
- Detail: `techniques/writeup-patterns-r2-a.md` | Sources: https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/ https://tuxpad.github.io/posts/o24_ghosts_in_the_wall/
### W34 — SSLKEYLOGFILE carve from RAM + multi-medium chain
- Add: `strings -el` TLS labels -> candidate log -> decrypt -> POST archive carve (hex-trim) -> VNC `key_down==1` password.
- Detail: `techniques/writeup-patterns-r2-a.md` | Sources: https://m4lwhere.medium.com/decryption-conniption-2025-correlation-one-ctf-e864f274ebb9 https://blog.cbarkr.com/ctf/picoCTF/2025/Bitlocker-2
### W35 — CloudTrail SQL/jq hunt + AssumeRole session pivot
- Add: data-plane first (role+session), `requestParameters` LIKE session -> IAM user, Lambda code-update = persist, `umount /var/log` reveal.
- Detail: `techniques/writeup-patterns-r2-a.md` | Sources: https://medium.com/devsecops-ai/solving-a-cloud-ctf-cloud-hunting-games-4fa54ff46232 https://medium.com/@adammesser_51095/cloud-digital-forensics-and-incident-response-elastic-kubernetes-service-takeover-leads-to-9553c5424df5
### W36 — GCP audit protoPayload pivot (principal -> data -> persistence)
- Add: rank principalEmail volume, `storage.objects.get` exfil file, OsLogin lateral set, CreateServiceAccount+Key pair, failed export still names bucket.
- Detail: `techniques/writeup-patterns-r2-a.md` | Sources: https://inksec.io/blue-team/labs/googlecloudhunt/ https://blog.cyberethical.me/htb-sherlock-miscloud
### W37 — Docker layer walk + whiteout resurrection
- Add: `history` names delete layer; `save`+walk `manifest.json`; `.wh.`/`.wh..wh..opq` hide but lower layers keep bytes; `dive` per-layer nav.
- Detail: `techniques/writeup-patterns-r2-a.md` | Sources: https://05t3.github.io/posts/PerfectRootCTF/ https://www.antitree.com/2025/08/defcon-tool-release-registry-pillage-2.0/
### W38 — Overlayfs escape read (lowerdir leak + DB-program pivot)
- Add: `mount` lowerdir paths are host-side; test PID/caps; DB `COPY FROM PROGRAM` privesc; mount host disk from privileged side.
- Detail: `techniques/writeup-patterns-r2-a.md` | Sources: https://unicrons.cloud/en/2025/08/15/writeup-cloud-security-championship-2---contain-me-if-you-can/ https://labs.reversec.com/posts/2024/04/abusing-search-permissions-on-docker-directories-for-privilege-escalation
### W39 — Kubernetes audit-log DFIR (verb/objectRef + RBAC climb)
- Add: username filter, verb+objectRef chain (roles->bindings->pod->exec); `exec` = top hunt; registry manifest-GET rogue IP + PATCH push-time.
- Detail: `techniques/writeup-patterns-r2-a.md` | Sources: https://solvere.app/ctfs/thm/day-22/ https://github.com/caydenrgarrett/Kubernetes-DFIR
### W40 — K8s checkpoint/CRIU + Falco runtime forensics
- Add: quarantine (deny-all + cordon), checkpoint-on-Falco-trigger, off-host evidence pack, checkpointctl static + buildah-restore dynamic.
- Detail: `techniques/writeup-patterns-r2-a.md` | Sources: https://www.sysdig.com/blog/csi-forensics-unraveling-kubernetes-crime-scenes https://bipi.in/blog/kubernetes-incident-response
### W41 — macOS unified-log triage (tracev3 + TTL discipline)
- Add: `log collect` beats sysdiagnose for history; offline parse to CSV; sender/eventMessage predicates; `private` redaction -> corroborate.
- Detail: `techniques/writeup-patterns-r2-a.md` | Sources: https://blog.elcomsoft.com/2025/06/extracting-and-analyzing-apple-unified-logs/ https://jebitok.hashnode.dev/macos-forensics-artefacts-tryhackme
### W42 — APFS snapshot diff (deleted-data-first discipline)
- Add: `tmutil`/`diskutil` list, `mount_apfs -s` per snapshot as own FS, snapshot-time upper bound, clones/Spotlight/FSEvents before carve.
- Detail: `techniques/writeup-patterns-r2-a.md` | Sources: https://www.nbftools.com/apfs-snapshots-in-digital-forensics/ https://dixon.cx/digital-forensics-guide/macos
### W43 — FileVault/T2 key-recovery ladder (escrow-first, brute-last)
- Add: escrow hunt (Keychain/MDM/backup), kcpassword-XOR -> Chainbreaker, live-mem volume key, T2-off-machine = ciphertext (logical acquisition).
- Detail: `techniques/writeup-patterns-r2-b.md` | Sources: https://medium.com/@itsGir/ctf-write-up-maclock-certified-cyber-defenders-b0fef014e96f https://blog.passware.com/from-filevault-to-t2-how-to-deal-with-native-apple-encryption/
### W44 — ADB triage extraction (no-root live pull)
- Add: `dumpsys usagestats` (deleted apps), bugreport grep, `/sdcard`+`/system` pull, content-provider queries, `adb backup` gaps; JTAG dumps -> binwalk.
- Detail: `techniques/writeup-patterns-r2-b.md` | Sources: https://blog.digital-forensics.it/2021/03/triaging-modern-android-devices-aka.html https://thamizhiniyancs.gitbook.io/writeups/ctf/2024/hackctf/forensics/dumped.md
### W45 — Android dump-in-depth (accounts -> comms -> media DB ladder)
- Add: ALEAPP names APK; `accounts_ce.db`/telephony/roles identity; app-DB snippets + recent_tasks snapshots; JADX exfil + AES key; EXIF GPS.
- Detail: `techniques/writeup-patterns-r2-b.md` | Sources: https://sarahosborn.com/4n6/posts/MVS_CTF_2024_Android_Writeup/ https://medium.com/@itsGir/ctf-write-up-androidbreach-certified-cyber-defenders-c9f068caac0d
### W46 — UBIFS/JFFS2 deep carve (ECC-strip + journal recovery)
- Add: partition-txt ground truth, OOB-stride strip before tools, jefferson/mtd-mount, ubireader + nandsim fallback, UBIFT journal/ORPH deleted recovery.
- Detail: `techniques/writeup-patterns-r2-b.md` | Sources: https://www.hacktivesecurity.com/blog/2024/12/18/not-all-roads-lead-to-pwn2own-firmware-reverse-engineering-part-2/ https://habr.com/ru/companies/bizone/articles/768904/
### W47 — ESP32/SPIFFS flash carve (partition-table-first)
- Add: custom ESP-IDF binwalk defs, `0x8000` partition map, Ghidra ESP32-loader + entry address, dual OTA slots, heap XOR sections.
- Detail: `techniques/writeup-patterns-r2-b.md` | Sources: https://ctftime.org/writeup/39209
### W48 — LUKS live-key recovery (LUKS1 vs LUKS2 fork)
- Add: `luksDump` version check; LUKS1 `dmsetup table` direct; LUKS2 LiME dump + findaes + `luksAddKey` trial; rotate after (dump holds key).
- Detail: `techniques/writeup-patterns-r2-b.md` | Sources: https://jfr.im/blog/2025/03/recovering-luks-keys/
### W49 — BitLocker FVEK-from-RAM fork (plugin vs wordlist vs escrow)
- Add: weak fork (`bitlocker2john` + hashcat 22100); strong fork (Vol2 `bitlocker --dislocker`, Vol3 lacks it); escrow fork (VSS/photo key); ntfs-3g mount.
- Detail: `techniques/writeup-patterns-r2-b.md` | Sources: https://blog.cbarkr.com/ctf/picoCTF/2025/Bitlocker-2 https://infoseciitr.in/ctf-writeups/byu-ctf/not_again/
### W50 — Partial-key brute force (known-segment recovery keys)
- Add: fix visible groups, brute unknown window only (`manage-bde` loop), decrypt to working copy on first success; unbounded 48-digit brute = stop.
- Detail: `techniques/writeup-patterns-r2-b.md` | Sources: https://triettran2222.gitbook.io/dfir-writeups/bitlocked-why2025-ctf
### W51 — VSS + E01 mount ladder for escrowed keys
- Add: online-mount E01 (Arsenal) to see real volumes, per-volume `vssadmin`, `mklink` shadow restore, escrow harvest -> unlock -> inner leads.
- Detail: `techniques/writeup-patterns-r2-b.md` | Sources: https://graymanre.github.io/ctf/btlo_thekey.html
### W52 — Timestomp proof pack (SI/FN + $J + LSN + precision tell)
- Add: MFTECmd 0x10/0x30 neighbor-match, `$J` BASIC_INFO_CHANGE confirm, LSN outlier sort, whole-second truncation tell, Prefetch/PS-history/EID2 corroboration.
- Detail: `techniques/writeup-patterns-r2-b.md` | Sources: https://mahmoud-shaker.gitbook.io/dfir-notes/timestomp-challenge-eg-ctf-2025-forensics-write https://diablo666.medium.com/timestomp-eg-cert-ctf-2025-forensics-write-up-ea248ab20ba4
### W53 — Hunt-pack-in-CTF method (chainsaw/hayabusa/EZTools order)
- Add: EZTools base, chainsaw-full or hayabusa-timeline sweep, rule hits as question index, raw-EID confirm, UTC-normalize answers.
- Detail: `techniques/writeup-patterns-r2-c.md` | Sources: https://mblunt.dev/writeups/dukectf-2025-events-never-lie/ https://medium.com/@krzysztof.kuzin/holmes-ctf-2025-the-enduring-echo-c45c1f0d18f5
### W54 — Sigma-rule authoring from evtx (detection-as-answer)
- Add: stable selectors (path+parent, never PID), category first (process_creation vs file_event), hollowing `-Embedding`, registry DeleteValue variants.
- Detail: `techniques/writeup-patterns-r2-c.md` | Sources: https://medium.com/@itsGir/ctf-write-up-sigma-101-certified-cyber-defenders-c9f068caac0d https://mrheckercat.github.io/yara/sigma/soc/htb/cybersecurity/2025/01/20/write-up-yara-sigma-skill-assessment/
### W55 — Havoc-C2 magic carve (deadbeef -> key/IV split -> CTR)
- Add: magic pin across streams, key+IV from FIRST packet fixed offset, same-pair decrypt all, hostname/profile confirms.
- Detail: `techniques/writeup-patterns-r2-c.md` | Sources: https://qiita.com/tournip/items/448ff703c3f525274f86
### W56 — MQTT + doc-macro + blockchain-tx mega-chain
- Add: `mqtt.msgtype==3` b85 carve, olevba URL+XOR drop, pylingual odd-pyc, tx-timing side-channel password scope, ext-less inner `file`-first.
- Detail: `techniques/writeup-patterns-r2-c.md` | Sources: https://hackmd.io/@asterrr/ry_S7GXhJe
### W57 — APK-malware full chain (download -> JADX -> Frida -> exfil)
- Add: ALEAPP names APK, JADX exfil+AES, Frida runtime key hooks (skip native static), window-scoped decrypt, VMDK side-quest stays separate.
- Detail: `techniques/writeup-patterns-r2-c.md` | Sources: https://hackmd.io/@blacowhait/itsec-ctf-2025 https://medium.com/@itsGir/ctf-write-up-androidbreach-certified-cyber-defenders-c9f068caac0d
### W58 — EKS IMDS -> JWT -> API-audit -> CloudTrail miner chain
- Add: injection -> btmp cadence + IMDS triple (URL+cert+JWT), SA-enum AccessDenied bursts, Secrets cloud keys, novel-AMI detection rule.
- Detail: `techniques/writeup-patterns-r2-c.md` | Sources: https://medium.com/@adammesser_51095/cloud-digital-forensics-and-incident-response-elastic-kubernetes-service-takeover-leads-to-9553c5424df5
### W59 — MemprocFS-vs-Volatility file-recovery discipline
- Add: MemprocFS clean-read first, dumpfiles + `xxd` trim on hash-miss, user-proc envars identity, handles DB paths, foremost on paint dumps.
- Detail: `techniques/writeup-patterns-r2-c.md` | Sources: https://medium.com/@sshekhar01/belkactf-7-stranger-dfings-writeup-e9f29561926c
### W60 — Open-source-only DFIR (strings-index + envars-first)
- Add: one bulk Unicode strings index, user-proc envars identity, typo-squat + filescan, direct sqlite3 over GUI, coord-only message isolate.
- Detail: `techniques/writeup-patterns-r2-c.md` | Sources: https://medium.com/@Debug_4n6/belkactf-7-writeup-our-deep-dive-into-the-stranger-dfings-memory-verse-077ac8eb5f3b
### W61 — Script-ordered staged-blob reassembly (order != capture order)
- Add: per-stream name enumerate, loader concat ORDER (not arrival), per-stream files, script-order join + transform, magic+sha256 gate pre-execution.
- Detail: `techniques/writeup-patterns-r2-c.md` | Sources: https://medium.com/@abdjaar36/nexhunt-ctf-2025-oczy-forensics-writeup-4f3d3c5f7e40
### W62 — Gitea-CVE -> GCP lateral chain (pcap RCE + audit follow)
- Add: hook-POST RCE + CVE-map, revshell SA harvest, OsLogin per-VM login set, storage role-assign intent, Export-Objects script + header-repeat XOR key.
- Detail: `techniques/writeup-patterns-r2-c.md` | Sources: https://blog.cyberethical.me/htb-sherlock-miscloud https://infosecwriteups.com/miscloud-hackthebox-sherlock-writeup-bea5403dbcc2

## EASY-FIRST ladder (2026 training refresh — ≤20 min)
1. `file` + `strings -n8 f | grep -Eo 'flag\{[^}]+\}|picoCTF\{[^}]+\}'` FIRST (<30s win); UTF-16 miss → add `strings -e l/-e b`.
2. pcap: `tshark -r c.pcap -Y 'tcp contains pico'`; Wireshark Follow→TCP Stream; `--export-objects http,out/`; misses → `tcp.segment_data | xxd -r -p | strings`.
3. DNS-heavy capture: `tshark -Y dns -T fields -e dns.qry.name | sort -u` (exfil labels), `-e dns.txt` (TXT answers); include `udp.port==53||tcp.port==853`.
4. Disk: `mmls` → `dd` the Linux partition → strings; deleted files → `fls -r -p` + `icat [inode]`; archives-of-nothing → `strings+grep` (git objects/zlib have no magic: `git cat-file --batch-all-objects --batch | strings`).
5. Memory/host: `windows.pslist + cmdline + filescan|grep -i flag`, else `strings|grep`; Linux disk → `/root/.bash_history`; `.evtx` → `4624/4625` logons; wrong-profile errors → `windows.info` first, fallback strings.

## R4 field patterns (browser-swarm 2026 — from 305 new writeups)
- DPAPI triage order: carve `01000000D08C9DDF` blobs → map `guidMasterKey` → masterkey via password/backup-key → Chrome `Login Data`/Cookies (user/machine-scoped, never cross-user `CryptUnprotectData`).
- WMI persistence: `strings`-walk `OBJECTS.DATA` layers, map `__EventFilter→Consumer→Binding` + timestamps (survives reimage if subscription left).
- VeraCrypt: browser history + deleted-note password + keyfile; outer decoy mounts, hidden volume needs second password (PIM brute).
- ClickFix/FileFix: payload lives in CLIPBOARD (`Win+R` + fake CAPTCHA) — hunt `conhost←powershell` parentage, not URLs.
- MJPEG/RTP pcap: `foremost -i cap.pcap` carves frames when Wireshark export misses; DTMF → decode tone sequence.
- KeePass: `keepass2john` + rockyou on `.kdbx` before any memory surgery; XOR-port-1337 exfil → try `0x41` then `0x42`.

Deep-read bodies (14 complete articles): techniques/r5-deep-reads.md.
