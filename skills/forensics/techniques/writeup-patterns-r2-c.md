# Forensics R2 patterns C — W53..W62 (hunt packs, C2, chains, DFIR discipline)

Technique-only distillations from `knowledge/writeups_mined/forensics_manifest_r2.md`
(topic lines + ctftime R2 rows). Signals → steps → commands → pitfalls → sources.

### W53 — Hunt-pack-in-CTF method (chainsaw/hayabusa/EZTools triage order)
- Signals: `Logs/` triage dirs, `.evtx` bundles, Sysmon Operational present,
  Defender/AMSI hits expected, question style asks for times + tool paths.
- Steps: 1. Base first (EZTools: MFTCmd `$MFT`+`$J`, PECmd prefetch, EvtxECmd
  JSON). 2. Hunt-pack sweep: `chainsaw hunt -s sigma/ --mapping
  sigma-event-logs-all.yml` (full) or `hayabusa csv-timeline` (7GB-scale).
  3. Read rule hits as the question index (Impacket lateral, WMI-spawn,
  PortProxy, ShadowCopy). 4. Confirm each hit in raw EID (4688 parent, logon
  IP, task-XML path). 5. Timezone-normalize every answer (UTC quote).
- Commands: `chainsaw hunt Logs/ -s sigma/ --mapping mappings/sigma-event-logs-all.yml --full` + `hayabusa csv-timeline -d evtx/ -o timeline.csv` + `chainsaw search -t 'Event.System.EventID: =5001' Logs/`
- Pitfalls: display-TZ lies (Event Viewer local vs UTC); spray-then-success
  order matters (4625 must precede the claimed 4624); 7GB evtx needs hayabusa,
  not viewer.
- Sources: https://mblunt.dev/writeups/dukectf-2025-events-never-lie/
  https://medium.com/@krzysztof.kuzin/holmes-ctf-2025-the-enduring-echo-c45c1f0d18f5
  https://noc.hashnode.dev/hackthebox-unit42-sherlock

### W54 — Sigma-rule authoring from evtx (detection-as-answer)
- Signals: Detection-Engineering labs, per-level evtx, "write the rule, get the
  flag", Hunter-style validators requiring title/detection/logsource.
- Steps: 1. Read the 2-3 sample events; pick STABLE selectors (Image path,
  ParentImage, CommandLine fragment) — never PID/timestamps. 2. Set logsource
  category FIRST (`process_creation` for EID1/4688, `file_event` for EID11/12).
  3. `selection:` + `condition: selection`, level by blast radius.
  4. Process-hollowing variant: parent-embedding CommandLine (`-Embedding`).
  5. Defense-evasion variant: registry TargetObject fragment (e.g. lockdown-
  policy key) with `EventType: DeleteValue`.
- Commands: `chainsaw hunt lab.evtx -s ./myrule.yml --mapping mappings/sigma-event-logs-all.yml` (validate-before-submit loop)
- Pitfalls: wrong category = eternal miss (EID12 is file_event, not process);
  over-specific rules pass the lab but teach nothing — prefer path+parent pairs.
- Sources: https://medium.com/@itsGir/ctf-write-up-sigma-101-certified-cyber-defenders-c9f068caac0d
  https://mrheckercat.github.io/yara/sigma/soc/htb/cybersecurity/2025/01/20/write-up-yara-sigma-skill-assessment/

### W55 — Havoc-C2 magic carve (deadbeef -> key/IV split -> CTR)
- Signals: repetitive POSTs, identical-size bodies, `de ad be ef` header,
  "not the common C2" text, first packet larger (key material inside).
- Steps: 1. Confirm magic at body offset 0 across streams. 2. First packet:
  AES-key (32B) + IV (16B) sit at fixed offset past magic. 3. Remainder =
  AES-256-CTR ciphertext under that pair — decrypt EVERY packet with the same
  pair. 4. Plaintext reveals profile/hostname confirming success; then grep
  all decrypted blobs for the objective string.
- Commands: `tshark -r c.pcap -Y http.request.method==POST -T fields -e tcp.stream -e http.file_data | head` + CyberChef/python AES-CTR(key, nonce, ct) per packet
- Pitfalls: key/IV come from packet ONE only — re-deriving per packet garbles;
  magic offset shifts with framing (verify on 3+ packets before batch).
- Sources: https://qiita.com/tournip/items/448ff703c3f525274f86

### W56 — MQTT + doc-macro + blockchain-tx mega-chain
- Signals: `mqtt` in hierarchy + broker narrative, doc with macros, python-EXE
  (pyc inside), eth-tx explorer questions, timing-keyed archives.
- Steps: 1. `mqtt.msgtype==3` PUBLISH carve + b85 decode -> archive.
  2. olevba macro: b64-URL fetch + fixed-key XOR drop EXE (never execute).
  3. PyInstaller carve: pylingual on odd-named pyc; blockchain functions =
  timing oracle (starttime/endtime per tx). 4. tx-input b64 decode -> storage
  links; `(endtime-starttime)>5s` marks randomized password positions -> scoped
  brute. 5. Inner file ext-less: `file` then rename (docx/zip).
- Commands: `tshark -r c.pcap -Y 'mqtt.msgtype==3' -T fields -e mqtt.msg | python3 -c "import sys,base64;..."` + `olevba evil.docm` + `pyinstxtractor evil.exe`
- Pitfalls: batch randomness is timing-observable — don't seed-guess, measure;
  ext-less inner files mislead `unzip` (identify first).
- Sources: https://hackmd.io/@asterrr/ry_S7GXhJe

### W57 — APK-malware full chain (download -> JADX -> Frida -> exfil)
- Signals: Android dump + malicious APK narrative, AES image encryption,
  Telegram/SMTP exfil code, native-lib key holders, credential-file staging.
- Steps: 1. ALEAPP Chrome-Downloads names the APK; pull from
  `media/0/Download`. 2. JADX: exfil class (SMTP host / Telegram endpoint),
  AES utils (b64 key), staged-file name. 3. Runtime keys (AES/IV, RSA) via
  Frida hooks (`aesinfo`-class scripts, native `getRSAKey` return hook) —
  no static RE of obfuscated natives. 4. Decrypt staged captures in the
  question's time window only. 5. VMDK/ransomware side-quests stay separate:
  FTK triage -> archiver-repair -> sandbox-behavior (VT) for stage-2 URL.
- Commands: `jadx-gui evil.apk` + `frida -U -f <pkg> -l aesinfo.js --no-pause` + `aleapp -i data/ -o report/`
- Pitfalls: RSA-wrapped blobs distract when AES key is already hooked (read the
  code path actually used); Telegram token + chat = BOTH needed for pull.
- Sources: https://hackmd.io/@blacowhait/itsec-ctf-2025
  https://medium.com/@itsGir/ctf-write-up-androidbreach-certified-cyber-defenders-c9f068caac0d

### W58 — EKS IMDS -> JWT -> API-audit -> CloudTrail miner chain
- Signals: EKS + container RCE, IMDS `169.254.169.254` hits, JWT in env/files,
  k8s API-audit + CloudTrail both in scope, mining/expensive-instance ending.
- Steps: 1. Web logs: command-injection -> reverse shell. 2. Container: btmp
  su-bruteforce tells (programmatic cadence), IMDS pulls cluster URL + cert.
  3. Pod SA JWT + URL + cert = kubeconfig; API-audit shows SA permission-enum
  (AccessDenied bursts = recon signature). 4. Cluster Secrets hold cloud keys;
  CloudTrail pivots to control plane (IAM/KMS/EC2 enum -> rogue instances).
  5. Novel AMI/instance-type vs approved baseline = detection rule to propose.
- Commands: `grep -E '169.254.169.254' access.log | head` + `jq -c 'select(.user.username=="system:serviceaccount:<ns>:default")' k8s-audit.json | head`
- Pitfalls: JWT alone is useless without API URL + CA (collect the triple);
  AccessDenied storms are the signal, not noise — count them per principal.
- Sources: https://medium.com/@adammesser_51095/cloud-digital-forensics-and-incident-response-elastic-kubernetes-service-takeover-leads-to-9553c5424df5

### W59 — MemprocFS-vs-Volatility file-recovery discipline
- Signals: Windows mem image, file-recovery questions failing hash match,
  extra-bytes/padding suspicions, administrative vs user process contexts.
- Steps: 1. Try MemprocFS virtual-FS read first for clean files (no carve
  padding). 2. Volatility `dumpfiles --pid --virtaddr` when FS-mount fails;
  expect trailing bytes — `xxd` trim to real size (header-to-EOF). 3. User
  context via `envars` on explorer/notepad (USERNAME/USERDOMAIN). 4. Handles
  plugin for DB/log paths owned by suspect PID; foremost on mspaint-class
  dumps for pasted screenshots.
- Commands: `vol -f m.mem windows.dumpfiles --pid <P> --virtaddr <V>` + `xxd dump.bin | tail` (size-trim check) + `vol -f m.mem windows.handles --pid <P>`
- Pitfalls: hash-mismatch after dumpfiles = padding, not wrong file — trim,
  don't re-dump endlessly; envars from SYSTEM procs misleads identity.
- Sources: https://medium.com/@sshekhar01/belkactf-7-stranger-dfings-writeup-e9f29561926c

### W60 — Open-source-only DFIR (strings-index + envars-first)
- Signals: same mem+mobile bundle, "no commercial tools" constraint, typo-squat
  processes, Telegram-C2 and pasted-screenshot questions.
- Steps: 1. Bulk `strings` (Unicode) the image ONCE -> grep index for emails,
  Bot-API URL shapes, hostnames. 2. Identity via user-process `envars`
  (notepad over csrss). 3. Masquerade hunt: name-near-miss + parent + filescan
  on-disk check. 4. Mobile side: direct sqlite3 queries (accounts, snippets)
  over GUI browsing. 5. Screenshot recovery: mspaint dump + foremost, radar-DB
  via handles->dumpfiles rename-to-.db.
- Commands: `strings -el m.mem > all.txt; grep -Ei -m20 'https://api.telegram.org/bot[0-9]+:' all.txt` + `vol -f m.mem windows.envars --pid <notepadPID>`
- Pitfalls: strings-index goes stale after each new dump (rebuild per image);
  translated chat logs need the coord-only messages isolated first.
- Sources: https://medium.com/@Debug_4n6/belkactf-7-writeup-our-deep-dive-into-the-stranger-dfings-memory-verse-077ac8eb5f3b

### W61 — Script-ordered staged-blob reassembly (order != capture order)
- Signals: loader script fetching MANY blobs over one endpoint, name-per-
  stream handshake, Array.Copy/concat order constants, sha256 self-check.
- Steps: 1. Enumerate streams + first-payload names (tshark per-stream).
  2. Read the loader's concat ORDER (variable list, not arrival order).
  3. Extract server-to-client bytes per stream to individual files.
  4. Join in script order, apply stated transform (XOR-repeating), verify
  magic + sha256 against the loader's constant before any execution.
- Commands: `for s in $(tshark -r c.pcapng -Y '<ip/port>' -T fields -e tcp.stream | sort -n | uniq); do tshark -r c.pcapng -Y "tcp.stream==$s && <dir>" -T fields -e tcp.payload | tr -d ':\n' | xxd -r -p > blob_$s.bin; done`
- Pitfalls: capture-order join yields a valid-looking but hash-failing binary;
  direction filters (`dstport` vs `srcport`) swapped = request/response mix.
- Sources: https://medium.com/@abdjaar36/nexhunt-ctf-2025-oczy-forensics-writeup-4f3d3c5f7e40

### W62 — Gitea-CVE -> GCP lateral chain (pcap RCE + audit follow)
- Signals: Gitea version traffic, `/hooks/git/post-receive` POSTs, gitea-vm +
  Linux VMs + packet-mirror set, `storage.objects.*` audit methods, XOR-sheet
  ending.
- Steps: 1. Pcap: POST to hook endpoint with b64/bash = RCE (CVE-map the
  Gitea version). 2. Revshell + `gcloud auth list` harvests the SA identity.
  3. `instances list` output in revshell enumerates lateral targets; SSH key
  plant + `ssh` protocol filter confirms logins. 4. Audit JSON: OsLogin
  CheckPolicy per-VM (login set), storage.objects.get (exfil file), role-
  assign attempt (public-bucket intent). 5. Exported script + encrypted blob
  via Export-Objects; header-repeat phrase = XOR key candidate.
- Commands: `tshark -r vpc.pcap -Y 'http.request.method==POST && http.request.uri contains "post-receive"' -T fields -e tcp.stream` + `jq -c 'select(.protoPayload.methodName|contains("OsLogin"))' GCloud_Logs.json`
- Pitfalls: insider-vs-outsider is decided by SOURCE IP (RFC1918 = insider),
  not by payload; default-VPC ports (3389) are exfil-relevant, not noise.
- Sources: https://blog.cyberethical.me/htb-sherlock-miscloud
  https://infosecwriteups.com/miscloud-hackthebox-sherlock-writeup-bea5403dbcc2
