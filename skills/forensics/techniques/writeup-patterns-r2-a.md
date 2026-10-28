# Forensics R2 patterns A — W33..W42 (QUIC, mem-keylog, cloud, container, K8s, macOS)

Technique-only distillations from `knowledge/writeups_mined/forensics_manifest_r2.md`
(topic lines). Each entry: signals → steps → commands → pitfalls → sources.
Full command context lives in SKILL.md Phases/A1-A10 + W1-W32; these add what
those do NOT cover.

### W33 — QUIC/HTTP3 keylog-decrypt + header-column carve
- Signals: `quic` dominates protocol hierarchy (UDP, ports 443/80), `tls.app_data`
  over UDP, browser-noise HTTP/2 + one standout download; sslkeylog alongside pcap.
- Steps: 1. Same `-o tls.keylog_file:` decrypt as TLS (QUIC reuses TLS 1.3 secrets).
  2. Do NOT use Export-Objects (no HTTP3 support): add `http3.headers.header.value`
  as a column, export dissections to CSV, filter GET/response pairs. 3. For file
  downloads: find GET, open response, locate DOT (final-fragment) packet, copy
  `Reassembled QUIC -> Data` as hex-stream, `bytes.fromhex` to file.
- Commands: `tshark -r c.pcapng -o tls.keylog_file:./sslkeys.log -Y http3 -T fields -e frame.number -e http3.headers.header.value | head -n 40` + CSV export + `python3 -c "open('f','wb').write(bytes.fromhex(open('h').read()))"`
- Pitfalls: Ctrl+F string search finds nothing pre-decrypt; Export-Objects HTTP
  silently misses HTTP3; HLS-over-QUIC needs m3u8+key carve then ffmpeg (see W33b
  variant in Robust: pyshark `http3.frame_type==0` payload concat).
- Sources: https://blog.elmo.sg/posts/parsing-decrypted-quic-traffic-in-wireshark/
  https://tuxpad.github.io/posts/o24_ghosts_in_the_wall/
  https://www.zhouweitong.site/2023/09/11/d3ctf-2021-misc-robust-writeup/

### W34 — SSLKEYLOGFILE carve from RAM + multi-medium chain
- Signals: pcap+mem pair, TLS-only + cleartext side-protocol (VNC/RDP) in same
  capture, challenge text names the keylog env var.
- Steps: 1. `strings -el` mem for TLS label set (`CLIENT_RANDOM` .. `SERVER_TRAFFIC_SECRET_0`).
  2. Rebuild `LABEL rand secret` lines to candidate log (one trial set at a time).
  3. Decrypt pcap, hunt POST-to-hosting (SNI `gofile`-class), carve archive, trim
  webform headers/trailers in hex editor. 4. Side-protocol keystrokes
  (`vnc.client_message_type==4 && vnc.key_down==1`) yield archive password.
- Commands: `strings -n 16 -el mem.raw | grep -E 'CLIENT_RANDOM|CLIENT_TRAFFIC_SECRET_0|SERVER_TRAFFIC_SECRET_0' > keylog.log` + `tshark -r e.pcapng -Y 'vnc.client_message_type==4 && vnc.key_down==1' -T fields -e vnc.key`
- Pitfalls: two packets per keypress (down+up) — filter `key_down==1`; Shift
  symbols appear as separate modifier events; NetworkMiner needs pcap (not pcapng).
- Sources: https://m4lwhere.medium.com/decryption-conniption-2025-correlation-one-ctf-e864f274ebb9
  https://blog.cbarkr.com/ctf/picoCTF/2025/Bitlocker-2

### W35 — CloudTrail SQL/jq hunt + AssumeRole session pivot
- Signals: `*_events` tables or CloudTrail JSON, `assumed-role/ROLE/session`
  strings, Lambda `UpdateFunctionCode` events, missing `/var/log` (unmount trick).
- Steps: 1. Sort by EventTime DESC. 2. Data-plane first (S3 GET/PUT on vault
  bucket) to name role + session. 3. Control-plane: `requestParameters` LIKE
  `%session%` finds the IAM user behind AssumeRole. 4. Lambda code-update =
  persistence suspect (pull function + diff). 5. `findmnt`/`umount /var/log`
  reveals hidden auth.log; SSH source = entry point. 6. Cron b64 = second persist.
- Commands: `SELECT * FROM cloudtrail WHERE requestParameters LIKE '%<session>%' ORDER BY EventTime DESC` + `umount /var/log; grep -Ei 'sshd.*Accepted|Failed' /var/log/auth.log | head`
- Pitfalls: role name (`S3Reader`) vs session name (`drinks`) are different fields;
  console timestamps are UTC — normalize before joining with host logs.
- Sources: https://medium.com/devsecops-ai/solving-a-cloud-ctf-cloud-hunting-games-4fa54ff46232
  https://medium.com/@adammesser_51095/cloud-digital-forensics-and-incident-response-elastic-kubernetes-service-takeover-leads-to-9553c5424df5

### W36 — GCP audit protoPayload pivot (principal -> data -> persistence)
- Signals: `GCloud_Logs.json`/audit JSON, `protoPayload.authenticationInfo`,
  Gitea/CVE RCE in paired pcap, `storage.objects.*` methods.
- Steps: 1. Rank `principalEmail` by auth-event volume (compromised = outlier).
  2. `storage.objects.get` on that principal names the exfil file. 3. Same
  principal + `compute`/`oslogin` methods maps lateralVM set. 4. IAM methods
  (`CreateServiceAccount` then `CreateServiceAccountKey`) = persistence pair —
  alert as one. 5. Failed `cloudsql.instances.export` still names target bucket.
- Commands: `jq -r '.[].protoPayload.authenticationInfo.principalEmail' GCloud_Logs.json | sort | uniq -c | sort -rn | head` + `jq -c 'select(.protoPayload.methodName=="storage.objects.get")' GCloud_Logs.json`
- Pitfalls: data-access logs may be disabled (absence is not alibi); default
  compute SA is over-broad — scope hunts by principal, not by project.
- Sources: https://inksec.io/blue-team/labs/googlecloudhunt/
  https://blog.cyberethical.me/htb-sherlock-miscloud
  https://codelabs.cs.pdx.edu/labs/W8.3_gcp_defender/index.html?index=..%2F..cs495

### W37 — Docker layer walk + whiteout resurrection
- Signals: image tarball / registry pull, `history` shows copy-then-delete,
  `.wh.` markers, manifest.json + blobs/sha256 layout.
- Steps: 1. `docker history` (or image config) to name the delete layer.
  2. `docker save` to tar; walk `manifest.json` -> per-layer `layer.tar`.
  3. Target the pre-delete layer digest (`dive` Tab-navigation or
  `tar -tf layer.tar | grep` sweep). 4. Whiteouts (`.wh.<name>`,
  `.wh..wh..opq`) mark deletions — the bytes still sit in lower layers; extract
  the lower layer directly, never the merged view.
- Commands: `docker save img -o img.tar; tar -xf img.tar -C img/` + `find img -name 'layer.tar' -exec sh -c 'echo {}; tar -tf {} | grep -i flag' \;` + `dive img:latest`
- Pitfalls: merged/upper view hides deleted files by design; `docker pull`
  hides layers (use `save`); opaque whiteouts wipe whole dirs from merged view.
- Sources: https://05t3.github.io/posts/PerfectRootCTF/
  https://blog.i5-650.systems/fcsc-2024/
  https://www.antitree.com/2025/08/defcon-tool-release-registry-pillage-2.0/

### W38 — Overlayfs escape read (lowerdir/upperdir + DB-program pivot)
- Signals: `overlay ... lowerdir=/var/lib/docker/overlay2/...` in mount table,
  missing docker socket, `CAP_SYS_ADMIN` failures, postgres/SQL service in scope.
- Steps: 1. Read `mount` for host-path leaks (lowerdir/upperdir/workdir).
  2. Test PID namespace (`/proc/1/root/.dockerenv`), block devices (`lsblk`),
  caps (`unshare -U -m` probe). 3. If DB allows program execution
  (`COPY ... FROM PROGRAM`), escalate inside the DB container first. 4. From the
  privileged side: enumerate host disks, mount primary disk, read target file.
- Commands: `mount | grep -o 'lowerdir=[^ ]*' | tr ',' '\n'` + `lsblk; ls -la /proc/1/root/` + `COPY t FROM PROGRAM 'sudo mount /dev/<disk> /mnt/host_root_disk'`
- Pitfalls: mount output paths are host-side, not container-reachable; PID-1
  tricks fail under PID isolation; core_pattern/nsenter need caps you lack —
  test, don't assume.
- Sources: https://unicrons.cloud/en/2025/08/15/writeup-cloud-security-championship-2---contain-me-if-you-can/
  https://labs.reversec.com/posts/2024/04/abusing-search-permissions-on-docker-directories-for-privilege-escalation

### W39 — Kubernetes audit-log DFIR (verb/objectRef + RBAC climb)
- Signals: `audit.log` JSON, `user.username`, `objectRef.subresource: exec`,
  registry HEAD/manifest logs, short-lived pods (70% < 5 min).
- Steps: 1. Filter audit log by suspect username; pivot on `verb`+`objectRef`
  (`get roles` -> `describe role` -> `get rolebindings` -> `describe pod` ->
  `exec`). 2. `exec` into production namespaces = top hunt (repeated execs =
  discovery/lateral, not debugging). 3. Registry logs: rogue IP via manifest-GET
  200 + PATCH push-time. 4. Pull-creds secret read explains the push; rotate ALL
  pod-mounted secrets post-hunt.
- Commands: `cat audit.log | grep '"username":"<user>"' | grep -o '"verb":"[^"]*","objectRef":{[^}]*}' | sort | uniq -c | sort -rn | head -n 30` + `grep -E 'manifests.* 200|PATCH' registry.log | head`
- Pitfalls: empty audit log may mean opt-in logging off (check policy first);
  plural `get` appears as `list` backend-side; push/pull creds must differ.
- Sources: https://solvere.app/ctfs/thm/day-22/
  https://github.com/caydenrgarrett/Kubernetes-DFIR
  https://www.jelly.dev/posts/kubecon-na-ctf-24/

### W40 — K8s checkpoint/CRIU + Falco runtime forensics
- Signals: Falco alerts (shell-in-container, sensitive-file open), ephemeral
  pods already gone, checkpoint tar archives on nodes.
- Steps: 1. Never `kubectl delete` the suspect pod: quarantine with deny-all
  NetworkPolicy + cordon node. 2. Automate checkpoint on Falco trigger
  (Falco->Falcosidekick->Argo->CRIU). 3. Move checkpoint off-host (bucket +
  sha256 manifest). 4. Static: `checkpointctl`/CRIT process-tree + mounts.
  5. Dynamic: rebuild image with buildah, restore in isolated cluster, record
  syscalls (sysdig/logray), hunt execve + egress.
- Commands: `crictl checkpoint -o /forensics/ckpt.tar <container>` + `checkpointctl show /forensics/ckpt.tar` + `kubectl get pod <p> -o yaml > pod-spec.yaml`
- Pitfalls: containerd/CRIU version skew breaks restore (match engine+CRIU);
  audit log sees API only — runtime behavior needs Falco/sysdig, not API logs.
- Sources: https://www.sysdig.com/blog/csi-forensics-unraveling-kubernetes-crime-scenes
  https://bipi.in/blog/kubernetes-incident-response
  https://h3ad-sec.github.io/H3AD-LEARN/threat-hunting/11-container-kubernetes-hunting.html

### W41 — macOS unified-log triage (tracev3 + TTL discipline)
- Signals: `/private/var/db/diagnostics/*.tracev3` + `uuidtext`, sysdiagnose
  archives, `log show` predicates, loginwindow/SSO narratives.
- Steps: 1. Prefer `log collect` archives over sysdiagnose for history (sysdiag
  is day-of only; most entries TTL out in hours). 2. Parse offline
  (mac_apt / Mandiant parser) to CSV/JSON, then grep sender/eventMessage
  (`IPConfiguration`, `SSID`, `loginwindow`). 3. Corroborate with plist + TCC
  + FSEvents (unified logs redact `private` without profile).
- Commands: `log collect --output /tmp/logs.logarchive` + `log show --archive /tmp/logs.logarchive --predicate 'senderImagePath CONTAINS "IPConfiguration"' --info | head -n 40`
- Pitfalls: "30-day retention" is a myth (rare long-TTL entries only); private
  redaction hides names/paths — install profile or corroborate elsewhere.
- Sources: https://blog.elcomsoft.com/2025/06/extracting-and-analyzing-apple-unified-logs/
  https://jebitok.hashnode.dev/macos-forensics-artefacts-tryhackme
  https://domoon.medium.com/mac-hunt-thm-writeup-bbdaed316031

### W42 — APFS snapshot diff (deleted-data-first discipline)
- Signals: APFS image, `tmutil listlocalsnapshots`, sealed System + Data
  volumes, TRIM/FileVault making carve hopeless.
- Steps: 1. List snapshots per volume (`tmutil`/`diskutil apfs
  listSnapshots`). 2. Mount each snapshot read-only (`mount_apfs -s <name>`),
  treat as its own filesystem with its own creation-time upper bound.
  3. Deleted-after-snapshot = intact in snapshot (with metadata). 4. Compare
  snapshot vs live file-by-file (mtime-ns LSB tricks live here on crafted
  challenges). 5. Only then fall back to clones/Spotlight/FSEvents; carve last.
- Commands: `tmutil listlocalsnapshots /` + `diskutil apfs listSnapshots /dev/diskXsY` + `mount_apfs -s <snap> /dev/diskXsY ~/snap_ro`
- Pitfalls: non-native tools misread APFS timestamps/extents — verify on macOS
  tooling; snapshot creation time bounds existence, it is not the file's time.
- Sources: https://www.nbftools.com/apfs-snapshots-in-digital-forensics/
  https://dixon.cx/digital-forensics-guide/macos
  https://ctf.bugku.com/writeup/detail/id/1317.html
