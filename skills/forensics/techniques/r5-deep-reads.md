# R5 deep reads — forensics (12 complete articles, browser-read 2026-10-17)

## 1. DFIR BengalSEO
- READ: MayaBot JS dropper via wscript posing as EXE; Matomo `stats.us3[.]org` idsite 35; 84 GitHub accounts; VT query on registrar+NS pair; 411 `wapp[.]live` subdomains.
- CHAIN: Bing SERP lure (github.io/pages.dev/sites.google) → Base62 referrer redirector → Turnstile/hCaptcha + Matomo fingerprint → 302 + Base64 timestamp → payload domain → ZIP → wscript MayaBot / scam call; hunt via Validin/urlscan/VT/GitHub API/Ahrefs/Any.Run.
- GOTCHA: Cloaked benign page + CORS-blocked CSS farm + monthly DOM shuffle defeat dup-content filters; check live 302/timestamp + matomo POST + Any.Run traffic.
- REUSE: Pivot on shared analytics ID + registrar/NS pair + commit `.patch` emails to cluster SEO-poison infra.

## 2. DFIR Bing-to-Akira
- READ: "ManageEngine OpManager" lure → trojan MSI → msimg32.dll side-load → AdgNsy.exe + AdaptixC2; `net user backup_DA … /add /dom` + Enterprise Admins; wbadmin NTDS staging; `locker.exe`; 44h to encrypt; DGA domain → :443.
- CHAIN: SEO MSI → BumbleBee DGA C2 → AdaptixC2 beacon (~5h later) → discovery → domain accounts → RustDesk → RDP to DC/backup → wbadmin shadow-copy → reverse-SSH → FileZilla exfil → Akira locker (root, then child domain days later).
- GOTCHA: 5h quiet + second-day return look like separate events; hunt DGA failures + new DA/EA + wbadmin + tunnels as ONE chain.
- REUSE: Alert on `net user /add /dom` + wbadmin + FileZilla + RustDesk co-occurring.

## 3. DFIR EtherRat/TukTuk
- READ: RAMMap-posing MSI via msiexec; portable node + Run key `AppResolver` → headless node + `.cfg`; 1rpc.io chain config; TryCloudflare tunnel; `rundll32 comsvcs` LSASS → `im4.txt`; NetExec lateral; GoTo Resolve RMM.
- CHAIN: Malicious MSI → EtherRat + Node → Run persistence → chain-config update → tunnel C2 → discovery → comsvcs dump → lateral → RMM → cloud exfil → Gentleman ransomware.
- GOTCHA: No live C2 until chain config updated + decoy domains pollute attribution; monitor 1rpc.io/Arweave/msiexec children/Run keys.
- REUSE: Blockchain/Arweave resolvers + TryCloudflare + RMM = C2 indicators, not noise.

## 4. DFIR Fog open-directory
- READ: Open dir with `sonic_scan.zip` (main.py + data.txt IP/user/pass/domain); DonPAPI `-pvk` for DPAPI/Chromium/Firefox; `any.ps1` auto-installs AnyDesk; Sliver + Proxychains; Certipy/Zer0dump; SonicWall VPN valid accounts.
- CHAIN: Scanner + target list → VPN login + port-scan → DonPAPI theft → Certipy + Zer0dump AD → SMB lateral → AnyDesk persistence → Sliver C2.
- GOTCHA: Open dir is affiliate toolkit, not victim; correlate `.bash_history` + data.txt targets with victims.
- REUSE: Hunt `sonic_scan.zip`/data.txt + AnyDesk ps1 + Sliver binaries on exposed boxes.

## 5. DFIR BlackSuit
- READ: Oversized Cobalt Strike beacon → CloudFlare C2; ~6h silence; in-memory SharpHound then saved to disk; Rubeus in-memory; SystemBC SOCKS; 15 days initial-to-ransom; 3 new Sigma rules.
- CHAIN: Unknown init → beacon → discovery (ADFind/systeminfo/nltest) → SharpHound/Rubeus → SMB lateral + service install → proxy → collection → 15d later SMB staging + RDP execute.
- GOTCHA: Unknown entry + dormant beacon + CloudFlare masking look benign; flag size-anomaly beacons + in-mem AD recon + ADMIN$ writes.
- REUSE: Large beacons + in-memory AD recon + SMB ADMIN$ staging = pre-ransom pattern.

## 6. DFIR Egg-Cellent Resume
- READ: Job-application lure (TA4557/FIN6 overlap); ie4uinit.exe side-load + msxsl.exe → more_eggs beacon; CS + Python Pyramid C2; CVE-2023-27532 Veeam lateral; cloudflared RDP tunnel; 8 new rules.
- CHAIN: Resume lure → LOLbins → more_eggs → dual C2 → discovery → Veeam exploit → lateral → tunnel persistence.
- GOTCHA: LOLbins + dual C2 look like admin activity; monitor ie4uinit/msxsl children + Veeam patch state + tunnels.
- REUSE: Job-lure + LOLbin + Veeam exploit + tunnel = one high-confidence chain.

## 7. DFIR OneNote-to-Nokoyawa
- READ: OneNote phishing (bypassed attachment blocks); IcedID → 30+ days beacon-only dwell; then CS + AnyDesk onto file/backup servers; FileZilla exfil → Nokoyawa.
- CHAIN: OneNote email → IcedID + persistence → month sleep → CS + AnyDesk → lateral → exfil → deploy.
- GOTCHA: Month of pure beaconing looks dead; track OneNote→IcedID + long-dwell + pre-encryption FTP.
- REUSE: Block OneNote attachments + hunt dormant IcedID + staged FTP tools pre-encryption.

## 8. Huntress Cleo (CVE-2024-50623/55956)
- READ: Dec 2024 LexiCom RCE; patch 5.8.0.21 STILL exploitable → second CVE; 10+ victims; Shodan-visible; defaults `C:\VLTrader`; exit IPs listed.
- CHAIN: Internet-facing Cleo → file-write RCE → PoC validation → mass-exploitation telemetry → firewall isolate → log/Shodan verify → await full patch.
- GOTCHA: "Fully patched" version still exploitable; isolate + check logs/Shodan, never trust version string.
- REUSE: Managed-file-transfer appliances = RCE-first; verify via Shodan + app logs.

## 9. Huntress SonicWall SSLVPN
- READ: Compromise spike explicitly NOT linked to <5% cloud-backup advisory; remediation = MySonicWall impact list + restrict WAN mgmt + credential reset.
- CHAIN: Exposed SSLVPN → mass logins → telemetry spike → impact verify → contain → reset → advisory remediation.
- GOTCHA: Unrelated advisory confuses scoping; use impact check + ingress restriction, don't conflate advisories.
- REUSE: Default-deny WAN management + external impact-verify + credential rotation on VPN spikes.

## 10. RedCanary 2026 TDR (Zscaler)
- READ: Now Zscaler (acquisition); top-10 mostly browser-executed or stealing browser data + paste-and-run; Trends = AI threats vs threats-to-AI + supply-chain/RMM.
- CHAIN: Yearly telemetry → top-10 + Trends → prioritize browser + AI + supply-chain/RMM → update detections.
- GOTCHA: Landing page JS-gated boilerplate, thin numbers; use full report PDF + liner notes.
- REUSE: Yearly re-prioritize around browser-stored secrets + paste-and-run + RMM abuse.

## 11. SpecterOps ADCS BloodHound P1
- READ: Knudsen Jan 2024; Certified Pre-Owned → EnterpriseCA node; ESC1 Cypher (enroll-supply-subject + auth + no-approval + signatures/schema-version); credit Oliver Lyak.
- CHAIN: Model CA/templates (six ESC1 reqs) → Cypher path query → visualize enroll path → enroll-and-escalate.
- GOTCHA: ADCS never one edge; check all six reqs incl. CA Enroll right + version/signatures.
- REUSE: Query ADCS ESC paths in BloodHound pre-engagement; require approval + constrain enrollment rights.

## 12. SKIPPED — 0xdf Meerkat (HTTP 404)

## 13. THM Chrome forensics (MrHDK)
- READ: `chromefiles.zip` → Wireshark SMB2 rebuild of `transfer.exe` → dnSpy AES key+IV → CyberChef decrypt → zip → AppData; DPAPImk2john → John+rockyou; Local State `os_crypt` key base64 minus 5-byte DPAPI header → Mimikatz masterkey → AES → Login Data URLs/passwords.
- CHAIN: PCAP rebuild → dnSpy static → CyberChef decrypt → DPAPI hash → John → Local State decode → Mimikatz → Chrome Login Data decrypt.
- GOTCHA: SMB2 AES hides files + hash encoding breaks John + 5-byte prefix breaks decrypt; rebuild files, recode UTF-8, strip header.
- REUSE: Chrome forensics = Local State + Login Data + DPAPI masterkey as one chain.

## 14-15. SKIPPED — BrunnerCTF VeraCrypt + After-Hours WMI (Medium Cloudflare 403, no snapshots)
