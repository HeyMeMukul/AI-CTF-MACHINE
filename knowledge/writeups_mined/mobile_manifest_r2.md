# Mobile CTF Writeups Mined R2 — Manifest (technique-only, no flags/keys)

> Method: WebSearch (fast/deep) + selective WebFetch, 2024–2026 preferred.
> R1-dedupe: every candidate URL was checked against
> `knowledge/writeups_mined/mobile_manifest.md` URL set
> (`comm` on sorted URL lists); R1 domains `lautarovculic.github.io` and
> `pentest-bi0s/Mobile-CTFs` excluded wholesale. `[RESEARCH]` = Android/iOS
> security research with direct CTF applicability. `[PRACTICE]` = labs /
> training repos. Technique-only: no flag/key values recorded.
> Index-transcribed rows (fetched README/tag/tree pages) carry summaries from
> title + file context, same convention as R1 Batch L.

## Batch R2-A — packer evolutions + dumpers (fetched + extracted)

- [Jiagu unpacker (AES-CBC+XOR, fake-ZIP-flag)](https://github.com/SafaSafari/jiagu_unpacker) | hard | shell-DEX isolate + app-class recovery vs modern Jiagu [RESEARCH-tool]
- [Defeating Jiagu the wrong way (libjgbibc stub)](https://medium.com/@0xcc00/defeating-jiagu-android-packer-the-wrong-way-a288bf316441) | hard | single-dex stub → protector-VM `.so` triage when static extractors fail
- [Tencent Legu Оренбургской dossier (TxAppEntry + post-2023 bypass)](https://github.com/zahidaz/awake/blob/main/docs/packers/tencent-legu.md) | hard | TxAppEntry/anti-debug/anti-Frida map + open/read scrub + connect-port null-route snippets [RESEARCH]
- [SecNeo decrypt_jar_128K hook dumper](https://gist.github.com/wilco375/d5d51bec59a35a77856d506f44afb79f) | hard | hook decrypt entry → post-decrypt DEX dump; notes classes.dgc method-body gap
- [secneo-gadget (TS unpack/dissect)](https://github.com/strazzere/secneo-gadget) | hard | gadget-driven SecNeo debug/dump pipeline [RESEARCH-tool]
- [Jiagu open re-implementation (no-landing dex)](https://github.com/Frezrik/Jiagu) | hard | shell-dex build + no-landing load scheme reference [RESEARCH]
- [Bangcle second-gen protector](https://github.com/KuNgia09/Bangcle) | hard | protector-side reference for telltale hunting [RESEARCH]
- [Shark Bangcle dossier](https://github.com/Anthropicdaddy/Shark/blob/main/docs/packers/bangcle.md) | medium-hard | assets-DEX + file-op hook / frida-dexdump no-config path [RESEARCH]
- [APKiD signature releases (JiaguK/SecNeo/DexGuard9/FreeRASP)](https://github.com/rednaga/APKiD/releases) | medium-hard | per-packer `.so`/header telltales for triage gate [RESEARCH-index]
- [frida4burp interception bundle (unpin+antiroot+proxy)](https://github.com/y0k4i-1337/frida4burp) | hard | config-first multi-script chain: cert-inject + proxy-override + native TLS hooks [RESEARCH-tool]

## Batch R2-B — anti-Frida / root / Magisk / KernelSU / attestation (fetched + extracted)

- [frida-stealth patch set (rename threads/sockets/ports)](https://github.com/AsenOsen/frida-stealth) | hard | source-build stealth + ZygiskFrida + AndroGum gumjs path [RESEARCH]
- [FridaDetectionBypass (ptrace/port/artifact/gadget)](https://github.com/aimardcr/FridaDetectionBypass) | hard | per-vector bypasses + custom-server + certificate-pinned channel notes [RESEARCH]
- [frida-android-scripts bundle 2026 (ssl/root/crypto/monitor)](https://github.com/abhirampatel/frida-android-scripts) | hard | RootBeer/file/Build.TAGS/exec/prop hooks + Cipher.doFinal boundary log [RESEARCH-tool]
- [frida-ssl-pinning-bypass collection (incl. anti-frida)](https://github.com/eros1sh/frida-ssl-pinning-bypass) | hard | universal + app-specific + native (curl/OpenSSL/BoringSSL) + stealth variants [RESEARCH-tool]
- [Securify root-battery bypass (k3.d label pairing)](https://medium.com/@mazin.ahmed.business/android-root-detection-bypass-using-frida-writeup-1-85994a28ced2) | hard | injection/hosts/magiskhide/ART/selinux/seccomp/ROM checks → per-check Frida fail-closed bypass
- [Root-detection bypass field notes 2025](https://medium.com/@AhmadSopyan/how-to-bypass-root-detection-with-frida-dbb59aa9704b) | hard | codeshare-fail → jadx library-ID → narrow hook ladder on AVD+Magisk
- [UnCrackable3 2026 (watchdog + native anti-Frida)](https://medium.com/@mahmoudslama695/cracking-owasp-uncrackable-level-3-bypassing-anti-frida-and-watchdog-protections-on-android-a93c767daca8) | hard | strstr-watchdog race + RootDetection triple + tampered-flag gate bypass chain
- [Zygisk-Assistant (hide root+Zygisk KSU/Magisk/APatch)](https://github.com/snake-4/Zygisk-Assistant) | hard | denylist/umount-modules hiding model per manager [RESEARCH-tool]
- [ksu_module_susfs (kernel-level hide)](https://github.com/CKMagisk/ksu_module_susfs) | hard | SUS-FS kernel hide helper for KernelSU [RESEARCH-tool]
- [hide-virt-apex-su (tmpfs-over-APEX detach)](https://github.com/serkenn/hide-virt-apex-su) | hard | zygote-namespace detach of stacked su-tmpfs + enforcing restore [RESEARCH-tool]
- [Magisk vs KernelSU detection comparison](https://github.com/OutrageousStorm/android-root-methods/blob/main/docs/magisk-vs-kernelsu.md) | medium-hard | artifact tables (su/data.adb/ps vs syscall-level) + Shamiko/TrickyStore stack [RESEARCH]
- [KernelSU-Next + SuSFS hide guide](https://gist.github.com/TheUnrealZaka/042040a1700ad869d54e781507a9ba4f) | hard | Noble-ROM hide procedure crib [RESEARCH]
- [VPN-hide module (Binder+kmod+iptables layers)](https://www.magiskmodule.com/vpnhide) | hard | per-app Java/native/visibility/port roles + tun0/port-scan masking [RESEARCH]
- [MASTG-TECH-0012 pinning-bypass technique](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0012) | hard | pinning-bypass decision surface + DEMO-0106/0107/0108/0114/0115/0117-0119/0124/0125/0131 pointers [RESEARCH-index]
- [OWASP anti-reversing defenses](https://mas.owasp.org/MASTG/0x05j-Testing-Resiliency-Against-Reverse-Engineering/) | hard | debugger/root/integrity/emulator control catalogue [RESEARCH]
- [Xanhacks Frida cheatsheet (404CTF frida-me)](https://xanhacks.gitlab.io/ctf-docs/android/03-frida) | medium-hard | setup + Java/native hook + frida-trace + PIN-bruteforce pattern [PRACTICE]

## Batch R2-C — iOS runtime / plist / guides (fetched + extracted)

- [HTB Cryptohorrific via plistutil (iOS)](https://medium.com/@gbahenrijoel/hackthebox-mobile-cryptohorrific-d22aa45c2301) | hard | challenge.plist → XML → staged Base64/key recovery inside iOS bundle
- [Practical CTF iOS (Mach-O + CCCrypt)](https://book.jorianwoltjer.com/mobile/ios) | hard | Mach-O triage + Apple-source arg-shape method for CCCrypt-style sinks [RESEARCH-guide]
- [iOS reverse guide (_dyld clamp + fork/sysctl)](https://github.com/zhaoxuya520/reverse-skill/blob/main/skills/mobile-reverse/references/ios-reverse-guide.md) | hard | dumpdecrypted/frida-ios-dump + ObjC-hook + image-count clamp + scheme/sysctl hides [RESEARCH-guide]
- [Platform RE notes (dyld/Mach-O/embedded)](https://cdn.jsdelivr.net/gh/zhaoxuya520/reverse-skill@main/skills/reverse-engineering/platforms.md) | hard | otool/lipo/nm + dyld-link + automotive/RTOS appendix [RESEARCH-guide]

## Batch R2-D — 2024 hard Android event writeups (xbr01 index-transcribed + extracted)

> Writeup URLs transcribed from fetched
> `xbr01/Mobile-CTF-Challenges` README + recursive tree (stubs <500B skipped).

- [SekaiCTF 2024 Crack Me (45MB APK + unminified JS)](https://github.com/xbr01/Mobile-CTF-Challenges/blob/main/SekaiCTF%20%282024%29/Crack%20Me/Write-Up.md) | hard | giant-APK triage → shipped JS-bundle recover → logic rebuild
- [SekaiCTF 2024 Hijacker (overlay exploit app)](https://github.com/xbr01/Mobile-CTF-Challenges/blob/main/SekaiCTF%20%282024%29/Hijacker/Write-Up.md) | hard | overlay replica (Overlay.java/xml) vs secure gate
- [CyberSpace 2024 login](https://github.com/xbr01/Mobile-CTF-Challenges/blob/main/CyberSpace%20CTF%20%282024%29/login/writeup/Write-Up.md) | medium-hard | login-APK auth-gate solve
- [IRON 2024 TreasureHunt](https://github.com/xbr01/Mobile-CTF-Challenges/blob/main/IRON%20CTF%202024/TreasureHunt/Write-Up.md) | medium-hard | hunt-state solve chain
- [IRON 2024 Fire in the Base Camp (hook.js)](https://github.com/xbr01/Mobile-CTF-Challenges/blob/main/IRON%20CTF%202024/Fire%20in%20the%20Base%20Camp/Write-Up.md) | hard | Frida hook-gated camp logic
- [IRON 2024 Secure Vault](https://github.com/xbr01/Mobile-CTF-Challenges/blob/main/IRON%20CTF%202024/Secure%20Vault/Write-Up.md) | hard | vault-crypto reimpl
- [TCP1P 2024 Intro to APK](https://github.com/xbr01/Mobile-CTF-Challenges/blob/main/TCP1P%20%282024%29/Intro%20to%20APK/Write-Up.md) | medium-hard | intro APK with screenshot-oracle closer
- [1337UP 2024 Cold Storage (brute-force script)](https://github.com/xbr01/Mobile-CTF-Challenges/blob/main/1337UP%20LIVE%20%28Intigriti%29%20%282024%29/Cold%20Storage/Write-Up.md) | hard | Cordova-www PIN/keygen split (companion to R1 W17 pair)
- [1337UP 2024 Quiz (click-loop)](https://github.com/xbr01/Mobile-CTF-Challenges/blob/main/1337UP%20LIVE%20%28Intigriti%29%20%282024%29/Quiz/Write-Up.md) | medium-hard | quiz-state automation solve
- [1337UP 2024 Where's my APK (.aab)](https://github.com/xbr01/Mobile-CTF-Challenges/blob/main/1337UP%20LIVE%20%28Intigriti%29%20%282024%29/Where%27s%20my%20APK%3F/Write-Up.md) | hard | App-Bundle (.aab) split-APK reconstruction triage
- [PwnSec 2024 ezmobile](https://github.com/xbr01/Mobile-CTF-Challenges/blob/main/PwnSec%20%282024%29/ezmobile/Write-Up.md) | medium-hard | entry APK gate solve
- [PwnSec 2024 Firestorm (Firebase conn + hook)](https://github.com/xbr01/Mobile-CTF-Challenges/blob/main/PwnSec%20%282024%29/Firestorm/Write-Up.md) | hard | Firebase-backed mobile chain with result-hook (companion to R1 FireStorm pair)
- [PwnSec 2024 FireInTheHole (43KB writeup)](https://github.com/xbr01/Mobile-CTF-Challenges/blob/main/PwnSec%20%282024%29/FireInTheHole/Write-Up.md) | hard | deep Firebase/rules chain
- [PwnSec 2024 Snake (Hook.js)](https://github.com/xbr01/Mobile-CTF-Challenges/blob/main/PwnSec%20%282024%29/Snake/Write-Up.md) | hard | YAML-gadget path companion (3rd Snake source; cf. R1 W21 pair)
- [WWF 2024 Remind's Funny Stories 3](https://github.com/xbr01/Mobile-CTF-Challenges/blob/main/World%20Wide%20Flags%20%282024%29/Remind%27s%20Funny%20Stories%203/Write-Up.md) | medium-hard | story-unlock state solve
- [LakeCTF 2024 AndroidApplaketion (equations solver)](https://github.com/xbr01/Mobile-CTF-Challenges/blob/main/LakeCTF%20%282024%29/AndroidApplaketion/Write-Up.md) | hard | equation-oracle offline solver
- [m0lecon 2025 DroidCryptor (Decrypt.py)](https://github.com/xbr01/Mobile-CTF-Challenges/blob/main/m0lecon%20%282025%29%20Beginner/DroidCryptor/Write-Up.md) | hard | asset-crypto offline decrypt (companion to bi0s-pentest Droid Cryptor)
- [KnightCTF 2025 Knight's Droid](https://github.com/xbr01/Mobile-CTF-Challenges/blob/main/KnightCTF%202025/Knight%27s%20Droid/Write-Up.md) | hard | droid-gate chain (companion to bi0s-pentest Knight)
- [BlockCTF 2024 Flower App (macOS .app)](https://github.com/xbr01/Mobile-CTF-Challenges/blob/main/BlockCTF%202024/Flower%20App/Write-Up.md) | hard | Apple-bundle RE crossover (Mach-O + plist surface)
- [HTB APKey via Janus splice](https://medium.com/@gbahenrijoel/hackthebox-mobile-apkey-e1dd0d434aeb) | hard | V1-signature APK splice → smali gate-strip → resign/install (2nd APKey source)
- [Bugku crackme checkSN (jadx + toHexString hook)](https://cloud.tencent.com/developer/article/2099688) | hard | 22-char SN gate: MD5 + positional shuffle → Frida intermediate capture
- [Bugku mobile series survey](https://programmerall.com/article/32241203411) | medium-hard | Android RE challenge survey [PRACTICE-index]
- [le31ei mobile2 training writeup](https://github.com/le31ei/ctf_challenges/blob/main/mobile/mobile2/writeup.pdf) | medium-hard | service-team training mobile lab [PRACTICE]

## Batch R2-E — 2025–2026 event writeups (fetched + extracted / tag-transcribed)

> pentest.bi0s.in rows transcribed from the fetched `mobile-security` tag page
> (33 posts, Jun 2026); technique families from title context.

- [UMASS 2026 Android ARM64 custom VM (liblegocore)](https://medium.com/@abdowaer098/android-arm64-umass-2026-ctf-writeup-eb4b0625f578) | hard | stripped-native RegisterNatives triage + ROT-7 red-herring + VM-handler reverse
- [BKISC 2026 Boring APK (AES-GCM assets + MitM graph-walk)](https://github.com/Abdelkad3r/cybersecurityelite.com/blob/main/content/ctf-writeups/bkisc-ctf-2026-boring-apk.md) | hard | NDK basic_string layout + qemu-aarch64 `.so` exec + meet-in-the-middle
- [BKISC 2026 Boring APK (ctftime pointer)](https://ctftime.org/writeup/40784) | hard | phone/mobile-tagged Boring-APK solve pointer
- [MHC 2026 NoSQolarly run-as + Couchbase read](https://medium.com/@sensosamwel63/mobile-hacking-conference-ctf-4b4851289f81) | hard | run-as grep JWT → cblite2 WAL carve → embedded-NoSQL read
- [MHC 2026 NoSQolarly N1QL + prompt-inject chain](https://github.com/deriv-security/ctf-writeups/blob/main/2026/Mobile-Hacking-Conference-CTF/android/NoSQolarly/README.md) | hard | local N1QL injection + AI context prompt-inject → JWT → AES-256-GCM key
- [MHC 2026 DreamForge-AI](https://github.com/deriv-security/ctf-writeups/tree/main/2026/Mobile-Hacking-Conference-CTF/android/DreamForge-AI) | hard | AI-companion app chain (tree-verified)
- [MHC 2026 KYC-Me-If-You-Can](https://github.com/deriv-security/ctf-writeups/tree/main/2026/Mobile-Hacking-Conference-CTF/android/KYC-Me-If-You-Can) | hard | KYC-gate app chain (tree-verified)
- [bi0sCTF Tallocator (native + heap)](https://bi0sblog-1271c6.gitlab.io/2024/02/26/Pwn/Tallocator-bi0sctf2024/) | hard | matrix-op RE + arbitrary-free heap corrupt → ORW (kernel-adjacent companion)
- [bi0sCTF22 DroidComp full post (WebView+AIDL)](https://bi0sblog-1271c6.gitlab.io/2023/01/25/Misc/bi0sCTF22-DroidComp/) | hard | JS-bridge → service-channel chain (full-post source)
- [Squirrel DROID](https://pentest.bi0s.in/blog/posts/squirrel-ctf-droid/) | hard | droid-gate solve
- [Shakti nowyouseeme](https://pentest.bi0s.in/blog/posts/shakti-ctf-nowyouseeme/) | hard | visibility-gate solve
- [PwnSec RudeFrida (3rd source)](https://pentest.bi0s.in/blog/posts/pwnsec-ctf-rude-frida/) | hard | rude-check ladder bypasses
- [PwnSec FreakyFrida (3rd source)](https://pentest.bi0s.in/blog/posts/pwnsec-ctf-freaky-frida/) | hard | dual-`.so` anti-Frida duel
- [PwnSec CuteFrida](https://pentest.bi0s.in/blog/posts/pwnsec-ctf-cute-frida/) | hard | Frida-ladder tutorial duel
- [Pearl Shadow Vault](https://pentest.bi0s.in/blog/posts/pearl-ctf-shadow-vault/) | hard | vault-crypto chain
- [Payatu Where Am I](https://pentest.bi0s.in/blog/posts/payatu-hiring-ctf-where-am-i/) | hard | location-oracle solve
- [Payatu Snorlax](https://pentest.bi0s.in/blog/posts/payatu-hiring-ctf-snorlax/) | hard | gate-chain solve
- [Payatu Path Finder](https://pentest.bi0s.in/blog/posts/payatu-hiring-ctf-path-finder/) | hard | path-oracle solve
- [Payatu Gate Keeper](https://pentest.bi0s.in/blog/posts/payatu-hiring-ctf-gate-keeper/) | hard | keeper-gate bypass
- [Payatu A Strange Door](https://pentest.bi0s.in/blog/posts/payatu-hiring-ctf-a-strange-door/) | hard | door-gate solve
- [P3RF3CT Knight (2nd source)](https://pentest.bi0s.in/blog/posts/p3rf3ctr00t-ctf-knight/) | hard | knight-move oracle path
- [MHC Spin and Win (2nd source)](https://pentest.bi0s.in/blog/posts/mobile-hacking-community-ctf-spin-and-win/) | medium-hard | spinner-RNG predict
- [MHC Prints](https://pentest.bi0s.in/blog/posts/mobile-hacking-community-ctf-prints/) | hard | print-oracle chain
- [MHC No Matter What You See](https://pentest.bi0s.in/blog/posts/mobile-hacking-community-ctf-no-matter-what-you-see/) | hard | display-spoof duel
- [MHC Based](https://pentest.bi0s.in/blog/posts/mobile-hacking-community-ctf-based/) | hard | encoding-ladder solve
- [m0lecon Droid Cryptor (2nd source)](https://pentest.bi0s.in/blog/posts/m0lec0n-ctf-droid-cryptor/) | hard | asset-crypto decrypt
- [l3ak Brain Calc (2nd source)](https://pentest.bi0s.in/blog/posts/l3ak-ctf-brain-calc/) | hard | Chaquopy `.imy` decode path
- [l3ak Apkocalypse (root + fwrite hook)](https://pentest.bi0s.in/blog/posts/l3ak-ctf-apkocalypse/) | hard | RootDetection fail-closed hook → fwrite-arg log on unlinked file
- [HeroCTF Freeda Simple Hook (2nd source)](https://pentest.bi0s.in/blog/posts/heroctf-freeda-simple-hook/) | medium-hard | method-hook ladder entry
- [HeroCTF Freeda Not Root (2nd source)](https://pentest.bi0s.in/blog/posts/heroctf-freeda-not-root/) | hard | root-check hook chain
- [HeroCTF Freeda Native Hook (2nd source)](https://pentest.bi0s.in/blog/posts/heroctf-freeda-native-hook/) | hard | native-function hook chain
- [Eschaton Hello World (2nd source)](https://pentest.bi0s.in/blog/posts/eschaton-ctf-hello-world/) | medium | first-activity triage ladder
- [Eschaton Hamster Combat (2nd source)](https://pentest.bi0s.in/blog/posts/eschaton-ctf-hamster-combat/) | medium-hard | tap-game state tamper
- [Eschaton Couple Gallery (2nd source)](https://pentest.bi0s.in/blog/posts/eschaton-ctf-couple-gallery/) | medium-hard | gallery-pair puzzle
- [Cyberchaze Super Secure Catalog](https://pentest.bi0s.in/blog/posts/cyberchaze-ctf-super-secure-catalog/) | hard | catalog-gate chain
- [Cyberchaze Specialist Beta](https://pentest.bi0s.in/blog/posts/cyberchaze-ctf-specialist-beta/) | hard | beta-gate chain
- [Cyberchaze Secure Catalog APK](https://pentest.bi0s.in/blog/posts/cyberchaze-ctf-secure-catalog-apk/) | hard | catalog-APK chain
- [Cyberchaze Firmware (res/raw + strings.xml)](https://pentest.bi0s.in/blog/posts/cyberchaze-ctf-firmware/) | hard | res/raw firmware.bin + XML-password + overlapped-write carve
- [Cyberchaze Capture Me](https://pentest.bi0s.in/blog/posts/cyberchaze-ctf-capture-me/) | hard | capture-oracle chain
- [BYUCTF baby-android-2](https://pentest.bi0s.in/blog/posts/byuctf-baby-android-2/) | hard | second-stage droid gate
- [BYUCTF baby-android-1](https://pentest.bi0s.in/blog/posts/byuctf-baby-android-1/) | medium-hard | entry droid gate

## Batch R2-F — classic-hard archive writeups (Mobile-CTF-Lab index-transcribed)

> URLs transcribed from the fetched `REal0day/The-Mobile-CTF-Lab` README
> (which mirrors `xtiankisutsa/awesome-mobile-CTF`, also fetched).
> R1-covered challenges/authors skipped; technique from title context.

- [CSRumble 2023 Exterminate](https://ik0ri4n.de/rumble-23#exterminate) | hard | rumble-mobile extermination chain
- [BSidesTLV 2023 KeyHunter](https://github.com/evyatar9/Writeups/tree/master/CTFs/2023-BSidesTLV/Mobile/464-KeyHunter) | hard | key-hunt mobile RE
- [UMDCTF 2023 JNIdorino](https://ctftime.org/writeup/37170) | hard | JNI-gated dino challenge
- [UMDCTF 2023 Pokeball Escape](https://ctftime.org/writeup/37169) | hard | escape-logic mobile chain
- [UMDCTF 2023 Whos That Pokemon](https://ctftime.org/writeup/37168) | hard | oracle-guess mobile chain
- [NahamCon 2022 Secure Notes (evyatar9)](https://github.com/evyatar9/Writeups/tree/master/CTFs/2022-NahamCon_CTF/Mobile/Secure_Notes) | hard | secure-notes vault (2nd source)
- [NahamCon 2022 OTP Vault](https://muhammad-alief.medium.com/nahamcon-ctf-2022-writeup-android-reverse-engineering-otp-vault-870e22d2ac50) | hard | OTP-vault RE + token recovery
- [NahamCon 2022 Mobilize](https://codingmace.gitbook.io/masterward/ctf/2022/nahamcon-ctf-2022#mobilize) | hard | mobilize deploy-state solve
- [MRCTF 2022 Stuuuuub](https://github.com/LLeavesG/MRCTF2022-Stuuuuub) | hard | stub-loader RE duel
- [CSRumble 2022 THREE LITTLE KEYS](https://github.com/xXLeoXxOne/writeups/blob/main/CyberSecurityRumble%202022/THREE%20LITTLE%20KEYS.md) | hard | triple-key staged solve
- [WMCTF 2022 WM Baby Droid](https://teamrocketist.github.io/2022/08/23/Pwn-WMCTF2022-WM-Baby-Droid/) | hard | baby-droid kernel-adjacent chain
- [Hacky Holidays 2022 Unlock Train Data](https://github.com/a-r-r-o-w/capture-the-flag/tree/master/writeups/hacky-holidays-deloitte-2022/downtown/easy-unlock-train-data) | hard | transit-data unlock chain
- [Hacky Holidays Identify Yourself](https://github.com/Matilda12390/Hacky-Holidays-CTF-Writeups/blob/main/Identify%20Yourself/Writeup.md) | hard | identity-gate solve
- [GreyCat 2022 Memory Game P2](https://rainbowpigeon.me/posts/grey-cat-the-flag-qualifiers-2022/#-memory-game-part-2) | hard | memory-oracle part 2
- [GreyCat 2022 Memory Game P1](https://rainbowpigeon.me/posts/grey-cat-the-flag-qualifiers-2022/#-memory-game-part-1) | hard | memory-oracle part 1
- [1337UP 2022 Gandalf's Interface](https://github.com/pymivn/ctf/blob/main/2022-1337UP-LIVE-CTF/GandalfsInterface.md) | hard | interface-gate solve
- [HacktivityCon 2021 (ikuamike)](https://blog.ikuamike.io/posts/2021/hacktivitycon-2021-ctf/) | hard | mobile track solve set
- [CTF Android (evabssi, FR)](https://evabssi.com/write-up-du-ctf-android/) | hard | French-lab Android RE chain
- [Cellebrite 2021 Heisenberg Android](https://cellebrite.com/en/part-1-walk-through-of-answers-to-the-2021-ctf-investigating-heisenbergs-android-device/) | hard | device-image artifact hunt (mobile forensics)
- [Cellebrite 2021 Marsha iPhone FFS/Backup](https://cellebrite.com/en/part-3-walk-through-of-answers-to-the-2021-ctf-marshas-iphone-ffs-and-backup/) | hard | iOS FFS + backup carve
- [Cellebrite 2021 Beth iPhone](https://cellebrite.com/en/part-4-walk-through-of-answers-to-the-2021-ctf-beths-iphone/) | hard | iOS image artifact hunt
- [Cellebrite 2021 (williamskosasi)](https://medium.com/@williamskosasi/cellebrite-ctf-2021-writeup-b73d821a708) | hard | 2nd-source device-forensics path
- [H@cktivitycon 2021 mobile (desterhuizen)](https://desterhuizen.medium.com/h-cktivitycon-2021-mobile-challenge-writeup-2e1a8b0bc9d6) | hard | 2nd-source mobile chain
- [Belkasoft May 2021](https://belkasoft.com/belkactf-may2021-writeup) | hard | mobile-artifact DFIR chain
- [STACK the Flags 2020 mobile](https://suntanchicken.medium.com/stack-the-flags-2020-mobile-challenges-write-up-493578091e07) | hard | stacked mobile gate set
- [HacktivityCon 2020 mobile (gogglehead)](https://www.goggleheadedhacker.com/blog/post/19) | hard | mobile track solve
- [CyberSpaceKenya zulumeats3 (ikuamike)](https://blog.ikuamike.io/posts/2020/cyberspacectf-zulumeats3/) | hard | meat-gate mobile solve
- [Magnet 2020 Android (stark4n6)](https://www.stark4n6.com/2020/06/magnet-virtual-summit-2020-ctf-android.html) | hard | Android image forensics
- [Magnet 2020 iOS (stark4n6)](https://www.stark4n6.com/2020/06/magnet-virtual-summit-2020-ctf-ios.html) | hard | iOS image forensics
- [Magnet 2020 iOS (dfir300)](https://dfir300.blogspot.com/2020/06/mvs2020ctf-write-up-ios.html) | hard | 2nd-source iOS forensics
- [Google CTF 2020 Android (blackbeard666)](https://blackbeard666.github.io/pwn_exhibit/content/2020_CTF/GoogleCTF/re_android/android_writeup.html) | hard | official-track Android RE
- [Google CTF 2020 Android (vsnrain)](https://github.com/vsnrain/ctf-writeups/blob/master/2020/googlectf/README.md) | hard | 2nd-source Android track
- [DFA/CCSC 2020 iOS forensics (iLEAPP)](https://www.petermstewart.net/dfa-ccsc-spring-2020-ctf-apple-ios-forensics-with-ileapp/) | hard | iLEAPP-parser artifact chain
- [AppSecIL greatsuccess (klassiker)](https://github.com/klassiker/ctf-writeups/blob/master/2020/appsec-il/greatsuccess.md) | hard | appsec gate chain
- [SunshineCTF 2020 iOS spoof](https://dev.to/igotinfected/spoofing-an-ios-device-tsa-techie-sunshinectf-2020-write-up-2l0c) | hard | iOS device-spoof gate
- [DroidCon SEC-T 2019 (anee.me)](https://anee.me/droidcon-sec-t-ctf-2019-d796be91bb3f) | hard | droidcon track RE
- [BSides Canberra 2019 You Shall Not Pass](https://medium.com/tsscyber/ctf-writeup-you-shall-not-pass-2c7a9254549b) | hard | gate-keeper RE duel
- [BSidesSF 2019 mobile track (aadityapurani)](https://aadityapurani.com/2019/03/07/bsidessf-ctf-2019-mobile-track/) | hard | mobile track set
- [BSidesSF CTF P1 (itsc0rg1)](https://medium.com/@itsc0rg1/bsidessf-ctf-challenge-write-up-part-1-e849bc917d37) | hard | challenge-author mobile path
- [BSidesSF CTF P2 (itsc0rg1)](https://medium.com/@itsc0rg1/bsidessf-ctf-challenge-write-up-part-2-f8f597be659) | hard | challenge-author mobile path II
- [Magnet 2019 mobile (stark4n6)](https://www.stark4n6.com/2019/04/ctf-on-budget-magnet-user-summit-2019_9.html) | hard | budget-device forensics
- [ASIS ShareL walkthrough](https://medium.com/bugbountywriteup/asis-ctf-sharel-walkthrough-da32f3533b40?) | hard | share-protocol mobile chain
- [Google CTF 2021 tridroid (official)](https://github.com/google/google-ctf/tree/master/2021/quals/pwn-tridroid) | hard | official Android pwn track
- [Google CTF 2020 reversing-android (official)](https://github.com/google/google-ctf/tree/master/2020/quals/reversing-android) | hard | official Android RE track
- [H1-202 2018 (corb3nik)](https://corb3nik.github.io/blog/h1-202-2018/h1-202-ctf) | hard | H1 mobile gate set
- [BSidesSF 2018 Android (antojoseph)](https://medium.com/@antojoseph_1995/bsidessf-2018-ctf-android-reversing-forensics-challenge-f5522664b6a2) | hard | Android RE + forensics pair
- [Hack the Android4 walkthrough](https://www.hackingarticles.in/hack-the-android4-walkthrough-ctf-challenge/) | hard | crackme-lab chain
- [SharifCTF Android Vol I](https://mstajbakhsh.ir/8st-sharifctf-android-writeups-vol/) | hard | Sharif Android set I
- [SharifCTF Android Vol II](https://mstajbakhsh.ir/8st-sharifctf-android-writeups-vol-ii/) | hard | Sharif Android set II
- [ASIS 2018 Gunshop (saarsec)](https://saarsec.rocks/2018/11/27/Gunshop.html) | hard | gunshop-logic RE duel
- [M1Con CTF (manchestergreyhats)](https://blog.manchestergreyhats.co.uk/2018/03/28/m1con-ctf-writeup/) | hard | M1 mobile set
- [BSidesSF wrap-up 2017 (skullsecurity)](https://blog.skullsecurity.org/2017/bsidessf-ctf-wrap-up) | hard | wrap-up mobile notes
- [itsC0rg1 mobile challenge notes](https://medium.com/@itsc0rg1/my-mobile-challenge-and-bsides-sf-ctf-f9fc4dfca60) | hard | author-side mobile design notes
- [Insomni'hack 2017 mindreader-250](https://github.com/ctfs/write-ups-2017/tree/6a3df5bcece6f952cb60db4a3ae2ce97a189b62d/insomnihack-teaser-2017/mobile/mindreader-250) | hard | mindreader oracle duel
- [LabyREnth mobile track (Palo Alto)](http://researchcenter.paloaltonetworks.com/2016/09/unit42-labyrenth-capture-the-flag-ctf-mobile-track-solutions/) | hard | vendor mobile-track survey
- [0ctf-2016 mobile dir](https://github.com/ctfs/write-ups-2016/tree/master/0ctf-2016/mobile) | hard | 0ctf mobile set pointer
- [Google-ctf-2016 mobile dir](https://github.com/ctfs/write-ups-2016/tree/39e9a0e2adca3a3d0d39a6ae24fa51196282aae4/google-ctf-2016/mobile) | hard | google mobile set pointer
- [RC3 2016 My Lil Droid](http://aukezwaan.nl/write-ups/rc3-ctf-2016-my-lil-droid-100-points/) | medium-hard | lil-droid gate solve
- [BE Cyber Dexter 2016](https://github.com/ctfs/write-ups-2016/tree/39e9a0e2adca3a3d0d39a6ae24fa51196282aae4/cyber-security-challenge-belgium-2016-qualifiers/Mobile%20Security/Dexter) | medium-hard | dexter-gate solve
- [BE Cyber Phishing 2016](https://github.com/ctfs/write-ups-2016/tree/39e9a0e2adca3a3d0d39a6ae24fa51196282aae4/cyber-security-challenge-belgium-2016-qualifiers/Mobile%20Security/Phishing-is-not-a-crime) | medium-hard | phish-trail mobile solve
- [TrendMicro 2015 offensive-200](https://github.com/ctfs/write-ups-2015/tree/9b3c290275718ff843c409842d738e6ef3e565fd/trend-micro-ctf-2015/analysis/offensive-200) | hard | offensive-analysis duel
- [CodeGate 2015 dodocrackme2](https://github.com/ctfs/write-ups-2015/tree/9b3c290275718ff843c409842d738e6ef3e565fd/codegate-ctf-2015/reversing/dodocrackme2) | hard | crackme RE duel
- [SECCON 2015 apk-1](https://github.com/ctfs/write-ups-2015/tree/9b3c290275718ff843c409842d738e6ef3e565fd/seccon-quals-ctf-2015/binary/reverse-engineering-android-apk-1) | hard | apk RE duel I
- [SECCON 2015 apk-2](https://github.com/ctfs/write-ups-2015/tree/9b3c290275718ff843c409842d738e6ef3e565fd/seccon-quals-ctf-2015/unknown/reverse-engineering-android-apk-2) | hard | apk RE duel II
- [32c3 2015 libdroid-150](https://github.com/ctfs/write-ups-2015/tree/9b3c290275718ff843c409842d738e6ef3e565fd/32c3-ctf-2015/reversing/libdroid-150) | hard | native-lib RE duel
- [ASIS 2014 numdroid](https://github.com/ctfs/write-ups-2014/tree/b02bcbb2737907dd0aa39c5d4df1d1e270958f54/asis-ctf-finals-2014/numdroid) | hard | num-oracle droid duel
- [SecuInside 2014 wooyatalk](https://github.com/ctfs/write-ups-2014/tree/b02bcbb2737907dd0aa39c5d4df1d1e270958f54/secuinside-ctf-prequal-2014/wooyatalk) | hard | messenger-protocol RE
- [Hack.lu 2013 Robot Plans](https://github.com/ctfs/write-ups-2013/tree/816de23a940856c10987b5047823de48a192c270/hack-lu-ctf-2013/internals/Robot-Plans) | hard | robot-plan RE duel

## Batch R2-G — attestation / keybox stack (fetched + extracted)

- [TrickyStore keybox resign model (SECURITY)](https://github.com/5ec1cff/TrickyStore/blob/release/SECURITY.md) | hard | keybox.xml resign of attest-chain + attest-key intercept caveats [RESEARCH]
- [playIntegrityFixDetector native engine](https://github.com/IR0NBYTE/playIntegrityFixDetector) | hard | PIF/PIF-fork/TrickyStore/TEESimulator/Treat-Wheel maps+props+socket detectors + key-attestation anomaly probes [RESEARCH-tool]
- [Shark play-integrity dossier](https://github.com/Anthropicdaddy/Shark/blob/main/docs/platform-abuse/play-integrity.md) | hard | May-2025 hardware-verdict enforcement impact + researcher workarounds [RESEARCH]
- [PlayIntegrityFix module](https://github.com/Bradford1040/PlayIntegrityFix) | hard | verdict-fix ladder (BASIC→DEVICE→STRONG) + keybox requirements [RESEARCH-tool]

## Batch R2-H — automotive / AAOS / companion-app (fetched + extracted)

- [BLE Theft Auto (USENIX Security '26)](https://www.usenix.org/system/files/usenixsecurity26-yu-jerry.pdf) | hard | aftermarket BLE keyfob app-layer RE: ILSpy DLL + hardcoded-cred/key-exchange audit [RESEARCH-paper]
- [BLE Theft Auto page](https://www.usenix.org/conference/usenixsecurity26/yu-jerry) | hard | talk pointer: crowdsourced-scan targeting model [RESEARCH-index]
- [AutoComply (Android Auto violations)](https://arxiv.org/html/2503.04003) | hard | CCFG static analysis of Auto manifest/service compliance gaps [RESEARCH-paper]
- [AOSP vehicle system isolation](https://source.android.com/docs/automotive/security/vehicle_system_isolation) | hard | CarService/VHAL/SELinux-ioctl trust-boundary map for AAOS attack surface [RESEARCH-doc]
- [AOSP IVI Bluetooth policy](https://source.android.com/docs/automotive/ivi_connectivity) | hard | CarBluetoothService/profile-manager pairing-policy surface [RESEARCH-doc]
- [Car-management-apps multi-tier analysis](https://www.researchgate.net/publication/349630201_A_Multi-Tier_Security_Analysis_of_Official_Car_Management_Apps_for_Android) | hard | OEM APK 改: permission/Janus/code-integrity/overlay/root finding catalogue [RESEARCH-paper]

## Batch R2-I — baseband-adjacent (fetched + extracted)

- [UNISOC baseband re-hosting line](https://arxiv.org/pdf/2608.07143v1) | hard | modem_control/cptl RE + AT+QADBKEY unlock + MPU-table instrumentation reclaim [RESEARCH-paper]
- [BaseMirror (CCS'24 RIL command RE)](https://arxiv.org/html/2409.00475v1) | hard | vendor-RIL → baseband-command static recovery across 28 firmwares [RESEARCH-paper]
- [BaseMirror ACM record](https://dl.acm.org/doi/pdf/10.1145/3658644.3690254) | hard | paper pointer: AP↔CP command-reuse statistics [RESEARCH-index]

## Batch R2-J — TrollStore-adjacent (fetched + extracted)

- [TrollStore (CoreTrust multi-signer bug)](https://github.com/opa334/TrollStore) | hard | permasign installer + version matrix + persistence-helper model [RESEARCH-tool]
- [TrollStore wiki (System-app + libmis)](https://github.com/opa334/TrollStore/wiki) | hard | FrontBoard/libmis launch check + icon-cache revert mechanics [RESEARCH-doc]

## Batch R2-K — mini-program / super-app (fetched + extracted)

- [wxappUnpacker (wuWxapkg pipeline)](https://github.com/cqg21/wxappUnpacker) | hard | wxapkg→config/js/wxml/wxss restore + adb pkg-pull path + subpackage caveats [RESEARCH-tool]
- [Wechat mini-program decompile kit 2024](https://github.com/huan-cdm/Wechat-small-program-decompile) | hard | decrypt→unpack end-to-end bundle [RESEARCH-tool]
- [WeChatMiniAppDecrypt (GUI automation)](https://github.com/YI597/WeChatMiniAppDecrypt) | hard | PC-WeChat decrypt+unpack toolset [RESEARCH-tool]
- [wxapkg-unpack (Rust/offline)](https://docs.rs/wxapkg-unpack/latest/wxapkg_unpack) | hard | cache-dir scan + offline-decrypt + version-pick unpacker [RESEARCH-tool]
- [Kanxue wxapkg RE thread 2024](https://bbs.kanxue.com/thread-281804.htm) | hard | WeChat-version-pinned unpack notes + wux1an/wxapkg pointer [RESEARCH]
- [WeChat mini-apps measurement (MiniCrawler)](https://dl.acm.org/doi/pdf/10.1145/3460081) | hard | subpackage + RE-driven crawler methodology [RESEARCH-paper]

## Batch R2-L — HarmonyOS / OpenHarmony (fetched + extracted)

- [dayu (ABC parser + decompiler)](https://github.com/hx1997/dayu) | hard | ark_disasm→pandasm→CFG/decompile pipeline for Ark bytecode [RESEARCH-tool]
- [ReArk (HAP/ABC workbench 2026)](https://github.com/lkimuk/ReArk) | hard | hap/app/abc browse + xref + resign + hilog/UI-device loop [RESEARCH-tool]
- [abcde (OpenHarmony RE kit)](https://github.com/Yricky/abcde) | hard | Kotlin ABC parser/disasm + resource-index + experimental JS decompile [RESEARCH-tool]
- [AbcKitTS bytecode instrumentation](https://developer.huawei.com/consumer/cn/doc/best-practices/bpta-abckitts-implements-instrumentation) | hard | libabckit-based method/block/instruction patch model (hook-point theory) [RESEARCH-doc]
- [arkcompiler_runtime_core](https://github.com/openharmony/arkcompiler_runtime_core) | hard | disassembler/pandafile/verifier/quickener source map [RESEARCH-src]
- [ArkCompiler eTS runtime overview](https://github.com/openharmony/arkcompiler_ets_runtime/blob/master/docs/overview.md) | hard | ABC/AOT execution + multi-device runtime model [RESEARCH-doc]

## Batch R2-M — solver/official additions (fetched + extracted / tree-transcribed)

- [1337UP Cold Storage (CryptoCat 4th source)](https://cryptocat.me/blog/ctf/2024/intigriti/mobile/cold_storage/) | hard | Cordova-www PIN/keygen split (4th source; cf. R1 W17 pair + R2-D)
- [SekaiCTF 2024 Crack Me (official solution)](https://github.com/project-sekai-ctf/sekaictf-2024/tree/main/reverse/crack-me/solution) | hard | author solution for giant-APK + JS-bundle challenge
- [UMass 2026 Brick Workshop (2nd source)](https://github.com/umair-aziz025/CTF_WRITEUPS/blob/main/UMass%20CTF%202026/writeups/Brick%20Workshop.md) | hard | liblegocore native path (2nd source; cf. Wa3r VM writeup)
- [UMass 2026 Smart Brick v2](https://github.com/umair-aziz025/CTF_WRITEUPS/blob/main/UMass%20CTF%202026/writeups/Smart%20Brick%20v2.md) | hard | second-stage brick VM duel
- [SANS Holiday Hack 2024 SantaSwipe (APK+AAB)](https://github.com/silly-lily/CTF-Writeups/blob/main/2024_SANS_Holiday_Hack/Act2/MobileAnalysis/README.md) | hard | APK + signed-AAB pair analysis with Java solver
- [MHL writeups repo mirror (same author)](https://github.com/mehmetfarisacar/Mobile-Hacking-Lab-Writeups) | medium-hard | repo mirror of R1 medium-series posts (index pointer)
- [Anti-Frida L1 training APK](https://github.com/brunovais/CTF_ANTI_FRIDA_LEVEL_1) | medium-hard | C++ anti-Frida training target [PRACTICE]
- [Android CTF assignment writeups 2026](https://github.com/ReGeLePuMa/android-ctf-challenges) | medium-hard | coursework mobile-device-security set [PRACTICE-index]
- [Android RE CTF collection (cywr)](https://github.com/cywr/android-re-ctfs) | medium-hard | static/dynamic/crypto/anti-analysis challenge set [PRACTICE-index]
- [Android CTF methodology writeup](https://github.com/Hrjyot/Android-CTF-writeup) | medium-hard | APK RE methodology + decoder [PRACTICE-guide]

## Batch R2-N — tool / guide / lab annex (fetched + extracted / index-verified)

> Clearly-marked annex: supports patterns; hard-count reported separately.

- [frida-dexdump (hluwa)](https://github.com/hluwa/frida-dexdump) | hard | in-memory DEX scan dumper [RESEARCH-tool]
- [medusa (Ch0pin)](https://github.com/Ch0pin/medusa) | hard | Frida instrumentation framework 2025 [RESEARCH-tool]
- [lemon eBPF memdump (eurecom-s3)](https://github.com/eurecom-s3/lemon) | hard | eBPF memory-dump for x64/ARM64/Android 2025 [RESEARCH-tool]
- [strongR-frida-android](https://github.com/hzzheyang/strongR-frida-android) | hard | custom-server stealth build [RESEARCH-tool]
- [ZygiskFrida](https://github.com/lico-n/ZygiskFrida) | hard | Zygisk-borne inject (no ptrace) [RESEARCH-tool]
- [Kitsune Mask (magisk-files)](https://github.com/HuskyDG/magisk-files) | hard | Magisk fork for ZygiskFrida-class hiding [RESEARCH-tool]
- [AntiFrida_Bypass bundle](https://github.com/apkunpacker/AntiFrida_Bypass) | hard | memory-trace hiding scripts [RESEARCH-tool]
- [Frida-Patchs collection](https://github.com/JsHookApp/Frida-Patchs) | hard | stealth-patch inspiration set [RESEARCH]
- [on-device APK RE kit](https://github.com/Acousticdevicemercouri734/androidReverse) | medium-hard | no-PC APK + native analysis flow [RESEARCH-tool]
- [awesome-frida index](https://github.com/dweinstein/awesome-frida) | medium-hard | script catalogue pointer [RESEARCH-index]
- [android-security-awesome](https://github.com/ashishb/android-security-awesome) | medium-hard | curated mobile-security pointer [RESEARCH-index]
- [osx-and-ios-security-awesome](https://github.com/ashishb/osx-and-ios-security-awesome) | medium-hard | iOS-security pointer [RESEARCH-index]
- [MobileApp pentest cheatsheet](https://github.com/tanprathan/MobileApp-Pentest-Cheatsheet) | medium-hard | methodology crib [RESEARCH-guide]
- [Android security reference](https://github.com/doridori/Android-Security-Reference) | medium-hard | reference pointer [RESEARCH-guide]
- [awesome-linux-android-hacking](https://github.com/pfalcon/awesome-linux-android-hacking) | medium-hard | hacking-resources pointer [RESEARCH-index]
- [Mobile Security Wiki](https://mobilesecuritywiki.com/) | medium-hard | wiki pointer [RESEARCH-index]
- [The iPhone Wiki](https://www.theiphonewiki.com/wiki/Main_Page) | medium-hard | iOS-internals pointer [RESEARCH-index]
- [secmobi wiki](https://github.com/secmobi/wiki.secmobi.com) | medium-hard | wiki pointer [RESEARCH-index]
- [osx-re-101](https://github.com/michalmalik/osx-re-101) | hard | OSX/iOS RE course pointer [RESEARCH-guide]
- [InsecureShop](https://github.com/optiv/Insecureshop) | medium | vuln-shop lab [PRACTICE]
- [OMTG-Hacking-Playground](https://github.com/OWASP/OMTG-Hacking-Playground) | medium | OWASP mobile lab [PRACTICE]
- [Damn-Vulnerable-Bank](https://github.com/rewanth1997/Damn-Vulnerable-Bank) | medium | vuln-bank lab [PRACTICE]
- [DVHMA hybrid app](https://github.com/logicalhacking/DVHMA) | medium | hybrid-app lab [PRACTICE]
- [InsecureBankv2](https://github.com/dineshshetty/Android-InsecureBankv2) | medium | bank-v2 lab [PRACTICE]
- [Sieve APK](https://github.com/mwrlabs/drozer/releases/download/2.3.4/sieve.apk) | medium | password-manager lab app [PRACTICE]
- [sievePWN](https://github.com/tanprathan/sievePWN) | medium | sieve exploit lab [PRACTICE]
- [DodoVulnerableBank](https://github.com/CSPF-Founder/DodoVulnerableBank) | medium | vuln-bank lab [PRACTICE]
- [owasp-igoat](https://github.com/hankbao/owasp-igoat) | medium | iOS goat lab [PRACTICE]
- [DVIA-v2](https://github.com/prateek147/DVIA-v2) | medium | iOS vuln-app v2 [PRACTICE]

## Batch R2-O — Frida CodeShare drop-in scripts (browse pages 1–3, fetched)

> Technique scripts, not writeups; counted separately in report. All URLs
> transcribed from fetched `codeshare.frida.re` browse pages.

- [universal SSL unpinning (pcipolloni)](https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/) | hard | re-pinning universal bypass [SCRIPT]
- [multiple unpinning (akabe1)](https://codeshare.frida.re/@akabe1/frida-multiple-unpinning/) | hard | multi-method cert-bypass [SCRIPT]
- [fridantiroot (dzonerzy)](https://codeshare.frida.re/@dzonerzy/fridantiroot/) | hard | antiroot-check bypass [SCRIPT]
- [multiple bypass SSL+root+emu (fdciabdul)](https://codeshare.frida.re/@fdciabdul/frida-multiple-bypass/) | hard | combo bypass [SCRIPT]
- [snapchat 2026 arm64 unpin (mr-blackhole)](https://codeshare.frida.re/@mr-blackhole/snapchat-ssl-bypass-all-new-version-of-2026/) | hard | per-app arm64 bypass [SCRIPT]
- [instagram unpin v395-430 (ferozomer)](https://codeshare.frida.re/@ferozomer/instagram-ssl-pinning-bypass/) | hard | version-pinned app bypass [SCRIPT]
- [ObjC method observer (mrmacete)](https://codeshare.frida.re/@mrmacete/objc-method-observer/) | hard | class/method call + arg/return log [SCRIPT]
- [APK crypto intercept (fadeevab)](https://codeshare.frida.re/@fadeevab/intercept-android-apk-crypto-operations/) | hard | Java-Crypto key/algo/plaintext boundary log [SCRIPT]
- [aesinfo runtime (dzonerzy)](https://codeshare.frida.re/@dzonerzy/aesinfo/) | hard | AES op info at runtime [SCRIPT]
- [universal unpinning 2 (sowdust)](https://codeshare.frida.re/@sowdust/universal-android-ssl-pinning-bypass-2/) | hard | all-SSL-check bypass [SCRIPT]
- [libc strstr anti-frida (enovella)](https://codeshare.frida.re/@enovella/anti-frida-bypass/) | hard | maps-scan needle bypass [SCRIPT]
- [find-android-hook (lichao)](https://codeshare.frida.re/@lichao890427/find-android-hook/) | hard | inline/GOT/Java hook finder [SCRIPT]
- [okhttp3 interceptor (owen800q)](https://codeshare.frida.re/@owen800q/okhttp3-interceptor/) | hard | OkHttp3 network intercept [SCRIPT]
- [iOS DataProtection list (ay-kay)](https://codeshare.frida.re/@ay-kay/ios-dataprotection/) | hard | NSFileProtectionKey enum [SCRIPT]
- [xamarin-antiroot (Gand3lf)](https://codeshare.frida.re/@Gand3lf/xamarin-antiroot/) | hard | Xamarin root-check bypass [SCRIPT]
- [iOS jailbreak bypass (liangxiaoyi)](https://codeshare.frida.re/@liangxiaoyi1024/ios-jailbreak-detection-bypass/) | hard | iOS13-tested JB bypass [SCRIPT]
- [android unpinning (masbog)](https://codeshare.frida.re/@masbog/frida-android-unpinning-ssl/) | hard | common-method unpin [SCRIPT]
- [dump-ios (lichao)](https://codeshare.frida.re/@lichao890427/dump-ios/) | hard | dumpdecrypted-via-Frida [SCRIPT]
- [flutter pinning iOS (zionspike)](https://codeshare.frida.re/@zionspike/bypass-flutter-pinning-ios/) | hard | Flutter-iOS cert bypass [SCRIPT]
- [fs-access hook (FrenchYeti)](https://codeshare.frida.re/@FrenchYeti/android-file-system-access-hook/) | hard | java.io.File + libc open/read + fd-path resolve [SCRIPT]
- [iOS all-class hooks (interference)](https://codeshare.frida.re/@interference-security/ios-app-all-classes-methods-hooks/) | hard | app-owned class/method mass-hook [SCRIPT]
- [iOS static analysis (interference)](https://codeshare.frida.re/@interference-security/ios-app-static-analysis/) | hard | ObjC/Swift static triage script [SCRIPT]
- [jnitrace (chame1eon)](https://codeshare.frida.re/@chame1eon/jnitrace/) | hard | JNI API trace [SCRIPT]
- [palera1n JB bypass (DevTraleski)](https://codeshare.frida.re/@DevTraleski/ios-jailbreak-detection-bypass-palera1n/) | hard | palera1n-wordlist bypass [SCRIPT]
- [iOS utils keychain/view (lichao)](https://codeshare.frida.re/@lichao890427/ios-utils/) | hard | keychain/view/click/OC-class utils [SCRIPT]
- [universal pins (akabe1)](https://codeshare.frida.re/@akabe1/frida-universal-pinning-bypasser/) | hard | universal cert bypass [SCRIPT]
- [debug-mode bypass (Raphkitue)](https://codeshare.frida.re/@Raphkitue/android-debug-mode-bypass/) | hard | USB-debug check bypass [SCRIPT]
- [tiktok unpin (Eltion)](https://codeshare.frida.re/@Eltion/tiktok-ssl-pinning-bypass/) | hard | per-app unpin [SCRIPT]
- [InMemoryDexClassLoader dump (cryptax)](https://codeshare.frida.re/@cryptax/inmemorydexclassloader-dump/) | hard | in-memory DEX byte dump [SCRIPT]
- [dynamichooks (realgam3)](https://codeshare.frida.re/@realgam3/dynamichooks/) | medium-hard | easy function-hook helper [SCRIPT]
- [whereisnative (dzonerzy)](https://codeshare.frida.re/@dzonerzy/whereisnative/) | hard | native-call + stacktrace finder [SCRIPT]
- [iOS WebInspector enable (leolashkevych)](https://codeshare.frida.re/@leolashkevych/ios-enable-webinspector/) | hard | WebView-debug enable (JB) [SCRIPT]
- [devmode-check bypass (zionspike)](https://codeshare.frida.re/@zionspike/bypass-developermode-check-android/) | hard | developer-mode gate bypass [SCRIPT]
- [flutter TLS+DIO (TheDauntless)](https://codeshare.frida.re/@TheDauntless/disable-flutter-tls-v1/) | hard | Flutter TLS verify kill [SCRIPT]
- [CCCrypt dump (xperylab)](https://codeshare.frida.re/@xperylab/cccrypt-dump/) | hard | CCCrypt arg/result dump [SCRIPT]
- [TCP trace (mame82)](https://codeshare.frida.re/@mame82/android-tcp-trace/) | hard | TCP + Java-trace log [SCRIPT]
- [NSURL iOS13 (DuffyAPP)](https://codeshare.frida.re/@DuffyAPP-IT/nsurl--ios13/) | hard | request body/method extract [SCRIPT]
- [deep-link observer (leolashkevych)](https://codeshare.frida.re/@leolashkevych/android-deep-link-observer/) | hard | deep-link URI dump [SCRIPT]
- [ios-app-info (dki)](https://codeshare.frida.re/@dki/ios-app-info/) | hard | iOS app info dump [SCRIPT]
- [native interceptor (hyugogirubato)](https://codeshare.frida.re/@hyugogirubato/android-native-interceptor/) | hard | customizable native monitor [SCRIPT]
- [iOS JB bypass (incogbyte)](https://codeshare.frida.re/@incogbyte/ios-jailbreak-bypass/) | hard | Sileo/paths + ptrace/sysctl/getppid [SCRIPT]
- [wifi-check bypass (zionspike)](https://codeshare.frida.re/@zionspike/bypass-wi-fi-check-on-android/) | hard | cellular-only gate bypass [SCRIPT]
- [instagram unpin (Eltion)](https://codeshare.frida.re/@Eltion/instagram-ssl-pinning-bypass/) | hard | 2nd-source IG unpin [SCRIPT]
- [arm64 strace (FrenchYeti)](https://codeshare.frida.re/@FrenchYeti/android-arm64-strace/) | hard | SVC syscall trace [SCRIPT]
- [EncryptedSharedPrefs check (Alkeraithe)](https://codeshare.frida.re/@Alkeraithe/encryptedsharedpreferences/) | hard | pre-encrypt value read [SCRIPT]

## Batch R2-O2 — CodeShare pages 4–5 (fetched)

- [query-provider (leolashkevych)](https://codeshare.frida.re/@leolashkevych/android-query-provider/) | hard | content-provider interact [SCRIPT]
- [frinja crypto suite (ninjadiary)](https://codeshare.frida.re/@ninjadiary/secret-diary-of-frinja/) | hard | crypto pentest suite [SCRIPT]
- [iOS keyboard check (ay-kay)](https://codeshare.frida.re/@ay-kay/ios-custom-keyboard-support/) | hard | 3rd-party keyboard detect [SCRIPT]
- [location spoof (dzervas)](https://codeshare.frida.re/@dzervas/android-location-spoofing/) | hard | GPS spoof [SCRIPT]
- [iOS URL-scheme fuzz (dki)](https://codeshare.frida.re/@dki/ios-url-scheme-fuzzing/) | hard | SpringBoard URL fuzz + scheme dump [SCRIPT]
- [OkHttp pinning (segura2010)](https://codeshare.frida.re/@segura2010/android-certificate-pinning-bypass/) | hard | OkHttpClient bypass [SCRIPT]
- [macOS+iOS pinning (BlueFalconHD)](https://codeshare.frida.re/@BlueFalconHD/bypass-pinning-macos-and-ios/) | hard | AFNetworking/TrustKit/BoringSSL sweep [SCRIPT]
- [iOS JB bypass (overnop)](https://codeshare.frida.re/@overnop/ios-jailbreak-bypass/) | hard | artifact path-check duel [SCRIPT]
- [iOS biometrics (chmodx)](https://codeshare.frida.re/@chmodx/ios-biometrics-bypass/) | hard | biometric gate bypass [SCRIPT]
- [iOS16 location (Rablidad)](https://codeshare.frida.re/@Rablidad/ios-16-location-spoofing/) | hard | CLLocation spoof 16.6 [SCRIPT]
- [crypto interceptor (hyugogirubato)](https://codeshare.frida.re/@hyugogirubato/android-crypto-interceptor/) | hard | algo/IO/keygen log [SCRIPT]
- [frinja-crypto-fixed (ensingerphilipp)](https://codeshare.frida.re/@ensingerphilipp/frinja-crypto-fixed/) | hard | crypto-identifier fixed [SCRIPT]
- [SSLKEYLOG universal (vadim-a-yegorov)](https://codeshare.frida.re/@vadim-a-yegorov/universalkeylogger/) | hard | Android/iOS/Linux keylog [SCRIPT]
- [classes-by-keywords (wrycaio)](https://codeshare.frida.re/@wrycaio/classes-by-keywords/) | hard | keyword class-dump [SCRIPT]
- [SSL bypass (Q0120S)](https://codeshare.frida.re/@Q0120S/bypass-ssl-pinning/) | hard | generic pin bypass [SCRIPT]
- [java-crypto-viewer (Serhatcck)](https://codeshare.frida.re/@Serhatcck/java-crypto-viewer/) | hard | Java crypto ops view [SCRIPT]
- [facebook unpin (Eltion)](https://codeshare.frida.re/@Eltion/facebook-ssl-pinning-bypass/) | hard | per-app unpin [SCRIPT]
- [RN emulator bypass (khantsithu1998)](https://codeshare.frida.re/@khantsithu1998/bypass-react-native-emulator-detection/) | hard | react-native-device-info dodge [SCRIPT]
- [sqlite hooks (ninjadiary)](https://codeshare.frida.re/@ninjadiary/sqlite-database/) | hard | SQLite general hooks [SCRIPT]
- [early native instrument (P0r0)](https://codeshare.frida.re/@P0r0/very-early-instrumentation-of-native-code/) | hard | .so ctor hook [SCRIPT]
- [native android fns (salecharohit)](https://codeshare.frida.re/@salecharohit/instrumenting-native-android-functions-using-frida/) | hard | notsosecure-method chain [SCRIPT]
- [launchd xpc (stek29)](https://codeshare.frida.re/@stek29/launchd-xpc-hack/) | hard | bootstrap look-up via launchd [SCRIPT]
- [dereflector (dzonerzy)](https://codeshare.frida.re/@dzonerzy/dereflector/) | hard | reflection-loaded class info [SCRIPT]
- [iOS10/11 SSL (dki)](https://codeshare.frida.re/@dki/ios10-ssl-bypass/) | hard | injected-app cert bypass [SCRIPT]
- [combined anti-root+flutter (fahad-source)](https://codeshare.frida.re/@fahad-source/frida-combined-bypass--anti-root--flutter-tls-pinning/) | hard | Magisk-indicator spoof + ssl_verify_peer_cert scan-patch [SCRIPT]
- [tiktok v44 unpin (hediluqman8)](https://codeshare.frida.re/@hediluqman8/tiktok-ssl-bypass/) | hard | Android-15 root path [SCRIPT]
- [flutter unpin (licitrasimone)](https://codeshare.frida.re/@licitrasimone/flutter-ssl-pinning-bypass/) | hard | native-verify patch + Java hooks [SCRIPT]
- [ultimate combo (jerry)](https://codeshare.frida.re/@jerry/ultimate-combined-bypass/) | medium-hard | combo bypass starter [SCRIPT]

## Batch R2-O3 — CodeShare page 6 (fetched)

- [prime-root Frida17 (beyrakIn)](https://codeshare.frida.re/@beyrakIn/prime-root/) | hard | modern root-bypass [SCRIPT]
- [iOS pin+AES+version (idiotic734)](https://codeshare.frida.re/@idiotic734/ios-ssl-pinning-and-aes-encryption-and-ios-versioning-check-bypass/) | hard | triple-condition iOS bypass [SCRIPT]
- [root+emu (cubetech126)](https://codeshare.frida.re/@cubetech126/root-and-emulator-detection-bypass/) | hard | dzonerzy-fork + emu [SCRIPT]
- [RN jail-monkey (RohindhR)](https://codeshare.frida.re/@RohindhR/react-native-jail-monkey-bypass-all-checks/) | hard | JailMonkey all-checks bypass [SCRIPT]
- [Darkprince JB (sridharas04)](https://codeshare.frida.re/@sridharas04/darkprince-jailbreak-detection-bypass/) | hard | multi-technique JB bypass [SCRIPT]
- [root bypass (Q0120S)](https://codeshare.frida.re/@Q0120S/root-detection-bypass/) | hard | root-gate bypass [SCRIPT]
- [VPN bypass (poseidontor)](https://codeshare.frida.re/@poseidontor/android-vpn-detection-bypass/) | hard | VPN-detect dodge [SCRIPT]
- [iOS cipher intercept (Humenger)](https://codeshare.frida.re/@Humenger/frida-ios-cipher/) | hard | iOS crypto-fn intercept [SCRIPT]
- [iOS proxy bypass (electrondefuser)](https://codeshare.frida.re/@electrondefuser/ios-proxy-detection-bypass/) | hard | CFNetwork proxy-settings dodge [SCRIPT]
- [tiktokssl (fdciabdul)](https://codeshare.frida.re/@fdciabdul/tiktokssl/) | hard | TikTok unpin [SCRIPT]
- [trace-java-calls (d3z3n0v3)](https://codeshare.frida.re/@d3z3n0v3/trace-function-calls/) | hard | package Java-call trace [SCRIPT]
- [iOS13 TLS keylog (LukeTheWalker)](https://codeshare.frida.re/@LukeTheWalker/ios13-tls-keylogger/) | hard | iOS TLS keylog [SCRIPT]
- [Android11 unpin (dkgitdev)](https://codeshare.frida.re/@dkgitdev/android-11-ssl-pinning-bypass/) | hard | fixed-fork unpin [SCRIPT]

## Batch R2-U — Practical CTF guides (sitemap-verified, book.jorianwoltjer.com)

- [Android backup guide](https://book.jorianwoltjer.com/mobile/android-backup.md) | medium-hard | adb-backup exfil flow [RESEARCH-guide]
- [Frida guide](https://book.jorianwoltjer.com/mobile/frida.md) | medium-hard | Frida mobile setup [RESEARCH-guide]
- [Compiling C for Android](https://book.jorianwoltjer.com/mobile/compiling-c-for-android.md) | hard | NDK helper-`.so` build path [RESEARCH-guide]
- [HTTP(S) proxy for Android](https://book.jorianwoltjer.com/mobile/http-s-proxy-for-android.md) | medium-hard | proxy intercept setup [RESEARCH-guide]

## Batch R2-W — closing additions (fetched)

- [8kSec malware P3 Pegasus](https://8ksec.io/mobile-malware-analysis-part-3-pegasus/) | hard | Pegasus iOS-spyware teardown [RESEARCH]
- [8kSec malware P8 deVixor](https://8ksec.io/mobile-malware-analysis-part-8-devixor/) | hard | deVixor teardown [RESEARCH]

## Batch R2-P — MASTG demo labs, hard-relevant subset (listing fetched)

> Full demo URLs verified from fetched `mas.owasp.org/MASTG/demos/` listing.
> Base: `https://mas.owasp.org/MASTG/demos/`.

- [DEMO-0106 Cipher.doFinal Frida](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0106/MASTG-DEMO-0106/) | hard | crypto-boundary exfil drill [PRACTICE-lab]
- [DEMO-0108 maps Frida bypass](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0108/MASTG-DEMO-0108/) | hard | /proc/self/maps scrub drill [PRACTICE-lab]
- [DEMO-0116 TracerPid/ptrace](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0116/MASTG-DEMO-0116/) | hard | native anti-debug drill [PRACTICE-lab]
- [DEMO-0117 CCCrypt Frida](https://mas.owasp.org/MASTG/demos/ios/MASVS-RESILIENCE/MASTG-DEMO-0117/MASTG-DEMO-0117/) | hard | iOS crypto-boundary drill [PRACTICE-lab]
- [DEMO-0119 D-Bus port bypass](https://mas.owasp.org/MASTG/demos/ios/MASVS-RESILIENCE/MASTG-DEMO-0119/MASTG-DEMO-0119/) | hard | iOS port-hide drill [PRACTICE-lab]
- [DEMO-0102 provider SQLi](https://mas.owasp.org/MASTG/demos/android/MASVS-CODE/MASTG-DEMO-0102/MASTG-DEMO-0102/) | hard | content-provider URI/sql drill [PRACTICE-lab]
- [DEMO-0139 provider path traversal](https://mas.owasp.org/MASTG/demos/android/MASVS-CODE/MASTG-DEMO-0139/MASTG-DEMO-0139/) | hard | filename traversal drill [PRACTICE-lab]
- [DEMO-0121 provider DB records](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0121/MASTG-DEMO-0121/) | hard | exported-provider row-read drill [PRACTICE-lab]
- [DEMO-0123 FileProvider exfil](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0123/MASTG-DEMO-0123/) | hard | URI-grant overshare drill [PRACTICE-lab]
- [DEMO-0128 unprotected activity](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0128/MASTG-DEMO-0128/) | hard | exported-activity drill [PRACTICE-lab]
- [DEMO-0129 unprotected service](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0129/MASTG-DEMO-0129/) | hard | exported-service drill [PRACTICE-lab]
- [DEMO-0130 unprotected receiver](https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0130/MASTG-DEMO-0130/) | hard | manifest-receiver drill [PRACTICE-lab]
- [DEMO-0107 Frida-detect kill](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0107/MASTG-DEMO-0107/) | medium-hard | detect-then-exit drill [PRACTICE-lab]
- [DEMO-0114 emulator checks](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0114/MASTG-DEMO-0114/) | medium-hard | emulator-gate drill [PRACTICE-lab]
- [DEMO-0115 JDWP checks](https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0115/MASTG-DEMO-0115/) | medium-hard | JDWP-gate drill [PRACTICE-lab]
- [DEMO-0118 pre-crypto Frida detect](https://mas.owasp.org/MASTG/demos/ios/MASVS-RESILIENCE/MASTG-DEMO-0118/MASTG-DEMO-0118/) | medium-hard | iOS hook-timing drill [PRACTICE-lab]
- [DEMO-0131 virtual-device iOS](https://mas.owasp.org/MASTG/demos/ios/MASVS-RESILIENCE/MASTG-DEMO-0131/MASTG-DEMO-0131/) | medium-hard | iOS vdev drill [PRACTICE-lab]
- [DEMO-0134 URL-scheme no-validate](https://mas.owasp.org/MASTG/demos/ios/MASVS-PLATFORM/MASTG-DEMO-0134/MASTG-DEMO-0134/) | medium-hard | scheme-input drill [PRACTICE-lab]

## Batch R2-Q — 8kSec research series (category pages fetched, 8ksec.io)

> Hard vendor research with direct CTF applicability. Base `https://8ksec.io`.

- [AdvFrida P1 iOS crypto libs](https://8ksec.io/advanced-frida-usage-part-1-ios-encryption-libraries-8ksec-blogs/) | hard | iOS encryption-library hook patterns [RESEARCH]
- [AdvFrida P2 Signal/Telegram iOS](https://8ksec.io/advanced-frida-usage-part-2-analyzing-signal-and-telegram-messages-on-ios/) | hard | message-intercept hook patterns [RESEARCH]
- [AdvFrida P3 iOS XPC inspect](https://8ksec.io/advanced-frida-usage-part-3-inspecting-ios-xpc-calls/) | hard | XPC-call inspection [RESEARCH]
- [AdvFrida P4 locationd sniff](https://8ksec.io/advanced-frida-usage-part-4-sniffing-location-data-from-locationd-in-ios/) | hard | daemon location-data sniff [RESEARCH]
- [AdvFrida P5 root bypass](https://8ksec.io/advanced-root-detection-bypass-techniques/) | hard | advanced root-detect/bypass ladder [RESEARCH]
- [AdvFrida P6 writers](https://8ksec.io/advanced-frida-usage-part-6-utilising-writers/) | hard | Frida writer primitives [RESEARCH]
- [AdvFrida P7 memops](https://8ksec.io/advanced-frida-usage-part-7-frida-memory-operations/) | hard | memory-operation patterns [RESEARCH]
- [AdvFrida P8 memops II](https://8ksec.io/frida-advanced-usage-part-8-frida-memory-operations-continued/) | hard | memory-operation patterns II [RESEARCH]
- [AdvFrida P9 memscan](https://8ksec.io/advanced-frida-usage-part-9-memory-scanning-in-android/) | hard | Android memory-scanning [RESEARCH]
- [AdvFrida P10 Stalker](https://8ksec.io/advanced-frida-usage-part-10-instruction-tracing-using-frida-stalker/) | hard | Stalker instruction-trace [RESEARCH]
- [Android deeplink+WebView](https://8ksec.io/android-deeplink-and-webview-exploitation-8ksec-blogs/) | hard | deep-link + WebView exploit chain [RESEARCH]
- [SELinux internals I](https://8ksec.io/android-selinux-internals-part-i-8ksec-blogs/) | hard | SELinux domains/policy base [RESEARCH]
- [SELinux internals II](https://8ksec.io/android-selinux-internals-part-ii/) | hard | denials + root-tool bypass [RESEARCH]
- [SELinux internals III](https://8ksec.io/android-selinux-internals-part-iii/) | hard | kernel-level bypass + exploit chains [RESEARCH]
- [SELinux internals IV](https://8ksec.io/android-selinux-internals-part-iv/) | hard | policy analysis + Android-16 mitigations [RESEARCH]
- [Securing Flutter 2024](https://8ksec.io/securing-flutter-applications/) | hard | OWASP-Mobile-Top-10 Flutter map [RESEARCH]
- [Hacking Android games](https://8ksec.io/hacking-android-games/) | hard | game-state/score tamper patterns [RESEARCH]
- [Mali CVE-2023-26083](https://8ksec.io/cve-2023-26083-kernel-pointer-leakage-in-mali-gpus-timeline-stream-message-buffers/) | hard | GPU kernel-pointer leak [RESEARCH]
- [Remove SSL pinning 2025](https://8ksec.io/why-you-should-remove-ssl-pinning-from-your-mobile-apps-in-2025/) | hard | pinning-considered-harmful analysis [RESEARCH]
- [Activity lifecycle blueprint](https://8ksec.io/a-blueprint-of-android-activity-lifecycle/) | hard | lifecycle-gate reasoning map [RESEARCH]
- [Rooting emulator](https://8ksec.io/rooting-an-android-emulator-for-mobile-security-testing/) | hard | emulator-root lab setup [RESEARCH-guide]
- [iOS deeplink P1](https://8ksec.io/ios-deeplink-attacks-part-1-introduction-8ksec-blogs/) | hard | iOS deep-link attack intro [RESEARCH]
- [iOS deeplink P2](https://8ksec.io/ios-deep-link-attacks-part-2-exploitation-8ksec-blogs/) | hard | iOS deep-link exploitation [RESEARCH]
- [ipsw walkthrough P1](https://8ksec.io/ipsw-walkthrough-part-1-the-swiss-army-knife-for-ios-macos-security-research/) | hard | ipsw/Dyldcache triage I [RESEARCH]
- [ipsw walkthrough P2](https://8ksec.io/ipsw-walkthrough-part-2-the-swiss-army-knife-for-ios-macos-security-research/) | hard | ipsw/Dyldcache triage II [RESEARCH]
- [iOS kernel panic logs](https://8ksec.io/analyzing-kernel-panic-ios/) | hard | panic-log forensics [RESEARCH]
- [iOS sandbox profiles](https://8ksec.io/reading-ios-sandbox-profiles/) | hard | sandbox-profile RE [RESEARCH]
- [Compiling Dopamine](https://8ksec.io/compiling-dopamine-jailbreak/) | hard | jailbreak build chain [RESEARCH]
- [Patch-diffing CVE-2024-23265](https://8ksec.io/patch-diffing-ios-kernel/) | hard | iOS kernel patch-diff [RESEARCH]
- [MIE deep dive P1](https://8ksec.io/mie-deep-dive-kernel/) | hard | memory-integrity-enforcement kernel [RESEARCH]
- [MIE deep dive P2](https://8ksec.io/mie-deep-dive-enabling-apps/) | hard | MIE app-enable + crash analysis [RESEARCH]
- [DarkSword browser chain](https://8ksec.io/how-browser-exploits-work-darksword-ios-cve-2025-43529/) | hard | iOS browser-exploit case [RESEARCH]
- [DarkSword kernel escalation](https://8ksec.io/darksword-kernel-escalation-cve-2025-43510-43520/) | hard | GPU→kernel R/W chain [RESEARCH]

## Batch R2-R — CTF mobile infra (fetched)

- [TCP1P Mobile-POC-Tester](https://github.com/TCP1P/Mobile-POC-Tester) | medium-hard | Finals-style PoC device-farm harness (W28-adjacent) [PRACTICE-infra]
- [TCP1P CTF-Mobile-Exploitation setup](https://github.com/TCP1P/CTF-Mobile-Exploitation) | medium-hard | 2023 mobile-exploitation env setup [PRACTICE-infra]

## Batch R2-S — team-blog extras + methodology guides (fetched)

- [PyDroid O-MVLL/dProtect Ch.01](https://teamrocketist.github.io/2023/07/22/Reverse-PyDroid/) | hard | OLLVM/dProtect-shielded Python-on-Android RE (Chaquopy-adjacent)
- [Xanhacks Android all-in-one](https://xanhacks.gitlab.io/ctf-docs/android/01-android/) | medium-hard | android triage methodology [PRACTICE-guide]
- [Xanhacks adb cheatsheet](https://xanhacks.gitlab.io/ctf-docs/android/02-adb/) | medium-hard | device-bridge crib [PRACTICE-guide]
- [Xanhacks root-AVD guide](https://xanhacks.gitlab.io/ctf-docs/android/04-root-avd-device/) | medium-hard | emulator-root lab setup [PRACTICE-guide]
- [CTF-Vault Android reversing](https://github.com/KiwKNR/CTF-Vault/blob/main/09-Mobile/Android-Reversing.md) | medium-hard | APK RE methodology [PRACTICE-guide]
- [CTF-Vault mobile intro](https://github.com/KiwKNR/CTF-Vault/blob/main/09-Mobile/Mobile-Intro.md) | medium | mobile triage intro [PRACTICE-guide]
- [CTF-Vault iOS hooking](https://github.com/KiwKNR/CTF-Vault/blob/main/09-Mobile/iOS-Hooking.md) | medium-hard | iOS hook methodology [PRACTICE-guide]

## Batch R2-T — seall.dev 2024–2025 + evyatar9 mobile dirs (index/page fetched)

- [CySea 2025 root-detection binaries](https://seall.dev/writeups/25-cysea-root-detection-is-the-least-of-our-problems-but-lets-have-it-anyway/) | hard | root-binary checklist duel (mobile RE)
- [DUCTF 2025 godot](https://seall.dev/writeups/25-ductf-godot/) | hard | Godot-engine game RE (engine-pattern support)
- [KashiCTF 2025 Game 1 Godot](https://seall.dev/writeups/25-kashi-game1untitledgame/) | hard | gdsdecomp → player.gd script read
- [KashiCTF 2025 Game 3 Unity+AssetRipper](https://seall.dev/writeups/25-kashi-game3catseabank/) | hard | Unity asset rip → wav-spectrogram read
- [KnightCTF 2025 Knight's Droid (3rd source)](https://seall.dev/writeups/25-knight-knightsdroid/) | hard | droid-gate chain (3rd source)
- [BackdoorCTF 2023 Sl4ydroid (canonical)](https://seall.dev/writeups/23-backdoor-sl4ydroid/) | hard | droid RE gate (canonical URL; supersedes posts-path slug)
- [NahamCon 2022 Click Me (evyatar9)](https://github.com/evyatar9/Writeups/tree/master/CTFs/2022-NahamCon_CTF/Mobile/Click_Me) | medium-hard | tap-counter gate (2nd source)
- [NahamCon 2022 Mobilize (evyatar9)](https://github.com/evyatar9/Writeups/tree/master/CTFs/2022-NahamCon_CTF/Mobile/Mobilize) | hard | deploy-state solve (2nd source)
- [NahamCon 2022 OTP Vault (evyatar9)](https://github.com/evyatar9/Writeups/tree/master/CTFs/2022-NahamCon_CTF/Mobile/OTP_Vault) | hard | OTP-vault RE (2nd source)

## Batch R2-X — official playground sources + SekaiID Android (fetched)

- [Playground-365 Endgame (official)](https://github.com/TCP1P/TCP1P-Playground-365-2025/tree/main/Mobile/Endgame) | hard | endgame practice source
- [Playground-365 Intro To Apk (official)](https://github.com/TCP1P/TCP1P-Playground-365-2025/tree/main/Mobile/Intro%20To%20Apk) | medium-hard | intro-APK practice source
- [Playground-365 intro_to_intent (official)](https://github.com/TCP1P/TCP1P-Playground-365-2025/tree/main/Mobile/intro_to_intent) | hard | intent-lab practice source
- [SekaiCTF 2026 SekaiID Android (debuggable run-as)](https://github.com/Abdelkad3r/cybersecurityelite.com/blob/main/content/ctf-writeups/sekai-ctf-2026-writeup.md) | hard | two-APK badge/verifier: intended IPC-forgery chain short-circuited by debuggable run-as
- [SekaiID per-challenge source](https://github.com/Abdelkad3r/SekaiCTF-2026/tree/main/misc/sekaiid) | hard | official handout+solver for SekaiID pair
- [SekaiCTF 2026 ppp libimobiledevice (iOS-adjacent)](https://github.com/Abdelkad3r/SekaiCTF-2026/tree/main/pwn/ppp) | hard | AFC heap-overflow → tcache GOT overwrite (Apple-ecosystem pwn)

## Batch R2-V — TCP1P official mobile sources + 8kSec malware teardowns (fetched)

- [TCP1P 2024 Interfaces (official)](https://github.com/TCP1P/TCP1P-CTF-2024-Challenges-Public/tree/main/Mobile/Interfaces) | hard | interface-gate official source
- [TCP1P 2024 LookDown (official)](https://github.com/TCP1P/TCP1P-CTF-2024-Challenges-Public/tree/main/Mobile/LookDown) | hard | lookdown chain official source (cf. R1 W28 guide)
- [TCP1P 2024 LookUp (official)](https://github.com/TCP1P/TCP1P-CTF-2024-Challenges-Public/tree/main/Mobile/LookUp) | hard | lookup chain official source
- [TCP1P 2024 Password Manager 2.0 (official)](https://github.com/TCP1P/TCP1P-CTF-2024-Challenges-Public/tree/main/Mobile/Password%20Manager%202.0) | hard | password-manager vault official source
- [INTECHFEST 2024 Endgame (official)](https://github.com/TCP1P/INTECHFEST-CTF-2024-Challenges-Public/tree/main/Mobile/Endgame) | hard | endgame official mobile source
- [INTECHFEST 2024 Hidden (official)](https://github.com/TCP1P/INTECHFEST-CTF-2024-Challenges-Public/tree/main/Mobile/Hidden) | hard | hidden-entry official source
- [INTECHFEST 2024 Hijacker (official)](https://github.com/TCP1P/INTECHFEST-CTF-2024-Challenges-Public/tree/main/Mobile/Hijacker) | hard | overlay-hijack official source (cf. SekaiCTF Hijacker pair)
- [INTECHFEST 2024 Password Manager (official)](https://github.com/TCP1P/INTECHFEST-CTF-2024-Challenges-Public/tree/main/Mobile/Password%20Manager) | hard | vault official source
- [8kSec malware P1 a11y stealer](https://8ksec.io/mobile-malware-analysis-part-1-crypto-wallet-stealer/) | hard | accessibility-service theft teardown [RESEARCH]
- [8kSec malware P2 MasterFred](https://8ksec.io/mobile-malware-analysis-part-2-masterfred/) | hard | MasterFred teardown [RESEARCH]
- [8kSec malware P4 iOS detection](https://8ksec.io/mobile-malware-analysis-part-4-intro-to-ios-malware-detection/) | hard | iOS-malware-detection intro [RESEARCH]
- [8kSec malware P6 Xenomorph](https://8ksec.io/mobile-malware-analysis-part-6-xenomorph/) | hard | Xenomorph ATS-bypass teardown [RESEARCH]
- [8kSec malware P7 Blackrock](https://8ksec.io/mobile-malware-analysis-part-7-blackrock/) | hard | Blackrock teardown [RESEARCH]
