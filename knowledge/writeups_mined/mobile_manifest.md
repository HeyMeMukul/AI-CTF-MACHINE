# Mobile CTF Writeups Mined — Manifest (technique-only, no flags/keys)

> Method: WebSearch + selective WebFetch, 2022–2026 focus: JNI/native,
> DEX packers + dumping, anti-Frida ladders, native pinning, Flutter/Hermes,
> deep-link/intent chains, Keystore flows, iOS jailbreak bypass, attestation gates.
> Every URL below was returned by web search/fetch or transcribed from a fetched
> index page (Batch R = pentest-bi0s/Mobile-CTFs folder listing, Batch L =
> lautarovculic writeups index; both listings fetched, URL pattern spot-verified
> resolving). `[RESEARCH]` = Android/iOS security research with direct CTF
> applicability. Trivial "decompile and read the hardcoded flag" solves excluded.
> Technique-only: no flag/key values recorded.

## Batch A — JNI / native reversing (fetched + extracted)

- [TFCCTF 2025 Android Reverse (TicketReceiver)](https://www.ccsl.carleton.ca/~mhossein/posts/tfcctf-2025-0.html) | hard | broadcast-receiver seed → RegisterNatives JNI → Ghidra memcmp gate + Frida hot-patch of native global + NOP branch
- [PwnSec 2025 FreakyFrida](https://www.ztz0.com/writeups/2025/pwnsec/mobile/freakyfrida/) | hard | dual-.so anti-Frida → smali-injected loader .so + PLT-hook on strcmp to exfiltrate comparison args
- [CyCTF GTM (AES decoy → JNI broadcast)](https://medium.com/@ahmed-alnajjar/cyctf-gtm-challenge-from-aes-decoy-to-jni-broadcast-2a5bd3c7a328) | hard | AES-ECB decoy decrypt → JNI sendFlag broadcast → onClick bypass + sendBroadcast intercept
- [BrunnerCTF 2025 Brod & Co (Flutter + native)](https://ymuu.me/posts/brod--co--android-ctf-write-up---brunnerctf-2025/) | hard | libapp shell + libnative coupon/flag builder → direct NativeFunction call on magic-constant helper
- [SparkCTF Task 2 (flag_dump memmove)](https://el-gastra.tech/posts/spark-ctf/) | medium-hard | native lib memmove of secret blob → fridump process-memory carve + strings
- [SparkCTF Task 3 (libtest triple-XOR)](https://el-gastra.tech/posts/spark-ctf/) | hard | JNI string check with staged XOR ladder → static reimplementation offline
- [京麒CTF 2025 rev (JNI asset loader)](https://lrhtony.cn/2025/05/25/2025jqctf/) | hard | statically-registered JNI over assets files → IDA dynamic run → 4× broadcast-attack RSA recovery
- [L3akCTF 2025 Androbro (static path)](https://zeph.work/blog/posts/l3akctf-2025) | hard | JNI_OnLoad → SHA256(pkg)+RC4 → XOR-decrypt hidden DEX asset → AES-CBC offline reimpl
- [L3akCTF 2025 Androbro (intended dynamic)](https://pwnthem0le.polito.it/2025/07/12/L3akCTF-2025-Androbro-writeup/) | hard | broadcast trigger intents + strcmp-hook arg logging to recover XOR key at runtime
- [网鼎杯 rev01 (dynamic-register + flattening)](https://www.cnblogs.com/helica/p/13174980.html) | hard | frida_hook_libart RegisterNatives reveal → IDA android_server debug of flattened checkFlag (base58 + RC4)
- [HackingCamp RunningGo (native getFlag)](https://thirtyseven.tistory.com/68) | hard | Frida hook vs smali patch vs native decrypt_flag reimplementation (subtract-1 + alternating-key XOR)
- [HTB Ancored (frf/prp/mrm JNI)](https://x3ric.com/blog/posts/HackTheBox-Ancored-Challenge/) | medium-hard | JNI XOR param builders traced in Ghidra → Python reimpl of request-secret derivation
- [HTB SAW (overlay + native file-drop)](https://callmeks.github.io/posts/htb-saw/) | hard | overlay-gated XOR alert() → native drops DEX file → Frida open/read direct file read + own-package native reuse
- [0xL4ugh MyVault (OTP-derived AES)](https://nolliv22.com/writeups/0xl4ugh%20ctf%202024/myvault) | medium | input+reverse key schedule → 10k PIN bruteforce reusing app Cipher code
- [UMassCTF Free Delivery (dual-XOR)](https://ctftime.org/writeup/39128) | medium | base64+XOR keystream in Java + libfreedelivery XOR-constant blob in native → two-part join
- [MetaCTF Gretel (native key/IV)](https://metactf.com/blog/flash-ctf-magdalena/) | medium | native getKey/getIV return-value logging via Frida → AES-CBC offline decrypt
- [NahamCon Ebank part 4 (native XOR)](https://kore.one/nahamcon-winter-2025-ctf-ebank-challenge-writeup/) | hard | 5-part flag: hex-reversed + pkgname-sum XOR + base64 + native .rodata XOR + bitwise NOT
- [CyCTF 2024 Armor (patched Utils dex)](https://justahmed.github.io/ctf/Android-CyCTF-2024-Finals/) | hard | anti-static infinite-loop ctor patched out of dex → key assembly → AES-CBC decrypt
- [Tencent ACE 2024 UE4 (libUE4)](http://www.yxfzedu.com/article/10506) | hard | frida-gadget repack inject → UE4 SDK dump → Unicorn-assisted deobfuscation of password check
- [Tencent 2023初赛 (IL2CPP VM)](https://sgsgsama.github.io/ctf/Android/%E8%85%BE%E8%AE%AF%E6%B8%B8%E6%88%8F%E5%AE%89%E5%85%A82023%E5%AE%89%E5%8D%93%E5%88%9D%E8%B5%9B/) | hard | non-default-port Frida dump of libil2cpp → ELF section repair → VM/MBA handler tracing

## Batch B — DEX packers, anti-Frida, protectors (fetched + extracted)

- [Frida detection & bypass taxonomy](https://qweraqq.github.io/security/2024/04/06/android-frida-detection-and-bypass.html) | hard | port/ptrace/maps/status/task/fd/injection checks → custom-port + spawn + string-strip + kernel-hide ladder [RESEARCH]
- [UnCrackable 3 strstr bypass](https://medium.com/h7w/owasp-uncrackable-3-android-application-bd25b3646acb) | hard | libfoo init-time maps scan for needles → strstr return-NULL hook + root triple-hook
- [UnCrackable 3 Ghidra variant](https://hngnh.com/posts/OWASP-Android-Uncrackable-Level-3/) | hard | pthread watcher → delayed hook on non-exported offset after loadLibrary
- [Patching native detectors (radare2)](https://www.kayssel.com/post/android-10/) | medium-hard | jmp-to-ret patch of detectFridaAndExit → rebuild + resign + reattach
- [Anti-Frida .so patching (Ghidra)](https://blog.spentera.id/bypassing-anti-frida-on-android/) | hard | frida-thread/memdisk/port check hunt → return-0 patch + on-device .so replace
- [APK unpacking guide (commercial packers)](https://tyrusrc.github.io/learnfromscratch/learn/topics/mobile/apk-unpacking/) | medium-hard | Bangcle/Ijiami/Jiagu/Legu telltales → InMemoryDexClassLoader dump flow [RESEARCH]
- [frida_fart (ClassLoader-aware dump)](https://github.com/CYRUS-STUDIO/frida_fart) | hard | enumerateClassLoaders + DexClassLoader-ctor fart triggers for non-delegated dex [RESEARCH]
- [FART active-invocation unpacker](https://github.com/hanbinglengyue/FART) | hard | ART active-call dump pipeline (Execute-point + bin/codeitem splice) [RESEARCH]
- [Purifire packer study (measurement)](https://arxiv.org/html/2509.16340v1) | hard | unpacker-vs-packer effectiveness + eBPF/x-ref DER patch model [RESEARCH]
- [DragonJAR packing-unpacking ref](https://github.com/DragonJAR/Android-Pentesting-Skill/blob/main/references/packing-unpacking.md) | medium-hard | per-packer .so signatures + frida-dexdump + SecClassLoader hooks [RESEARCH]
- [apk-reverse advanced-unpacking](https://git.nite07.com/nite/apk-reverse/src/commit/ce2e4f98e1f68e3db26fc2f1df01d5920fb9d968/skills/apk-reverse/references/advanced-unpacking.md) | hard | skeleton-vs-extraction-shell + no-Frida /proc-mem dump + validate gate [RESEARCH]
- [frida-unpack (OpenMemory)](https://github.com/dstmath/frida-unpack) | medium | libart OpenMemory/OpenCommon base+size dump scripts [RESEARCH]
- [android-unpacking skill (frida-dexdump)](https://skills.rest/skill/android-unpacking) | medium | Legu/Bangcle/360 whole-release dump runbook + multi-dex handling [RESEARCH]
- [frida_dex_dump (OpenCommon)](https://github.com/CYRUS-STUDIO/frida_dex_dump) | hard | libdexfile.so DexFileLoader::OpenCommon hook → base/size carve [RESEARCH]
- [DexGuard protector profile](https://www.awakewiki.org/packers/dexguard/) | hard | polymorphic string/class encryption + native pinning + frida-dexdump recovery notes [RESEARCH]
- [awesomeFrida RegisterNatives](https://github.com/bigsinger/awesomeFrida/blob/main/FridaForAndroid/part9/sections/9.2.md) | hard | libart RegisterNatives enumerate + auto-hook + signature-parse codegen [RESEARCH]

## Batch C — pinning bypasses + objection (fetched + extracted)

- [HTB Pinned (objection)](https://gaberoy.zip/posts/pinned/pinned/) | medium | objection android sslpinning disable + TrustManager-override confirm + proxy login capture
- [HTB Pinned (DER-swap rebuild)](https://medium.com/@brian.nuwagaba.ludovic/unpinning-pinned-hack-the-box-android-challenge-22cd6a945948) | medium | res/raw cert replace + rebuild/resign vs universal-Frida-unpin dual path
- [BreizhCTF OwnApp v1+v2 (JNI + Flutter pinning)](https://darkpills.com/breizhctf-2024-mobile-ownapp-and-web-popup-creator-write-ups/) | hard | JNI strings URL → reflutter failover → memory-carved URL + client-gated replay
- [Flutter pinning guide (BoringSSL offset)](https://blog.mindedsecurity.com/2024/05/bypassing-certificate-pinning-on.html) | hard | ssl_client/ssl_server xref → offset from JNI_OnLoad → retval-true hook
- [librust.so pinning (rustls)](https://medium.com/@0x1r1s/bypassing-librust-so-ssl-pinning-6fcd96362fcc) | hard | verify_server_cert locate via non-stripped local build → Frida patch
- [SekaiCTF Crackme (RN + pinning intercept)](https://fexsec.net/variousctfs/crackme-sekaictf2024/) | medium-hard | RN bundle AES creds → Firebase authed flag path + pinning-bypass traffic capture
- [CSIT mini (pinning APK, offline solve)](https://github.com/teozt/csit_2024_cny_mini_challenge) | medium | pinning-themed APK solved statically: base64 + AES-ECB reimpl, no install
- [Objection pinning walkthrough](https://pentestguy.com/ssl-pinning-bypass-using-frida-and-objection/) | medium | AndroGoat sslpinning/root disable + multiple-unpinning codeshare path [RESEARCH]
- [MASTG objection tool page](https://mas.owasp.org/MASTG/tools/android/MASTG-TOOL-0029/) | medium | patchapk gadget + startup-command early instrumentation model [RESEARCH]
- [HackTricks objection tutorial](https://hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/frida-tutorial/objection-tutorial.html) | medium | gadget-vs-server flows + heap/crypto limitations [RESEARCH]
- [MASTG pinning TECH-0012](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0012/) | medium | multiple-unpinning vs objection coverage + custom-framework fallback [RESEARCH]
- [objection repo](https://github.com/sensepost/objection) | medium | REPL model + explore/patchapk/sslpinning module surface [RESEARCH]
- [Objection AndroGoat + Twitter](https://wiki.elvis.science/index.php?title=Objection%3A_Root_Detection_%26_Certificate_Pinning_Bypass) | medium | root-disable + sslpinning-disable verify loop [RESEARCH]
- [Root + pinning survey](https://securitycafe.ro/2022/02/01/root-detection-and-ssl-pinning-bypass/) | medium | Frida vs objection vs Kill-Switch matrix + codeshare index [RESEARCH]
- [RootBeer + objection REPL](https://itsecurenep.hashnode.dev/frida-objection-setup) | medium | class_methods watch + set return_value false + sslpinning disable [RESEARCH]
- [Stinger pinning runbook](https://stinger.io/mobile/android/Bypasses/Android-Bypass-Certificate-Pinning/) | medium | Burp-detect-then-objection flow [RESEARCH]
- [Root+pinning+fingerprint chain](https://infosecwriteups.com/android-pentesting-101-part-3-2bf846b05594) | medium | chained single-script bypass + Burp capture [RESEARCH]
- [NVISO Flutter ARMv7 pattern-scan](https://blog.nviso.eu/2019/08/13/intercepting-traffic-from-android-flutter-applications/) | hard | session_verify_cert_chain first-bytes scan + THUMB +1 hook + iptables routing
- [NVISO Flutter ARMv8 offset](https://blog.nviso.eu/2020/05/20/intercepting-flutter-traffic-on-android-x64/) | hard | scalar search for error-line constant + binwalk/radare2 pattern resolve + base+offset hook
- [SensePost Flutter hardcore Frida](https://sensepost.com/blog/2025/intercepting-https-communication-in-flutter-going-full-hardcore-mode-with-frida/) | hard | reFlutter source-patch analysis → Frida Memory.scan reimplementation of verifier hook

## Batch D — Flutter / Hermes / React-Native (fetched + extracted)

- [Insomni'hack Herald (hbcdump patch)](https://ctftime.org/writeup/32238) | hard | Hermes v84 hbcdump disasm → JStrictEqual→NotEqual byte-patch + apktool repack/resign
- [Herald (hbctool v84 port)](https://github.com/Pusty/writeups/tree/master/InsomnihackTeaser2022) | hard | hbctool version port + NewArrayWithBuffer arrayBuffer carve for password/flag buffers
- [Herald (hasm login bypass)](https://sahua.ng/posts/insomnihack-teaser-2022/) | medium-hard | hasm disasm → tryAuth compare flip → recompile + admin login
- [so-AIRMES (hermes-decomp xref)](https://labs.symbioticsec.ai/hubfs/PDF%20Downloads/CTF%20Writeup%20so-AIRMES.pdf) | hard | strings→xref→Metro module → AirmesCrypto JNI bridge → xorshift keystream known-prefix solve
- [React-Native-CTF lab pair](https://github.com/banditVedant/React-Native-CTF/blob/main/README.md) | medium | plain-RN vs Hermes-enabled APK pair for bundle-tool training [RESEARCH-index]
- [AnkiPro Hermes patch (v90 fork)](https://vlourme.medium.com/reverse-engineering-react-native-and-hermes-byte-code-bb5b96db368f) | hard | hbctool fork → LoadFromEnvironment→LoadConstUInt8 patch + closure replace for premium flag
- [Hermes RE Q&A (tool ladder)](https://reverseengineering.stackexchange.com/questions/26463/how-can-i-modify-or-decompile-hermes-js-bytecode) | medium | hbcdump vs hbctool vs hermes-decomp version coverage [RESEARCH]
- [hbctool repo](https://github.com/bongtrop/hbctool/) | medium | Hermes disasm/asm round-trip model for patch-repack loops [RESEARCH]
- [Flutter labs chall0-2 (debug vs release)](https://github.com/brnpl/Flutter-Reverse-Engineering-Labs) | medium | kernel_blob debug leak vs release libapp strings triage cluster
- [Flutter labs chall3-5 (Frida + channel)](https://github.com/brnpl/Flutter-Reverse-Engineering-Labs) | medium-hard | return-value/parameter hooks + Java platform-channel seam hooks
- [Flutter labs chall6-8 (intercept + integrity)](https://github.com/brnpl/Flutter-Reverse-Engineering-Labs) | hard | reFlutter traffic mode + integrity-check bypass + BoringSSL pinning bypass
- [1337UP CyberSharing (blutter → patch)](https://kos0ng.gitbook.io/ctfs/write-up/2024/1337up-live-ctf/mobile) | hard | blutter + IDA name recovery → magic-compare hunt → B.NE→B.EQ patch + deep-link trigger
- [Where's my APK (AAB → blutter)](https://0xm4hm0ud.me/posts/wheres-my-apk-1337up-live-2024-ctf) | medium-hard | bundletool AAB→APK → blutter files.dart magic hunt → HTTPToolkit response rewrite
- [Where's my APK (2nd source)](https://learn-cyber.net/writeup/Where's-my-APK) | medium-hard | same AAB/blutter/response-rewrite chain confirm
- [NahamCon Fly Away 1 (reFlutter intercept)](https://maulvialf.medium.com/nahamcon-ctf-2024-writeup-mobile-category-713b19da447e) | medium | reFlutter traffic patch + lyrics-endpoint flag read
- [NahamCon Fly Away 2 (Dart snapshot hook)](https://maulvialf.medium.com/nahamcon-ctf-2024-writeup-mobile-category-713b19da447e) | hard | dump.dart offsets + Frida Dart-snapshot hook on decryptIntegrityCheck
- [Fly Away (offset-math confirm)](https://hackmd.io/@avila-pwn-notes/r183kzlEA) | hard | reflutter frida.js isolate-base + code-offset arithmetic confirm
- [Buggy Jumper 1 (Godot recover)](https://blog.ikuamike.io/posts/2024/nahamcon_ctf_2024_mobile/) | medium | Godot flag.gdc → gdsdecomp full-project recover
- [Buggy Jumper 2 (score → verify)](https://blog.ikuamike.io/posts/2024/nahamcon_ctf_2024_mobile/) | medium-hard | global.gd register→save→verify + engine UA + saved_value.dat score write
- [Buggy Jumper (strings confirm)](https://lautarovculic.github.io/writeups/NahamCon%202024%20-%20Buggy%20Jumper/) | medium | gdsdecomp + strings read confirm
- [Buggy Jumper (shop flow confirm)](https://hackmd.io/@avila-pwn-notes/r183kzlEA) | medium-hard | shop.gd/global.gd points-flow confirm
- [Kitty Kitty Bang Bang (direct JNI call)](https://maulvialf.medium.com/nahamcon-ctf-2024-writeup-mobile-category-713b19da447e) | medium-hard | dependency-free stringFromJNI → Frida direct invocation, no input needed
- [THCon Escape the battlefield (encrypted PCK)](https://ctftime.org/writeup/39048) | hard | Godot encrypted PCK → debugger script_encryption_key dump → gdsdecomp extract
- [L3akCTF Braincalc (Chaquopy pyc)](https://medium.com/@kyoungminroh01/l3akctf-2025-writeup-braincalc-mobile-22ef696c05b8) | medium-hard | .imy zip → py3.12 pyc → pylingual decompile → static-only decode (dynamic dead-end noted)

## Batch E — Unity IL2CPP / Xamarin / Cordova / UE4 engines (fetched + extracted)

- [Fla(g)ppy Bird IL2CPP (guarded API)](https://www.ztz0.com/writeups/2025/intechfest-quals/rev/flagppy_bird/) | hard | shuffled-metadata + RC4 body → dl_iterate_phdr bless + coherent (score,encryptedScore) write
- [XYCTF Unity IL2CPP (UPX + dumper)](https://sechub.in/view/2874612) | hard | UPX GameAssembly → Il2CppDumper → IDA struct script → StringLiteral AES params
- [强网just (encrypted libil2cpp)](https://cn-sec.com/archives/4618085.html) | hard | dobby-hooked dlopen decrypt → metadata cipher reimpl → TEA-variant FlagChecker solve
- [强网just (2nd source)](https://www.ctfiot.com/275655.html) | hard | same libil2cpp/metadata decrypt + native-hook confirm
- [XYCTF ez unity (bridge tracing)](https://jishuzhan.net/article/1788583261337817089) | medium-hard | frida-il2cpp-bridge dump.cs + String/Check class tracing for key/iv/ciphertext
- [il2cpp_class_dumper (magic-changed)](https://github.com/AndroidReverser-Test/il2cpp_class_dumper) | hard | InitLocked-offset dynamic class dump for modified IL2CPP [RESEARCH]
- [8kSec Unity game hacking](https://www.8ksec.io/hacking-android-games/) | medium-hard | Il2CppDumper vs il2cpp-bridge dump/trace/collectMoney-hook ladder [RESEARCH]
- [PtraceIl2cppDumper](https://github.com/AndroidReverser-Test/PtraceIl2cppDumper) | hard | ptrace-injected assembly dump module [RESEARCH]
- [SeeTheSharpFlag (Xamarin XALZ)](https://medium.com/@3ed0x92/seethesharpflag-8aeee35ef7ec) | hard | assemblies XALZ → xamarin-decompress → dotPeek AES key/IV recover
- [SeeTheSharpFlag (2nd source)](https://medium.com/@68abdelrahmanmohamed/htb-seethesharpflag-mobile-6d16e94eeaca) | hard | same XALZ→decompress→decompile chain confirm
- [Cold Storage Cordova (obfuscated keygen)](https://ctftime.org/writeup/39671) | hard | cordova www keygen.js deobfuscation → affine+XOR keygen reimpl + console-run
- [Cold Storage (packaging path)](https://medium.com/@ahmadshamius2/my-attempt-at-1337up-ctf-40f385bed06f) | medium | zipalign/sign + Cordova assets discovery + index.html PIN-gate path
- [CyMob-Commander (Cordova 14-gate)](https://medium.com/@AlQa3Qa3_M0X0101/cyctf-qualification-2024-cymob-commander-c54a9ad1d96a) | hard | hook-all root/hook/debug/port/integrity checks + WebView remote-debug enable → JS locate
- [CyMob-Commander (smali NOP)](https://medium.com/@eid662937/cyctf-2024-qualifications-mobile-challenges-catchit-kage-cymob-commander-20e3685bcf58) | hard | smali comment-out of checks + rebuild/resign + Chrome-inspect breakpoint + JS deobfuscate
- [Tencent 2023 IL2CPP VM/MBA](https://sgsgsama.github.io/ctf/Android/%E8%85%BE%E8%AE%AF%E6%B8%B8%E6%88%8F%E5%AE%89%E5%85%A82023%E5%AE%89%E5%8D%93%E5%88%9D%E8%B5%9B/) | hard | dumped-.so ELF repair (soFixer) → IDA rebase + VM handler + MBA tracing
- [SekaiCTF Hijacker (overlay PIN)](https://xk0m1.github.io/2024/08/30/Sekai-CTF-2024/) | hard | TYPE_APPLICATION_OVERLAY replica LoginActivity → 6-digit capture + server submit

## Batch F — deep-link / intent / provider / WebView chains (fetched + extracted)

- [CyCTF Catchit (JS-bridge)](https://medium.com/@eid662937/cyctf-2024-qualifications-mobile-challenges-catchit-kage-cymob-commander-20e3685bcf58) | medium-hard | exported MainActivity + host-gated forward → WebView Jester.showFlag bridge
- [Catchit (inspect-console variant)](https://youssifseliem.github.io/CTF/CyCTF%20qualification%202024/catchit%20(mobile).html) | medium-hard | chrome-inspect console bridge-call + logcat read variant
- [CyCTF Kage (result-hijack)](https://medium.com/@eid662937/cyctf-2024-qualifications-mobile-challenges-catchit-kage-cymob-commander-20e3685bcf58) | hard | Secret_Action + Unlock extra + Tsukuyomi hijack activity returning registration code
- [Kage (Hijack-activity code)](https://youssifseliem.github.io/CTF/CyCTF%20qualification%202024/kage%20(mobile).html) | hard | same chain with full PoC-app intent-filter + setResult code
- [CyCTF Secure View (file-scheme bypass)](https://medium.com/@z0km/cyctf-2025-all-telecom-security-mobile-challenges-writeups-quals-finals-de05c84685fc) | hard | secureviewer:// + single-slash file-path isUrlSafe bypass → WebView internal flag read
- [Secure View (PoC project)](https://github.com/3bdoislam/CyCTF_2025) | hard | finals PoC-app + submit-server flow project files
- [CyCTF Execution (finals model)](https://medium.com/@z0km/cyctf-2025-all-telecom-security-mobile-challenges-writeups-quals-finals-de05c84685fc) | hard | local fake-flag → PoC exploit app → server-side real-flag flow
- [CyCTF Sparrow (Parcelable provider)](https://medium.com/@z0km/cyctf-2025-all-telecom-security-mobile-challenges-writeups-quals-finals-de05c84685fc) | hard | exported NoteViewerActivity + Parcelable NoteModel + FileProvider content read
- [Sparrow (PoC project)](https://github.com/3bdoislam/CyCTF_2025) | hard | PoC-app Parcel-build project confirm
- [ICSCTF Senoparty (provider leak)](https://callmeks.github.io/posts/icsctf-senoparty/) | hard | grantUriPermissions + setResult echo + malicious-APK result-chain bitmap read
- [TCP1P Lookdown (WebView file read)](https://medium.com/@5h3nron/lookdown-challenge-from-tcp1p-a-step-by-step-guide-3ed20e9ec385) | hard | lookdown:// + allowFileAccess WebView + encoded-filename filter bypass + PoC app
- [MHL Guess Me (fragment-suffix RCE)](https://0xbinder.github.io/posts/android-challenge-guess-me/) | hard | url-suffix validator bypass via fragment → AndroidBridge exec bridge RCE
- [Guess Me (encoded-suffix variant)](https://youssifseliem.github.io/Mobile%20Pentesting/Android/Mobile%20Hacking%20Labs/guessMe.html) | hard | percent-encoded suffix payload + hosted-page command demo
- [MHL Strings (AES-gated deep link)](https://hackadoodledoo.com/posts/writeup-mobile-hacking-lab-strings/) | hard | mhl://labs AES-gated Activity2 + date-seed + libflag.so Memory.scan pattern hunt
- [Strings (decrypt-first variant)](https://lautarovculic.github.io/writeups/Mobile%20Hacking%20Lab%20-%20Strings/) | hard | fixed-IV decrypt → secret → base64 deep-link + Intent startActivity chain
- [Strings (Java.choose + adb trigger)](https://medium.com/@asifshaik7093/mobile-hacking-labs-strings-challenge-writeup-0940180b5b1f) | hard | KLOW invoke + adb VIEW trigger + hexdump confirm
- [Strings (MHL medium series)](https://medium.com/@mehmetfarisacar/mobile-hacking-lab-strings-71cddbf466f5) | medium | 4th-source same gated-deep-link chain
- [InjuredAndroid flags 11-12 (links + PoC)](https://medium.com/@francesco.masi1989/injuredandroid-android-ctf-write-up-part-ii-5b8933fd0d33) | medium-hard | custom-scheme launch + Firebase sub-path + Parcelable ProtectedIntent PoC app
- [InjuredAndroid flags 13/16/17](https://www.irregular25.in/posts/injured-android/solution/) | hard | CSP http→https upgrade + Volley decrypt endpoint + Flutter pinning-plugin hook
- [InjuredAndroid flags 1-4 recon](https://sukritdua.com/posts/android-pentesting-part-6/) | medium | exported-activity + strings.xml + base64 recon ladder
- [InjuredAndroid early-version notes](https://sh4d0wlesss.github.io/android/Injured-Android-Writeup-Vol-1/) | medium | bundled-native-asset + menu-binary execution path
- [InjuredAndroid official walkthrough](https://github.com/B3nac/InjuredAndroid/blob/master/InjuredAndroid-FlagWalkthroughs.md) | hard | Flag16 pathPattern CSP + Flag17 Flutter pinning + flag13 RCE link set
- [InjuredAndroid Flag13 RCE](https://meetcyber.net/exploiting-deep-links-for-rce-in-mobile-applications-6806c330c00b) | hard | custom-scheme binary/param traversal → staged shell payload + output-file readback
- [Deep-link enumeration guide](https://nirajkharel.com.np/posts/android-pentesting-deeplinks/) | medium | scheme/host/path/param manifest→code enumeration ladder [RESEARCH]
- [TCP1P Intention (exported sender)](https://hackmd.io/582S6D-PS0yo520gxITloA) | medium-hard | exported FlagSender + exploit-app setResult read
- [TCP1P Imagery (PICK intercept)](https://hackmd.io/582S6D-PS0yo520gxITloA) | hard | implicit PICK intercept + result-code-gated openInputStream of private dir
- [TCP1P Netsight (bridge + intent-scheme)](https://hackmd.io/582S6D-PS0yo520gxITloA) | hard | exported WebView JS bridge → intent:// payload → grantUri FileProvider chain
- [TCP1P (mirror URL)](https://hackmd.io/@avila-pwn-notes/S1a16gqb6) | hard | same 3-challenge chain, mirror copy
- [NahamCon Frozen Gift (JS bridge)](https://kore.one/nahamcon-winter-2025-ctf-frozen-gift-challenge-writeup/) | medium-hard | SnowGiftBridge unlock call + tier-gated native flag
- [Frozen Gift (series summary)](https://welsh.co.ke/posts/nahamcon-winter-ctf-2025-mobile-writeups/) | medium | exported-receiver/tier-escalation series note
- [NahamCon Magic Snowfall (receiver)](https://kore.one/nahamcon-winter-2025-ctf-magic-snowfall-challenge-writeup/) | medium | exported receiver + hardcoded secret + tier-extra broadcast
- [NahamCon Dojo (hardcoded admin token)](https://kore.one/nahamcon-winter-2025-ctf-dojo-helper-center-challenge-writeup/) | medium | Constants token → Bearer admin-endpoint backend pivot
- [NahamCon Ebank (full 5-part)](https://kore.one/nahamcon-winter-2025-ctf-ebank-challenge-writeup/) | hard | non-exported activity via redirection + staged-decode reimpl
- [Intent-redirection bounty case](https://medium.com/@jooelsaka/an-interesting-bug-that-i-found-in-android-mobile-application-becf25c8c4d8) | medium-hard | Parcelable referrerActivity → unexported WebView javascript: XSS [RESEARCH]
- [Deep-link open-redirect set](https://medium.com/@ahmedelmorsy312/how-did-we-find-the-same-vulnerability-in-9-android-apps-caca254a5ba9) | medium | unverified-router → PoC-app redirect chain [RESEARCH]
- [InjuredAndroid flags 1-6](https://medium.com/@francesco.masi1989/injuredandroid-android-ctf-write-up-part-i-7394ffd33ba7) | medium | exported/broadcast/DES-hook starter cluster
- [InjuredAndroid flags 1-10](https://medium.com/@mly57003/mobile-pentesting-a-walkthrough-of-the-first-10-challenges-on-injured-android-app-part1-0e85c600494f) | medium | SQLite-crack + cloud-enum + Firebase-dotjson cluster
- [CyCTF Hooky iOS (static-only)](https://medium.com/@z0km/cyctf-2025-all-telecom-security-mobile-challenges-writeups-quals-finals-de05c84685fc) | hard | red-herring triage → native helper key recovery → offline decrypt
- [CyCTF revME iOS (Cordova plugin)](https://medium.com/@z0km/cyctf-2025-all-telecom-security-mobile-challenges-writeups-quals-finals-de05c84685fc) | hard | Cordova native-plugin key recovery in Ghidra → offline decrypt
- [MHL Notely AI (query-strip)](https://engbaselabutaleb.com/blog/14-ios-notely-ai-challenge-by-mobile-hacking-lab) | hard | Frida port/path/thread/dylib hide ladder + query-filter strip → archived-notes read
- [Ch0pin dontreload (header attach)](https://github.com/Ch0pin/uncrackable) | hard | host-locked WebView + conditional Bearer attach → takeover exfil payload (no-root constraint)
- [Ch0pin insider (prefs exfil)](https://github.com/Ch0pin/uncrackable) | hard | SharedPreferences exfil over victim-app Intent channel + PoC display app
- [Ch0pin Secure-Browser (cookie race)](https://github.com/Ch0pin/uncrackable) | hard | secure-cookie WebView-jump verification challenge

## Batch G — Firebase / backend pivots (fetched + extracted)

- [FAM Flag 2 Database (anon-auth)](https://exploitnotes.hashnode.dev/fam-ctf-the-library-to-the-endpoint-writeup) | hard | permissive RTDB rule + Identity-Toolkit anonymous sign-in → token-authed read
- [FAM Flag 3 Vault (AppCheck)](https://exploitnotes.hashnode.dev/fam-ctf-the-library-to-the-endpoint-writeup) | hard | native-hidden debug token → AppCheck exchange → dual-header Firestore read
- [FAM Flag 4 Endpoint (signing hook)](https://exploitnotes.hashnode.dev/fam-ctf-the-library-to-the-endpoint-writeup) | hard | JNI request-signer hook: swap body to privileged role, reuse client signing
- [Firebase anon-auth methodology](https://razzle-mouse.gitbook.io/razzle_mouse/android-pentesting/firebase-realtime-database-anonymous-auth-bypass) | hard | public-read probe → anonymous sign-up → authed-path read ladder + rule-fix notes [RESEARCH]
- [PwnSec FireStorm (Frida password)](https://lautarovculic.github.io/writeups/PwnSec%20CTF%202024%20-%20FireStorm/) | medium-hard | Java.choose forced Password() → email+password backend auth → database read
- [PwnSec FireStorm (author notes)](https://medium.com/@Handoumeh/pwnsec-ctf-2024-mobile-1b373affd69b) | medium-hard | native string-builder + Firebase config chain confirm
- [PwnSec FireInTheHole (asset AES)](https://medium.com/@Handoumeh/pwnsec-ctf-2024-mobile-1b373affd69b) | medium | assets blob + backend-hosted key/IV → AES offline
- [PwnSec Snake (YAML gadget)](https://medium.com/@Handoumeh/pwnsec-ctf-2024-mobile-1b373affd69b) | hard | root-check smali patch → external-storage YAML deserialization gadget → magic-arg native log
- [PwnSec Snake (intent + file)](https://lautarovculic.github.io/writeups/PwnSec%20CTF%202024%20-%20Snake/) | hard | extra-gated Activity + crafted YAML file + adb trigger confirm
- [SekaiCTF CrackMe (RN + authed flag)](https://stefanin.com/posts/crack-me-writeup/) | medium-hard | RN bundle key/IV → credential decrypt → idToken-authed database read
- [SekaiCTF CrackMe (AES confirm)](https://github.com/Pusty/writeups/tree/master/SekaiCTF2024) | medium-hard | Hex-ciphertext AES params + backend read confirm
- [SekaiCTF CrackMe (traffic confirm)](https://xk0m1.github.io/2024/08/30/Sekai-CTF-2024/) | medium-hard | proxy capture of flag-endpoint read confirm
- [KPMG VaultPass v2 (anon-auth + link)](https://infosecwriteups.com/breaking-the-kpmg-ctf-2025-hardest-mobile-challenge-a-deep-dive-into-vaultpass-v2-94bb61f409fb) | hard | hardcoded API key → anonymous auth → deep-link-gated admin secrets read
- [VaultPass v2 (mirror)](https://daily.dev/posts/breaking-the-kpmg-ctf-2025-hardest-mobile-challenge-a-deep-dive-into-vaultpass-v2-edamjrbfj) | hard | same credential→auth→secrets chain, mirror copy
- [Allsafe Firebase + SQLi](https://medium.com/@xUr00U/allsafe-ctf-part-1-7976e0ada30a) | medium | strings.xml URL → dotjson read + login SQLi cluster
- [Spark Flag01 Firebase](https://el-gastra.tech/posts/spark-ctf/) | medium | strings.xml URL → dotjson read
- [AndroGoat Firebase + patching](https://infosecwriteups.com/mobile-pentesting-androgoat-assessment-walkthrough-1a63a7edc677) | medium-hard | misconfigured database + binary-patching + biometric cluster [PRACTICE]
- [NahamCon Secure Safe (PIN + salted-XOR)](https://ctftime.org/writeup/21401) | medium | 4-digit PIN bruteforce over salted-digest XOR decrypt

## Batch H — iOS jailbreak / RASP / pinning (fetched + extracted)

- [MHL No Escape (offset hook + UI dump)](https://ymuu.me/posts/mobilehackinglab-ios-challenges-writeups/challenge-02---no-escape/) | hard | Swift aggregator offset hook (spaced binary name) + scheduled UILabel tree dump
- [No Escape (symbol + patch)](https://karim-moftah.github.io/posts/No-Escape/) | hard | symbol-enumerate hook + mov-return-false binary patch + reinstall
- [No Escape (r2frida)](https://lautarovculic.github.io/writeups/Mobile%20Hacking%20Lab%20-%20No%20Escape/) | hard | r2frida return-intercept + ARM patch + spawn flow
- [No Escape (triple method)](https://0xbartita.com/blog/mhl-02-no-escape) | hard | Frida vs binary-patch vs LLDB on one aggregator + double-hit register flip
- [No Escape (Ghidra flow patch)](https://infosecwriteups.com/bypassing-ios-jailbreak-detection-by-patching-the-binary-with-ghidra-write-up-of-no-escape-lab-02b417b3a235) | hard | 4-check call-graph patch + resign/reinstall flow
- [Captain No Hook (aggregator replace)](https://incogbyte.github.io/posts/captain-no-hook-mobilehackinglabs/) | hard | frida-trace symbol hunt + NativeCallback aggregator replace + dyld image-name hide
- [Captain No Hook (full RASP chain)](https://nasrsec.com/blog/mobile/mobilehackinglab-captainnohook-ios/) | hard | ptrace/sysctl/port/file/DYLD chain + gated decrypt + button-hook label read
- [FridaInTheMiddle (LLDB-only)](https://www.cylentsec.com/blog/2025/12/13/8ksec-FridaInTheMiddle-CTF/) | hard | debugserver freeze + sanity-check register flip + Swift string-memory read
- [FridaInTheMiddle (hybrid)](https://blog.reversesociety.co/blog/2025/8ksec-ios-ctf-writeup) | hard | LLDB detect-bypass + Frida arg-intercept hybrid
- [iOS UnCrackable L2 (ptrace + crypt)](https://www.ryantzj.com/posts/owasp-mstg-ios-crackme/) | hard | class-dump → ptrace/sysctl hooks + file-list bypass + decrypt-function log
- [DVIAv2 5-level Swift bypass](https://philkeeble.com/ios/reverse-engineering/iOS-Bypass-Jailbreak/) | hard | register-level hooks on Swift checks + ObjC boolean flip + combined script
- [DVIA Corellium class hunt](https://cellebrite.com/en/blog/ios-jailbreak-detection-bypass/) | medium-hard | class/method enumerate + return-replace on virtualized device
- [DVIA r2frida trace/flip](https://twelvesec.com/2023/09/27/ios-instrumentation-using-corellium-frida-and-r2frida/) | medium-hard | class filter + trace + Interceptor return-flip over USBFlux
- [DVIA login (r2frida dif)](https://www.appknox.com/blog/ios-apps-penetration-testing-r2frida-for-ios-app-runtime-manipulation) | medium | validator-method trace + return-replace login bypass
- [DVIA pinning + IPA pull](https://blog.onsec.io/lab-for-pentesting-ios-applications-part-2/) | medium | codeshare pinning bypass + objection module + on-device IPA dump
- [iOS lab setup matrix](https://blog.onsec.io/lab-for-pentesting-ios-applications-part-1/) | medium | jailbreak-per-version + Frida-source install matrix [RESEARCH]
- [iOS no-jailbreak gadget](https://notsunde.com/blogs/ios-pentest-setup-pt2) | hard | dylib-insert FridaGadget + sideload + entitlement-gated debugger attach [RESEARCH]
- [MASTG jailbreak TECH-0152](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0152/) | medium | objection module + frida-trace return-replace [RESEARCH]
- [MASTG iOS pinning TECH-0064](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0064/) | medium | kill-switch vs objection vs binary-patch ladder [RESEARCH]
- [iOS pinning codeshare flow](https://pentestguy.com/ios-ssl-pinning-bypass-using-frida/) | medium | Burp CA trust + codeshare bypass hook [RESEARCH]
- [iOS pinning IDA anchor](https://www.ids-sax2.com/how-to-perform-ssl-pinning-bypass-on-ios-apps-using-frida-and-objection/) | medium-hard | trust-evaluate anchor in IDA + objection/Frida dual path [RESEARCH]
- [LLDB boolean bypass + auto](https://diverto.github.io/2024/11/24/bypassing-boolean-based-ios-jailbreak-detection-with-lldb) | hard | syscall-path watch → return-register flip + Python breakpoint automation
- [Ch0pin Four (input-only)](https://github.com/Ch0pin/uncrackable) | hard | sandbox-preserving input-only label-spoof challenge
- [MASTG CodeShare index](https://mas.owasp.org/MASTG/tools/generic/MASTG-TOOL-0032/) | medium | unpinning/flutter-tls/jnitrace/dex-dump script index [RESEARCH]

## Batch I — Keystore / crypto / attestation / root (fetched + extracted)

- [CTRL_Alt_Frida (EncryptedSharedPreferences)](https://jctf.team/writeups/AppSec-IL-2025/CTRL_Alt_Frida/) | hard | MasterKey recreate + encrypted-prefs read via Frida upload-script (array anti-memscan note)
- [White-box AES DFA via Frida](https://www.cnblogs.com/GGbomb/p/18621516) | hard | native round-tracing → pre-final-round state fault → faulty-ciphertext key recovery
- [Insomni'hack Notes (iterated AES)](https://cryptax.github.io/ins2024-notes/) | hard | hundreds-of-thousands-iteration AES-ECB + wordlist bruteforce + Android/Java API porting notes
- [Keystore/TEE research (TA fuzzing)](https://imlzq.com/android/fuzzing/unicorn/tee/2024/05/29/Dive-Into-Android-TA-BugHunting-And-Fuzzing.html) | hard | TA emulation + auth-bound decryption + missing-auth-API case [RESEARCH]
- [MARA attestation downgrade](https://yikunh.github.io/publication/zhou-2024-a/zhou-2024-a.pdf) | hard | software-vs-hardware check-result downgrade model [RESEARCH]
- [SafetyNet arbitrary-attestation PoC](https://gist.github.com/liamcottle/2db0e954f7262da30596fccd1bfc54ef) | hard | arbitrary-claim BASIC + hardware-backed flag PoC [RESEARCH]
- [Attestation formal model](https://doi.org/10.1145/3579856.3582812) | hard | Knox relay + key-attestation freshness findings [RESEARCH]
- [safetynet-fix module](https://github.com/kdrag0n/safetynet-fix) | medium-hard | CTS-profile + hardware-attestation dodge module [RESEARCH]
- [ProtonAOSP SafetyNet notes](https://protonaosp.org/developers/details/safetynet) | medium | fingerprint-scoping + model-rename dodge notes [RESEARCH]
- [MHC Root Quest (dual false-hook)](https://pentest.bi0s.in/blog/posts/mobile-hacking-community-ctf-root-quest/) | medium | emulator + root check dual return-false hook
- [MASTG root TECH-0144](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0144/) | medium | file-probe filter + namespace-hiding + patch alternatives [RESEARCH]
- [MASTG method-hook TECH-0043](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0043/) | medium | dialog-suppress + decrypt-return intercept model [RESEARCH]
- [UnCrackable 1 (checks + AES recall)](https://hngnh.com/posts/OWASP-Android-Uncrackable-Level-1/) | medium | triple-check false + decrypt re-invoke for secret
- [UnCrackable 1 (spawn-early)](https://nibarius.github.io/learning-frida/2020/05/16/uncrackable1) | medium | spawn-before-check + lifecycle-triggered secret dump
- [UnCrackable 1 (smali patch)](https://nightfury0x1.gitlab.io/mobile/android/owasp/uncrackableL1/) | medium | smali const-false + resign + verify-true patch path
- [Juicy Bar obfuscated AES](https://ad2001.com/blog/obfuscated-secrets) | medium-hard | custom-decode wrapper → SecretKeySpec/IvParameterSpec constructor hooks → hex-decode halves

## Batch R — repo-indexed challenge dirs (listing fetched, URL pattern spot-verified)

> Each line = one repo-hosted mobile challenge dir (APK + README/solve). Chain =
> technique family from challenge title + event context. Difficulties inferred.

- [Cyberchaze Capture me!!](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/Cyberchaze%20CTF/Capture%20me%21%21) | medium | APK triage → manifest/strings entry-point solve
- [Cyberchaze Chaos In Production House](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/Cyberchaze%20CTF/Chaos%20In%20Production%20House) | medium-hard | production-build reversing: logging/config leftovers → secret recovery
- [Cyberchaze Did you miss me?](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/Cyberchaze%20CTF/Did%20you%20miss%20me%3F) | medium-hard | stale-component hunt: outdated activity/provider → legacy-gate bypass
- [Cyberchaze RobMob](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/Cyberchaze%20CTF/RobMob) | medium-hard | robbery-game logic: client-side money/state tamper → flag purchase
- [Pearl ShadowVault](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/Pearl%20CTF/ShadowVault) | hard | vault-crypto: staged key recovery + offline decrypt
- [Ugra SecuSafe](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/Ugra%20CTF/SecuSafe) | hard | safe-crypto: PIN/keypad-gated decrypt reimpl
- [K!nd4SUS SU APP](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/K%21nd4SUS%20CTF/SU%20APP) | hard | su-gated flow: root-check bypass → privileged-path flag read
- [Nowruz Slutter Revange](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/Nowruz%201404/Slutter%20Revange) | hard | Flutter ("Slutter") bundle: snapshot/strings → channel-seam hook
- [m0leCon DroidCryptor](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/m0leCon%20CTF/DroidCryptor) | medium | AES lab: static key + token-IV offline decrypt
- [UNbreakable dev_release](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/UNbreakable%20International/dev_release) | medium-hard | release-build reversing: stripped logic → API/key recovery
- [DiceCTF Convenience Store](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/DiceCTF/Convenience%20Store) | hard | store-logic puzzle: transaction-state tamper → flag checkout
- [squ1rrel droid](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/squ1rrel%20CTF/droid) | hard | APK reversing + backend oracle: client gates → server confirm
- [DaVinci Infected Brick](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/DaVinciCTF/Infected%20Brick) | hard | trojaned-brick analysis: persistence/decode → C2-string recovery
- [D^3CTF d3piano](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/D%5E3CTF/d3piano) | hard | piano-app logic: input-sequence → sound/state-gated decrypt
- [N0PS LooneyDroid](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/N0PSCTF/LooneyDroid) | medium-hard | cartoon-app reversing: hidden-activity → intent trigger
- [N0PS VaLidTOR](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/N0PSCTF/VaLidTOR) | hard | validator-gated flow: input oracle → crypto reimpl
- [bi0sCTF cratecrack](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/bi0sCTF/cratecrack) | hard | WebView-JS → native UAF heap-leak → signature-nonce crypto solve
- [Google CTF fluffy](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/Google%20CTF/fluffy) | hard | fluffy-app reversing: staged deobfuscation → flag assembly
- [Payatu A Strange Door](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/Payatu%20Hiring%20CTF/A%20Strange%20Door) | medium-hard | door-gate logic: activity-chain → key recovery
- [Payatu Gate Keeper Final](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/Payatu%20Hiring%20CTF/Gate%20Keeper%20Final) | hard | multi-gate keeper: layered checks → sequential bypass
- [Payatu Path Finder](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/Payatu%20Hiring%20CTF/Path%20Finder) | medium-hard | path-puzzle: file/route discovery → flag path
- [Payatu Snorlex](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/Payatu%20Hiring%20CTF/Snorlex) | medium-hard | game-logic tamper: state edit → reward flag
- [Payatu Where Am I](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/Payatu%20Hiring%20CTF/Where%20Am%20I) | hard | location-gated flag: mock-location/provider hook → region bypass
- [L3akCTF Androbro](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/L3akCTF/Androbro) | hard | native-layered crypto + hidden-DEX solve (repo copy)
- [L3akCTF Apkocalypse](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/L3akCTF/Apkocalypse) | hard | APK-apocalypse: multi-stage unpack + logic rebuild
- [L3akCTF BrainCalc](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/L3akCTF/BrainCalc) | medium-hard | Chaquopy pyc recover (repo copy)
- [L3akCTF PricelessL3ak](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/L3akCTF/PricelessL3ak) | hard | leak-oracle: memory/log leak → secret assembly
- [BDSec Hacker App](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/BDSec/Hacker%20App) | medium-hard | hacker-sim reversing: terminal-gate → command-oracle solve
- [ShaktiCTF Now You See Me](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/ShaktiCTF/Now%20You%20See%20Me) | hard | visibility-gated flag: UI-state/timing trick → reveal path
- [WorldWideCTF Emulator](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/WorldWideCTF/Emulator) | hard | emulator-detection duel: prop-spoof vs check ladder
- [idekCTF Exposition](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/idekCTF/Exposition) | medium-hard | expo-app reversing: config/secret recovery
- [MHC Based](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/Mobile%20Hacking%20Community%20CTF/Based) | medium | baseline-app triage: manifest → strings → logic solve
- [MHC Lab AI Accelerator](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/Mobile%20Hacking%20Community%20CTF/Lab%20-%20AI%20Accelerator) | hard | on-device-AI gate: model-output oracle → bypass
- [MHC Native Echoes Of Moria](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/Mobile%20Hacking%20Community%20CTF/Native%20Echoes%20Of%20Moria) | hard | native echo-oracle: JNI round-trip → secret reflection
- [MHC No Comments](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/Mobile%20Hacking%20Community%20CTF/No%20Comments) | medium | comment-gated notes: hidden-field → flag read
- [MHC No Matter What You See](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/Mobile%20Hacking%20Community%20CTF/No%20Matter%20What%20You%20See) | hard | UI-deception: displayed-vs-real state → memory/log truth
- [MHC Prints](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/Mobile%20Hacking%20Community%20CTF/Prints) | medium | print-path leak: log/share-sheet → flag capture
- [MHC Root Quest](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/Mobile%20Hacking%20Community%20CTF/Root%20Quest) | medium | root+emulator dual bypass (repo copy)
- [MHC ShakenNotStirred](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/Mobile%20Hacking%20Community%20CTF/ShakenNotStirred) | medium-hard | sensor-gated flag: accelerometer/shake spoof → trigger
- [MHC SnakeOnAPhone](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/Mobile%20Hacking%20Community%20CTF/SnakeOnAPhone) | medium-hard | snake-game state tamper → score-gated flag
- [MHC Spin and Win](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/Mobile%20Hacking%20Community%20CTF/Spin%20and%20Win) | medium | spinner-RNG: seed/predict → jackpot flag
- [MHC The Knox Club](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/Mobile%20Hacking%20Community%20CTF/The%20Knox%20Club) | hard | Knox/attestation-gated: client-verdict hook → club flag
- [Sekai Bank Signature](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/SekaiCTF/Sekai%20Bank%20Signature) | hard | bank-signature crypto: sign-oracle → transaction forge
- [Sekai Bank Transaction](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/SekaiCTF/Sekai%20Bank%20Transaction) | hard | transaction-tamper: request rewrite → ledger flag
- [TFC Creaky Vault](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/TFC%20CTF/Creaky%20Vault) | hard | vault-crypto: aged/creaky cipher reimpl → decrypt
- [TFC Oxidized Intentions](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/TFC%20CTF/Oxidized%20Intentions) | hard | broadcast+JNI game solve (repo copy)
- [Cyber Mimis Just](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/Cyber%20Mimis%20CTF/Just) | medium | just-in-time gate: timing/race → flag window
- [PwnSec CuteFrida](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/PwnSec%20CTF/CuteFrida) | medium-hard | Frida-hook tutorial ladder: method-hook → return-tamper
- [PwnSec FreakyFrida](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/PwnSec%20CTF/FreakyFrida) | hard | anti-Frida dual-.so duel (repo copy)
- [PwnSec RudeFrida](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/PwnSec%20CTF/RudeFrida) | hard | rude-anti-hook: rude-check ladder → narrow bypasses
- [LakeCTF Another Android Applaketion](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/Lake%20CTF/Another%20Android%20Applaketion) | medium-hard | applaketion wordplay: resource/asset hunt → flag
- [HeroCTF Freeda Simple Hook](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/HeroCTF/Freeda%20Simple%20Hook) | medium | basic method-hook: return-value read
- [HeroCTF Freeda Not Root](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/HeroCTF/Freeda%20Not%20Root) | medium-hard | root-check hook → clean-environment flag
- [HeroCTF Freeda Native Hook](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/HeroCTF/Freeda%20Native%20Hook) | hard | native-function hook: JNI arg/return tamper
- [GlacierCTF IcySlide2](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/GlacierCTF/IcySlide2) | hard | slider-puzzle binary: state-solve → flag path
- [MHLxIT Parse & Pwn](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/Mobile%20Hacking%20Lab%20x%20IT%20Harmony%20CTF/Parse%20%26%20Pwn) | hard | parser-differential: malformed-input → code-execution primitive
- [MHLxIT Tide Lock](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/Mobile%20Hacking%20Lab%20x%20IT%20Harmony%20CTF/Tide%20Lock) | hard | tide/time-gated lock: clock tamper → unlock window
- [MHLxIT Kernel Net](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/Mobile%20Hacking%20Lab%20x%20IT%20Harmony%20CTF/Kernel%20Net) | hard | kernel-net filter: packet/oracle path → flag exfil
- [MHLxIT FuzzMe](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/Mobile%20Hacking%20Lab%20x%20IT%20Harmony%20CTF/FuzzMe) | hard | harness-fuzz: crash-oracle → input-shape flag
- [P3RF3CT BiFrost](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/P3RF3CTR00T%20CTF/BiFrost) | hard | bifrost-bridge: two-world state sync → flag cross
- [P3RF3CT Knight](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/P3RF3CTR00T%20CTF/Knight) | medium-hard | knight-move puzzle: move-oracle → path flag
- [P3RF3CT Days Gone](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/P3RF3CTR00T%20CTF/Days%20Gone) | medium-hard | expiry-gone logic: date tamper → unlock
- [P3RF3CT Mad Max](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/P3RF3CTR00T%20CTF/Mad%20Max) | hard | fury-road game: resource-tamper → max flag
- [Kashi Painfully Slow](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/Kashi%20CTF/Painfully%20Slow) | hard | slow-oracle: timing-side-channel → secret recovery
- [DaVinci VinciVault (iOS)](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/DaVinciCTF/VinciVault) | hard | iOS vault: jailbreak-gated decrypt → flag
- [MHC Quackify (iOS)](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/Mobile%20Hacking%20Community%20CTF/Quackify) | medium-hard | iOS duck-hunt logic: state tamper → flag
- [MHC Quantun Chat (iOS)](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/Mobile%20Hacking%20Community%20CTF/Quantun%20Chat) | hard | iOS chat-crypto: message oracle → decrypt
- [MHLxIT Broke Lesnor (iOS)](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/Mobile%20Hacking%20Lab%20x%20IT%20Harmony%20CTF/Broke%20Lesnor) | medium-hard | iOS banker-logic: balance tamper → flag
- [MHLxIT Draw Back (iOS)](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/Mobile%20Hacking%20Lab%20x%20IT%20Harmony%20CTF/Draw%20Back) | medium-hard | iOS draw-puzzle: gesture oracle → unlock
- [MHLxIT Link Liar (iOS)](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/Mobile%20Hacking%20Lab%20x%20IT%20Harmony%20CTF/Link%20Liar) | hard | iOS universal-link lie: link-chain → flag route
- [MHLxIT Pictator (iOS)](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2025/Mobile%20Hacking%20Lab%20x%20IT%20Harmony%20CTF/Pictator) | medium-hard | iOS image-oracle: pixel/metadata hunt → flag
- [Eschaton Hello World](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2026/Eschaton%20CTF%20Quals/Hello%20World) | medium | hello-world triage: first-activity → flag path
- [Eschaton Couple Gallery](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2026/Eschaton%20CTF%20Quals/Couple%20Gallery) | medium-hard | gallery-pair puzzle: image-match → unlock
- [Eschaton Text Safe](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2026/Eschaton%20CTF%20Quals/Text%20Safe) | medium-hard | text-safe crypto: note encrypt → key recovery
- [Eschaton Hamster Combat](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2026/Eschaton%20CTF%20Quals/Hamster%20Combat) | medium-hard | tap-game tamper: combo/state edit → flag
- [MHLCTF NoSQolarly](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2026/MHLCTF/NoSQolarly) | hard | NoSQL-injection: query-operator → data exfil
- [BKCTF Missing Homework](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2026/BKCTF/Missing%20Homework) | medium-hard | homework-tracker: assignment-state → flag unlock
- [VolgaCTF Aether](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2026/VolgaCTF/Aether) | hard | aether-crypto: staged decrypt → flag
- [SekaiCTF SekaiID](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2026/SekaiCTF/SekaiID) | hard | ID-oracle: identifier forge → auth bypass
- [SekaiCTF UFO](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2026/SekaiCTF/UFO) | hard | UFO-track puzzle: signal/oracle → flag
- [UniVsThreats PhantomGate](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2026/UniVsThreats/PhantomGate) | hard | phantom-gate: invisible-component → intent reach
- [UniVsThreats Vault](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2026/UniVsThreats/Vault) | hard | vault-crypto: key ladder → decrypt
- [UniVsThreats Whisper](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2026/UniVsThreats/Whisper) | hard | whisper-channel: covert-message → flag decode
- [UniVsThreats IronDrop](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2026/UniVsThreats/IronDrop) | hard | drop-share: file-handoff intercept → flag
- [Novruz Analyze Application](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2026/NovruzCTF/Analyze%20Application) | medium | guided-analysis: manifest→code→flag ladder
- [BSidesSF Vinyl Drop](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2026/BSidesSF/Vinyl%20Drop) | medium-hard | needle-drop puzzle: track-order → flag
- [BSidesSF Doremi](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2026/BSidesSF/Doremi) | medium-hard | scale-puzzle: note-sequence → unlock
- [BKISC Boring APK](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2026/BKISC/Boring%20APK) | medium | boring-triage: deceptive-simple → hidden-layer flag
- [FromDuskTillDawn Fibonhackmon](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2026/FromDuskTillDawnCTF/Fibonhackmon) | hard | fibonacci-oracle: sequence-gated decrypt
- [BYUCTF Back and Forth](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2026/BYUCTF/Back%20and%20Forth) | medium-hard | activity-tennis: result-chain → flag
- [0xv01d Mawj Relay](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2026/0xv01dCTF/Mawj%20Relay) | hard | wave-relay: signal-forward → flag route
- [0xv01d Nahar Splits](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2026/0xv01dCTF/Nahar%20Splits) | hard | split-secret: part-join → flag assembly
- [0xv01d Qasr Backup](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2026/0xv01dCTF/Qasr%20Backup) | medium-hard | backup-exfil: backup-rules → data read
- [0xv01d Qasr Cache](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2026/0xv01dCTF/Qasr%20Cache) | medium-hard | cache-scrape: stale-entry → flag recovery
- [brunner Cake Search](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2026/brunnerCTF/Cake%20Search) | medium-hard | search-oracle: query-shape → hidden-entry flag
- [brunner Clean Desk](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2026/brunnerCTF/Clean%20Desk) | medium-hard | cleaner-logic: wipe-order → recoverable flag
- [brunner One Pass](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2026/brunnerCTF/One%20Pass) | hard | single-pass gate: one-shot oracle → flag
- [brunner One Voice](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2026/brunnerCTF/One%20Voice) | hard | voice-oracle: audio-gate → flag decode
- [brunner Total Reward](https://github.com/pentest-bi0s/Mobile-CTFs/tree/main/2026/brunnerCTF/Total%20Reward) | hard | reward-accumulator: points-tamper → flag purchase

## Batch L — lautarovculic index (listing fetched; technique family from title context)

> One author-indexed writeup per line; slugs transcribed from the fetched listing.
> Chains = technique family implied by challenge title/series; index-mined, see report.

- [8kSec AndroDialer](https://lautarovculic.github.io/writeups/8kSec%20-%20AndroDialer%20-%20The%20Ultimate%20Phone%20Experience/) | hard | dialer-RASP: call-flow gates → telecom-manager hook ladder
- [8kSec AndroPseudoProtect](https://lautarovculic.github.io/writeups/8kSec%20-%20AndroPseudoProtect%20-%20The%20Ultimate%20Device%20Security/) | hard | pseudo-RASP: layered device checks → per-check narrow bypasses
- [8kSec BackSync](https://lautarovculic.github.io/writeups/8kSec%20-%20BackSync/) | hard | backup-sync duel: backup-rules vs exfil read
- [8kSec BadPreferences](https://lautarovculic.github.io/writeups/8kSec%20-%20BadPreferences/) | medium-hard | prefs-tamper: SharedPreferences edit → gate bypass
- [8kSec BorderDroid](https://lautarovculic.github.io/writeups/8kSec%20-%20BorderDroid%20-%20International%20Border%20Protection/) | hard | border-check: locale/region gate → property spoof
- [8kSec ClearRoute](https://lautarovculic.github.io/writeups/8kSec%20-%20ClearRoute/) | hard | route-gate: navigation-state → flag path
- [8kSec DroidCave](https://lautarovculic.github.io/writeups/8kSec%20-%20DroidCave%20-%20Secure%20Password%20Management/) | hard | password-manager vault: master-gate → crypto reimpl
- [8kSec DroidView](https://lautarovculic.github.io/writeups/8kSec%20-%20DroidView%20-%20Ultimate%20Private%20Browsing%20Solution/) | hard | private-browser: WebView gates → file/bridge read
- [8kSec DroidWars](https://lautarovculic.github.io/writeups/8kSec%20-%20DroidWars%20-%20The%20Plugins%20Race/) | hard | plugin-race: dynamic-code-load order → flag plugin
- [8kSec FactsDroid](https://lautarovculic.github.io/writeups/8kSec%20-%20FactsDroid%20-%20Your%20Universal%20Knowledgebase/) | medium-hard | knowledgebase: content-query → hidden-entry read
- [8kSec FreeFallGame](https://lautarovculic.github.io/writeups/8kSec%20-%20FreeFallGame/) | medium-hard | game-physics tamper: score/state edit → flag
- [8kSec FridaInTheMiddle](https://lautarovculic.github.io/writeups/8kSec%20-%20FridaInTheMiddle/) | hard | anti-Frida RASP + arg-intercept (index copy)
- [8kSec GeofenceGamble](https://lautarovculic.github.io/writeups/8kSec%20-%20GeofenceGamble%20-%20The%20Ultimate%20Game%20of%20Speed/) | hard | geofence-gamble: mock-location/provider hook → fence bypass
- [8kSec ReconDroid](https://lautarovculic.github.io/writeups/8kSec%20-%20ReconDroid%20-%20The%20Application%20Intelligence%20Provider/) | hard | provider-intel: authority enumerate → row read
- [8kSec SwizzleMeTimbers](https://lautarovculic.github.io/writeups/8kSec%20-%20SwizzleMeTimbers/) | hard | iOS method-swizzle duel: IMP swap detect → hook order win
- [8kSec TraceTheChat](https://lautarovculic.github.io/writeups/8kSec%20-%20TraceTheChat/) | hard | chat-trace: pinning bypass → message-intercept flag
- [8kSec TraceTheMap](https://lautarovculic.github.io/writeups/8kSec%20-%20TraceTheMap/) | hard | map-trace: location/traffic intercept → route flag
- [8kSec WhereAmIReally](https://lautarovculic.github.io/writeups/8kSec%20-%20WhereAmIReally/) | hard | location-spoof duel: multi-source check → consistent mock
- [MHL Flipcoin Wallet](https://lautarovculic.github.io/writeups/Mobile%20Hacking%20Lab%20-%20Flipcoin%20Wallet/) | hard | wallet-crypto: coin-state tamper → payout flag
- [MHL Freshcart](https://lautarovculic.github.io/writeups/Mobile%20Hacking%20Lab%20-%20Freshcart/) | medium-hard | cart-logic: price/qty tamper → checkout flag
- [MHL Gotham Times](https://lautarovculic.github.io/writeups/Mobile%20Hacking%20Lab%20-%20Gotham%20Times/) | medium-hard | news-paywall: article-gate → flag read
- [MHL NoteKeeper](https://lautarovculic.github.io/writeups/Mobile%20Hacking%20Lab%20-%20NoteKeeper/) | hard | note-buffer: overflow-gated notes → flag (pairs with MHL medium series)
- [MHL Post Board](https://lautarovculic.github.io/writeups/Mobile%20Hacking%20Lab%20-%20Post%20Board/) | medium-hard | WebView board: post-XSS/bridge → flag read
- [MHL Quackify](https://lautarovculic.github.io/writeups/Mobile%20Hacking%20Lab%20-%20Quackify/) | medium-hard | duck-hunt state: level tamper → flag
- [MHL Quantum Chat](https://lautarovculic.github.io/writeups/Mobile%20Hacking%20Lab%20-%20Quantum%20Chat/) | hard | chat-crypto: message oracle → decrypt
- [MHL Run Time](https://lautarovculic.github.io/writeups/Mobile%20Hacking%20Lab%20-%20Run%20Time/) | hard | runtime-manip: timing/checkpoint duel → flag
- [MHL Serial Notes](https://lautarovculic.github.io/writeups/Mobile%20Hacking%20Lab%20-%20Serial%20Notes/) | medium-hard | serial-gated notes: keygen/verify → unlock
- [MHL Shaken not stirred](https://lautarovculic.github.io/writeups/Mobile%20Hacking%20Lab%20-%20Shaken%2C%20not%20stirred/) | medium-hard | sensor-gate: shake-event spoof → trigger
- [MHL Time Trap](https://lautarovculic.github.io/writeups/Mobile%20Hacking%20Lab%20-%20Time%20Trap/) | hard | time-trap: clock/delay duel → window hit
- [MHL TokenBleed](https://lautarovculic.github.io/writeups/Mobile%20Hacking%20Lab%20-%20TokenBleed/) | hard | token-leak: log/memory bleed → token capture → authed read
- [NahamCon Guitar](https://lautarovculic.github.io/writeups/NahamCon%202024%20-%20Guitar/) | medium-hard | audio-app: string/resource hunt → flag chord
- [NahamCon Andra & Resourceful](https://lautarovculic.github.io/writeups/NahamCon%20CTF%202021%20-%20Andra%20%26%20Resourceful/) | medium | resource-double: asset + resource fork → flag join
- [NahamCon Click Me](https://lautarovculic.github.io/writeups/NahamCon%20CTF%202022%20-%20Click%20Me%21/) | medium | click-gate: tap-counter → flag threshold
- [NahamCon Mobilize](https://lautarovculic.github.io/writeups/NahamCon%20CTF%202022%20-%20Mobilize/) | medium-hard | mobilize-logic: deploy-state → flag release
- [NahamCon Secure Notes 2022](https://lautarovculic.github.io/writeups/NahamCon%20CTF%202022%20-%20Secure%20Notes/) | medium-hard | secure-notes crypto: note vault → key recovery
- [HTB Angler](https://lautarovculic.github.io/writeups/Angler%20%E2%80%93%20Hack%20The%20Box/) | hard | phish-hook: deep-link lure → credential/flag capture
- [HTB Cryptohorrific](https://lautarovculic.github.io/writeups/Cryptohorrific%20%E2%80%93%20Hack%20The%20Box/) | hard | horror-crypto: staged decrypt → flag
- [HTB Don't Overreact](https://lautarovculic.github.io/writeups/Don%E2%80%99t%20Overreact%20%E2%80%93%20Hack%20The%20Box/) | hard | reactive-UI duel: state-race → flag render
- [HTB DroidPhish Sherlock](https://lautarovculic.github.io/writeups/DroidPhish%20%28Sherlock%29%20-%20Hack%20The%20Box/) | hard | forensic-APK: artifact hunt → phish-trail flag
- [HTB Explore](https://lautarovculic.github.io/writeups/Explore%20%E2%80%93%20Hack%20The%20Box/) | medium-hard | explorer-app: file-tree walk → flag file
- [HTB FastJson and Furious](https://lautarovculic.github.io/writeups/FastJson%20and%20Furious%20%E2%80%93%20Hack%20The%20Box/) | hard | JSON-deserialization: gadget chain → RCE/flag
- [HTB FlappyFlopper](https://lautarovculic.github.io/writeups/FlappyFlopper%20-%20Hack%20The%20Box/) | medium-hard | flappy-state: score tamper → flag
- [HTB Investigator](https://lautarovculic.github.io/writeups/Investigator%20%E2%80%93%20Hack%20The%20Box/) | hard | investigator-OSINT: in-app trail → flag
- [HTB Jigsaw](https://lautarovculic.github.io/writeups/Jigsaw%20-%20Hack%20The%20Box/) | hard | jigsaw-dex: split-dex join → logic rebuild
- [HTB Joker](https://lautarovculic.github.io/writeups/Joker%20%E2%80%93%20Hack%20The%20Box/) | hard | joker-wildcard: unpredictable-gate → oracle tame
- [HTB Manager](https://lautarovculic.github.io/writeups/Manager%20%E2%80%93%20Hack%20The%20Box/) | hard | manager-auth: role-gate → privilege path
- [HTB Pedometer](https://lautarovculic.github.io/writeups/Pedometer%20-%20Hack%20The%20Box/) | medium-hard | step-counter: sensor spoof → goal flag
- [HTB Supermarket](https://lautarovculic.github.io/writeups/Supermarket%20%E2%80%93%20Hack%20The%20Box/) | medium-hard | market-logic: cart/price tamper → checkout flag
- [HTB Waiting](https://lautarovculic.github.io/writeups/Waiting%20%E2%80%93%20Hack%20The%20Box/) | hard | wait-oracle: delay-gate → timing solve
- [HTB WonderSMS](https://lautarovculic.github.io/writeups/WonderSMS%20-%20Hack%20The%20Box/) | hard | SMS-intercept: broadcast-receiver → OTP/flag capture
- [Google Ill Intentions](https://lautarovculic.github.io/writeups/Google%20CTF%202016%20-%20Ill%20Intentions/) | hard | classic intent-firewall duel: intent-shape → gate bypass
- [Google Little Bobby](https://lautarovculic.github.io/writeups/Google%20CTF%202016%20-%20Little%20Bobby%20application/) | medium-hard | injection-in-app: SQLi-gate → flag row
- [Google Sandbox](https://lautarovculic.github.io/writeups/Google%20CTF%202020%20-%20Sandbox/) | hard | sandbox-escape: WebView/JS cage → broker read
- [Google Shall We Play A Game](https://lautarovculic.github.io/writeups/Google%20CTF%20Quals%202018%20-%20Shall%20We%20Play%20A%20Game%3F/) | hard | game-console: command-oracle → flag move
- [UniWA CaptainHook](https://lautarovculic.github.io/writeups/UniWA%202022%20-%20CaptainHook/) | hard | hook-duel: anti-hook vs hook order → flag
- [UniWA SeekNDestroy](https://lautarovculic.github.io/writeups/UniWA%202022%20-%20SeekNDestroy/) | medium-hard | seek-puzzle: hidden-object → destroy-gate flag
- [UniWA SlapApp](https://lautarovculic.github.io/writeups/UniWA%202022%20-%20SlapApp/) | medium-hard | slap-timing: tap-race → flag
- [UniWA WarmupApp](https://lautarovculic.github.io/writeups/UniWA%202022%20-%20WarmupApp/) | medium | warmup-triage: manifest → logic flag
- [BSidesSF pinlock](https://lautarovculic.github.io/writeups/BSides%20San%20Francisco%20CTF%202017%20%20-%20pinlock/) | medium-hard | PIN-lock: bruteforce-gated crypto reimpl
- [RaziCTF Chasing a lock](https://lautarovculic.github.io/writeups/RaziCTF%202020%20-%20Chasing%20a%20lock/) | hard | lock-chase: dynamic-code → moving-gate solve
- [Trend Micro Keybox](https://lautarovculic.github.io/writeups/Trend%20Micro%20CTF%202020%20-%20Keybox/) | hard | keybox-DRM: box-gated decrypt → key recovery
- [H1-702 Challenge 1](https://lautarovculic.github.io/writeups/HackerOne%20H1-702%20-%20Challenge%201/) | hard | H1-mobile-1: staged appsec gates → flag
- [H1-702 Challenge 2](https://lautarovculic.github.io/writeups/HackerOne%20H1-702%20-%20Challenge%202/) | hard | H1-mobile-2: deeper gate chain → flag
- [H1-702 Challenge 3](https://lautarovculic.github.io/writeups/HackerOne%20H1-702%20-%20Challenge%203/) | hard | H1-mobile-3: hardest gate set → flag
- [CyberTruck Android CTF](https://lautarovculic.github.io/writeups/CyberTruck%20Challenge%202019%20-%20Android%20CTF/) | medium-hard | truck-ECU companion: BLE/serial oracle → flag
- [Intentional Exercise](https://lautarovculic.github.io/writeups/Intentional%20Exercise/) | medium-hard | intent-drill: component-shape → gate pass
- [Oauthbreaker](https://lautarovculic.github.io/writeups/Oauthbreaker/) | hard | OAuth-flow break: redirect/token swap → account flag
- [UVT Jokes and Info](https://lautarovculic.github.io/writeups/UVT%20CTF%202025%20-%20Jokes%20and%20Info/) | medium-hard | joke-oracle: API-shape → hidden-info flag
- [Hacktivitycon To Do & Reactor](https://lautarovculic.github.io/writeups/Hacktivitycon%202021%20-%20To%20Do%20%26%20Reactor/) | medium-hard | todo-state + reactor-timing → flag pair
- [Mystiko Kryptonite](https://lautarovculic.github.io/writeups/Mystiko%20-%20Kryptonite/) | hard | kryptonite-crypto: weakness-oracle → decrypt
- [AHE17 AESdecrypt](https://lautarovculic.github.io/writeups/AHE17%20-%20AESdecrypt/) | medium-hard | AES-lab: param recovery → offline decrypt
- [AHE17 Flag-Validator](https://lautarovculic.github.io/writeups/AHE17%20-%20Flag-Validator/) | medium-hard | validator-hook: check-function → return tamper
- [THC Android serial](https://lautarovculic.github.io/writeups/THC%20CTF%202018%20-%20Android%20serial/) | medium-hard | serial-gate: keygen reimpl → unlock
- [Ilam Android Reverse](https://lautarovculic.github.io/writeups/Ilam%20CTF%202018%20-%20Android%20Reverse/) | medium-hard | classic APK reversing: logic rebuild → flag

## Batch P — practice labs / cross-cutting research (fetched + extracted)

- [DIVA walkthrough (13-vuln survey)](https://geethna.github.io/posts/diva-app-walkthrough/) | medium | storage/SQL/WebView/access-control lab survey [PRACTICE]
- [DIVA MASTG (impersonation + file read)](https://jamarir.hashnode.dev/owasp-mastg-android-diva-damn-insecure-and-vulnerable-app) | medium-hard | Frida open/read impersonation + file-scheme WebView read [PRACTICE]
- [AndroGoat assessment](https://infosecwriteups.com/mobile-pentesting-androgoat-assessment-walkthrough-1a63a7edc677) | medium-hard | unprotected-components + WebView-file + root/pinning/biometric cluster [PRACTICE]
- [Storage exploitation handbook](https://wanderingbytes.github.io/mobile-pentest-handbook/04-storage.html) | medium-hard | sandbox map + MMKV/DataStore + snapshot-cache + severity model [RESEARCH]
- [HackTricks Flutter](https://hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/flutter.html) | hard | engine-hash→BoringSSL rebuild vs pattern-scan vs blutter object-pool [RESEARCH]
- [MASTG Flutter TECH-0109](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0109/) | medium | reFlutter vs iptables+TLS-disable decision tree [RESEARCH]
- [reFlutter how-to](https://github.com/kayodeao/Bypass-ssl-pinning) | medium | snapshot-hash + invisible-proxy resign flow [RESEARCH]
- [Flutter Firebase OTP intercept](https://hackmd.io/@michellenovenda/ryb-OAv-Ml) | hard | reFlutter + L3 VPN capture + SOCKS5 bridge + native-Firebase bypass rules
- [corCTF corphone (Android kernel LPE)](https://u1f383.github.io/android/2025/09/08/corCTF-2025-corphone.html) | hard | driver-UAF → page-UAF → security-hook patch → namespace-enter data read
- [DroidComp (WebView + AIDL)](https://bi0sblog-1271c6.gitlab.io/tags/Android/) | medium-hard | JS-bridge → service-channel mobile chain (tag page pointer)
- [cratecrack companion solve](https://github.com/s41nt0l3xus/CTF-writeups/tree/master/bi0sctf-2025/cratecrack) | hard | allocator-UAF JS heap-leak + signature-nonce crypto solve (companion to ctftime entry)
- [MHL Config Editor (medium series)](https://medium.com/@mehmetfarisacar/mobile-hacking-lab-config-editor-08793d462472) | medium | config-tamper lab chain

## Batch Q — residual verified sources (fetched + extracted)

- [frida_hook_libart (RegisterNatives kit)](https://github.com/lasting-yang/frida_hook_libart) | hard | libart hook + ArtMethod entry-point resolve + RegisterNative lookup [RESEARCH]
- [CodeShare trace-registernatives](https://codeshare.frida.re/@LAripping/trace-registernatives/) | medium | drop-in RegisterNatives tracer [RESEARCH]
- [Stripped-.so hook Q&A](https://stackoverflow.com/questions/58491568/how-do-you-hook-a-native-stripped-library-using-frida) | hard | FindClass+RegisterNatives intercept → fnPtr reveal → offset hook [RESEARCH]
- [ART JNI dynamic resolve](https://www.harvey-l.com/blog/resolve-jni-native-methods-dynamically/) | hard | ArtMethod RegisterNative entry-point + PrettyMethod resolve [RESEARCH]
- [RegisterNatives auto-hook pipeline](https://www.ctfiot.com/267644.html) | hard | dump bindings → signature-parse → generated Frida mass-hook [RESEARCH]
- [UnCrackable Lvl 1 (Irregular)](https://www.irregular25.in/posts/uncrackable-lvl-1/solution/) | medium | triple-check false + AES re-invoke confirm
- [Injured Android (lautaro index)](https://lautarovculic.github.io/writeups/Injured%20Android/) | medium-hard | flags 1/2/7/11/12/13 + file-provider closer (index copy)
- [HTB Instant (APK → API)](https://blog.bravosec.net/posts/HackTheBox-Writeup-Instant/) | medium-hard | APK token extract → arbitrary-file-read API → session-file decrypt pivot
- [HackingCamp MobileStore (order-SQLi)](https://thirtyseven.tistory.com/68) | medium | sort-param SQLi + case-mix WAF dodge → credential extract (companion piece)
- [iOS login binary-patch](https://medium.com/@rival.rvdt/revenge-binary-patching-ios-application-to-bypass-login-16e0989d7dd1) | medium-hard | iOS auth-branch patch → login bypass
- [MAS iOS crackmes index](https://mas.owasp.org/crackmes/iOS/) | medium | L1 string-hunt + L2 anti-tamper pair [RESEARCH-index]
- [MAS crackmes root index](https://mas.owasp.org/crackmes/) | medium | UnCrackable program map [RESEARCH-index]
- [MAS Android crackmes (L1-L3)](https://mas.owasp.org/crackmes/Android/) | medium-hard | root + native + maps-scan Frida ladder with linked solutions [RESEARCH-index]
- [MASTG DIVA app page](https://mas.owasp.org/MASTG/apps/android/MASTG-APP-0007/) | medium | 13-challenge lab map [RESEARCH-index]
- [DIVA part 1 (storage/SQLi)](https://medium.com/@sudobro/diva-beta-android-app-walkthrough-4b0f114aa74) | medium | prefs/SQL/temp-file stores + SQLi gate [PRACTICE]
- [Juicy Bar Frida trio](https://ad2001.com/blog/frida) | medium | return-read + field-set + UUID-spoof hook trio
- [APKey obfuscated key-rebuild](https://www.mfumis.com/posts/apkey-writeup/) | medium | fragmented-string AES rebuild + onClick force-decrypt hook
- [Misaki Xamarin part (XALZ)](https://misakikata.github.io/2022/09/HTB-Challenges-Mobile/) | hard | bundled-build XALZ assemblies → C# decrypt reimpl + smali gate-strip
- [NepCTF clickmemore (anti-debug)](https://www.cnblogs.com/wgf4242/p/18622079) | medium-hard | debugger-check hooks + counter-field tamper to threshold
- [Firebase-APK bounty case](https://medium.com/@secshubhamsharma/bug-hunting-101-the-firebase-misconfig-that-earned-me-a-bounty-dd600cef8ade) | medium | APK strings.xml URL → dotjson read + scanner-tooling notes [RESEARCH]
- [CyCTF Andoroido (dex + pkg-spoof)](https://justahmed.github.io/ctf/Android-CyCTF-2024-Finals/) | hard | exported url-extra → downloadDex → hosted-dex execute + ActivityThread package-name spoof
- [Android physical-attack surface](https://hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/android-physical-attacks.html) | hard | Gatekeeper/Keymaster/Weaver/StrongBox auth-bound-key model [RESEARCH]
- [MHL Secure Notes (medium series)](https://medium.com/@mehmetfarisacar/mobile-hacking-lab-secure-notes-82ef0e89b7bd) | medium | secure-notes lab chain
- [MHL Post Board WebView (medium series)](https://medium.com/@mehmetfarisacar/mobile-hacking-lab-post-board-webview-156a613cd67a) | medium | WebView board lab chain
- [MHL NoteKeeper overflow (medium series)](https://medium.com/@mehmetfarisacar/mobile-hacking-lab-notekeeper-buffer-overflow-4d6150c7cacc) | medium-hard | native note-buffer overflow lab
- [MHL IoT Connect (medium series)](https://medium.com/@mehmetfarisacar/mobile-hacking-lab-iot-connect-7d949715f0a7) | medium | IoT-companion API lab chain
- [MHL Guess Me (medium series)](https://medium.com/@mehmetfarisacar/mobile-hacking-lab-guess-me-ec76fedfa270) | medium | deep-link lab chain (5th source)
- [MHL Food Store (medium series)](https://medium.com/@mehmetfarisacar/mobile-hacking-lab-food-store-e487e40c6b79) | medium | store-logic lab chain
- [MHL Document Viewer (medium series)](https://medium.com/@mehmetfarisacar/mobile-hacking-lab-document-viewer-fc0b0be13c57) | medium | file-viewer path lab chain
- [MHL Cyclic Scanner (medium series)](https://medium.com/@mehmetfarisacar/mobile-hacking-lab-cyclic-scanner-9dcdb34975c9) | medium | scanner-oracle lab chain
- [CyCTF Grand Theft Mobile (memory-dump)](https://emp3r0r10.github.io/ctf-writeups/CyCTF_2025_Quals-Mobile_Writeups/) | hard | AES-decoy → native broadcast + memory-dump flag read
- [CyCTF Vault Raider (3-part reimpl)](https://emp3r0r10.github.io/ctf-writeups/CyCTF_2025_Quals-Mobile_Writeups/) | hard | device-ID + native-part + resource-XOR → master-key reimpl chain
- [CyCTF GTM (broadcast hook)](https://medium.com/@z0km/cyctf-2025-all-telecom-security-mobile-challenges-writeups-quals-finals-de05c84685fc) | hard | putExtra flag-hook + lib disasm chain (3rd source)
- [CyCTF Vault Raider (static path)](https://medium.com/@z0km/cyctf-2025-all-telecom-security-mobile-challenges-writeups-quals-finals-de05c84685fc) | hard | hash/XOR/native part-join static chain (3rd source)
