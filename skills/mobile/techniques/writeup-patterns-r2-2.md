# Mobile Writeup-Distilled Patterns R2-2 (W42..W52)

Companion to `skills/mobile/SKILL.md` → `## Writeup-Distilled Patterns R2`.
Technique-only. Package/class names are placeholders (`com.example.ctf`).

## Index

| ID | Pattern | Primary source writeups |
|---|---|---|
| W42 | DenyList→Shamiko→SUSFS hide ladder | magisk-vs-kernelsu, susfs, Zygisk-Assistant |
| W43 | virt-apex tmpfs detach + enforcing restore | hide-virt-apex-su, KernelSU-Next guide |
| W44 | Play Integrity client-gate-only rule | TrickyStore, PlayIntegrityFix, Shark, detector |
| W45 | RootBeer battery per-check pairing | Securify bypass, root-2025 notes, DEMO-0087/0088 |
| W46 | Embedded-NoSQL (Couchbase) read | NoSQolarly ×2 |
| W47 | fwrite-on-unlink capture | Apkocalypse, FrenchYeti fs-hook |
| W48 | res/raw firmware + XML password carve | Cyberchaze Firmware, Secure Catalog APK |
| W49 | Janus V1-signature APK splice | APKey Janus, car-apps Janus finding |
| W50 | wxapkg unpack + subpackage trap | wxappUnpacker, huan-cdm kit, kanxue thread |
| W51 | WebView bridge → service channel | DroidComp full post, MASTG-DEMO-0031 |
| W52 | HarmonyOS HAP/ABC triage | dayu, ReArk, abcde |

---

## W42 — DenyList→Shamiko→SUSFS hide ladder (Magisk/KernelSU)

Recognition: app detects `su`, manager packages, Zygisk traces, or props;
simple hide toggles fail one tier at a time.
Steps: (1) map which tier fires (file/mount/process/prop); (2) climb the
ladder: DenyList per-app → Shamiko-style Zygisk hide → kernel-level SUS-FS
hide for KernelSU; (3) verify per-tier with a detector app before touching
the target; (4) keep bootloader/verified-boot state consistent with the story
told to the app.
Pitfalls: mixing managers (Magisk + KernelSU modules conflict); hiding the
manager but leaving module mounts visible.
Sources: https://github.com/OutrageousStorm/android-root-methods/blob/main/docs/magisk-vs-kernelsu.md ·
https://github.com/CKMagisk/ksu_module_susfs ·
https://github.com/snake-4/Zygisk-Assistant

## W43 — virt-apex tmpfs detach + enforcing restore

Recognition: RootBeer-style `su`-on-PATH checks fire even with denylists,
ZygiskNext, and passing attestation — a tmpfs stacked over an APEX bin dir
carries a lone `su` into every app's PATH.
Steps: (1) confirm via zygote `mountinfo` (stacked tmpfs over the APEX bin);
(2) detach the stacked layers inside zygote mount namespaces (leave init's
namespace alone); (3) restore SELinux enforcing if the exploit left it
permissive; (4) re-run the detector (PATH walk + `which su` must come clean).
Pitfalls: full reboot may lose exploit-based roots — prefer soft reboot after
installing the fix; cleaning the wrong namespace breaks the root stack.
Sources: https://github.com/serkenn/hide-virt-apex-su ·
https://gist.github.com/TheUnrealZaka/042040a1700ad869d54e781507a9ba4f

## W44 — Play Integrity client-gate-only rule (keybox era)

Recognition: app gates on `MEETS_STRONG/DEVICE` verdicts; hardware-backed
signals enforced (May-2025 baseline); keybox-spoofing stacks in play.
Steps: (1) read the verdict tier the client actually enforces; (2) hook ONLY
the client-side gate for CTF purposes (verdict parsing / gate boolean);
(3) treat server-side verdict verification as a hard stop → hand off
(operator/web-ctf), never burn real keyboxes; (4) document tier
(BASIC vs DEVICE vs STRONG) in the writeup.
Pitfalls: confusing a client-displayed verdict with a server-enforced one;
chasing STRONG on an emulator (architecturally out of reach).
Sources: https://github.com/5ec1cff/TrickyStore/blob/release/SECURITY.md ·
https://github.com/Bradford1040/PlayIntegrityFix ·
https://github.com/Anthropicdaddy/Shark/blob/main/docs/platform-abuse/play-integrity.md ·
https://github.com/IR0NBYTE/playIntegrityFixDetector

## W45 — RootBeer battery per-check pairing

Recognition: app runs a labelled battery of checks (files, packages, `su`
execution, build tags, props, SELinux, ROM) and shows per-check results.
Steps: (1) decompile and pair each UI label with its check method;
(2) bypass checks one by one with narrow Frida hooks (fail-closed → false);
(3) re-run and confirm all labels flip; (4) keep the bypass minimal — blanket
hooks trip integrity counters.
Pitfalls: popular codeshare scripts fail on custom batteries — always read the
battery first; version-conditional checks (SDK-gated selinux/seccomp) need
per-branch handling.
Sources: https://medium.com/@mazin.ahmed.business/android-root-detection-bypass-using-frida-writeup-1-85994a28ced2 ·
https://medium.com/@AhmadSopyan/how-to-bypass-root-detection-with-frida-dbb59aa9704b ·
https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0087/MASTG-DEMO-0087/

## W46 — Embedded-NoSQL (Couchbase Lite) read

Recognition: `run-as` file walk shows a `.cblite2` dir; JWT/token-shaped
strings hit inside `db.sqlite3-wal`, not in prefs or plain sqlite.
Steps: (1) `run-as` + grep for token prefix to locate the store;
(2) pull BOTH `db.sqlite3` and `db.sqlite3-wal` (WAL holds uncommitted rows);
(3) `strings` the WAL for the token; (4) treat the token's claims as the next
key (e.g. AES-GCM key field) per the app's own use.
Pitfalls: pulling only the main DB file (WAL has the goods); token rotation
mid-chain — re-pull before the decrypt step.
Sources: https://medium.com/@sensosamwel63/mobile-hacking-conference-ctf-4b4851289f81 ·
https://github.com/deriv-security/ctf-writeups/blob/main/2026/Mobile-Hacking-Conference-CTF/android/NoSQolarly/README.md

## W47 — fwrite-on-unlink capture (deleted-file exfil)

Recognition: native code writes the secret to a file and immediately unlinks
it; UI shows a crash/toast when the flagged action runs.
Steps: (1) bypass the entry gate (root check) to reach the trigger;
(2) hook `fwrite` (libc) and log `(ptr, size)` buffers at call time;
(3) fire the trigger; read the captured bytes from the hook log — never from
disk (the file is gone).
Snippet (concept): `fwrite` onEnter → `Memory.readUtf8String(args[0], size)`.
Pitfalls: hooking the wrong libc symbol variant; the app may crash after the
write — capture first, debug second.
Sources: https://pentest.bi0s.in/blog/posts/l3ak-ctf-apkocalypse/ ·
https://codeshare.frida.re/@FrenchYeti/android-file-system-access-hook/

## W48 — res/raw firmware + XML password carve

Recognition: APK carries a `res/raw` blob (firmware/update image) plus a
password-looking string in `strings.xml`; blob extracts as an archive or ELF.
Steps: (1) export the raw blob from jadx; (2) `file` it, then try archive
extract with the XML string as password; (3) if it is an ELF, run `strings`
(or execute in a sandbox for `file`-confirmed executables); (4) watch for
overlapped/sequential writes hiding a second stage.
Pitfalls: assuming the blob is opaque data — always `file` it; password may
be split across resources (grep the whole `res/` tree).
Sources: https://pentest.bi0s.in/blog/posts/cyberchaze-ctf-firmware/ ·
https://pentest.bi0s.in/blog/posts/cyberchaze-ctf-secure-catalog-apk/

## W49 — Janus V1-signature APK splice

Recognition: APK signed with the v1 (JAR) scheme only; runs on an old API
level; goal is code change without invalidating the install signature.
Steps: (1) confirm v1-only signing; (2) splice modified DEX bytes into the
APK (Janus-tolerant prefix area); (3) strip/neutralize the target gate in
smali; (4) install on a vulnerable API level and trigger.
Pitfalls: v2/APK-Signature-Scheme blocks the splice — verify scheme first;
modern devices ignore v1-only quirks (match the target API level).
Sources: https://medium.com/@gbahenrijoel/hackthebox-mobile-apkey-e1dd0d434aeb ·
https://www.researchgate.net/publication/349630201_A_Multi-Tier_Security_Analysis_of_Official_Car_Management_Apps_for_Android

## W50 — wxapkg unpack + subpackage trap

Recognition: target logic lives in a super-app mini-program (`.wxapkg`);
direct unpack yields partial sources; "missing files" notices appear.
Steps: (1) pull the package from the app's pkg dir via adb;
(2) unpack + restore (config/JS/WXML/WXSS splitters);
(3) on subpackage notices, trigger the in-app routes that download the
subpackages, then unpack those too; (4) map JS bridges/endpoints from the
restored sources.
Pitfalls: unpacking dependency bundles instead of the real mini-program
(size heuristic: the real one is the small one); version drift breaks
restorers — pin the restorer to the client version.
Sources: https://github.com/cqg21/wxappUnpacker ·
https://github.com/huan-cdm/Wechat-small-program-decompile ·
https://bbs.kanxue.com/thread-281804.htm

## W51 — WebView bridge → service channel (super-app seam)

Recognition: JS-bridge-exposed app where Java hooks see nothing; a bound
service consumes bridge-passed data (AIDL-style channel).
Steps: (1) enumerate bridge interfaces from the WebView layer;
(2) trace bridge input into the service call; (3) drive the bridge directly
(console or crafted page) with probe payloads; (4) read the service-side
effect (file/flag/provider row).
Pitfalls: testing the WebView alone (the bug is in the service trust);
missing the bridge registration (dynamic `addJavascriptInterface`).
Sources: https://bi0sblog-1271c6.gitlab.io/2023/01/25/Misc/bi0sCTF22-DroidComp/ ·
https://mas.owasp.org/MASTG/demos/android/MASVS-PLATFORM/MASTG-DEMO-0031/MASTG-DEMO-0031/

## W52 — HarmonyOS HAP/ABC triage (Ark bytecode)

Recognition: `.hap`/`.app` package with `.abc` (Ark bytecode) modules;
Android tooling (jadx/apktool) yields nothing.
Steps: (1) list package structure (modules, resources, signatures);
(2) disassemble ABC (`ark_disasm`-family) to Panda Assembly;
(3) parse classes/methods/strings, follow xrefs to the flag logic;
(4) attempt experimental decompile for logic-dense methods; verify by
re-running the decode, not by guessing.
Pitfalls: ABC-version vs tool mismatch (garbage disasm — never patch blind);
resource-index indirection hides string literals (resolve via the index).
Sources: https://github.com/hx1997/dayu ·
https://github.com/lkimuk/ReArk ·
https://github.com/Yricky/abcde
