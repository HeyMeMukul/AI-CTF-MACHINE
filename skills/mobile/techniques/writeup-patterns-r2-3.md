# Mobile Writeup-Distilled Patterns R2-3 (W53..W62)

Companion to `skills/mobile/SKILL.md` → `## Writeup-Distilled Patterns R2`.
Technique-only. Package/class names are placeholders (`com.example.ctf`).

## Index

| ID | Pattern | Primary source writeups |
|---|---|---|
| W53 | AAOS companion + BLE oracle (+ stray-device triage) | BLE Theft Auto ×2, car-apps paper, AutoComply |
| W54 | RIL-mirror baseband-command RE | BaseMirror ×2, UNISOC re-host |
| W55 | TrollStore-adjacent sideload reasoning | TrollStore repo + wiki |
| W56 | Dyld image-count clamp + ipsw triage | zhaoxuya iOS guide, 8kSec ipsw ×2 |
| W57 | ObjC swizzle-order duel | mrmacete observer, interference hooks, zhaoxuya |
| W58 | Plist/closure-string crypto hunt (Apple bundle) | Cryptohorrific plist, Flower App bundle |
| W59 | Flutter hash-mismatch fallback chain | 8kSec Flutter, fahad combo, licitrasimone |
| W60 | Native-TLS route split (OkHttp/Rustls/BoringSSL) | abhirampatel bundle, segura2010, owen800q |
| W61 | Engine-asset exfil (Godot PCK + Unity rip) | DUCTF godot, Kashi G1/G3 |
| W62 | Debuggable run-as collapse | SekaiID ×2, NoSQolarly run-as |

---

## W53 — AAOS companion + BLE oracle (+ stray-device triage)

Recognition: car/ companion app with BLE pairing, proprietary app-layer
protocol over BLE, or an AAOS head-unit APK (car-service permissions, VHAL
surface). Wear/TV strays: `leanback` manifest features, watch-face
complication providers.
Steps: (1) decompile the companion app (watch for non-Java BLE stacks —
e.g. a .NET DLL inside the APK); (2) audit the app-layer protocol for
hardcoded creds, weak key exchange, and unauthenticated commands;
(3) for AAOS APKs, map car-service permissions + VHAL/SELinux-ioctl boundary;
(4) strays: confirm `leanback`/`watch` features, then run the standard
manifest→deeplink→provider triage (the platform differs, the bugs repeat).
Pitfalls: testing BLE pairing crypto instead of the app-layer protocol (the
bugs live above pairing); confusing Android Auto (phone-projected) with AAOS
(full-stack IVI) surfaces.
Sources: https://www.usenix.org/system/files/usenixsecurity26-yu-jerry.pdf ·
https://www.usenix.org/conference/usenixsecurity26/yu-jerry ·
https://www.researchgate.net/publication/349630201_A_Multi-Tier_Security_Analysis_of_Official_Car_Management_Apps_for_Android ·
https://arxiv.org/html/2503.04003

## W54 — RIL-mirror baseband-command RE (AP↔CP oracle)

Recognition: puzzle hints at modem/RIL/baseband; vendor RIL `.so` in
firmware; AT/QMI/MBN traffic near the flag path.
Steps: (1) skip the baseband firmware — target the vendor RIL library (the
AP-side mirror of CP commands); (2) recover command constructors
statically (tame virtual-call-heavy graphs first); (3) replay/inspect
commands at the RIL boundary with Frida; (4) for unlock-style puzzles,
follow the ADB/provisioning side-channel (serial-derived keys, procfs
loaders) before touching the modem.
Pitfalls: diving straight into baseband firmware (order of magnitude
harder); trusting unauthenticated on-device tracepoint libraries blindly.
Sources: https://arxiv.org/html/2409.00475v1 ·
https://dl.acm.org/doi/pdf/10.1145/3658644.3690254 ·
https://arxiv.org/pdf/2608.07143v1

## W55 — TrollStore-adjacent sideload reasoning

Recognition: iOS challenge hinging on install/signature mechanics
(permasign, entitlements, System-vs-User app state) rather than app logic.
Steps: (1) identify the signature primitive (multi-signer CoreTrust quirk
vs modern lockdown); (2) track app state across icon-cache reloads
(System→User reverts); (3) use a persistence helper inside a real system app
to re-register state; (4) verify launchability after every reload cycle.
Pitfalls: assuming install == launchable (FrontBoard re-checks at launch);
fighting the version matrix (14.0–17.0 only for the classic bug).
Sources: https://github.com/opa334/TrollStore ·
https://github.com/opa334/TrollStore/wiki

## W56 — Dyld image-count clamp + ipsw triage

Recognition: jailbreak/dyld-injection checks count loaded images; analysis
needs a decrypted IPA + dyld-shared-cache context.
Steps: (1) dump/decrypt the app binary; (2) enumerate loaded images and clamp
the count API to a sane value in the hook; (3) triage with ipsw-style
dyldcache + framework listings to resolve private symbols;
(4) confirm ObjC/Swift boundaries before hooking (W57).
Pitfalls: clamping too low breaks the loader (pick a plausible count);
dumping before the closure cache settles yields stale images.
Sources: https://github.com/zhaoxuya520/reverse-skill/blob/main/skills/mobile-reverse/references/ios-reverse-guide.md ·
https://8ksec.io/ipsw-walkthrough-part-1-the-swiss-army-knife-for-ios-macos-security-research/ ·
https://8ksec.io/ipsw-walkthrough-part-2-the-swiss-army-knife-for-ios-macos-security-research/

## W57 — ObjC swizzle-order duel

Recognition: app detects method-swizzling (IMP comparison) or races hook
installation; generic hooks get evicted.
Steps: (1) enumerate classes/methods statically (class-dump path);
(2) observe with an ObjC method observer (arg/return + stacktrace) before
writing the bypass; (3) win the order duel: hook earlier (spawn) or replace
the aggregator outright instead of attaching; (4) re-verify IMPs after each
app update (selectors shift).
Pitfalls: attaching where replace is needed (loses the race); observing with
the same tool the app detects (ladder W38/W41 first on iOS equivalents).
Sources: https://codeshare.frida.re/@mrmacete/objc-method-observer/ ·
https://codeshare.frida.re/@interference-security/ios-app-all-classes-methods-hooks/ ·
https://github.com/zhaoxuya520/reverse-skill/blob/main/skills/mobile-reverse/references/ios-reverse-guide.md

## W58 — Plist/closure-string crypto hunt (Apple bundle)

Recognition: iOS/macOS bundle where the secret hides in `plist`/closure
caches or bundle resources rather than code.
Steps: (1) convert plists to XML and hunt for high-entropy strings;
(2) map each blob to its consumer (which screen/key reads it);
(3) recover the transform statically (Base64 → key → decrypt) instead of
fighting the UI; (4) Apple-bundle crossover: same flow works for macOS
`.app` targets (Mach-O + plist surface).
Pitfalls: stopping at the first plausible string (decoys live in plists too);
ignoring the closure-cache copy (stale vs live values).
Sources: https://medium.com/@gbahenrijoel/hackthebox-mobile-cryptohorrific-d22aa45c2301 ·
https://github.com/xbr01/Mobile-CTF-Challenges/blob/main/BlockCTF%202024/Flower%20App/Write-Up.md

## W59 — Flutter hash-mismatch fallback chain

Recognition: Flutter app; engine snapshot hash unsupported by patchers;
per-endpoint stacks differ (Dart vs Rust vs platform).
Steps: (1) try traffic-mode resign first (fastest win);
(2) on hash mismatch, switch to verifier offset-from-export hooking
(per-build offsets, never reused); (3) for DIO/Rust-driven endpoints, patch
at the native verify function (pattern-scan per arch); (4) combine with an
anti-root bypass so the app runs proxied on a rooted device.
Pitfalls: one bypass for all endpoints (route-split first); reusing offsets
across builds (always recompute).
Sources: https://8ksec.io/securing-flutter-applications/ ·
https://codeshare.frida.re/@fahad-source/frida-combined-bypass--anti-root--flutter-tls-pinning/ ·
https://codeshare.frida.re/@licitrasimone/flutter-ssl-pinning-bypass/

## W60 — Native-TLS route split (OkHttp3 / Rustls / BoringSSL)

Recognition: mixed networking stacks; Java unpinning fixes some endpoints
while others stay dark (Rust/Native TLS).
Steps: (1) attribute each endpoint to its stack (OkHttp3 interceptor log vs
native TLS trace); (2) bypass per stack: OkHttp3 pin + TrustManager hooks,
Rustls verifier patch, BoringSSL offset hook; (3) confirm plaintext per
endpoint in the proxy (no partial credit — every stack must be covered).
Pitfalls: declaring victory after the Java endpoints decrypt; stripped Rust
builds need per-version pattern work.
Sources: https://github.com/abhirampatel/frida-android-scripts ·
https://codeshare.frida.re/@segura2010/android-certificate-pinning-bypass/ ·
https://codeshare.frida.re/@owen800q/okhttp3-interceptor/

## W61 — Engine-asset exfil (Godot PCK + Unity rip)

Recognition: game-engine mobile/game target; logic clean in code, secret in
assets (`.pck` scenes, Unity asset bundles, audio files).
Steps: (1) identify the engine (Godot PCK magic / Unity bundle layout);
(2) extract with version-matched tools (gdsdecomp for PCK, AssetRipper for
Unity); (3) read scripts/scenes first (flag often sits in a script line);
(4) for media assets, try non-obvious decodings (spectrogram, geometry).
Pitfalls: tool↔engine version mismatch (garbage output — match first);
playing the game instead of reading the assets.
Sources: https://seall.dev/writeups/25-ductf-godot/ ·
https://seall.dev/writeups/25-kashi-game1untitledgame/ ·
https://seall.dev/writeups/25-kashi-game3catseabank/

## W62 — Debuggable run-as collapse (ship-the-debug-build)

Recognition: two-app IPC puzzle (badge/verifier, wallet/scanner) with an
exported-provider/intent chain — but manifests ship `debuggable="true"`.
Steps: (1) ALWAYS check `debuggable` + file ownership before walking the
intended IPC chain; (2) `run-as <pkg>` straight to the flag file when the
UID matches; (3) only if non-debuggable, walk the intended chain
(intent redirect → provider grant → claims forgery); (4) same shortcut
applies to embedded-NoSQL stores (W46) via `run-as` file pull.
Pitfalls: burning hours on the intended IPC chain before the 5-second
manifest check; assuming store builds match debug builds (verify the
shipped artifact).
Sources: https://github.com/Abdelkad3r/cybersecurityelite.com/blob/main/content/ctf-writeups/sekai-ctf-2026-writeup.md ·
https://github.com/Abdelkad3r/SekaiCTF-2026/tree/main/misc/sekaiid ·
https://medium.com/@sensosamwel63/mobile-hacking-conference-ctf-4b4851289f81
