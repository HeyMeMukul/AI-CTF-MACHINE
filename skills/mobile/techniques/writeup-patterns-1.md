# Mobile Writeup-Distilled Patterns — full notes (W1..W30)

Companion to `skills/mobile/SKILL.md` → `## Writeup-Distilled Patterns`.
Technique-only. Package/class names below are placeholders (`com.example.ctf`).

## Index

| ID | Pattern | Primary source writeups |
|---|---|---|
| W1 | RegisterNatives census + auto-hook codegen | TFCCTF-2025 rev, 网鼎杯 rev01, awesomeFrida |
| W2 | PLT-hook exfil (strcmp-family) | FreakyFrida, Androbro-intended |
| W3 | Smali-injected helper .so | FreakyFrida |
| W4 | Broadcast/putExtra interception | GTM, TFCCTF-2025, Magic Snowfall |
| W5 | Two-stage AES-decoy → native-real-flag | GTM, Vault Raider |
| W6 | Flutter blutter → pool → cond-patch | Brod & Co, CyberSharing |
| W7 | reflutter traffic-mode resign chain | OwnApp v2, Fly Away 1 |
| W8 | BoringSSL verifier offset-from-export | Minded, NVISO ×2, SensePost |
| W9 | Rustls verifier patch | librust pinning |
| W10 | DER-swap rebuild (TrustManager) | HTB Pinned |
| W11 | Hermes compare-opcode flip + repack | Herald ×3 |
| W12 | hermes-decomp xref → bridge target | so-AIRMES |
| W13 | Xamarin XALZ → managed decompile | SeeTheSharpFlag ×3 |
| W14 | Godot PCK recover (+ encrypted key) | Buggy Jumper ×4, THCon PCK |
| W15 | IL2CPP metadata/body + bridge trace | Fla(g)ppy Bird, XYCTF, 强网just |
| W16 | Chaquopy .imy → matched decompile | Braincalc |
| W17 | Cordova www deobfuscate + console-run | Cold Storage ×2 |
| W18 | UE4 lib + SDK-dump + sim-exec | Tencent ACE/qu强网 UE4 |
| W19 | White-box AES DFA via fault | GGBomb white-box |
| W20 | EncryptedSharedPreferences re-create | CTRL_Alt_Frida |
| W21 | YAML/deser gadget via external file | PwnSec Snake |
| W22 | Firebase anon-auth + AppCheck exchange | FAM, VaultPass v2, FireStorm |
| W23 | Firestore client-filter strip | Notely AI |
| W24 | Swift aggregator triple-bypass | No Escape ×5 |
| W25 | RASP-aggregator replace + dylib hide | Captain No Hook ×2 |
| W26 | Swift string-memory read | FridaInTheMiddle |
| W27 | DownloadDex + package-name spoof | Andoroido |
| W28 | PoC-app + intent-scheme/Parcelable chains | Senoparty, Lookdown, Sparrow, Kage, Catchit |
| W29 | Overlay replica input capture | Hijacker, SAW |
| W30 | Commercial-protector decrypt-hook | DexGuard profile, Armor |

---

## W1 — RegisterNatives census + auto-hook codegen

Recognition: `nm -D` shows only `JNI_OnLoad`; jadx shows `native` methods with no
`Java_*` export; loader `.so` present.
Steps: (1) spawn app with a RegisterNatives hook that logs
`{class, name, sig, fnPtr, module, offset}`; (2) dump list to file; (3) generate
one Frida hook per entry (parse JNI sig → arg printers); (4) re-run and read I/O.
Commands:

```bash
frida -U -f com.example.ctf -l hook_RegisterNatives.js --no-pause
# hook script: enumerate libart symbols matching RegisterNatives (skip CheckJNI),
# walk JNINativeMethod triples, resolve module+offset via Process.findModuleByAddress
```

Pitfalls: ART-version symbol-name drift (match substring, not exact); spawn-vs-attach
timing (loader may register before attach → prefer spawn); 32/64-bit pointer sizes.
Sources: https://www.ccsl.carleton.ca/~mhossein/posts/tfcctf-2025-0.html ·
https://www.cnblogs.com/helica/p/13174980.html ·
https://github.com/bigsinger/awesomeFrida/blob/main/FridaForAndroid/part9/sections/9.2.md

## W2 — PLT-hook exfil instead of breaking anti-tamper

Recognition: dual `.so` design (worker + guardian); spawn dies under Frida but
repackaged app runs; `strcmp`/`memcmp` on hot path.
Steps: (1) confirm comparison primitive in Ghidra; (2) build tiny helper `.so`
whose constructor PLT-hooks the comparator to log both inputs then call through;
(3) smali-inject `loadLibrary("helper")` + trigger call; (4) rebuild/resign/run,
read logcat.
Pitfalls: PLT vs lazy-binding (hook after first call resolves); keep original
semantics (log-then-call-through) or app state diverges; arch-matched toolchain.
Sources: https://www.ztz0.com/writeups/2025/pwnsec/mobile/freakyfrida/ ·
https://pwnthem0le.polito.it/2025/07/12/L3akCTF-2025-Androbro-writeup/

## W3 — Smali-injected helper .so (loader shim)

Recognition: need code execution inside target process but Frida is killed;
apktool round-trip works.
Steps: (1) `apktool d`; (2) insert `System.loadLibrary("helper")` after existing
loads in the target class static-init/onCreate smali; (3) add trigger call if the
flag path never runs; (4) drop compiled `libhelper.so` per-ABI into `lib/`;
(5) `apktool b`, zipalign, sign, install.
Pitfalls: ABI dir must match device; `loadLibrary` order matters (helper after
target lib); Clang NDK `APP_ABI` per-folder; signature change breaks nothing
except server-pinned cert checks.
Sources: https://www.ztz0.com/writeups/2025/pwnsec/mobile/freakyfrida/

## W4 — Broadcast/putExtra interception

Recognition: `sendBroadcast`/`setResult` near flag assembly; receiver with
action + extras in manifest; logcat flag-shaped lines after UI tap.
Steps: (1) hook `ContextWrapper.sendBroadcast` (and `sendOrderedBroadcast`)
filtering on action/extra key; (2) bypass the UI gate (direct native/method call);
(3) trigger from UI; (4) read intercepted extra.
Snippet:

```javascript
Java.perform(function () {
    var C = Java.use("android.content.ContextWrapper");
    C.sendBroadcast.overload('android.content.Intent').implementation = function (i) {
        try { console.log("[*] action=" + i.getAction() + " extra=" + i.getStringExtra("flag")); } catch (e) {}
        return this.sendBroadcast(i);
    };
});
```

Pitfalls: overload variants (2-arg, permission-gated); sticky vs ordered delivery;
receiver may need the real broadcast to proceed — call through, don't swallow.
Sources: https://medium.com/@ahmed-alnajjar/cyctf-gtm-challenge-from-aes-decoy-to-jni-broadcast-2a5bd3c7a328 ·
https://www.ccsl.carleton.ca/~mhossein/posts/tfcctf-2025-0.html ·
https://kore.one/nahamcon-winter-2025-ctf-magic-snowfall-challenge-writeup/

## W5 — Two-stage AES-decoy → native-real-flag

Recognition: first decrypt yields a plausible-but-wrongly-formatted secret; a
`native` method consumes the "unlocked" state and emits the real artifact.
Steps: (1) solve stage 1 statically (key + algorithm from jadx); (2) do NOT stop
at stage-1 output — trace where the success branch calls into native; (3) treat
stage 1 as a gate-key, hook/bypass it, intercept the native emission (W4/W1).
Pitfalls: format-prefix check too early (decoy matches prefix loosely); native
may re-derive rather than store — capture at emission, not at rest.
Sources: https://medium.com/@ahmed-alnajjar/cyctf-gtm-challenge-from-aes-decoy-to-jni-broadcast-2a5bd3c7a328 ·
https://emp3r0r10.github.io/ctf-writeups/CyCTF_2025_Quals-Mobile_Writeups/

## W6 — Flutter blutter → object-pool → cond-patch

Recognition: `libapp.so` + `libflutter.so`; jadx shows shell only.
Steps: (1) `strings libapp.so` triage; (2) run blutter → `asm/` + `pp.txt`;
(3) grep pool for magic constants/URLs; (4) import names into IDA/Ghidra;
(5) find compare on magic value; (6) flip cond (`B.NE`→`B.EQ` etc. per-ISA);
(7) repack/resign/trigger via deep link.
Pitfalls: engine-version/blutter mismatch (check snapshot hash); Thumb vs ARM64
encodings for cond flip; patched lib breaks page-alignment → re-zipalign.
Sources: https://ymuu.me/posts/brod--co--android-ctf-write-up---brunnerctf-2025/ ·
https://kos0ng.gitbook.io/ctfs/write-up/2024/1337up-live-ctf/mobile

## W7 — reflutter traffic-mode resign chain

Recognition: Flutter app with backend traffic; Java hooks see nothing.
Steps: (1) `reflutter app.apk` → traffic mode → enter Burp IP; (2) zipalign +
uber-apk-signer resign; (3) Burp listener `*:8083` + invisible proxying;
(4) install, trigger flagged screen, read plaintext.
Pitfalls: engine-hash unsupported → fall back to W8; native (non-Dart) stacks
(e.g. Firebase) are NOT patched by reflutter — split-route them direct (W8 note).
Sources: https://darkpills.com/breizhctf-2024-mobile-ownapp-and-web-popup-creator-write-ups/ ·
https://maulvialf.medium.com/nahamcon-ctf-2024-writeup-mobile-category-713b19da447e

## W8 — BoringSSL verifier offset-from-export hook

Recognition: reflutter unsupported hash; need no-repack intercept.
Steps: (1) pull matching-ABI `libflutter.so`; (2) find verifier: xref
`ssl_client`+`ssl_server` strings → single 3-arg candidate, or scalar-search the
error-line constant; (3) offset = `func − image_base`; (4) Frida
`base+offset`, `onLeave: retval.replace(0x1)`; (5) route traffic (iptables/VPN).
Pitfalls: per-build/per-arch offsets (never reuse); scan-crash on x86_64 →
prefer offset method; hook after linker loads lib (watch dlopen).
Sources: https://blog.mindedsecurity.com/2024/05/bypassing-certificate-pinning-on.html ·
https://blog.nviso.eu/2019/08/13/intercepting-traffic-from-android-flutter-applications/ ·
https://sensepost.com/blog/2025/intercepting-https-communication-in-flutter-going-full-hardcore-mode-with-frida/

## W9 — Rustls verifier patch

Recognition: `librust.so` in APK; Flutter/Java bypasses change nothing; Burp
shows TLS errors only for Rust-driven endpoints.
Steps: (1) identify `verify_server_cert` (build app locally with `--no-strip`
if source available, else string-xref); (2) patch/hook to return success;
(3) trigger load of the Rust path (explore app until `.so` maps); (4) confirm
plaintext in proxy.
Pitfalls: stripped builds need pattern work per-version; library loads lazily —
hook late or watch dlopen.
Sources: https://medium.com/@0x1r1s/bypassing-librust-so-ssl-pinning-6fcd96362fcc

## W10 — DER-swap rebuild for TrustManager pinning

Recognition: `res/raw/*.der|.crt` + `TrustManagerFactory`/`SSLContext` in jadx.
Steps: (1) export Burp CA in DER; (2) `apktool d`, replace the pinned file
(same name/format); (3) `apktool b`, align, sign, reinstall; (4) proxy works
with zero hooks.
Pitfalls: filename/format must match loader; SHA-checks elsewhere defeat this →
fall back to hook; `usesCleartextTraffic`/API-level side notes.
Sources: https://medium.com/@brian.nuwagaba.ludovic/unpinning-pinned-hack-the-box-android-challenge-22cd6a945948

## W11 — Hermes compare-opcode flip + repack

Recognition: `assets/index.android.bundle`, Hermes magic; login/compare in bundle.
Steps: (1) confirm bytecode version; (2) disassemble with version-matched tool
(hbcdump/hbctool fork); (3) find auth function; (4) flip compare opcode byte
(`JStrictEqual`↔`JStrictNotEqual`); (5) reassemble/repack/resign; (6) login
with known-user + anything.
Pitfalls: version mismatch = garbage disasm (never patch blind); opcode table
differs per version — verify byte against that version's table.
Sources: https://ctftime.org/writeup/32238 ·
https://github.com/Pusty/writeups/tree/master/InsomnihackTeaser2022 ·
https://sahua.ng/posts/insomnihack-teaser-2022/

## W12 — hermes-decomp xref → bridge-target workflow

Recognition: 10k-function bundle; JS is UI shell; native module holds secret.
Steps: (1) `decompile` + `extract` (Metro modules) + string dump; (2) `xref`
interesting strings (bridge names, error text); (3) read the calling module to
learn the native entry + expected prefix/format; (4) pivot to JNI `.so` (W1).
Pitfalls: generator/async state machines misread — follow yields; string-table
only (don't read bundled deps); version coverage of tool vs bundle.
Sources: https://labs.symbioticsec.ai/hubfs/PDF%20Downloads/CTF%20Writeup%20so-AIRMES.pdf

## W13 — Xamarin XALZ → managed decompile

Recognition: jadx shows no logic + `unknown/assemblies` blobs; challenge hints
at C#/.NET.
Steps: (1) extract assemblies; (2) header-check for XALZ vs PE; (3) run
xamarin-decompress; (4) open in dnSpy/dotPeek/ILSpy; (5) read key/IV + decrypt
call; (6) reimpl decrypt offline.
Pitfalls: bundled builds pack DLLs into `.so` (need XamAsmUnZ-style split
first); all DLLs must be decompressed together for repack; align+sign after edit.
Sources: https://medium.com/@3ed0x92/seethesharpflag-8aeee35ef7ec ·
https://medium.com/@68abdelrahmanmohamed/htb-seethesharpflag-mobile-6d16e94eeaca ·
https://misakikata.github.io/2022/09/HTB-Challenges-Mobile/

## W14 — Godot PCK recover (+ encrypted key)

Recognition: `libgodot` + `assets/scripts/*.gdc` or `.pck` inside APK.
Steps: (1) feed APK to gdsdecomp/GDRE (`--recover`); (2) if encrypted: break on
the engine's pack-error string in debugger, dump `script_encryption_key`;
(3) set key in tool, extract project; (4) read game scripts; server-chained
sequels: follow register→save→verify endpoints with engine UA.
Pitfalls: tool-vs-engine version match; key-length padding quirks; score/state
files as alternate tamper path.
Sources: https://blog.ikuamike.io/posts/2024/nahamcon_ctf_2024_mobile/ ·
https://hackmd.io/@avila-pwn-notes/r183kzlEA ·
https://ctftime.org/writeup/39048

## W15 — IL2CPP metadata/body decrypt + bridge trace

Recognition: `libil2cpp.so` + `global-metadata.dat`; dumpers fail (shuffled
header / encrypted body / UPX).
Steps: (1) unpack UPX if present; (2a) runtime route: frida-il2cpp-bridge
`Il2Cpp.dump()` + class/method `trace()` to capture names, args, key/iv;
(2b) static route: reverse the loader's decrypt, restore header, run
Il2CppDumper + IDA struct script; (3) hook guarded APIs (image-integrity) via
enumerator-hook or direct-struct walk; (4) keep paired state consistent when
writing game values.
Pitfalls: dumped `.so` needs ELF repair before IDA; metadata offsets shift —
rebase IDA to dump base; anti-hook that blesses callers (hook the bless, W15-note).
Sources: https://www.ztz0.com/writeups/2025/intechfest-quals/rev/flagppy_bird/ ·
https://sechub.in/view/2874612 ·
https://cn-sec.com/archives/4618085.html

## W16 — Chaquopy .imy → matched decompile

Recognition: thin Java + `assets/chaquopy/*.imy`; logic in Python.
Steps: (1) treat `.imy` as zip; extract `.pyc`; (2) check magic → exact Python
version; (3) use a decompiler supporting that version (legacy tools fail on
3.12+); (4) read flag logic; dynamic play is usually a dead end.
Pitfalls: version mismatch = "unsupported" errors (tool hunt, not code bug);
verify by re-running decode, not by playing the game.
Sources: https://medium.com/@kyoungminroh01/l3akctf-2025-writeup-braincalc-mobile-22ef696c05b8

## W17 — Cordova www deobfuscate + console-run

Recognition: `assets/www` + `cordova.js`; MainActivity nearly empty; Frida on
Java sees nothing.
Steps: (1) read `index.html` → find JS entry (`keygen.js` etc.); (2) deobfuscate
(obf-io style) or paste into console; (3) call `keygen()`-style functions
directly with breakpoints to trace transforms (affine/XOR/reorder);
(4) reimplement or replay output.
Pitfalls: PIN-gate in HTML is separate from key derivation — read both;
Keystore-flavored sequels need native-side work (don't force Cordova path).
Sources: https://ctftime.org/writeup/39671 ·
https://medium.com/@ahmadshamius2/my-attempt-at-1337up-ctf-40f385bed06f

## W18 — UE4 lib + SDK-dump + sim-exec deobfuscation

Recognition: `libUE4.so`; frida-server port probed; password-check native.
Steps: (1) inject via repacked gadget (port-probe dodge: forward to other
port); (2) dump SDK (tuned dumper + live-memory offsets); (3) NOP anti-debug
stubs; (4) for branch-mixed checkers: Unicorn-trace both sides of IT-block
dispatches, rebuild cond-jumps (Keystone), re-analyze.
Pitfalls: anti-debug kills process persistently (reboot device after trip);
dump-then-repair ELF before IDA; verify with live hook, not just static.
Sources: http://www.yxfzedu.com/article/10506 ·
https://sgsgsama.github.io/ctf/Android/%E8%85%BE%E8%AE%AF%E6%B8%B8%E6%88%8F%E5%AE%89%E5%85%A82023%E5%AE%89%E5%8D%93%E5%88%9D%E8%B5%9B/

## W19 — White-box AES DFA via state-fault injection

Recognition: `WBACR*`/`EncryptOneBlock`-shaped exports; key never materializes;
10-round structure with state buffers.
Steps: (1) active-call the encrypt entry with fixed input; (2) trace round
counter to find pre-final-round state address; (3) `Memory.writeByteArray`
single-byte faults across runs, capture faulty ciphertexts; (4) run DFA solver
for round key; (5) schedule-recover master key.
Pitfalls: fault the wrong round → unsolvable set (verify round count first);
state address shifts per call — capture per-invocation, don't hardcode.
Sources: https://www.cnblogs.com/GGbomb/p/18621516

## W20 — EncryptedSharedPreferences re-create + read

Recognition: `androidx.security.crypto` usage; prefs file unreadable; master key
in Keystore (non-exportable by design).
Steps: (1) read create() params (file name, key/value schemes) from decompile;
(2) in Frida: build same `MasterKey` (default alias) + same schemes;
(3) `EncryptedSharedPreferences.create(ctx, sameFile, ...)`; (4) `getString`
the key. Never carve memory for the key — use the API boundary.
Pitfalls: file-name/scheme mismatch → empty read (copy exactly); upload-script
constraints (obfuscated class names differ server-side — enumerate, don't hardcode).
Sources: https://jctf.team/writeups/AppSec-IL-2025/CTRL_Alt_Frida/

## W21 — YAML/deserialization gadget via external file

Recognition: external-storage file read + `snakeyaml`/deserialization lib +
logcat "file not found" hint + intent extra steering into loader.
Steps: (1) bypass device/root gates (smali patch) since hooks are watched;
(2) craft gadget payload instantiating the flag-printing class with magic arg;
(3) place file at expected path; (4) fire steering intent via adb; (5) logcat read.
Pitfalls: vulnerable-lib version matters (gadget availability); path/permissions
exact; Frida may be off-limits — static + adb only.
Sources: https://medium.com/@Handoumeh/pwnsec-ctf-2024-mobile-1b373affd69b ·
https://lautarovculic.github.io/writeups/PwnSec%20CTF%202024%20-%20Snake/

## W22 — Firebase anon-auth + AppCheck-debug-token exchange

Recognition: `firebaseio.com`/`firebasedatabase.app` URLs + API key in
`strings.xml`; `/.json` → denied; `signInAnonymously`/debug-token code present.
Steps: (1) `GET <db>/.json` (public probe); (2) Identity-Toolkit `signUp`
(anonymous) → `idToken`; (3) retry with `?auth=`; (4) Firestore/AppCheck tier:
extract debug token (often weakly hidden in `.so`), exchange at AppCheck
endpoint, call with `Authorization: Bearer` + `X-Firebase-AppCheck`.
Pitfalls: API key is public-by-design (not the bug); rules like `auth != null`
are the bug — report rule, not key; token expiry → re-mint mid-chain.
Sources: https://exploitnotes.hashnode.dev/fam-ctf-the-library-to-the-endpoint-writeup ·
https://infosecwriteups.com/breaking-the-kpmg-ctf-2025-hardest-mobile-challenge-a-deep-dive-into-vaultpass-v2-94bb61f409fb ·
https://lautarovculic.github.io/writeups/PwnSec%20CTF%202024%20-%20FireStorm/

## W23 — Firestore client-filter strip

Recognition: iOS app querying a notes-like collection with client-side
`whereField:isEqualTo:` filters; backend returns only filtered rows.
Steps: (1) hide instrumentation (port/path/thread/dylib — W25 ladder);
(2) replace the query-builder IMP: force archive-like flag true, drop
owner/uid clauses, pass the rest through; (3) read returned rows.
Pitfalls: method-signature match for IMP replace must be exact; filters may be
re-applied server-side — verify row counts before/after.
Sources: https://engbaselabutaleb.com/blog/14-ios-notely-ai-challenge-by-mobile-hacking-lab

## W24 — Swift aggregator triple-bypass (hook / patch / debugger)

Recognition: single `isJailbroken`-style Swift aggregator called from 2+
sites; generic tools fail; internal (non-exported) symbol.
Steps — pick one: (a) Frida: base+offset `onLeave retval.replace(0)` (resolve
real module name first — spaces included); (b) patch: overwrite prologue with
`mov w0,#0; ret`, resign/reinstall; (c) LLDB: break at `ret`, `register write
x0 0` at EVERY hit (aggregator runs per call site).
Pitfalls: hooking by name fails (internal symbol — use offset); one flip is not
enough when two call sites each invoke it; ASLR → recompute base each launch.
Sources: https://0xbartita.com/blog/mhl-02-no-escape ·
https://ymuu.me/posts/mobilehackinglab-ios-challenges-writeups/challenge-02---no-escape/ ·
https://karim-moftah.github.io/posts/No-Escape/

## W25 — RASP-aggregator replace + injected-dylib hide (iOS)

Recognition: `FailedCheck`-style enum + checker class (`*ReverseEngineering*`);
port/file/DYLD/sysctl/ptrace battery; Frida dies at spawn.
Steps: (1) enumerate symbols (frida-trace) for check names; (2)
`Interceptor.replace` each aggregator with `NativeCallback → 0`;
(3) hide injection: `_dyld_get_image_name` return-filter, thread-name mask,
`connect`-port block, path-probe fail; (4) hook UI trigger → read label tree.
Pitfalls: replace (not attach) for aggregators to win races; narrow filters only
(blanket libc zeroing crashes the app); spawn-early for launch-time checks.
Sources: https://incogbyte.github.io/posts/captain-no-hook-mobilehackinglabs/ ·
https://nasrsec.com/blog/mobile/mobilehackinglab-captainnohook-ios/

## W26 — Swift string-memory read

Recognition: hooked Swift function fires but `x0/x1` show metadata, not text.
Steps: (1) break at function; (2) read register holding string ref; (3) apply
large-string layout (+metadata offset) then `x/s`; (4) confirm prefix bytes.
Pitfalls: small-vs-large string layouts differ — if garbage, try the other;
don't confuse the boolean in `x0` with the payload register.
Sources: https://www.cylentsec.com/blog/2025/12/13/8ksec-FridaInTheMiddle-CTF/ ·
https://blog.reversesociety.co/blog/2025/8ksec-ios-ctf-writeup

## W27 — DownloadDex + package-name spoof

Recognition: exported activity takes URL extra → downloads dex → DexClassLoader
`execute` → package-name equality gate.
Steps: (1) send intent with attacker URL serving crafted dex; (2) dex payload
rewrites `ActivityThread.mBoundApplication.info.mPackageName` via
`currentActivityThread()` singleton (avoid `this`); (3) single-dex build
(`multiDexEnabled false`); (4) host + trigger.
Pitfalls: classloader-context `this` trap; multidex splits the payload;
package check may run before/after execute — order accordingly.
Sources: https://justahmed.github.io/ctf/Android-CyCTF-2024-Finals/

## W28 — PoC-app + intent-scheme/Parcelable escalation chains

Recognition: exported WebView/activity + unexported consumer; provider with
`grantUriPermissions`; `Intent.parseUri` bridges; Finals-style PoC-submit model.
Shapes: (a) exported→unexported forward with crafted extras; (b) `intent://`
payload through a JS bridge to reach non-exported components; (c) Parcelable
inner-intent to cross the export boundary; (d) implicit-intent (PICK) intercept
returning attacker URI with grant flags; (e) deep-link → file-path with
allowFileAccess WebView.
Pitfalls: result-code/flag exactness (e.g. grant-flag bit, expected resultCode);
chooser-order for implicit intents; WebView filter bypass via encoding/case.
Sources: https://callmeks.github.io/posts/icsctf-senoparty/ ·
https://medium.com/@5h3nron/lookdown-challenge-from-tcp1p-a-step-by-step-guide-3ed20e9ec385 ·
https://medium.com/@z0km/cyctf-2025-all-telecom-security-mobile-challenges-writeups-quals-finals-de05c84685fc

## W29 — Overlay replica input capture

Recognition: PIN/password gate with accessibility/overlay abuse surface;
`TYPE_APPLICATION_OVERLAY` capability.
Steps: (1) build replica layout of the gate screen; (2) draw over target
(permission flow); (3) collect input per-button; (4) submit captured value to
real gate (server or local).
Pitfalls: overlay permission UX (guide the tap flow); focus flags so target
still receives its own events where needed; newer APIs restrict overlays.
Sources: https://xk0m1.github.io/2024/08/30/Sekai-CTF-2024/ ·
https://callmeks.github.io/posts/htb-saw/

## W30 — Commercial-protector decrypt-hook

Recognition: protectors (DexGuard-family/jiagu-style): string/class encryption,
per-build polymorphism, native pinning + early root/debug/emulator checks.
Steps: (1) identify decryptor class (string-xref to encoded blobs);
(2) hook decryptor → dump plaintexts (URLs/keys); (3) combined early-spawn
bypass (kill-block + prop-spoof + file-access block + port-hide);
(4) frida-dexdump after full init for class-encrypted builds; (5) OpenSSL-level
hook as pinning backstop (covers Java+BoringSSL+custom).
Pitfalls: per-build polymorphism — re-analyze each build, never reuse class
names; cracked-vs-licensed strength gap changes effort estimate; dump timing
must be post-init.
Sources: https://www.awakewiki.org/packers/dexguard/ ·
https://justahmed.github.io/ctf/Android-CyCTF-2024-Finals/
