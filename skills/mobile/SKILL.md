---
name: mobile
description: Android and iOS CTF triage to exploit via static, dynamic, and pinning-bypass playbooks
category: mobile
phase: 1-3
---
Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`; separate evidence from inference, preserve scope, validate each link, and label uncertainty.

# Mobile CTF Skill

## Mental Model

Mobile CTFs are app-reversing puzzles with a platform wrapper. The flag
path is almost always one of six shapes:

1. **Hardcoded secret** — key, URL, or flag string in `classes.dex`,
   `strings.xml`, native `.so`, or `Info.plist`. Solved by static grep.
2. **Exported component** — activity/service/receiver/provider reachable
   via intent or deep link without auth. Solved by manifest reading +
   `adb am` launch.
3. **Weak crypto / storage** — AES with hardcoded IV, Base64-"encrypted"
   prefs, world-readable files, `adb backup` exfil. Solved by re-implement.
4. **Runtime check to bypass** — root/emulator/debugger detection, cert
   pinning, or license check. Solved by Frida hook or smali patch.
5. **Backend API abuse** — hardcoded endpoint + token; the app is a client
   and the bug is server-side. Pivot to `web-ctf`.
6. **Cross-platform bundle** — Flutter (`libapp.so`) or React-Native
   (Hermes bundle) hiding logic outside Java/ObjC. Solved by bundle dump.

Default hypothesis order: manifest + strings (60s) → decompile + grep
→ exported-component probe → dynamic hook → backend pivot. Static solves
most; dynamic is for crypto/keystore and pinning only.

Scope guard: technique-only, no real flags. Analyze provided APK/IPA only.
Emulator + `adb` on your own host; never attack store apps or real users.
Frida scripts hook the challenge app's crypto and auth checks — standard
CTF practice, not malware.

## Workflow

### Phase 1 — Baseline (APK/IPA triage, ≤120s, read-only)

Goal: file inventory, manifest surface, and fastest static path.

Steps:

1. Record hash/size; confirm APK (zip) vs IPA vs raw dex.
2. `apktool d` (resources/smali) + `jadx` (Java) in parallel-safe
   read-only outputs to separate dirs.
3. Read `AndroidManifest.xml`: package, permissions, `debuggable`,
   `allowBackup`, exported components, deep-link schemes.
4. `strings classes.dex` sweep: flag format, `http`, keys, `AES`, `secret`.
5. iOS branch: unzip IPA, read `Info.plist`, list frameworks/dylibs.

Commands:

```bash
sha256sum app.apk; file app.apk
apktool d app.apk -o out_apktool 2>&1 | tail -n 5
jadx -d out_jadx app.apk 2>&1 | tail -n 5
grep -Ei 'debuggable|allowBackup|exported|uses-permission|scheme|host' out_apktool/AndroidManifest.xml | head -n 30
unzip -p app.apk classes.dex | strings -n 8 | grep -Ei -m 20 'flag\{|http|api[_-]?key|secret|password|aes' | head -n 20
ls out_apktool/lib/ out_apktool/assets/ 2>/dev/null
find out_apktool -name '*.so' | head -n 10
```

iOS branch:

```bash
unzip -l app.ipa | head -n 40
unzip -q app.ipa -d out_ipa
find out_ipa -name 'Info.plist' | head -n 5
plutil -p out_ipa/Payload/*.app/Info.plist 2>/dev/null | head -n 80
ls out_ipa/Payload/*.app/ | head -n 40
strings -n 8 out_ipa/Payload/*.app/* 2>/dev/null | grep -Ei -m 20 'flag|http|api[_-]?key|secret' | head -n 20
```

Flutter / React-Native detection:

```bash
ls out_apktool/lib/*/libapp.so out_apktool/lib/*/libflutter.so 2>/dev/null
find out_jadx -iname '*flutter*' | head -n 10
ls out_apktool/assets/ | grep -Ei 'hermes|index.android|jsbundle' | head -n 10
unzip -l app.apk | grep -Ei 'libapp|libflutter|hermes|jsbundle' | head -n 10
```

`Reasoning Checkpoint`: manifest surface + strings hits + bundle type →
route (static secret vs exported component vs native vs bundle vs iOS) →
next phase input.

### Phase 2 — Confirmation (static confirm, no patching yet)

Goal: confirm the exact class/method/file holding the secret or check.

Steps:

1. Grep decompiled Java for crypto, auth, and network sinks.
2. Read the flagged method fully ( jadx output beats smali for logic).
3. Cross-check smali only when patching is planned.
4. For native: `strings` + `file` the `.so`, list JNI exports.
5. For iOS: class-dump concept — list classes/methods statically; confirm
   with Frida only in the gated phase.

Commands:

```bash
grep -rHn -m 30 'AES\|Cipher\|SecretKey\|IvParameter\|KeyStore' out_jadx/sources/ | head -n 30
grep -rHn -m 20 'HttpURLConnection\|OkHttp\|Retrofit' out_jadx/sources/ | head -n 20
grep -rHn -m 20 'root\|emulator\|isDebugged\|pinning\|CertificatePinner' out_jadx/sources/ | head -n 20
grep -rHn 'android:exported' out_apktool/AndroidManifest.xml | head -n 20
cat out_apktool/res/values/strings.xml 2>/dev/null | head -n 40
file out_apktool/lib/*/*.so 2>/dev/null | head -n 10
strings -n 8 out_apktool/lib/*/*.so 2>/dev/null | grep -Ei -m 15 'flag|key|aes' | head -n 15
```

Deep-link + backup/debuggable surface (same pass):

```bash
grep -B2 -A6 'intent-filter' out_apktool/AndroidManifest.xml | head -n 50
grep -Hn 'allowBackup\|debuggable\|usesCleartextTraffic' out_apktool/AndroidManifest.xml
aapt dump badging app.apk 2>/dev/null | head -n 20
```

`Reasoning Checkpoint`: exact class/method/sink quoted (file:line) +
static verdict (hardcoded key vs check-to-hook vs backend URL) → negative
testing.

### Phase 3 — Negative (rule out before emulator time)

Goal: kill the hypotheses that burn the most wall-clock.

Checks:

1. **Not obfuscated beyond grep?** If `jadx` output is single-letter
   classes with string encryption, plain `strings` still works on dex —
   confirm a dex-level hit before declaring defeat.
2. **Not server-side?** Hardcoded `https://` + bearer token with no local
   flag logic means the bug is backend — pivot to `web-ctf`, stop
   reversing the client.
3. **Not Flutter/Hermes?** `libapp.so` present means Java grep is the
   wrong layer — switch to bundle dump, do not keep reading smali.
4. **Emulator needed?** If static already yields key + algorithm,
   re-implement offline instead of booting an emulator.

Commands:

```bash
unzip -p app.apk classes.dex | strings -n 8 | wc -l
unzip -p app.apk classes.dex | strings -n 8 | grep -cEi 'http|aes|cipher|flag'
ls out_jadx/sources/ | head -n 20
grep -rHn -m 5 'a\.b\.c\|o0OO0O\|stringDecrypt\|DexGuard\|ProGuard' out_jadx/sources/ | head -n 10
grep -rHn -m 10 'https\?://' out_jadx/sources/ | head -n 10
adb devices 2>&1 | head -n 5
emulator -list-avds 2>&1 | head -n 10
```

`Reasoning Checkpoint`: dead layers with evidence (obfuscation level,
backend-vs-local verdict, bundle type, emulator need) → single live
hypothesis into gated dynamic step.

### Phase 4 — Exploit (GATED: one dynamic step, ≤120s)

Gate: one bounded action against your own emulator/device. Then stop and
evaluate. One corrected retry → one alternate → `blocked`.

Pick exactly ONE:

**A. Launch exported component (safe, local):**

```bash
adb install -r app.apk 2>&1 | tail -n 3
adb shell dumpsys package com.example.ctf | grep -A2 -i 'activity\|service\|provider' | head -n 30
adb shell am start -n com.example.ctf/.FlagActivity 2>&1 | head -n 10
adb shell am start -a android.intent.action.VIEW -d 'ctf://flag' 2>&1 | head -n 10
adb logcat -d | grep -Ei -m 20 'flag|exception|ctf' | head -n 20
```

**B. Frida hook crypto/auth (own emulator, challenge app only):**

```bash
frida-ps -U 2>&1 | head -n 20
frida -U -f com.example.ctf -l hook_crypto.js --no-pause 2>&1 | head -n 40
adb logcat -d | grep -Ei -m 20 'decrypted|key|iv|flag' | head -n 20
```

**C. Backup exfil (if `allowBackup=true`):**

```bash
adb backup -f /tmp/opencode/app.ab -noapk com.example.ctf 2>&1 | head -n 3
dd if=/tmp/opencode/app.ab bs=24 skip=1 2>/dev/null | openssl zlib -d > /tmp/opencode/app.tar
tar -tf /tmp/opencode/app.tar 2>/dev/null | head -n 20
```

**D. Patch + rebuild (offline, then reinstall):**

```bash
apktool b out_apktool -o patched.apk 2>&1 | tail -n 5
apksigner sign --ks /tmp/opencode/debug.keystore --out patched-signed.apk patched.apk 2>&1 | head -n 5
adb install -r patched-signed.apk 2>&1 | tail -n 3
```

Stop condition: one artifact (flag log line, decrypted file, bypassed
check). Never parallelize installs/hooks against the same emulator.

`Reasoning Checkpoint`: gated action + observed output (logcat line,
file, bypass) → verdict (success → validation; else retry/alternate/
blocked).

### Phase 5 — Validation-handoff (prove it, package it)

Goal: reproducible steps + finding bundle for Lead.

Steps:

1. Re-run the winning step once (deterministic reinstall/re-hook).
2. Capture: exact `adb` command or Frida script + logcat excerpt.
3. Record package name, version, component, and tool versions.
4. Write `results/mob_<id>/` bundle; never paste real flags into hosted
   models.

Commands:

```bash
adb logcat -d | grep -Ei -m 5 'flag' > results/mob_flag_evidence.txt
cp hook_crypto.js results/mob_hook.js 2>/dev/null
sha256sum app.apk > results/mob_hash.txt
```

`Reasoning Checkpoint`: evidence → reproducible steps → handoff
(finding bundle + backend pivot note if server-side).

## Tool Table (exact copy-paste commands)

| Task | Command |
|---|---|
| Decode resources+smali | `apktool d app.apk -o out_apktool` |
| Rebuild APK | `apktool b out_apktool -o patched.apk` |
| Decompile to Java | `jadx -d out_jadx app.apk` |
| Dex only, no res | `jadx -d out_jadx --no-res classes.dex` |
| Single class | `jadx --single-class com.example.Flag out_jadx app.apk` |
| List APK contents | `unzip -l app.apk` |
| Dex strings | `unzip -p app.apk classes.dex \| strings -n 8 \| grep -Ei -m 20 'flag\|http\|aes'` |
| Manifest badging | `aapt dump badging app.apk` |
| Manifest XML | `cat out_apktool/AndroidManifest.xml` |
| Devices | `adb devices` |
| Install | `adb install -r app.apk` |
| Logcat | `adb logcat -d \| grep -Ei -m 20 'flag\|exception'` |
| Clear logcat | `adb logcat -c` |
| Dump package | `adb shell dumpsys package com.example.ctf` |
| Backup | `adb backup -f app.ab -noapk com.example.ctf` |
| Frida list | `frida-ps -U` |
| Frida hook | `frida -U -f com.example.ctf -l hook.js --no-pause` |
| Frida attach | `frida -U -n com.example.ctf -l hook.js` |
| Objection explore | `objection -g com.example.ctf explore` |
| Sign patched APK | `apksigner sign --ks debug.keystore --out signed.apk patched.apk` |
| Align APK | `zipalign -v 4 app.apk aligned.apk` |
| Native strings | `strings -n 8 lib/arm64-v8a/*.so \| grep -Ei -m 20 'flag\|key'` |
| iOS unzip | `unzip -q app.ipa -d out_ipa` |
| iOS plist | `plutil -p out_ipa/Payload/*.app/Info.plist` |
| Hermless check | `unzip -l app.apk \| grep -Ei 'hermes\|jsbundle\|libapp'` |

Objection concept: `objection -g <pkg> explore` gives a REPL for bypassing
SSL pinning, dumping keychain/prefs, and hooking without writing Frida
JS by hand. In CTFs it is a speed shortcut for the same hooks below.

## Code / Payload Library

### 1. Frida crypto hook (AES / Cipher / KeyStore)

```javascript
// hook_crypto.js — log AES keys, IVs, and plaintext (challenge app only)
Java.perform(function () {
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.doFinal.overload("[B").implementation = function (input) {
        console.log("[*] Cipher.doFinal len=" + (input ? input.length : 0));
        try { console.log("    algo=" + this.getAlgorithm()); } catch (e) {}
        var out = this.doFinal(input);
        console.log("    out(hex)=" + Java.use("java.util.Arrays").toString(out).slice(0, 200));
        return out;
    };
    var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
    SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function (key, algo) {
        console.log("[*] SecretKeySpec algo=" + algo + " keylen=" + key.length);
        return this.$init(key, algo);
    };
});
```

Run: `frida -U -f com.example.ctf -l hook_crypto.js --no-pause`

### 2. Pinning-bypass concept (OkHttp / TrustManager)

```javascript
// pinning_bypass.js — concept: neutralize common pinning checks
Java.perform(function () {
    try {
        var Pinner = Java.use("okhttp3.CertificatePinner");
        Pinner.check.overload("java.lang.String", "java.util.List").implementation = function () {
            console.log("[*] pinning check skipped");
            return;
        };
    } catch (e) { console.log("[-] no OkHttp3 pinner: " + e); }
    try {
        var TM = Java.use("javax.net.ssl.X509TrustManager");
        // implemented via dynamic proxy neutralizing checkServerTrusted
        console.log("[*] TrustManager class present, patch checkServerTrusted to no-op");
    } catch (e) { console.log("[-] no TrustManager hook: " + e); }
});
```

Note: exact overloads vary by OkHttp version — enumerate with
`Pinner.check.overloads` in the REPL first. Concept only; adapt to the
decompiled imports. Root/debug twin: hook the app's own
`isRooted/isEmulator/isDebugged` (names from Phase-2 grep) to return
`false`.

### 3. Re-implement weak crypto offline (no emulator needed)

```python
# reimpl.py — mirrors hardcoded AES/ECB or XOR from decompiled Java
from Crypto.Cipher import AES
import base64
key = b"HARDCODED_KEY_16B"   # copy exact bytes from jadx output
blob = base64.b64decode(open("cipher.txt").read().strip())
print(AES.new(key, AES.MODE_ECB).decrypt(blob))
```

### 4. Exported-provider read + deep-link fuzz sketches

```bash
adb shell dumpsys package com.example.ctf | grep -i provider | head -n 10
adb shell content query --uri content://com.example.ctf.flags/flags 2>&1 | head -n 10
for path in flag debug admin test; do
  adb shell am start -a android.intent.action.VIEW -d "ctf://$path" 2>&1 | head -n 2
done
adb logcat -d | grep -Ei -m 15 'flag|exception' | head -n 15
```

### 5. iOS plist + class-dump concept

```bash
plutil -p Payload/*.app/Info.plist | grep -Ei 'url|scheme|server|key' | head -n 15
frida-trace -U -m '*[* *auth*]' -a com.example.ctf 2>&1 | head -n 15
```

### 6. Flutter (`libapp.so`) + React-Native (Hermes) notes

Flutter release builds compile Dart to `libapp.so` — stop reading smali
once `libflutter.so` is confirmed. Try `strings libapp.so | grep -Ei
'flag|http|key'`; for logic, snapshot-dump tools (`blutter`/`reflutter`
concept) recover names for native-layer Frida hooks. Hermes bundles
(`index.android.bundle`, `*.hbc`) hold JS bytecode: extract, disassemble
with `hermesc`/`hbcdump` concept, `strings` first — CTF shortcuts often
survive compilation.

## Decision Tree

```text
apktool + jadx done, manifest read?
  exported=true activity/service/provider?
    YES -> adb am start / content query (gated) -> flag?
  strings has flag format / key / URL?
    key + Cipher.* -> re-implement offline (fastest)
    URL + token -> backend pivot (web-ctf)
  libapp.so / libflutter.so present?
    YES -> flutter path (strings libapp.so, snapshot dump concept)
  hermes/jsbundle present?
    YES -> hermes path (dump + strings)
  Cipher/KeyStore/pinning/root strings?
    YES -> frida hook (gated, one script)
  allowBackup=true?
    YES -> adb backup exfil (gated)
  debuggable=true?
    YES -> easier hook/debug (note for dynamic)
  IPA instead of APK?
    -> plist + strings + frida-trace path
  none hit -> re-read launcher activity fully (misread likely)
```

## AI Automation Notes

- Worker loop: decode → manifest → strings → sink grep → ONE gated
  dynamic step → logcat diff. Cap: 2 static passes + 1 dynamic, then
  `blocked` with sink list. One worker per emulator (shared `adb` state).
- Template matrix: `{exported-launch, deep-link, provider-query, backup,
  frida-crypto, frida-pinning, patch-rebuild}` × logcat diff; log each
  row's observed error.
- Unique artifacts: `results/mob_<id>/`. Stop: flag-pattern log line,
  decrypted secret, bypassed check, or 3 failed methods → `blocked`.
- OPSEC: provided binaries only; never paste real tokens/flags hosted.

## Advanced / Hard-Challenge Playbook

Hard mobile challenges hide logic one layer below the first static
pass: Java is a loader, real checks live in native code, packed DEX,
bundled runtimes (Flutter/Hermes), or OS-backed keys. Ordered by
frequency: JNI native, packers, anti-Frida, attestations, bundles,
Keystore/iOS. Technique-only; adapt names from Phase-2 grep.

### A1. Native-lib (JNI) reversing: symbols to Ghidra to Frida

When `lib/arm64-v8a/*.so` exists and Java holds thin `native`
declarations plus `System.loadLibrary`, the flag path is in C/C++.
Prefer `arm64-v8a`; list exports before opening Ghidra; decode
signatures before hooking.

Commands:

```bash
ls -R out_apktool/lib/ 2>/dev/null | head -n 20
nm -D out_apktool/lib/arm64-v8a/*.so 2>/dev/null | grep -Ei 'Java_|JNI_OnLoad|getFlag|check|decrypt|verify' | head -n 30
grep -rn 'loadLibrary\|native .*(' out_jadx/sources/ 2>/dev/null | head -n 20
strings -n 8 out_apktool/lib/arm64-v8a/*.so 2>/dev/null | grep -Ei -m 20 'flag|key|iv|aes|token|root|debug' | head -n 20
```

JNI signature decoding (dynamic-link naming rule):

```text
Java_<package_underscored>_<Class>_<method>
  args: (JNIEnv*, jobject/jclass, <declared Java args...>)
  static native  -> second arg is jclass; instance -> jobject (this)
```

Static-link case: no `Java_*` export exists. Hunt `JNI_OnLoad` plus
`RegisterNatives` call sites in Ghidra; the registration table holds
`{methodName, signature, fnPtr}` triples. Faster alternate: hook
`RegisterNatives` at runtime and log registered names/signatures.

Ghidra hygiene for `JNIEnv*` mess: define `JNIEnv`/`jstring` types,
rename `param_1` to `env` and `param_3` to the real input, retype
indirect calls (`GetStringUTFChars` etc.). Then look for the comparison
primitive: `memcmp`/`strcmp` vs decrypt output, length check, and any
early `check_root`-style gate forcing a decoy return. Shortcut: if an
exported helper returns the secret for a magic constant, call it
directly via `NativeFunction(addr, "pointer", [])` after bypassing the
gate — no full reversal needed.

`Reasoning Checkpoint`: export list + JNI signature + Ghidra function
name/offset quoted → verdict (direct-call candidate vs full-reversing
needed vs escalate to `/rev`) → next input.

### A2. DEX packers (Bangcle / ijiami concept): dump via Frida mem scan

Tells: `classes.dex` stub-only, packer `Application` subclass, asset
blobs, loader `.so` in `lib/`. Let the app self-unpack, then dump.

Concept order: confirm packer (stub dex, loader `.so`, logic absent
from jadx) → dex-magic dump at runtime → reload dumps in jadx →
resume Phase 2.

Commands:

```bash
unzip -p app.apk classes.dex | strings -n 8 | wc -l
unzip -l app.apk | grep -Ei 'secexe|secmain|ijiami|jiagu|legu|mobisec|libexec' | head -n 10
ls -la out_apktool/assets/ 2>/dev/null | head -n 20
```

Frida mem-scan dump concept (scan readable ranges for dex magic after
`onCreate`, delay 2-5s past loader init, write each hit to disk, pull
via `adb pull`, validate magic before jadx). Prefer ready dumpers by
concept (deep memory scan / ART DexFile walk) over hand-rolled scripts.
Attach-mode if spawn-mode dies early. If methods stay per-call
encrypted, exercise app screens then re-scan.

`Reasoning Checkpoint`: packer tells + dump count/sizes + jadx reload
result → verdict (unpacked → Phase 2; partial → exercise-then-rescan).

### A3. Anti-Frida bypasses: port check, maps scan, thread-name checks

Hard apps stack Frida fingerprints. Identify fired rows from
logcat/`strings`/smali, bypass narrowly one at a time.

| # | Check | How it detects | Bypass concept |
|---|---|---|---|
| 1 | TCP port probe | connects to default agent ports, parses `/proc/net/tcp` for listeners | run agent on non-default port; or hook connect/parse to hide it |
| 2 | `/proc/self/maps` scan | `strstr(maps, "frida-agent"/"gadget"/"linjector")` | hook `strstr`/`strstr`-family to return NULL for those needles only; or hook file-read to filter lines |
| 3 | File existence | `File.exists("/data/local/tmp/frida-server")`-style | rename agent binary/path on device; or hook exists/access to spoof |
| 4 | Named-pipe / fd scan | lists `/proc/self/fd`, matches pipe names | hook directory-listing or string-compare narrowly |
| 5 | Thread-name scan | reads `/proc/self/task/*/comm`, matches `gum-js-loop`/`gdbus`-style worker names | hook the read/compare; do NOT blanket-kill all thread enumeration |
| 6 | `ptrace(TRACEME)` self-attach | second tracer fails if already traced | hook `ptrace` in libc to return 0 without tracing |
| 7 | `TracerPid` check | parses `/proc/self/status` for non-zero tracer | hook the status read to report 0 |

Targeted bypass concept (challenge app only, apply only fired rows):
hook `strstr`-family to return NULL for Frida needles only, replace
`ptrace` to return 0, redirect `access` su-probes to a nonexistent
path. Narrow filters only — never blanket-zero libc calls.

Smali-patch alternative (offline, when hooks race the check): patch the
single aggregator (e.g. `detectFrida()`-style) to return `false`,
rebuild, resign, reinstall. Proof: agent on default path/port with
live worker threads, no kill-dialog on the previously-failing screen.

`Reasoning Checkpoint`: which checks fired (evidence line each) +
bypass applied per check + re-run result → verdict (clean run → resume
dump/hook; still dying → next fingerprint or escalate).

### A4. SafetyNet / Play-Integrity concept + test-device bypass

Concept: modern attestation moves the verdict off-device. The app
requests a signed verdict from platform services; the server decides.
Local hooks can only influence what the app *does with* a verdict, not
forge a genuine signed pass. In CTFs the challenge author must make the
flag reachable on a test device, so expect one of: (a) verdict is only
advisory and a client-side `if (verdictPass)` gates the flag — hookable;
(b) emulator image is allow-listed by the challenge harness; (c) a
debug/test flag disables attestation; (d) the check is stubbed to a
local mock. Strategy: grep attestation entry points, hook the client-side gate
(the boolean/enum the app branches on), never chase forging
server-signed tokens. If no local gate exists and the backend rejects
the test device, record evidence and escalate to operator.

```bash
grep -rHn -m 20 'SafetyNet\|PlayIntegrity\|IntegrityManager\|attest\|nonce\|verdict' out_jadx/sources/ | head -n 20
```

Test-device posture: stock emulator image at target API, correct clock
(nonce freshness), challenge network only; use harness allow-list if
documented.

`Reasoning Checkpoint`: attestation entry + gate location (file:line)
+ hook-or-harness path → verdict (client-gated → hook; server-gated →
operator/backend note, stop burning hook time).

### A5. Flutter (`libapp.so`, Dart snapshot strings)

Release Flutter compiles Dart AOT into `libapp.so` — jadx shows only
the shell. Order: `strings libapp.so` first, then snapshot tooling
(blutter-style parsers recover names + object-pool strings for
Ghidra/Frida), then the MethodChannel seam (hook/patch the Java plugin
side, not AOT math). Debug builds may ship `kernel_blob.bin` /
`isolate_snapshot_data` instead — parse those first.

```bash
ls out_apktool/lib/*/libapp.so out_apktool/lib/*/libflutter.so 2>/dev/null
strings -n 8 out_apktool/lib/arm64-v8a/libapp.so 2>/dev/null | grep -Ei -m 30 'flag|http|api|key|secret|token|aes' | head -n 30
```

Snapshot/tooling concept: snapshot-dump output feeds Ghidra symbol
import plus Frida target selection. The MethodChannel bridge is the
bypass seam — hook or smali-patch the Java side (see A3 alternative).

### A6. Hermes bytecode (`hbcdump` concept)

React-Native Hermes ships JS as bytecode (`index.android.bundle` /
`*.hbc` under `assets/`). Java is a thin bridge; logic is in the
bundle plus any native module it calls.

```bash
ls out_apktool/assets/ 2>/dev/null | head -n 20
unzip -l app.apk | grep -Ei 'index.android.bundle|\.hbc|hermes|jsbundle' | head -n 10
```

Concept pipeline: extract bundle → disassemble with a
version-matched Hermes disassembler (`hbcdump`-style / `hbctool`-style:
match the bundle's bytecode version exactly) → string-table dump →
cross-reference bridge names (`NativeModules.<Name>.<method>`) to
functions → trace into native `.so` (then A1). String-table-first beats
reading bundled dependencies; version-mismatch errors mean switching
tool builds, never patching the bundle.

`Reasoning Checkpoint`: bundle path + bytecode version + string hits +
bridge target → verdict (JS-only → patch/repack concept; bridge →
native A1).

### A7. Deep-link + intent hijack chains

Exported deep links and providers chain: enumerate → probe crafted
extras → logcat-diff → escalate to provider/file → gated component.

```bash
grep -B3 -A8 'intent-filter' out_apktool/AndroidManifest.xml | head -n 80
grep -rn 'getStringExtra\|getData\|getIntent\|DeepLink\|handleIntent' out_jadx/sources/ 2>/dev/null | head -n 20
```

Chain sketch (own emulator, challenge app only):

```bash
adb shell am start -a android.intent.action.VIEW -d 'ctf://flag' 2>&1 | head -n 5
adb shell am start -n <pkg>/.FlagActivity --es seed 'probe' 2>&1 | head -n 5
adb shell am broadcast -n <pkg>/.TicketReceiver --es seed 'probe' 2>&1 | head -n 5
adb shell content query --uri content://<pkg>.flags/flags 2>&1 | head -n 10
adb logcat -d | grep -Ei -m 20 'flag|exception|ctf|ticket|seed' | head -n 20
```

Chain sketch (own emulator, challenge app only): fire crafted link /
extras one at a time, diff logcat per attempt. Read the receiving
method fully first: accumulator transforms on extras, missing-extra
crashes leaking key names, `Toast`/`Log` sinks echoing state.

`Reasoning Checkpoint`: exported surface list + probe inputs tried +
logcat delta → verdict (direct reach vs transform-to-satisfy vs dead).

### A8. Keystore-backed key extraction limits (CAN vs CANNOT)

Android Keystore keys marked non-exportable never expose key material
to the app process — crypto happens in a system process / TEE /
StrongBox:

- CAN: use the key through its authorized API on the same device;
  hook plaintext/ciphertext at the API boundary; list aliases and
  backing level to prove hardware backing.
- CANNOT: export raw bytes for offline cracking when hardware-backed;
  move the key to another device. Do not carve memory for a StrongBox
  key — pivot to API-boundary hooking.

```bash
grep -rHn -m 20 'KeyStore\|KeyGenParameterSpec\|setIsStrongBoxBacked\|getSecurityLevel\|isInsideSecurityHardware\|SecretKey' out_jadx/sources/ | head -n 20
```

Frida posture: hook `Cipher.doFinal` / `Signature.sign` around the
alias use and log inputs/outputs — the plaintext is the prize, the key
stays put. Auth-gated with no harness auth → record gate, escalate.

`Reasoning Checkpoint`: alias + backing level + authorizations quoted
→ verdict (API-hook viable vs auth-gated → escalate).

### A9. iOS jailbreak-detection bypass concept

Same shape as Android root checks (file/scheme probes, dyld/debugger
checks). Bypass the exact fired predicate via Frida (own harness only).

```bash
strings -n 8 Payload/*.app/* 2>/dev/null | grep -Ei -m 20 'cydia|jailbreak|fork|ptrace|dyld|substrate' | head -n 20
```

`Reasoning Checkpoint`: fired iOS checks + bypass per check + clean
launch proof → verdict.

## Multi-Step Chains (Abstract Patterns)

Hard flags need 2-4 chained primitives. Each step's output is the next
step's input. Record the handoff value per step.

### Chain 1: apk to dex to native key to Frida hook to decrypt

Shape: Java holds ciphertext + loader; native `.so` holds or derives
the key; flag = decrypt(ciphertext, nativeKey).

1. Static: jadx locates ciphertext blob + `Cipher` call site
   (file:line); `.so` strings locate key labels; Ghidra confirms
   derivation.
2. Gated: Frida hooks the native key-return or `Cipher.doFinal` to
   capture exact runtime key/IV.
3. Offline: re-implement decrypt once with captured parameters.

Stop/branch: server-nonce-dependent key → Chain 2; hook killed → A3
first, then resume.

`Reasoning Checkpoint`: blob location + key source + captured params +
offline decrypt output → verdict.

### Chain 2: pinning to bypass to intercept to token

Shape: app pins TLS (OkHttp `CertificatePinner` / native
`SSLContext`-level check); flag or session token only appears in
proxied traffic.

1. Static: confirm pinning sink (enumerate version-specific
   overloads in REPL before hooking).
2. Gated: Java-layer bypass first; native `SSLContext` hook if no
   traffic change.
3. Intercept: local proxy, trigger flagged screen, capture token.
4. Pivot: token becomes `web-ctf` input or direct flag.

Stop/branch: no traffic delta after both hooks → pinning is not the
gate (re-baseline toward Chain 1).

`Reasoning Checkpoint`: pinning sink + bypass applied + intercepted
artifact → verdict.

### Chain 3: deep-link to provider to file to flag

Shape: exported deep link reaches an intermediate activity that writes
or exposes state consumed by a gated component.

1. Static: manifest chain (link → activity → provider authority).
2. Gated step 1: crafted link; confirm provider row / file / log.
3. Gated step 2: query provider / read file / launch gated component.
4. Validate: single replay script for both steps in order.

`Reasoning Checkpoint`: per-step artifact (log line, row, file) +
replay result → verdict.

## Failure-Mode Catalog + Recovery

Each entry: detection signal → recovery. One corrected retry, then
alternate, then `blocked` after 3 total.

| # | Failure | Detection | Recovery |
|---|---|---|---|
| F1 | jadx decompile fail / empty output | `sources/` empty or stub-only; dex strings near zero | smali + dex `strings`; treat as packer (A2), dump then re-decompile |
| F2 | Frida server ABI/version mismatch | attach errors mention protocol/version/ABI | match pair EXACTLY (version + arch); re-verify `frida-ps -U` |
| F3 | App detects emulator / refuses run | instant exit, `emulator/root detected` log | spoof props narrowly OR real test device; hook predicate to clean |
| F4 | Native stripped, no `Java_*` symbols | `nm -D` shows only `JNI_OnLoad` | hook `RegisterNatives` / read `JNI_OnLoad` table; xref string constants; call by offset |
| F5 | Pinning in native (Java bypass no-op) | no plaintext after Java hook | hook native TLS boundary (`SSLContext`-init / verify callback) |
| F6 | Killed at spawn (anti-Frida race) | spawn dies, attach survives | attach-mode + delayed hooks; A3 bypasses; smali-patch alternate |
| F7 | Flutter `libapp.so`, jadx barren | `libflutter.so`+`libapp.so` present | stop Java grep; `strings libapp.so` → snapshot tooling → channel seam (A5) |
| F8 | Hermes version mismatch | deserializer expected-vs-got error | switch disassembler build to bundle's exact version (A6) |

Quick triage for the catalog:

```bash
ls out_jadx/sources/ 2>/dev/null | head -n 5; unzip -p app.apk classes.dex | strings -n 8 | wc -l
frida --version; adb shell getprop ro.product.cpu.abi
nm -D out_apktool/lib/arm64-v8a/*.so 2>/dev/null | head -n 10
```

`Reasoning Checkpoint`: failure observed + row (F1-F8) + recovery
tried + outcome → retry / alternate / `blocked`.

## Version-Drift Guards

Mobile toolchains drift fast; pin before a hard run:

- Frida pair pinning: record host `frida`/`frida-tools`, device
  `frida-server`, arch in `results/mob_<id>/tool_versions.txt`.
  Minor mismatches fail — never "close enough".
- apktool/jadx flag drift: re-check `--help` on the run host; store
  exact working command lines.
- Android API changes: backup availability, `allowBackup`/exported
  defaults, cleartext, scoped storage, StrongBox vary by API. Note
  targetSdk + device API; silent no-ops suggest API gating first.
- Bundle versions: Hermes bytecode, Dart/Flutter engine, and parser
  builds must match the sample. Record all three.
- Ghidra/JDK drift: note both versions; `JNIEnv` packs and decompiler
  output shift across releases.

`Reasoning Checkpoint`: pinned versions recorded + API levels noted →
proceed; any unpinned upgrade mid-run → re-verify pair before blaming
the challenge.

## Time-Budget Tiers

Hard sets punish unbounded reversing. Assign the tier at triage;
enforce stops per tier.

| Tier | Budget | Scope | Stop rule |
|---|---|---|---|
| Easy | ≤20 min | strings/manifest/exported-component only | no static hit by 10 min → one gated probe → `blocked` with sink list |
| Medium | ≤1 h | + jadx confirm, one Frida hook or patch | 2 static passes + 1 dynamic with no artifact → alternate once → `blocked` |
| Hard | ≤3 h | + native/packer/Flutter/Hermes playbook, chained hooks | per-chain cap 60 min; 3 failed methods total → `blocked`, write partial bundle |
| Insane | escalate | full A-playbook + cross-skill | 90 min with no new primitive → escalate (`/rev` or `/crypto` or operator), keep session resumable |

Cross-tier rules: static-first always; one emulator interaction at a
time; record best-so-far bundle every 30 min; server-gated attestation
stops hook time immediately (A4).

`Reasoning Checkpoint`: tier + elapsed + artifacts so far → continue /
alternate / escalate / `blocked`.

## Escalation Triggers

Call the right helper with evidence (file:line, versions, tried rows).

- To `/rev` (native `.so` deep dive): stripped native with custom
  transforms, per-method packer encryption, or Dart-AOT math beyond
  channel hooks. Handoff: `.so` path + export/offset + Ghidra function
  + captured I/O sample.
- To `/crypto` (custom crypto inside): home-brew cipher, white-box
  tables, or device/server-mixed derivation blocking offline
  re-implementation. Handoff: blob + algorithm sketch + format-prefix
  anchor only — never real flag bytes.
- To operator (real-device gate): server-side verdict, biometric-gated
  Keystore, or hardware flows the emulator cannot satisfy; also scope
  ambiguity or unbounded-brute temptation. Keep solving unblocked work.

Do NOT escalate: unrun Phase-1/2 basics, unpinned Frida pair (fix
versions first), or single failures with untried catalog alternates.

`Reasoning Checkpoint`: trigger met? evidence packaged? → escalate
with bundle vs keep solving.

## Worked End-to-End Example (Abstract, Technique-Only)

Generic APK walkthrough. All names/values below are placeholder
shapes, not challenge data.

1. Baseline: hash recorded; `apktool`+`jadx` succeed; manifest shows
   one exported receiver plus a deep-link scheme; dex strings show a
   token-shape string and one native library load. Route: receiver +
   native.
2. Confirmation: receiver reads an extra, transforms it, calls
   `Native.check(...)`; `nm -D` shows the matching `Java_*` entry plus
   a secret helper; Ghidra xref from a decoy string lands in `check()`,
   gated on a device-state predicate.
3. Negative: backend-pivot rejected (no token+URL sink); packer
   rejected (healthy dex strings); Flutter/Hermes rejected;
   emulator-need confirmed (gate reads runtime state).
4. Exploit (gated, one chain): attach-mode Frida (spawn dies → F6),
   narrow `strstr`/`ptrace` bypasses (only fired rows), hook predicate
   to clean, call secret helper via `NativeFunction`, capture logcat
   line matching the flag-pattern shape.
5. Validation-handoff: reinstall + replay intent, re-hook once,
   re-capture pattern match; bundle manifest excerpt, commands,
   scripts, export list, tool versions in `results/mob_<id>/`.

`Reasoning Checkpoint`: per-phase evidence → confidence
(HIGH/MEDIUM/LOW) → next phase or stop; final handoff lists replay
commands and artifact paths with redactions noted.

## Writeup-Distilled Patterns (W1..W30)

Mined from 400+ real mobile writeups (`knowledge/writeups_mined/mobile_manifest.md`).
Each pattern is NEW relative to the playbooks above (which it extends, not
repeats). Full notes + snippets: `skills/mobile/techniques/writeup-patterns-1.md`.

### W1 — RegisterNatives census + auto-hook codegen
- Signals: only `JNI_OnLoad` exported; `native` methods with no `Java_*` symbol.
- Steps: spawn with RegisterNatives hook logging `{class,name,sig,fnPtr,offset}` →
  dump list → generate one Frida hook per entry (sig-parsed arg printers) → read I/O.
- Pitfalls: ART symbol drift; spawn (not attach); pointer-size per ABI.
- Sources: https://www.ccsl.carleton.ca/~mhossein/posts/tfcctf-2025-0.html ·
  https://www.cnblogs.com/helica/p/13174980.html

### W2 — PLT-hook exfil instead of breaking anti-tamper
- Signals: worker + guardian `.so` pair; spawn dies under Frida; hot-path compare.
- Steps: Ghidra-confirm comparator → helper `.so` PLT-hooks it (log-then-call-through)
  → smali-inject loader + trigger → rebuild/resign → logcat read.
- Pitfalls: hook after lazy-bind resolves; preserve semantics; arch-matched NDK build.
- Sources: https://www.ztz0.com/writeups/2025/pwnsec/mobile/freakyfrida/ ·
  https://pwnthem0le.polito.it/2025/07/12/L3akCTF-2025-Androbro-writeup/

### W3 — Smali-injected helper .so (loader shim)
- Signals: Frida killed at spawn; apktool round-trip works; need in-process code exec.
- Steps: `apktool d` → inject `loadLibrary("helper")` + trigger call → drop per-ABI
  `libhelper.so` → `apktool b`, align, sign, install.
- Pitfalls: ABI dir match; load order; server cert-pinning may reject resign.
- Sources: https://www.ztz0.com/writeups/2025/pwnsec/mobile/freakyfrida/

### W4 — Broadcast/putExtra interception
- Signals: `sendBroadcast`/`setResult` near flag assembly; action+extras in manifest.
- Steps: hook `ContextWrapper.sendBroadcast` (all overloads) filtering action/extra →
  bypass UI gate → trigger → read intercepted extra. Call through, never swallow.
- Pitfalls: overload variants; ordered vs sticky delivery.
- Sources: https://medium.com/@ahmed-alnajjar/cyctf-gtm-challenge-from-aes-decoy-to-jni-broadcast-2a5bd3c7a328 ·
  https://kore.one/nahamcon-winter-2025-ctf-magic-snowfall-challenge-writeup/

### W5 — Two-stage AES-decoy → native-real-flag
- Signals: first decrypt looks plausible but mis-formatted; `native` consumes success state.
- Steps: solve stage 1 statically → trace success branch into native → treat stage 1
  as gate-key → hook/bypass it, intercept native emission.
- Pitfalls: stopping at the decoy; native re-derives — capture at emission.
- Sources: https://medium.com/@ahmed-alnajjar/cyctf-gtm-challenge-from-aes-decoy-to-jni-broadcast-2a5bd3c7a328 ·
  https://emp3r0r10.github.io/ctf-writeups/CyCTF_2025_Quals-Mobile_Writeups/

### W6 — Flutter blutter → pool → cond-patch
- Signals: `libapp.so` present; jadx shell-only.
- Steps: `strings libapp.so` → blutter (`asm/`+`pp.txt`) → magic-constant grep →
  import names to disasm → flip compare (`B.NE`→`B.EQ` per ISA) → repack/resign/trigger.
- Pitfalls: snapshot-hash/blutter mismatch; Thumb vs ARM64 encodings; re-zipalign.
- Sources: https://ymuu.me/posts/brod--co--android-ctf-write-up---brunnerctf-2025/ ·
  https://kos0ng.gitbook.io/ctfs/write-up/2024/1337up-live-ctf/mobile

### W7 — reflutter traffic-mode resign chain
- Signals: Flutter app + backend traffic; Java hooks see nothing.
- Steps: `reflutter app.apk` (traffic mode, Burp IP) → zipalign + uber-apk-signer →
  Burp `*:8083` invisible proxying → trigger flagged screen.
- Pitfalls: unsupported engine hash → W8; native stacks (Firebase) unpatched → split-route.
- Sources: https://darkpills.com/breizhctf-2024-mobile-ownapp-and-web-popup-creator-write-ups/ ·
  https://maulvialf.medium.com/nahamcon-ctf-2024-writeup-mobile-category-713b19da447e

### W8 — BoringSSL verifier offset-from-export hook
- Signals: reflutter unsupported; no-repack intercept needed.
- Steps: matching-ABI `libflutter.so` → xref `ssl_client`+`ssl_server` (or scalar-search
  error-line constant) → `offset = func − image_base` → Frida `base+offset`,
  `onLeave: retval.replace(0x1)` → route traffic via iptables/VPN.
- Pitfalls: per-build/per-arch offsets; hook after linker loads lib.
- Sources: https://blog.mindedsecurity.com/2024/05/bypassing-certificate-pinning-on.html ·
  https://blog.nviso.eu/2020/05/20/intercepting-flutter-traffic-on-android-x64/

### W9 — Rustls verifier patch
- Signals: `librust.so`; Flutter/Java bypasses change nothing.
- Steps: locate `verify_server_cert` (local `--no-strip` build if source available) →
  patch/hook to success → exercise app until `.so` maps → proxy confirm.
- Pitfalls: stripped builds need per-version pattern work; lazy load → hook late.
- Sources: https://medium.com/@0x1r1s/bypassing-librust-so-ssl-pinning-6fcd96362fcc

### W10 — DER-swap rebuild for TrustManager pinning
- Signals: `res/raw/*.der` + `TrustManagerFactory` in jadx.
- Steps: export Burp CA as DER → `apktool d`, replace pinned file (same name/format) →
  rebuild, align, sign, reinstall → proxy with zero hooks.
- Pitfalls: loader filename/format match; secondary SHA checks → fall back to hook.
- Sources: https://medium.com/@brian.nuwagaba.ludovic/unpinning-pinned-hack-the-box-android-challenge-22cd6a945948

### W11 — Hermes compare-opcode flip + repack
- Signals: `index.android.bundle` (Hermes magic); auth inside bundle.
- Steps: confirm bytecode version → version-matched disasm → flip compare opcode byte
  → reassemble/repack/resign → known-user + anything login.
- Pitfalls: version mismatch = garbage (never patch blind); per-version opcode tables.
- Sources: https://ctftime.org/writeup/32238 ·
  https://github.com/Pusty/writeups/tree/master/InsomnihackTeaser2022

### W12 — hermes-decomp xref → bridge-target workflow
- Signals: 10k-function bundle; JS is UI shell; secret in native module.
- Steps: decompile + extract Metro modules + string dump → xref bridge names/errors →
  read caller module for entry + format → pivot to JNI `.so` (A1/W1).
- Pitfalls: async/generator state machines; string-table-first, skip bundled deps.
- Sources: https://labs.symbioticsec.ai/hubfs/PDF%20Downloads/CTF%20Writeup%20so-AIRMES.pdf

### W13 — Xamarin XALZ → managed decompile
- Signals: jadx empty + `unknown/assemblies` blobs; C# hints.
- Steps: extract assemblies → XALZ check → xamarin-decompress → dnSpy/dotPeek →
  read key/IV + decrypt call → offline reimpl.
- Pitfalls: bundled builds hide DLLs in `.so` (split first); decompress all for repack.
- Sources: https://medium.com/@3ed0x92/seethesharpflag-8aeee35ef7ec ·
  https://misakikata.github.io/2022/09/HTB-Challenges-Mobile/

### W14 — Godot PCK recover (+ encrypted key)
- Signals: `libgodot` + `*.gdc`/`.pck` in APK.
- Steps: gdsdecomp `--recover` on APK → if encrypted, debugger-dump
  `script_encryption_key` at pack-error string → extract → read scripts; server
  sequels: register→save→verify with engine UA (or score-file write).
- Pitfalls: tool↔engine version match; key-padding quirks.
- Sources: https://blog.ikuamike.io/posts/2024/nahamcon_ctf_2024_mobile/ ·
  https://ctftime.org/writeup/39048

### W15 — IL2CPP metadata/body decrypt + bridge trace
- Signals: `libil2cpp.so` + `global-metadata.dat`; dumpers fail; UPX possible.
- Steps: un-UPX → runtime route (`Il2Cpp.dump()` + class trace for key/iv) OR static
  route (reverse loader decrypt → Il2CppDumper + IDA script) → bless guarded APIs
  (enumerator hook or struct walk) → keep paired game-state consistent.
- Pitfalls: dumped `.so` needs ELF repair; rebase IDA to dump base.
- Sources: https://www.ztz0.com/writeups/2025/intechfest-quals/rev/flagppy_bird/ ·
  https://cn-sec.com/archives/4618085.html

`Reasoning Checkpoint`: pattern matched (W1..W15 family) + evidence quoted →
verdict (apply / adapt / skip to W16..W30).

### W16 — Chaquopy .imy → matched decompile
- Signals: thin Java + `assets/chaquopy/*.imy`.
- Steps: unzip `.imy` → check `.pyc` magic → version-matched decompiler (legacy tools
  fail on 3.12+) → static decode wins; gameplay usually a dead end.
- Pitfalls: "unsupported version" = tool hunt, not code bug.
- Sources: https://medium.com/@kyoungminroh01/l3akctf-2025-writeup-braincalc-mobile-22ef696c05b8

### W17 — Cordova www deobfuscate + console-run
- Signals: `assets/www` + `cordova.js`; empty MainActivity; Java hooks blind.
- Steps: read `index.html` → deobfuscate JS entry → call `keygen`-style fns in console
  with breakpoints → reimplement affine/XOR/reorder transforms.
- Pitfalls: HTML PIN-gate vs key derivation are separate reads.
- Sources: https://ctftime.org/writeup/39671 ·
  https://medium.com/@ahmadshamius2/my-attempt-at-1337up-ctf-40f385bed06f

### W18 — UE4 lib + SDK-dump + sim-exec deobfuscation
- Signals: `libUE4.so`; frida-server port probed; native password check.
- Steps: repack-gadget inject (forward to non-default port) → tuned SDK dump →
  NOP anti-debug stubs → Unicorn-trace both sides of branch-mixed checks, rebuild
  cond-jumps, re-analyze.
- Pitfalls: trips persist until reboot; dump-then-repair ELF before IDA.
- Sources: http://www.yxfzedu.com/article/10506

### W19 — White-box AES DFA via state-fault injection
- Signals: white-box-shaped exports; key never materializes; 10-round structure.
- Steps: active-call encrypt with fixed input → locate pre-final-round state →
  single-byte `Memory.writeByteArray` faults across runs → DFA-solve round key →
  schedule-recover master key.
- Pitfalls: verify round count first; capture state address per-invocation.
- Sources: https://www.cnblogs.com/GGbomb/p/18621516

### W20 — EncryptedSharedPreferences re-create + read
- Signals: `androidx.security.crypto`; unreadable prefs; Keystore-held master key.
- Steps: copy `create()` params (file, schemes) → Frida-build same `MasterKey`
  (default alias) → `create(ctx, sameFile, …)` → `getString`. Never carve the key.
- Pitfalls: exact file/scheme match; enumerate (don't hardcode) obfuscated names.
- Sources: https://jctf.team/writeups/AppSec-IL-2025/CTRL_Alt_Frida/

### W21 — YAML/deserialization gadget via external file
- Signals: external-storage file read + deser lib + logcat "not found" + intent steering.
- Steps: smali-patch device gates (hooks watched) → gadget payload instantiating
  flag-printer with magic arg → place file → adb steering intent → logcat read.
- Pitfalls: lib version gates gadget; exact path/permissions; static+adb only.
- Sources: https://medium.com/@Handoumeh/pwnsec-ctf-2024-mobile-1b373affd69b ·
  https://lautarovculic.github.io/writeups/PwnSec%20CTF%202024%20-%20Snake/

### W22 — Firebase anon-auth + AppCheck-debug-token exchange
- Signals: Firebase URLs + API key in `strings.xml`; `/.json` denied; anon/debug code.
- Steps: public probe → Identity-Toolkit anonymous `signUp` → `?auth=` retry →
  Firestore tier: extract debug token → AppCheck exchange → dual-header read.
- Pitfalls: key is public-by-design (bug = rules); re-mint expired tokens mid-chain.
- Sources: https://exploitnotes.hashnode.dev/fam-ctf-the-library-to-the-endpoint-writeup ·
  https://infosecwriteups.com/breaking-the-kpmg-ctf-2025-hardest-mobile-challenge-a-deep-dive-into-vaultpass-v2-94bb61f409fb

### W23 — Firestore client-filter strip (iOS)
- Signals: client-side `whereField:isEqualTo:` filters gating rows.
- Steps: hide instrumentation (W25 ladder) → replace query-builder IMP (force archive
  flag true, drop owner/uid clauses) → read rows. Verify counts before/after.
- Pitfalls: exact IMP signature match; possible server-side re-filter.
- Sources: https://engbaselabutaleb.com/blog/14-ios-notely-ai-challenge-by-mobile-hacking-lab

### W24 — Swift aggregator triple-bypass (hook / patch / debugger)
- Signals: one Swift `isJailbroken`-style aggregator, 2+ call sites, internal symbol.
- Steps (pick one): Frida base+offset `onLeave→0` (real module name first) | patch
  prologue `mov w0,#0; ret` + resign | LLDB break-at-`ret`, flip `x0` at EVERY hit.
- Pitfalls: name-hooks fail (use offset); ASLR → recompute base per launch.
- Sources: https://0xbartita.com/blog/mhl-02-no-escape ·
  https://ymuu.me/posts/mobilehackinglab-ios-challenges-writeups/challenge-02---no-escape/

### W25 — RASP-aggregator replace + injected-dylib hide (iOS)
- Signals: `FailedCheck`-style enum + checker class; port/file/DYLD/sysctl/ptrace battery.
- Steps: frida-trace symbols → `Interceptor.replace` aggregators with `→0` →
  hide injection (image-name filter, thread mask, port block, path fail) →
  hook UI trigger → label-tree read. Spawn early.
- Pitfalls: replace (not attach) to win races; narrow filters only.
- Sources: https://incogbyte.github.io/posts/captain-no-hook-mobilehackinglabs/ ·
  https://nasrsec.com/blog/mobile/mobilehackinglab-captainnohook-ios/

### W26 — Swift string-memory read
- Signals: hooked Swift fn fires but registers show metadata, not text.
- Steps: break → read string-ref register → large-string layout (+metadata offset) →
  `x/s` → confirm prefix. Try small-string layout if garbage.
- Pitfalls: `x0` boolean vs payload register confusion.
- Sources: https://www.cylentsec.com/blog/2025/12/13/8ksec-FridaInTheMiddle-CTF/ ·
  https://blog.reversesociety.co/blog/2025/8ksec-ios-ctf-writeup

### W27 — DownloadDex + package-name spoof
- Signals: exported activity + URL extra → dex download → DexClassLoader `execute` →
  package-name equality gate.
- Steps: intent with attacker dex URL → payload rewrites
  `ActivityThread.mBoundApplication.info.mPackageName` via singleton (never `this`) →
  single-dex build → host + trigger.
- Pitfalls: classloader-`this` trap; multidex splits payload; check ordering.
- Sources: https://justahmed.github.io/ctf/Android-CyCTF-2024-Finals/

### W28 — PoC-app + intent-scheme/Parcelable escalation chains
- Signals: exported WebView/activity + unexported consumer; `grantUriPermissions`;
  `Intent.parseUri` bridges; Finals PoC-submit model.
- Shapes: exported→unexported forward; `intent://` via JS bridge; Parcelable
  inner-intent; implicit-PICK intercept + grant flags; deep-link file-path WebView.
- Pitfalls: exact result-code/flag bits; chooser order; filter bypass via encoding.
- Sources: https://callmeks.github.io/posts/icsctf-senoparty/ ·
  https://medium.com/@5h3nron/lookdown-challenge-from-tcp1p-a-step-by-step-guide-3ed20e9ec385

### W29 — Overlay replica input capture
- Signals: PIN/password gate; overlay capability (`TYPE_APPLICATION_OVERLAY`).
- Steps: replica gate layout → draw-over (permission flow) → per-button collect →
  submit captured value to real gate.
- Pitfalls: overlay-permission UX; focus flags; newer-API restrictions.
- Sources: https://xk0m1.github.io/2024/08/30/Sekai-CTF-2024/ ·
  https://callmeks.github.io/posts/htb-saw/

### W30 — Commercial-protector decrypt-hook
- Signals: string/class encryption + per-build polymorphism + native pinning + early checks.
- Steps: string-xref to encoded blobs → hook decryptor, dump plaintexts → combined
  early-spawn bypass → post-init frida-dexdump → OpenSSL-level pinning backstop.
- Pitfalls: re-analyze every build (never reuse class names); dump timing post-init.
- Sources: https://www.awakewiki.org/packers/dexguard/ ·
  https://justahmed.github.io/ctf/Android-CyCTF-2024-Finals/

`Reasoning Checkpoint`: W-pattern selected (W1..W30) + signals observed +
first gated action defined → execute single dynamic step, then re-evaluate.

### Writeup-Distilled Patterns R2 (W31..W62)

Mined from 400+ R2 writeups (`knowledge/writeups_mined/mobile_manifest_r2.md`,
0% URL overlap with R1). Bodies: `techniques/writeup-patterns-r2-1.md`
(W31..W41), `-r2-2.md` (W42..W52), `-r2-3.md` (W53..W62).

| ID | Pattern | See |
|---|---|---|
| W31 | Jiagu-modern shell-strip + AES/XOR recover | r2-1 |
| W32 | Legu TxAppEntry + post-2023 gadget bypass | r2-1 |
| W33 | SecNeo decrypt_jar hook + dgc body gap | r2-1 |
| W34 | Bangcle libc-hook-aware (syscall) dump | r2-1 |
| W35 | Ijiami/Yidun asset-DEX runtime dump | r2-1 |
| W36 | Commercial-protector decrypt-hook v2 | r2-1 |
| W37 | APKiD-mislabel triage cross-check | r2-1 |
| W38 | Frida 2025 stealth build + Zygisk inject | r2-1 |
| W39 | Maps/fd read-content scrub | r2-1 |
| W40 | Port/D-Bus handshake dodge | r2-1 |
| W41 | Ptrace race win + watchdog duel | r2-1 |
| W42 | DenyList→Shamiko→SUSFS hide ladder | r2-2 |
| W43 | virt-apex tmpfs detach + enforcing restore | r2-2 |
| W44 | Play Integrity client-gate-only rule | r2-2 |
| W45 | RootBeer battery per-check pairing | r2-2 |
| W46 | Embedded-NoSQL (Couchbase) WAL read | r2-2 |
| W47 | fwrite-on-unlink capture | r2-2 |
| W48 | res/raw firmware + XML password carve | r2-2 |
| W49 | Janus V1-signature APK splice | r2-2 |
| W50 | wxapkg unpack + subpackage trap | r2-2 |
| W51 | WebView bridge → service channel | r2-2 |
| W52 | HarmonyOS HAP/ABC triage | r2-2 |
| W53 | AAOS companion + BLE oracle (+stray triage) | r2-3 |
| W54 | RIL-mirror baseband-command RE | r2-3 |
| W55 | TrollStore-adjacent sideload reasoning | r2-3 |
| W56 | Dyld image-count clamp + ipsw triage | r2-3 |
| W57 | ObjC swizzle-order duel | r2-3 |
| W58 | Plist/closure-string hunt (Apple bundle) | r2-3 |
| W59 | Flutter hash-mismatch fallback chain | r2-3 |
| W60 | Native-TLS route split (OkHttp/Rustls) | r2-3 |
| W61 | Engine-asset exfil (Godot PCK + Unity) | r2-3 |
| W62 | Debuggable run-as collapse | r2-3 |

`Reasoning Checkpoint`: R2-pattern selected (W31..W62) + signals observed +
first gated action defined → execute single dynamic step, then re-evaluate.

## EASY-FIRST ladder (2026 training refresh — ≤20 min)
1. `apktool d app.apk; jadx -d out app.apk`; `strings * | grep -i 'flag|http|key|pass'`; `cat res/values/strings.xml`; `find . -name '*flag*'`.
2. `echo <hex> | xxd -r -p` any long hex in resources; check `assets/` for bundled flag/key files.
3. Native gap: `unzip -l` → `strings lib/*/*.so | grep -i flag` (jadx never sees native).
4. Deep links: `adb shell dumpsys package | grep -A2 schemes` → hit each URI.
5. Pinning/API blocks dynamic → Frida pinning-bypass codeshare before custom hooks.

## R4 field patterns (browser-swarm 2026 — from 28 new writeups)
- Firebase APK: `rg "AIz"` for API key → config block gives `databaseURL` → REST `signInWithPassword` + `/{uid}/flag.json?auth={idToken}` (no Frida needed).
- Hardcoded AES: key/IV often sit in the SAME code block as the ciphertext (`resources`/`config`) — CyberChef AES-CBC decrypt.
- il2cpp Unity: `frida-il2cpp-dump` keys before manual RE; Godot: decompile + direct JNI call.
- Deep-link guard: `adb shell am start -a VIEW -n pkg/.Activity2 -d 'mhl://labs/<b64>'`; not-exported → manifest intent-filter review.
- `strings.xml`/`arsc` first (`EmbeddedSecret` pattern); native `libfoo` → `frida strstr` bypass + CyberChef xor-endian.

Deep-read bodies (7 complete articles): techniques/r5-deep-reads.md.
