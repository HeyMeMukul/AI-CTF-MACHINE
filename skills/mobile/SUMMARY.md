# mobile SUMMARY (quickref)

Triage: `unzip -l`, `apktool d app.apk -o out_apktool`,
`jadx -d out_jadx app.apk`, manifest: `debuggable|allowBackup|exported|
permission|scheme`, dex strings: `unzip -p … classes.dex | strings | grep
-Ei 'flag|http|aes|secret'`.

Static confirm: grep Java for `Cipher|SecretKey|Http|OkHttp|
CertificatePinner|isRooted`, intents `getStringExtra|DeepLink`,
providers `android:authorities`; native `strings lib/*/*.so`;
assets `strings.xml|*.json`.

Bundle check: `libapp.so|libflutter.so` → Flutter path;
`hermes|jsbundle` → Hermes disasm path; stop Java grep when hit.

Backend? hardcoded `https://` + token, no local flag logic → pivot web-ctf.

Gated dynamic (own emulator, ONE step ≤120s): `adb install -r`,
`adb shell am start -n pkg/.Activity`, deep link
`am start -a VIEW -d 'ctf://flag'`, `content query --uri …`,
`frida -U -f pkg -l hook_crypto.js --no-pause`, `objection -g pkg explore`,
backup if `allowBackup`: `adb backup -f app.ab -noapk pkg`.

Patch: `apktool b out_apktool -o patched.apk` → `apksigner sign` →
reinstall. iOS: `unzip ipa`, `plutil -p Info.plist`, `frida-trace`.

Validate: re-run winner once, `adb logcat -d | grep -Ei flag >
results/mob_evidence.txt`, bundle hook + manifest + hash in
`results/mob_<id>/`.

Hard playbook: native `nm -D lib/arm64-v8a/*.so | grep Java_|JNI_OnLoad`,
Ghidra string-xref, `RegisterNatives` hunt if stripped, direct
`NativeFunction` call; packers (stub dex + loader .so) → runtime
dex-magic dump, reload in jadx; anti-Frida per fired check (port /
maps-`strstr` / files / threads / `ptrace`) narrow bypass or
smali-patch aggregator; attestation → hook client gate only.

Bundles: `strings libapp.so` → snapshot dump → MethodChannel seam;
Hermes bundle → version-matched disasm → string-table xref → native
bridge. Keystore: non-exportable keys → hook `Cipher` boundary, never
carve memory. iOS: hook fired jailbreak predicate only.

Failures: jadx-empty→smali+dump; Frida version mismatch→exact pair;
emulator-gate→spoof narrowly or real device; native pinning→native
`SSLContext` hook. Pin versions (frida pair, jadx/apktool flags, API
level, Hermes/Dart builds). Tiers: easy ≤20m / medium ≤1h / hard ≤3h /
insane→escalate. Escalate: stripped-transforms→/rev, home-brew
crypto→/crypto, server-verdict/hw-key→operator.

Gates: 1 triage → 2 static confirm (file:line) → 3 negatives (obfus?
server-side? bundle? emulator?) → 4 ONE dynamic → 5 handoff.

One worker per emulator; provided binaries only; never paste tokens/flags.

Writeup-mined (W1..W30, full notes in techniques/writeup-patterns-1.md):
engines: Xamarin XALZ→dnSpy; Godot gdsdecomp (+debugger key);
IL2CPP bridge dump/trace; Chaquopy .imy→matched-pyc; Cordova www
console-run; UE4 SDK-dump. Exfil: PLT-hook comparator; helper-.so
smali-inject; sendBroadcast intercept; BoringSSL offset-from-export;
DER-swap rebuild; Hermes opcode-flip. Data: Firebase anon→AppCheck
exchange; EncryptedSharedPreferences re-create; DFA state-fault;
Swift hook/patch/LLDB triple; PoC-app Parcelable/intent-scheme chains;
overlay replica; protector decrypt-hook. Manifest:
knowledge/writeups_mined/mobile_manifest.md (416 entries).

Writeup-mined R2 (W31..W62, bodies in techniques/writeup-patterns-r2-*.md):
packers: Jiagu strip; Legu TxAppEntry; SecNeo dgc-gap; Bangcle syscall-dump;
Ijiami/Yidun runtime; DexGuard-v2 hook; APKiD cross-check. Anti-FRIDA/root:
stealth build; maps-scrub; port-dodge; ptrace-race; DenyList→SUSFS ladder;
apex-tmpfs detach; integrity client-gate-only; RootBeer pairing. Exfil/store:
Couchbase WAL; fwrite-unlink; res/raw carve; Janus splice; debuggable run-as.
Bridges/engines: wxapkg subpkgs; WebView→service; HAP/ABC; AAOS/BLE;
RIL-mirror; TrollStore; Dyld+ipsw; swizzle-duel; plist-hunt; Flutter
fallback; TLS route-split; Godot/Unity assets. Manifest R2:
knowledge/writeups_mined/mobile_manifest_r2.md (409 entries, 0% R1 overlap).
