# Mobile Writeup-Distilled Patterns R2-1 (W31..W41)

Companion to `skills/mobile/SKILL.md` → `## Writeup-Distilled Patterns R2`.
Technique-only. Package/class names are placeholders (`com.example.ctf`).

## Index

| ID | Pattern | Primary source writeups |
|---|---|---|
| W31 | Jiagu-modern static shell-strip | jiagu_unpacker, Jiagu-2026 defeat, Frezrik Jiagu |
| W32 | Tencent Legu TxAppEntry + post-2023 bypass | awake tencent-legu, APKiD releases, frida-dexdump |
| W33 | SecNeo decrypt_jar hook + dgc gap | wilco375 gist, secneo-gadget, Shark bangcle |
| W34 | Bangcle libc-hook-aware dumping | Shark bangcle, KuNgia09 Bangcle, NDSS unpack study |
| W35 | Ijiami/Yidun asset-DEX runtime dump | Purifire study, APKiD releases |
| W36 | Commercial-protector decrypt-hook v2 | APKiD DexGuard9.x, awake legu, Shark play-integrity |
| W37 | APKiD-mislabel triage cross-check | APKiD releases, Purifire SecNeo/Jiagu mapping |
| W38 | Frida 2025 stealth build | frida-stealth, FridaDetectionBypass, ZygiskFrida |
| W39 | Maps/fd read-content scrub | awake legu, MASTG-DEMO-0108, enovella codeshare |
| W40 | Port/D-Bus handshake dodge | aimardcr bypass, MASTG-DEMO-0119, awake connect-null |
| W41 | Ptrace race win + Zygisk inject | Zygisk-Assistant, MASTG-DEMO-0116, UnCrackable3-2026 |

---

## W31 — Jiagu-modern static shell-strip + AES/XOR DEX recover

Recognition: single `classes.dex` stub + `libjgbibc_64.so`-style protector lib;
static extractors fail with size-0 output; fake ZIP-encryption flags on the APK.
Steps: (1) confirm stub (one dex, app-class replaced); (2) try static
shell-strip first (AES-CBC + XOR layers, shell-vs-original DEX split, app-class
recovery); (3) on 0-byte failure pivot to protector-`.so` triage (identify VM
entry, fall back to runtime dump); (4) reload recovered DEX in jadx.
Commands:

```bash
python3 jiagu_unpacker.py -apk packed.apk -out extracted
unzip -l packed.apk | grep -Ei 'libjgbibc|classes.dex'
```

Pitfalls: extractor-vs-packer version skew (0-byte output = version gap, not a
broken tool); fake-ZIP flags defeat plain unzip — use the decrypt path.
Sources: https://github.com/SafaSafari/jiagu_unpacker ·
https://medium.com/@0xcc00/defeating-jiagu-android-packer-the-wrong-way-a288bf316441 ·
https://github.com/Frezrik/Jiagu

## W32 — Tencent Legu TxAppEntry + post-2023 gadget-name bypass

Recognition: manifest app-class `com.tencent.StubShell.TxAppEntry` + `TxAppEntry`
meta-data; `libDexHelper`-style native lib; ptrace self-attach at launch.
Steps: (1) read manifest for stub + real app-class; (2) spawn-early with
combined hides: `open`/`read` maps-scrub for agent strings, `connect` port
null-route for the default Frida port, renamed-gadget string dodge for
post-2023 builds; (3) hook `DexClassLoader`/`InMemoryDexClassLoader` or sweep
for DEX magic post-decrypt; (4) dump after native loader finishes.
Snippet (concept): scrub `frida` substrings out of the `read` buffer when the
fd is a maps file; drop `connect` sockaddr when the port matches the default.
Pitfalls: dump timing (pre-decrypt = stub only); renamed-gadget builds defeat
literal string lists — match behavior, not names.
Sources: https://github.com/zahidaz/awake/blob/main/docs/packers/tencent-legu.md ·
https://github.com/rednaga/APKiD/releases ·
https://github.com/hluwa/frida-dexdump

## W33 — SecNeo decrypt_jar_128K hook + classes.dgc method-body gap

Recognition: SecNeo/Bangcle loader `.so`; `assets/classes.dgc`-style method-body
store; dumped DEX runs but hot methods are empty stubs.
Steps: (1) hook the jar-decrypt entry (`decrypt_jar_128K`-family) and dump DEX
post-decrypt; (2) expect empty-method stubs whose bodies live in the `.dgc`
asset; (3) treat the dump as a map, then recover bodies dynamically (trace the
target method at runtime) rather than statically; (4) confirm with a Gadget/TS
unpack pipeline for older SecNeo.
Pitfalls: assuming the dumped DEX is complete (the `.dgc` gap); method bodies
may decrypt per-call — capture at execution, not at rest.
Sources: https://gist.github.com/wilco375/d5d51bec59a35a77856d506f44afb79f ·
https://github.com/strazzere/secneo-gadget ·
https://github.com/Anthropicdaddy/Shark/blob/main/docs/packers/bangcle.md

## W34 — Bangcle libc-hook-aware dumping (syscall-direct)

Recognition: Bangcle/SecNeo-family packer that hooks libc (`read`/`write`/
`open`/`mmap`) to crash dumpers; unpacker dies when calling libc file APIs.
Steps: (1) confirm libc-hook behavior (crash only when dumping via libc);
(2) switch the dump path to raw syscalls (`svc`) instead of libc wrappers;
(3) dump decrypted regions from `/proc/<pid>/maps` after full init;
(4) validate DEX magic + class count before jadx reload.
Pitfalls: multi-layer unpacking (memory holds packed layers until executed —
dump late); self-modifying loader shifts offsets per run.
Sources: https://github.com/Anthropicdaddy/Shark/blob/main/docs/packers/bangcle.md ·
https://github.com/KuNgia09/Bangcle ·
https://arxiv.org/html/2509.16340

## W35 — Ijiami/Yidun asset-DEX runtime dump

Recognition: `libijiami`-style loader or Yidun (NetEase) shell; encrypted DEX in
assets; APKiD mislabels common (Jiagu-as-generic, UPX-modified-as-Ijiami).
Steps: (1) cross-check packer ID (APKiD + telltale `.so` + assets listing);
(2) spawn with anti-Frida hides (W39/W40); (3) hook all ClassLoader variants
and dump DEX bytes post-load; (4) handle multi-DEX (repeat per `classesN.dex`).
Pitfalls: trusting a single identifier (APKiD staleness — verify with two
signals); dumping before the loader finishes yields the shell only.
Sources: https://arxiv.org/html/2509.16340 ·
https://github.com/rednaga/APKiD/releases ·
https://github.com/hluwa/frida-dexdump

## W36 — Commercial-protector decrypt-hook v2 (DexGuard/DexProtector 9.x)

Recognition: string/class encryption + per-build polymorphism + native pinning +
telemetry-flavored protectors (DexGuard 9.x, DexProtector DPLF, FreeRASP-hints).
Steps: (1) string-xref to encoded blobs to find the decryptor class;
(2) hook decryptor → dump plaintexts (URLs/keys) at runtime; (3) combined
early-spawn bypass (maps-scrub + port-hide + file-probe fail);
(4) post-init dex dump; (5) OpenSSL-level hook as pinning backstop.
Pitfalls: per-build polymorphism — re-analyze every build, never reuse class
names; cracked-vs-licensed strength gap changes the effort estimate.
Sources: https://github.com/rednaga/APKiD/releases ·
https://github.com/zahidaz/awake/blob/main/docs/packers/tencent-legu.md ·
https://github.com/Anthropicdaddy/Shark/blob/main/docs/platform-abuse/play-integrity.md

## W37 — APKiD-mislabel triage cross-check

Recognition: APKiD reports a packer name that contradicts loader behavior
(e.g. "Jiagu" as a generic term, "UPX modified" that is really Ijiami,
SecNeo-vs-Bangcle naming drift).
Steps: (1) record APKiD verdict; (2) independently list loader `.so` names,
manifest stub class, and assets; (3) resolve conflicts with the
SecNeo=Bangcle / Jiagu=360 / Yidun/UPX-modified mapping table;
(4) pick the dump workflow for the *verified* packer, not the label.
Pitfalls: single-tool trust; vendor renaming across years (SecNeo A/B splits).
Sources: https://github.com/rednaga/APKiD/releases ·
https://arxiv.org/html/2509.16340

## W38 — Frida 2025 stealth build (rename + Zygisk inject)

Recognition: app dies at spawn under stock frida-server/gadget; checks name
threads, sockets, pipes, and default port.
Steps: (1) build Frida from source with stealth patches (renamed threads,
sockets, main loops, SELinux contexts); (2) run server on a non-standard port
with certificate-pinned channel; (3) prefer Zygisk-based injection
(no-ptrace) with a patched gadget; (4) add in-memory trace hiding for
Magisk/Frida strings.
Pitfalls: prebuilt "stealth" binaries get fingerprinted — build it yourself so
string artifacts differ; gadget-vs-server version must match exactly.
Sources: https://github.com/AsenOsen/frida-stealth ·
https://github.com/aimardcr/FridaDetectionBypass ·
https://github.com/lico-n/ZygiskFrida

## W39 — Maps/fd read-content scrub

Recognition: app scans `/proc/self/maps`, `fd/` pipes, or task files for
`frida`/`gadget`/`xposed` needles (often via `strstr` on `fgets` buffers).
Steps: (1) confirm the needle + reader (`strstr` return-NULL hook is the
minimal win); (2) for `read`-buffer scans, rewrite the buffer in `onLeave`
when the fd is a maps-like file; (3) pair with fd/path hides for pipe checks.
Snippet (concept): `read` onLeave → if caller reads own maps, replace needle
substrings in the returned buffer, keep length identical.
Pitfalls: length-changing replacements corrupt parsing — same-length fills
only; blanket libc zeroing crashes the app (narrow to the probe).
Sources: https://github.com/zahidaz/awake/blob/main/docs/packers/tencent-legu.md ·
https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0108/MASTG-DEMO-0108/ ·
https://codeshare.frida.re/@enovella/anti-frida-bypass/

## W40 — Port/D-Bus handshake dodge

Recognition: app probes the default Frida port or completes a D-Bus/WebSocket
handshake to fingerprint the server.
Steps: (1) move the server to a non-standard `--listen` port; (2) null-route
`connect` to the default port; (3) for handshake-spoof checks, pin the channel
(origin + certificate) so a fake-client probe fails closed; (4) verify with a
spawn-early attach (checks often run once at launch).
Pitfalls: port-hide alone fails against handshake-spoofing builds — combine
both; re-check after app updates (ports rotate per version).
Sources: https://github.com/aimardcr/FridaDetectionBypass ·
https://mas.owasp.org/MASTG/demos/ios/MASVS-RESILIENCE/MASTG-DEMO-0119/MASTG-DEMO-0119/ ·
https://github.com/zahidaz/awake/blob/main/docs/packers/tencent-legu.md

## W41 — Ptrace race win + Zygisk inject (watchdog duels)

Recognition: `ptrace` self-attach / `TracerPid` / watchdog thread kills the
process when a tracer appears; delayed hooks miss the check window.
Steps: (1) spawn (never attach) so hooks land before the watchdog starts;
(2) hook `ptrace` itself to fake success for self-attach calls;
(3) prefer Zygisk-borne injection (no ptrace event at all);
(4) for UnCrackable-style layered checks, bypass Java root checks first, then
win the native race with an early `strstr`/watchdog hook.
Pitfalls: attach-timing losses look like "hook doesn't work" — always retry as
spawn; one bypass is rarely enough (Java + native + watchdog stack).
Sources: https://github.com/snake-4/Zygisk-Assistant ·
https://mas.owasp.org/MASTG/demos/android/MASVS-RESILIENCE/MASTG-DEMO-0116/MASTG-DEMO-0116/ ·
https://medium.com/@mahmoudslama695/cracking-owasp-uncrackable-level-3-bypassing-anti-frida-and-watchdog-protections-on-android-a93c767daca8
