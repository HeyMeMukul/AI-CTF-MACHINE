---
name: imported-android-apktool
description: Decompile an APK, inspect manifest/components/secrets, and hook runtime checks with Frida when needed.
category: mobile
phase: analyze
source: https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/analyzing-android-malware-with-apktool
license: Apache-2.0
ctf_domains: [mobile]
status: imported
---

# APK static + Frida triage (imported)

> Adapted for CTF use from [Anthropic Cybersecurity Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/analyzing-android-malware-with-apktool). License: `Apache-2.0`.
> Technique-only; no flags or target-specific data. Authorized CTF use only.

Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`.

## When to use

A mobile challenge ships an APK and the flag is behind a check, a hidden activity, or an embedded secret.

## Signals

- APK
- exported activity/service
- hardcoded URL/key
- native lib
- root/emulator check

## Preconditions

- apktool/jadx/Frida available
- authorized challenge app

## CTF workflow

1. `apktool d app.apk -o out` and `jadx -d out-jadx app.apk`; read `AndroidManifest.xml` for exported components and permissions.
2. Grep for URLs, API keys, `firebase`, `flag`, and native library names; inspect `lib/*/` with `strings`.
3. Open exported components with `adb shell am start`; check `adb logcat` for leaked data.
4. Hook checks with `frida -U -f <pkg> -l hook.js` or `objection`; bypass root/emulator/pinning only in the challenge app.

## Falsifier

No exported component/secret and runtime checks pass with a legitimate flow; the flag may require a server interaction.

## Pitfalls

- split APKs
- native packing
- SSL pinning
- emulator detection
- obfuscation

## Source and license

- Source: https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/analyzing-android-malware-with-apktool
- Author/team: Anthropic Cybersecurity Skills
- License: `Apache-2.0`
- Imported: 2026-10-20; adapted summary, not a verbatim copy.
