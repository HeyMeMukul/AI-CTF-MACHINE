---
name: imported-firebase-apk-scanner
description: Decompile an APK, extract Firebase/Google config and exported components, then test the backend rules.
category: mobile
phase: exploit
source: https://github.com/trailofbits/skills/tree/main/plugins/firebase-apk-scanner/skills/firebase-apk-scanner
license: CC-BY-SA-4.0
ctf_domains: [mobile, web-ctf]
status: imported
---

# Android APK / Firebase misconfiguration (imported)

> Adapted for CTF use from [Trail of Bits](https://github.com/trailofbits/skills/tree/main/plugins/firebase-apk-scanner/skills/firebase-apk-scanner). License: `CC-BY-SA-4.0`.
> Technique-only; no flags or target-specific data. Authorized CTF use only.

Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`.

## When to use

A mobile challenge ships an APK and the flag or auth flow depends on Firebase, exported activities, or embedded keys.

## Signals

- APK
- google-services.json
- firebaseio.com/firebaseapp.com
- exported component
- hardcoded API key

## Preconditions

- APK available
- authorized CTF target

## CTF workflow

1. `apktool d app.apk -o out` and `jadx -d out-jadx app.apk`; read `AndroidManifest.xml` for exported components and permissions.
2. Grep for `google-services.json`, `firebaseio.com`, `firebaseapp.com`, `storage.googleapis.com`, `AIza`, and custom URLs.
3. Check Firebase database/storage rules with a read-only request; do not write unless the challenge explicitly allows it.
4. Trace the auth/flag path in jadx; hook runtime checks with Frida/objection only if static analysis is insufficient.

## Falsifier

No Firebase config, no exported component, and the backend rejects unauthenticated reads.

## Pitfalls

- API key restrictions
- split APKs
- native libs
- SSL pinning
- staging projects

## Source and license

- Source: https://github.com/trailofbits/skills/tree/main/plugins/firebase-apk-scanner/skills/firebase-apk-scanner
- Author/team: Trail of Bits
- License: `CC-BY-SA-4.0`
- Imported: 2026-10-20; adapted summary, not a verbatim copy.
