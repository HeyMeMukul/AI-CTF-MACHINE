---
name: imported-ios-assessment
description: Inspect an iOS app bundle, entitlements, keychain/NSUserDefaults, and runtime checks with Frida/objection.
category: mobile
phase: analyze
source: https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/performing-ios-app-security-assessment
license: Apache-2.0
ctf_domains: [mobile]
status: imported
---

# iOS app static + Frida assessment (imported)

> Adapted for CTF use from [Anthropic Cybersecurity Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/performing-ios-app-security-assessment). License: `Apache-2.0`.
> Technique-only; no flags or target-specific data. Authorized CTF use only.

Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`.

## When to use

A mobile challenge ships an IPA/app bundle and the flag is behind a local check, keychain entry, or pinning/anti-jailbreak gate.

## Signals

- IPA/app bundle
- Mach-O
- entitlements
- keychain
- jailbreak/pinning check

## Preconditions

- jailbroken device or corellium/emulator
- Frida/objection, otool, plutil, class-dump

## CTF workflow

1. Unzip the IPA; `plutil -p Info.plist`, `codesign -d --entitlements`, `otool -l` for linked libs and encryption (`cryptid`).
2. Dump classes with `class-dump`/`jtool2`; search strings for URLs, keys, `flag`, and `NSUserDefaults`/keychain usage.
3. Run `frida-ps -U` and `objection -g <bundle> explore`; hook `NSUserDefaults`, keychain, and the success check.
4. Bypass jailbreak/pinning only in the challenge app with Frida scripts; confirm the hook fires before trusting the result.

## Falsifier

The binary is FairPlay-encrypted, no runtime access is available, and static strings show no local secret.

## Pitfalls

- App Store encryption
- arm64e
- Swift name mangling
- jailbreak detection
- pinning
- keychain access groups

## Source and license

- Source: https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/performing-ios-app-security-assessment
- Author/team: Anthropic Cybersecurity Skills
- License: `Apache-2.0`
- Imported: 2026-10-20; adapted summary, not a verbatim copy.
