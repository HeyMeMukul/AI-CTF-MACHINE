---
name: imported-upx-unpack
description: Detect UPX/modified-UPX packing, restore the magic/headers, and unpack to a static binary for analysis.
category: rev
phase: analyze
source: https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/analyzing-packed-malware-with-upx-unpacker
license: Apache-2.0
ctf_domains: [rev]
status: imported
---

# UPX / packed binary unpacking (imported)

> Adapted for CTF use from [Anthropic Cybersecurity Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/analyzing-packed-malware-with-upx-unpacker). License: `Apache-2.0`.
> Technique-only; no flags or target-specific data. Authorized CTF use only.

Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`.

## When to use

A rev/forensics binary has high entropy, a tiny import table, or UPX markers and strings/decompiler output looks empty.

## Signals

- high entropy
- UPX! marker
- tiny IAT
- packed section
- anti-unpack

## Preconditions

- binary copy
- UPX and a debugger
- sandbox for execution

## CTF workflow

1. `file`, `readelf -S`, `strings | grep UPX`, and `upx -l binary`; check section names/entropy.
2. Try `upx -d binary -o unpacked`; if the magic is modified, restore `UPX!` at the header offset and retry.
3. If UPX is not the packer, run in the sandbox and dump at the original entry point (OEP) after the unpacking stub.
4. Re-run `readelf`/`strings`/Ghidra on the unpacked image; verify the entry point and imports are sane.

## Falsifier

The binary is not packed, or it is packed with a custom protector that needs dynamic unpacking.

## Pitfalls

- modified UPX magic
- anti-debug
- static linking
- wrong architecture
- running on host

## Source and license

- Source: https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/analyzing-packed-malware-with-upx-unpacker
- Author/team: Anthropic Cybersecurity Skills
- License: `Apache-2.0`
- Imported: 2026-10-20; adapted summary, not a verbatim copy.
