---
name: imported-memory-volatility
description: Profile a RAM dump, enumerate processes/network/injected code, and dump the artifact that carries the flag.
category: forensics
phase: exploit
source: https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/analyzing-memory-dumps-with-volatility
license: Apache-2.0
ctf_domains: [forensics]
status: imported
---

# Volatility 3 memory forensics (imported)

> Adapted for CTF use from [Anthropic Cybersecurity Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/analyzing-memory-dumps-with-volatility). License: `Apache-2.0`.
> Technique-only; no flags or target-specific data. Authorized CTF use only.

Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`.

## When to use

A forensics challenge ships a `.raw`/`.mem`/`.dmp` image and asks about processes, connections, or injected code.

## Signals

- memory dump
- windows/linux
- process injection
- credentials
- hidden process

## Preconditions

- Volatility 3 installed
- symbols available for the OS build

## CTF workflow

1. `vol -f mem.raw windows.info` (or `linux.pslist`) to identify the OS/profile; download matching symbols if needed.
2. `windows.pslist`, `pstree`, `psscan`, `cmdline`, `netscan`, `malfind`, `dlllist`, `handles`; compare pslist vs psscan for hidden processes.
3. Dump suspicious processes/files with `--dump`/`dumpfiles`; extract strings and scan with YARA.
4. For Linux use `linux.pslist`, `linux.bash`, `linux.malfind`, `linux.lsmod`, and `linux.netfilter`.

## Falsifier

Wrong profile/symbols produce empty plugin output; confirm the OS build before concluding the dump is clean.

## Pitfalls

- symbol mismatch
- huge dumps
- encrypted/compressed memory
- plugin version drift

## Source and license

- Source: https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/analyzing-memory-dumps-with-volatility
- Author/team: Anthropic Cybersecurity Skills
- License: `Apache-2.0`
- Imported: 2026-10-20; adapted summary, not a verbatim copy.
