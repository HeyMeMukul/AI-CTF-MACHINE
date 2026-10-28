---
name: imported-windows-artifacts
description: Parse registry hives, prefetch, event logs, USB history, browser databases, and shellbags into one timeline.
category: forensics
phase: exploit
source: https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/analyzing-windows-registry-for-artifacts
license: Apache-2.0
ctf_domains: [forensics]
status: imported
---

# Windows artifact forensics (imported)

> Adapted for CTF use from [Anthropic Cybersecurity Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/analyzing-windows-registry-for-artifacts). License: `Apache-2.0`.
> Technique-only; no flags or target-specific data. Authorized CTF use only.

Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`.

## When to use

A forensics challenge ships a Windows disk/memory image or registry hives and asks what ran, who logged in, or what device connected.

## Signals

- NTUSER.DAT/SAM/SYSTEM/SOFTWARE
- .pf prefetch
- .evtx
- UsrClass.dat
- browser History
- USB device

## Preconditions

- Windows image or hive copies
- Eric Zimmerman tools / regripper / Hindsight available

## CTF workflow

1. Identify hives and artifacts: `NTUSER.DAT`, `UsrClass.dat`, SAM/SYSTEM/SOFTWARE, `.pf`, `.evtx`, browser DBs, `$MFT`.
2. Registry: `RECmd` or `regripper -f NTUSER.DAT -r ntuser`; check Run keys, UserAssist, RecentDocs, USBSTOR, ShellBags.
3. Execution: `PECmd` for prefetch, `AmcacheParser`/`AppCompatCacheParser` for program execution, `JLECmd`/`LECmd` for jump lists.
4. Event logs: `EvtxECmd`/`hayabusa` for logons, service installs, PowerShell, and USB; browser: `Hindsight` for history/downloads.
5. Merge timestamps into a timeline (UTC) and correlate the artifact that answers the challenge question.

## Falsifier

The image is not Windows, the hives are encrypted/corrupt, or no user artifact exists for the asked event.

## Pitfalls

- locked hives (use copies + .LOG1/.LOG2)
- local vs UTC
- system vs user hive
- deleted-user hives
- timestamp precision

## Source and license

- Source: https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/analyzing-windows-registry-for-artifacts
- Author/team: Anthropic Cybersecurity Skills
- License: `Apache-2.0`
- Imported: 2026-10-20; adapted summary, not a verbatim copy.
