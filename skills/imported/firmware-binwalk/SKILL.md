---
name: imported-firmware-binwalk
description: Identify a firmware container, carve embedded filesystems, and inspect init scripts, credentials, and update logic.
category: hardware
phase: analyze
source: https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/performing-firmware-extraction-with-binwalk
license: Apache-2.0
ctf_domains: [hardware, forensics]
status: imported
---

# Firmware extraction (binwalk/entropy) (imported)

> Adapted for CTF use from [Anthropic Cybersecurity Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/performing-firmware-extraction-with-binwalk). License: `Apache-2.0`.
> Technique-only; no flags or target-specific data. Authorized CTF use only.

Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`.

## When to use

A hardware/IoT challenge ships a `.bin`/`.img`/firmware update and the flag is inside an embedded filesystem or init script.

## Signals

- firmware blob
- squashfs/cramfs
- uImage/TRX
- update package
- UART hint

## Preconditions

- binwalk and filesystem tools available
- artifact is a copy, not a live device

## CTF workflow

1. `file`, `binwalk firmware.bin`, and `binwalk -E` entropy to find compressed/encrypted regions.
2. `binwalk -e --run-as=root firmware.bin` (in a sandbox) to carve; inspect offsets with `dd`/`xxd` if extraction fails.
3. Mount/extract squashfs/cramfs/jffs2, then grep `/etc/init.d`, `rcS`, web roots, and shadow/passwd for credentials.
4. Check update signatures/keys and hardcoded URLs; if a device is in scope, confirm UART/JTAG access rules before touching hardware.

## Falsifier

Entropy is uniform and no filesystem/update format is recognized; the blob may be encrypted or truncated.

## Pitfalls

- encrypted firmware
- vendor-specific containers
- squashfs version
- running extraction as root on host
- destructive flash writes

## Source and license

- Source: https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/performing-firmware-extraction-with-binwalk
- Author/team: Anthropic Cybersecurity Skills
- License: `Apache-2.0`
- Imported: 2026-10-20; adapted summary, not a verbatim copy.
