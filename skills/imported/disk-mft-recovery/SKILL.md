---
name: imported-disk-mft-recovery
description: Mount/inspect a disk image, parse the MFT or filesystem, and recover the deleted or slack-resident flag.
category: forensics
phase: exploit
source: https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/analyzing-mft-for-deleted-file-recovery
license: Apache-2.0
ctf_domains: [forensics]
status: imported
---

# Disk image / MFT and deleted-file recovery (imported)

> Adapted for CTF use from [Anthropic Cybersecurity Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/analyzing-mft-for-deleted-file-recovery). License: `Apache-2.0`.
> Technique-only; no flags or target-specific data. Authorized CTF use only.

Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`.

## When to use

A forensics challenge ships a disk image and the flag was deleted, hidden in slack, or stored in an alternate data stream.

## Signals

- `.img`/`.dd`/`.E01`
- NTFS/ext4
- deleted file
- MFT/$UsnJrnl
- slack space

## Preconditions

- Sleuth Kit/ewf tools available
- image integrity confirmed

## CTF workflow

1. `ewfmount image.E01 /mnt/ewf` (if E01) then `mmls`, `fsstat`, and `fls -r -p` on the partition offset.
2. Recover inodes with `icat`/`tsk_recover`; parse `$MFT` with `MFTECmd`/`analyzeMFT` and check `$UsnJrnl` for deletions.
3. Carve unallocated space with `photorec`/`foremost`; inspect slack with `blkls`/`icat`.
4. Build a timeline (`plaso`/`log2timeline`) only if the flag depends on when a file was deleted.

## Falsifier

The filesystem is encrypted or the image is incomplete; carving cannot recover plaintext.

## Pitfalls

- partition offset
- deleted inode reuse
- timestamps in UTC
- compressed/encrypted volumes
- E01 segment order

## Source and license

- Source: https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/analyzing-mft-for-deleted-file-recovery
- Author/team: Anthropic Cybersecurity Skills
- License: `Apache-2.0`
- Imported: 2026-10-20; adapted summary, not a verbatim copy.
