---
name: imported-differential-review
description: Diff two versions to find the security-relevant change: new sink, missing check, authz change, or patched bug.
category: rev
phase: analyze
source: https://github.com/trailofbits/skills/tree/main/plugins/differential-review/skills/differential-review
license: CC-BY-SA-4.0
ctf_domains: [rev, web-ctf]
status: imported
---

# Differential review / patch diffing (imported)

> Adapted for CTF use from [Trail of Bits](https://github.com/trailofbits/skills/tree/main/plugins/differential-review/skills/differential-review). License: `CC-BY-SA-4.0`.
> Technique-only; no flags or target-specific data. Authorized CTF use only.

Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`.

## When to use

A CTF gives source/binary versions, a patch, or a commit range; or you want to infer the intended bug from a fix.

## Signals

- two versions
- patch file
- commit range
- binary diff

## Preconditions

- base and patched artifacts
- enough symbols/strings to align

## CTF workflow

1. For source: `git diff base..head --stat` then read only hunks touching parsing, auth, crypto, allocation, or IPC.
2. Trace new/changed dataflow to a sink; check whether a check was added or removed.
3. For binaries: `radiff2 -C a b`, `diaphora`/`bindiff`, or Ghidra version tracking; focus on changed functions.
4. Write the vulnerability hypothesis as: input → changed path → missing check → impact.

## Falsifier

The diff is cosmetic/refactor only and no changed path reaches a security-relevant sink.

## Pitfalls

- generated/vendored code
- patch obfuscation
- different build flags
- renamed symbols

## Source and license

- Source: https://github.com/trailofbits/skills/tree/main/plugins/differential-review/skills/differential-review
- Author/team: Trail of Bits
- License: `CC-BY-SA-4.0`
- Imported: 2026-10-20; adapted summary, not a verbatim copy.
