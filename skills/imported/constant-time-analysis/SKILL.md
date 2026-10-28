---
name: imported-constant-time-analysis
description: Look for secret-dependent branches, divisions, early-exit comparisons, and table lookups in compiled crypto code.
category: crypto
phase: analyze
source: https://github.com/trailofbits/skills/tree/main/plugins/constant-time-analysis/skills/constant-time-analysis
license: CC-BY-SA-4.0
ctf_domains: [crypto]
status: imported
---

# Constant-time / timing side-channel review (imported)

> Adapted for CTF use from [Trail of Bits](https://github.com/trailofbits/skills/tree/main/plugins/constant-time-analysis/skills/constant-time-analysis). License: `CC-BY-SA-4.0`.
> Technique-only; no flags or target-specific data. Authorized CTF use only.

Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`.

## When to use

A CTF crypto service compares tags/keys in variable time, uses division on secrets, or exposes a timing oracle.

## Signals

- `memcmp`/`strcmp` on a secret
- division/modulo by secret
- secret-indexed table
- timing oracle in a service

## Preconditions

- crypto code or binary available
- a timing oracle can be measured or inferred

## CTF workflow

1. Compile/disassemble at the target optimization level; look for `div`/`idiv`, secret-dependent jumps, and early-exit compares.
2. Identify which flagged operations actually touch key/nonce/plaintext material; ignore public-only arithmetic.
3. Replace with constant-time primitives (branchless select, fixed-time compare, precomputed tables) and re-check at more than one opt level/arch.
4. If measuring, use dudect/ctgrind with many samples; treat small deltas as noise until statistically stable.

## Falsifier

All secret-dependent operations are branchless/fixed-time and timing variance stays within noise across runs.

## Pitfalls

- compiler strength-reduces a constant divisor
- cache/JIT effects invisible in asm
- measuring on a noisy host
- optimizing only one architecture

## Source and license

- Source: https://github.com/trailofbits/skills/tree/main/plugins/constant-time-analysis/skills/constant-time-analysis
- Author/team: Trail of Bits
- License: `CC-BY-SA-4.0`
- Imported: 2026-10-20; adapted summary, not a verbatim copy.
