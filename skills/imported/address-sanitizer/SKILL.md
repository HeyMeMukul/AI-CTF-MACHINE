---
name: imported-address-sanitizer
description: Build with ASan/UBSan and read the first sanitizer report to classify a memory-safety bug quickly.
category: pwn
phase: exploit
source: https://github.com/trailofbits/skills/tree/main/plugins/testing-handbook-skills/skills/address-sanitizer
license: CC-BY-SA-4.0
ctf_domains: [pwn, rev]
status: imported
---

# AddressSanitizer crash triage (imported)

> Adapted for CTF use from [Trail of Bits](https://github.com/trailofbits/skills/tree/main/plugins/testing-handbook-skills/skills/address-sanitizer). License: `CC-BY-SA-4.0`.
> Technique-only; no flags or target-specific data. Authorized CTF use only.

Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`.

## When to use

A crash or fuzz artifact needs a precise bug class (overflow, UAF, double-free, OOB) before exploit work.

## Signals

- SIGSEGV or heap abort
- source available
- fuzz artifact
- need exact faulting access

## Preconditions

- target builds with Clang/GCC sanitizers
- symbols available

## CTF workflow

1. Rebuild `clang -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1`.
2. Run the reproducer with `ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=1`.
3. Read the FIRST error: access type, address, allocation/free stack, and the faulting frame.
4. Classify (OOB read/write, UAF, double-free, stack overflow) and keep the minimized input.

## Falsifier

A clean ASan run means only that this input did not trigger a memory error; it does not prove the code is safe.

## Pitfalls

- leak reports masking the real error
- optimization hiding the fault
- unsymbolized reports
- static libraries built without ASan

## Source and license

- Source: https://github.com/trailofbits/skills/tree/main/plugins/testing-handbook-skills/skills/address-sanitizer
- Author/team: Trail of Bits
- License: `CC-BY-SA-4.0`
- Imported: 2026-10-20; adapted summary, not a verbatim copy.
