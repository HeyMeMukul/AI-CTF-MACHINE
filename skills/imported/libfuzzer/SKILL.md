---
name: imported-libfuzzer
description: Turn a parser or input handler into an LLVMFuzzerTestOneInput harness and run a bounded libFuzzer campaign with ASan.
category: pwn
phase: exploit
source: https://github.com/trailofbits/skills/tree/main/plugins/testing-handbook-skills/skills/libfuzzer
license: CC-BY-SA-4.0
ctf_domains: [pwn, rev]
status: imported
---

# libFuzzer coverage-guided fuzzing (imported)

> Adapted for CTF use from [Trail of Bits](https://github.com/trailofbits/skills/tree/main/plugins/testing-handbook-skills/skills/libfuzzer). License: `CC-BY-SA-4.0`.
> Technique-only; no flags or target-specific data. Authorized CTF use only.

Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`.

## When to use

A C/C++ binary parses attacker-controlled bytes and you can compile it with Clang; or a CTF rev task exposes an input parser worth fuzzing.

## Signals

- C/C++ source available
- byte-oriented parser
- Clang toolchain
- need a crash or coverage

## Preconditions

- target compiles with clang
- a deterministic parse entry point exists

## CTF workflow

1. Write `extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)` around the parser; never read stdin or files in the harness.
2. Reject inputs below the minimum size and cap size so one input cannot allocate unbounded memory.
3. Build with `clang++ -fsanitize=fuzzer,address -fno-omit-frame-pointer -g -O1 harness.cc target.cc -o fuzz`.
4. Seed `corpus/` with valid samples and add a dictionary of protocol tokens; run `./fuzz corpus -max_total_time=300 -artifact_prefix=artifacts/`.
5. Reproduce and triage the first artifact with ASan; use `-minimize_crash=1` to shrink it before analysis.

## Falsifier

No new coverage after several minutes and no crash; the harness may not reach the parser or instrumentation is missing.

## Pitfalls

- harness reads a file/stdin instead of `data`
- leaks or `exit()` inside the harness
- no seed corpus
- unbounded loop on malformed input

## Source and license

- Source: https://github.com/trailofbits/skills/tree/main/plugins/testing-handbook-skills/skills/libfuzzer
- Author/team: Trail of Bits
- License: `CC-BY-SA-4.0`
- Imported: 2026-10-20; adapted summary, not a verbatim copy.
