---
name: imported-harness-writing
description: Design a deterministic, fast, leak-free harness that reaches the code you actually want to test.
category: pwn
phase: exploit
source: https://github.com/trailofbits/skills/tree/main/plugins/testing-handbook-skills/skills/harness-writing
license: CC-BY-SA-4.0
ctf_domains: [pwn, rev]
status: imported
---

# Fuzzing harness design (imported)

> Adapted for CTF use from [Trail of Bits](https://github.com/trailofbits/skills/tree/main/plugins/testing-handbook-skills/skills/harness-writing). License: `CC-BY-SA-4.0`.
> Technique-only; no flags or target-specific data. Authorized CTF use only.

Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`.

## When to use

You have a target library/function and need to turn raw fuzzer bytes into its arguments without bypassing the parser.

## Signals

- target API identified
- raw bytes must become structured input
- fuzzer finds nothing

## Preconditions

- the target entry point is callable in-process
- state can be reset per input

## CTF workflow

1. Identify the deepest stable entry point after initialization; call it, not `main`, when possible.
2. Map bytes to arguments deterministically; initialize all structs and reset globals per input.
3. Cap input size, avoid file/network I/O, and return 0 for invalid inputs instead of aborting.
4. Compile with a sanitizer and verify one valid seed reaches the target with a temporary print or breakpoint.

## Falsifier

The harness crashes on a known-valid seed, returns before the target, or produces non-deterministic behavior.

## Pitfalls

- consuming stdin
- global state across iterations
- abort on parse errors
- unbounded loops
- not resetting the allocator

## Source and license

- Source: https://github.com/trailofbits/skills/tree/main/plugins/testing-handbook-skills/skills/harness-writing
- Author/team: Trail of Bits
- License: `CC-BY-SA-4.0`
- Imported: 2026-10-20; adapted summary, not a verbatim copy.
