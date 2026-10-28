---
name: imported-aflpp
description: Use AFL++ when libFuzzer is unavailable, you need persistent mode, or you want many cores mutating one harness.
category: pwn
phase: exploit
source: https://github.com/trailofbits/skills/tree/main/plugins/testing-handbook-skills/skills/aflpp
license: CC-BY-SA-4.0
ctf_domains: [pwn, rev]
status: imported
---

# AFL++ multi-core fuzzing (imported)

> Adapted for CTF use from [Trail of Bits](https://github.com/trailofbits/skills/tree/main/plugins/testing-handbook-skills/skills/aflpp). License: `CC-BY-SA-4.0`.
> Technique-only; no flags or target-specific data. Authorized CTF use only.

Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`.

## When to use

A CLI or library target can be instrumented with `afl-clang-fast`; you need multi-core fuzzing or a forkserver/persistent harness.

## Signals

- C/C++ target
- AFL++ installable
- multi-core run
- persistent-mode opportunity

## Preconditions

- target builds with afl-clang-fast
- a `@@` file or stdin input contract

## CTF workflow

1. Build `AFL_USE_ASAN=1 afl-clang-fast -g -O1 harness.c -o harness` (or instrument the target with `afl-clang-lto`).
2. Create `in/` seeds; run `afl-fuzz -i in -o out -m none -- ./harness @@` with ASan memory limits disabled.
3. Add persistent mode with `__AFL_LOOP(1000)` around the parse call for a large speedup.
4. After discovery, run `afl-cmin -i out/default/queue -o cmin -- ./harness @@` and `afl-tmin` on the crash.

## Falsifier

No paths after 10 minutes or `afl-fuzz` reports the target is not instrumented.

## Pitfalls

- ASan plus a small `-m` limit
- core_pattern unreadable
- CPU governor warnings
- harness re-execs per input instead of forkserver

## Source and license

- Source: https://github.com/trailofbits/skills/tree/main/plugins/testing-handbook-skills/skills/aflpp
- Author/team: Trail of Bits
- License: `CC-BY-SA-4.0`
- Imported: 2026-10-20; adapted summary, not a verbatim copy.
