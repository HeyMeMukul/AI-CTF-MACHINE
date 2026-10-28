# AFL++ multi-core fuzzing

Use AFL++ when libFuzzer is unavailable, you need persistent mode, or you want many cores mutating one harness.

- Use when: A CLI or library target can be instrumented with `afl-clang-fast`; you need multi-core fuzzing or a forkserver/persistent harness.
- Domains: pwn, rev
- Source: https://github.com/trailofbits/skills/tree/main/plugins/testing-handbook-skills/skills/aflpp
- Status: imported, source-verified (no CTF fixture yet)
