# libFuzzer coverage-guided fuzzing

Turn a parser or input handler into an LLVMFuzzerTestOneInput harness and run a bounded libFuzzer campaign with ASan.

- Use when: A C/C++ binary parses attacker-controlled bytes and you can compile it with Clang; or a CTF rev task exposes an input parser worth fuzzing.
- Domains: pwn, rev
- Source: https://github.com/trailofbits/skills/tree/main/plugins/testing-handbook-skills/skills/libfuzzer
- Status: imported, source-verified (no CTF fixture yet)
