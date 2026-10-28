# Fuzzing harness design

Design a deterministic, fast, leak-free harness that reaches the code you actually want to test.

- Use when: You have a target library/function and need to turn raw fuzzer bytes into its arguments without bypassing the parser.
- Domains: pwn, rev
- Source: https://github.com/trailofbits/skills/tree/main/plugins/testing-handbook-skills/skills/harness-writing
- Status: imported, source-verified (no CTF fixture yet)
