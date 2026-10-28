# AddressSanitizer crash triage

Build with ASan/UBSan and read the first sanitizer report to classify a memory-safety bug quickly.

- Use when: A crash or fuzz artifact needs a precise bug class (overflow, UAF, double-free, OOB) before exploit work.
- Domains: pwn, rev
- Source: https://github.com/trailofbits/skills/tree/main/plugins/testing-handbook-skills/skills/address-sanitizer
- Status: imported, source-verified (no CTF fixture yet)
