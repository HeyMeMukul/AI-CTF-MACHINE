# Constant-time / timing side-channel review

Look for secret-dependent branches, divisions, early-exit comparisons, and table lookups in compiled crypto code.

- Use when: A CTF crypto service compares tags/keys in variable time, uses division on secrets, or exposes a timing oracle.
- Domains: crypto
- Source: https://github.com/trailofbits/skills/tree/main/plugins/constant-time-analysis/skills/constant-time-analysis
- Status: imported, source-verified (no CTF fixture yet)
