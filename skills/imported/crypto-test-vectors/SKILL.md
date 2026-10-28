---
name: imported-crypto-test-vectors
description: Use Wycheproof vectors and property-based tests to distinguish a real crypto implementation from a lookalike.
category: crypto
phase: validate
source: https://github.com/trailofbits/skills/tree/main/plugins/testing-handbook-skills/skills/wycheproof
license: CC-BY-SA-4.0
ctf_domains: [crypto]
status: imported
---

# Crypto test vectors / property tests (imported)

> Adapted for CTF use from [Trail of Bits](https://github.com/trailofbits/skills/tree/main/plugins/testing-handbook-skills/skills/wycheproof). License: `CC-BY-SA-4.0`.
> Technique-only; no flags or target-specific data. Authorized CTF use only.

Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`.

## When to use

A crypto challenge gives an implementation/API and you need to know whether it enforces a primitive correctly.

## Signals

- custom crypto
- verify/decrypt API
- edge cases
- test vectors
- property oracle

## Preconditions

- local implementation or API
- vector set or property to test

## CTF workflow

1. Load Wycheproof JSON for the primitive; run every vector and compare accept/reject, not just success cases.
2. Add property tests: round-trip, boundary values (0, n-1, max), malformed lengths, and nonce/IV reuse.
3. For a live oracle, batch queries within rate limits and record the exact input/response.
4. Treat a single passing vector as insufficient; require the full edge-case set or a reproducible property violation.

## Falsifier

All vectors and properties pass; the primitive is correctly implemented and the bug is elsewhere.

## Pitfalls

- harness bugs
- vector version mismatch
- only happy-path tests
- timing/rate limits
- encoding differences

## Source and license

- Source: https://github.com/trailofbits/skills/tree/main/plugins/testing-handbook-skills/skills/wycheproof
- Author/team: Trail of Bits
- License: `CC-BY-SA-4.0`
- Imported: 2026-10-20; adapted summary, not a verbatim copy.
