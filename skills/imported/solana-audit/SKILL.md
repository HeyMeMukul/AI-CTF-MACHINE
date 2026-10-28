---
name: imported-solana-audit
description: Check Solana programs for missing signer/owner checks, PDA collisions, arbitrary CPI, and reinitialization bugs.
category: blockchain
phase: exploit
source: https://github.com/trailofbits/skills/tree/main/plugins/building-secure-contracts/skills/solana-vulnerability-scanner
license: CC-BY-SA-4.0
ctf_domains: [blockchain]
status: imported
---

# Solana program audit (imported)

> Adapted for CTF use from [Trail of Bits](https://github.com/trailofbits/skills/tree/main/plugins/building-secure-contracts/skills/solana-vulnerability-scanner). License: `CC-BY-SA-4.0`.
> Technique-only; no flags or target-specific data. Authorized CTF use only.

Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`.

## When to use

A blockchain challenge ships an Anchor/Solana program and a win condition; you need the account-validation flaw.

## Signals

- Anchor/Solana program
- PDA seeds
- CPI
- #[account]
- win condition

## Preconditions

- Rust/Anchor toolchain
- local validator or program source

## CTF workflow

1. `anchor build` / `cargo build-sbf`, then `anchor test`; read every `#[account(...)]` constraint and the win condition.
2. Check signer/owner checks: is `authority` a `Signer`? Is the program-owned account validated? Can an attacker pass a fake account?
3. Check PDA seeds/bump canonicalization and collisions; pre-create an account to make a victim `init` fail.
4. Check CPI: target program id, account metas, signer seeds, and whether arbitrary CPI can be induced.
5. Check reinit/close/rent and integer/lamport math; reproduce with a local validator test.

## Falsifier

All accounts are signer/owner/seed-validated and the win condition is unreachable from the attacker role.

## Pitfalls

- account confusion
- missing signer
- PDA collision
- arbitrary CPI
- reinit
- rent/lamports

## Source and license

- Source: https://github.com/trailofbits/skills/tree/main/plugins/building-secure-contracts/skills/solana-vulnerability-scanner
- Author/team: Trail of Bits
- License: `CC-BY-SA-4.0`
- Imported: 2026-10-20; adapted summary, not a verbatim copy.
