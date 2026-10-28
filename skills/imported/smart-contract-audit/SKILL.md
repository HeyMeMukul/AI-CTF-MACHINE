---
name: imported-smart-contract-audit
description: Run a fast Foundry/Slither/Echidna loop over a CTF contract and check the classic win-condition bugs.
category: blockchain
phase: exploit
source: https://github.com/trailofbits/skills/tree/main/plugins/building-secure-contracts/skills/secure-workflow-guide
license: CC-BY-SA-4.0
ctf_domains: [blockchain]
status: imported
---

# Smart-contract CTF audit loop (imported)

> Adapted for CTF use from [Trail of Bits](https://github.com/trailofbits/skills/tree/main/plugins/building-secure-contracts/skills/secure-workflow-guide). License: `CC-BY-SA-4.0`.
> Technique-only; no flags or target-specific data. Authorized CTF use only.

Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`.

## When to use

A blockchain challenge ships Solidity and a `isSolved()`/withdraw condition; you need a reproducible exploit test.

## Signals

- Solidity/Foundry project
- win condition
- proxy/upgrade
- external call
- oracle/price

## Preconditions

- contracts compile
- test/fork environment available

## CTF workflow

1. `forge build` and `forge test -vvv`; read the win condition and the constructor/initializer state.
2. Run `slither .` and `myth analyze` for a quick map; do not trust them as proof.
3. Check access control, reentrancy, delegatecall/proxy storage, integer rounding, oracle manipulation, signature replay, and initialization.
4. Write a failing Foundry test that demonstrates the win condition, then minimize it; use `cast`/anvil fork for live-state checks.

## Falsifier

No external call/value path, access control is correct, and the win condition is unreachable from the attacker role.

## Pitfalls

- proxy storage layout
- token decimals
- test-only backdoors
- fork block drift
- gas limits

## Source and license

- Source: https://github.com/trailofbits/skills/tree/main/plugins/building-secure-contracts/skills/secure-workflow-guide
- Author/team: Trail of Bits
- License: `CC-BY-SA-4.0`
- Imported: 2026-10-20; adapted summary, not a verbatim copy.
