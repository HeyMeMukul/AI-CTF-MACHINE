---
name: imported-ethereum-contracts
description: A fast EVM checklist: reentrancy, access control, delegatecall/proxy, integer/rounding, oracle, signature replay, and initialization.
category: blockchain
phase: exploit
source: https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/analyzing-ethereum-smart-contract-vulnerabilities
license: Apache-2.0
ctf_domains: [blockchain]
status: imported
---

# EVM smart-contract vulnerability classes (imported)

> Adapted for CTF use from [Anthropic Cybersecurity Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/analyzing-ethereum-smart-contract-vulnerabilities). License: `Apache-2.0`.
> Technique-only; no flags or target-specific data. Authorized CTF use only.

Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`.

## When to use

A CTF ships an EVM contract and a `isSolved()` condition; you need the shortest path from attacker role to win state.

## Signals

- Solidity
- EVM
- win condition
- proxy
- external call
- signature

## Preconditions

- contract source or bytecode
- Foundry/anvil or a fork RPC

## CTF workflow

1. Identify the Solidity version, constructor/initializer, owner/role checks, and the exact win condition.
2. Trace every external call and value transfer; check reentrancy and `delegatecall`/proxy storage collisions.
3. Check integer rounding/decimals, oracle/price assumptions, signature replay/nonce, and uninitialized implementation.
4. Reproduce with a Foundry test or `cast` against anvil; minimize to one transaction path.

## Falsifier

No external call/value path, correct access control, and the win condition is unreachable from the attacker role.

## Pitfalls

- proxy storage layout
- token decimals
- fork block drift
- gas limits
- test-only backdoors

## Source and license

- Source: https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/analyzing-ethereum-smart-contract-vulnerabilities
- Author/team: Anthropic Cybersecurity Skills
- License: `Apache-2.0`
- Imported: 2026-10-20; adapted summary, not a verbatim copy.
