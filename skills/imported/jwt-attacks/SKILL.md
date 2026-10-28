---
name: imported-jwt-attacks
description: Test alg:none, RS256→HS256 confusion, weak HMAC secrets, kid injection, and jku/x5u trust.
category: web-ctf
phase: exploit
source: https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/testing-for-json-web-token-vulnerabilities
license: Apache-2.0
ctf_domains: [web-ctf]
status: imported
---

# JWT attack matrix (imported)

> Adapted for CTF use from [Anthropic Cybersecurity Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/testing-for-json-web-token-vulnerabilities). License: `Apache-2.0`.
> Technique-only; no flags or target-specific data. Authorized CTF use only.

Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`.

## When to use

A web challenge issues a JWT and the flag/admin path depends on a claim, role, or signature check.

## Signals

- JWT in cookie/header
- role/admin claim
- JWKS endpoint
- kid header
- weak secret hint

## Preconditions

- a valid token
- the verification behavior can be observed

## CTF workflow

1. Decode header/payload; note `alg`, `kid`, `jku`, `x5u`, `iss`, `aud`, and the claim that gates the flag.
2. Try `alg:none` (empty signature) and algorithm confusion: RS256 public key used as HS256 secret.
3. Crack a weak HMAC secret with `hashcat -m 16500 jwt.txt wordlist`; re-sign with the recovered key.
4. Test `kid` path traversal/SQLi, `jku`/`x5u` pointing at an attacker-controlled JWKS, and claim/audience abuse.
5. Verify the server accepts the forged token with one request; do not spray tokens.

## Falsifier

The library pins the algorithm, rejects `none`, validates `kid`/`jku`, and the secret is strong.

## Pitfalls

- library-specific alg handling
- public key format
- audience/issuer checks
- clock skew
- rate limits

## Source and license

- Source: https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/testing-for-json-web-token-vulnerabilities
- Author/team: Anthropic Cybersecurity Skills
- License: `Apache-2.0`
- Imported: 2026-10-20; adapted summary, not a verbatim copy.
