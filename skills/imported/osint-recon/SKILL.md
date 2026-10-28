---
name: imported-osint-recon
description: Scope a fictional CTF persona/domain with public sources: DNS, certificates, archives, handles, and metadata.
category: osint
phase: recon
source: https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/conducting-external-reconnaissance-with-osint
license: Apache-2.0
ctf_domains: [osint]
status: imported
---

# OSINT external recon (imported)

> Adapted for CTF use from [Anthropic Cybersecurity Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/conducting-external-reconnaissance-with-osint). License: `Apache-2.0`.
> Technique-only; no flags or target-specific data. Authorized CTF use only.

Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`.

## When to use

An OSINT challenge provides a handle, domain, image, or organization and expects a public-source answer.

## Signals

- username/handle
- domain
- email
- photo
- organization
- social profile

## Preconditions

- challenge defines the allowed public sources
- only fictional CTF personas/data

## CTF workflow

1. Pivot on the exact identifier: `whois`, DNS (`dig`), `crt.sh`, `subfinder`, and passive DNS/archive sources.
2. Search the handle across platforms with `sherlock`/`maigret`; check profile metadata, avatars, and reused usernames.
3. Use the Wayback Machine and Google/Bing dorks for deleted pages, documents, and exposed metadata.
4. Corroborate every answer with at least two independent sources; do not contact real people or bypass logins.

## Falsifier

No public record links the identifier to the requested fact, or the only source is an unverified snippet.

## Pitfalls

- common-handle collisions
- dated archives
- AI-generated profiles
- privacy/ToS limits
- single-source answers

## Source and license

- Source: https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/conducting-external-reconnaissance-with-osint
- Author/team: Anthropic Cybersecurity Skills
- License: `Apache-2.0`
- Imported: 2026-10-20; adapted summary, not a verbatim copy.
