---
name: imported-heap-spray
description: Map the allocator, choose a spray size, and groom deterministic reuse before poisoning or overlapping.
category: pwn
phase: exploit
source: https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/analyzing-heap-spray-exploitation
license: Apache-2.0
ctf_domains: [pwn]
status: imported
---

# Heap grooming / spray for CTF pwn (imported)

> Adapted for CTF use from [Anthropic Cybersecurity Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/analyzing-heap-spray-exploitation). License: `Apache-2.0`.
> Technique-only; no flags or target-specific data. Authorized CTF use only.

Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`.

## When to use

A pwn challenge has a heap menu, UAF/overflow, and you need controlled layout rather than a lucky allocation.

## Signals

- alloc/free/edit/show menu
- UAF
- tcache/fastbin
- no leak
- heap overflow

## Preconditions

- glibc version known or discoverable
- a debugger with heap inspection (pwndbg/GEF)

## CTF workflow

1. Map every menu op to alloc/free/show/edit and record sizes; confirm `request2size` rounding in gdb.
2. Spray same-size chunks to fill tcache/bin state; use guard chunks so consolidation does not swallow the victim.
3. Groom LIFO order (free victim last) and verify the tcache head in `bins`/`vis_heap_chunks` before poisoning.
4. On glibc >= 2.32, encode the safe-linked fd with the true `next` field address; on >= 2.34 avoid dead hooks.

## Falsifier

No UAF/overflow or safe-linking plus a missing heap leak makes raw pointer poisoning crash.

## Pitfalls

- wrong glibc
- raw safe-link pointer
- tcache key/double-free checks
- alignment
- ASLR heap base

## Source and license

- Source: https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/analyzing-heap-spray-exploitation
- Author/team: Anthropic Cybersecurity Skills
- License: `Apache-2.0`
- Imported: 2026-10-20; adapted summary, not a verbatim copy.
