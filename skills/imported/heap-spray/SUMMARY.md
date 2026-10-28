# Heap grooming / spray for CTF pwn

Map the allocator, choose a spray size, and groom deterministic reuse before poisoning or overlapping.

- Use when: A pwn challenge has a heap menu, UAF/overflow, and you need controlled layout rather than a lucky allocation.
- Domains: pwn
- Source: https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/analyzing-heap-spray-exploitation
- Status: imported, source-verified (no CTF fixture yet)
