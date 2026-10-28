# UPX / packed binary unpacking

Detect UPX/modified-UPX packing, restore the magic/headers, and unpack to a static binary for analysis.

- Use when: A rev/forensics binary has high entropy, a tiny import table, or UPX markers and strings/decompiler output looks empty.
- Domains: rev
- Source: https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/analyzing-packed-malware-with-upx-unpacker
- Status: imported, source-verified (no CTF fixture yet)
