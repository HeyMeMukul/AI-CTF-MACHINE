---
name: imported-pcap-wireshark
description: Turn a packet capture into protocol hierarchy, conversations, exported objects, and the one stream that matters.
category: forensics
phase: exploit
source: https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/analyzing-network-traffic-with-wireshark
license: Apache-2.0
ctf_domains: [forensics]
status: imported
---

# PCAP triage with tshark/Wireshark (imported)

> Adapted for CTF use from [Anthropic Cybersecurity Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/analyzing-network-traffic-with-wireshark). License: `Apache-2.0`.
> Technique-only; no flags or target-specific data. Authorized CTF use only.

Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`.

## When to use

A forensics challenge ships `.pcap`/`.pcapng` and the flag is in HTTP objects, credentials, DNS, or a TCP stream.

## Signals

- pcap
- HTTP/TLS/DNS
- file transfer
- credentials
- covert channel

## Preconditions

- tshark/Wireshark available

## CTF workflow

1. `capinfos capture.pcap` and `tshark -r capture.pcap -q -z io,phs` for protocols and volume.
2. `tshark -r capture.pcap -Y http -T fields -e http.host -e http.request.uri`; export objects with `--export-objects http,out`.
3. Find the relevant conversation with `-z conv,tcp`; follow it with `-z follow,tcp,ascii,<stream>`.
4. Check DNS/TLS metadata, credentials in FTP/POP/SMTP, and unusual ports; carve files from streams if needed.

## Falsifier

The capture is fully encrypted and no keys/metadata are present; protocol analysis alone will not recover plaintext.

## Pitfalls

- TCP reassembly
- truncated captures
- VLAN/encapsulation
- TLS 1.3
- export-object name collisions

## Source and license

- Source: https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/analyzing-network-traffic-with-wireshark
- Author/team: Anthropic Cybersecurity Skills
- License: `Apache-2.0`
- Imported: 2026-10-20; adapted summary, not a verbatim copy.
