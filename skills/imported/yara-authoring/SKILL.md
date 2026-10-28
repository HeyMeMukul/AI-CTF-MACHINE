---
name: imported-yara-authoring
description: Write a narrow YARA rule from unique strings/byte patterns and validate it against positive and benign samples.
category: forensics
phase: exploit
source: https://github.com/trailofbits/skills/tree/main/plugins/yara-authoring/skills/yara-rule-authoring
license: CC-BY-SA-4.0
ctf_domains: [forensics, rev]
status: imported
---

# YARA rule authoring for artifacts (imported)

> Adapted for CTF use from [Trail of Bits](https://github.com/trailofbits/skills/tree/main/plugins/yara-authoring/skills/yara-rule-authoring). License: `CC-BY-SA-4.0`.
> Technique-only; no flags or target-specific data. Authorized CTF use only.

Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`.

## When to use

A forensics/malware challenge gives a memory dump, disk image, or sample set and you need to locate a family or marker.

## Signals

- memory/disk image
- multiple samples
- need to locate a pattern
- known family marker

## Preconditions

- at least one positive sample
- a benign corpus for false-positive testing

## CTF workflow

1. Extract unique strings and byte sequences with `strings`, `xxd`, and a hex editor; prefer long, specific patterns.
2. Write `rule name { meta: ... strings: $a = "..." condition: uint16(0) == 0x5a4d and all of them }`.
3. Test `yara -r rule.yar samples/` and a benign corpus; tighten until only positives match.
4. Scan the memory/disk image with `yara -r -s rule.yar image.raw` and record offsets.

## Falsifier

The rule matches benign samples or misses the known positive; it is not specific enough.

## Pitfalls

- common strings
- packed/encoded samples
- case sensitivity
- hex wildcards too broad

## Source and license

- Source: https://github.com/trailofbits/skills/tree/main/plugins/yara-authoring/skills/yara-rule-authoring
- Author/team: Trail of Bits
- License: `CC-BY-SA-4.0`
- Imported: 2026-10-20; adapted summary, not a verbatim copy.
