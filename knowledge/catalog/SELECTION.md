# Imported security skills — catalog audit

Source catalog: [VoltAgent/awesome-agent-skills](https://github.com/VoltAgent/awesome-agent-skills) (MIT).
Secondary sources: [Trail of Bits skills](https://github.com/trailofbits/skills) (CC BY-SA 4.0) and
[Anthropic Cybersecurity Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) (Apache-2.0).

## What was indexed

| Origin | Entries |
|---|---:|
| awesome-agent-skills README | 1112 |
| Anthropic Cybersecurity Skills | 818 |
| Trail of Bits skills | 85 |
| **Total** | **2015** |

Status counts: `{'unmapped': 1042, 'reference': 374, 'indexed': 567, 'imported': 32}`.

The 1,497-entry awesome list is mostly non-security (docx/pptx, marketing, frontend,
cloud SDK setup). The security-relevant material is concentrated in Trail of Bits
and the 818-skill cybersecurity library. They are indexed in
`knowledge/catalog/index.json`; the 20 highest-value skills are implemented as
CTF-adapted cards and source-verified recipes.

## Imported now (32)

- `libfuzzer` (pwn; pwn, rev) — libFuzzer coverage-guided fuzzing
- `aflpp` (pwn; pwn, rev) — AFL++ multi-core fuzzing
- `harness-writing` (pwn; pwn, rev) — Fuzzing harness design
- `address-sanitizer` (pwn; pwn, rev) — AddressSanitizer crash triage
- `constant-time-analysis` (crypto; crypto) — Constant-time / timing side-channel review
- `dwarf-expert` (rev; rev) — DWARF debug-info reconstruction
- `yara-authoring` (forensics; forensics, rev) — YARA rule authoring for artifacts
- `differential-review` (rev; rev, web-ctf) — Differential review / patch diffing
- `firebase-apk-scanner` (mobile; mobile, web-ctf) — Android APK / Firebase misconfiguration
- `smart-contract-audit` (blockchain; blockchain) — Smart-contract CTF audit loop
- `insecure-defaults` (web-ctf; web-ctf, forensics) — Insecure defaults / secrets sweep
- `static-analysis-semgrep` (rev; web-ctf, rev) — Semgrep / CodeQL source triage
- `memory-volatility` (forensics; forensics) — Volatility 3 memory forensics
- `pcap-wireshark` (forensics; forensics) — PCAP triage with tshark/Wireshark
- `disk-mft-recovery` (forensics; forensics) — Disk image / MFT and deleted-file recovery
- `linux-elf-malware` (rev; rev, forensics) — Linux ELF static + dynamic triage
- `heap-spray` (pwn; pwn) — Heap grooming / spray for CTF pwn
- `android-apktool` (mobile; mobile) — APK static + Frida triage
- `pdf-office-malware` (forensics; forensics) — PDF / Office document triage
- `ethereum-contracts` (blockchain; blockchain) — EVM smart-contract vulnerability classes
- `firmware-binwalk` (hardware; hardware, forensics) — Firmware extraction (binwalk/entropy)
- `stego-detection` (stego; stego, forensics) — Steganography detection pipeline
- `osint-recon` (osint; osint) — OSINT external recon
- `llm-prompt-injection` (ai-ml; ai-ml) — LLM prompt-injection testing
- `windows-artifacts` (forensics; forensics) — Windows artifact forensics
- `ios-assessment` (mobile; mobile) — iOS app static + Frida assessment
- `solana-audit` (blockchain; blockchain) — Solana program audit
- `jwt-attacks` (web-ctf; web-ctf) — JWT attack matrix
- `api-fuzzing-restler` (web-ctf; web-ctf) — OpenAPI-driven API fuzzing (RESTler)
- `upx-unpack` (rev; rev) — UPX / packed binary unpacking
- `js-deobfuscation` (web-ctf; web-ctf, rev) — JavaScript deobfuscation
- `crypto-test-vectors` (crypto; crypto) — Crypto test vectors / property tests

## What was rejected and why

- Productivity/document skills (docx, pptx, xlsx, PDF forms, brand, Figma, Slack):
  not CTF techniques.
- Marketing/product/education/legal skills: out of scope.
- Vendor-specific cloud SDK setup: not a CTF primitive.
- Generic code-review/test-framework skills: partially useful, but already covered
  by the fuzzing/static-analysis cards.
- The remaining 800+ cybersecurity skills are indexed as `indexed`/`reference`
  and searchable via `python3 -m engine knowledge --catalog`; they are not loaded
  into every prompt.

## Licensing

- Cards derived from Trail of Bits are licensed **CC BY-SA 4.0**; attribution and
  source links are in each card.
- Cards derived from Anthropic Cybersecurity Skills are licensed **Apache-2.0**.
- The catalog index is a metadata index of MIT/Apache-2.0/CC-BY-SA-4.0 sources;
  see `skills/imported/NOTICE.md`.
