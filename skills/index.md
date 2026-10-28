# Skills Index — MOC graph (Phase → skill) — v2.0, 19 core + 32 imported

- Phase 0: `triage/` — 60–120s classify across 14 domains → surface.json → router table.
- Phase 1–2 Web: `web-ctf/` — recon, SQLi/NoSQLi, XSS, SSTI, LFI/RFI, SSRF, XXE, deser, JWT, GraphQL, pollution, CMDi, upload, logic.
- Phase 1–3 Pwn: `pwn/` — checksec tree, offset, leak→ROP, fmt, heap, skeletons E1–E5.
- Phase 2–3 Rev: `rev/` — Ghidra headless+MCP, r2, angr, Frida, unpack, .NET/Go/pyc/APK/WASM.
- Phase 1–3 Crypto: `crypto/` — classifier, RSA matrix, RsaCtfTool, AES oracles, ECC, classical, hashcrack.
- Phase 1–3 Forensics: `forensics/` — pcap, disk, memory (Vol3), timeline.
- Phase 1–3 Stego: `stego/` — ordered pipeline (exiftool→binwalk→zsteg/steghide→spectrogram→QR).
- Phase 1–3 Misc: `misc-pyjail/` — pyjails, esolangs, programming, encodings, archives, QR.
- Phase 1–3 OSINT: `osint/` — sherlock/maigret, theHarvester, crt.sh, Wayback, dorks, metadata.
- Phase 1–3 Hardware: `hardware/` — firmware (binwalk/firmwalker), UART/JTAG/SPI, sigrok, side-channel, Verilog.
- Phase 1–3 Blockchain: `blockchain/` — foundry loop, EVM vulns 1–8, cast/anvil, proxies.
- Phase 1–3 Mobile: `mobile/` — apktool/jadx, manifest, Frida, pinning bypass, iOS/Flutter notes.
- Phase 1–3 AI/ML: `ai-ml/` — prompt-injection taxonomy, exfil patterns, guardrail probing.
- All phases: `sessions/` — persistent pwntools-conn + gdb-dbg patterns, state machine, templates.
- All phases: `mcp-servers/` — arsenal catalog (always-on vs per-task), exact configs, risk rules.
- All phases: `browser-ops/` — operator-Chrome + CDP attach + challenge/file extraction pipeline.
- Lead-only synthesis: `chaining-flagpath/` (= M9, multi-step flag paths, score ≥50).
- Phase 5: `report-writeup/` — writeups from validated flags only.
- All phases: `sequential-thinking/` — numbered-thought reasoning discipline (`/think`).

All skills include the shared evidence/scope/validation policy in
`_shared/SKILL_CONTRACT.md`. Deep-read casebooks live in each domain's
`techniques/r5-deep-reads.md`; consult a case only when its preconditions match.
`SUMMARY.md` is dispatch guidance; the task file and current challenge evidence
remain authoritative. Run `tools/framework_lint.py` and `tools/skill_lint.py`


## Imported security skills (32)
Source-verified CTF adaptations from Trail of Bits, Anthropic Cybersecurity Skills,
and the VoltAgent catalog. See `imported/README.md`, `imported/NOTICE.md`, and
`../knowledge/catalog/SELECTION.md`.
- Fuzzing/sanitizers: `imported/libfuzzer`, `imported/aflpp`, `imported/harness-writing`, `imported/address-sanitizer`.
- Crypto/rev: `imported/constant-time-analysis`, `imported/crypto-test-vectors`, `imported/dwarf-expert`,
  `imported/differential-review`, `imported/upx-unpack`.
- Web/forensics: `imported/insecure-defaults`, `imported/static-analysis-semgrep`, `imported/jwt-attacks`,
  `imported/api-fuzzing-restler`, `imported/js-deobfuscation`, `imported/yara-authoring`,
  `imported/memory-volatility`, `imported/pcap-wireshark`, `imported/disk-mft-recovery`,
  `imported/linux-elf-malware`, `imported/pdf-office-malware`, `imported/windows-artifacts`.
- Mobile/blockchain/pwn: `imported/firebase-apk-scanner`, `imported/android-apktool`,
  `imported/ios-assessment`, `imported/smart-contract-audit`, `imported/ethereum-contracts`,
  `imported/solana-audit`, `imported/heap-spray`.
- Hardware/stego/OSINT/AI: `imported/firmware-binwalk`, `imported/stego-detection`,
  `imported/osint-recon`, `imported/llm-prompt-injection`.
Search the full 2,015-entry index: `python3 -m engine knowledge --catalog --query "..."`.
