# Imported security skills — what came from the awesome-agent-skills catalog

The catalog at [VoltAgent/awesome-agent-skills](https://github.com/VoltAgent/awesome-agent-skills)
lists ~1,497 skills. Most are not CTF techniques: document generation, marketing,
frontend design, vendor SDK setup, education, legal. Blindly copying all of them
would add context bloat and unverified claims.

I audited the catalog and two deeper security sources it points to:

| Source | Entries indexed | License |
|---|---:|---|
| `awesome-agent-skills` README | 1,112 parsed (badge says 1,497; some rows use non-standard formatting) | MIT |
| [Anthropic Cybersecurity Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) | 818 | Apache-2.0 |
| [Trail of Bits skills](https://github.com/trailofbits/skills) | 85 | CC-BY-SA-4.0 |
| **Catalog index** | **2,015** | mixed, attributed |

Status: **32 imported**, 567 indexed, 374 reference, 1,042 unmapped. Full details
and the rejection rationale are in
[`knowledge/catalog/SELECTION.md`](../knowledge/catalog/SELECTION.md).

## The 32 imported cards

| Domain | Imported |
|---|---|
| pwn / rev | `libfuzzer`, `aflpp`, `harness-writing`, `address-sanitizer`, `dwarf-expert`, `differential-review`, `heap-spray`, `upx-unpack` |
| crypto | `constant-time-analysis`, `crypto-test-vectors` |
| web / source | `insecure-defaults`, `static-analysis-semgrep`, `jwt-attacks`, `api-fuzzing-restler`, `js-deobfuscation` |
| forensics | `yara-authoring`, `memory-volatility`, `pcap-wireshark`, `disk-mft-recovery`, `linux-elf-malware`, `pdf-office-malware`, `windows-artifacts` |
| mobile | `firebase-apk-scanner`, `android-apktool`, `ios-assessment` |
| blockchain | `smart-contract-audit`, `ethereum-contracts`, `solana-audit` |
| hardware | `firmware-binwalk` |
| stego | `stego-detection` |
| OSINT | `osint-recon` |
| AI/ML | `llm-prompt-injection` |

Each card lives at `skills/imported/<slug>/SKILL.md`, has `source`, `license`,
`ctf_domains`, and `status` in its frontmatter, and is paired with a
`recipes/imported-<slug>.json` card for the autonomous engine.

## Two knowledge tiers (important)

| Tier | Where | Verified how | Used by the solver? |
|---|---|---|---|
| Fixture-tested | `recipes/*.json` (`verified: true`) | Has an eval fixture and a salted-flag test | Yes, normally |
| Source-verified | `recipes/imported-*.json` (`verification: source`) | Source link + author reviewed; **no CTF fixture yet** | Yes, labeled `source-verified (not fixture-tested)` |
| Unverified / quarantined | `knowledge/writeups_mined/*` | No provenance check; sampled labels were wrong | **No**, unless `--include-unverified` |

This is deliberate. The 32 imported cards are useful immediately, but they are
not presented as fixture-proven. Promoting one to `verified: true` requires a
fixture and a passing eval.

## How to use

```bash
# Search the full 2,015-entry catalog (titles/descriptions/domains)
python3 -m engine knowledge --catalog --query "volatility memory forensics"
python3 -m engine knowledge --catalog --query "fuzzing harness"

# Retrieve executable recipes (fixture + source-verified)
python3 -m engine knowledge --query "libfuzzer crash" --domain pwn --top 3
python3 -m engine knowledge --query "pcap http objects" --domain forensics
```

The solver retrieves the top recipes for each task automatically and labels
source-verified ones in the prompt.

## Licensing and attribution

- Trail of Bits cards are derivative works under **CC BY-SA 4.0**; keep the
  attribution and share-alike license if you redistribute them.
- Anthropic Cybersecurity Skills cards are derivative works under **Apache-2.0**.
- The catalog index is metadata from MIT/Apache-2.0/CC-BY-SA-4.0 sources; see
  [`skills/imported/NOTICE.md`](../skills/imported/NOTICE.md).

## Adding more

1. Pick an entry from `knowledge/catalog/index.json` with `status: indexed`.
2. Write a CTF-adapted card (not a verbatim copy) with:
   `name`, `description`, `category`, `phase`, `source`, `license`,
   `ctf_domains`, `status: imported`.
3. Add `recipes/imported-<slug>.json` with signals, preconditions, steps,
   falsifier, pitfalls, sources, `verification: source`.
4. Add a fixture and promote to `verified: true` only when it passes.
5. Run `python3 -m engine doctor` and `python3 tools/framework_lint.py --strict`.
