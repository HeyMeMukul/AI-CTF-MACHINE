---
name: imported-llm-prompt-injection
description: Map the trust boundary, test direct/indirect injection and system-prompt leakage, and prove impact with a synthetic canary.
category: ai-ml
phase: exploit
source: https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/detecting-indirect-prompt-injection
license: Apache-2.0
ctf_domains: [ai-ml]
status: imported
---

# LLM prompt-injection testing (imported)

> Adapted for CTF use from [Anthropic Cybersecurity Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/detecting-indirect-prompt-injection). License: `Apache-2.0`.
> Technique-only; no flags or target-specific data. Authorized CTF use only.

Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`.

## When to use

An AI/ML challenge exposes a chatbot, RAG pipeline, tool-using agent, or guardrail and asks for the hidden instruction/flag.

## Signals

- chat endpoint
- RAG/document ingestion
- tool-using agent
- system prompt
- guardrail

## Preconditions

- challenge model endpoint is the only target
- use synthetic canaries, never real secrets

## CTF workflow

1. Map what the model can see and do: system prompt, retrieved documents, tools, memory, and output channel.
2. Test direct override, role-play, delimiter confusion, and system-prompt leakage with benign probes.
3. For RAG/indirect injection, place the payload in a document the model retrieves; use a unique canary string to prove exfil.
4. Confirm impact with the smallest reproducible request; do not test unrelated public AI services.

## Falsifier

The model ignores injected instructions and no canary reaches an output/tool channel.

## Pitfalls

- guardrail false confidence
- prompt leakage vs instruction override
- tool egress
- non-determinism
- scope creep

## Source and license

- Source: https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/detecting-indirect-prompt-injection
- Author/team: Anthropic Cybersecurity Skills
- License: `Apache-2.0`
- Imported: 2026-10-20; adapted summary, not a verbatim copy.
