---
name: imported-js-deobfuscation
description: Beautify, AST-fold, and sandbox obfuscated JS to recover the hidden check, URL, key, or flag path.
category: web-ctf
phase: analyze
source: https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/deobfuscating-javascript-malware
license: Apache-2.0
ctf_domains: [web-ctf, rev]
status: imported
---

# JavaScript deobfuscation (imported)

> Adapted for CTF use from [Anthropic Cybersecurity Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/deobfuscating-javascript-malware). License: `Apache-2.0`.
> Technique-only; no flags or target-specific data. Authorized CTF use only.

Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`.

## When to use

A web challenge ships a heavily obfuscated JS bundle/skimmer and the logic or secret is hidden in string arrays/eval.

## Signals

- obfuscated JS
- string array
- _0x names
- eval/Function
- source map

## Preconditions

- JS file/bundle
- Node sandbox and browser devtools

## CTF workflow

1. `js-beautify`/prettier first; look for string arrays, decoder functions, and `eval`/`Function` wrappers.
2. Use `webcrack`/`de4js` or a small Babel AST pass to fold string arrays and constant expressions.
3. Run suspicious code in a Node VM/browser sandbox with network blocked; log arguments to eval/Function.
4. Check source maps, `atob`/`crypto` calls, and DOM sinks; extract the check/flag path and confirm in the browser.

## Falsifier

The code is server-side or WASM; static JS deobfuscation cannot recover it.

## Pitfalls

- anti-debug
- eval obfuscation
- browser-only APIs
- infinite loops
- prototype pollution in the sandbox

## Source and license

- Source: https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/deobfuscating-javascript-malware
- Author/team: Anthropic Cybersecurity Skills
- License: `Apache-2.0`
- Imported: 2026-10-20; adapted summary, not a verbatim copy.
