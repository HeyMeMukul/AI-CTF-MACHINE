---
name: imported-static-analysis-semgrep
description: Use Semgrep/CodeQL to find source-to-sink paths fast, then verify manually in the running challenge.
category: rev
phase: analyze
source: https://github.com/trailofbits/skills/tree/main/plugins/static-analysis/skills/semgrep
license: CC-BY-SA-4.0
ctf_domains: [web-ctf, rev]
status: imported
---

# Semgrep / CodeQL source triage (imported)

> Adapted for CTF use from [Trail of Bits](https://github.com/trailofbits/skills/tree/main/plugins/static-analysis/skills/semgrep). License: `CC-BY-SA-4.0`.
> Technique-only; no flags or target-specific data. Authorized CTF use only.

Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`.

## When to use

Source is available (web/rev) and you need to locate injection, authz, deserialization, or crypto sinks quickly.

## Signals

- source tree
- framework config
- many routes
- suspicious sink

## Preconditions

- source available
- buildable or parseable

## CTF workflow

1. `semgrep --config auto .` for a quick baseline; add a focused rule for the framework's sink (SQL, exec, template, deserialize).
2. For deeper dataflow, `codeql database create db --language=<lang>` then `codeql database analyze db <suite> --format=sarif-latest`.
3. Triage by reachability: is the sink reachable from an unauthenticated route/input?
4. Confirm with one benign request or a local unit test; do not report an unconfirmed static hit.

## Falsifier

No source-to-sink path or a sanitizer/allowlist blocks the input.

## Pitfalls

- false positives
- generated code
- missing build
- framework magic
- sanitizers

## Source and license

- Source: https://github.com/trailofbits/skills/tree/main/plugins/static-analysis/skills/semgrep
- Author/team: Trail of Bits
- License: `CC-BY-SA-4.0`
- Imported: 2026-10-20; adapted summary, not a verbatim copy.
