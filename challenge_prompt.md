# Challenge Prompt — per-event scope and rules template

Complete one copy of this file in each engagement folder. Keep credentials and secrets in an ignored local file, not here.

## Competition
- Name:
- Platform (CTFd / HTB / picoCTF / local / other):
- Platform URL (if applicable):
- Start/end time and timezone:
- Rules/hints source:

## Scope — authoritative
- Challenge IDs in scope:
- Allowed challenge hosts/IPs/ports/URLs:
- Explicitly out of scope:
- Are challenge services shared/stateful? (yes/no/unknown):
- Network restrictions / rate limits:

## Rules and gates
- Hint budget and hint-approval rule:
- Per-challenge attempt/submission limits:
- Submission method (manual / CTFd / HTB MCP / other):
- Human-only steps (login, CAPTCHA, 2FA, destructive reset):
- Expected answer/flag format, if stated (record the literal format only, never a captured answer):
- If no format is stated, write `unknown`; do not assume `picoCTF{}`.

## Challenge record (repeat per challenge)
- CHAL-ID and title:
- Points/category as displayed (informational, not authoritative):
- Statement path:
- Given-files path:
- Service endpoint and protocol:
- Known reset/instance lifecycle:
- Expected success condition / answer format:
- Notes and unresolved scope questions:

## Canonical layout
```text
challenges/_inbox/<slug>/              # browser pulls before classification
challenges/<domain>/<CHAL-XXX-slug>/   # domain = evidence-based triage category
  given/            # original files (read-only)
  statement.md      # challenge description (sanitize secrets)
  service.txt       # challenge endpoint only
  surface.json      # triage evidence, confidence, primary/secondary route
  recon/            # Phase 1 observations
  profiles/         # analysis hypotheses and evidence
  exploits/         # one solve.py + result per hypothesis
  transcripts/      # local, redacted session logs
  flag.txt          # local-only validated answer, when applicable
  FLAG-XXX.validated.md
  writeup.md        # validated evidence only
```
Scaffold: `tools/new_challenge.py --domain <domain> --chal CHAL-001-example --from-inbox challenges/_inbox/<slug>`
