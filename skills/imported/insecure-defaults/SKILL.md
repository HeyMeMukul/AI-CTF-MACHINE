---
name: imported-insecure-defaults
description: Sweep source/config for default credentials, weak secrets, debug flags, permissive CORS, and example keys.
category: web-ctf
phase: triage
source: https://github.com/trailofbits/skills/tree/main/plugins/insecure-defaults/skills/insecure-defaults
license: CC-BY-SA-4.0
ctf_domains: [web-ctf, forensics]
status: imported
---

# Insecure defaults / secrets sweep (imported)

> Adapted for CTF use from [Trail of Bits](https://github.com/trailofbits/skills/tree/main/plugins/insecure-defaults/skills/insecure-defaults). License: `CC-BY-SA-4.0`.
> Technique-only; no flags or target-specific data. Authorized CTF use only.

Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`.

## When to use

A web/source challenge looks 'secure' but may ship a default admin password, dev secret, or debug endpoint.

## Signals

- source/config dump
- login form
- JWT/cookie secret
- debug flag
- CORS `*`

## Preconditions

- source or config accessible
- authorized challenge target

## CTF workflow

1. Grep for `admin:admin`, `changeme`, `password`, `SECRET_KEY`, `DEBUG=True`, `ALLOWED_HOSTS=*`, `CORS_ORIGIN_ALLOW_ALL`.
2. Check `.env`, `config.*`, `docker-compose`, `settings.py`, `application.properties`, and example files.
3. Try the default credential once; inspect JWT/cookie signing secrets and `kid`/`jku` config.
4. Verify whether the default is actually active in the running service, not just present in a sample file.

## Falsifier

Secrets are rotated, debug is off, and default credentials are rejected by the live service.

## Pitfalls

- example/test files
- env overrides
- rate limits
- fake secrets as decoys

## Source and license

- Source: https://github.com/trailofbits/skills/tree/main/plugins/insecure-defaults/skills/insecure-defaults
- Author/team: Trail of Bits
- License: `CC-BY-SA-4.0`
- Imported: 2026-10-20; adapted summary, not a verbatim copy.
