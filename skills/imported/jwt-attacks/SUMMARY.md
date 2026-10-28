# JWT attack matrix

Test alg:none, RS256→HS256 confusion, weak HMAC secrets, kid injection, and jku/x5u trust.

- Use when: A web challenge issues a JWT and the flag/admin path depends on a claim, role, or signature check.
- Domains: web-ctf
- Source: https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/main/skills/testing-for-json-web-token-vulnerabilities
- Status: imported, source-verified (no CTF fixture yet)
