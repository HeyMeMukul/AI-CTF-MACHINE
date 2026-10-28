# Insecure defaults / secrets sweep

Sweep source/config for default credentials, weak secrets, debug flags, permissive CORS, and example keys.

- Use when: A web/source challenge looks 'secure' but may ship a default admin password, dev secret, or debug endpoint.
- Domains: web-ctf, forensics
- Source: https://github.com/trailofbits/skills/tree/main/plugins/insecure-defaults/skills/insecure-defaults
- Status: imported, source-verified (no CTF fixture yet)
