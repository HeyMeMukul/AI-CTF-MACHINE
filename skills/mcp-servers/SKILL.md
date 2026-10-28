---
name: mcp-servers
description: MCP server arsenal for CTF — which servers, exact configs, enable-per-task policy
category: infrastructure
phase: all
---
Execution policy: follow `skills/_shared/SKILL_CONTRACT.md`; separate evidence from inference, preserve scope, validate each link, and label uncertainty.

# MCP SERVERS — CTF Arsenal (verified Oct 2026)

## Mental Model
MCP servers turn tools into agent-callable functions with schema validation (kills hallucinated
exploits — STRIATUM lesson). But every enabled server costs context + attack surface. Policy:
**few always-on, powerful per-task.** Enable heavy/RCE-capable servers only inside the task that needs
them, disable after. Flags and MCP tokens are local-only (see `config/ctf_policy.json`).

## Workflow

### Phase 1 — Baseline (what is available?)
Check installed servers before assuming: `GET http://127.0.0.1:<port>/health` or try the MCP
`tools/list`. Record versions (tool names drift: dalfox `url` vs `scan`, RsaCtfTool fork flags).

**Reasoning Checkpoint:** server reachable → pin version → else fall back to CLI wrapper.

### Phase 2 — Confirmation (minimal tool probe)
Call ONE read-only tool (`status`, `list_functions`, `health`) to confirm the server talks to the
right target (right binary, right CTFd instance, right Burp project).

**Reasoning Checkpoint:** probe matches task target → proceed → else reconfigure.

### Phase 3 — Negative (do NOT do this)
- Never enable `kali` (`--ip 0.0.0.0`) on untrusted networks — SSH tunnel or Docker only.
- Never enable `ctf-utils` (CTF-MCP: 14 CRITICAL RCE tools) outside the sandbox container.
- Never send flags to `brave-search`/any web tool. Never commit MCP tokens.
- Do not configure Ghidra+IDA+Binja all at once — pick ONE (default: Ghidra, free).

**Reasoning Checkpoint:** risk check passed → least-privilege set enabled.

### Phase 4 — Exploit (gated: enable → use → disable)
Per-task enable pattern in `opencode.json` (`"enabled": false` default for heavy servers, flip for
the task, flip back after). ONE task, ONE extra server.

**Reasoning Checkpoint:** task done → server disabled → transcript saved.

### Phase 5 — Validation-handoff
Handoff: which servers were used, versions, what was mutated (renames/patches), server logs path.

**Reasoning Checkpoint:** environment restored → next task gets clean slate.

## Tool Table — Server Catalog (verdicts from research)

> LIVE STATUS 2026-10-15 (this machine, `tools/mcp_doctor.py --probe`):
> CONNECTED+VERIFIED: cyberchef, crypto-tools, mdb (gdb), filesystem (scoped),
> volatility (vendored Linux patch), GHIDRA (12.1.4 + GhidraMCP 2.0, decompile
> verified; headless binds one binary — use `tools/rev_ghidra.py` for any-binary
> one-shots, opencode `ghidra` entry per fixed-target sessions).
> CONFIGURED-OFF (enable per event/task):
> ctfd, htb-ctf, ctf-toolkit (sandbox-only). SKIPPED (backend missing):
> burp (no Burp Pro), kali (duplicates bash).

### Always-on (cheap, safe)

| Server | Install | opencode.json entry | Key tools |
|---|---|---|---|
| filesystem | `npx -y @modelcontextprotocol/server-filesystem` | `["npx","-y","@modelcontextprotocol/server-filesystem","<WORKSPACE>"]` | `read_file, write_file, list_directory, search_files` (scope to workspace!) |
| github | `npx -y @modelcontextprotocol/server-github`, env `GITHUB_PERSONAL_ACCESS_TOKEN` | stdio | repos/issues/search (OSINT code search) |
| brave-search | `npx -y @brave/brave-search-mcp-server`, env `BRAVE_API_KEY` | stdio | web search (dorking; NEVER send flags) |
| playwright | `npx @playwright/mcp@latest` | `["npx","@playwright/mcp@latest","--caps","core,vision,network"]` | `browser_navigate/snapshot/click` (web-CTF) |
| memory | `npx -y @modelcontextprotocol/server-memory` | stdio | knowledge-graph (profiles, FP patterns) |
| sequential-thinking | `npx -y @modelcontextprotocol/server-sequentialthinking` | stdio | `sequentialthinking` (flag-path planning) |
| cyberchef | `npm i cyberchef-mcp` (`doublegate/CyberChef-MCP`, 504 ops) | `["npx","-y","cyberchef-mcp"]` | From-Base64/Hex, AES/XOR, Magic auto-detect |
| crypto-tools | `npx @rog0x/mcp-crypto-tools` | stdio | hash/encode/jwt-decode (lightweight) |

### Per-task (powerful — enable only when needed)

| Server | Install | Transport | Key tools | Use when |
|---|---|---|---|---|
| ghidra (LaurieWired/GhidraMCP) | `uvx --from git+https://github.com/LaurieWired/GhidraMCP ghidra-mcp --ghidra-server http://127.0.0.1:8080/` + extension ZIP via `File > Install Extensions`; headless: `--headless --binary <target>` needs `GHIDRA_INSTALL_DIR` | stdio bridge → HTTP `:8080` | `decompile`, list methods/imports/exports, rename | rev tasks (default RE choice, free) |
| mdb (smadi0x86/MDB-MCP) | `uvx --from git+https://github.com/smadi0x86/MDB-MCP mdb-mcp` (needs gdb/lldb) | stdio | `debugger_start/command/interrupt/terminate` (respects `~/.gdbinit`, pwndbg/GEF work) | pwn tasks |
| ctf-utils (Coff0xc/CTF-MCP, 126 tools) | `pip install -e .`, command `ctf-mcp` | stdio | RSA (Wiener/Hastad/common-modulus/Franklin-Reiter), XSS/SSTI/JWT/deser, ROP/fmt/tcache/House-of-*/SROP | any exploit task — SANDBOX ONLY (14 CRITICAL RCE tools) |
| ctfd (umbra2728/ctfd-mcp, PyPI `ctfd-mcp`) | `uvx ctfd-mcp`, env `CTFD_URL` + `CTFD_TOKEN` | stdio | `start_container/stop_container`, list/get challenges, submit flag | playing CTFd events (incl. dynamic docker) |
| htb-ctf (official) | No repo — platform feature: per-user MCP token from HTB profile settings, per-event toggle (admin, off default). URL `https://mcp.hackthebox.ai/v1/ctf/mcp/` (Streamable HTTP). Claude: `claude mcp add --transport http htb-mcp-ctf https://mcp.hackthebox.ai/v1/ctf/mcp/ --header "Authorization: Bearer <TOKEN>"` | Streamable HTTP | list events, challenge details, start/stop containers, submit flag, scores | playing HTB CTFs |
| htb-labs (zebbern/htb-mcp community) | `npx -y @zebbern/htb`, env `HTB_API_KEY` | stdio | machines/challenges/flags/VPN | HTB labs (not CTF events) |
| volatility (bornpresident/Volatility-MCP-Server) | `pip install mcp httpx`, set `VOLATILITY_DIR` | stdio | vol3 plugins as tools (pslist/netscan/malfind/filescan) | memory-forensics tasks |
| burp (Den-Sec/burp-mcp, 61 tools) | build JAR `./gradlew jar` → load in Burp Pro, `pip install -e .`, env `BURP_API_KEY` + `BURP_API_URL=http://127.0.0.1:8089` — NOTE: port is `8089`, not `9876` | stdio → HTTP+X-API-Key | Repeater/Intruder/Collaborator/scan/crawl/GraphQL/Swagger | web tasks needing Intruder/OOB |
| kali (official Wh0am123/MCP-Kali-Server) | `sudo apt install mcp-kali-server` → `kali-server-mcp --port 5000 --ip 127.0.0.1` | bridge `:5000` + stdio | nmap/gobuster/hydra/sqlmap/nikto/john/metasploit | Kali-host runs; remote via `ssh -L 5000:localhost:5000` |

### Licensed-only / skip
- IDA (`mrexodia/ida-pro-mcp`): only if you own IDA Pro 8.3+/9 (Free unsupported). Binja: native MCP (Commercial/Ultimate) or `MCPPhalanx/binaryninja-mcp`.
- SKIP: retro-only Ghidra servers, thin/unmaintained Kali servers, picoCTF MCP (none exists — use CTFd MCP + fetch).

## Decision Tree
```
need decompile/xrefs? → ghidra (rev) — else r2 CLI
need breakpoints/registers? → mdb (pwn) — else gdb CLI
need 126-in-1 payloads? → ctf-utils in sandbox
playing CTFd? → ctfd MCP | playing HTB event? → htb-ctf official
need Intruder/OOB at scale? → burp (else sqlmap/ffuf CLI)
need mem plugins? → volatility MCP (else vol.py CLI)
on Kali host? → kali MCP via tunnel (else bash tools)
```

## AI Automation Notes
- `tools/mcp_doctor.py` (M1): probes each configured server, reports reachable/version, used by Lead pre-dispatch.
- Token budget: heavy servers (ghidra 200+ tools) explode tool schemas — prefer lazy-loading servers and `tools/list` filtering; disable immediately after task.
- All MCP tokens in ignored local file (never in repo, never in chat logs).
