#!/usr/bin/env python3
"""rev_ghidra.py — one-shot Ghidra decompile via ephemeral headless MCP server.

WHY: GhidraMCP headless binds ONE binary per server instance, so a persistent
opencode MCP entry can't switch targets. This wrapper spawns the server per
call (Ghidra analyzes once, ~60-120s first run), issues JSON-RPC, kills it.
For interactive multi-call RE sessions, prefer the persistent `ghidra` MCP
entry (fixed GHIDRA_BINARY) or r2/GDB loop.

Usage:
  rev_ghidra.py --binary ./vuln --decompile main
  rev_ghidra.py --binary ./vuln --list-functions [--filter main]
  rev_ghidra.py --binary ./vuln --info
  rev_ghidra.py --binary ./vuln --call rename_function --args '{"old_name":"FUN_001","new_name":"vuln"}'
Requires: GHIDRA_INSTALL_DIR, Temurin JDK 21 on PATH (source tools/env.sh),
/home/cyb3rfy/ghidra-mcp extension jar. Timeout default 600s (analysis is slow).
Exit 0=result printed, 1=error.
"""
import argparse
import json
import os
import subprocess
import sys

JAR = "/home/cyb3rfy/ghidra-mcp/GhidraMCP-release-2-0/ghidra_12.1.4_PUBLIC_20261010_GhidraMCP.zip"
# NOTE: extracted jar lives at /tmp/ghidraext (ephemeral); prefer stable path:
JAR_STABLE = "/home/cyb3rfy/ghidra-mcp/GhidraMCP.jar"
BRIDGE = ["uvx", "--python", "3.13", "--from",
          "ghidra-mcp[headless] @ git+https://github.com/LaurieWired/GhidraMCP",
          "ghidra-mcp", "--headless"]

def ensure_jar():
    if os.path.isfile(JAR_STABLE):
        return JAR_STABLE
    for cand in ("/tmp/ghidraext/GhidraMCP/lib/GhidraMCP.jar",):
        if os.path.isfile(cand):
            os.makedirs(os.path.dirname(JAR_STABLE), exist_ok=True)
            with open(cand, "rb") as f, open(JAR_STABLE, "wb") as t:
                t.write(f.read())
            return JAR_STABLE
    # fall back: extract from release zip
    import zipfile
    zpath = "/home/cyb3rfy/ghidra-mcp/GhidraMCP-release-2-0/ghidra_12.1.4_PUBLIC_20261010_GhidraMCP.zip"
    with zipfile.ZipFile(zpath) as z:
        for n in z.namelist():
            if n.endswith("GhidraMCP.jar"):
                os.makedirs(os.path.dirname(JAR_STABLE), exist_ok=True)
                open(JAR_STABLE, "wb").write(z.read(n))
                return JAR_STABLE
    return None

def rpc(calls, binary, timeout):
    jar = ensure_jar()
    if not jar:
        print("ERROR: GhidraMCP.jar not found (download release first)")
        return 1
    env = dict(os.environ)
    env.setdefault("GHIDRA_INSTALL_DIR", "/home/cyb3rfy/ghidra/ghidra_12.1.4_PUBLIC")
    msgs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                    "clientInfo": {"name": "rev_ghidra", "version": "1.0"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
    ]
    msgs += [{"jsonrpc": "2.0", "id": 10 + i, "method": "tools/call",
              "params": {"name": name, "arguments": args}}
             for i, (name, args) in enumerate(calls)]
    blob = "".join(json.dumps(m) + "\n" for m in msgs)
    try:
        p = subprocess.run(BRIDGE + ["--binary", binary, "--extension-jar", jar],
                           input=blob, capture_output=True, text=True,
                           timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        print(f"ERROR: Ghidra run timed out ({timeout}s) — big binary, raise --timeout")
        return 1
    ok = False
    for line in p.stdout.splitlines():
        try:
            d = json.loads(line)
        except ValueError:
            continue
        r = d.get("result", {})
        if "content" in r:
            for c in r["content"]:
                t = c.get("text", "")
                print(t[:6000])
                ok = True
        if isinstance(r, dict) and r.get("isError"):
            print("TOOL-ERROR:", json.dumps(r)[:500])
            return 1
    if not ok:
        print("ERROR: no tool result (see stderr tail):")
        print(p.stderr.strip().splitlines()[-3:])
        return 1
    return 0

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--decompile", default=None)
    ap.add_argument("--list-functions", action="store_true")
    ap.add_argument("--filter", default=None)
    ap.add_argument("--info", action="store_true")
    ap.add_argument("--call", default=None)
    ap.add_argument("--args", default="{}")
    ap.add_argument("--timeout", type=int, default=600)
    a = ap.parse_args()
    if not os.path.isfile(a.binary):
        print(f"ERROR: no binary {a.binary}")
        return 1
    calls = []
    if a.info:
        calls.append(("get_program_info", {}))
    if a.list_functions:
        q = {"limit": 100}
        if a.filter:
            q["filter"] = a.filter
        calls.append(("list_functions", q))
    if a.decompile:
        calls.append(("decompile_function", {"name": a.decompile}))
    if a.call:
        try:
            args = json.loads(a.args)
        except ValueError:
            print("ERROR: --args must be JSON")
            return 1
        calls.append((a.call, args))
    if not calls:
        print("ERROR: nothing to do (need --info/--list-functions/--decompile/--call)")
        return 1
    return rpc(calls, os.path.abspath(a.binary), a.timeout)

if __name__ == "__main__":
    sys.exit(main())
