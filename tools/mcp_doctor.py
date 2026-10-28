#!/usr/bin/env python3
"""mcp_doctor.py — health-check every MCP server in opencode.json.

Usage: mcp_doctor.py [--config opencode.json] [--probe] [--server NAME]
  (default)  list servers with enabled flag + backend availability
  --probe    speak JSON-RPC initialize→tools/list to each ENABLED local server,
             report tool counts (slow: spawns npx/uvx; ~10-60s each)
  --server   probe only one server
Exit 0=all probed OK (or all backends present), 1=any failure, 2=warnings only.
Backend checks (no spawn): node/npx, uvx, python+mcp lib, gdb, vol binary,
vendored vol server file.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

INIT = ('{"jsonrpc":"2.0","id":1,"method":"initialize","params":{'
        '"protocolVersion":"2025-11-25","capabilities":{},'
        '"clientInfo":{"name":"mcp-doctor","version":"1.0"}}}\n'
        '{"jsonrpc":"2.0","method":"notifications/initialized"}\n'
        '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n')

def backend_ok(name, cmd):
    """Static backend checks without spawning the server."""
    if name in ("playwright", "cyberchef", "crypto-tools", "filesystem",
                "memory", "sequential-thinking"):
        return shutil.which("npx") is not None, "npx"
    if name in ("mdb", "ctfd", "ctf-toolkit"):
        return shutil.which("uvx") is not None, "uvx"
    if name == "volatility":
        vend = os.path.join(ROOT, "tools", "_vendor", "volatility_mcp_server.py")
        vol = os.path.expanduser("~/.local/bin/vol")
        ok = os.path.isfile(vend) and (os.path.isfile(vol) or shutil.which("vol"))
        try:
            import mcp.server.fastmcp  # noqa: F401
            lib = True
        except ImportError:
            lib = False
        return ok and lib, "vendored server + vol + mcp<2 lib"
    if name in ("htb-ctf",):
        return True, "remote (needs Bearer token at use time)"
    if name == "burp":
        import os as _os
        import importlib.util as _ilu
        url = _os.environ.get("BURP_API_URL", "http://127.0.0.1:8089")
        key = bool(_os.environ.get("BURP_API_KEY"))
        has_py = shutil.which("python3") is not None
        has_mod = _ilu.find_spec("burp_mcp") is not None
        det = (f"python3 -m burp_mcp -> {url} "
               f"({'key set' if key else 'NO BURP_API_KEY — start Burp + export key'}; "
               f"{'mod ok' if has_mod else 'no burp_mcp module — pip install -e server/ from Den-Sec/burp-mcp'})")
        ok = has_py and has_mod and key
        return ok, det + " [disabled by default; web falls back to ffuf/sqlmap CLI]"
    if name in ("brave-search",):
        import os as _os
        ok = shutil.which("npx") is not None and bool(_os.environ.get("BRAVE_API_KEY"))
        return ok, "npx + BRAVE_API_KEY (export per OSINT task)"
    if name in ("github",):
        import os as _os
        ok = shutil.which("npx") is not None and bool(_os.environ.get("GITHUB_PERSONAL_ACCESS_TOKEN"))
        return ok, "npx + GITHUB_PERSONAL_ACCESS_TOKEN (export per OSINT task)"
    if name == "ghidra":
        gdir = "/home/cyb3rfy/ghidra/ghidra_12.1.4_PUBLIC"
        jar = "/home/cyb3rfy/ghidra-mcp/GhidraMCP.jar"
        jdk = "/home/cyb3rfy/jdk/jdk-21.0.12.1+1/bin/java"
        ok = (os.path.isdir(gdir) and os.path.isfile(jar)
              and os.path.isfile(jdk) and shutil.which("uvx"))
        return ok, "Ghidra 12.1.4 + ext jar + Temurin JDK21 + uv"
    if name == "gdb":
        return shutil.which("gdb") is not None, "gdb"
    return True, "unknown server (no check)"

def probe(name, cfg):
    if cfg.get("type") != "local" or not cfg.get("enabled"):
        return None, "skipped (disabled or remote)"
    cmd = cfg.get("command", [])
    if not cmd:
        return False, "no command"
    try:
        p = subprocess.run(cmd, input=INIT, capture_output=True, text=True, timeout=120)
        tools = []
        for line in p.stdout.splitlines():
            try:
                d = json.loads(line)
            except ValueError:
                continue
            res = d.get("result", {})
            if isinstance(res, dict) and "tools" in res:
                tools = [t.get("name", "?") for t in res["tools"]]
        if tools:
            return True, f"{len(tools)} tools ({', '.join(tools[:6])}{'...' if len(tools) > 6 else ''})"
        err = p.stderr.strip().splitlines()
        return False, (err[-1][:160] if err else "no tools in response")
    except subprocess.TimeoutExpired:
        return False, "probe timeout (cold fetch?)"
    except FileNotFoundError as e:
        return False, f"launcher missing: {e}"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=os.path.join(ROOT, "opencode.json"))
    ap.add_argument("--probe", action="store_true")
    ap.add_argument("--server", default=None)
    a = ap.parse_args()
    try:
        servers = json.load(open(a.config)).get("mcp", {})
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"ERROR: {e}")
        return 1
    worst, warns = 0, 0
    for name, cfg in servers.items():
        if a.server and name != a.server:
            continue
        ok, detail = backend_ok(name, cfg.get("command", []))
        tag = "backend-ok" if ok else "BACKEND-MISSING"
        if not ok:
            # Disabled servers are opt-in per task/event (need keys/sandbox) —
            # advisory only. Only an ENABLED server with a missing backend fails.
            if cfg.get("enabled"):
                worst = 1
            else:
                tag += " (disabled: enable per task, see description)"
        extra = ""
        if a.probe:
            pok, pdetail = probe(name, cfg)
            if pok is None:
                extra = f" | probe: {pdetail}"
            elif pok:
                extra = f" | probe OK: {pdetail}"
            else:
                extra = f" | PROBE-FAIL: {pdetail}"
                worst = 1
        print(f"[{'x' if cfg.get('enabled') else ' '}] {name:20s} {tag:14s} {detail}{extra}")
    return worst

if __name__ == "__main__":
    sys.exit(main())
