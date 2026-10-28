#!/usr/bin/env bash
# start.sh — ONE script that brings the whole CTF rig live for a new engagement.
#
# New-engagement model (v1.0): this folder IS the template. Per CTF:
#   cp -r CTF /path/to/<event-slug>/ && cd /path/to/<event-slug> && ./start.sh "Event Name" https://platform-url
#
# What start.sh does:
#   [0] dependency check (python3, node/npx, uvx, chrome, vol, gdb, docker-optional)
#   [1] warms MCP backends (npx/uvx pre-fetch so first probe isn't cold)
#   [2] inits state.json for THIS event (name/platform, pristine counters)
#   [3] launches operator Chrome on :9222 (persistent .browser-profile, attach-only)
#   [4] runs tools/mcp_doctor.py (all MCP backends incl. Burp probe if configured)
#   [5] runs offline self-test (bench tail) + prints API keys you may still need
#
# Usage: ./start.sh "Event Name" https://platform-url [--probe] [--skip-browser]
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
[ -f "$ROOT/tools/env.sh" ] && source "$ROOT/tools/env.sh" || true

NAME="${1:-}"
PLATFORM="${2:-}"
PROBE=0; SKIP_BROWSER=0
for a in "$@"; do
  [[ "$a" == "--probe" ]] && PROBE=1
  [[ "$a" == "--skip-browser" ]] && SKIP_BROWSER=1
done
if [[ -z "$NAME" || -z "$PLATFORM" ]]; then
  echo 'usage: ./start.sh "Event Name" https://platform-url [--probe] [--skip-browser]'
  exit 1
fi

echo "== [0] dependencies =="
miss=0
for t in python3 node npx uvx google-chrome gdb file strings exiftool docker; do
  if command -v "$t" >/dev/null 2>&1; then echo "  ok: $t"; else echo "  MISSING: $t"; miss=1; fi
done
python3 -c "import playwright" 2>/dev/null && echo "  ok: py-playwright" || echo "  MISSING: py-playwright (pip install playwright && playwright install chromium)"
[ "$miss" -ne 0 ] && echo "(missing items degrade their domains; browser+MCP still start)"

echo "== [1] MCP backends (warm) =="
# Pre-fetch so opencode's first MCP spawn isn't a cold 60s download.
npx -y @modelcontextprotocol/server-memory --help >/dev/null 2>&1 & 
npx -y @modelcontextprotocol/server-sequential-thinking --help >/dev/null 2>&1 &
npx -y cyberchef-mcp --help >/dev/null 2>&1 &
wait || true
echo "  warmed: memory, sequential-thinking, cyberchef (background)"

echo "== [2] event init =="
python3 - "$ROOT/state.json" "$NAME" "$PLATFORM" <<'EOF'
import json, sys, datetime
p, name, plat = sys.argv[1], sys.argv[2], sys.argv[3]
st = json.load(open(p))
now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
st["competition"].update({"name": name, "platform": plat, "url": plat,
  "started": now, "status": "active", "current_focus": None})
st["_meta"].update({"last_updated_by": "start.sh", "last_updated_at": now})
json.dump(st, open(p, "w"), indent=2)
print(f"  event: {name} | {plat}")
EOF
mkdir -p challenges/_inbox results tasks writeups downloads/_staging .browser-profile

echo "== [3] operator Chrome =="
if [[ "$SKIP_BROWSER" == "1" ]]; then
  echo "  skipped (--skip-browser)"
else
  "$ROOT/setup_ctf.sh" --browser 9222 || echo "  (browser launch failed — run ./setup_ctf.sh --browser manually)"
fi

echo "== [4] MCP health =="
if [[ "$PROBE" == "1" ]]; then python3 "$ROOT/tools/mcp_doctor.py" --probe || true
else python3 "$ROOT/tools/mcp_doctor.py" || true; fi

echo "== [5] self-test (offline) =="
python3 "$ROOT/tools/bench.py" 2>&1 | tail -n 2 || echo "  (bench failed — run ./run_ctf.sh preflight for detail)"

cat <<'KEYS'
-- API keys you may need (export BEFORE opencode, only for those platforms) --
  CTFd events .....: export CTFD_URL=https://... CTFD_TOKEN=<token>   (then enable 'ctfd' MCP)
  HTB events ......: HTB profile -> MCP token -> enable 'htb-ctf' remote MCP (Bearer header)
  Burp Pro ........: run Burp + load MCP extension, export BURP_API_URL=http://127.0.0.1:8089 BURP_API_KEY=<key>
  OSINT dorking ...: export BRAVE_API_KEY=<key> (then enable 'brave-search')
  OSINT code ......: export GITHUB_PERSONAL_ACCESS_TOKEN=<token> (then enable 'github')
  Local-only MCPs (playwright/memory/thinking/cyberchef/crypto-tools/mdb/volatility/ghidra/filesystem): NO keys.
KEYS
echo
echo "NEXT:"
echo "  1. Log in + solve any CAPTCHA MANUALLY in the operator Chrome window."
echo "  2. python3 tools/session_check.py --url \"$PLATFORM\"   (want exit 0)"
echo "  3. opencode   ->   /resume   (or /solve CHAL-001 after pull)"
echo "  4. ./run_ctf.sh pull --max 10"
