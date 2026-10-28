#!/usr/bin/env bash
# run_ctf.sh — day-ops for ONE engagement copy (v1.0 copy-per-CTF model).
#
#   ./start.sh "Event Name" https://platform-url
#       Full bring-up: deps + MCP warm + state init + Chrome + health + self-test.
#       Run once per copied engagement folder. Then log in manually.
#   ./run_ctf.sh preflight
#       Env + deps + state + backends + fast self-test. Run anytime.
#   ./run_ctf.sh start "Event Name" https://platform-url
#       Same as start.sh (delegates). Kept for muscle memory.
#   ./run_ctf.sh status
#       Competition state, ledger, bench sanity in one view.
#   ./run_ctf.sh pull [--max N]
#       Pull unregistered challenges (needs logged-in session).
#   ./run_ctf.sh quickwins [CHAL-ID]
#       Cheap offline sweep (flag regex/b64/hex) so no challenge returns nothing.
#   ./run_ctf.sh stop
#       Close scratch tabs, kill the dedicated Chrome, summary.
#
# After start: run `opencode` here, then `/resume` (or `/solve CHAL-XXX`).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"  # tools assume framework root as cwd
# shellcheck disable=SC1091
[ -f "$ROOT/tools/env.sh" ] && source "$ROOT/tools/env.sh"

cmd="${1:-help}"
need() { command -v "$1" >/dev/null 2>&1 || { echo "MISSING: $1"; return 1; }; }

preflight() {
  echo "== [0] runtime =="
  need python3 && python3 --version | head -n 1
  echo "== [1] state =="
  python3 -c "import json; s=json.load(open('$ROOT/state.json')); print('state OK:', s['competition'].get('name'), '| challenges:', len(s.get('challenges',[])), '| flags:', len(s.get('flags',[])))"
  echo "== [2] toolchains =="
  local miss=0
  for t in gcc gdb file strings exiftool binwalk tshark nmap ffuf gobuster john hashcat docker tmux uvx npx; do
    command -v "$t" >/dev/null 2>&1 && echo "  ok: $t" || { echo "  MISSING: $t"; miss=1; }
  done
  python3 -c "import playwright, volatility3; print('  ok: playwright+volatility3')" 2>/dev/null || echo "  MISSING: playwright/volatility3 (pip install --user playwright volatility3)"
  [ -d "${GHIDRA_INSTALL_DIR:-/none}" ] && echo "  ok: ghidra" || echo "  SKIP: ghidra (rev falls back to r2/gdb)"
  [ "$miss" -ne 0 ] && echo "(missing CLI tools only degrade their domains)"
  echo "== [3] MCP backends =="
  python3 "$ROOT/tools/mcp_doctor.py"
  echo "== [4] self-test (offline) =="
  python3 "$ROOT/tools/bench.py" 2>&1 | tail -n 2
  echo "PREFLIGHT DONE"
}

start_event() {
  # v1.0: this folder IS the engagement (copied per event). Delegate to start.sh.
  exec "$ROOT/start.sh" "$@"
}

poll_platform() {
  local platform="${1:?usage: run_ctf.sh poll <platform-url>}"
  echo "== poll =="
  python3 "$ROOT/tools/ctfusion.py" --poll --pages 2 --base-url "$platform"
  python3 "$ROOT/tools/ctfusion.py" --queue --max 15
}

status_view() {
  "$ROOT/setup_ctf.sh" --status
  python3 "$ROOT/tools/ctfusion.py" --status
  python3 "$ROOT/tools/result_quality_gate.py" --validate-state --check-consistency 2>&1 | tail -n 1
}

pull_all() {
  local max="${1:-10}"
  local url
  url="$(python3 -c "import json;print(json.load(open('$ROOT/state.json'))['competition'].get('url',''))")"
  python3 "$ROOT/tools/session_check.py" --url "$url" || {
    echo ">> Session blocked — solve the CAPTCHA MANUALLY in the Chrome window, then:"; echo "   python3 tools/captcha_gate.py --url \"$url\""; return 2; }
  echo "pulling up to $max unregistered challenges (serial, paced)…"
  python3 - <<EOF
import json, subprocess, sys
items = json.load(open('$ROOT/challenges/_index.json'))
reg = {c.get('id') for c in json.load(open('$ROOT/state.json')).get('challenges', [])}
n = 0
for it in items:
    cid = it.get('chal_id')
    if not cid or cid in reg or n >= $max: continue
    print(f'-- pull {cid} {it.get("title","")} --')
    r = subprocess.run(['python3', 'tools/browser_extract.py', '--pull', cid,
                        '--base-url', json.load(open('$ROOT/state.json'))['competition']['url']],
                       cwd='$ROOT', capture_output=True, text=True, timeout=300)
    print((r.stdout + r.stderr)[-400:])
    n += 1
print(f'pulled {n}')
EOF
}

stop_all() {
  echo "== tabs =="
  python3 "$ROOT/tools/btabs.py" cleanup || true
  echo "== challenge summary =="
  python3 "$ROOT/tools/ctfusion.py" --status
  pkill -f "remote-debugging-port=9222" 2>/dev/null && echo "dedicated Chrome stopped" || echo "dedicated Chrome already stopped"
}

case "$cmd" in
  preflight) preflight ;;
  start) shift; start_event "$@" ;;
  poll) shift; poll_platform "$@" ;;
  status) status_view ;;
  pull) shift; pull_all "$@" ;;
  quickwins) shift; python3 "$ROOT/tools/autosolve.py" --all "$@" ;;
  stop) stop_all ;;
  *) sed -n '2,20p' "$0"; exit 1 ;;
esac
