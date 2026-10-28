#!/usr/bin/env bash
# setup_ctf.sh — CTF solver framework init / resume / status
# Usage:
#   ./setup_ctf.sh --init "competition-name" [platform]   # scaffold dirs + state
#   ./setup_ctf.sh --resume                              # show resume pointer
#   ./setup_ctf.sh --status                              # state summary
#   ./setup_ctf.sh --build [--profile full]              # build solver image
#   ./setup_ctf.sh --browser [port]                       # launch dedicated operator Chrome (manual login)
#   ./setup_ctf.sh --browser-status [port]                # check CDP + session profile
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROFILE_DIR="$ROOT/.browser-profile"
CDP_PORT="${2:-9222}"

cmd="${1:---status}"
case "$cmd" in
  --init)
    NAME="${2:-picoCTF-practice}"
    PLATFORM="${3:-local}"
    mkdir -p "$ROOT"/{challenges,results,tasks,tasks/templates,docs,knowledge/corpus_seed,knowledge/writeups_patterns,knowledge/tool_cheatsheets,tools,skills/{_shared,triage,web-ctf,pwn,rev,crypto,forensics,stego,misc-pyjail,osint,hardware,blockchain,mobile,ai-ml,sessions,mcp-servers,browser-ops,chaining-flagpath,report-writeup},phases,config,writeups}
    mkdir -p "$ROOT/challenges/_inbox"
    for d in web-ctf pwn rev crypto forensics stego misc-pyjail osint hardware blockchain mobile ai-ml; do
      mkdir -p "$ROOT/challenges/$d"
    done
    python3 - "$ROOT/state.json" "$NAME" "$PLATFORM" <<'EOF'
import json, sys, datetime
p, name, plat = sys.argv[1], sys.argv[2], sys.argv[3]
st = json.load(open(p))
st["competition"].update({"name": name, "platform": plat,
  "started": datetime.datetime.utcnow().isoformat() + "Z", "status": "active"})
st["_meta"]["last_updated_by"] = "setup --init"
json.dump(st, open(p, "w"), indent=2)
print(f"init: competition={name} platform={plat}")
EOF
    echo "dirs ready. Next: opencode  →  /resume  or  /triage CHAL-001"
    ;;
  --resume)
    python3 -c "import json; s=json.load(open('$ROOT/state.json')); print('focus:', s['competition'].get('current_focus')); print('challenges:', len(s.get('challenges',[]))); print('flags:', len(s.get('flags',[])))"
    echo "Next: opencode /resume"
    ;;
  --status)
    python3 -c "import json; s=json.load(open('$ROOT/state.json')); print(json.dumps({'competition':s['competition'],'triage':s['triage'],'analysis':s['analysis'],'exploiting':s['exploiting'],'flags':len(s.get('flags',[]))}, indent=2))"
    ;;
  --build)
    PROFILE="slim"
    [[ "${2:-}" == "--profile" && "${3:-}" == "full" ]] && PROFILE="full"
    docker build --build-arg "PROFILE=$PROFILE" -f "$ROOT/Dockerfile.kali-ctf" -t ctf-solver:$PROFILE "$ROOT"
    echo "built ctf-solver:$PROFILE"
    ;;
  --browser)
    # Dedicated operator Chrome: separate persistent profile (Chrome 136+ forbids
    # remote-debug on default). Operator owns login/CAPTCHA MANUALLY; agent only
    # attaches via CDP. Hardened flags reduce automation fingerprint so legit
    # manual logins trip fewer challenges; they do NOT bypass any CAPTCHA.
    mkdir -p "$PROFILE_DIR"
    if curl -s --max-time 3 "http://127.0.0.1:$CDP_PORT/json/version" > /dev/null 2>&1; then
      echo "Chrome already on :$CDP_PORT. Reusing (attach-only)."
    else
      BIN="$(command -v google-chrome || command -v chromium || command -v chromium-browser || true)"
      [[ -z "$BIN" ]] && { echo "no chrome binary found"; exit 1; }
      "$BIN" --user-data-dir="$PROFILE_DIR" --remote-debugging-port="$CDP_PORT" \
        --no-first-run --no-default-browser-check \
        --disable-blink-features=AutomationControlled \
        --disable-dev-shm-usage --disable-hang-monitor \
        --password-store=basic --no-sandbox about:blank > "$ROOT/.browser.log" 2>&1 &
      sleep 3
      curl -s --max-time 5 "http://127.0.0.1:$CDP_PORT/json/version" | head -c 300; echo
    fi
    echo "BROWSER RULES (read before touching the platform):"
    echo "  1. LOG IN + SOLVE any CAPTCHA MANUALLY in that window. Agent never fills creds."
    echo "  2. Keep ONE operator tab flow at a time (serial per profile, 8-10s pacing)."
    echo "  3. CAPTCHA/429 on agent attach -> STOP, solve manually, then re-run --check."
    echo "THEN: python3 tools/session_check.py --url <platform>  (expect exit 0)"
    echo "THEN: python3 tools/browser_extract.py --check --base-url <platform>"
    ;;
  --browser-status)
    curl -s --max-time 5 "http://127.0.0.1:$CDP_PORT/json/version" || { echo "NO-BROWSER on :$CDP_PORT"; exit 1; }
    echo; echo "profile: $PROFILE_DIR"
    ;;
  *) echo "usage: $0 --init <name> [platform] | --resume | --status | --build [--profile full] | --browser [port] | --browser-status [port]"; exit 1;;
esac
