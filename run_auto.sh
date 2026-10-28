#!/usr/bin/env bash
# run_auto.sh — start the autonomous CTF engine against a CTFd platform.
#
# Required:
#   export CTFD_URL=https://ctf.example.com
#   export CTFD_TOKEN=...          # CTFd profile -> Settings -> Access Tokens
#   export LLM_BASE_URL=https://api.openai.com/v1
#   export LLM_API_KEY=...
#   export LLM_MODEL=...
#
# Optional:
#   WORKERS=8  MAX_HOURS=12  CONFIG=config/engine.json
#   EVENT_SLUG=my-event  ATTEMPTS=1
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

: "${CTFD_URL:?export CTFD_URL=https://your-ctfd}"
: "${CTFD_TOKEN:?export CTFD_TOKEN=your-api-token}"
: "${LLM_API_KEY:?export LLM_API_KEY=your-key}"
: "${LLM_MODEL:?export LLM_MODEL=your-model-id}"
: "${LLM_BASE_URL:=https://api.openai.com/v1}"
export CTFD_URL CTFD_TOKEN LLM_API_KEY LLM_BASE_URL LLM_MODEL

CONFIG="${CONFIG:-config/engine.json}"
EVENT_SLUG="${EVENT_SLUG:-ctf}"
ATTEMPTS="${ATTEMPTS:-1}"

if ! docker image inspect "${IMAGE:-ctf-kali:latest}" >/dev/null 2>&1; then
  echo "Sandbox image ${IMAGE:-ctf-kali:latest} is missing."
  echo "Build it once with: ./scripts/build_image.sh"
  exit 1
fi

python3 -m engine doctor --config "$CONFIG" --ping || {
  echo
  echo "Doctor failed. Fix the items above before starting the daemon."
  exit 1
}

exec python3 -m engine daemon \
  --config "$CONFIG" \
  --platform ctfd \
  --url "$CTFD_URL" \
  --provider openai \
  --event "$EVENT_SLUG" \
  --attempts "$ATTEMPTS" \
  --workers "${WORKERS:-8}" \
  --max-hours "${MAX_HOURS:-12}"
