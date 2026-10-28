#!/usr/bin/env bash
# operator_ping.sh — hard-gate beeper (ported from bug-bounty framework).
# Usage: tools/operator_ping.sh "<need>" [once|loop]
# Prints the need + beeps until answered. Never silent standby: Lead keeps
# solving unblocked work while this pings.
set -uo pipefail
NEED="${1:-operator input needed}"
MODE="${2:-loop}"
echo "=== OPERATOR GATE === $NEED"
echo "Started: $(date -u +%FT%TZ). Resolve, then Ctrl-C this ping."
if [[ "$MODE" == "once" ]]; then
  printf '\a'; echo "NEED: $NEED"
  exit 0
fi
while true; do
  printf '\a'
  echo "[$(date -u +%T)] NEED: $NEED"
  sleep 10
done
