#!/usr/bin/env bash
# tools/ghidra_mcp.sh — opencode MCP launcher for GhidraMCP headless.
# Headless GhidraMCP binds ONE binary per server instance, so the binary comes
# from $GHIDRA_BINARY (set per rev task). Without it we fail fast with guidance
# instead of binding a stale target. For ad-hoc decompile of any binary, use:
#   python3 tools/rev_ghidra.py --binary <f> --decompile <fn>
set -u
if [ -z "${GHIDRA_BINARY:-}" ]; then
  echo "ghidra MCP needs GHIDRA_BINARY=/path/to/target (per-task binary)." >&2
  echo "Either set it and restart opencode, or use: python3 tools/rev_ghidra.py --binary <f> --decompile <fn>" >&2
  exit 1
fi
if [ ! -f "$GHIDRA_BINARY" ]; then
  echo "GHIDRA_BINARY not found: $GHIDRA_BINARY" >&2
  exit 1
fi
# shellcheck disable=SC1091
[ -f "$(dirname "$0")/env.sh" ] && source "$(dirname "$0")/env.sh"
export GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR:-/home/cyb3rfy/ghidra/ghidra_12.1.4_PUBLIC}"
JAR="${GHIDRA_JAR:-/home/cyb3rfy/ghidra-mcp/GhidraMCP.jar}"
exec uvx --python 3.13 --from "ghidra-mcp[headless] @ git+https://github.com/LaurieWired/GhidraMCP" \
  ghidra-mcp --headless --binary "$GHIDRA_BINARY" --extension-jar "$JAR"
