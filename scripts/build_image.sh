#!/usr/bin/env bash
# build_image.sh — build the sandbox image used by the autonomous engine.
#
#   ./scripts/build_image.sh
#
# The image is the core toolset (python3, pwntools, gdb, binutils, netcat,
# crypto libs). Add domain tools to Dockerfile.kali-ctf and rebuild.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
IMAGE="${IMAGE:-ctf-kali:latest}"

echo "[build] image=$IMAGE"
docker build -f Dockerfile.kali-ctf -t "$IMAGE" .
echo "[build] done: $IMAGE"
docker image inspect "$IMAGE" --format '{{.RepoTags}} {{.Size}}'
