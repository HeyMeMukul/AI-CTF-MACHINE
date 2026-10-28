#!/usr/bin/env bash
# tools/env.sh — framework runtime environment (source me).
#   source tools/env.sh
# Provides: Temurin JDK 21 (Ghidra 12.x requirement), GHIDRA_INSTALL_DIR,
# user-local bins, stable PATH order (JDK first so `java` resolves correctly).
CTF_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export JAVA_HOME="/home/cyb3rfy/jdk/jdk-21.0.12.1+1"
export GHIDRA_INSTALL_DIR="/home/cyb3rfy/ghidra/ghidra_12.1.4_PUBLIC"
export PATH="$JAVA_HOME/bin:/home/cyb3rfy/.local/bin:$PATH"
export CTF_ROOT
