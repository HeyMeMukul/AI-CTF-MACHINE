#!/usr/bin/env python3
"""artifact_spill.py — dump oversized outputs to files, return a 10-line summary.

SOTA basis: EnIGMA spill-to-file + LM summary (context-blowup fix #1).
Convention: Worker dumps >50-line outputs here; chat carries summaries only.

Usage: artifact_spill.py --from-cmd "tshark -r cap.pcap -V" [--out NAME] [--timeout 120]
  Runs the command, writes full output to artifacts/out-<n>.txt, prints the
  first 5 + last 5 lines plus byte/line counts and the artifact path.
  artifacts/ defaults to ./artifacts (created). Exit = command's exit code.
"""
import argparse
import glob
import os
import subprocess
import sys

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--from-cmd", required=True)
    ap.add_argument("--out", default=None)
    ap.add_argument("--dir", default="artifacts")
    ap.add_argument("--timeout", type=int, default=120)
    a = ap.parse_args()
    os.makedirs(a.dir, exist_ok=True)
    if a.out:
        path = os.path.join(a.dir, a.out)
    else:
        n = len(glob.glob(os.path.join(a.dir, "out-*.txt"))) + 1
        path = os.path.join(a.dir, f"out-{n:03d}.txt")
    try:
        p = subprocess.run(a.from_cmd, shell=True, capture_output=True,
                           text=True, timeout=a.timeout)
        blob = f"$ {a.from_cmd}\n[exit={p.returncode}]\n" + p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        blob = f"$ {a.from_cmd}\n[TIMEOUT after {a.timeout}s]\n"
        p = None
    open(path, "w").write(blob)
    lines = blob.splitlines()
    print(f"artifact: {path} ({len(blob)} bytes, {len(lines)} lines)")
    print("--- head ---")
    print("\n".join(lines[:5]))
    print("--- tail ---")
    print("\n".join(lines[-5:]))
    return p.returncode if p else 124

if __name__ == "__main__":
    sys.exit(main())
