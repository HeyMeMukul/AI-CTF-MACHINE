#!/usr/bin/env python3
"""captcha_gate.py — human-in-the-loop CAPTCHA / bot-wall gate.

A CAPTCHA is a HUMAN task by design. This tool does NOT solve, bypass, or
race it. It: (1) classifies the current operator tab via session_check logic,
(2) if challenged, pings the operator to solve MANUALLY in the dedicated
Chrome window, (3) re-probes until clear or --timeout expires.

Usage:
  captcha_gate.py --url <platform-or-target> [--cdp http://127.0.0.1:9222]
                  [--timeout 600] [--probe-interval 15]
Exit 0=clear (session_check exit 0), 2=still challenged at timeout, 1=down/error.

Pairs with: tools/operator_ping.sh (audible/human gate) + docs/LIVE_OPS.md §2.
"""
import argparse
import subprocess
import sys
import time

ROOT_NOTE = ("Solve the CAPTCHA / bot-check MANUALLY in the operator Chrome "
             "window (port 9222 profile), then the probe resumes automatically. "
             "Agent stays idle — no reloads, no retries, no new tabs.")


def probe(url, cdp):
    r = subprocess.run([sys.executable, "tools/session_check.py",
                        "--url", url, "--cdp", cdp],
                       capture_output=True, text=True, timeout=60)
    print((r.stdout + r.stderr).strip()[-300:])
    return r.returncode


def main():
    ap = argparse.ArgumentParser(description="Human CAPTCHA gate (no auto-solve).")
    ap.add_argument("--url", required=True)
    ap.add_argument("--cdp", default="http://127.0.0.1:9222")
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--probe-interval", type=int, default=15)
    a = ap.parse_args()
    deadline = time.time() + a.timeout
    first = True
    while True:
        rc = probe(a.url, a.cdp)
        if rc == 0:
            print("GATE CLEAR: session authenticated.")
            return 0
        if first:
            print(f"OPERATOR ACTION REQUIRED: {ROOT_NOTE}")
            try:
                subprocess.run(["bash", "tools/operator_ping.sh",
                                f"CAPTCHA/bot-wall on {a.url} — solve MANUALLY in operator Chrome",
                                "once"], timeout=30)
            except Exception as e:  # noqa: BLE001 — ping is best-effort
                print(f"(operator_ping failed: {e}; solve manually anyway)")
            first = False
        else:
            print(f"... still challenged, waiting {a.probe_interval}s (agent idle)")
        if time.time() >= deadline:
            print("GATE TIMEOUT: still challenged. Mark blocked(rate), work unblocked chals.")
            return 2
        time.sleep(a.probe_interval)


if __name__ == "__main__":
    sys.exit(main())
