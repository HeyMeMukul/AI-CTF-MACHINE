#!/usr/bin/env python3
"""model_router.py — explicit model-route lookup (no invented fleet).

Routes are read from config/model_routes.json and/or environment variables:
  CTF_MODEL_LEAD, CTF_MODEL_WORKER, CTF_MODEL_FAST

Usage:
  model_router.py --task plan
  model_router.py --task exploit --leaf-tags heap-fengshui
  model_router.py --check

Exit 0 = route printed / check configured; 1 = unconfigured (--check);
2 = no route configured for this task.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ROUTES_FILE = ROOT / "config" / "model_routes.json"

COMPLEX_TAGS = {"crypto-math", "heap-fengshui", "vm-deobf", "lattice",
                "ecdsa-nonce", "fsop", "srop", "kernel-adjacent", "defi-math"}
LEAD_TASKS = {"plan", "dispatch-review", "flagpath", "writeup", "think",
              "chain", "resume", "status-review", "handoff-merge"}
FAST_TASKS = {"status", "lint", "triage-classify", "summarize", "probe",
              "format", "index"}


def load_routes() -> dict[str, str]:
    routes = {"lead": "", "worker": "", "fast": ""}
    if ROUTES_FILE.is_file():
        try:
            data = json.loads(ROUTES_FILE.read_text(encoding="utf-8"))
            for key in routes:
                if isinstance(data.get(key), str):
                    routes[key] = data[key].strip()
        except (OSError, ValueError):
            pass
    for key in routes:
        env = os.environ.get(f"CTF_MODEL_{key.upper()}", "").strip()
        if env:
            routes[key] = env
    return routes


def choose(task: str, tags: set[str]) -> str:
    if tags & COMPLEX_TAGS or task in LEAD_TASKS or task.startswith(("plan", "synth", "merge", "review")):
        return "lead"
    if task in FAST_TASKS:
        return "fast"
    return "worker"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--task", default=None)
    ap.add_argument("--leaf-tags", default="")
    ap.add_argument("--stalled", action="store_true")
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    routes = load_routes()
    configured = {k: v for k, v in routes.items() if v}
    distinct = set(configured.values())

    if a.check:
        if len(configured) < 2 or len(distinct) < 2:
            print("UNCONFIGURED: set at least two distinct models in "
                  f"{ROUTES_FILE} or CTF_MODEL_LEAD/WORKER/FAST")
            return 1
        print(f"OK: {len(configured)} route(s), {len(distinct)} distinct model(s)")
        return 0

    if not a.task:
        ap.print_help()
        return 2
    tags = {t.strip() for t in a.leaf_tags.split(",") if t.strip()}
    key = "lead" if a.stalled else choose(a.task.lower().replace("-", "_"), tags)
    model = routes.get(key, "")
    if not model:
        print(f"UNCONFIGURED: route {key!r} has no model. Set {ROUTES_FILE} or "
              f"CTF_MODEL_{key.upper()}.")
        return 2
    print(model)
    return 0


if __name__ == "__main__":
    sys.exit(main())
