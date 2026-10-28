"""Configuration loading and path helpers for the CTF engine.

The engine is stdlib-only, so config is JSON (not YAML).  Environment
variables written as ``${NAME}`` are expanded at load time.  Paths are
resolved relative to the CTF root (the directory containing ``engine/``).
"""

from __future__ import annotations

import copy
import json
import os
import re
from pathlib import Path
from typing import Any

_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")

DEFAULTS: dict[str, Any] = {
    "event_slug": "demo",
    "provider": {
        "kind": "mock",
        "base_url": "${LLM_BASE_URL}",
        "api_key_env": "LLM_API_KEY",
        "model": "${LLM_MODEL}",
        "temperature": 0.2,
        "max_tokens": 4096,
        "timeout_s": 180,
        "extra_body": {},
    },
    "solver": {
        "max_steps": 40,
        "max_seconds": 900,
        "max_tokens": 200000,
        "max_submits": 5,
        "max_llm_retries": 2,
        "compact_after_messages": 80,
        "attempts": 1,
    },
    "sandbox": {
        "kind": "local",
        "image": "ctf-kali:latest",
        "network": "none",
        "live_network": "bridge",
        "cpus": 2,
        "memory": "2g",
        "pids_limit": 256,
        "timeout_s": 120,
        "read_only": False,
    },
    "scheduler": {
        "workers": 8,
        "poll_seconds": 30,
        "max_hours": 12,
        "max_attempts": 3,
        "lease_seconds": 1800,
        "seed_points": 100,
    },
    "platform": {
        "kind": "ctfd",
        "url": "${CTFD_URL}",
        "token_env": "CTFD_TOKEN",
        "pace_seconds": 2,
        "timeout_s": 30,
    },
    "knowledge": {
        "include_unverified": False,
        "include_source_verified": True,
        "top_k": 2,
    },
    "paths": {
        "events": "events",
        "runs": "runs",
        "recipes": "recipes",
    },
}

ROOT = Path(__file__).resolve().parents[1]


def _expand(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _expand(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_expand(v) for v in obj]
    if isinstance(obj, str):
        return _ENV_RE.sub(lambda m: os.environ.get(m.group(1), ""), obj)
    return obj


def _merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def load(path: str | os.PathLike | None = None, overrides: dict | None = None) -> dict:
    cfg = copy.deepcopy(DEFAULTS)
    if path:
        p = Path(path)
        if not p.is_file():
            raise FileNotFoundError(f"config not found: {p}")
        cfg = _merge(cfg, json.loads(p.read_text(encoding="utf-8")))
    if overrides:
        cfg = _merge(cfg, overrides)
    return _expand(cfg)


def get(cfg: dict, dotted: str, default: Any = None) -> Any:
    cur: Any = cfg
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def path_of(cfg: dict, dotted: str) -> Path:
    """Resolve a configured path relative to the CTF root."""
    value = get(cfg, dotted, "")
    p = Path(str(value))
    return p if p.is_absolute() else (ROOT / p)


def event_root(cfg: dict) -> Path:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(get(cfg, "event_slug", "event"))).strip("-") or "event"
    return path_of(cfg, "paths.events") / slug


def runs_root(cfg: dict) -> Path:
    return path_of(cfg, "paths.runs")


def recipes_root(cfg: dict) -> Path:
    return path_of(cfg, "paths.recipes")


def ensure_dirs(*paths: Path) -> None:
    for p in paths:
        p.mkdir(parents=True, exist_ok=True)
