"""Command-line interface for the autonomous CTF engine."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from . import __version__, config, knowledge
from .adapters import CTFdAdapter, LocalAdapter
from .daemon import Daemon
from .eval_runner import run_suite, run_task_dir
from .providers import ProviderError, build_provider
from .scheduler import Store


# --------------------------------------------------------------------- helpers
def _common() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--config", default=None, help="JSON config (default: config/engine.json)")
    return p


def _load(args, overrides: dict | None = None) -> dict:
    path = args.config
    if path is None:
        candidate = config.ROOT / "config" / "engine.json"
        path = str(candidate) if candidate.is_file() else None
    cfg = config.load(path, overrides)
    if getattr(args, "provider", None):
        cfg.setdefault("provider", {})["kind"] = args.provider
    return cfg


def _print_kv(title: str, pairs: dict) -> None:
    print(title)
    for key, value in pairs.items():
        print(f"  {key}: {value}")


# -------------------------------------------------------------------- commands
def cmd_selftest(args) -> int:
    print(f"CTF engine {__version__} selftest")
    loader = unittest.TestLoader()
    suite = loader.discover(str(config.ROOT / "tests"), pattern="test_*.py")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        print("SELFTEST FAIL: unit tests")
        return 1
    cfg = _load(args, {"provider": {"kind": "mock"}, "sandbox": {"kind": "local"},
                       "event_slug": "selftest"})
    suite_result = run_suite(config.ROOT / "eval" / "suites" / "smoke.json", "mock", cfg)
    if suite_result.total == 0 or suite_result.solved != suite_result.total:
        print(f"SELFTEST FAIL: mock eval {suite_result.solved}/{suite_result.total}")
        return 1
    print(f"SELFTEST PASS: {suite_result.solved}/{suite_result.total} mock tasks solved")
    return 0


def cmd_eval(args) -> int:
    cfg = _load(args)
    suite = Path(args.suite)
    if not suite.is_absolute():
        suite = config.ROOT / suite
    result = run_suite(suite, args.provider, cfg, keep=args.keep)
    if args.fail_under is not None and result.pass_at_1 < args.fail_under:
        print(f"FAIL: pass@1 {result.pass_at_1:.2f} < {args.fail_under:.2f}")
        return 1
    return 0


def cmd_run(args) -> int:
    cfg = _load(args)
    folder = Path(args.task)
    if not folder.is_absolute():
        folder = config.ROOT / folder
    result = run_task_dir(folder, args.provider, cfg, keep=args.keep)
    print(json.dumps(result.to_dict(), indent=1))
    return 0 if result.status == "solved" else 1


def cmd_knowledge(args) -> int:
    cfg = _load(args)
    if args.catalog:
        entries = knowledge.search_catalog(
            args.query, config.ROOT, top_k=args.top,
            domains=[args.domain] if args.domain else None,
            include_unmapped=args.include_unverified,
        )
        if not entries:
            print("no matching catalog entries")
            return 1
        for entry in entries:
            print(f"[{entry.get('status'):8s}] {entry.get('name')}  "
                  f"({', '.join(entry.get('domains') or []) or 'unmapped'})")
            print(f"  {entry.get('description', '')[:240]}")
            print(f"  {entry.get('url', '')}")
        return 0
    recipes = knowledge.retrieve(
        args.query,
        config.recipes_root(cfg),
        domain=args.domain,
        top_k=args.top,
        include_unverified=args.include_unverified,
        include_source_verified=not args.exclude_source_verified,
    )
    if not recipes:
        print("no matching recipes (is the corpus verified?)")
        return 1
    for recipe in recipes:
        print(f"## {recipe.get('title', recipe.get('id'))} [{recipe.get('domain')}] "
              f"verified={recipe.get('verified')} "
              f"verification={recipe.get('verification', 'fixture')}")
        for key in ("signals", "preconditions", "steps", "falsifier", "pitfalls", "sources"):
            value = recipe.get(key)
            if value:
                if isinstance(value, list):
                    print(f"  {key}: " + "; ".join(str(v) for v in value))
                else:
                    print(f"  {key}: {value}")
        print()
    return 0


def cmd_doctor(args) -> int:
    cfg = _load(args)
    problems = 0
    print(f"CTF engine {__version__} doctor")
    _print_kv("config", {
        "provider": config.get(cfg, "provider.kind"),
        "model": config.get(cfg, "provider.model") or "(unset)",
        "sandbox": config.get(cfg, "sandbox.kind"),
        "platform": config.get(cfg, "platform.kind"),
        "event_slug": config.get(cfg, "event_slug"),
    })
    kind = str(config.get(cfg, "provider.kind", "mock")).lower()
    if kind == "mock":
        print("  WARN provider=mock (offline tests only; set provider.kind=openai for real runs)")
    else:
        key_env = str(config.get(cfg, "provider.api_key_env", "LLM_API_KEY"))
        if not os.environ.get(key_env):
            print(f"  FAIL missing API key env {key_env}")
            problems += 1
        if not str(config.get(cfg, "provider.base_url", "")).startswith("http"):
            print("  FAIL provider.base_url is not an http(s) URL")
            problems += 1
        if not config.get(cfg, "provider.model"):
            print("  FAIL provider.model is empty")
            problems += 1
        if args.ping and problems == 0:
            try:
                text = build_provider(cfg).ping()
                print(f"  OK provider ping: {text!r}")
            except Exception as exc:  # noqa: BLE001
                print(f"  FAIL provider ping: {type(exc).__name__}: {exc}")
                problems += 1

    sandbox = str(config.get(cfg, "sandbox.kind", "local")).lower()
    if sandbox == "local":
        print("  WARN sandbox=local is not a security boundary; use docker for platform tasks")
    else:
        image = str(config.get(cfg, "sandbox.image", ""))
        proc = subprocess.run(["docker", "image", "inspect", image], capture_output=True, text=True)
        if proc.returncode != 0:
            print(f"  FAIL docker image {image!r} not found (build it or change sandbox.image)")
            problems += 1
        else:
            print(f"  OK docker image {image}")

    recipe_problems = knowledge.audit(config.recipes_root(cfg))
    for problem in recipe_problems:
        print(f"  FAIL recipe: {problem}")
        problems += 1
    if not recipe_problems:
        print("  OK recipes verified and well-formed")
    catalog = knowledge.catalog_stats(config.ROOT)
    imported = len(list((config.ROOT / "skills" / "imported").glob("*/SKILL.md")))
    print(f"  OK imported skills: {imported} card(s)")
    print(f"  OK catalog: {catalog['total']} entries {catalog['counts']}")

    suite = config.ROOT / "eval" / "suites" / "smoke.json"
    print(f"  {'OK' if suite.is_file() else 'FAIL'} eval suite {suite}")
    if not suite.is_file():
        problems += 1

    platform = str(config.get(cfg, "platform.kind", "ctfd")).lower()
    if platform == "ctfd":
        token_env = str(config.get(cfg, "platform.token_env", "CTFD_TOKEN"))
        if not os.environ.get(token_env):
            print(f"  WARN {token_env} is not set (needed for live CTFd)")
        elif args.ping:
            try:
                adapter = CTFdAdapter(str(config.get(cfg, "platform.url", "")), os.environ[token_env],
                                      float(config.get(cfg, "platform.pace_seconds", 2)))
                print(f"  OK CTFd: {len(adapter.list_challenges())} challenge(s) visible")
            except Exception as exc:  # noqa: BLE001
                print(f"  FAIL CTFd: {type(exc).__name__}: {exc}")
                problems += 1
    print("DOCTOR: " + ("PASS" if problems == 0 else f"FAIL ({problems} problem(s))"))
    return 0 if problems == 0 else 1


def cmd_daemon(args) -> int:
    cfg = _load(args)
    if args.workers:
        cfg.setdefault("scheduler", {})["workers"] = args.workers
    if args.poll:
        cfg.setdefault("scheduler", {})["poll_seconds"] = args.poll
    if args.sandbox:
        cfg.setdefault("sandbox", {})["kind"] = args.sandbox
    if args.event:
        cfg["event_slug"] = args.event
    if args.attempts:
        cfg.setdefault("solver", {})["attempts"] = args.attempts
    platform = args.platform or str(config.get(cfg, "platform.kind", "ctfd"))
    if platform == "local":
        tasks_dir = Path(args.tasks_dir) if args.tasks_dir else config.ROOT / "eval" / "tasks"
        adapter = LocalAdapter(tasks_dir)
    elif platform == "ctfd":
        url = args.url or str(config.get(cfg, "platform.url", ""))
        token_env = args.token_env or str(config.get(cfg, "platform.token_env", "CTFD_TOKEN"))
        token = os.environ.get(token_env, "")
        if not url or not token:
            print(f"ERROR: CTFd needs --url and ${token_env}")
            return 2
        adapter = CTFdAdapter(url, token, float(config.get(cfg, "platform.pace_seconds", 2)))
    else:
        print(f"ERROR: unknown platform {platform!r} (ctfd|local)")
        return 2
    store = Store(config.event_root(cfg) / "state.sqlite3")
    try:
        daemon = Daemon(cfg, adapter, store, provider_kind=args.provider)
        daemon.run(max_hours=args.max_hours, once=args.once)
    except KeyboardInterrupt:
        print("\n[stop] interrupted")
    finally:
        store.close()
    return 0


def cmd_init(args) -> int:
    slug = args.event
    cfg = config.load(None, {"event_slug": slug,
                             "platform": {"kind": args.platform, "url": args.url or ""}})
    event_dir = config.event_root(cfg)
    config.ensure_dirs(event_dir / "challenges", event_dir / "runs", event_dir / "flags")
    cfg_path = event_dir / "engine.json"
    if not cfg_path.exists():
        cfg_path.write_text(json.dumps({
            "event_slug": slug,
            "platform": {"kind": args.platform, "url": args.url or ""},
        }, indent=1), encoding="utf-8")
    print(f"initialized {event_dir}")
    print(f"config: {cfg_path}")
    print("next: set LLM_BASE_URL / LLM_API_KEY / LLM_MODEL, then run "
          f"`python3 -m engine daemon --platform {args.platform} --config {cfg_path}`")
    return 0


def cmd_status(args) -> int:
    cfg = _load(args)
    db = Path(args.db) if args.db else config.event_root(cfg) / "state.sqlite3"
    if not db.is_file():
        print(f"no state database at {db}")
        return 1
    store = Store(db)
    try:
        print(json.dumps(store.stats(), indent=1))
        for row in store.list()[:30]:
            print(f"{row['state']:8s} {row['id']:24s} {row['category']:12s} "
                  f"{row['points']:5d}pts attempts={row['attempts']}")
    finally:
        store.close()
    return 0


def cmd_ping(args) -> int:
    cfg = _load(args)
    try:
        print(build_provider(cfg).ping())
        return 0
    except (ProviderError, Exception) as exc:  # noqa: BLE001
        print(f"PING FAIL: {type(exc).__name__}: {exc}")
        return 1


# ------------------------------------------------------------------------ main
def build_parser() -> argparse.ArgumentParser:
    common = _common()
    parser = argparse.ArgumentParser(prog="python -m engine",
                                     description=f"Autonomous CTF engine v{__version__}")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("selftest", parents=[common], help="unit tests + mock eval")
    p.set_defaults(func=cmd_selftest)

    p = sub.add_parser("eval", parents=[common], help="run an offline eval suite")
    p.add_argument("--suite", default="eval/suites/smoke.json")
    p.add_argument("--provider", default="mock", choices=["mock", "openai"])
    p.add_argument("--fail-under", type=float, default=None)
    p.add_argument("--keep", action="store_true")
    p.set_defaults(func=cmd_eval)

    p = sub.add_parser("run", parents=[common], help="run one task directory")
    p.add_argument("--task", required=True)
    p.add_argument("--provider", default="mock", choices=["mock", "openai"])
    p.add_argument("--keep", action="store_true")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("knowledge", parents=[common], help="query verified recipes")
    p.add_argument("--query", required=True)
    p.add_argument("--domain", default=None)
    p.add_argument("--top", type=int, default=3)
    p.add_argument("--include-unverified", action="store_true")
    p.add_argument("--catalog", action="store_true", help="search the full imported catalog index")
    p.add_argument("--exclude-source-verified", action="store_true",
                   help="show only fixture-tested recipes")
    p.set_defaults(func=cmd_knowledge)

    p = sub.add_parser("doctor", parents=[common], help="check config, sandbox, provider, recipes")
    p.add_argument("--ping", action="store_true")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("daemon", parents=[common], help="autonomous poll/solve/submit loop")
    p.add_argument("--platform", default=None, choices=["ctfd", "local"])
    p.add_argument("--url", default=None)
    p.add_argument("--token-env", default=None)
    p.add_argument("--tasks-dir", default=None)
    p.add_argument("--provider", default=None, choices=["mock", "openai"])
    p.add_argument("--workers", type=int, default=None)
    p.add_argument("--poll", type=int, default=None)
    p.add_argument("--sandbox", default=None, choices=["local", "docker"])
    p.add_argument("--event", default=None, help="event slug for events/<slug>/")
    p.add_argument("--attempts", type=int, default=None, help="fresh-eyes attempts per task")
    p.add_argument("--max-hours", type=float, default=None)
    p.add_argument("--once", action="store_true")
    p.set_defaults(func=cmd_daemon)

    p = sub.add_parser("init", parents=[common], help="create an event workspace")
    p.add_argument("--event", required=True)
    p.add_argument("--platform", default="ctfd", choices=["ctfd", "local"])
    p.add_argument("--url", default="")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("status", parents=[common], help="show queue and outcome stats")
    p.add_argument("--db", default=None)
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("ping", parents=[common], help="one-token provider smoke test")
    p.set_defaults(func=cmd_ping)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args) or 0)


if __name__ == "__main__":
    sys.exit(main())
