"""The autonomous daemon: poll a platform, schedule tasks, solve, submit, repeat.

Usage:
    python3 -m engine daemon --platform ctfd --url "$CTFD_URL" --workers 8

The daemon is a single process with a durable SQLite queue and a thread pool.
Each task gets its own sandbox; a crash or timeout is recorded and the loop
keeps going.  Stop with Ctrl-C (running tasks finish).
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import time
import traceback
import uuid
from pathlib import Path

from . import config
from .core import SubmitLedger, Task, sha256_text
from .envs import build_env
from .providers import build_provider
from .scheduler import Store
from .solver import Solver


class Daemon:
    def __init__(self, cfg: dict, adapter, store: Store, provider_kind: str | None = None):
        self.cfg = cfg
        self.adapter = adapter
        self.store = store
        self.provider_kind = provider_kind or str(config.get(cfg, "provider.kind", "mock"))
        self.event_dir = config.event_root(cfg)
        self.workers = int(config.get(cfg, "scheduler.workers", 8))
        self.poll_seconds = int(config.get(cfg, "scheduler.poll_seconds", 30))
        self.max_attempts = int(config.get(cfg, "scheduler.max_attempts", 3))
        self.lease_seconds = int(config.get(cfg, "scheduler.lease_seconds", 1800))

    def run(self, max_hours: float | None = None, once: bool = False) -> dict:
        config.ensure_dirs(self.event_dir / "challenges", self.event_dir / "runs", self.event_dir / "flags")
        started = time.time()
        self._banner()
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=self.workers)
        futures: dict[concurrent.futures.Future, str] = {}
        try:
            while True:
                try:
                    added = self.adapter.sync(self.store, self.event_dir)
                    if added:
                        print(f"[sync] {added} new task(s)")
                except Exception as exc:  # noqa: BLE001 - platform outages must not kill the daemon
                    print(f"[sync-error] {type(exc).__name__}: {exc}")
                requeued = self.store.requeue_expired(self.max_attempts)
                if requeued:
                    print(f"[reaper] {requeued} expired lease(s)")
                for future in list(futures):
                    if future.done():
                        futures.pop(future, None)
                while len(futures) < self.workers:
                    task = self.store.lease(self.lease_seconds, self.max_attempts)
                    if task is None:
                        break
                    print(f"[lease] {task.id} ({task.category}, {task.points} pts)")
                    future = executor.submit(self._run_task, task)
                    futures[future] = task.id
                if once:
                    concurrent.futures.wait(futures)
                    break
                if max_hours is not None and (time.time() - started) / 3600.0 >= max_hours:
                    print(f"[stop] max_hours={max_hours} reached; waiting for running tasks")
                    break
                time.sleep(self.poll_seconds)
        finally:
            executor.shutdown(wait=True)
        stats = self.store.stats()
        print(f"[done] {stats}")
        return stats

    # ------------------------------------------------------------------ worker
    def _run_task(self, task: Task) -> None:
        workdir = self.event_dir / "challenges" / task.id
        run_dir = self.event_dir / "runs" / f"{task.id}-{uuid.uuid4().hex[:8]}"
        run_dir.mkdir(parents=True, exist_ok=True)
        env = None
        try:
            live = task.source.startswith("ctfd")
            env = build_env(self.cfg, workdir, live=live)
            env.start()
            oracle = self.adapter.oracle_for(task)
            attempts = max(1, int(config.get(self.cfg, "solver.attempts", 1)))
            ledger = SubmitLedger(max_submits=int(config.get(self.cfg, "solver.max_submits", 5)))
            prior: list[str] = []
            result = None
            for attempt in range(1, attempts + 1):
                mock_script = (task.metadata.get("mock_script")
                               if self.provider_kind == "mock" and attempt == 1 else None)
                provider = build_provider(self.cfg, mock_script=mock_script)
                attempt_dir = run_dir / f"attempt-{attempt}"
                result = Solver(provider, self.cfg).run(
                    task, env, oracle, attempt_dir,
                    attempt=attempt, attempts=attempts, prior=prior, ledger=ledger,
                )
                if result.status == "solved":
                    break
                prior.append(f"attempt {attempt}: {result.status} after {result.steps} steps"
                             + (f" ({result.error})" if result.error else ""))
            if result is None:
                raise RuntimeError("solver produced no result")
            (run_dir / "result.json").write_text(json.dumps(result.to_dict(), indent=1), encoding="utf-8")
            if result.status == "solved" and result.candidate:
                flag_path = self.event_dir / "flags" / f"{task.id}.txt"
                flag_path.parent.mkdir(parents=True, exist_ok=True)
                flag_path.write_text(result.candidate + "\n", encoding="utf-8")
                os.chmod(flag_path, 0o600)
                print(f"[solved] {task.id} -> {flag_path} "
                      f"({result.steps} steps, {result.seconds:.1f}s)")
            else:
                print(f"[{result.status}] {task.id} ({result.steps} steps, {result.seconds:.1f}s)")
            self.store.complete(task.id, result.status, result.seconds, result.tokens, result.error)
        except Exception as exc:  # noqa: BLE001 - one task must not kill the daemon
            detail = f"{type(exc).__name__}: {exc}"
            print(f"[error] {task.id}: {detail}")
            traceback.print_exc(limit=3)
            self.store.complete(task.id, "error", 0.0, 0, detail[:1000])
        finally:
            if env is not None:
                try:
                    env.close()
                except Exception:  # noqa: BLE001
                    pass

    def _banner(self) -> None:
        cfg = self.cfg
        print("=" * 72)
        print(f"CTF engine daemon  |  event={config.get(cfg, 'event_slug')}  "
              f"platform={config.get(cfg, 'platform.kind')}  provider={self.provider_kind}")
        print(f"workers={self.workers} poll={self.poll_seconds}s lease={self.lease_seconds}s "
              f"max_attempts={self.max_attempts}")
        print(f"sandbox={config.get(cfg, 'sandbox.kind')} image={config.get(cfg, 'sandbox.image')}")
        print(f"event_dir={self.event_dir}")
        print("=" * 72)
