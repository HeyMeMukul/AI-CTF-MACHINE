"""Offline eval harness: tasks with known flags, a local oracle, and metrics.

Run with the deterministic mock provider to test the control plane, or with a
real provider to measure solve rate.  No network is required for the smoke
suite.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from . import config
from .core import LocalFlagOracle, RunResult, Task, Trace, sha256_text
from .envs import LocalEnv, build_env
from .providers import MockProvider, build_provider, load_script
from .solver import Solver


@dataclass
class SuiteResult:
    suite: str
    results: list[RunResult] = field(default_factory=list)
    path: str = ""

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def solved(self) -> int:
        return sum(1 for r in self.results if r.status == "solved")

    @property
    def pass_at_1(self) -> float:
        return self.solved / self.total if self.total else 0.0

    def to_dict(self) -> dict:
        return {
            "suite": self.suite,
            "total": self.total,
            "solved": self.solved,
            "pass@1": round(self.pass_at_1, 3),
            "seconds": round(sum(r.seconds for r in self.results), 2),
            "tokens": sum(r.tokens for r in self.results),
            "results": [r.to_dict() for r in self.results],
        }


def _load_task(folder: Path) -> tuple[dict, str]:
    spec = json.loads((folder / "task.json").read_text(encoding="utf-8"))
    expected = ""
    expected_path = folder / "expected_flag.txt"
    if expected_path.is_file():
        expected = expected_path.read_text(encoding="utf-8").strip()
    return spec, expected


def _mock_path(folder: Path, run_dir: Path, expected: str) -> Path | None:
    src = folder / "mock.json"
    if not src.is_file():
        return None
    resolved = run_dir / "mock_resolved.json"
    resolved.write_text(src.read_text(encoding="utf-8").replace("{{FLAG}}", expected), encoding="utf-8")
    return resolved


def run_task_dir(folder: str | Path, provider_kind: str, cfg: dict, keep: bool = False) -> RunResult:
    folder = Path(folder)
    spec, expected = _load_task(folder)
    salt = str(spec.get("salt") or "")
    flag_hash = str(spec.get("flag_sha256") or (sha256_text(salt + expected) if expected else ""))
    run_dir = Path(tempfile.mkdtemp(prefix=f"ctf-run-{spec.get('id', 'task')}-"))
    workdir = run_dir / "work"
    (workdir / "given").mkdir(parents=True, exist_ok=True)
    files_dir = folder / "files"
    if files_dir.is_dir():
        shutil.copytree(files_dir, workdir / "given", dirs_exist_ok=True)
    task = Task(
        id=str(spec.get("id") or folder.name),
        title=str(spec.get("title") or folder.name),
        category=str(spec.get("category") or "unknown"),
        difficulty=str(spec.get("difficulty") or "unknown"),
        points=int(spec.get("points") or 100),
        description=str(spec.get("description") or ""),
        files=[f"given/{p.name}" for p in (workdir / "given").iterdir() if p.is_file()],
        connection=spec.get("connection"),
        flag_format=spec.get("flag_format"),
        source="eval",
        platform_id=spec.get("id"),
        metadata={"flag_sha256": flag_hash, "salt": salt},
    )
    sandbox = str(spec.get("sandbox") or config.get(cfg, "sandbox.kind", "local"))
    if sandbox == "docker":
        env = build_env(cfg, workdir, live=False)
    else:
        env = LocalEnv(workdir)
    oracle = LocalFlagOracle(flag_hash, salt)
    if provider_kind == "mock":
        mock = _mock_path(folder, run_dir, expected)
        if mock is None:
            raise ValueError(f"mock provider requested but {folder}/mock.json is missing")
        provider = MockProvider(load_script(mock))
    else:
        provider = build_provider(cfg)
    trace = Trace(run_dir / "trace.jsonl", task_id=task.id)
    try:
        env.start()
        result = Solver(provider, cfg).run(task, env, oracle, run_dir, trace=trace)
    finally:
        env.close()
    out_dir = config.runs_root(cfg) / f"{time.strftime('%Y%m%d-%H%M%S')}-{spec.get('id', 'task')}"
    config.ensure_dirs(out_dir)
    trace_copy = out_dir / "trace.jsonl"
    shutil.copyfile(trace.path, trace_copy)
    result.trace_path = str(trace_copy)
    (out_dir / "result.json").write_text(json.dumps(result.to_dict(), indent=1), encoding="utf-8")
    if keep:
        print(f"[keep] {run_dir}")
    else:
        shutil.rmtree(run_dir, ignore_errors=True)
    return result


def run_suite(suite_path: str | Path, provider_kind: str, cfg: dict, keep: bool = False) -> SuiteResult:
    suite_path = Path(suite_path)
    spec = json.loads(suite_path.read_text(encoding="utf-8"))
    base = suite_path.parent.parent / "tasks"
    suite = SuiteResult(suite=str(spec.get("name") or suite_path.stem))
    for name in spec.get("tasks") or []:
        folder = base / name
        if not (folder / "task.json").is_file():
            print(f"[skip] missing task: {folder}")
            continue
        t0 = time.time()
        try:
            result = run_task_dir(folder, provider_kind, cfg, keep=keep)
        except Exception as exc:  # noqa: BLE001 - a broken task should not abort the suite
            print(f"[error] {name}: {type(exc).__name__}: {exc}")
            result = RunResult(task_id=name, status="error", verdict=None, steps=0,
                               seconds=time.time() - t0, tokens=0, trace_path="",
                               error=f"{type(exc).__name__}: {exc}")
        suite.results.append(result)
        print(f"[{result.status:7s}] {name:20s} {result.seconds:6.1f}s "
              f"{result.steps:3d} steps {result.tokens:6d} tok")
    out_dir = config.runs_root(cfg) / f"{time.strftime('%Y%m%d-%H%M%S')}-{suite.suite}"
    config.ensure_dirs(out_dir)
    suite.path = str(out_dir / "results.json")
    (out_dir / "results.json").write_text(json.dumps(suite.to_dict(), indent=1), encoding="utf-8")
    print(f"\n{suite.suite}: {suite.solved}/{suite.total} solved "
          f"(pass@1={suite.pass_at_1:.2f}) in {sum(r.seconds for r in suite.results):.1f}s -> {suite.path}")
    return suite
