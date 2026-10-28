"""Core data model: tasks, verdicts, budgets, traces, and oracles."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

FLAG_RE = re.compile(r"(?i)(picoctf|htb|thm|flag|ctf)\{[^}\n]{1,300}\}")


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def redact(text: str) -> str:
    """Never let a flag value reach a log line or a chat transcript."""
    if not text:
        return text
    return FLAG_RE.sub("[REDACTED-FLAG]", text)


def jsonable(obj: Any, limit: int = 20000) -> str:
    try:
        text = json.dumps(obj, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        text = str(obj)
    if len(text) > limit:
        text = text[:limit] + f"...[truncated {len(text) - limit} chars]"
    return text


@dataclass
class Task:
    id: str
    title: str = ""
    category: str = "unknown"
    difficulty: str = "unknown"
    points: int = 0
    description: str = ""
    files: list[str] = field(default_factory=list)
    connection: str | None = None
    flag_format: str | None = None
    source: str = "local"
    platform_id: str | None = None
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "difficulty": self.difficulty,
            "points": int(self.points or 0),
            "description": self.description,
            "files": list(self.files),
            "connection": self.connection,
            "flag_format": self.flag_format,
            "source": self.source,
            "platform_id": self.platform_id,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Task":
        fields = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        if "points" in fields:
            try:
                fields["points"] = int(fields["points"] or 0)
            except (TypeError, ValueError):
                fields["points"] = 0
        return cls(**fields)


@dataclass
class Verdict:
    status: str  # accepted | rejected | unknown | error
    source: str = ""
    detail: str = ""

    @property
    def accepted(self) -> bool:
        return self.status in ("accepted", "correct", "already_solved")

    def to_dict(self) -> dict:
        return {"status": self.status, "source": self.source, "detail": self.detail}


@dataclass
class Budget:
    max_steps: int = 40
    max_seconds: float = 900
    max_tokens: int = 200000
    max_submits: int = 5
    started: float = field(default_factory=time.time)
    steps: int = 0
    tokens: int = 0
    submits: int = 0

    def elapsed(self) -> float:
        return time.time() - self.started

    def expired(self) -> str | None:
        if self.steps >= self.max_steps:
            return f"max_steps={self.max_steps}"
        if self.elapsed() >= self.max_seconds:
            return f"max_seconds={self.max_seconds}"
        if self.tokens >= self.max_tokens:
            return f"max_tokens={self.max_tokens}"
        return None

    def spend(self, tokens: int = 0, steps: int = 0) -> None:
        self.tokens += max(0, int(tokens))
        self.steps += max(0, int(steps))


@dataclass
class SubmitLedger:
    """Shared across attempts so best-of-N cannot exceed the platform budget."""
    max_submits: int = 5
    submits: int = 0
    tried: set[str] = field(default_factory=set)


@dataclass
class RunResult:
    task_id: str
    status: str  # solved | blocked | partial | negative | error
    verdict: Verdict | None
    steps: int
    seconds: float
    tokens: int
    trace_path: str
    candidate_sha: str | None = None
    candidate: str | None = None  # kept in memory for the gated flag file; never serialized
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "status": self.status,
            "verdict": self.verdict.to_dict() if self.verdict else None,
            "steps": self.steps,
            "seconds": round(self.seconds, 3),
            "tokens": self.tokens,
            "trace_path": self.trace_path,
            "candidate_sha": self.candidate_sha,
            "error": self.error,
        }


class Trace:
    """Append-only JSONL event log: the source of truth for a run."""

    def __init__(self, path: str | Path, run_id: str | None = None, task_id: str = ""):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.run_id = run_id or uuid.uuid4().hex[:12]
        self.task_id = task_id
        self._lock = threading.Lock()

    def log(self, kind: str, **fields: Any) -> dict:
        record = {"ts": now_iso(), "run": self.run_id, "task": self.task_id, "type": kind}
        record.update(fields)
        line = json.dumps(record, ensure_ascii=False, default=str)
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        return record


class LocalFlagOracle:
    """Offline oracle: compare a salted SHA-256, never store the plaintext flag."""

    def __init__(self, expected_sha256: str, salt: str = ""):
        self.expected = (expected_sha256 or "").strip().lower()
        self.salt = salt or ""

    def check(self, candidate: str) -> Verdict:
        c = (candidate or "").strip()
        if not c:
            return Verdict("rejected", "local-sha256", "empty candidate")
        if not self.expected:
            return Verdict("error", "local-sha256", "no expected hash configured")
        ok = sha256_text(self.salt + c) == self.expected
        return Verdict("accepted" if ok else "rejected", "local-sha256")


class CommandOracle:
    """External validator: exit 0 means accepted.  For nonstandard answer formats."""

    def __init__(self, command: str, timeout_s: int = 30):
        self.command = command
        self.timeout_s = timeout_s

    def check(self, candidate: str) -> Verdict:
        try:
            proc = subprocess.run(
                ["/bin/bash", "-lc", self.command],
                input=(candidate or "").strip() + "\n",
                capture_output=True, text=True, timeout=self.timeout_s,
            )
        except subprocess.TimeoutExpired:
            return Verdict("error", "command", "validator timeout")
        if proc.returncode == 0:
            return Verdict("accepted", "command", (proc.stdout or "")[:200])
        return Verdict("rejected", "command", (proc.stderr or proc.stdout or "")[:200])


class AlwaysRejectOracle:
    def check(self, candidate: str) -> Verdict:
        return Verdict("rejected", "always-reject", "no oracle configured")
