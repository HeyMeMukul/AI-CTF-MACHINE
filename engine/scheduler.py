"""Durable task queue with expected-value scheduling.

SQLite is enough for a single-box CTF rig: WAL mode, one writer lock, and
idempotent task states.  The scheduler is deliberately separate from the
solver so a crashed worker never loses a task.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

from .core import Task, now_iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    platform TEXT,
    platform_id TEXT,
    title TEXT,
    category TEXT,
    difficulty TEXT,
    points INTEGER NOT NULL DEFAULT 0,
    state TEXT NOT NULL DEFAULT 'queued',
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    lease_until REAL,
    payload TEXT NOT NULL,
    last_error TEXT
);
CREATE INDEX IF NOT EXISTS idx_tasks_state ON tasks(state, created_at);
CREATE TABLE IF NOT EXISTS outcomes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT,
    category TEXT,
    difficulty TEXT,
    solved INTEGER NOT NULL,
    seconds REAL,
    tokens INTEGER,
    at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_outcomes_cat ON outcomes(category, difficulty);
"""


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False, timeout=30)
        self.conn.row_factory = sqlite3.Row
        with self.conn:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.executescript(SCHEMA)

    # ------------------------------------------------------------------ writes
    def enqueue(self, task: Task) -> bool:
        payload = json.dumps(task.to_dict(), ensure_ascii=False)
        with self._lock, self.conn:
            cur = self.conn.execute(
                "INSERT OR IGNORE INTO tasks(id, platform, platform_id, title, category, difficulty, "
                "points, state, attempts, created_at, updated_at, payload) "
                "VALUES (?,?,?,?,?,?,?, 'queued', 0, ?, ?, ?)",
                (task.id, task.source, task.platform_id, task.title, task.category,
                 task.difficulty, int(task.points or 0), time.time(), time.time(), payload),
            )
            return cur.rowcount > 0

    def lease(self, lease_seconds: int = 1800, max_attempts: int = 3) -> Task | None:
        now = time.time()
        with self._lock, self.conn:
            rows = self.conn.execute(
                "SELECT * FROM tasks WHERE state='queued' AND attempts < ?", (max_attempts,)
            ).fetchall()
            if not rows:
                return None
            ranked = sorted(rows, key=lambda row: -self._ev(row, now))
            best = ranked[0]
            cur = self.conn.execute(
                "UPDATE tasks SET state='running', lease_until=?, attempts=attempts+1, updated_at=? "
                "WHERE id=? AND state='queued'",
                (now + lease_seconds, now, best["id"]),
            )
            if cur.rowcount != 1:
                return None
            return Task.from_dict(json.loads(best["payload"]))

    def complete(self, task_id: str, state: str, seconds: float = 0.0, tokens: int = 0,
                 error: str | None = None) -> None:
        if state not in ("solved", "blocked", "partial", "negative", "error", "parked"):
            raise ValueError(f"bad terminal state: {state}")
        now = time.time()
        with self._lock, self.conn:
            row = self.conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
            if row is None:
                return
            self.conn.execute(
                "UPDATE tasks SET state=?, lease_until=NULL, updated_at=?, last_error=? WHERE id=?",
                (state, now, (error or "")[:1000], task_id),
            )
            self.conn.execute(
                "INSERT INTO outcomes(task_id, category, difficulty, solved, seconds, tokens, at) "
                "VALUES (?,?,?,?,?,?,?)",
                (task_id, row["category"], row["difficulty"], 1 if state == "solved" else 0,
                 seconds, tokens, now),
            )

    def requeue_expired(self, max_attempts: int = 3) -> int:
        now = time.time()
        count = 0
        with self._lock, self.conn:
            rows = self.conn.execute(
                "SELECT * FROM tasks WHERE state='running' AND lease_until IS NOT NULL AND lease_until < ?",
                (now,),
            ).fetchall()
            for row in rows:
                if row["attempts"] >= max_attempts:
                    self.conn.execute(
                        "UPDATE tasks SET state='blocked', lease_until=NULL, updated_at=?, "
                        "last_error='lease expired; max attempts reached' WHERE id=?",
                        (now, row["id"]),
                    )
                    self.conn.execute(
                        "INSERT INTO outcomes(task_id, category, difficulty, solved, seconds, tokens, at) "
                        "VALUES (?,?,?,0,0,0,?)",
                        (row["id"], row["category"], row["difficulty"], now),
                    )
                else:
                    self.conn.execute(
                        "UPDATE tasks SET state='queued', lease_until=NULL, updated_at=?, "
                        "last_error='lease expired; requeued' WHERE id=?",
                        (now, row["id"]),
                    )
                count += 1
        return count

    # ------------------------------------------------------------------- reads
    def has(self, task_id: str) -> bool:
        with self._lock:
            row = self.conn.execute("SELECT 1 FROM tasks WHERE id=?", (task_id,)).fetchone()
            return row is not None

    def get(self, task_id: str) -> dict | None:
        with self._lock:
            row = self.conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
            return dict(row) if row else None

    def list(self, state: str | None = None) -> list[dict]:
        with self._lock:
            if state:
                rows = self.conn.execute("SELECT * FROM tasks WHERE state=? ORDER BY updated_at DESC",
                                         (state,)).fetchall()
            else:
                rows = self.conn.execute("SELECT * FROM tasks ORDER BY updated_at DESC").fetchall()
            return [dict(r) for r in rows]

    def stats(self) -> dict:
        with self._lock:
            counts = {row["state"]: row["n"] for row in self.conn.execute(
                "SELECT state, COUNT(*) n FROM tasks GROUP BY state"
            ).fetchall()}
            totals = self.conn.execute(
                "SELECT COUNT(*) n, COALESCE(SUM(solved),0) s, COALESCE(SUM(seconds),0) sec "
                "FROM outcomes"
            ).fetchone()
            return {
                "states": counts,
                "outcomes": totals["n"],
                "solved": totals["s"],
                "seconds": round(totals["sec"], 1),
            }

    # -------------------------------------------------------------- EV / priors
    def p_solve(self, category: str, difficulty: str) -> float:
        prior = {"easy": 0.55, "medium": 0.35, "hard": 0.15, "insane": 0.05}.get(
            (difficulty or "").lower(), 0.30)
        with self._lock:
            row = self.conn.execute(
                "SELECT COUNT(*) n, COALESCE(SUM(solved),0) s FROM outcomes "
                "WHERE category=? AND difficulty=?", (category, difficulty)
            ).fetchone()
        n, s = int(row["n"]), int(row["s"])
        return (s + prior * 4.0) / (n + 4.0)

    def _ev(self, row: sqlite3.Row, now: float) -> float:
        task = Task.from_dict(json.loads(row["payload"]))
        p = self.p_solve(row["category"], row["difficulty"])
        points = max(int(row["points"] or 0), 1)
        age_h = max(0.0, (now - float(row["created_at"])) / 3600.0)
        decay = max(0.35, 1.0 - age_h / 24.0)
        attempts = int(row["attempts"] or 0)
        cost = 1.0 + 0.5 * attempts
        return (p * points * decay) / cost

    def close(self) -> None:
        with self._lock:
            self.conn.close()
