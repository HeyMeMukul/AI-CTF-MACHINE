"""Local adapter for the offline eval suite and the daemon demo.

A task directory looks like::

    eval/tasks/base64/
      task.json          # id, category, difficulty, points, description, salt, flag_sha256
      files/             # copied into <event>/challenges/<id>/given/
      expected_flag.txt  # only used by the mock provider / local oracle
      mock.json          # scripted tool calls; {{FLAG}} is substituted
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from ..core import LocalFlagOracle, Task, sha256_text


class LocalAdapter:
    def __init__(self, tasks_dir: str | Path):
        self.tasks_dir = Path(tasks_dir)

    def _task_dirs(self) -> list[Path]:
        if not self.tasks_dir.is_dir():
            return []
        return sorted(p for p in self.tasks_dir.iterdir() if (p / "task.json").is_file())

    def sync(self, store, event_dir: str | Path, download: bool = True) -> int:
        event_dir = Path(event_dir)
        added = 0
        for folder in self._task_dirs():
            spec = json.loads((folder / "task.json").read_text(encoding="utf-8"))
            task_id = str(spec.get("id") or folder.name)
            if store.has(task_id):
                continue
            work = event_dir / "challenges" / task_id
            given = work / "given"
            given.mkdir(parents=True, exist_ok=True)
            files_dir = folder / "files"
            if files_dir.is_dir():
                shutil.copytree(files_dir, given, dirs_exist_ok=True)
            expected_path = folder / "expected_flag.txt"
            expected = expected_path.read_text(encoding="utf-8").strip() if expected_path.is_file() else ""
            salt = str(spec.get("salt") or "")
            flag_hash = str(spec.get("flag_sha256") or "")
            if not flag_hash and expected:
                flag_hash = sha256_text(salt + expected)
            mock_path = ""
            mock_src = folder / "mock.json"
            if mock_src.is_file():
                text = mock_src.read_text(encoding="utf-8").replace("{{FLAG}}", expected)
                resolved = work / "mock_resolved.json"
                resolved.write_text(text, encoding="utf-8")
                mock_path = str(resolved)
            task = Task(
                id=task_id,
                title=str(spec.get("title") or task_id),
                category=str(spec.get("category") or "unknown"),
                difficulty=str(spec.get("difficulty") or "unknown"),
                points=int(spec.get("points") or 0),
                description=str(spec.get("description") or ""),
                files=[f"given/{p.name}" for p in given.iterdir() if p.is_file()],
                connection=spec.get("connection"),
                flag_format=spec.get("flag_format"),
                source="local",
                platform_id=task_id,
                metadata={
                    "flag_sha256": flag_hash,
                    "salt": salt,
                    "mock_script": mock_path,
                    "expected_sha256_only": True,
                },
            )
            if store.enqueue(task):
                added += 1
        return added

    def oracle_for(self, task: Task):
        return LocalFlagOracle(str(task.metadata.get("flag_sha256") or ""),
                               str(task.metadata.get("salt") or ""))

    def submit(self, challenge_id: str, flag: str):
        for folder in self._task_dirs():
            spec = json.loads((folder / "task.json").read_text(encoding="utf-8"))
            if str(spec.get("id") or folder.name) == challenge_id:
                expected_path = folder / "expected_flag.txt"
                if expected_path.is_file():
                    expected = expected_path.read_text(encoding="utf-8").strip()
                    from ..core import Verdict
                    return Verdict("accepted" if flag.strip() == expected else "rejected", "local")
        from ..core import Verdict
        return Verdict("error", "local", "unknown local task")
