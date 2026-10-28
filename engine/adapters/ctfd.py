"""CTFd platform adapter and oracle.

Uses the public CTFd API:
  GET  /api/v1/challenges
  GET  /api/v1/challenges/<id>
  POST /api/v1/challenges/attempt   {"challenge_id": N, "submission": "..."}

Auth is a CTFd API token in the ``Authorization: Token <token>`` header.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from ..core import Task, Verdict


class PlatformError(RuntimeError):
    pass


def _api_base(base_url: str) -> str:
    base = (base_url or "").rstrip("/")
    if base.endswith("/api/v1"):
        return base
    return base + "/api/v1"


def parse_challenge_list(payload: dict) -> list[dict]:
    data = payload.get("data", payload) if isinstance(payload, dict) else payload
    if isinstance(data, dict):
        data = data.get("challenges") or data.get("data") or []
    if not isinstance(data, list):
        return []
    return [item for item in data if isinstance(item, dict) and item.get("id") is not None]


def parse_attempt(payload: dict) -> Verdict:
    data = payload.get("data", payload) if isinstance(payload, dict) else {}
    status = str((data or {}).get("status") or "").lower()
    message = str((data or {}).get("message") or "")
    if status in ("correct", "already_solved", "accepted"):
        return Verdict("accepted", "ctfd", message)
    if status in ("incorrect", "rejected", "wrong"):
        return Verdict("rejected", "ctfd", message)
    return Verdict("unknown", "ctfd", message or f"unrecognized status: {status!r}")


class CTFdAdapter:
    def __init__(self, base_url: str, token: str, pace_seconds: float = 2.0, timeout_s: int = 30):
        if not base_url:
            raise PlatformError("CTFd URL is empty")
        self.base_url = base_url.rstrip("/")
        self.api = _api_base(self.base_url)
        self.token = token or ""
        self.pace_seconds = max(0.0, float(pace_seconds))
        self.timeout_s = int(timeout_s)
        self._last_submit = 0.0

    # ------------------------------------------------------------------ HTTP
    def _headers(self) -> dict:
        headers = {"Accept": "application/json", "User-Agent": "ctf-engine/2.0"}
        if self.token:
            headers["Authorization"] = f"Token {self.token}"
        return headers

    def _request(self, method: str, path: str, payload: dict | None = None, raw: bool = False):
        url = self.api + path if path.startswith("/") else f"{self.api}/{path}"
        data = None
        headers = self._headers()
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                body = resp.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:600]
            raise PlatformError(f"{method} {url} -> HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise PlatformError(f"{method} {url} -> {exc}") from exc
        if raw:
            return body
        if not body:
            return {}
        try:
            return json.loads(body.decode("utf-8", "replace"))
        except ValueError as exc:
            raise PlatformError(f"{method} {url} returned non-JSON") from exc

    # --------------------------------------------------------------- endpoints
    def list_challenges(self) -> list[dict]:
        payload = self._request("GET", "/challenges")
        return parse_challenge_list(payload)

    def get_challenge(self, challenge_id: str | int) -> dict:
        payload = self._request("GET", f"/challenges/{challenge_id}")
        data = payload.get("data", payload)
        return data if isinstance(data, dict) else {}

    def download_files(self, detail: dict, dest: str | Path) -> list[str]:
        dest = Path(dest)
        dest.mkdir(parents=True, exist_ok=True)
        saved: list[str] = []
        for index, entry in enumerate(detail.get("files") or []):
            url = entry if isinstance(entry, str) else str(entry.get("url") or "")
            if not url:
                continue
            full = urllib.parse.urljoin(self.base_url + "/", url)
            name = Path(urllib.parse.urlparse(full).path).name
            name = re.sub(r"[^A-Za-z0-9_.-]+", "_", name) or f"file-{index}"
            target = dest / name
            if target.exists():
                saved.append(name)
                continue
            try:
                req = urllib.request.Request(full, headers=self._headers())
                with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                    content = resp.read()
                target.write_bytes(content)
                saved.append(name)
            except (urllib.error.URLError, OSError):
                continue
        return saved

    def submit(self, challenge_id: str | int, flag: str) -> Verdict:
        wait = self.pace_seconds - (time.time() - self._last_submit)
        if wait > 0:
            time.sleep(wait)
        self._last_submit = time.time()
        try:
            payload = self._request("POST", "/challenges/attempt",
                                    {"challenge_id": int(challenge_id), "submission": flag})
        except PlatformError as exc:
            return Verdict("error", "ctfd", str(exc)[:300])
        return parse_attempt(payload)

    # ------------------------------------------------------------------ sync
    def sync(self, store, event_dir: str | Path, download: bool = True) -> int:
        event_dir = Path(event_dir)
        added = 0
        for item in self.list_challenges():
            cid = str(item.get("id"))
            task_id = f"ctfd-{cid}"
            if store.has(task_id) or item.get("solved_by_me"):
                continue
            try:
                detail = self.get_challenge(cid)
            except PlatformError:
                detail = {}
            merged = dict(item)
            merged.update(detail or {})
            work = event_dir / "challenges" / task_id
            given = work / "given"
            files: list[str] = []
            if download:
                files = self.download_files(merged, given)
                files = [f"given/{name}" for name in files]
            task = Task(
                id=task_id,
                title=str(merged.get("name") or merged.get("title") or task_id),
                category=str(merged.get("category") or "unknown"),
                difficulty="unknown",
                points=int(merged.get("value") or merged.get("points") or 0),
                description=str(merged.get("description") or ""),
                files=files,
                connection=str(merged.get("connection_info") or "") or None,
                flag_format=None,
                source="ctfd",
                platform_id=cid,
                metadata={"solved_by_me": bool(merged.get("solved_by_me")),
                          "solves": merged.get("solves")},
            )
            if store.enqueue(task):
                added += 1
        return added

    def oracle_for(self, task: Task):
        return CTFdOracle(self, task.platform_id or task.id)


class CTFdOracle:
    def __init__(self, adapter: CTFdAdapter, challenge_id: str | int):
        self.adapter = adapter
        self.challenge_id = challenge_id

    def check(self, candidate: str) -> Verdict:
        return self.adapter.submit(self.challenge_id, candidate)
