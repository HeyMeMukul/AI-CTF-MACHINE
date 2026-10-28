"""Sandboxed execution environments.

``LocalEnv`` is for trusted offline fixtures only.  ``DockerEnv`` is the
default for anything downloaded from a platform: non-root, no capabilities,
bounded CPU/memory/PIDs, and an explicit network mode.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from . import config

CAP = 12000


def cap_text(text: str, limit: int = CAP) -> str:
    if text is None:
        return ""
    if len(text) <= limit:
        return text
    marker = f"\n...[truncated {len(text) - limit} chars]...\n"
    available = max(0, limit - len(marker))
    head = available * 2 // 3
    tail = available - head
    return text[:head] + marker + (text[-tail:] if tail else "")


@dataclass
class ExecResult:
    exit: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False

    def to_dict(self, limit: int = CAP) -> dict:
        return {
            "exit": self.exit,
            "stdout": cap_text(self.stdout, limit),
            "stderr": cap_text(self.stderr, limit),
            "duration_ms": self.duration_ms,
            "timed_out": self.timed_out,
        }


def _safe_rel(root: Path, rel: str) -> Path:
    p = Path(rel)
    if p.is_absolute() or ".." in p.parts:
        raise ValueError(f"path escapes the workdir: {rel!r}")
    return root / p


class LocalEnv:
    """Run commands on the host in an isolated working directory.

    This is *not* a security boundary.  Use it only for trusted eval fixtures
    or when the operator explicitly accepts host execution.
    """

    kind = "local"

    def __init__(self, root: str | Path, timeout_s: int = 120):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.timeout_s = timeout_s

    def start(self) -> "LocalEnv":
        return self

    def _env(self) -> dict:
        env = {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": str(self.root),
            "PWD": str(self.root),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "TERM": "dumb",
        }
        return env

    def exec(self, cmd: str, timeout_s: int | None = None, stdin: str | None = None) -> ExecResult:
        t0 = time.time()
        timeout = timeout_s or self.timeout_s
        try:
            proc = subprocess.run(
                ["/bin/bash", "-lc", cmd],
                cwd=self.root, input=stdin, capture_output=True, text=True,
                timeout=timeout, env=self._env(),
            )
            return ExecResult(proc.returncode, proc.stdout or "", proc.stderr or "",
                              int((time.time() - t0) * 1000))
        except subprocess.TimeoutExpired as exc:
            out = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            err = exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            return ExecResult(124, out, err + f"\n[timeout after {timeout}s]",
                              int((time.time() - t0) * 1000), timed_out=True)
        except FileNotFoundError as exc:
            return ExecResult(127, "", str(exc), int((time.time() - t0) * 1000))

    def put(self, local_path: str | Path, remote_path: str) -> None:
        dest = _safe_rel(self.root, remote_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(local_path, dest)

    def put_bytes(self, data: bytes, remote_path: str) -> None:
        dest = _safe_rel(self.root, remote_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)

    def get(self, remote_path: str) -> bytes:
        return _safe_rel(self.root, remote_path).read_bytes()

    def reset(self) -> None:
        for child in self.root.iterdir():
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child, ignore_errors=True)
            else:
                child.unlink(missing_ok=True)

    def close(self) -> None:
        return None

    def __enter__(self) -> "LocalEnv":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.close()


class DockerEnv:
    """A long-lived Docker container with an explicit security posture."""

    kind = "docker"

    def __init__(
        self,
        image: str,
        root: str | Path,
        network: str = "none",
        cpus: float = 2,
        memory: str = "2g",
        pids_limit: int = 256,
        timeout_s: int = 120,
        read_only: bool = False,
    ):
        self.image = image
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.network = network
        self.cpus = cpus
        self.memory = memory
        self.pids_limit = pids_limit
        self.timeout_s = timeout_s
        self.read_only = read_only
        self.name = f"ctf-{uuid.uuid4().hex[:10]}"
        self._started = False

    def _run(self, args: list[str], timeout: int | None = None, input_text: str | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(args, capture_output=True, text=True,
                              timeout=timeout, input=input_text)

    def start(self) -> "DockerEnv":
        check = self._run(["docker", "image", "inspect", self.image], timeout=30)
        if check.returncode != 0:
            raise RuntimeError(
                f"docker image {self.image!r} not found. Build it first, e.g. "
                f"`docker build -f Dockerfile.kali-ctf -t {self.image} .`"
            )
        args = [
            "docker", "run", "-d", "--rm", "--name", self.name,
            "--network", self.network,
            "--cpus", str(self.cpus),
            "--memory", self.memory,
            "--pids-limit", str(self.pids_limit),
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--tmpfs", "/tmp:rw,size=256m",
            "-v", f"{self.root}:/work",
            "-w", "/work",
        ]
        if self.read_only:
            args += ["--read-only"]
        args += [self.image, "sleep", "infinity"]
        proc = self._run(args, timeout=60)
        if proc.returncode != 0:
            raise RuntimeError(f"docker run failed: {(proc.stderr or proc.stdout)[:500]}")
        for _ in range(50):
            state = self._run(["docker", "inspect", "-f", "{{.State.Running}}", self.name], timeout=10)
            if state.stdout.strip() == "true":
                self._started = True
                return self
            time.sleep(0.1)
        raise RuntimeError(f"container {self.name} did not start")

    def exec(self, cmd: str, timeout_s: int | None = None, stdin: str | None = None) -> ExecResult:
        if not self._started:
            self.start()
        t0 = time.time()
        timeout = timeout_s or self.timeout_s
        try:
            proc = self._run(["docker", "exec", "-i", self.name, "bash", "-lc", cmd],
                             timeout=timeout, input_text=stdin)
            return ExecResult(proc.returncode, proc.stdout or "", proc.stderr or "",
                              int((time.time() - t0) * 1000))
        except subprocess.TimeoutExpired as exc:
            out = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            err = exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            return ExecResult(124, out, err + f"\n[timeout after {timeout}s]",
                              int((time.time() - t0) * 1000), timed_out=True)

    def put(self, local_path: str | Path, remote_path: str) -> None:
        remote = _safe_rel(self.root, remote_path)
        remote.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(local_path, remote)

    def put_bytes(self, data: bytes, remote_path: str) -> None:
        remote = _safe_rel(self.root, remote_path)
        remote.parent.mkdir(parents=True, exist_ok=True)
        remote.write_bytes(data)

    def get(self, remote_path: str) -> bytes:
        return _safe_rel(self.root, remote_path).read_bytes()

    def reset(self) -> None:
        for child in self.root.iterdir():
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child, ignore_errors=True)
            else:
                child.unlink(missing_ok=True)

    def close(self) -> None:
        if self._started or self.name:
            self._run(["docker", "rm", "-f", self.name], timeout=30)
            self._started = False

    def __enter__(self) -> "DockerEnv":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.close()


def build_env(cfg: dict, root: str | Path, live: bool = False):
    kind = str(config.get(cfg, "sandbox.kind", "local")).lower()
    timeout_s = int(config.get(cfg, "sandbox.timeout_s", 120))
    if kind == "local":
        return LocalEnv(root, timeout_s=timeout_s)
    if kind == "docker":
        network = config.get(cfg, "sandbox.live_network", "bridge") if live else config.get(cfg, "sandbox.network", "none")
        return DockerEnv(
            image=str(config.get(cfg, "sandbox.image", "ctf-kali:latest")),
            root=root,
            network=str(network or "none"),
            cpus=float(config.get(cfg, "sandbox.cpus", 2)),
            memory=str(config.get(cfg, "sandbox.memory", "2g")),
            pids_limit=int(config.get(cfg, "sandbox.pids_limit", 256)),
            timeout_s=timeout_s,
            read_only=bool(config.get(cfg, "sandbox.read_only", False)),
        )
    raise ValueError(f"unknown sandbox kind: {kind!r}")
