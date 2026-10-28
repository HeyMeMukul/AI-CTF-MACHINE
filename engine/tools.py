"""Tool gateway: the only way the model can touch the environment.

Every tool has a schema, a hard timeout, an output cap, an artifact spill, and
(when relevant) a permission check.  The model sees compact observations; the
full output stays on disk.
"""

from __future__ import annotations

import json
import os
import re
import shlex
from dataclasses import dataclass
from pathlib import Path

from .core import Budget, SubmitLedger, Verdict, redact, sha256_text
from .envs import cap_text
from .knowledge import search_catalog

MAX_TOOL_OUTPUT = 12000


@dataclass
class ToolOutcome:
    ok: bool
    data: dict
    finished: bool = False
    status: str | None = None
    accepted: bool = False
    candidate: str | None = None
    verdict: Verdict | None = None


class Toolbox:
    def __init__(
        self,
        env,
        oracle,
        trace,
        budget: Budget,
        artifact_dir: str | Path,
        allow_submit: bool = True,
        max_output: int = MAX_TOOL_OUTPUT,
        ledger: SubmitLedger | None = None,
        catalog_root: str | Path | None = None,
    ):
        self.env = env
        self.oracle = oracle
        self.trace = trace
        self.budget = budget
        self.artifact_dir = Path(artifact_dir)
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self.allow_submit = allow_submit
        self.max_output = max_output
        self.ledger = ledger or SubmitLedger(max_submits=budget.max_submits)
        self.tried = self.ledger.tried
        self.catalog_root = Path(catalog_root) if catalog_root else None
        self.notes_path = self.artifact_dir / "notes.md"

    # ------------------------------------------------------------------ schemas
    def schemas(self) -> list[dict]:
        def fn(name: str, desc: str, props: dict, required: list[str]) -> dict:
            return {
                "type": "function",
                "function": {
                    "name": name,
                    "description": desc,
                    "parameters": {
                        "type": "object",
                        "properties": props,
                        "required": required,
                        "additionalProperties": False,
                    },
                },
            }

        tools = [
            fn("bash", "Run one non-interactive shell command inside the challenge workdir. "
                       "Use it for file inspection, scripts, exploit runs, and service interaction. "
                       "Output is capped; the full output is saved to an artifact path.",
               {"cmd": {"type": "string", "description": "Shell command to run."},
                "timeout_s": {"type": "integer", "description": "Timeout seconds (1-300)."}},
               ["cmd"]),
            fn("read_file", "Read a UTF-8 text file from the workdir (capped).",
               {"path": {"type": "string"}, "max_bytes": {"type": "integer"}}, ["path"]),
            fn("write_file", "Write a text file into the workdir (creates parents).",
               {"path": {"type": "string"}, "content": {"type": "string"}}, ["path", "content"]),
            fn("list_files", "List files in the workdir with sizes.",
               {"path": {"type": "string"}}, []),
            fn("http", "Make one HTTP request from inside the sandbox (curl). Use for web challenges.",
               {"url": {"type": "string"}, "method": {"type": "string"},
                "headers": {"type": "object"}, "data": {"type": "string"}}, ["url"]),
            fn("note", "Record a hypothesis, observation, or next step in the run notebook.",
               {"text": {"type": "string"}}, ["text"]),
            fn("catalog_search",
               "Search the imported security-skill catalog (2,000+ entries) for a technique, tool, "
               "or domain hint. Use it when the local recipes do not cover the challenge.",
               {"query": {"type": "string"},
                "domain": {"type": "string"},
                "top_k": {"type": "integer"}}, ["query"]),
        ]
        tools.append(fn(
            "submit_flag",
            "Submit a candidate flag to the challenge oracle. Call this only when you have the exact "
            "answer. A rejection is final for that value; do not resubmit it.",
            {"flag": {"type": "string"}}, ["flag"]))
        tools.append(fn(
            "finish",
            "Stop the run when you cannot make progress. status=blocked|partial|negative; include a "
            "short evidence-based summary and the next useful step.",
            {"status": {"type": "string", "enum": ["blocked", "partial", "negative"]},
             "summary": {"type": "string"}}, ["status", "summary"]))
        return tools

    # ------------------------------------------------------------------- invoke
    def call(self, name: str, args: dict | None) -> ToolOutcome:
        args = args or {}
        self.budget.spend(steps=1)
        try:
            if name == "bash":
                return self._bash(args)
            if name == "read_file":
                return self._read(args)
            if name == "write_file":
                return self._write(args)
            if name == "list_files":
                return self._list(args)
            if name == "http":
                return self._http(args)
            if name == "note":
                return self._note(args)
            if name == "catalog_search":
                return self._catalog(args)
            if name == "submit_flag":
                return self._submit(args)
            if name == "finish":
                return self._finish(args)
            return ToolOutcome(False, {"error": f"unknown tool: {name}"})
        except Exception as exc:  # noqa: BLE001 - the model must see tool errors
            return ToolOutcome(False, {"error": f"{type(exc).__name__}: {exc}"[:800]})

    # ---------------------------------------------------------------- utilities
    def _artifact(self, label: str, text: str) -> str:
        path = self.artifact_dir / f"step-{self.budget.steps:03d}-{label}.txt"
        path.write_text(text, encoding="utf-8", errors="replace")
        try:
            return os.path.relpath(path, Path(self.env.root))
        except (TypeError, ValueError):
            return str(path)

    # -------------------------------------------------------------------- tools
    def _bash(self, args: dict) -> ToolOutcome:
        cmd = str(args.get("cmd") or "").strip()
        if not cmd:
            return ToolOutcome(False, {"error": "cmd is required"})
        timeout = int(args.get("timeout_s") or getattr(self.env, "timeout_s", 120))
        timeout = max(1, min(timeout, 300))
        res = self.env.exec(cmd, timeout_s=timeout)
        full = f"$ {cmd}\n--- exit {res.exit} ---\n{res.stdout}\n{res.stderr}"
        artifact = self._artifact("bash", full)
        data = {
            "exit": res.exit,
            "stdout": cap_text(res.stdout, self.max_output),
            "stderr": cap_text(res.stderr, self.max_output),
            "timed_out": res.timed_out,
            "artifact": artifact,
        }
        if res.timed_out:
            data["hint"] = "command timed out; narrow the command or reduce the workload"
        if "flag{" in (res.stdout + res.stderr).lower() or re.search(r"(?i)(picoctf|htb|thm|ctf)\{", res.stdout + res.stderr):
            data["hint"] = "a flag-shaped string appears above; verify it is the exact challenge answer before submit_flag"
        return ToolOutcome(True, data)

    def _read(self, args: dict) -> ToolOutcome:
        path = str(args.get("path") or "").strip()
        if not path:
            return ToolOutcome(False, {"error": "path is required"})
        limit = max(1, min(int(args.get("max_bytes") or 64000), 256000))
        raw = self.env.get(path)[:limit]
        text = raw.decode("utf-8", "replace")
        return ToolOutcome(True, {"path": path, "bytes": len(raw),
                                  "content": cap_text(text, self.max_output)})

    def _write(self, args: dict) -> ToolOutcome:
        path = str(args.get("path") or "").strip()
        content = str(args.get("content") or "")
        if not path:
            return ToolOutcome(False, {"error": "path is required"})
        self.env.put_bytes(content.encode("utf-8"), path)
        return ToolOutcome(True, {"path": path, "bytes": len(content.encode("utf-8"))})

    def _list(self, args: dict) -> ToolOutcome:
        path = str(args.get("path") or ".")
        res = self.env.exec(
            f"find {shlex.quote(path)} -maxdepth 3 -type f -printf '%p\\t%s\\n' 2>/dev/null | sort | head -200"
        )
        if res.exit != 0 or not res.stdout.strip():
            res = self.env.exec(f"ls -la {shlex.quote(path)} 2>&1 | head -200")
        return ToolOutcome(True, {"path": path, "listing": cap_text(res.stdout + res.stderr, self.max_output)})

    def _http(self, args: dict) -> ToolOutcome:
        url = str(args.get("url") or "").strip()
        if not url:
            return ToolOutcome(False, {"error": "url is required"})
        method = str(args.get("method") or "GET").upper()
        if method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
            return ToolOutcome(False, {"error": f"unsupported method {method}"})
        parts = ["curl", "-sS", "-i", "-m", "20", "-X", method]
        headers = args.get("headers") or {}
        if isinstance(headers, dict):
            for key, value in headers.items():
                parts += ["-H", f"{key}: {value}"]
        data = args.get("data")
        if data is not None:
            parts += ["--data-binary", str(data)]
        parts.append(url)
        cmd = " ".join(shlex.quote(p) for p in parts)
        res = self.env.exec(cmd, timeout_s=30)
        return ToolOutcome(True, {"exit": res.exit, "response": cap_text(res.stdout, self.max_output),
                                  "stderr": cap_text(res.stderr, 2000), "method": method, "url": url})

    def _note(self, args: dict) -> ToolOutcome:
        text = str(args.get("text") or "").strip()
        if not text:
            return ToolOutcome(False, {"error": "text is required"})
        with open(self.notes_path, "a", encoding="utf-8") as f:
            f.write(f"- {text}\n")
        return ToolOutcome(True, {"noted": text[:500], "notes_path": str(self.notes_path)})

    def _catalog(self, args: dict) -> ToolOutcome:
        if self.catalog_root is None:
            return ToolOutcome(False, {"error": "catalog is not available in this run"})
        query = str(args.get("query") or "").strip()
        if not query:
            return ToolOutcome(False, {"error": "query is required"})
        domain = str(args.get("domain") or "").strip() or None
        top_k = max(1, min(int(args.get("top_k") or 5), 10))
        entries = search_catalog(
            query, self.catalog_root, top_k=top_k,
            domains=[domain] if domain else None,
        )
        results = [{
            "status": e.get("status"),
            "name": e.get("name"),
            "domains": e.get("domains"),
            "description": (e.get("description") or "")[:300],
            "url": e.get("url"),
            "imported_as": e.get("imported_as"),
        } for e in entries]
        return ToolOutcome(True, {"query": query, "results": results})

    def _submit(self, args: dict) -> ToolOutcome:
        if not self.allow_submit:
            return ToolOutcome(False, {"error": "submission is disabled for this run"})
        candidate = str(args.get("flag") or "").strip()
        if not candidate:
            return ToolOutcome(False, {"error": "flag is required"})
        if self.ledger.submits >= self.ledger.max_submits:
            return ToolOutcome(False, {"error": "submit budget exhausted; call finish with a summary"},
                               finished=True, status="blocked")
        if candidate in self.ledger.tried:
            return ToolOutcome(False, {"error": "this exact value was already submitted; do not retry it"})
        self.ledger.tried.add(candidate)
        self.ledger.submits += 1
        self.budget.submits = self.ledger.submits
        verdict = self.oracle.check(candidate)
        self.trace.log(
            "verdict",
            status=verdict.status,
            source=verdict.source,
            candidate_sha=sha256_text(candidate),
            candidate_len=len(candidate),
            detail=redact(verdict.detail or ""),
        )
        if verdict.accepted:
            return ToolOutcome(True, {"status": "accepted", "message": "flag accepted by the oracle"},
                               finished=True, status="solved", accepted=True,
                               candidate=candidate, verdict=verdict)
        if verdict.status == "rejected":
            return ToolOutcome(True, {"status": "rejected",
                                      "message": "not accepted. Do not resubmit this value; change the hypothesis."},
                               verdict=verdict)
        return ToolOutcome(True, {"status": verdict.status,
                                  "message": "oracle did not return a clear verdict; do not treat this as a rejection.",
                                  "detail": redact(verdict.detail or "")}, verdict=verdict)

    def _finish(self, args: dict) -> ToolOutcome:
        status = str(args.get("status") or "blocked").lower()
        if status not in ("blocked", "partial", "negative"):
            status = "blocked"
        summary = str(args.get("summary") or "")[:2000]
        return ToolOutcome(True, {"status": status, "summary": summary},
                           finished=True, status=status)
