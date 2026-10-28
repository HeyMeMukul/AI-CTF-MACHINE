"""The solver loop: one tool call at a time, grounded observations, oracle gate."""

from __future__ import annotations

import json
import re
import time
from pathlib import Path

from . import config, knowledge, prompts
from .core import Budget, RunResult, SubmitLedger, Task, Trace, redact, sha256_text
from .envs import cap_text
from .providers import parse_text_tool_call
from .tools import Toolbox


class Solver:
    def __init__(self, provider, cfg: dict):
        self.provider = provider
        self.cfg = cfg

    def run(self, task: Task, env, oracle, run_dir: str | Path, trace: Trace | None = None,
            attempt: int = 1, attempts: int = 1, prior: list[str] | None = None,
            ledger: SubmitLedger | None = None) -> RunResult:
        run_dir = Path(run_dir)
        run_dir.mkdir(parents=True, exist_ok=True)
        trace = trace or Trace(run_dir / "trace.jsonl", task_id=task.id)
        budget = Budget(
            max_steps=int(config.get(self.cfg, "solver.max_steps", 40)),
            max_seconds=float(config.get(self.cfg, "solver.max_seconds", 900)),
            max_tokens=int(config.get(self.cfg, "solver.max_tokens", 200000)),
            max_submits=int(config.get(self.cfg, "solver.max_submits", 5)),
        )
        ledger = ledger or SubmitLedger(max_submits=budget.max_submits)
        toolbox = Toolbox(
            env=env,
            oracle=oracle,
            trace=trace,
            budget=budget,
            artifact_dir=Path(env.root) / ".engine" / "artifacts",
            ledger=ledger,
            catalog_root=config.ROOT,
        )
        query = " ".join([task.title or "", task.category or "", task.description[:800] or ""])
        recipes = knowledge.retrieve(
            query,
            config.recipes_root(self.cfg),
            domain=task.category if task.category not in ("", "unknown") else None,
            top_k=int(config.get(self.cfg, "knowledge.top_k", 2)),
            include_unverified=bool(config.get(self.cfg, "knowledge.include_unverified", False)),
            include_source_verified=bool(config.get(self.cfg, "knowledge.include_source_verified", True)),
        )
        messages = [
            {"role": "system", "content": prompts.build_system_prompt(self.cfg, task, recipes)},
            {"role": "user", "content": prompts.build_user_prompt(task, attempt, attempts, prior)},
        ]
        trace.log("run_start", task=task.to_dict(), recipes=[r.get("id") for r in recipes],
                  provider=type(self.provider).__name__, attempt=attempt, attempts=attempts)
        status = "blocked"
        verdict = None
        candidate: str | None = None
        error: str | None = None
        no_tool = 0
        last_signature: tuple | None = None
        repeats = 0

        while True:
            reason = budget.expired()
            if reason:
                trace.log("budget_exhausted", reason=reason)
                break

            result = self._chat_with_retry(messages, toolbox.schemas(), trace)
            if result is None:
                status = "error"
                error = "provider failed"
                break
            budget.spend(result.total_tokens)
            trace.log(
                "llm",
                content=cap_text(redact(result.content or ""), 1500),
                tool_calls=[c.name for c in result.tool_calls],
                prompt_tokens=result.prompt_tokens,
                completion_tokens=result.completion_tokens,
                elapsed=round(budget.elapsed(), 3),
            )

            calls = list(result.tool_calls)
            if not calls and result.content:
                parsed = parse_text_tool_call(result.content)
                if parsed:
                    calls = [parsed]

            if not calls:
                no_tool += 1
                messages.append({"role": "assistant", "content": result.content or "(no content)"})
                messages.append({
                    "role": "user",
                    "content": "You must call exactly one tool. If you are blocked, call finish with status "
                               "and a precise summary. Do not answer in prose.",
                })
                if no_tool >= 3:
                    trace.log("no_tool_guard")
                    break
                continue
            no_tool = 0

            messages.append({
                "role": "assistant",
                "content": result.content or "",
                "tool_calls": [call.to_openai() for call in calls],
            })
            finished = False
            for call in calls:
                outcome = toolbox.call(call.name, call.arguments)
                trace.log(
                    "tool",
                    name=call.name,
                    args=self._redact_args(call.name, call.arguments),
                    ok=outcome.ok,
                    finished=outcome.finished,
                    data=cap_text(redact(json.dumps(outcome.data, default=str)), 4000),
                )
                messages.append({
                    "role": "tool",
                    "tool_call_id": call.id,
                    "name": call.name,
                    "content": json.dumps(outcome.data, ensure_ascii=False, default=str)[:16000],
                })
                if outcome.finished:
                    status = outcome.status or ("solved" if outcome.accepted else "blocked")
                    verdict = outcome.verdict
                    candidate = outcome.candidate
                    finished = True
                    break
            if finished:
                break

            first = calls[0]
            signature = (first.name, json.dumps(first.arguments, sort_keys=True, default=str))
            if signature == last_signature:
                repeats += 1
            else:
                repeats = 0
            last_signature = signature
            if repeats == 2:
                messages.append({
                    "role": "user",
                    "content": "You repeated the same tool call. Change the command, the hypothesis, or call finish.",
                })
            if repeats >= 4:
                trace.log("loop_guard", repeats=repeats)
                break

            self._compact(messages)

        seconds = budget.elapsed()
        result = RunResult(
            task_id=task.id,
            status=status,
            verdict=verdict,
            steps=budget.steps,
            seconds=seconds,
            tokens=budget.tokens,
            trace_path=str(trace.path),
            candidate_sha=sha256_text(candidate) if candidate else None,
            candidate=candidate,
            error=error,
        )
        trace.log("run_end", result=result.to_dict())
        return result

    # ------------------------------------------------------------------ helpers
    def _chat_with_retry(self, messages, tools, trace: Trace):
        attempts = int(config.get(self.cfg, "solver.max_llm_retries", 2)) + 1
        last: Exception | None = None
        for i in range(attempts):
            try:
                return self.provider.chat(messages, tools=tools,
                                          temperature=float(config.get(self.cfg, "provider.temperature", 0.2)))
            except Exception as exc:  # noqa: BLE001 - provider failures are typed
                last = exc
                trace.log("provider_error", attempt=i + 1, error=f"{type(exc).__name__}: {exc}"[:800])
                if i + 1 < attempts:
                    time.sleep(min(8, 2 ** i))
        trace.log("provider_exhausted", error=str(last)[:800] if last else "unknown")
        return None

    def _compact(self, messages: list[dict]) -> None:
        limit = int(config.get(self.cfg, "solver.compact_after_messages", 80))
        if len(messages) <= limit:
            return
        head = messages[:2]
        tail = messages[-30:]
        while tail and tail[0].get("role") == "tool":
            tail = tail[1:]
        messages.clear()
        messages.extend(head)
        messages.append({"role": "system", "content": "[older observations omitted to stay within the context window]"})
        messages.extend(tail)

    @staticmethod
    def _redact_args(name: str, args: dict) -> dict:
        if name == "submit_flag":
            value = str((args or {}).get("flag", ""))
            return {"flag": "[REDACTED]", "len": len(value)}
        text = json.dumps(args or {}, default=str)
        return {"args": redact(text)[:3000]}


def looks_like_flag(text: str) -> bool:
    return bool(re.search(r"(?i)(picoctf|htb|thm|flag|ctf)\{[^}\n]{1,300}\}", text or ""))
