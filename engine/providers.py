"""LLM providers: OpenAI-compatible chat completions plus a scripted mock.

Only the Python standard library is used, so the engine runs on a fresh box.
The OpenAI-compatible path covers OpenAI, OmniRoute, OpenRouter, vLLM, LM Studio,
and most local gateways.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from . import config


class ProviderError(RuntimeError):
    pass


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict

    def to_openai(self) -> dict:
        return {
            "id": self.id,
            "type": "function",
            "function": {"name": self.name, "arguments": json.dumps(self.arguments, ensure_ascii=False)},
        }


@dataclass
class ChatResult:
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    prompt_tokens: int = 0
    completion_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


def parse_text_tool_call(text: str) -> ToolCall | None:
    """Accept a JSON tool call embedded in plain text (fallback providers)."""
    if not text:
        return None
    candidates = []
    fenced = re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    candidates.extend(fenced)
    start, end = text.find("{"), text.rfind("}")
    if start >= 0 and end > start:
        candidates.append(text[start:end + 1])
    for raw in candidates:
        try:
            data = json.loads(raw)
        except (TypeError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        name = data.get("tool") or data.get("name")
        args = data.get("arguments") or data.get("args") or data.get("input") or {}
        if name and isinstance(args, dict):
            return ToolCall(id=f"text-{int(time.time() * 1000)}", name=str(name), arguments=args)
    return None


class OpenAIProvider:
    def __init__(self, base_url: str, api_key: str, model: str, temperature: float = 0.2,
                 max_tokens: int = 4096, timeout_s: int = 180, extra_body: dict | None = None,
                 max_retries: int = 2):
        if not base_url:
            raise ProviderError("provider.base_url is empty")
        if not model:
            raise ProviderError("provider.model is empty")
        if not api_key:
            raise ProviderError("provider API key is empty")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.temperature = float(temperature)
        self.max_tokens = int(max_tokens)
        self.timeout_s = int(timeout_s)
        self.extra_body = dict(extra_body or {})
        self.max_retries = max(0, int(max_retries))

    @property
    def url(self) -> str:
        return f"{self.base_url}/chat/completions"

    def chat(self, messages: list[dict], tools: list[dict] | None = None, **kwargs: Any) -> ChatResult:
        body: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": kwargs.get("temperature", self.temperature),
            "max_tokens": kwargs.get("max_tokens", self.max_tokens),
        }
        if tools:
            body["tools"] = tools
            body["tool_choice"] = kwargs.get("tool_choice", "auto")
        body.update(self.extra_body)
        raw = json.dumps(body).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {self.api_key}",
            "User-Agent": "ctf-engine/2.0",
        }
        last_error: Exception | None = None
        for attempt in range(self.max_retries + 1):
            req = urllib.request.Request(self.url, data=raw, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                    payload = json.loads(resp.read().decode("utf-8", "replace"))
                return self._parse(payload)
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode("utf-8", "replace")[:800]
                last_error = ProviderError(f"HTTP {exc.code}: {detail}")
                if exc.code in (408, 409, 429, 500, 502, 503, 504) and attempt < self.max_retries:
                    time.sleep(min(8, 2 ** attempt))
                    continue
                raise last_error
            except (urllib.error.URLError, TimeoutError, ValueError) as exc:
                last_error = ProviderError(f"{type(exc).__name__}: {exc}")
                if attempt < self.max_retries:
                    time.sleep(min(8, 2 ** attempt))
                    continue
                raise last_error
        raise last_error or ProviderError("provider failed")

    def _parse(self, payload: dict) -> ChatResult:
        choices = payload.get("choices") or []
        if not choices:
            raise ProviderError(f"provider returned no choices: {json.dumps(payload)[:400]}")
        message = choices[0].get("message") or {}
        content = message.get("content") or ""
        calls: list[ToolCall] = []
        for i, item in enumerate(message.get("tool_calls") or []):
            fn = item.get("function") or {}
            args = fn.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args) if args.strip() else {}
                except json.JSONDecodeError:
                    args = {"_raw_arguments": args}
            if not isinstance(args, dict):
                args = {"_raw_arguments": args}
            calls.append(ToolCall(id=str(item.get("id") or f"call-{i}"),
                                  name=str(fn.get("name") or ""), arguments=args))
        usage = payload.get("usage") or {}
        return ChatResult(
            content=str(content or ""),
            tool_calls=calls,
            prompt_tokens=int(usage.get("prompt_tokens") or 0),
            completion_tokens=int(usage.get("completion_tokens") or 0),
        )

    def ping(self) -> str:
        result = self.chat([{"role": "user", "content": "Reply with the single word: OK"}],
                           tools=None, max_tokens=8)
        return (result.content or "").strip()[:80]


class MockProvider:
    """Deterministic provider for tests and the offline demo."""

    def __init__(self, script: list[dict] | dict):
        if isinstance(script, dict):
            script = script.get("script") or script.get("responses") or []
        self.script = list(script)
        self.index = 0

    def chat(self, messages: list[dict], tools: list[dict] | None = None, **kwargs: Any) -> ChatResult:
        if self.index >= len(self.script):
            return ChatResult(content="[[MOCK SCRIPT EXHAUSTED]]", tool_calls=[])
        item = self.script[self.index]
        self.index += 1
        if isinstance(item, list):
            item = {"tool_calls": item}
        calls: list[ToolCall] = []
        for i, raw in enumerate(item.get("tool_calls") or []):
            if not isinstance(raw, dict):
                continue
            name = raw.get("name") or raw.get("tool") or ""
            args = raw.get("arguments", raw.get("args", {}))
            if not isinstance(args, dict):
                args = {"_raw_arguments": args}
            calls.append(ToolCall(id=str(raw.get("id") or f"mock-{self.index}-{i}"),
                                  name=str(name), arguments=args))
        usage = item.get("usage") or {}
        return ChatResult(content=str(item.get("content") or ""), tool_calls=calls,
                          prompt_tokens=int(usage.get("prompt_tokens") or 120),
                          completion_tokens=int(usage.get("completion_tokens") or 40))


def load_script(path: str | os.PathLike) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict):
        data = data.get("script") or data.get("responses") or []
    if not isinstance(data, list):
        raise ProviderError(f"mock script must be a list: {path}")
    return data


def build_provider(cfg: dict, mock_script: str | list[dict] | None = None):
    kind = str(config.get(cfg, "provider.kind", "mock")).lower()
    if kind == "mock":
        if mock_script is None:
            raise ProviderError("mock provider requires --mock-script or a task mock_script")
        if isinstance(mock_script, (str, os.PathLike)):
            return MockProvider(load_script(mock_script))
        return MockProvider(mock_script)
    if kind in ("openai", "openai-compatible", "omniroute", "openrouter"):
        key_env = str(config.get(cfg, "provider.api_key_env", "LLM_API_KEY"))
        api_key = os.environ.get(key_env, "")
        base_url = str(config.get(cfg, "provider.base_url", ""))
        model = str(config.get(cfg, "provider.model", ""))
        return OpenAIProvider(
            base_url=base_url,
            api_key=api_key,
            model=model,
            temperature=float(config.get(cfg, "provider.temperature", 0.2)),
            max_tokens=int(config.get(cfg, "provider.max_tokens", 4096)),
            timeout_s=int(config.get(cfg, "provider.timeout_s", 180)),
            extra_body=config.get(cfg, "provider.extra_body", {}),
            max_retries=int(config.get(cfg, "solver.max_llm_retries", 2)),
        )
    raise ProviderError(f"unknown provider kind: {kind!r}")
