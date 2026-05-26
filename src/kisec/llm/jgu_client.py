from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kisec.utils.io import read_json, write_json


ROOT = Path(__file__).resolve().parents[3]
DEFAULT_JGU_API_BASE = "https://openai-compatible.example.invalid/v1"
DEFAULT_JGU_MODEL = "GPT OSS 120B"


class JGUClientConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class LLMResponse:
    text: str
    model: str
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None
    cached: bool = False
    provider: str = "jgu"


def _load_dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def _env_value(names: list[str], dotenv: dict[str, str]) -> str | None:
    placeholder_markers = {
        "<insert_local_key_here>",
        "<insert_base_url_here>",
        "<insert_model_here>",
        "...",
        "changeme",
    }
    for name in names:
        value = os.environ.get(name) or dotenv.get(name)
        if value and value.strip() not in placeholder_markers and not value.strip().startswith("<insert_"):
            return value
    return None


@dataclass(frozen=True)
class JGUClientConfig:
    api_key: str
    base_url: str
    model: str
    timeout_seconds: int = 60
    max_retries: int = 2
    temperature: float = 0.0
    max_tokens: int = 1024

    @classmethod
    def from_env(cls, env_file: str | Path = ".env", cli_model: str | None = None) -> "JGUClientConfig":
        dotenv = _load_dotenv(ROOT / env_file)
        api_key = _env_value(["JGU_API_KEY", "KI_CHAT_API_KEY"], dotenv)
        base_url = _env_value(["JGU_API_BASE", "KI_CHAT_API_BASE", "KI_CHAT_BASE_URL"], dotenv) or DEFAULT_JGU_API_BASE
        model = _env_value(["JGU_MODEL", "KI_CHAT_MODEL"], dotenv) or cli_model or DEFAULT_JGU_MODEL
        max_tokens_raw = _env_value(["JGU_MAX_TOKENS", "KI_CHAT_MAX_TOKENS"], dotenv)
        max_tokens = int(max_tokens_raw) if max_tokens_raw and max_tokens_raw.isdigit() else 1024
        missing = []
        if not api_key:
            missing.append("JGU_API_KEY or KI_CHAT_API_KEY")
        if missing:
            raise JGUClientConfigError(
                "Missing LLM provider configuration: "
                + ", ".join(missing)
                + ". Use --dry-run for deterministic mock evaluation."
            )
        return cls(api_key=api_key, base_url=base_url.rstrip("/"), model=model, max_tokens=max_tokens)


class MockLLMClient:
    """Deterministic local substitute used for tests and dry-run evaluations."""

    model = "mock_llm_v13"

    def chat_json(self, messages: list[dict[str, str]], cache_key_extra: str = "") -> LLMResponse:
        text = "\n".join(message.get("content", "") for message in messages).lower()
        if any(marker in text for marker in ["not yet", "no recent", "not defined", "keine", "nicht definiert"]):
            status = "not_fulfilled"
            confidence = "medium"
        elif "draft" in text or "expired" in text or "future" in text or "planned" in text:
            status = "unclear"
            confidence = "medium"
        elif "tabletop" in text and "role" in text and "supplier" in text and "approved" in text:
            status = "fulfilled"
            confidence = "high"
        elif "incident response" in text or "sicherheitsvorfall" in text:
            status = "partially_fulfilled"
            confidence = "medium"
        else:
            status = "unclear"
            confidence = "low"
        evidence_ids = sorted(set(part for part in text.replace("[", " ").replace("]", " ").split() if part.startswith("ev-") or part.startswith("manual-") or part.startswith("pub-") or part.startswith("atk-")))[:3]
        payload = {
            "predicted_status": status,
            "accepted_evidence_ids": evidence_ids,
            "rejected_evidence_ids": [],
            "missing_evidence": [] if status == "fulfilled" else ["insufficient validated implementation evidence"],
            "source_attribution_warnings": [],
            "explanation": "Deterministic mock response for dry-run evaluation.",
            "confidence": confidence,
        }
        return LLMResponse(text=json.dumps(payload), model=self.model, provider="mock")


class JGULLMClient:
    """Small OpenAI-compatible chat client with safe caching.

    The client never logs or returns the API key. It reads configuration from
    environment variables or a local .env file through JGUClientConfig.
    """

    def __init__(
        self,
        config: JGUClientConfig,
        cache_dir: str | Path = "experiments/logs/llm_v13/cache",
        store_raw: bool = False,
        raw_dir: str | Path = "experiments/logs/llm_v13/raw",
    ) -> None:
        self.config = config
        self.cache_dir = ROOT / cache_dir
        self.raw_dir = ROOT / raw_dir
        self.store_raw = store_raw
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        if store_raw:
            self.raw_dir.mkdir(parents=True, exist_ok=True)

    @property
    def model(self) -> str:
        return self.config.model

    def _endpoint(self) -> str:
        base = self.config.base_url.rstrip("/")
        if base.endswith("/chat/completions"):
            return base
        return f"{base}/chat/completions"

    def _prepared_messages(self, messages: list[dict[str, str]]) -> list[dict[str, str]]:
        prepared = [dict(message) for message in messages]
        model = self.config.model.lower()
        if "qwen3" in model and "thinking" in model:
            for message in reversed(prepared):
                if message.get("role") == "user":
                    content = message.get("content", "")
                    if not content.lstrip().startswith("/no_think"):
                        message["content"] = "/no_think\n" + content
                    break
        return prepared

    def _cache_path(self, messages: list[dict[str, str]], cache_key_extra: str) -> Path:
        payload = {
            "model": self.config.model,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "messages": messages,
            "extra": cache_key_extra,
        }
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
        return self.cache_dir / f"{digest}.json"

    def chat_json(self, messages: list[dict[str, str]], cache_key_extra: str = "") -> LLMResponse:
        messages = self._prepared_messages(messages)
        cache_path = self._cache_path(messages, cache_key_extra)
        if cache_path.exists():
            cached = read_json(cache_path)
            return LLMResponse(
                text=str(cached["text"]),
                model=str(cached.get("model", self.config.model)),
                prompt_tokens=cached.get("prompt_tokens"),
                completion_tokens=cached.get("completion_tokens"),
                total_tokens=cached.get("total_tokens"),
                cached=True,
                provider="jgu",
            )

        request_payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "response_format": {"type": "json_object"},
        }
        data = json.dumps(request_payload).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
        }
        req = urllib.request.Request(self._endpoint(), data=data, headers=headers, method="POST")
        last_error: str | None = None
        for attempt in range(self.config.max_retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=self.config.timeout_seconds) as response:
                    raw = response.read().decode("utf-8")
                parsed = json.loads(raw)
                text = parsed["choices"][0]["message"].get("content") or ""
                usage = parsed.get("usage", {})
                compact = {
                    "text": text,
                    "model": self.config.model,
                    "prompt_tokens": usage.get("prompt_tokens"),
                    "completion_tokens": usage.get("completion_tokens"),
                    "total_tokens": usage.get("total_tokens"),
                }
                write_json(cache_path, compact)
                if self.store_raw:
                    write_json(self.raw_dir / cache_path.name, {"response": parsed})
                return LLMResponse(provider="jgu", **compact)
            except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError, KeyError) as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                if attempt >= self.config.max_retries:
                    break
                time.sleep(1.5 * (attempt + 1))
        raise RuntimeError(f"LLM request failed for model {self.config.model}: {last_error}")
