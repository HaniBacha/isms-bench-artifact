#!/usr/bin/env python
from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from kisec.llm.jgu_client import (
    DEFAULT_JGU_API_BASE,
    DEFAULT_JGU_MODEL,
    JGUClientConfig,
    JGUClientConfigError,
    _env_value,
    _load_dotenv,
)
from kisec.utils.io import write_json


def _redact_base(base_url: str) -> str:
    parsed = urlparse(base_url)
    if parsed.hostname:
        return f"{parsed.scheme}://{parsed.hostname}"
    return "configured"


def main() -> None:
    dotenv = _load_dotenv(ROOT / ".env")
    api_key = _env_value(["JGU_API_KEY", "KI_CHAT_API_KEY"], dotenv)
    base_url = _env_value(["JGU_API_BASE", "KI_CHAT_API_BASE", "KI_CHAT_BASE_URL"], dotenv) or DEFAULT_JGU_API_BASE
    model = _env_value(["JGU_MODEL", "KI_CHAT_MODEL"], dotenv) or DEFAULT_JGU_MODEL
    try:
        config = JGUClientConfig.from_env()
        result = {
            "key_exists": True,
            "base_url_redacted": _redact_base(config.base_url),
            "model": config.model,
            "ready": True,
            "error": "",
        }
    except JGUClientConfigError as exc:
        result = {
            "key_exists": bool(api_key),
            "base_url_redacted": _redact_base(base_url) if base_url else "",
            "model": model or "",
            "ready": False,
            "error": str(exc),
        }
    write_json(ROOT / "experiments/results/llm_env_check_v14.json", result)
    print(
        {
            "key_exists": "yes" if result["key_exists"] else "no",
            "base_url": result["base_url_redacted"] or "missing",
            "model": result["model"] or "missing",
            "ready": result["ready"],
        }
    )


if __name__ == "__main__":
    main()
