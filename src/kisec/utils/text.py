from __future__ import annotations

import re

TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")


def tokenize(text: str) -> list[str]:
    return [token.lower() for token in TOKEN_RE.findall(text)]


def normalize_space(text: str) -> str:
    return " ".join(text.split())
