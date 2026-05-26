from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any


VALID_STATUSES = {"fulfilled", "partially_fulfilled", "not_fulfilled", "unclear"}
VALID_CONFIDENCE = {"low", "medium", "high"}


@dataclass(frozen=True)
class ParsedLLMOutput:
    data: dict[str, Any]
    parse_error: bool = False
    repair_attempted: bool = False
    error_message: str = ""


def _empty_unclear(error_message: str, repair_attempted: bool) -> ParsedLLMOutput:
    return ParsedLLMOutput(
        data={
            "predicted_status": "unclear",
            "accepted_evidence_ids": [],
            "rejected_evidence_ids": [],
            "missing_evidence": ["LLM output could not be parsed"],
            "source_attribution_warnings": [],
            "explanation": "Invalid or unparsable LLM output; defaulted to unclear.",
            "confidence": "low",
        },
        parse_error=True,
        repair_attempted=repair_attempted,
        error_message=error_message,
    )


def _extract_json(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?", "", stripped, flags=re.IGNORECASE).strip()
        stripped = re.sub(r"```$", "", stripped).strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        return stripped
    match = re.search(r"\{.*\}", stripped, flags=re.DOTALL)
    if match:
        return match.group(0)
    return stripped


def _coerce_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str):
        return [value] if value else []
    return [str(value)]


def _normalize(data: dict[str, Any]) -> dict[str, Any]:
    status = str(data.get("predicted_status", "unclear")).strip()
    if status not in VALID_STATUSES:
        status = "unclear"
    confidence = str(data.get("confidence", "low")).strip().lower()
    if confidence not in VALID_CONFIDENCE:
        confidence = "low"
    return {
        "predicted_status": status,
        "accepted_evidence_ids": _coerce_list(data.get("accepted_evidence_ids")),
        "rejected_evidence_ids": _coerce_list(data.get("rejected_evidence_ids")),
        "missing_evidence": _coerce_list(data.get("missing_evidence")),
        "source_attribution_warnings": _coerce_list(data.get("source_attribution_warnings")),
        "explanation": str(data.get("explanation", ""))[:1200],
        "confidence": confidence,
    }


def parse_llm_json(text: str) -> ParsedLLMOutput:
    repair_attempted = False
    try:
        return ParsedLLMOutput(data=_normalize(json.loads(_extract_json(text))))
    except Exception as first_exc:
        repair_attempted = True
        candidate = _extract_json(text)
        candidate = candidate.replace("'", '"')
        candidate = re.sub(r",\s*([}\]])", r"\1", candidate)
        try:
            return ParsedLLMOutput(data=_normalize(json.loads(candidate)), repair_attempted=True)
        except Exception as second_exc:
            return _empty_unclear(f"{type(first_exc).__name__}; repair failed: {type(second_exc).__name__}", repair_attempted)
