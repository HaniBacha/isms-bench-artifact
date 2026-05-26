from __future__ import annotations

from dataclasses import dataclass

from kisec.models import EvidencePassage


@dataclass(frozen=True)
class RetrievalResult:
    evidence_id: str
    document_id: str
    score: float
    rank: int


class BaseRetriever:
    name = "base"

    def fit(self, passages: list[EvidencePassage]) -> "BaseRetriever":
        raise NotImplementedError

    def retrieve(
        self,
        query: str,
        k: int = 5,
        candidate_document_ids: list[str] | None = None,
    ) -> list[RetrievalResult]:
        raise NotImplementedError
