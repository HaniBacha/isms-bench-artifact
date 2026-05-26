from __future__ import annotations

from kisec.models import EvidencePassage
from kisec.retrieval.base import BaseRetriever, RetrievalResult


class DenseRetrieverStub(BaseRetriever):
    """Placeholder for sentence-transformer retrieval.

    Dense retrieval is intentionally not required for the first baseline because
    the repository must run without paid APIs or heavyweight downloads.
    """

    name = "dense_stub"

    def fit(self, passages: list[EvidencePassage]) -> "DenseRetrieverStub":
        self.passages = passages
        return self

    def retrieve(
        self,
        query: str,
        k: int = 5,
        candidate_document_ids: list[str] | None = None,
    ) -> list[RetrievalResult]:
        raise NotImplementedError(
            "Dense retrieval is a TODO. Install sentence-transformers and add an "
            "embedding index implementation in kisec.retrieval.dense."
        )
