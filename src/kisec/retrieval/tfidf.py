from __future__ import annotations

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

from kisec.models import EvidencePassage
from kisec.retrieval.base import BaseRetriever, RetrievalResult


class TfidfRetriever(BaseRetriever):
    name = "tfidf"

    def __init__(self) -> None:
        self.passages: list[EvidencePassage] = []
        self.vectorizer = TfidfVectorizer(lowercase=True, ngram_range=(1, 2))
        self.matrix = None
        self._document_to_indices: dict[str, list[int]] = {}

    def fit(self, passages: list[EvidencePassage]) -> "TfidfRetriever":
        self.passages = passages
        self.matrix = self.vectorizer.fit_transform([passage.text for passage in passages])
        self._document_to_indices = {}
        for index, passage in enumerate(passages):
            self._document_to_indices.setdefault(passage.document_id, []).append(index)
        return self

    def retrieve(
        self,
        query: str,
        k: int = 5,
        candidate_document_ids: list[str] | None = None,
    ) -> list[RetrievalResult]:
        if self.matrix is None:
            raise RuntimeError("Retriever must be fitted before retrieve().")
        query_vector = self.vectorizer.transform([query])
        candidate_set = set(candidate_document_ids or [])
        if candidate_set:
            candidate_indices = [
                index
                for document_id in candidate_set
                for index in self._document_to_indices.get(document_id, [])
            ]
            if candidate_indices:
                subset = self.matrix[candidate_indices]
                subset_scores = np.asarray((subset @ query_vector.T).todense()).ravel()
                scores_by_index = {idx: float(score) for idx, score in zip(candidate_indices, subset_scores)}
                ranked_indices = sorted(candidate_indices, key=lambda idx: (-scores_by_index[idx], idx))
            else:
                scores_by_index = {}
                ranked_indices = []
        else:
            scores = np.asarray((self.matrix @ query_vector.T).todense()).ravel()
            scores_by_index = {idx: float(scores[idx]) for idx in range(len(scores))}
            ranked_indices = sorted(range(len(scores_by_index)), key=lambda idx: (-scores_by_index[idx], idx))
        results: list[RetrievalResult] = []
        for idx in ranked_indices:
            passage = self.passages[idx]
            if candidate_set and passage.document_id not in candidate_set:
                continue
            if scores_by_index[idx] <= 0 and results:
                continue
            results.append(
                RetrievalResult(
                    evidence_id=passage.evidence_id,
                    document_id=passage.document_id,
                    score=float(scores_by_index[idx]),
                    rank=len(results) + 1,
                )
            )
            if len(results) >= k:
                break
        return results
