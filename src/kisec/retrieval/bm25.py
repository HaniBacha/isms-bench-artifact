from __future__ import annotations

import math
from collections import Counter

from kisec.models import EvidencePassage
from kisec.retrieval.base import BaseRetriever, RetrievalResult
from kisec.utils.text import tokenize


class _LocalBM25:
    def __init__(self, tokenized_documents: list[list[str]], k1: float = 1.5, b: float = 0.75):
        self.tokenized_documents = tokenized_documents
        self.k1 = k1
        self.b = b
        self.doc_len = [len(doc) for doc in tokenized_documents]
        self.avgdl = sum(self.doc_len) / max(len(self.doc_len), 1)
        self.term_freqs = [Counter(doc) for doc in tokenized_documents]
        doc_freq: Counter[str] = Counter()
        for doc in tokenized_documents:
            doc_freq.update(set(doc))
        self.idf = {
            term: math.log(1 + (len(tokenized_documents) - freq + 0.5) / (freq + 0.5))
            for term, freq in doc_freq.items()
        }

    def get_scores(self, query_tokens: list[str]) -> list[float]:
        scores: list[float] = []
        for index, term_freq in enumerate(self.term_freqs):
            doc_score = 0.0
            doc_len = self.doc_len[index] or 1
            for token in query_tokens:
                freq = term_freq.get(token, 0)
                if freq == 0:
                    continue
                numerator = freq * (self.k1 + 1)
                denominator = freq + self.k1 * (1 - self.b + self.b * doc_len / self.avgdl)
                doc_score += self.idf.get(token, 0.0) * numerator / denominator
            scores.append(doc_score)
        return scores


class BM25Retriever(BaseRetriever):
    name = "bm25"

    def __init__(self) -> None:
        self.passages: list[EvidencePassage] = []
        self._tokenized: list[list[str]] = []
        self._index: object | None = None
        self._local_index: _LocalBM25 | None = None
        self._document_to_indices: dict[str, list[int]] = {}
        self.backend = "local_bm25"

    def fit(self, passages: list[EvidencePassage]) -> "BM25Retriever":
        self.passages = passages
        self._tokenized = [tokenize(passage.text) for passage in passages]
        self._local_index = _LocalBM25(self._tokenized)
        self._document_to_indices = {}
        for index, passage in enumerate(passages):
            self._document_to_indices.setdefault(passage.document_id, []).append(index)
        try:
            from rank_bm25 import BM25Okapi  # type: ignore

            self._index = BM25Okapi(self._tokenized)
            self.backend = "rank_bm25"
        except Exception:
            self._index = self._local_index
            self.backend = "local_bm25"
        return self

    def _score_index(self, idx: int, query_tokens: list[str]) -> float:
        if self._local_index is None:
            return 0.0
        term_freq = self._local_index.term_freqs[idx]
        doc_len = self._local_index.doc_len[idx] or 1
        doc_score = 0.0
        for token in query_tokens:
            freq = term_freq.get(token, 0)
            if freq == 0:
                continue
            numerator = freq * (self._local_index.k1 + 1)
            denominator = freq + self._local_index.k1 * (
                1 - self._local_index.b + self._local_index.b * doc_len / self._local_index.avgdl
            )
            doc_score += self._local_index.idf.get(token, 0.0) * numerator / denominator
        return doc_score

    def retrieve(
        self,
        query: str,
        k: int = 5,
        candidate_document_ids: list[str] | None = None,
    ) -> list[RetrievalResult]:
        if self._index is None:
            raise RuntimeError("Retriever must be fitted before retrieve().")
        candidate_set = set(candidate_document_ids or [])
        query_tokens = tokenize(query)
        if candidate_set:
            candidate_indices = [
                index
                for document_id in candidate_set
                for index in self._document_to_indices.get(document_id, [])
            ]
            scores_by_index = {idx: self._score_index(idx, query_tokens) for idx in candidate_indices}
            ranked_indices = sorted(candidate_indices, key=lambda idx: (-scores_by_index[idx], idx))
        else:
            scores = list(self._index.get_scores(query_tokens))  # type: ignore[attr-defined]
            scores_by_index = {idx: scores[idx] for idx in range(len(scores))}
            ranked_indices = sorted(range(len(scores)), key=lambda idx: (-scores[idx], idx))
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
