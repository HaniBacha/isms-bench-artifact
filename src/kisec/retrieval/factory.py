from __future__ import annotations

from kisec.retrieval.base import BaseRetriever
from kisec.retrieval.bm25 import BM25Retriever


def make_retriever(method: str) -> BaseRetriever:
    if method == "bm25":
        return BM25Retriever()
    if method == "tfidf":
        from kisec.retrieval.tfidf import TfidfRetriever

        return TfidfRetriever()
    if method == "dense":
        from kisec.retrieval.dense import DenseRetrieverStub

        return DenseRetrieverStub()
    raise ValueError(f"Unknown retrieval method: {method}")
