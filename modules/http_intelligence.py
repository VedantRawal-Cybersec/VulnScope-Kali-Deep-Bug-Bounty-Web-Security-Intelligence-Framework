from __future__ import annotations

from core.evidence_store import EvidenceStore
from core.request_engine import ResponseRecord


def collect_http_metadata(store: EvidenceStore, response: ResponseRecord) -> None:
    store.metadata["root_probe"] = {
        "url": response.url,
        "status_code": response.status_code,
        "content_type": response.content_type,
        "content_length": response.content_length,
        "title": response.title,
        "error": response.error,
    }
