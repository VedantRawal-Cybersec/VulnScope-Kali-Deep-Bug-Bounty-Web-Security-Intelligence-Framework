from __future__ import annotations

import re
from urllib.parse import urlparse

from core.evidence_store import EvidenceStore, Finding
from learning.knowledge_base import REMEDIATION_KNOWLEDGE

OBJECT_ROUTE_RE = re.compile(r"/(?:api/)?(?:users?|accounts?|orders?|invoices?|profiles?|payments?)(?:/|$)", re.I)
ID_LIKE_RE = re.compile(r"/(?:\d+|[0-9a-f]{8,})(?:/|$)", re.I)


def analyze_access_control_hints(store: EvidenceStore) -> None:
    candidates: list[dict[str, str | bool]] = []

    for endpoint in sorted(store.endpoints):
        path = urlparse(endpoint).path
        query_params = store.parameters.get(endpoint, [])
        object_route = bool(OBJECT_ROUTE_RE.search(path))
        id_in_path = bool(ID_LIKE_RE.search(path))
        id_param = any(param.lower().endswith("id") or param.lower() == "id" for param in query_params)

        if object_route or id_in_path or id_param:
            candidates.append(
                {
                    "endpoint": endpoint,
                    "object_route": object_route,
                    "id_in_path": id_in_path,
                    "id_parameter": id_param,
                    "review": "Object-level authorization / IDOR manual validation candidate",
                }
            )

    store.metadata["access_control_hints"] = {
        "candidate_count": len(candidates),
        "candidates": candidates[:100],
    }

    if candidates:
        store.add_finding(
            Finding(
                finding_id=store.next_finding_id(),
                title="Object-Level Access Control Candidates Identified",
                category="Access Control / IDOR Candidate",
                severity="Medium",
                confidence="Medium",
                status="Manual Validation Required",
                endpoint="Multiple endpoints",
                where_found="Route and parameter pattern analysis",
                how_detected=[
                    "Object-related route names, numeric/hex object identifiers, or ID-like parameters were identified"
                ],
                why_risky="Endpoints that expose object identifiers may be vulnerable if the server checks login state but fails to verify that the current user is authorized to access the requested object.",
                evidence={"candidates": candidates[:30]},
                recommended_validation=[
                    "Use two authorized test accounts.",
                    "Request the same object from both accounts only where program scope permits.",
                    "Confirm whether object ownership is enforced server-side.",
                ],
                remediation=REMEDIATION_KNOWLEDGE["access_control"],
            )
        )
