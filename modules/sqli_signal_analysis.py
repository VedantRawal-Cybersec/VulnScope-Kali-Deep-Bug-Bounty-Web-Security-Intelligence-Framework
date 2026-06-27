from __future__ import annotations

from core.evidence_store import EvidenceStore, Finding
from core.request_engine import ResponseRecord
from learning.knowledge_base import REMEDIATION_KNOWLEDGE

DB_ERROR_INDICATORS = [
    "sql syntax",
    "mysql",
    "postgresql",
    "sqlite",
    "ora-",
    "odbc",
    "jdbc",
    "database error",
    "unclosed quotation",
    "syntax error",
]

NUMERIC_HINTS = ("id", "user_id", "account_id", "order_id", "product_id", "invoice_id")


def analyze_sqli_signals(store: EvidenceStore, responses: list[ResponseRecord]) -> None:
    """Non-destructive SQLi signal analysis.

    This module does not inject SQL payloads and does not enumerate data. It only
    looks for already-visible database error indicators and numeric parameters
    that deserve manual review in authorized scope.
    """
    db_error_hits: list[dict[str, str]] = []
    numeric_param_candidates: list[dict[str, str]] = []

    for response in responses:
        if response.error or not response.text:
            continue
        lowered = response.text.lower()
        for indicator in DB_ERROR_INDICATORS:
            if indicator in lowered:
                db_error_hits.append({"endpoint": response.url, "indicator_class": indicator})
                break

    for endpoint, params in store.parameters.items():
        for param in params:
            if param.lower() in NUMERIC_HINTS or param.lower().endswith("id"):
                numeric_param_candidates.append({"endpoint": endpoint, "parameter": param})

    store.metadata["sqli_signal_analysis"] = {
        "db_error_hit_count": len(db_error_hits),
        "numeric_parameter_candidate_count": len(numeric_param_candidates),
        "db_error_hits": db_error_hits[:50],
        "numeric_parameter_candidates": numeric_param_candidates[:100],
    }

    if db_error_hits:
        store.add_finding(
            Finding(
                finding_id=store.next_finding_id(),
                title="Database Error Signal Observed",
                category="SQLi Signal Analysis",
                severity="High",
                confidence="Medium",
                status="Manual Validation Required",
                endpoint="Multiple responses",
                where_found="Textual response database-error signal scan",
                how_detected=["Database-like error indicators were observed in textual responses"],
                why_risky="Database error messages can indicate unsafe error handling or query behavior. This is not proof of SQL injection and requires safe manual validation.",
                evidence={"db_error_hits": db_error_hits[:25]},
                recommended_validation=[
                    "Validate only inside authorized scope.",
                    "Do not dump, enumerate, or extract database contents.",
                    "Confirm whether errors are caused by normal application behavior or unsafe query handling.",
                ],
                remediation=REMEDIATION_KNOWLEDGE["sqli"],
            )
        )

    if numeric_param_candidates:
        store.add_finding(
            Finding(
                finding_id=store.next_finding_id(),
                title="Numeric Parameters Identified for Injection Review",
                category="SQLi Signal Analysis",
                severity="Info",
                confidence="Medium",
                status="Manual Review Required",
                endpoint="Multiple endpoints",
                where_found="Parameter classification",
                how_detected=["ID-like numeric parameters were identified from URLs and forms"],
                why_risky="Numeric parameters are common database lookup inputs. This is only a prioritization hint for manual review, not a vulnerability confirmation.",
                evidence={"numeric_parameter_candidates": numeric_param_candidates[:30]},
                recommended_validation=["Review server-side query handling and validation for listed parameters."],
                remediation=REMEDIATION_KNOWLEDGE["sqli"],
            )
        )
