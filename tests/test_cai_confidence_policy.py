from cai_confidence_policy import score_candidate


def test_low_signal_without_evidence_is_noise():
    result = score_candidate(
        vulnerability_type="IDOR/BOLA",
        item={"title": "id parameter found", "evidence": "parameter name only, no baseline"},
        evidence_type=None,
        evidence_detail="",
        control_comparison_result="No explicit control/baseline artifact captured in source evidence.",
    )
    assert result["confidence"] == "low"
    assert result["classification"] == "NOISE"


def test_structural_diff_without_reproduction_is_review_lead():
    result = score_candidate(
        vulnerability_type="Safe Parameter Review",
        item={"evidence": "safe marker reflected in response body"},
        evidence_type="structural response diff",
        evidence_detail="marker reflected in response body",
        control_comparison_result="No explicit control/baseline artifact captured in source evidence.",
    )
    assert result["confidence"] == "medium"
    assert result["classification"] == "REVIEW LEAD"


def test_cross_account_with_control_can_confirm():
    result = score_candidate(
        vulnerability_type="IDOR/BOLA",
        item={"evidence": "cross-account request id A and request id B reproduced two requests confirmed sensitive account data"},
        evidence_type="cross-session/cross-account comparison",
        evidence_detail="account A object returned under account B session with request ids A/B",
        control_comparison_result="baseline known-safe object returned no anomaly",
    )
    assert result["confidence"] == "high"
    assert result["classification"] == "CONFIRMED"
    assert result["confidence_score"] >= 0.75
