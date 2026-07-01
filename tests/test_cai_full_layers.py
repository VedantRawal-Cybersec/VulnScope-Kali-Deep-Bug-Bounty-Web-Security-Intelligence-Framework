from cai_adaptive_risk_cli import _business_multiplier
from cai_business_logic_cli import build_business_review
from cai_prioritization_cli import build_prioritization
from cai_safety_gate import evaluate_action


def test_safety_gate_blocks_out_of_scope_and_write_methods():
    assert evaluate_action(target="https://example.com", candidate_url="https://evil.example.net", method="GET")["allowed"] is False
    assert evaluate_action(target="https://example.com", candidate_url="https://example.com/a", method="POST")["allowed"] is False
    assert evaluate_action(target="https://example.com", candidate_url="https://example.com/a", topic="remote-resource-reference-review")["allowed"] is False
    assert evaluate_action(target="https://example.com", candidate_url="https://example.com/a", topic="remote-resource-reference-review", user_approved=True)["allowed"] is True


def test_business_multiplier_detects_context():
    assert _business_multiplier({"path": "/billing/invoice"}) >= 1.2
    assert _business_multiplier({"path": "/public"}) == 1.0
