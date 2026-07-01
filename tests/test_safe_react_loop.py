from core.ollama_brain import ALLOWED_ACTIONS, think
from core.react_loop import DEFAULT_PLAN
from core.state_manager import StateManager


def test_brain_fallback_returns_allowlisted_action():
    decision = think("initial output", {"target": "https://example.com", "plan": DEFAULT_PLAN, "completed": [], "turn": 1})
    assert decision["action"] in ALLOWED_ACTIONS
    assert decision["action"] == DEFAULT_PLAN[0]


def test_brain_moves_to_next_pending_action():
    decision = think("previous step complete", {"target": "https://example.com", "plan": DEFAULT_PLAN, "completed": [DEFAULT_PLAN[0]], "turn": 2})
    assert decision["action"] == DEFAULT_PLAN[1]


def test_state_manager_persists_completed_action(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    state = StateManager("https://example.com")
    state.mark_completed("dependency_status", {"status": "completed"})
    assert "dependency_status" in state.state["completed"]
    checkpoint = state.write_report()
    assert checkpoint["status"] == "completed"
