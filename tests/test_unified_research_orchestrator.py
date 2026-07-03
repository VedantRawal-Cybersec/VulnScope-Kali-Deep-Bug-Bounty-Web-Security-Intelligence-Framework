from pathlib import Path
from types import SimpleNamespace

from core.engines.research_profiles import RESEARCH_PROFILES, profiles_by_phase
from core.engines.unified_research_orchestrator import UnifiedResearchOrchestrator


class DummyState:
    def __init__(self, tmp_path: Path):
        self.out_dir = tmp_path
        self.urls = {
            "1": SimpleNamespace(url="https://example.com/api/users?id=1"),
            "2": SimpleNamespace(url="https://example.com/login"),
            "3": SimpleNamespace(url="https://example.com/assets/app.js"),
        }
        self.params = {
            "p1": SimpleNamespace(name="id"),
            "p2": SimpleNamespace(name="redirect"),
        }
        self.findings = []
        self.stats = {}
        self.saved = False

    def save(self):
        self.saved = True


def test_profiles_cover_requested_repositories():
    assert len(RESEARCH_PROFILES) >= 21
    repos = {profile.repository for profile in RESEARCH_PROFILES}
    assert "https://github.com/usestrix/strix.git" in repos
    assert "https://github.com/gitfive/gitfive.git" in repos


def test_profiles_by_phase_returns_discovery_profiles():
    discovery = profiles_by_phase("discovery")
    assert discovery
    assert any(profile.family in {"agentic-orchestration", "web-vulnerability-triage", "web-assessment-workflow"} for profile in discovery)


def test_unified_orchestrator_writes_reports(tmp_path):
    state = DummyState(tmp_path)
    orchestrator = UnifiedResearchOrchestrator(state=state, dashboard=None)
    payload = orchestrator.run_all()
    assert payload["copied_offensive_code"] is False
    assert payload["embedded_attack_payloads"] is False
    assert payload["decisions"]
    assert Path(payload["json_path"]).exists()
    assert Path(payload["markdown_path"]).exists()
    assert state.saved is True
