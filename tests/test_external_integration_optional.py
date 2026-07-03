import os
import subprocess
import sys

import pytest


@pytest.mark.skipif(os.getenv("VULNSCOPE_RUN_EXTERNAL_INTEGRATION") != "1", reason="external integration test is opt-in")
def test_optional_public_lab_scan_produces_report():
    cmd = [
        sys.executable,
        "vulnscope.py",
        "--target",
        "http://testphp.vulnweb.com",
        "--yes",
        "--mode",
        "bugbounty",
        "--max-pages",
        "20",
        "--max-depth",
        "2",
        "--max-actions",
        "40",
        "--request-budget",
        "120",
        "--no-live-dashboard",
    ]
    result = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=900)
    assert result.returncode == 0
    assert "unified-research-orchestration" in result.stdout or "final-findings-dashboard" in result.stdout
