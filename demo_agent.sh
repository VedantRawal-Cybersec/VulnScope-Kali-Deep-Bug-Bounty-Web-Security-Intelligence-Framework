#!/usr/bin/env bash
set -euo pipefail

echo "[+] VulnScope neural agent dry run"
python3 vulnscope_agent.py --config agent_config.yaml --dry-run

echo "[+] Open: reports/output/neural-agent/thinking-log.md"
