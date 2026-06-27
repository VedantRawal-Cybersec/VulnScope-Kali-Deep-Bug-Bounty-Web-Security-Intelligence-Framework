#!/usr/bin/env bash
set -euo pipefail

echo "[+] Updating VulnScope-Kali from GitHub..."

git fetch origin main
git reset --hard origin/main
python3 -m pip install -r requirements.txt
python3 -m compileall .
python3 vulnscope.py --version

echo "[+] Update completed."
