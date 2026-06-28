#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import sys

MENU = """
┌──────────────────── VulnScope Kali Console ────────────────────┐
│ 1. Run full agentic workflow                                    │
│ 2. Dry-run full workflow                                        │
│ 3. Show available local tool registry                           │
│ 4. Run AI Discovery on existing evidence                        │
│ 5. Run Mythic validation on existing evidence                   │
│ 6. Run Uplift analyzer on existing evidence                     │
│ 7. Export reports ZIP                                           │
│ 8. Exit                                                         │
└─────────────────────────────────────────────────────────────────┘
"""


def main() -> int:
    py = sys.executable or "python3"
    while True:
        print(MENU)
        choice = input("Select option: ").strip()
        if choice == "1":
            url = input("Authorized target URL: ").strip()
            subprocess.call([py, "agentic_controller_cli.py", "--url", url])
        elif choice == "2":
            url = input("Authorized target URL: ").strip()
            subprocess.call([py, "agentic_controller_cli.py", "--url", url, "--dry-run"])
        elif choice == "3":
            subprocess.call([py, "-c", "from integrations.tool_registry import registry_as_dict; import json; print(json.dumps(registry_as_dict(), indent=2))"])
        elif choice == "4":
            subprocess.call([py, "ai_discovery_cli.py", "--input", "reports/output/evidence.json"])
        elif choice == "5":
            subprocess.call([py, "mythic_hunter_cli.py", "--input", "reports/output/evidence.json", "--depth", "DEEP_HUNTER_MODE"])
        elif choice == "6":
            subprocess.call([py, "mythic_uplift_cli.py", "--input", "reports/output/evidence.json"])
        elif choice == "7":
            subprocess.call([py, "export_reports.py", "--open-folder"])
        elif choice == "8":
            return 0
        else:
            print("Invalid option")


if __name__ == "__main__":
    raise SystemExit(main())
