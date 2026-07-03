# VulnScope Usage

## Version check

```bash
python3 main.py --version
```

## Edit the tool list

```bash
python3 vulnscope.py --edit-tools
```

This opens `tools.txt` in `nano` or the editor specified by `$EDITOR`.

## Batch-install tools from tools.txt

`tools.txt` format:

```text
# comments are ignored
https://github.com/projectdiscovery/nuclei.git
https://github.com/projectdiscovery/katana.git
```

Install:

```bash
python3 vulnscope.py --add-tool -tools.txt
```

Non-interactive confirmation:

```bash
python3 vulnscope.py --add-tool -tools.txt --yes
```

Logs:

```text
logs/tool_install.log
logs/tool_install_summary.json
```

## Add one tool interactively

```bash
python3 vulnscope.py --add-tool
```

## List tools

```bash
python3 vulnscope.py --list-tools
```

## Scan modes

Safe active scan:

```bash
python3 vulnscope.py --target https://example.com --yes --scan-mode safe-active
```

Bug bounty shortcut:

```bash
python3 vulnscope.py --target https://example.com --yes --mode bugbounty
```

Lab shortcut:

```bash
python3 vulnscope.py --target http://127.0.0.1:3000 --yes --mode lab --browser
```

`--mode lab` is an alias for `--scan-mode lab`. It is intended only for owned targets or intentionally vulnerable local labs. VulnScope core still disables destructive activity, credential attacks, callback injection, cache poisoning, service disruption, and target data modification.

## Disable dynamic tools during a scan

```bash
python3 vulnscope.py --target https://example.com --yes --no-dynamic-tools
```

## Reports

```text
reports/output/cai-superior/<host>/final-findings-dashboard.md
reports/output/cai-superior/<host>/autonomous-scan-report.md
reports/output/cai-superior/<host>/parameter-inventory-v2.json
reports/output/cai-superior/<host>/phase-runner-summary.json
reports/output/cai-superior/<host>/dynamic-tool-phase-summary.json
tools/registry.json
logs/tool_install.log
```
