# Testing VulnScope-Kali

## Python syntax check

Run this after every pull:

```bash
python3 -m compileall .
```

## Dependency check

```bash
pip3 install -r requirements.txt
python3 -c "import requests, bs4, rich, yaml, jinja2; print('dependencies ok')"
```

## Safe local run

Use only authorized targets. For first test, use a local lab or a website you own.

```bash
python3 vulnscope.py --url http://localhost:3000 --mode passive --max-pages 10
```

## Output check

```bash
ls -la reports/output/
cat reports/output/target-report.md
python3 -m json.tool reports/output/evidence.json
```

## AutoPilot environment check

```bash
python3 autopilot/environment_scanner.py
cat reports/output/autopilot-environment.json
```

## GitHub Actions

The repository includes `.github/workflows/python-check.yml` to compile all Python files on push, pull request, or manual workflow run.

## Expected behavior

- The scanner asks for authorization in interactive mode.
- The scanner stays same-domain only.
- The scanner generates Markdown and JSON reports.
- XSS and SQLi modules are signal-only and non-destructive.
- Unknown tools are not executed.
- External tools are detected but not used for scanning automatically.
