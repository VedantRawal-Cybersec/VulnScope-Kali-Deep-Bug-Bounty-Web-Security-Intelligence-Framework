# Report Export / Download

VulnScope-Kali now includes a local report export option.

It packages all generated reports into a ZIP file in the user's `Downloads` folder by default.

## Export Reports

Run from the project root:

```bash
python3 export_reports.py
```

Output example:

```text
~/Downloads/vulnscope-report-pack-20260628-154500.zip
```

## Export and Open Folder

```bash
python3 export_reports.py --open-folder
```

## List Report Files Before Export

```bash
python3 export_reports.py --list
```

## Custom Output Path

```bash
python3 export_reports.py --output ~/Desktop/my-vulnscope-reports.zip
```

## What Gets Included

The export pack automatically includes available files from:

```text
reports/output/target-report.md
reports/output/evidence.json
reports/output/autopilot-environment.json
reports/output/mythic/
reports/output/uplift/
reports/output/ai-discovery/
```

Supported exported formats:

- `.md`
- `.json`
- `.txt`
- `.html`
- `.csv`

## Recommended Workflow

```bash
python3 vulnscope.py --url https://example.com --mode passive --max-pages 5
python3 ai_discovery_cli.py --input reports/output/evidence.json
python3 mythic_hunter_cli.py --input reports/output/evidence.json --depth DEEP_HUNTER_MODE
python3 mythic_uplift_cli.py --input reports/output/evidence.json
python3 export_reports.py --open-folder
```
