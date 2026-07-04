# AI Registry Repair

Older VulnScope builds could register many GitHub tools as installed and approved even when they did not have verified manifests, safe run templates, phase classification, or help-probe evidence. This creates fake-ready tools.

Use AI Registry Repair to re-analyze and repair the existing registry.

## Conservative repair

This rewrites manifests, corrects phase/safety metadata, deduplicates entries, and downgrades uncertain tools to manual review. It does not auto-approve runs.

```bash
python3 vulnscope.py --ai-repair-tools
```

## Approve safe tools during repair

Use only after reviewing the generated output. This approves passive and safe-active tools after repair. Lab-only, blocked, and uncertain tools remain unapproved.

```bash
python3 vulnscope.py --ai-repair-tools --ai-repair-approve-safe-run
```

## Limit repair for testing

```bash
python3 vulnscope.py --ai-repair-tools --ai-repair-limit 5
```

## Output

```text
logs/tool_analysis/registry_repair_summary.json
tools/<owner>__<repo>/manifest.json
tools/registry.json
```

## Status meanings

- `READY`: safe passive/safe-active tool with manifest and run approval.
- `REGISTERED_REQUIRES_APPROVAL`: configured but run approval is still required.
- `NEEDS_MANUAL_REVIEW`: repo could not be safely configured automatically.
- `BLOCKED`: blocked behavior indicators were found.

## Why this exists

If `python3 vulnscope.py --list-tools` shows every unknown repo as `phase: discovery`, `installed: true`, and `approved_run: true`, the registry was created by the old heuristic installer. Run repair before trusting the tool matrix.
