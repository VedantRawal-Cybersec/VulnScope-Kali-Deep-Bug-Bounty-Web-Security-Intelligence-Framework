# VulnScope Agent Core

The Agent Core is a CAI-inspired orchestration layer for safe, evidence-first assessment workflows.

It adds:

- agent registry
- structured task model
- activity logging
- human approval gate
- safe tool router
- model router
- workflow memory
- specialist review orchestration

## Files

```text
agent_core/
├── __init__.py
├── activity_log.py
├── agent_registry.py
├── controller.py
├── human_gate.py
├── model_router.py
├── task_model.py
├── tool_router.py
└── workflow_memory.py
```

## Run with Hunt Workflow

```bash
python3 hunt.py --target https://example.com --mode bounty --agent-core
```

Non-interactive scope confirmation:

```bash
python3 hunt.py --target https://example.com --mode bounty --agent-core --yes
```

Dry run optional external stages:

```bash
python3 hunt.py --target https://example.com --mode comprehensive --agent-core --dry-run --yes
```

## Outputs

```text
reports/output/agent_core/activity.jsonl
reports/output/agent_core/agent-registry.md
reports/output/agent_core/agent-core-summary.json
reports/output/agent_core/specialist-results/
reports/output/agent_core/workflow-memory.json
```

## Agent Core Policy

The Agent Core is designed for authorized assets only.

It produces:

- review candidates
- evidence references
- validation tasks
- next recommended safe actions
- reportability context

It does not turn observations into confirmed vulnerabilities without evidence and manual validation.

## Recommended Command

```bash
python3 hunt.py --target https://example.com --mode bounty --agent-core --yes
```

For deeper local review:

```bash
python3 hunt.py --target https://example.com --mode comprehensive --agent-core --yes
```
