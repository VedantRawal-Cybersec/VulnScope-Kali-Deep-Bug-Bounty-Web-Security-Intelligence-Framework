# VulnScope Neural Review Agent

The neural agent adds a human-style loop to VulnScope. It performs a cycle of perceive, observe, plan, act, reflect, and learn.

## Guardrails

- Run only on hosts listed in `agent_config.yaml`.
- The agent checks `robots.txt` and `/.well-known/security.txt` before work.
- The action list is fixed to existing VulnScope modules.
- Memory is stored locally in SQLite.
- A readable thinking log is written for the user.

## Files

- `vulnscope_agent.py` - main agent module.
- `agent_config.yaml` - runtime configuration.
- `agent_config.example.yaml` - example configuration.
- `demo_agent.sh` - quick dry-run demo.

## Run

```bash
python3 vulnscope_agent.py --config agent_config.yaml --dry-run
python3 vulnscope_agent.py --config agent_config.yaml
```

## Ollama mode

Set this in `agent_config.yaml`:

```yaml
model_provider: ollama
model_name: llama3
```

If the local model is unavailable, the agent falls back to the fixed rule sequence.

## Outputs

- `reports/output/neural-agent/thinking-log.md`
- `reports/output/neural-agent/agent-memory.sqlite3`
- `reports/output/neural-agent/agent-state.json`
- `reports/output/neural-agent/agent.log`
- `reports/output/report-v2/executive-report-v2.md`

## Decision cycle

1. Perceive: read target, host list, robots.txt, and security.txt.
2. Observe: inspect current report files and summaries.
3. Plan: choose the next module using the model hint or fixed sequence.
4. Act: run the selected VulnScope command.
5. Reflect: score success or failure and write a plain-English note.
6. Learn: save actions and reflections in SQLite.

## Extending actions

Add a new entry to the `ACTIONS` dictionary in `vulnscope_agent.py`, then add the action name to `ORDER`. Keep actions non-destructive and report-focused.
