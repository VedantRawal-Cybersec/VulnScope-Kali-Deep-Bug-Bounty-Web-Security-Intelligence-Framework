# VulnScope AI Provider Setup

VulnScope now supports real provider calls through the universal provider layer.

## Supported providers

```text
anthropic / claude
 deepseek
 openai
 groq
 openrouter
 ollama
```

## Important

Do not paste API keys into chat, GitHub, screenshots, reports, or commits. Add them locally only.

## Setup Claude / Anthropic

```bash
python3 ai_provider_cli.py --setup --provider anthropic --model claude-3-5-sonnet-latest
```

This stores the following locally in `.env.local`:

```text
ANTHROPIC_API_KEY=<your-key>
ANTHROPIC_MODEL=claude-3-5-sonnet-latest
```

You can also use the alias:

```bash
python3 ai_provider_cli.py --setup --provider claude --model claude-3-5-sonnet-latest
```

## Setup DeepSeek

```bash
python3 ai_provider_cli.py --setup --provider deepseek --model deepseek-chat
```

This stores:

```text
DEEPSEEK_API_KEY=<your-key>
DEEPSEEK_MODEL=deepseek-chat
```

## Check status

```bash
python3 ai_provider_cli.py --status
```

## Test Claude

```bash
python3 ai_provider_cli.py --test --provider anthropic
```

or:

```bash
python3 ai_provider_cli.py --test --provider claude
```

## Test DeepSeek

```bash
python3 ai_provider_cli.py --test --provider deepseek
```

## Run hunt workflow with Claude

```bash
python3 hunt.py --target https://example.com --mode bounty --agent-core --provider anthropic --yes
```

Alias:

```bash
python3 hunt.py --target https://example.com --mode bounty --agent-core --provider claude --yes
```

## Run hunt workflow with DeepSeek

```bash
python3 hunt.py --target https://example.com --mode bounty --agent-core --provider deepseek --yes
```

## Outputs

```text
reports/output/agent_core/ai-review.md
reports/output/agent_core/agent-core-summary.json
```

## Safety behavior

Before provider calls, VulnScope redacts common secrets from prompts using:

```text
agent_core/prompt_firewall.py
```

Provider keys are read from local environment variables or `.env.local` only. They are never committed by the tool.
