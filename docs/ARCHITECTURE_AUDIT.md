# VulnScope Architecture Audit

## What is currently holding the tool back

### 1. Default workflow is overloaded

`main.py` launches `vulnscope.py`, and the launcher can run multiple pipelines in sequence:

1. Safe CAI ReAct autonomous engine
2. Optional 100-tool orchestrator
3. Optional legacy ReAct loop

This makes the tool slower and less predictable. The main workflow should be a single autonomous path. Legacy modules should be opt-in.

### 2. Parameter scheduler can repeat the same input

The ReAct loop can choose `reflection_canary` for a parameter, but the parameter remains queued unless classification also completes. This allows the same parameter to be selected repeatedly instead of progressing through a testing ladder.

Required fix: every parameter needs an explicit safe test plan and progress state.

### 3. LLM calls are too frequent and too slow

The current planner may call the LLM every ReAct turn with a large state payload and a 20-second timeout. On large scopes this can make the tool feel worse after adding Ollama.

Required fix: make the deterministic scheduler own progress, while the LLM is used periodically for prioritization and interpretation.

### 4. LLM is advisory, not operationally useful enough

The LLM proposes actions, but the real advancement depends on deterministic fallback. This is safe, but the model needs better compact context and less noisy state.

Required fix: send the LLM only the next action candidates, recent evidence, coverage deltas, and decision constraints.

### 5. Too many files/modules are not the same as autonomy

The tool already has many modules. More modules can worsen the system if they are not connected to a central state machine. Autonomy requires:

- a single state source,
- a single scheduler,
- clear stop conditions,
- explicit parameter test plans,
- evidence validation,
- consistent dashboard telemetry.

## First remediation batch

This batch focuses on:

- making legacy modules opt-in,
- fixing parameter test progression,
- reducing LLM latency impact,
- preserving the safe CAI ReAct engine as the only default path.
