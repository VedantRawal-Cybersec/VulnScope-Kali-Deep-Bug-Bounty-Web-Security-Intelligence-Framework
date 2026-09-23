# Master Orchestration Loop

## Cycle

1. Load program rules and scope.
2. Load active sessions by opaque reference.
3. Read target summary.
4. Read coverage gaps.
5. Read active jobs.
6. Read recent observations.
7. Read relevant intelligence for detected technologies.
8. Rank unexplored boundaries.
9. Allocate short-lived specialists.
10. Collect outputs.
11. Store facts/inferences/unknowns separately.
12. Update graph.
13. Store negative knowledge.
14. Queue suspicious behavior for clean-room validation.
15. Reallocate compute.
16. Repeat.

## Priority model

Conceptual score:

priority =
  security_importance
  * unexplored_coverage
  * novelty
  * target_relevance
  * evidence_signal
  / (estimated_cost * duplication_probability)

## Dynamic allocation

Discovery-heavy target:
- more cartographers/API/JS agents

Mapped target:
- more authorization/workflow/differential agents

Candidate-heavy target:
- more validators/skeptics/evidence agents

## Stop conditions

Never stop because "no bugs found".

Stop only when:
- configured time/request budget is exhausted, or
- user stops the run, or
- explicit coverage threshold and required workflow/state coverage are reached.

Always return remaining unknowns.