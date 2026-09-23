# Master Orchestration Loop

1. Load program rules and exact scope.
2. Resolve available opaque session references.
3. Read Target Brain summary.
4. Read coverage and unknowns.
5. Read active/recent jobs.
6. Read recent Burp observations.
7. Read relevant current vulnerability intelligence for detected technologies.
8. Rank unexplored trust/security boundaries.
9. Allocate short-lived specialists.
10. Collect structured outputs.
11. Store FACT / INFERENCE / UNKNOWN separately.
12. Update the target graph.
13. Store negative knowledge.
14. Queue unexpected security-relevant behavior for clean-room validation.
15. Reallocate compute as the target model changes.
16. Repeat.

Priority concept:
security_importance * unexplored_coverage * novelty * target_relevance * evidence_signal / (estimated_cost * duplication_probability)

Do not stop because "no bugs found". Stop only on configured budget/user stop/explicit coverage criteria, and always return remaining unknowns.