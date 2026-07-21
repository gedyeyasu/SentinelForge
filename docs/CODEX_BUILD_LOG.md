# Codex build log

This file distinguishes the work completed during the OpenAI Build Week submission
period and gives judges a short path to inspect it.

## Required Codex session

**`/feedback` Session ID:** `ADD_BEFORE_SUBMISSION`

Run `/feedback` in the Codex task where the majority of the core project functionality
was implemented. Paste the identifier here and in the Devpost form. Do not substitute a
Git commit identifier for the Codex session identifier.

## Timeline evidence

The submission period began July 13, 2026 at 9:00 AM Pacific Time. The repository's
first commit is dated July 17, 2026, so the implementation history is inside the
submission period.

```bash
git log --reverse --format='%h %ad %s' --date=iso-strict
```

Representative commits:

| Date | Commit | Contribution |
|---|---|---|
| July 17 | `3e0591c` | Product and build plan |
| July 17 | `74b6730` | Proof-carrying detection and remediation core |
| July 17 | `66df8c0` | Persisted control plane |
| July 17 | `4c415da` | Browser dashboard |
| July 18 | `c25a02f` | Deployment hardening and target boundaries |
| July 18 | `57e79ed` | Live events and pull request flow |
| July 19 | `9cb69f4` | Hypothesis-driven race-condition testing |
| July 21 | current branch | GPT-5.6 evidence judge and Build Week compliance |

## OpenAI-specific extension

Codex reviewed the existing repository and live Fly.io deployment, then implemented:

- `src/sentinelforge/inference/openai_evidence.py`: GPT-5.6 Responses application
  programming interface adapter with strict structured output.
- `src/sentinelforge/orchestrator.py`: explicit GPT-5.6 evidence-review phase.
- `src/sentinelforge/pentest.py`: redacted evidence transformation, advisory decision,
  event, and model trace.
- `src/sentinelforge/control/api.py`: provider readiness and schedule-route fix found
  during live browser review.
- `src/sentinelforge/web/static/`: visible GPT-5.6 status and decision.
- `tests/test_openai_evidence.py`: request-boundary, parsing, and override-prevention
  tests.
- Root README, license, agent guidance, demo script, and submission documentation.

## Key decisions made with Codex

1. GPT-5.6 reviews evidence rather than detecting vulnerabilities. This gives it a
   reasoning-heavy job without making a model its own safety judge.
2. Model output is advisory. Tests and policies can block; only a person can approve
   merge or deployment.
3. The model receives a short allowlisted evidence object, not raw repository content.
4. The OpenAI stage is explicit when unavailable. The product never fabricates a
   provider success.
5. The project is described as hypothesis-driven discovery, not guaranteed zero-day
   detection.

## Verification evidence

Final local verification on July 21, 2026:

```text
pytest: 283 passing, 7 warnings
ruff: all checks passed across src and tests
browser review: gstack core loop passed; no console errors; responsive layouts checked
deployment: public default branch and Fly.io release (see public Git history for the deployed SHA)
```
