# OpenAI Build Week submission notes

## Submission

- **Project:** SentinelForge
- **Team:** SentinelForge / Gedeon Tona
- **Track:** Developer Tools
- **Live application:** https://sentinelforge.fly.dev/
- **Repository:** https://github.com/gedyeyasu/SentinelForge
- **Deadline:** July 21, 2026 at 5:00 PM Pacific Time

## One-sentence description

SentinelForge is an autonomous security release gate that turns an authorized code
change into replayable vulnerability evidence, an isolated tested patch, an independent
GPT-5.6 evidence decision, and a draft pull request that still requires human approval.

## Why this fits Developer Tools

The product is integrated into the developer release workflow. It combines repository
inspection, testing, developer operations, security automation, agent orchestration,
and pull request evidence. A judge can use the deployed browser interface or install the
command line tool and run the bundled synthetic application.

## Judging criteria

### Technological implementation

- The repository contains an ordered multi-phase orchestrator, not a chat wrapper.
- Specialized agents use explicit inputs, tools, outputs, request budgets, and timeouts.
- The GPT-5.6 Responses application programming interface integration uses a strict
  JavaScript Object Notation schema and a bounded redacted prompt.
- A code-level invariant prevents GPT-5.6 from overriding a deterministic block.
- Optional provider failure degrades visibly without changing the security verdict.
- The test suite validates the model boundary, control plane, schedulers, detectors,
  policies, evidence, remediation, and integrations.

### Design

The interface exposes the release as a sequence: Scan, Release Proof, Pentest, Schedule,
and Settings. It displays live phase events, findings, evidence hashes, provider status,
the GPT-5.6 advisory decision, and the human gate.

### Potential impact

Security engineers currently spend time reproducing scanner output, assigning a ticket,
patching it, running tests, and assembling audit evidence. SentinelForge automates the
bounded mechanical work and delivers a review package. The intended production entry
point is a continuous integration and continuous delivery gate before release.

### Quality of the idea

The differentiator is proof rather than another alert feed. Detection, remediation,
verification, model review, attestation, and human approval are one traceable loop. The
model has a useful role but is not trusted to declare its own work safe.

## GPT-5.6 trust boundary

```text
Raw repository and live responses
        │
        ▼
Deterministic validation and redaction
        │
        ▼
Bounded evidence summary
  - counts
  - receipt identifiers
  - SHA-256 hashes
  - policy denials
  - test result summary
  - deterministic verdict
        │
        ▼
GPT-5.6 Responses API
  - strict structured output
  - store=false
  - no tools
  - no source mutation
        │
        ▼
Advisory decision
  - approve_for_human_review
  - block
  - needs_more_evidence
        │
        ▼
Code invariant + signed evidence + human gate
```

## Submission requirement matrix

| Requirement | Evidence |
|---|---|
| Working project | Deployed Fly.io URL and local quick start |
| Developer Tools track | Security release workflow, command line tool, control plane |
| Codex usage | `docs/CODEX_BUILD_LOG.md`, dated commits, `/feedback` session ID |
| GPT-5.6 usage | `inference/openai_evidence.py`, orchestrator phase, tests, interface |
| Public repository | GitHub repository and root `LICENSE` |
| Setup and sample data | Root README and `examples/vulnerable_shop` |
| Supported platforms | Root README |
| Test without rebuilding | Live application and local synthetic fixture |
| Video | Public YouTube link shorter than three minutes, added at submission time |

## Final manual steps

1. Add an OpenAI application programming interface key to the deployment as
   `OPENAI_API_KEY` so the live interface shows the GPT-5.6 judge as ready.
2. Deploy this branch and run one bounded demo flow.
3. Record the script in `docs/YOUTUBE_SCRIPT.md`; upload it to YouTube as public or
   unlisted and verify audio and duration.
4. Run `/feedback` in the Codex task where the majority of the core work was built.
5. Paste the session identifier into Devpost and `docs/CODEX_BUILD_LOG.md`.
6. Replace the placeholders in `docs/SUBMISSION.md`, then submit before the deadline.
