# SentinelForge

SentinelForge is a proof-carrying release gate for AI-generated API changes. It detects security defects, produces structured evidence, creates a minimal patch in an isolated workspace, adds a permanent regression test, and verifies the resulting candidate before any human-approved repository action.

The current vertical slice detects missing tenant authorization in FastAPI object routes. Active staging pentesting follows after this deterministic detection-and-patching core is complete.

## First vertical slice

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/sentinelforge scan examples/vulnerable_shop
.venv/bin/sentinelforge remediate examples/vulnerable_shop
```

The controlled fixture is deliberately vulnerable and must never be publicly deployed. Remediation happens only in `.sentinelforge/runs/<finding-id>/patched`; SentinelForge does not modify the source repository, push a branch, open a pull request, merge, deploy, or send attack traffic in this phase.

## What the command proves

- The detector derives an authorization invariant from an actual FastAPI route.
- The finding has a stable ID, severity, evidence, confidence, and remediation contract.
- The patch is created outside the source repository and is content-addressed.
- A cross-tenant regression test is generated alongside the patch.
- The patched copy must pass the new security test and the repository's existing tests.

See [the implementation plan](docs/PLAN.md) for the sponsor integration and adversarial-release roadmap.

SentinelForge is an autonomous adversarial release gate for teams shipping AI-generated code faster than human security teams can review it.

For every authorized release candidate, it maps the changed attack surface, dispatches bounded red-team agents, validates exploits with replayable evidence, generates competing patches, attacks the patches again, runs the existing test suite, and produces a review-ready pull request plus a release security attestation.

## Hackathon build

Built for the AITX Community x NVIDIA Claw Agent Hackathon, with the Red Hat Live Data track as the primary track.

Planned integrations:

- NVIDIA Nemotron and NIM for agent reasoning and inference
- NemoClaw for persistent orchestration and heartbeats
- OpenShell for policy-enforced execution sandboxes
- vLLM on NVIDIA Brev for concurrent model serving
- Red Hat Security Data API for live vulnerability intelligence
- HiddenLayer for prompt-injection and model I/O defense
- GitHub for evidence-backed remediation pull requests

The full product, architecture, safety model, demo flow, and 48-hour execution plan are in [docs/PLAN.md](docs/PLAN.md).

## Safety boundary

SentinelForge targets only explicitly authorized staging environments and controlled repositories. The hackathon build excludes production penetration testing, destructive payloads, denial-of-service, persistence, and real data exfiltration. Merging and deployment always require human approval.

## Iteration policy

Every implementation lake must pass its relevant checks before it is committed and pushed. Each iteration should be independently demoable or provide a verified foundation for the next vertical slice.
