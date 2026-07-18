# SentinelForge

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
