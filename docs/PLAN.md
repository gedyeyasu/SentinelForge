<!-- /autoplan restore point: /Users/gedeoneyasu/.gstack/projects/gedyeyasu-SentinelForge/main-autoplan-restore-20260717-195000.md -->
# SentinelForge Implementation Plan

Status: APPROVED PREMISES — IMPLEMENTATION IN PROGRESS
Hackathon: AITX Community x NVIDIA Claw Agent Hackathon
Deadline: July 19, 2026, 11:00 AM America/Chicago
Primary track: Red Hat Live Data
Target bounties: Best NemoClaw + OpenShell, Best Nemotron, Best vLLM, Most Commercializable

## 1. Product Definition

SentinelForge is an autonomous adversarial release gate for teams shipping AI-generated code faster than human security teams can review it.

For every release candidate, SentinelForge creates or targets an authorized staging environment, maps the changed attack surface, dispatches specialized red-team agents, validates any suspected vulnerability with replayable evidence, generates competing patches, attacks the patches again, runs the existing test suite, and produces a review-ready pull request plus a release security attestation.

The product does not claim that an application is secure or that it can discover every zero-day. It proves which attack paths were attempted, which exploits succeeded, which remediations were verified, and what residual risk remains.

## 2. Users and Jobs

Primary users:

- Engineering teams shipping frequent AI-assisted changes.
- Security engineers who currently review release cuts and assign remediation tickets.
- Startups and smaller companies without enough dedicated security capacity.
- Platform teams that need a governed first line of defense before human review.

Jobs to be done:

1. Attack every authorized release candidate before production.
2. Prioritize real exploitability over scanner noise.
3. Turn successful exploits into permanent regression tests.
4. Produce minimal patches with before-and-after evidence.
5. Preserve a human approval gate for merging and production deployment.
6. Learn organization-specific authentication flows, invariants, and historical failures.

## 3. Demo Definition

The three-to-five-minute demo will run against an authorized staging API and a controlled branch of the owner's product repository.

Primary scenario:

1. A release event or manual demo trigger starts a run.
2. SentinelForge compares the release candidate with the last trusted baseline.
3. It detects a new or changed API endpoint.
4. Two synthetic tenants and users exercise the endpoint.
5. A red-team agent demonstrates a cross-tenant authorization flaw or another seeded realistic vulnerability.
6. SentinelForge stores a replayable exploit receipt.
7. Patch agents generate competing fixes.
8. The verifier reruns the original exploit, mutated attacks, and the repository's existing tests.
9. SentinelForge creates a review-ready branch or PR containing the patch, permanent regression test, and security receipt.
10. The dashboard shows vulnerable-before and blocked-after evidence in real time.

Secondary scenario:

1. A NemoClaw heartbeat reads fresh Red Hat CVE or CSAF data.
2. The intelligence agent matches an advisory to the target repository's dependency inventory.
3. A reachable finding triggers safe reproduction, remediation, retesting, and an updated attestation.

## 4. Sponsor Technology Contract

Every integration below must perform a visible, testable job. No logo-only integrations are accepted.

| Technology | Required job | Demo evidence |
|---|---|---|
| NVIDIA Nemotron | Threat analysis, attack planning, patch generation, verification summaries | Model and token trace per agent |
| NVIDIA NIM | Stable hosted Nemotron inference using event credentials | Successful hosted inference health check |
| vLLM | Concurrent Nemotron worker inference and performance comparison | Sequential vs batched latency chart |
| NVIDIA Brev | Reproducible GPU host for vLLM when available | Environment manifest and health check |
| NemoClaw | Persistent orchestrator, heartbeat, fixed multi-agent roster | `HEARTBEAT.md`, `agents.yaml`, live run |
| OpenShell | Policy-enforced execution and attack containment | Policy file plus denied out-of-scope action |
| Red Hat Security Data API | Live CVE, CSAF, and OVAL intelligence | Fresh advisory event in run timeline |
| HiddenLayer | Inspect untrusted prompts, repository content, tool calls, and model output | Quarantined prompt-injection attempt |
| GitHub API or MCP | Read repository, create branch, publish evidence-backed PR | Controlled PR or dry-run PR artifact |
| NVIDIA Agent Skills | Official setup knowledge for NemoClaw and OpenShell | Pinned skill inventory in build docs |

Featherless is optional after the core loop works. It may provide an independent challenger model for evaluation, but it must not displace Nemotron as the central model or add demo risk.

## 5. System Architecture

```text
                      RELEASE EVENT / HEARTBEAT
                                 |
                                 v
                    +-------------------------+
                    | NemoClaw Orchestrator   |
                    | run state + memory      |
                    +------------+------------+
                                 |
                  +--------------+---------------+
                  |                              |
                  v                              v
        +--------------------+       +------------------------+
        | Release Diff Mapper|       | Threat Intel Watcher   |
        | repo + OpenAPI/SBOM|       | Red Hat CVE/CSAF/OVAL  |
        +----------+---------+       +-----------+------------+
                   |                             |
                   +--------------+--------------+
                                  v
                       +-----------------------+
                       | Attack Plan + Scope   |
                       | signed scope contract |
                       +-----------+-----------+
                                   |
                                   v
                    +-----------------------------+
                    | OpenShell Security Twin     |
                    | staging target + test users |
                    +--------------+--------------+
                                   |
                  +----------------+----------------+
                  |                |                |
                  v                v                v
             Auth Agent      Injection Agent   Logic Agent
                  |                |                |
                  +----------------+----------------+
                                   v
                         +-------------------+
                         | Finding Validator |
                         | replayable proof  |
                         +---------+---------+
                                   |
                      no finding --+-- confirmed finding
                                           |
                                           v
                          +-----------------------------+
                          | Parallel Patch Candidates   |
                          | Nemotron via NIM or vLLM    |
                          +--------------+--------------+
                                         |
                                         v
                           +---------------------------+
                           | Adversarial Verifier      |
                           | exploit + mutation + tests|
                           +-------------+-------------+
                                         |
                                         v
                           +---------------------------+
                           | Release Attestation + PR  |
                           +---------------------------+

All untrusted text and model interactions pass through HiddenLayer.
All executable tools run under an OpenShell policy with default-deny networking.
```

## 6. Agent Roster

The checked-in `agents.yaml` will define the following bounded roles:

| Agent | Inputs | Allowed tools | Output |
|---|---|---|---|
| `main` | Trigger, scope, policy, run state | Read, delegate, status writes | Run orchestration |
| `surface_mapper` | Git diff, routes, OpenAPI, SBOM | Read-only repo tools | Changed attack-surface map |
| `auth_attacker` | Endpoints, two test identities | Scoped HTTP client | Auth and tenant attack attempts |
| `injection_attacker` | Input-bearing endpoints | Scoped HTTP client | Injection attack attempts |
| `logic_attacker` | Business workflow graph | Scoped HTTP client | Multi-step abuse attempts |
| `dependency_hunter` | SBOM and advisories | Red Hat API, repo read | Reachability hypothesis |
| `finding_validator` | Candidate evidence | Replay runner | Confirmed or rejected finding |
| `patch_engineer` | Confirmed finding and repo | Temporary worktree write | Patch candidate plus test |
| `adversarial_verifier` | Patch candidates | Test and scoped attack tools | Ranked validation results |
| `release_auditor` | Complete event log | Read-only | Signed-style JSON attestation and PR body |

Spawn depth is limited to two. Only `main` may spawn worker agents. Attack agents cannot write repository files. Patch agents cannot access staging credentials. No agent can merge a PR.

## 7. Core Runtime Flow

### 7.1 Trigger

Accepted triggers:

- `POST /api/runs` from the demo dashboard.
- GitHub pull-request or release webhook after repository integration.
- NemoClaw heartbeat when a relevant advisory changes.

Every trigger is normalized into:

```json
{
  "trigger_type": "manual|pull_request|release|heartbeat",
  "repository": "owner/name",
  "baseline_ref": "main",
  "candidate_ref": "branch-or-sha",
  "target_id": "configured-staging-target",
  "requested_at": "RFC3339 timestamp"
}
```

### 7.2 Authorization and Scope Contract

No run starts without a checked-in or operator-approved scope:

```yaml
target:
  base_url: ${STAGING_BASE_URL}
  ownership_verified: true
allowed_hosts:
  - ${STAGING_HOST}
allowed_methods: [GET, POST, PUT, PATCH, DELETE]
forbidden_paths: []
max_requests_per_second: 3
max_total_requests: 300
allow_destructive_payloads: false
allow_denial_of_service: false
allow_persistence: false
allow_data_exfiltration: false
test_identities:
  - tenant_a_user
  - tenant_b_user
kill_switch_file: /run/sentinelforge/STOP
```

DELETE is disabled by default at runtime unless an endpoint-specific policy explicitly allows deletion of synthetic records. Production hosts and private address ranges outside the security twin are denied.

### 7.3 Evidence Standard

A finding is confirmed only when all are present:

1. Exact target and endpoint.
2. Preconditions and synthetic identity used.
3. Sanitized request and response transcript.
4. Expected security invariant.
5. Observed violation.
6. Replay command executable only inside the authorized sandbox.
7. Confidence and severity rationale.
8. HiddenLayer verdict for all untrusted content involved.

### 7.4 Patch Standard

A candidate patch is eligible only when:

1. The original exploit fails after the change.
2. At least three safe mutations of the exploit also fail.
3. The repository's existing tests pass.
4. A permanent regression test is added.
5. Static and dependency scans do not regress.
6. The diff is limited to the smallest safe blast radius.
7. Residual risk and unverifiable assumptions are disclosed.

## 8. State Model

```text
QUEUED
  -> SCOPING
  -> MAPPING
  -> ATTACKING
  -> NO_FINDING -> ATTESTED
  -> FINDING_CANDIDATE
       -> REJECTED_FALSE_POSITIVE -> ATTACKING
       -> CONFIRMED
            -> PATCHING
            -> VERIFYING
                 -> PATCH_REJECTED -> PATCHING
                 -> PATCH_VERIFIED
                      -> PR_PREPARED
                      -> ATTESTED

Any state -> CANCELLED when kill switch is set.
Any state -> FAILED with an actionable error receipt.
```

Run transitions are append-only events. The current state is derived from the event stream so the dashboard can replay the complete run.

## 9. Persistence and Learning

Initial storage is SQLite for fast local development and deterministic demo setup.

Core entities:

- `runs`: trigger, refs, target, state, timestamps, cost.
- `events`: append-only timeline with agent, tool, decision, and redacted payload reference.
- `findings`: invariant, evidence, severity, status.
- `patch_candidates`: diff reference, tests, score, rejection reason.
- `security_invariants`: permanent executable protections learned from findings.
- `target_memory`: endpoint map, login workflow, role graph, prior attacks.
- `advisory_cursor`: last Red Hat feed timestamp and deduplication key.

Learning means persistent retrieval and measurable improvement, not autonomous model-weight training. The demo will compare the first and second run for authentication discovery time, attack coverage, tool calls, and inference cost.

## 10. Inference Architecture

An OpenAI-compatible inference adapter hides the provider from agent logic.

Modes:

- `nvidia_nim`: primary stable mode using the hackathon NVIDIA API key.
- `vllm`: performance mode using a Nemotron model hosted on Brev or supported local NVIDIA hardware.
- `mock`: deterministic tests and offline development only.

Required request metadata:

- Run ID and agent role.
- Model and provider.
- Prompt-template version.
- Input and output token counts.
- Latency and retry count.
- HiddenLayer input and output verdicts.
- Tool-call parse success.

API keys are environment variables and must never appear in repository files, logs, prompts, evidence, or PR bodies.

## 11. Initial Repository Layout

```text
SentinelForge/
  README.md
  pyproject.toml
  .env.example
  .gitignore
  Makefile
  docs/
    PLAN.md
    DEMO.md
    SECURITY.md
  config/
    agents.yaml
    scope.example.yaml
    openshell-policy.yaml
  sentinelforge/
    api/
    orchestration/
    agents/
    inference/
    integrations/
    policies/
    evidence/
    storage/
  dashboard/
  tests/
    unit/
    integration/
    e2e/
    evals/
  fixtures/
    vulnerable_api/
  scripts/
```

The implementation language is Python 3.12. FastAPI provides the control-plane API and server-sent events for the live run timeline. Pydantic provides explicit contracts. SQLAlchemy and SQLite provide persistence. The dashboard should remain thin and consume the API rather than duplicating orchestration logic.

## 12. Implementation Lakes

### Lake 1: Deterministic detection and evidence

- Initialize the Python project, linting, tests, and configuration.
- Implement a narrow explainable FastAPI BOLA detector.
- Derive a tenant-authorization invariant from the actual route and object load.
- Emit a stable finding ID, confidence, evidence, and remediation contract.
- Provide a controlled two-tenant vulnerable fixture.

Exit test: the detector finds the missing tenant check, produces no finding when an explicit check exists, and never modifies the source repository.

### Lake 2: Isolated patch and verification

- Copy the target into an isolated run workspace.
- Create a minimal authorization patch and permanent regression test.
- Produce a content-addressed unified-diff bundle.
- Run the generated security test and existing repository tests.
- Retain exact verification output and patch digest.

Exit test: the original fixture remains vulnerable and unchanged, while the isolated patched copy passes both cross-tenant denial and normal behavior tests.

### Lake 3: Runnable control plane

- Implement typed run and append-only event models.
- Implement `POST /api/runs`, `GET /api/runs/{id}`, and event streaming.
- Add deterministic mock inference and policy adapters.
- Add a minimal verdict dashboard timeline.

Exit test: a detection-and-remediation run moves through every state and renders live evidence.

### Lake 4: Governed active pentesting

- Parse and validate `scope.yaml`.
- Enforce host, method, path, request-count, and rate limits.
- Add kill-switch support and an OpenShell adapter.
- Map OpenAPI or observed routes and load two synthetic identities.
- Implement the authorization attacker first.
- Validate and persist a replayable exploit receipt.
- Replay the exploit and bounded mutations against candidate and patch.

Exit test: the controlled vulnerable fixture is exploited, the receipt is replayable, the same attack is blocked by the verified patch, and no request can leave the approved target.

### Lake 5: Model-assisted patch competition

- Generate one patch candidate through Nemotron, retaining the deterministic patch as the baseline.
- Apply candidates independently.
- Run exploit, mutations, and existing tests.
- Rank candidates and retain rejection reasons.

Exit test: the vulnerable fixture fails before the patch and passes after the selected patch.

### Lake 6: Sponsor integrations

- Connect NVIDIA NIM and record model telemetry.
- Check in NemoClaw heartbeat and agent manifest.
- Connect Red Hat Security Data API with a persistent cursor.
- Integrate HiddenLayer input and output checks.
- Run Nemotron through vLLM on Brev and benchmark concurrency.

Exit test: each sponsor integration has a visible health check and appears in one complete run trace.

### Lake 7: GitHub and product target

- Add GitHub App, token, or MCP adapter with least privilege.
- Read the controlled product branch and create a temporary patch branch.
- Prepare or open a PR only after explicit approval.
- Configure the authorized staging API and synthetic accounts.
- Run the complete flow against the owner's product.

Exit test: a controlled product vulnerability produces an evidence-backed PR without touching production.

### Lake 8: Demo reliability

- Seed a realistic vulnerability in a controlled demo branch.
- Add a one-command reset.
- Cache models and dependencies.
- Add NIM fallback for vLLM failure.
- Add prerecorded evidence only as emergency backup, never as the primary demo.
- Rehearse the complete flow at least five times.

Exit test: five consecutive runs finish inside the target time without manual repair.

## 13. Test Strategy

| Layer | Coverage |
|---|---|
| Unit | Scope validation, state transitions, evidence redaction, ranking, feed dedupe |
| Integration | Red Hat adapter, inference adapter, HiddenLayer adapter, SQLite event stream |
| Security integration | Host allowlist, rate limit, kill switch, secret redaction, tool denial |
| End-to-end | Trigger to exploit to patch to verified PR artifact |
| Model eval | Attack-plan validity, false-positive rejection, patch correctness, report fidelity |
| Performance | Sequential vs batched vLLM workers, total run latency and cost |

Critical deterministic cases:

1. Out-of-scope host is blocked before DNS or HTTP execution.
2. Production-looking host is rejected even when supplied by model output.
3. Malicious repository instructions are quarantined by HiddenLayer.
4. Invalid model tool calls cannot execute.
5. Kill switch stops pending workers and prevents new requests.
6. Duplicate heartbeat advisory does not create duplicate runs.
7. Candidate patch that breaks existing tests is rejected.
8. Finding without replayable evidence is labeled unconfirmed and cannot generate a PR.
9. Secrets are absent from persisted events and generated PR content.
10. Restarting the control plane reconstructs active run state from events.

## 14. Acceptance Criteria

### P0 — detection and patching must pass

1. A controlled FastAPI authorization defect is detected from source structure without a model declaring the verdict.
2. The finding contains a stable ID, invariant, precise location, structured evidence, confidence, and remediation contract.
3. The source repository remains unchanged; all edits occur in an isolated run workspace.
4. The patch adds an ownership check and a permanent cross-tenant regression test.
5. The patched copy no longer triggers the detector and passes the generated security test plus existing tests.
6. A content-addressed patch bundle and exact verification report are produced.

### P1 — active pentesting must pass after P0

1. A manual or release trigger starts a visible multi-step run.
2. The run uses at least three specialized agents with distinct bounded tools.
3. Every executable attack is confined by the active policy adapter; OpenShell is the sponsored implementation.
4. A blocked out-of-scope action is visible in the demo.
5. A controlled vulnerability is exploited with independently replayable evidence.
6. The same receipt succeeds against the candidate and is blocked against the exact patched artifact.
7. The system produces an evidence-backed local PR payload awaiting human approval.

### P2 — sponsor showcase

1. Nemotron is the central model and every inference is traceable.
2. HiddenLayer checks untrusted input and output and blocks a demonstrated injection attempt.
3. A real Red Hat advisory changes an attack hypothesis or creates explicit no-impact evidence.
4. NemoClaw exposes the fixed roster and heartbeat; OpenShell proves containment.
5. vLLM/Brev demonstrates measured concurrent inference without becoming a demo dependency.
6. Five consecutive rehearsals complete without manual repair.

## 15. Demo Timeline

```text
0:00  Problem: AI code velocity exceeds security review capacity.
0:20  Show release candidate and new API change.
0:40  Trigger SentinelForge.
0:55  Show NemoClaw agent roster and OpenShell scope.
1:10  Red agents attack the staging API in parallel.
1:45  Show successful cross-tenant exploit and sanitized evidence.
2:05  Show a malicious instruction blocked by HiddenLayer.
2:20  Patch agents generate competing fixes with Nemotron.
2:50  Verifier rejects one candidate and accepts another.
3:20  Show before/after exploit result and passing repository tests.
3:45  Show the generated regression test and PR receipt.
4:15  Show heartbeat advisory trigger and persistent-learning delta.
4:40  Close with cost, commercial value, and human approval boundary.
```

## 16. Forty-Eight-Hour Schedule

### Hours 0-6

- Repository, plan, Python skeleton, test stack.
- Control-plane run state and live event stream.
- Minimal dashboard.
- Deterministic fixture and mock run.

### Hours 6-14

- Scope contract and HTTP safety layer.
- OpenShell setup and policy.
- Authorization attack agent and replay evidence.

### Hours 14-24

- NIM/Nemotron integration.
- Patch candidate generation.
- Worktree-based verification and regression-test generation.

### Hours 24-32

- NemoClaw heartbeat and multi-agent manifest.
- Red Hat advisory integration.
- HiddenLayer integration and injection-block demo.

### Hours 32-38

- Brev/vLLM deployment and concurrency benchmark.
- GitHub PR adapter.
- Product repository and staging configuration.

### Hours 38-44

- UI polish, evidence receipt, metrics, error handling.
- Five complete rehearsals and reliability fixes.

### Hours 44-48

- Submission copy, architecture diagram, README, three-to-five-minute video.
- Final live demo rehearsal and emergency fallback preparation.

## 17. Failure Modes and Recovery

| Failure | Detection | Recovery |
|---|---|---|
| NIM quota or outage | Health check and inference error | Switch to cached local vLLM route |
| vLLM model unavailable | Startup timeout | Use hosted NIM and keep benchmark artifact |
| Brev unavailable | Environment health check | Run local/mock mode; preserve NIM demo |
| Staging API unavailable | Preflight request | Use controlled local fixture and disclose |
| Product tests exceed demo time | Timed test discovery | Run security regression plus approved fast suite; full suite asynchronously |
| False-positive exploit | Independent replay fails | Reject finding; no patch or PR |
| Patch breaks behavior | Existing tests fail | Reject candidate and retain reason |
| Model emits unsafe tool call | Policy validation fails | Block, log, and continue with bounded recovery |
| Prompt injection in repo | HiddenLayer flags content | Quarantine content and exclude instruction from context |
| Agent loops | Step and cost budget exceeded | Cancel worker and summarize partial result |
| Secret appears in output | Redaction scan fails | Block persistence and PR creation |

## 18. Not in Scope for the Hackathon

- Production penetration testing.
- Destructive payloads, denial-of-service, persistence, or real data exfiltration.
- General guarantees of zero-day discovery or complete security.
- Automatic merging or production deployment.
- Broad support for every language and framework.
- Enterprise SSO, billing, multi-region operation, and compliance certification.
- Full network and Active Directory penetration testing.
- Autonomous model-weight training.

## 19. Inputs Still Required

- Product repository local path or GitHub URL.
- Authorized staging API base URL and allowed hostnames.
- Confirmation that staging is isolated from production data and services.
- Permission or credentials for two synthetic users or tenants.
- Forbidden endpoints and third-party integrations.
- GitHub permission model for creating a controlled branch and PR.
- NVIDIA, HiddenLayer, and optional Featherless credentials through local environment variables, never chat or committed files.

## 20. Confirmed Premises

Approved by the builder on 2026-07-17.

1. The first complete vertical slice should prioritize API authorization and cross-tenant access because it demonstrates active business-logic exploitation better than dependency scanning alone.
2. The primary demo target will be a controlled branch and authorized staging environment, never production.
3. A seeded realistic vulnerability is acceptable for demo reliability, while discovery mode still searches for genuine issues.
4. Human approval remains required before opening a PR against an external repository, merging, or deploying.
5. Python 3.12, FastAPI, SQLite, and a thin web dashboard are acceptable implementation choices for the 48-hour build.
6. NIM is the stable inference path; vLLM on Brev is the performance path and can fall back without breaking the core demo.
7. The main hackathon track is Red Hat Live Data, with sponsor bounties pursued through the same architecture.

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|---|---|---|---:|---|---|
| Office Hours | `/office-hours` | Product definition and narrow wedge | 3 | complete | Design specification improved from 6.5 to 9.4/10 |
| CEO Review | `/plan-ceo-review` | Scope and strategy | 1 | complete | Narrowed category to proof-carrying release gate; P0/P1/P2 conflict resolved |
| Eng Review | `/plan-eng-review` | Architecture and tests | 0 | pending | Runs against detection/patching implementation |
| Design Review | `/plan-design-review` | Dashboard UX | 0 | pending | Deferred until control-plane UI lake |
| DX Review | `/plan-devex-review` | Setup and integration experience | 0 | pending | Runs after one-command local workflow exists |

**VERDICT:** Premises approved. Detection-and-patching P0 authorized and in progress; active pentesting follows only after P0 passes.

## Decision Audit Trail

| Date | Decision | Reason | Status |
|---|---|---|---|
| 2026-07-17 | Accept all seven premises | Explicit builder approval | locked |
| 2026-07-17 | Position as a proof-carrying release gate, not a general autonomous security team | Creates a falsifiable wedge and avoids unprovable coverage claims | locked |
| 2026-07-17 | Build deterministic vulnerability detection and isolated patch verification before active pentesting | Explicit builder sequencing; creates a trustworthy substrate for later attack agents | locked |
| 2026-07-17 | Keep sponsor services behind typed adapters | Preserves demo reliability and makes the receipt/invariant corpus the durable product asset | locked |

**UNRESOLVED DECISIONS:** None block P0 implementation. Product repository, staging target, and sponsor credentials are required only for later lakes.
