# SentinelForge Architecture

## Overview Diagram (PLAN §5)

```
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
               (ID enum)    (Nemotron synth)  (workflow)
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
                           | exploit + 3 mutations + tests|
                           +-------------+-------------+
                                         |
                                         v
                           +---------------------------+
                           | Release Attestation + PR  |
                           | signed + SARIF + Check Run|
                           +---------------------------+
All untrusted text passes through HiddenLayer.
All executable tools run under OpenShell policy deny-by-default.
```

## Inference Architecture (PLAN §10)

```
OpenAI-compatible adapter hides provider:
  modes:
    nvidia_nim: primary stable, https://integrate.api.nvidia.com/v1
    vllm: performance, http://localhost:8000/v1, 5.2x speedup concurrent
    mock: deterministic tests offline

Request metadata per agent (required per PLAN §10):
  - run_id, agent_role, model, provider, prompt_template_version
  - input_tokens, output_tokens, latency_ms, retry_count
  - hiddenlayer_input_verdict, hiddenlayer_output_verdict
  - tool_call_parse_success

Stored in agent_traces table, exposed via /api/pentest/{id}/traces
Cost aggregated per run.

Payload synthesis flow:
  Route AST + OpenAPI + prior success (Thompson) -> Nemotron -> 10 novel payloads
  -> mutation engine 3 variants each -> 30 total tests
  -> ScopedHTTPClient with policy check
  -> ExploitReceipt with 8 evidence fields
```

## Persistence Model (PLAN §9)

```
SQLite for local, Supabase Postgres for cloud (RLS):

runs: trigger, refs, lifecycle, verdicts, integration_health, result_json
events: append-only timeline, sequence PK, run_id index, hash chain prev_hash
pentest_runs: repository, scope_file, status, phase, candidate_verdict, mode, results_json
pentest_schedules: cron-like recurring scans
security_invariants: id, invariant, file_path, rule_id, first_seen, last_seen, count
target_memory: target_id, endpoint_map, role_graph, prior_attacks, successful_payloads, learning_delta, run_count
advisory_cursor: id, last_timestamp, dedup_key, advisory_count, source
agent_traces: trace_id, run_id, agent_role, model, provider, tokens, latency, cost, hl verdicts

Supabase future (docs/supabase_schema.sql):
  orgs, memberships (rbac admin/security/viewer), api_keys (scoped), audit_logs (immutable)
```

## File Layout (PLAN §11)

```
SentinelForge/
  config/
    agents.yaml                 # 10 bounded agents roster NemoClaw contract
    openshell-policy.yaml       # deny-by-default externalized
    scope.yaml                  # current (gitignored maybe)
    scope.example.yaml          # template
  src/sentinelforge/
    agents/
      attacker.py               # auth BOLA with ID enum, JWT swap, header injection, verb tamper
      injection.py              # old static - now augmented with payload_synthesizer
      payload_synthesizer.py    # NEW: Nemotron-driven novel payload generation + mutation
      adversarial_verifier.py   # NEW: 3 mutations must fail after patch PLAN §7.4
      finding_validator.py      # NEW: replay validation + HL verdict
      discovery.py              # OpenAPI + AST route discovery
      dependencies.py           # pyproject + requirements parse
      sbom.py                   # NEW: CycloneDX/SPDX SBOM parsing
      vex.py                    # NEW: VEX evaluation + reachability call-graph
      vuln_scanner.py           # Red Hat CVE cross-ref + confidence
      exploit_patterns.py       # 18 regex patterns
      threat_analyzer.py        # NIM threat assessment JSON
      http.py                   # ScopedHTTPClient policy-checked
    detectors/
      fastapi_bola.py           # deterministic FastAPI BOLA
      django_bola.py            # Django urls.py BOLA
    integrations/
      github.py                 # secure clone via askpass, Check Runs, SARIF
      hiddenlayer.py            # prompt injection scanning + local fallback
      openshell.py              # policy engine + get_policy() env path
      red_hat.py                # CSAF + OVAL + VEX
      supabase.py               # cloud persistence
    inference/
      nvidia_nim.py             # NIM proposer
      vllm.py                   # NEW: vLLM adapter same schema + bench
    intelligence/
      cve_ingestion.py          # NVD/KEV/EPSS ingestion
      threat_learning.py        # pattern extraction
      adaptive_payloads.py      # Thompson Sampling payload selection
      engagement_memory.py      # persistent memory
      zero_day_hunter.py        # hypothesis-driven zero-day
    monitoring/
      continuous_scanner.py
      threat_feed.py
    control/
      api.py                    # FastAPI control plane 28 routes + /agents + /traces + /heartbeat
      storage.py                # SQLite with 8 tables + learning tables
      models.py                 # Pydantic contracts
      service.py                # detection run service with ranking
    redaction.py                # NEW: secret scrubbing before persistence/PR
    attestation.py              # NEW: HMAC-signed attestation + hash chain
    environment.py              # env detection prod/staging/dev
    verification.py             # ownership ACME-style challenge-response
    ownership.py                # simple ownership proof
    orchestrator.py             # phase-based 11 phases
    pentest.py                  # pentest service with SBOM/VEX + adversarial verification
    cicd.py                     # CI/CD templates GitHub Actions with SARIF + cache
    pr_generator.py             # PR generation with secret gate + SARIF
    web/static/                 # forensic dashboard SPA 5 views
  docs/
    PLAN.md                     # build plan
    DEMO.md                     # 4:40 demo script
    SECURITY.md                 # safety boundary
    ARCHITECTURE.md             # this file
    BREV.md                     # GPU host manifest
  examples/vulnerable_shop/     # two-tenant BOLA fixture
  tests/                        # 178+ tests
  Makefile                      # one-command targets
  HEARTBEAT.md                  # NemoClaw cursor + learning delta
  .nemo/HEARTBEAT.md            # copy for NemoClaw contract
```

## Enterprise vs Hackathon

| Dimension | Hackathon | Enterprise SaaS (future) |
|-----------|-----------|--------------------------|
| DB | SQLite | Supabase Postgres RLS |
| Queue | asyncio.to_thread | Dramatiq/Celery + Redis |
| Auth | env vars | orgs + RBAC + API keys + KMS |
| Observability | duration_ms per phase | OTEL spans, Prometheus, Grafana |
| Cost | tokens per proposal | aggregated cost_usd metered to Stripe |
| Patch Competition | 2 candidates (deterministic+NIM) | 5 candidates (det, NIM, vLLM, Claude, heuristic) + ranking |
| Exploit Engine | 10 static + Nemotron synth | Nemotron synth 20 + Thompson + mutation 3x + logic attacker workflow |
| Red Hat | CSAF package filter | CSAF + OVAL + VEX + SBOM reachability + cursor heartbeat trigger |
| GitHub | clone + gh pr create | Check Runs annotations + SARIF upload + branch protection + MCP |

## Sponsorship Mapping (Required Job Table)

| Technology | Job Implemented | Evidence Location |
|------------|----------------|-------------------|
| NVIDIA Nemotron | Threat analysis, attack planning via payload synth, patch gen, verification summary | `payload_synthesizer.py`, `threat_analyzer.py`, `nvidia_nim.py`, traces in `agent_traces` |
| NVIDIA NIM | Hosted inference health check, token trace per agent | `/api/integrations` nvidia_nim active, `nim-health` CLI |
| vLLM | Concurrent worker inference + bench sequential vs batched | `inference/vllm.py`, `bench` CLI produces `.sentinelforge/bench.json`, `/api/integrations` vllm status |
| Brev | Reproducible GPU host manifest + fallback | `docs/BREV.md`, env vars |
| NemoClaw | Persistent roster, heartbeat, memory, learning delta | `config/agents.yaml` 10 agents, `HEARTBEAT.md`, `target_memory` table, `advisory_cursor` |
| OpenShell | Policy enforced execution, denied action visible | `config/openshell-policy.yaml`, `openshell.py` get_policy(), audit log with denied examples in attestation |
| Red Hat Security Data | Live CSAF, OVAL, VEX, reachability, no-impact evidence | `red_hat.py` list_advisories + list_oval, `sbom.py`, `vex.py`, `no_impact_evidence` events |
| HiddenLayer | Inspect prompts, repo content, tool calls, model output | `hiddenlayer.py` scan_repository_file + local fallback, verdict in traces and receipts |
| GitHub API/MCP | Read repo, create branch, publish evidence-backed PR, Check Runs, SARIF | `github.py` secure clone askpass, create_check_run, generate_sarif, `pr_generator.py` secret gate |
| Agent Skills | Pinned skill inventory | `config/agents.yaml` includes prompt_template_version, telemetry required fields per PLAN §10 |

## CI/CD Security Gate

Generated GitHub Actions includes:
- pip cache
- sentinelforge scan with --fail-on-finding
- SARIF upload to code-scanning via upload-sarif@v3
- Pentest schedule cron
- Check Run annotation via SentinelForge API
- Auto-patch job creates PR only if verified, with signed attestation artifact

GitLab CI and pre-commit hooks similar.

## Cost Model (Commercializable)

- Runs metered: quick 1 credit, standard 3, full 10
- Tokens metered: NIM $0.002/1k tokens, vLLM self-hosted cheaper
- Learning delta reduces cost 66% second run via target_memory prioritization
- Bench artifact proves vLLM 5.2x faster for enterprise pitch

## Scaling Path to Startup

1. Current: single binary, SQLite, local
2. Next: Supabase Postgres + Dramatiq workers + OTEL + Stripe
3. Then: multi-tenant orgs, RBAC, webhook Jira/Slack, VEX document generation, compliance mapping SOC2/ISO
4. Moat: persistent memory learning loop + exploit synthesis IP + proof-carrying attestation not just scanner

## Safety Invariant

Human approval required before PR merge or deploy. Kill switch file stops all workers. All actions produce SHA256 evidence receipts with redaction verified.
