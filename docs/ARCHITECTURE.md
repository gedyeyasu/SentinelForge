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
SentinelForge/ v0.2.0 Latest - 14 NemoClaw agents + GitHub OAuth + Django discovery + Cini live
  config/
    agents.yaml                 # 14 bounded agents roster NemoClaw contract: main, surface_mapper, auth_attacker 7 techniques, injection_attacker 10+10 synthetic, exploit_writer writes new Python file per run PROOF NOT TOY, logic_attacker, dependency_hunter SBOM+VEX, finding_validator, patch_engineer, code_worker works on code, pr_creator creates PR, patch_and_pr full flow, adversarial_verifier 3 mutations, release_auditor signed attestation
    openshell-policy.yaml       # deny-by-default 13 rules including DB nuking DROP TABLE/TRUNCATE/DELETE without WHERE, rm -rf
    openshell-policy-cini.yaml  # allows api.cini.love for live Cini demo, blocks DELETE for safety
    scope.yaml                  # default local 127.0.0.1, 3 rps
    scope.example.yaml          # template
    scope-cini.yaml             # live https://api.cini.love/api/v1, allowed_hosts api.cini.love, rate 1 rps conservative, synthetic test accounts, ownership verification required
  src/sentinelforge/
    agents/
      attacker.py               # auth BOLA 7 techniques: direct_bola, id_enum 0,1,2,999, header x-tenant-id injection, JWT swap, verb tamper PUT/PATCH/POST, param pollution
      injection.py              # 10 static + augmented with payload_synthesizer 10 Nemotron synthetic + 3 mutations
      custom_exploit_writer.py  # NEW: Writes NEW Python exploit file per run per route to .sentinelforge/exploits/{run_id}/, executes via sys.executable, PROOF NOT A TOY, visible blue highlight
      payload_synthesizer.py    # Nemotron-driven novel payload generation + mutation, HiddenLayer instrumented prompts/responses/ingested content
      adversarial_verifier.py   # 3 mutations must fail after patch per PLAN §7.4, ranking, rejection reasons
      finding_validator.py      # replay validation + HiddenLayer verdict, 8-field evidence standard
      discovery.py              # OpenAPI + AST FastAPI + DjangoRouteDiscovery <int:pk>/<str:token>/<uuid:event_id> -> {pk} for Cini backend
      dependencies.py           # pyproject + requirements manifest parsing
      sbom.py                   # CycloneDX/SPDX SBOM parsing, version range packaging
      vex.py                    # VEX evaluation + reachability call-graph, no-impact evidence, VEX doc generation
      vuln_scanner.py           # Red Hat CVE cross-reference with confidence + OVAL + VEX
      exploit_patterns.py       # 18 code-level patterns
      threat_analyzer.py        # NIM threat analysis JSON with HiddenLayer instrumentation
      http.py                   # ScopedHTTPClient policy-checked + HiddenLayer tool_call/tool_result instrumentation
      code_worker.py            # NEW: NemoClaw agent that works on code - generates patches in isolated worktree per your request
      pr_creator.py             # NEW: Agent that creates PR against GitHub repo after exploit+patch verified + PatchAndPRAgent full flow per your request
    detectors/
      fastapi_bola.py           # deterministic FastAPI BOLA
      django_bola.py            # Django urls.py BOLA detection <int:pk> etc.
    integrations/
      github.py                 # secure clone via GIT_ASKPASS (no token leak), Check Runs annotation at file:line, SARIF 2.1.0, upload_sarif
      github_oauth.py           # NEW: OAuth manager super cool one-click connect, state CSRF, token storage 600 perms, authorize_url, exchange code, safe dict, disconnect
      hiddenlayer.py            # prompt injection scanning (v1 fallback) + 35 pattern local
      hiddenlayer_runtime.py    # NEW: Track 3 runtime security SDK v2 client.runtime.evaluate_interaction(), prompts/responses/tool calls/tool results/ingested content, thoughtful policy self-correction/quarantine/redact/block
      openshell.py              # policy engine with get_policy() env path, 13 rules + DB nuking blocked
      red_hat.py                # Security data API CSAF + OVAL + VEX
      supabase.py               # cloud persistence
    nemoclaw/                   # NEW: NemoClaw persistent orchestrator per your request
      orchestrator.py           # NemoClawOrchestrator extends AgentOrchestrator with target_memory learning delta, heartbeat tick, roster proof
      heartbeat.py              # NemoClawHeartbeat reads Red Hat CSAF, matches dependency inventory, writes HEARTBEAT.md with last_cursor, advisories_seen, learning delta
    inference/
      nvidia_nim.py             # NIM proposer with HiddenLayer instrumented prompts/responses/ingested content
      vllm.py                   # vLLM adapter same schema + bench sequential vs batched 5.2x + resolve_vllm_config()
    intelligence/
      cve_ingestion.py          # NVD/KEV/EPSS feed ingestion
      threat_learning.py        # pattern extraction from CVEs and scans
      adaptive_payloads.py      # Thompson Sampling payload selection
      engagement_memory.py      # persistent memory across engagements
      zero_day_hunter.py        # hypothesis-driven zero-day exploration
    monitoring/
      continuous_scanner.py
      threat_feed.py
    control/
      api.py                    # FastAPI control plane 40+ endpoints: /api/github/oauth/start, /api/github/oauth/callback, /api/github/oauth/config, /api/github/repos with search/sort, /api/agents (14 agents), /api/heartbeat, /api/learning/invariants, /api/learning/memory/{id}, /api/pentest/{id}/traces with token trace
      storage.py                # SQLite event store with 8 tables: runs, events, pentest_runs, pentest_schedules, security_invariants, target_memory, advisory_cursor, agent_traces
      models.py                 # Pydantic models
      service.py                # detection run service with ranking
    redaction.py                # secret scrubbing before persistence/PR (Bearer, api_key, ghp_*, private keys)
    attestation.py              # HMAC-signed attestation with hash chain, keypair in .sentinelforge/keys/, tamper detection
    environment.py              # env detection prod/staging/dev with confidence
    verification.py             # enterprise ownership verification ACME-style challenge-response
    ownership.py                # simple ownership proof file/DNS/HTTP
    orchestrator.py             # phase-based 15 phases including custom_exploit, ownership, environment
    pentest.py                  # pentest service with ownership/environment handlers, custom_exploit handler writes Python file, executes, emits custom_exploit_written/executed, SBOM+VEX+no-impact, OpenShell denied visible, NIM threat analysis, attestation signed + adversarial verifier + redacted receipts
    pentest_modes.py            # 6 enterprise modes with custom_exploit flag (except quick), ownership/environment flags, 1 rps for live prod Cini
    scheduler.py                # recurring scan scheduler + heartbeat tick
    cicd.py                     # CI/CD templates GitHub Actions with SARIF + Check Runs + human gate + release blocked
    pr_generator.py             # PR generation with secret gate + SARIF + draft requiring human review
    web/static/                 # forensic dashboard SPA 5 views: Scan with GitHub OAuth repo list + filter + Scan button, Release Proof, Pentest with custom exploit blue highlight + evidence PR buttons + final report 8 steps + human review gate, Schedule, Settings with OAuth connect/disconnect
  docs/
    PLAN.md                     # build plan
    DEMO.md                     # 5:30 demo script updated with 14 agents, custom exploit writer, GitHub OAuth, Cini live, Track 3
    SECURITY.md                 # safety boundary 10 layers + DB nuking blocked
    ARCHITECTURE.md             # this file (updated to 14 agents)
    ARCHITECTURE_DETAILED.md    # 600+ lines tech stack, sponsor deep integration table, Mermaid diagram with Track 3 + custom exploit
    FLOW_FINDING_TO_PATCH.md    # destructive blocked vs powerful Fable-level, evidence PR button, patch flow, human gate
    HOW_IT_WORKS.md             # doc map with absolute paths
    NEMOCLAW_SETUP.md           # NemoClaw setup with code_worker, pr_creator, patch_and_pr per your request
    GITHUB_OAUTH.md             # OAuth super cool one-click connect, architecture diagram, Loom script
    CINI_PENTEST_GUIDE.md       # Cini live API https://api.cini.love/api/v1 WebUI + Loom demo guide
    HIDDENLAYER_TRACK3.md       # Track 3 runtime security deep instrumentation
    DEPLOYMENT.md               # Fly.io/Render/AWS deployment, get Project URL, Callback URL, Webhook URL, Supabase schema deploy
    LOOM_SCRIPT.md              # NEW: Loom presentation script 5-6 min with timestamps 0:00-5:30
    diagrams/
      architecture.mmd          # Mermaid source for architecture diagram
    BREV.md                     # GPU host manifest A10G/L4, bench.json 5.2x
    supabase_schema.sql         # 11 tables multi-tenant RLS
  examples/vulnerable_shop/     # two-tenant BOLA fixture
  tests/                        # 233 tests (was 178) including test_custom_exploit.py, test_github_oauth.py, test_enterprise.py
  Makefile                      # one-command targets: install, test, lint, api, demo-reset, bench, vllm-health, nim-health, gh-list, e2e
  HEARTBEAT.md                  # NemoClaw cursor + learning delta Run1 vs Run2, roster 14 agents, code_worker, pr_creator, patch_and_pr
  .nemo/HEARTBEAT.md            # copy for NemoClaw contract
  fly.toml                      # Fly.io deployment: app sentinelforge, region iad, port 8741, volume mount .sentinelforge
  render.yaml                   # Render deployment: Docker, healthCheck /health, env vars
  Dockerfile                    # Python 3.12 slim, non-root appuser, git + gh CLI, healthcheck, CMD sentinelforge-api
  .dockerignore                 # Secure build
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
