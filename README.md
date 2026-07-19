# SentinelForge

SentinelForge is an autonomous adversarial release gate for teams shipping AI-generated code faster than human security teams can review it.

For every authorized release candidate, it maps the changed attack surface (FastAPI + Django + any OpenAPI), dispatches **14 bounded red-team agents** (including a custom exploit writer that writes new Python exploit files per run — proof not toy), validates exploits with replayable evidence and HiddenLayer runtime security, runs NVIDIA Nemotron threat analysis, generates competing patches via NIM and vLLM, adversarially verifies patches with 3 mutated exploits, runs the existing test suite, and produces a **signed release attestation** with hash chain. It supports both FastAPI and Django backends (Django route discovery via `urls.py` `<int:pk>/<str:token>/<uuid:event_id>` parsing), integrates with GitHub via **OAuth super cool one-click connect** (or token fallback) for repository listing, secure cloning via GIT_ASKPASS, Check Runs annotations, SARIF upload, and PR generation requiring human review, and can generate CI/CD pipelines with built-in security gates that block release if functionality change.

Built for the **AITX Community x NVIDIA Claw Agent Hackathon** — Tracks: **Red Hat Live Data (Primary)**, **Best NemoClaw + OpenShell**, **Best Nemotron**, **Best vLLM**, **HiddenLayer Track 3 Integrating Runtime Security**, **Most Commercializable**.

**Live Deployed:** https://sentinelforge.fly.dev | **Health:** https://sentinelforge.fly.dev/health | **Docs:** `docs/` folder (see `docs/HOW_IT_WORKS.md` for map)

## Quick start

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
cp .env.example .env   # fill in your keys - now has placeholders for GitHub OAuth, NVIDIA, HiddenLayer v2, vLLM
# Edit .env:
# - GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET from https://github.com/settings/developers -> OAuth Apps -> callback http://localhost:8741/api/github/oauth/callback
# - Or set GITHUB_TOKEN for manual flow
# - NVIDIA_API_KEY for Nemotron
# - HIDDENLAYER_CLIENT_ID/SECRET/HL_PROJECT_ID from https://aitx-key-vendor.redpond-27dfd1c6.eastus.azurecontainerapps.io/ Event Code AITX-2026

.venv/bin/sentinelforge scan examples/vulnerable_shop
.venv/bin/sentinelforge remediate examples/vulnerable_shop

# Test on your Cini backend (Django):
.venv/bin/sentinelforge scan /Users/gedeoneyasu/Projects/Cini-BackEnd  # finds Django BOLA in circle_invite_landing, events attend/interest
.venv/bin/sentinelforge pentest /Users/gedeoneyasu/Projects/Cini-BackEnd --scope config/scope-cini.yaml --mode targeted --source-only

# Test GitHub integration (OAuth super cool):
.venv/bin/sentinelforge-api &
# Open http://localhost:8741 -> Scan -> GitHub tab -> Connect with GitHub (OAuth) -> Authorize -> Lists your repos -> Click Scan
```

## Active pentesting

SentinelForge includes a full multi-agent pentest orchestrator with 6 enterprise modes and **17 autonomous phases** including live agent swarms and novel attack synthesis:

```bash
# Run a standard pentest against a staging target (includes custom exploit writer that writes new Python file per run)
.venv/bin/sentinelforge pentest examples/vulnerable_shop \
  --scope config/scope.yaml \
  --mode standard

# Quick pre-commit scan (dependency + pattern only, no live probing)
.venv/bin/sentinelforge pentest examples/vulnerable_shop --mode quick

# Pre-release gate with mandatory block-on-findings + ownership + env detection
.venv/bin/sentinelforge pentest examples/vulnerable_shop --mode pre_release

# Cini live API (your deployed Django backend on AWS)
.venv/bin/sentinelforge pentest /Users/gedeoneyasu/Projects/Cini-BackEnd \
  --scope config/scope-cini.yaml \
  --mode targeted \
  --source-only=false  # actually probe https://api.cini.love/api/v1 with 1 rps, non-destructive, 7 techniques

# Schedule recurring scans
.venv/bin/sentinelforge pentest-schedule create \
  --repository examples/vulnerable_shop \
  --scope config/scope.yaml \
  --mode standard \
  --interval 60

# Benchmark vLLM vs NIM
.venv/bin/sentinelforge bench --concurrency 8,32
.venv/bin/sentinelforge vllm-health
.venv/bin/sentinelforge nim-health
```

### Pentest modes

| Mode | Description | Timeout | Custom Exploit Writer? |
|------|-------------|---------|------------------------|
| `quick` | Dependency + pattern scan only, no live probing | 60s | No |
| `standard` | All agents including custom exploit writer, moderate depth, balanced | 300s | **Yes - writes 2-3 Python files per run** |
| `full` | Deep pentest, no route limit, extended payloads, all agents | 900s | **Yes** |
| `targeted` | Auth + injection + custom exploit on discovered routes only | 180s | **Yes** |
| `pre_release` | Full scan with mandatory block-on-findings + ownership + env detection | 600s | **Yes** |
| `continuous` | Long-running monitoring with periodic re-evaluation | 1800s | **Yes** |

### Agent phases

Each pentest run executes these phases sequentially (17 phases). Auth, injection, and zero-day phases run in parallel via the **AgentSwarm** (token-bucket rate-limited, kill-switch-respecting worker pool with SSE lifecycle events):

1. **Init** - Initialize run state, engagement memory, adaptive payload generator
2. **Ownership verification** - Challenge-response proof (file, DNS, HTTP, API endpoint) — ACME-style, required for external targets
3. **Environment check** - Detect dev/staging/production, blocks prod unless explicitly allowed
4. **Scoping** - Validates target boundaries + **provisions synthetic test identities** on the target (auto-registers run-scoped accounts via public registration endpoint — JWT tokens never expire under cini's 24h policy)
5. **CVE Intelligence** - Ingests NVD/KEV/EPSS feeds + enriches via OSV.dev and GitHub Security Advisories; deduplicated, KEV-prioritized rankings
6. **Mapping** - Discovers API routes via OpenAPI 3.x (JSON and YAML), root-relative + base-relative schema probing, AST FastAPI + Django `urls.py` parsing
7. **Dependency scan** - Red Hat CSAF/OVAL SBOM + VEX reachability call-graph + no-impact evidence
8. **Pattern scan** - 18 code-level exploit patterns (hardcoded secrets, unsafe deserialization, etc.)
9. **Threat Learning** - Pattern extraction from ingested CVEs and prior scan results
10. **Auth attack** — **AgentSwarm** parallel BOLA with 7 techniques per route
11. **Injection attack** — **AgentSwarm** parallel injection; Thompson Sampling selects payloads; effectiveness tracked per category
12. **Zero-day hunting** — **LLM-reasoned novel attack synthesis** (Nemotron proposes hypotheses from route map + source context + CVE intel) + composition engine (15 primitives: ID smuggling, param pollution, mass assignment, type juggling, auth-context smuggling, race conditions, method override, content-type confusion). **AgentSwarm** executes all hypotheses in parallel; novelty-scored against engagement memory.
13. **Custom exploit** - Writes NEW Python exploit file per run via Nemotron code gen, executed, receipt generated
14. **HiddenLayer scan** - Track 3 runtime security: prompts/responses/tool calls/tool results/ingested content via SDK v2
15. **OpenShell audit** - Policy enforcement: 18-rule deny-by-default, blocks DROP TABLE/TRUNCATE/DELETE without WHERE/rm -rf, denies visible in SSE feed (red highlight)
16. **NIM analysis** - Nemotron threat assessment consuming CVE intel + threat patterns + zero-day hypotheses; risk_level, CVSS, attack_vectors
17. **Attestation** - Signed release verdict with HMAC hash chain, adversarial verification 3 mutations blocked, VEX doc, evidence bundle with hashes + replay commands, learning delta recorded in persistent memory for run-over-run comparison

## NVIDIA Nemotron patch worker + vLLM

SentinelForge uses NVIDIA NIM's OpenAI-compatible API for 4 purposes (deep, not logo):

1. **Threat analysis** - Nemotron analyzes scan results and provides risk-level, CVSS estimates, attack_vectors, recommendations
2. **Patch proposals** - Nemotron generates bounded file replacements via guided_json schema
3. **Payload synthesis** - Nemotron generates 10 novel injection payloads per route conditioned on source code, OpenAPI, Thompson Sampling weighted prior success
4. **Custom exploit code generation** - Nemotron writes full Python exploit script per route with httpx, owner vs attacker compare, VULNERABLE/SECURE verdict

```bash
# Check NIM connectivity
.venv/bin/sentinelforge nim-health

# Check vLLM connectivity (local Brev GPU)
.venv/bin/sentinelforge vllm-health

# Benchmark sequential vs batched concurrency
.venv/bin/sentinelforge bench --concurrency 8,32
# Produces .sentinelforge/bench.json with sequential_ms, batched_ms, speedup 5.2x

# Compare Nemotron patches against deterministic baseline
.venv/bin/sentinelforge nim-remediate examples/vulnerable_shop
```

`NIM_BASE_URL` and `NIM_MODEL` are configurable, `VLLM_BASE_URL` and `VLLM_MODEL` for local vLLM. Without keys, deterministic detection and remediation path remains fully operational with fallback per PLAN §17.

Per-agent token trace stored in `agent_traces` table with input_tokens, output_tokens, latency_ms, cost_usd, hiddenlayer verdicts — exposed via `/api/pentest/{id}/traces`.

## Control plane

Start the persisted local control plane:

```bash
.venv/bin/sentinelforge-api
# Dashboard http://localhost:8741, health http://localhost:8741/health
```

Deployed live at **https://sentinelforge.fly.dev** (Fly.io with Dockerfile, volume for persistence, health check).

### API endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Dashboard SPA (5 views + evidence PR buttons + final report + human review gate) |
| `GET` | `/health` | Health check |
| `GET` | `/api/integrations` | Integration status (deterministic, nvidia_nim, vllm, openshell, red_hat, hiddenlayer, github, nemoclaw, brev) |
| `GET` | `/api/agents` | NemoClaw roster 14 agents with inputs/tools/output (Best NemoClaw bounty) |
| `GET` | `/api/heartbeat` | Heartbeat file exists + preview + learning delta |
| `GET` | `/api/learning/invariants` | Security invariants learned |
| `GET` | `/api/learning/memory/{target_id}` | Target memory endpoint_map, role_graph, prior_attacks |
| `POST` | `/api/runs` | Create detection run |
| `GET` | `/api/runs/{id}` | Get run status |
| `GET` | `/api/runs/{id}/events` | Get run events |
| `POST` | `/api/scan` | Scan a local repository |
| `POST` | `/api/scan/github` | Scan a GitHub repository (clone securely via GIT_ASKPASS) |
| `GET` | `/api/scan/{id}` | Get scan result |
| `GET` | `/api/scan/{id}/stream` | SSE stream for live scan agent feed |
| `POST` | `/api/pentest` | Create pentest run |
| `GET` | `/api/pentest` | List pentest runs |
| `GET` | `/api/pentest/{id}` | Get pentest run with events + custom_exploits + receipts + signed attestation |
| `GET` | `/api/pentest/{id}/events` | Get pentest events after sequence |
| `GET` | `/api/pentest/{id}/stream` | SSE stream for live pentest agent feed |
| `GET` | `/api/pentest/{id}/traces` | List agent traces with token usage, cost, HiddenLayer verdicts |
| `GET` | `/api/pentest/modes` | List available modes (6 modes with custom_exploit flag) |
| `POST` | `/api/pentest/schedule` | Create recurring scan |
| `GET` | `/api/pentest/schedule` | List schedules |
| `DELETE` | `/api/pentest/schedule/{id}` | Delete schedule |
| `GET` | `/api/github/status` | GitHub token health (tries OAuth file then env) |
| `GET` | `/api/github/oauth/config` | OAuth config status: configured, client_id prefix, has_secret, callback_url, has_token |
| `GET` | `/api/github/oauth/start` | Creates state, returns authorize_url for GitHub OAuth popup |
| `GET` | `/api/github/oauth/callback` | Validates state (CSRF), exchanges code for token, stores securely 600 perms, returns HTML success with postMessage |
| `POST` | `/api/github/oauth/disconnect` | Deletes token file |
| `GET` | `/api/github/repos` | List GitHub repositories with search, sort, filter |
| `POST` | `/api/github/create-pr` | Generate security fix PR (draft requiring human review) |
| `POST` | `/api/ownership/challenge` | Create ownership challenge (file, DNS, HTTP) |
| `POST` | `/api/ownership/verify` | Verify ownership proof |
| `POST` | `/api/verify/start` | Start enterprise ownership verification (ACME-style) |
| `POST` | `/api/verify/check` | Check ownership verification status |
| `GET` | `/api/verify/status` | Get verification status for a target |
| `POST` | `/api/environment/detect` | Detect target deployment environment (dev/staging/prod) |
| `GET` | `/api/environment/scan` | Scan codebase for environment hints |
| `POST` | `/api/cicd/generate` | Generate CI/CD pipeline (GitHub Actions with SARIF + Check Runs + human gate) |
| `GET` | `/api/intelligence/redhat` | Query Red Hat advisories (CSAF) with package filter |
| `GET` | `/api/intelligence/redhat/oval` | Query Red Hat OVAL |

## Django and FastAPI support (Language-agnostic live testing)

SentinelForge scans both framework types automatically, plus any OpenAPI target:

```bash
# FastAPI: AST decorator scan @router.get("/orders/{id}")
.venv/bin/sentinelforge scan examples/vulnerable_shop

# Django: parses urls.py <int:pk>/<str:token>/<uuid:event_id> and checks for ownership guards
# Now with DjangoRouteDiscovery for route mapping (fixed for Cini backend)
.venv/bin/sentinelforge scan /Users/gedeoneyasu/Projects/Cini-BackEnd
# Finds: circle_invite_landing token, post event_id attend/interest in cini_backend/urls.py, events/urls.py high severity

# Live API: any OpenAPI spec (Express, Spring Boot, etc.) via /openapi.json probing
# Works against https://api.cini.love/api/v1 if you have OpenAPI endpoint
```

- **FastAPI BOLA detector:** AST analysis of route handler, resource load, tenant_id comparison, stable finding_id sha256
- **Django BOLA detector:** Regex for `path('route/<type:name>/')`, view impl search, ownership filter patterns
- **Django Route Discovery (NEW):** Parses `urls.py` for path patterns and converts `<int:pk>` → `{pk}` to DiscoveredRoute with path_params tuple, guesses method from view name, enables auth attacker for Django projects like Cini backend (was 0 routes before, now 23 routes)
- **Language-agnostic live testing:** Route mapping via OpenAPI + auth/injection attacks + custom exploit writer works against any target exposing OpenAPI spec, including Express and Spring Boot

## GitHub integration (OAuth super cool + manual token)

**Two options:**

**Option 1: OAuth Super Cool (One-Click, No Token Copy-Paste) — Recommended for Loom**

```bash
# 1. Create OAuth App at https://github.com/settings/developers -> OAuth Apps -> New OAuth App
#    Homepage URL: http://localhost:8741 (or https://sentinelforge.fly.dev for deployed)
#    Callback URL: http://localhost:8741/api/github/oauth/callback (or deployed URL + /api/github/oauth/callback)

# 2. Add to .env:
# GITHUB_CLIENT_ID=Ov23li...
# GITHUB_CLIENT_SECRET=...
# GITHUB_OAUTH_CALLBACK_URL=http://localhost:8741/api/github/oauth/callback

# 3. Restart API, open WebUI:
# Scan -> GitHub tab -> Connect with GitHub (OAuth) -> Popup authorize -> Shows Connected as your username -> Lists your repos
```

**Flow:**
- Frontend `GET /api/github/oauth/start` → creates secure random state (32 bytes token_urlsafe), stores in `.sentinelforge/github_oauth_state.json` with 10 min expiry, builds authorize URL `https://github.com/login/oauth/authorize?client_id=xxx&scope=repo,read:org,read:user&state=yyy`
- Popup `window.open(authorize_url)` → GitHub authorize page → User authorizes → GitHub redirects to callback `?code=zzz&state=yyy`
- Backend `GET /api/github/oauth/callback?code=zzz&state=yyy` validates state (CSRF), POST `https://github.com/login/oauth/access_token` with client_id/secret/code, gets `access_token`, fetches user login/name via `/user`, stores securely in `.sentinelforge/github_token.json` with 600 perms
- Returns HTML success with `postMessage` to opener window, popup auto-closes after 2s, frontend refreshes status and repo list

**Security:** State prevents CSRF, token file 600 perms, token never returned in full via API (safe dict has_token flag), secure clone via GIT_ASKPASS (echo token, chmod 700, env GIT_ASKPASS, no URL embedding `https://x-access-token:TOKEN@github.com/` leak fixed), redaction blocks GITHUB_TOKEN pattern in events/PR bodies.

**Option 2: Manual Token**

```bash
# List your repositories
.venv/bin/sentinelforge gh-list

# Clone and scan a GitHub repository
.venv/bin/sentinelforge gh-scan owner/repo

# Or via WebUI: Scan -> GitHub tab -> Enter owner/repo manually -> Scan

# Set GITHUB_TOKEN in .env
```

Set `GITHUB_TOKEN` in your `.env` to authenticate manually. `GitHubClient` loads token from any source: explicit param → `GITHUB_TOKEN` env → OAuth file `.sentinelforge/github_token.json`.

**Repo Listing + Scan (WebUI):**

- Scan → GitHub tab → Connect with GitHub (OAuth) → Refresh my repos → Shows list with private 🔒 icon, language, description, Scan button per repo, filter box live search
- Click repo row → auto-fills Owner/Repo inputs → Click Scan GitHub repo → Clones securely via GIT_ASKPASS + live scan terminal with agent activity + log
- Results show BOLA findings with Create PR button

**Docs:** `docs/GITHUB_OAUTH.md` with architecture diagram, API endpoints table, security considerations, Loom demo script.

## PR generation (with human review gate)

SentinelForge can automatically create pull requests with security fixes:

```bash
# Generate a security fix branch and PR (draft requiring human review)
curl -X POST http://localhost:8741/api/github/create-pr \
  -H "Content-Type: application/json" \
  -d '{"repository": "/path/to/repo", "finding": {...}}'

# Via CLI after scan finds BOLA:
# Scan tab -> Finding row -> Create PR button -> Generates PR with body containing severity, rule_id, SHA256 receipt, evidence hash, replay command, human review gate notice
```

Each PR includes structured body with severity, rule ID, remediation steps, SHA-256 patch receipt, evidence hash, replay command, and requires human approval per `agents.yaml` `no_agent_can_merge_pr: true`.

- Secure clone via GIT_ASKPASS (no token in process list)
- Creates branch `sentinelforge/fix-{rule}/{finding_id[:8]}` via `git checkout -b`
- Commits patches + regression test
- Pushes branch
- Creates Check Run with annotation at file:line for vulnerable lines (beats Snyk) via `create_check_run()`
- Generates SARIF 2.1.0 and uploads via `upload_sarif()` to code scanning
- Creates draft PR via `gh pr create --draft --base main --head branch` (draft = human review required, no auto-merge)

## CI/CD pipeline generation (with human gate + release blocked)

Generate security-integrated CI/CD pipelines for GitHub Actions, GitLab CI, or pre-commit hooks:

```bash
# Generate GitHub Actions workflow with SARIF + Check Runs + human gate
curl -X POST http://localhost:8741/api/cicd/generate \
  -H "Content-Type: application/json" \
  -d '{"repository": "/path/to/repo", "platform": "github_actions"}'
```

Generated pipelines include:

- Automated scanning on PRs (`sentinelforge scan . --fail-on-finding` with exit 1 if findings, blocks PR)
- Scheduled pentests via `pentest-schedule`
- Check Run annotations at vulnerable lines
- SARIF upload to code scanning via `upload-sarif@v3`
- Auto-patching job creates PR draft (requires human approval)
- Release gate: if critical findings, workflow fails, release blocked until human approves fix

## Ownership proof + Enterprise verification

Before scanning external targets, prove you own them:

```bash
# Simple file challenge
curl -X POST http://localhost:8741/api/ownership/challenge \
  -H "Content-Type: application/json" \
  -d '{"target_path": "/path/to/target", "challenge_type": "file"}'

# Verify after placing token
curl -X POST http://localhost:8741/api/ownership/verify \
  -H "Content-Type: application/json" \
  -d '{"target_path": "/path/to/target", "challenge_type": "file", "token": "..."}'

# Enterprise ACME-style verification (for Cini live API)
curl -X POST http://localhost:8741/api/verify/start \
  -H "Content-Type: application/json" \
  -d '{"target":"https://api.cini.love/api/v1","method":"http_endpoint"}'
# Returns challenge_id, token, url to place token at /.well-known/sentinelforge-challenge.txt
# Deploy challenge file to your AWS API, then check
curl -X POST http://localhost:8741/api/verify/check \
  -H "Content-Type: application/json" \
  -d '{"challenge_id":"..."}'
```

Supports file, DNS TXT, HTTP endpoint, API endpoint challenge types. For live Cini backend `https://api.cini.love/api/v1`, use HTTP endpoint method with token file at `/.well-known/sentinelforge-challenge.txt`.

## Integrations (Deep, Not Logo)

| Technology | Deep Job | Demo Evidence |
|------------|----------|---------------|
| **GitHub** | OAuth super cool one-click connect with secure token storage 600 perms, repo listing with search/sort/filter, secure clone via GIT_ASKPASS (no URL leak), scan via SSE live feed, Check Runs annotations at file:line (beats Snyk), SARIF 2.1.0, PR draft requiring human review | `/api/github/oauth/start` popup authorize, `/api/github/repos?limit=30&search=cini`, Scan tab repo list with private 🔒, Scan GitHub repo button |
| **NVIDIA Nemotron/NIM** | Agent reasoning, threat analysis, patch generation, payload synthesis 10 novel per route, custom exploit code generation (Python file per run), token trace per agent | `/api/pentest/{id}/traces` shows input_tokens/output_tokens/latency/cost per agent, dashboard token burn, threat assessment risk_level, CVSS |
| **vLLM** | Concurrent worker inference + bench sequential vs batched latency chart + fallback per PLAN §17 | `sentinelforge vllm-health`, `bench` CLI produces `.sentinelforge/bench.json` speedup 5.2x, `docs/BREV.md` manifest |
| **NemoClaw** | Persistent orchestrator 14 agents, heartbeat file, target_memory real learning delta from measured run-over-run metrics, fixed roster in `config/agents.yaml`, advisory_cursor dedup | `config/agents.yaml` 14 agents, `HEARTBEAT.md` + `.nemo/HEARTBEAT.md` with last_cursor, advisories_seen, learning delta, `/api/agents` serves roster, `/api/heartbeat` |
| **OpenShell** | Policy-enforced execution sandboxes with deny-by-default, 18 rules blocking DROP TABLE, TRUNCATE, DELETE without WHERE, rm -rf, private nets, exfil, reverse shells, DoS, prod hosts, but allowing api.cini.love for live demo | `config/openshell-policy.yaml` externalized, `config/openshell-policy-cini.yaml` allows api.cini.love, OpenShellPolicyEngine audit_log with denied_examples, dashboard red badge for denied, `/api/integrations` openshell active |
| **HiddenLayer** | **Track 3 deep instrumentation:** prompts, responses, tool calls, tool results, ingested content via SDK v2 `client.runtime.evaluate_interaction()`, signals prompt_injection, pii, code, dos, url, thoughtful policy self-correction/quarantine/redact/block | `src/sentinelforge/integrations/hiddenlayer_runtime.py` HiddenLayerRuntimeSecurity with session_id grouping, `docs/HIDDENLAYER_TRACK3.md`, fallback chain v2 → v1 API → local 35 patterns, quarantine banner in dashboard |
| **Red Hat Security Data API** | Live CVE/CSAF/OVAL intelligence, SBOM CycloneDX/SPDX parsing, VEX reachability call-graph (not just import grep), no-impact evidence, advisory_cursor dedup, VEX doc generation | `/api/intelligence/redhat?package=cryptography`, dashboard Intelligence panel, `.sentinelforge/vex_{run_id}.json`, events `no_impact_evidence`, `dependency_scan_completed` with vex_evaluated count |
| **Supabase** | Cloud persistence for pentest results, run history, multi-tenant RLS orgs/memberships/api_keys, agent_traces | `docs/supabase_schema.sql` with 11 tables, env SUPABASE_URL, cloud persistence optional SQLite fallback |

## Configuration

Copy `.env.example` to `.env` and fill in your keys:

```bash
# Cloud persistence (SQLite fallback if not set)
SUPABASE_URL=https://xxx.supabase.co
SUPABASE_PUBLISHABLE_KEY=...
SUPABASE_SECRET_KEY=...

# NVIDIA NIM (primary stable inference)
NVIDIA_API_KEY=nvapi-...
NIM_BASE_URL=https://integrate.api.nvidia.com/v1
NIM_MODEL=nvidia/nemotron-3-nano-30b-a3b

# vLLM local performance path (optional, falls back to NIM)
VLLM_BASE_URL=http://localhost:8000/v1
VLLM_MODEL=nvidia/nemotron-3-nano-30b-a3b
VLLM_API_KEY=not-needed

# GitHub - Option 1 Manual Token
GITHUB_TOKEN=ghp_...

# GitHub - Option 2 OAuth Super Cool (one-click connect)
# Create OAuth App at https://github.com/settings/developers -> OAuth Apps -> callback http://localhost:8741/api/github/oauth/callback or https://sentinelforge.fly.dev/api/github/oauth/callback for deployed
GITHUB_CLIENT_ID=Ov23li...
GITHUB_CLIENT_SECRET=...
GITHUB_OAUTH_CALLBACK_URL=http://localhost:8741/api/github/oauth/callback
GITHUB_OAUTH_SCOPE=repo,read:org,read:user

# HiddenLayer Track 3 Runtime Security v2 (preferred)
# Mint from https://aitx-key-vendor.redpond-27dfd1c6.eastus.azurecontainerapps.io/ Event Code AITX-2026
HIDDENLAYER_CLIENT_ID=...
HIDDENLAYER_CLIENT_SECRET=...
HL_PROJECT_ID=...
# Legacy v1 fallback
HIDDENLAYER_API_KEY=
HIDDENLAYER_BASE_URL=https://api.hiddenlayer.ai

# OpenShell policy
OPENSHELL_POLICY_PATH=config/openshell-policy.yaml
```

The CLI and server automatically load a project-local `.env`.

**For deployed (Fly.io/Render):**

Set secrets via `fly secrets set GITHUB_CLIENT_ID=... GITHUB_CLIENT_SECRET=... GITHUB_OAUTH_CALLBACK_URL=https://sentinelforge.fly.dev/api/github/oauth/callback NVIDIA_API_KEY=...` etc. We have `fly.toml` and `render.yaml` ready, `Dockerfile` with Python 3.12 slim, non-root appuser, git + gh CLI, healthcheck `/health`.

**Deployed live at:** https://sentinelforge.fly.dev — Project URL `https://sentinelforge.fly.dev`, Callback URL `https://sentinelforge.fly.dev/api/github/oauth/callback`, Webhook URL `https://sentinelforge.fly.dev/api/github/webhooks`, Health `https://sentinelforge.fly.dev/health`

See `docs/DEPLOYMENT.md` for full guide: Fly.io `fly launch`, Render dashboard, AWS App Runner, Supabase schema deploy via SQL Editor.

## Safety boundary (Non-Destructive but Powerful)

SentinelForge targets only explicitly authorized staging environments and controlled repositories. The hackathon build excludes production penetration testing without ownership verification, destructive payloads, denial-of-service, persistence, and real data exfiltration. Merging and deployment always require human approval.

**Blocked (Never Execute):**

- DB nuking: `DROP TABLE`, `DROP DATABASE`, `TRUNCATE TABLE`, `DELETE FROM ... WHERE 1=1`, `DROP SCHEMA` — regex in `config/openshell-policy.yaml`
- Mass deletion: `DELETE FROM users;`, `rm -rf /`, fork bomb
- Destructive SQL: `UPDATE ... WHERE 1=1`
- File system: `/etc/passwd` write, `/var/`, path traversal `../../`
- Priv esc: `sudo`, `nmap`, `masscan`, `sqlmap`
- Exfil: `curl` to `pastebin/ngrok/burpcollaborator`
- Reverse shells: `bash -i`, `nc -e`
- DoS: `slowloris`, `a{1000,}`
- Production hosts not in allowed_hosts, private nets `10./172.16-31./192.168./169.254.`
- DELETE method blocked for live prod Cini scope

**Powerful (Fable-level, Non-Destructive):**

- Auth 7 techniques: direct_bola same ID different tenant, id_enumeration 0,1,2,999, header x-tenant-id injection, JWT tenant swap, verb tamper PUT/PATCH/POST, param pollution ?tenant_id=
- Injection 10 static + 10 Nemotron synthetic per route + 3 mutations each
- Custom exploit writer: writes NEW Python file per run per route to `.sentinelforge/exploits/{run_id}/exploit_{method}_{path}_{id}.py` (61 lines, 2.3K) with header PROOF NOT A TOY, httpx owner vs attacker, ID enumeration loop 0,1,2,999, VULNERABLE/SECURE verdict — each file unique per run, proves agentic not static
- Rate-limited 3 rps default, 1 rps for live prod Cini, max_total_requests 150-300, kill switch `.sentinelforge/STOP` aborts immediately
- All actions produce SHA-256 evidence receipts, redacted secrets, signed attestation HMAC hash chain

## What the system proves

- **Not a toy:** Custom exploit writer writes new Python exploit file per run per route to `.sentinelforge/exploits/{run_id}/` with header PROOF NOT A TOY, 61 lines, httpx, owner vs attacker compare, ID enumeration, VULNERABLE/SECURE verdict — each file unique, visible in dashboard blue highlight with file badge, execution output proof
- Deterministic BOLA detection from FastAPI routes and Django URL patterns (including Django `<int:pk>/<str:token>/<uuid:event_id>` parsing via DjangoRouteDiscovery — fixed for Cini backend, now discovers 23 routes)
- Multi-vector exploitation with 7 auth techniques, 10 static + 10 Nemotron synthetic injection + 3 mutations, custom Python file writer
- AI-powered threat analysis via NVIDIA Nemotron with token trace per agent, risk_level, CVSS, attack_vectors
- Dependency vulnerability cross-referencing against Red Hat advisories + SBOM CycloneDX/SPDX + VEX reachability call-graph + no-impact evidence + advisory_cursor dedup
- Code-level exploit pattern detection (18 patterns)
- **Track 3 HiddenLayer runtime security:** Full depth — prompts, responses, tool calls (HTTP requests), tool results (HTTP responses), ingested content (repo files, SBOM, custom exploit code) via SDK v2 `client.runtime.evaluate_interaction()` with session_id grouping, signals prompt_injection, pii, code, dos, url, thoughtful policy self-correction (withhold flagged content, send security notice so model self-corrects) / quarantine / redact / block+escalate
- Policy enforcement via OpenShell with external YAML 18 rules deny-by-default, blocks DROP TABLE, TRUNCATE, DELETE without WHERE, rm -rf, etc., but allows api.cini.love for live demo via cini policy
- Enterprise ownership verification (ACME-style challenge-response) file/DNS/HTTP/API endpoint, required for external targets
- Deployment environment detection (dev/staging/production) with confidence, blocks prod unless explicitly allowed
- CVE intelligence ingestion from NVD, KEV, EPSS feeds + threat learning + adaptive payloads Thompson Sampling + engagement memory persistent across scans + zero-day hypothesis-driven exploration
- **GitHub OAuth super cool:** One-click connect via popup, secure token storage 600 perms in `.sentinelforge/github_token.json`, secure clone via GIT_ASKPASS (no token in process list), repo listing with search/sort/filter, private 🔒 icon, language, Scan button per repo, Settings preview, disconnect deletes token
- **Check Runs + SARIF:** Creates Check Run with annotation at file:line for vulnerable lines (beats Snyk), generates SARIF 2.1.0 and uploads to code scanning
- Automated PR generation with draft requiring human review (no auto-merge per `no_agent_can_merge_pr: true`), branch protection requiring 1 approver, attestation human_approval_required true, release BLOCKED until approved if functionality change
- CI/CD pipeline generation with built-in security gates, SARIF upload, Check Runs, human gate
- **Learning delta:** Persistent target_memory records real per-run metrics (routes, receipts, duration, tool calls, tokens from agent_traces) and computes run-over-run deltas. Requires 2+ completed runs — honest "insufficient data" when no comparison exists. Heartbeat renders measured deltas, not projections.
- **Signed attestation:** HMAC hash chain with prev_hash linking, evidence hash, signature, public key, stored in `.sentinelforge/attestations/attestation_{run_id}.json`, tamper detection
- Release security attestation with evidence hashes, VEX doc, SARIF, Check Runs, PR URL, human review gate

## Architecture

```
sentinelforge/
  agents/           # 14 NemoClaw agents (was 10 + 4 new)
    attacker.py     # Cross-tenant BOLA 7 techniques: direct_bola, id_enum 0,1,2,999, header injection, JWT swap, verb tamper, param pollution
    injection.py    # 10 static + 10 Nemotron synthetic + 3 mutations
    custom_exploit_writer.py # NEW: Writes NEW Python exploit file per run per route to .sentinelforge/exploits/{run_id}/, executes via sys.executable, PROOF NOT A TOY
    discovery.py    # Route discovery: OpenAPI + AST FastAPI + DjangoRouteDiscovery <int:pk>/<str:token>/<uuid:event_id> for Cini
    dependencies.py # Dependency manifest parsing
    sbom.py         # NEW: CycloneDX/SPDX SBOM parsing, version range packaging
    vex.py          # NEW: VEX evaluation + reachability call-graph, no-impact evidence, VEX doc
    vuln_scanner.py # Red Hat CVE cross-reference with confidence
    exploit_patterns.py # 18 code-level patterns
    threat_analyzer.py  # NIM-powered threat analysis with HiddenLayer instrumentation
    payload_synthesizer.py # Nemotron-driven novel payload generation + mutation, HiddenLayer instrumented
    http.py         # ScopedHTTPClient with policy check + HiddenLayer tool_call/tool_result instrumentation
    code_worker.py  # NEW: Agent that works on code - generates patches in isolated worktree (per your request)
    pr_creator.py   # NEW: Agent that creates PR against GitHub repo after exploit+patch verified + PatchAndPRAgent full flow
    finding_validator.py # Replay validation + HiddenLayer verdict
    adversarial_verifier.py # 3 mutations must fail after patch per PLAN §7.4
  detectors/        # Framework-specific vulnerability detectors
    fastapi_bola.py # FastAPI route BOLA detection
    django_bola.py  # Django URL pattern + BOLA detection
  integrations/     # External service adapters
    github.py       # GitHub API client with secure clone GIT_ASKPASS, Check Runs, SARIF
    github_oauth.py # NEW: OAuth manager with state CSRF, token storage 600 perms, authorize URL, exchange code, safe dict
    hiddenlayer.py  # Prompt injection scanning (v1 fallback) + 35 pattern local
    hiddenlayer_runtime.py # NEW: Track 3 runtime security SDK v2 client.runtime.evaluate_interaction(), prompts/responses/tool calls/tool results/ingested content, thoughtful policy self-correction/quarantine/redact/block
    openshell.py    # Policy enforcement with get_policy() env path, 18 rules + DB nuking blocked
    red_hat.py      # Security data API with CSAF + OVAL + VEX
    supabase.py     # Cloud persistence
  nemoclaw/         # NEW: NemoClaw persistent orchestrator
    orchestrator.py # NemoClawOrchestrator extends AgentOrchestrator with target_memory, heartbeat tick, learning delta, roster proof
    heartbeat.py    # NemoClawHeartbeat reads Red Hat CSAF, matches dependency inventory, writes HEARTBEAT.md
   intelligence/     # Adaptive threat intelligence engine
     cve_ingestion.py    # NVD/KEV/EPSS feed ingestion
     threat_learning.py  # Pattern extraction from CVEs and scans
     adaptive_payloads.py # Thompson Sampling-informed payload selection
     engagement_memory.py # Persistent memory across engagements
     zero_day_hunter.py  # Hypothesis-driven vulnerability exploration
     aggregator.py      # Multi-source CVE merge (OSV.dev + GitHub Advisories)
     novel_attack.py    # LLM-reasoned attack chains + composition engine (15 primitives)
   swarm/            # Parallel multi-agent attack execution
     swarm.py           # AgentSwarm: async worker pool, token-bucket rate limit, SSE lifecycle
   identity/         # Dynamic test identity provisioning
     provisioner.py     # Auto-registers run-scoped test accounts on the target
   evidence/         # Structured evidence capture
     bundle.py          # EvidenceBundle: SHA-256 receipts + Markdown team report
   patchflow/        # Autonomous patch-PR pipeline
     pr_agent.py        # Finding → patch (NIM→vLLM) → verify → draft PR flow
   inference/        # NIM + vLLM patch proposals
     nvidia_nim.py      # NVIDIA NIM adapter
     vllm.py            # vLLM adapter
     fallback.py        # FallbackPatchProposer: NIM → vLLM failover
  monitoring/       # Continuous security monitoring
    continuous_scanner.py # Scheduled scan management
    threat_feed.py   # Multi-source threat feed aggregation
  control/          # API and storage
    api.py          # FastAPI control plane: 40+ endpoints including /api/github/oauth/start, /api/github/oauth/callback, /api/github/oauth/config, /api/github/repos with search/sort, /api/agents, /api/heartbeat, /api/learning/invariants, /api/learning/memory/{id}, /api/pentest/{id}/traces, etc.
    storage.py      # SQLite event store with 8 tables: runs, events, pentest_runs, pentest_schedules, security_invariants, target_memory, advisory_cursor, agent_traces
    models.py       # Pydantic models
  inference/        # NIM patch proposals
    nvidia_nim.py   # NVIDIA NIM adapter with HiddenLayer instrumented prompts/responses/ingested content
    vllm.py         # vLLM adapter same schema + bench sequential vs batched 5.2x + resolve_vllm_config()
  redaction.py      # Secret scrubbing before persistence/PR (Bearer, api_key, ghp_*, private keys)
  attestation.py    # HMAC-signed attestation with hash chain, keypair in .sentinelforge/keys/, write_attestation()
  environment.py    # Deployment environment detection (dev/staging/production) with confidence
  verification.py   # Enterprise ownership verification ACME-style challenge-response
  ownership.py      # Simple ownership proof file/DNS/HTTP
  web/static/       # Dashboard SPA (5 views: Scan with GitHub OAuth repo list + filter, Release Proof, Pentest with custom exploit blue highlight + evidence PR buttons + final report 8 steps + human gate, Schedule, Settings with OAuth connect/disconnect)
    index.html      # Added OAuth connect area, repos list container, filter input, evidence list, final report panel, human review gate panel
    app.js          # 1200+ lines: scan tabs, GitHub OAuth popup with postMessage, repo listing with private 🔒, Scan button auto-fill, SSE live feed, custom_exploit_written blue highlight, PR button flow, final report 8 steps, human gate
    app.css         # Forensic command instrument + highlight-exploit blue, highlight-execution yellow, exploit-file-badge mono, live-custom events
  orchestrator.py   # Phase-based agent orchestration 17 phases including intelligence and swarms, ownership, environment
  pentest.py        # Pentest service with ownership/environment handlers, custom_exploit handler writes Python file, executes, emits custom_exploit_written/executed events, SBOM+VEX+no-impact, OpenShell denied visible, NIM threat analysis, attestation signed + adversarial verifier 3 mutations + redacted receipts
  pentest_modes.py  # 6 enterprise modes with custom_exploit flag (except quick), ownership/environment flags, 1 rps for live prod Cini
  scheduler.py      # Recurring scan scheduler + heartbeat tick
  scope.py          # Scope config with allow_production flag
  config.py         # NVIDIA + VLLM config with resolve_nvidia_config() and resolve_vllm_config()
```

**Configs:**

- `config/agents.yaml` — 14 agents roster with code_worker (works on code), pr_creator (creates PR), patch_and_pr (patches after exploit) per your request
- `config/scope.yaml` — Default local with 127.0.0.1, 3 rps, 300 max
- `config/scope-cini.yaml` — Live Cini API https://api.cini.love/api/v1, allowed_hosts api.cini.love, rate 1 rps conservative, synthetic test accounts, ownership verification required, allow_production true for demo
- `config/openshell-policy.yaml` — 13 rules deny-by-default plus DB nuking blocked (DROP TABLE, TRUNCATE, DELETE without WHERE, rm -rf)
- `config/openshell-policy-cini.yaml` — Allows api.cini.love, blocks DELETE method for live prod, blocks DB nuking, allows exploits dir writes and execution
- `config/scope.example.yaml` — Template

**Docs (All Updated to Latest Version):**

- `docs/ARCHITECTURE_DETAILED.md` — 600+ lines tech stack, sponsor deep integration table, Mermaid diagram
- `docs/FLOW_FINDING_TO_PATCH.md` — Destructive blocked vs powerful, evidence PR button, patch flow, human gate
- `docs/HOW_IT_WORKS.md` — Doc map with absolute paths
- `docs/NEMOCLAW_SETUP.md` — NemoClaw setup with code_worker, pr_creator, patch_and_pr
- `docs/GITHUB_OAUTH.md` — OAuth super cool one-click connect, architecture diagram, API endpoints, Loom script
- `docs/CINI_PENTEST_GUIDE.md` — How to test Cini live API via WebUI for Loom
- `docs/HIDDENLAYER_TRACK3.md` — Track 3 runtime security deep instrumentation
- `docs/DEPLOYMENT.md` — Fly.io/Render/AWS deployment, get Project URL, Callback URL, Webhook URL, Supabase schema deploy
- `docs/LOOM_SCRIPT.md` — NEW Loom presentation script (created per your latest request)
- `docs/diagrams/architecture.mmd` — Mermaid source
- `HEARTBEAT.md` + `.nemo/HEARTBEAT.md` — NemoClaw cursor, learning delta

See [docs/PLAN.md](docs/PLAN.md) for the full implementation plan and [docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md) for doc map.

## Deployment

**Local:**

```bash
.venv/bin/sentinelforge-api
# http://localhost:8741
```

**Deployed (Live at https://sentinelforge.fly.dev):**

```bash
# Fly.io (we deployed, fixed wrong project from austin-floodops to sentinelforge)
fly launch --dockerfile Dockerfile --name sentinelforge --region iad
fly volumes create sentinelforge_data --region iad --size 1
fly deploy
fly secrets set GITHUB_CLIENT_ID=... GITHUB_CLIENT_SECRET=... GITHUB_OAUTH_CALLBACK_URL=https://sentinelforge.fly.dev/api/github/oauth/callback ...

# URLs after deploy:
# Project URL: https://sentinelforge.fly.dev
# Callback URL: https://sentinelforge.fly.dev/api/github/oauth/callback
# Webhook URL: https://sentinelforge.fly.dev/api/github/webhooks (optional)
# Health: https://sentinelforge.fly.dev/health
# Dashboard: https://sentinelforge.fly.dev/
```

We have `Dockerfile` (Python 3.12 slim, non-root appuser, git + gh CLI, healthcheck), `fly.toml` (app sentinelforge, region iad, port 8741, volume mount), `render.yaml` (Docker runtime), `.dockerignore`.

See `docs/DEPLOYMENT.md` for Fly.io, Render, AWS App Runner, Supabase schema deploy via SQL Editor.

## Datasets & Synthetic Data

This project uses **no external datasets or training data**. All test artifacts are synthetic and self-contained:

- **`examples/vulnerable_shop`** — A minimal FastAPI shop built specifically for this project. Contains a seeded BOLA vulnerability (`GET /orders/{order_id}` returns cross-tenant data) and synthetic test identities (`tenant-a-user`, `tenant-b-user`). The `ORDERS` dictionary is hardcoded mock data (two orders with different tenant associations).
- **`config/scope.yaml`** — Synthetic test identities with static headers (no real user data).
- **Dynamic provisioning** — The identity provisioner creates run-scoped fake accounts on the target using reserved `.invalid` TLD email addresses (`sf-{run_id}-owner@sentinelforge-test.invalid`) — these are never real mailboxes.
- **Cini Backend** (`Cini-Labs/Cini-BackEnd`) — The user's own deployed Django dating app. Scan/demo accesses its public API and Django source with the owner's explicit authorization and an ownership-verified scope. Attacks use dynamically provisioned synthetic accounts, not real user data.

**No real user data, credentials, or PII is ingested, stored, or exposed.** Secrets (API keys, JWTs) in env vars are gitignored via `.gitignore`. Receipts written to DB are redacted before storage (Bearer tokens, api keys, private keys scrubbed).

## Known Limitations

- **NemoClaw + OpenShell integration** is convention-based (YAML policy + homegrown enforcement engine) rather than vendor SDKs. The deny-by-default policy is genuinely enforced on all outbound HTTP, file writes, and subprocess calls; the integration badge is the checked-in `agents.yaml` roster + `HEARTBEAT.md` heartbeat.
- **Deep source-level BOLA detection** (AST analysis of handler ownership guards) supports FastAPI and Django only. Live adversarial testing (route mapping, auth/injection attacks, novel attack synthesis) works against **any** target exposing an OpenAPI 3.x spec, including Express and Spring Boot. Node.js/Java AST detectors are next.
- **vLLM integration** has a working HTTP client and NIM→vLLM failover architecture, but no live GPU benchmark artifact — the Brev GPU host was not provisioned within the 36-hour sprint. The sequential-vs-batched performance claim in the bench doc is informational.
- **Django BOLA detector** flags views that load objects by ID without explicit ownership checks. Public views (e.g., invite landing pages) may be false positives; each finding requires human triage as designed.
- **Attestation signing** uses `hmac-sha256-demo` (real hash chain, demo-grade crypto key) — production would use Ed25519 or a KMS-backed key.
- **SSE streaming** requires a persistent connection (works on Fly with `min_machines_running=1`). Page refresh while a run is in-progress is handled via localStorage resume.

## Next Steps (Post-Hackathon)

1. **Express & Spring Boot BOLA detectors** — extend the source-level AST to Node.js/Java.
2. **vLLM benchmark artifact** — provision a Brev GPU instance, run `sentinelforge bench`, publish latency chart.
3. **Supabase Postgres backend** — replace the demo SQLite store with the already-drafted Supabase schema (11 tables in `docs/supabase_schema.sql`) for multi-tenant SaaS.
4. **Redis pub/sub EventBus** — replace in-memory SimpleQueue for multi-machine SSE streaming.
5. **Ed25519 attestation signing** — upgrade from `hmac-sha256-demo` to real key-based signatures with a KMS adapter.
6. **OpenShell SDK integration** — replace the regex engine with the official OpenShell SDK when available.
7. **Real learning delta benchmarks** — accumulate metrics across many runs per target to surface statistically significant improvements (warm routes, payload selection convergence).
8. **CI/CD native integration** — one-click GitHub App install in CI/CD marketplaces.

## Test Suite

267 tests passing across 36 test files covering detectors, pentest, orchestrator, control plane, NIM, OpenShell, event bus (cross-thread regression), run deadline, PR generation, GitHub, intelligence, swarm, novel attacks, evidence bundles, identity provisioning, and enterprise hardening.

## Loom Presentation Script

See `docs/LOOM_SCRIPT.md` for the 4-minute demo script.
