# SentinelForge

SentinelForge is an autonomous adversarial release gate for teams shipping AI-generated code faster than human security teams can review it.

For every authorized release candidate, it maps the changed attack surface, dispatches bounded red-team agents, validates exploits with replayable evidence, runs NVIDIA Nemotron threat analysis, generates competing patches, attacks the patches again, runs the existing test suite, and produces a release security attestation. It supports both FastAPI and Django backends, integrates with GitHub for repository scanning and PR generation, and can generate CI/CD pipelines with built-in security gates.

Built for the **AITX Community x NVIDIA Claw Agent Hackathon**.

## Quick start

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
cp .env.example .env   # fill in your keys
.venv/bin/sentinelforge scan examples/vulnerable_shop
.venv/bin/sentinelforge remediate examples/vulnerable_shop
```

## Active pentesting

SentinelForge includes a full multi-agent pentest orchestrator with 6 enterprise modes:

```bash
# Run a standard pentest against a staging target
.venv/bin/sentinelforge pentest examples/vulnerable_shop \
  --scope config/scope.yaml \
  --mode standard

# Quick pre-commit scan (dependency + pattern only, no live probing)
.venv/bin/sentinelforge pentest examples/vulnerable_shop --mode quick

# Pre-release gate with mandatory block-on-findings
.venv/bin/sentinelforge pentest examples/vulnerable_shop --mode pre_release

# Schedule recurring scans
.venv/bin/sentinelforge pentest-schedule create \
  --repository examples/vulnerable_shop \
  --scope config/scope.yaml \
  --mode standard \
  --interval 60
```

### Pentest modes

| Mode | Description | Timeout |
|------|-------------|---------|
| `quick` | Dependency + pattern scan only, no live probing | 60s |
| `standard` | All agents, moderate depth, balanced | 300s |
| `full` | Deep pentest, no route limit, extended payloads | 900s |
| `targeted` | Auth + injection on discovered routes only | 180s |
| `pre_release` | Full scan with mandatory block-on-findings | 600s |
| `continuous` | Long-running monitoring with periodic re-evaluation | 1800s |

### Agent phases

Each pentest run executes these phases sequentially:

1. **Init** - Initialize run state
2. **Ownership verification** - Challenge-response proof (file, DNS, HTTP, API endpoint)
3. **Environment check** - Detect dev/staging/production via URL, headers, content signals
4. **Scoping** - Validates target boundaries, allowed hosts, rate limits
5. **Mapping** - Discovers API routes via OpenAPI + AST-based FastAPI scanner
6. **Dependency scan** - Cross-references packages against Red Hat Security Data API
7. **Pattern scan** - Detects 18 code-level exploit patterns (hardcoded secrets, unsafe deserialization, etc.)
8. **Auth attack** - Cross-tenant BOLA exploitation attempts
9. **Injection attack** - 10 payloads: prompt injection, SQL injection, XSS, SSRF, path traversal
10. **HiddenLayer scan** - Prompt injection and model I/O defense scanning
11. **OpenShell audit** - Policy enforcement verification
12. **NIM analysis** - NVIDIA Nemotron threat assessment of all findings
13. **Attestation** - Produces release verdict with evidence hashes

## NVIDIA Nemotron patch worker

SentinelForge uses NVIDIA NIM's OpenAI-compatible API for two purposes:

1. **Threat analysis** - Nemotron analyzes scan results and provides risk-level assessments, CVSS estimates, and remediation recommendations
2. **Patch proposals** - Nemotron generates bounded file replacements for confirmed findings

```bash
# Check NIM connectivity
.venv/bin/sentinelforge nim-health

# Compare Nemotron patches against deterministic baseline
.venv/bin/sentinelforge nim-remediate examples/vulnerable_shop
```

`NIM_BASE_URL` and `NIM_MODEL` are configurable. Without a key, the deterministic detection and remediation path remains fully operational.

## Control plane

Start the persisted local control plane:

```bash
.venv/bin/sentinelforge-api
```

### API endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Dashboard |
| `GET` | `/health` | Health check |
| `GET` | `/api/integrations` | Integration status |
| `POST` | `/api/runs` | Create detection run |
| `GET` | `/api/runs/{id}` | Get run status |
| `GET` | `/api/runs/{id}/events` | Get run events |
| `POST` | `/api/scan` | Scan a local repository |
| `POST` | `/api/scan/github` | Scan a GitHub repository |
| `POST` | `/api/pentest` | Create pentest run |
| `GET` | `/api/pentest` | List pentest runs |
| `GET` | `/api/pentest/{id}` | Get pentest run |
| `GET` | `/api/pentest/modes` | List available modes |
| `POST` | `/api/pentest/schedule` | Create recurring scan |
| `GET` | `/api/pentest/schedule` | List schedules |
| `DELETE` | `/api/pentest/schedule/{id}` | Delete schedule |
| `GET` | `/api/github/status` | GitHub token health |
| `GET` | `/api/github/repos` | List GitHub repositories |
| `POST` | `/api/github/create-pr` | Generate security fix PR |
| `POST` | `/api/ownership/challenge` | Create ownership challenge |
| `POST` | `/api/ownership/verify` | Verify ownership proof |
| `POST` | `/api/verify/start` | Start enterprise ownership verification |
| `POST` | `/api/verify/check` | Check ownership verification status |
| `GET` | `/api/verify/status` | Get verification status for a target |
| `POST` | `/api/environment/detect` | Detect target deployment environment |
| `GET` | `/api/environment/scan` | Scan codebase for environment hints |
| `POST` | `/api/cicd/generate` | Generate CI/CD pipeline |
| `GET` | `/api/intelligence/redhat` | Query Red Hat advisories |

## Django and FastAPI support

SentinelForge scans both framework types automatically:

```bash
# Scan detects FastAPI + Django URL patterns
.venv/bin/sentinelforge scan examples/vulnerable_shop

# Django BOLA detector parses urls.py patterns and checks for ownership guards
.venv/bin/sentinelforge scan /path/to/django-project
```

The Django detector parses `urls.py` patterns, identifies views that load objects without ownership checks, and flags potential broken object-level authorization (BOLA) vulnerabilities.

## GitHub integration

Connect to GitHub to list repositories, clone them, and scan remotely:

```bash
# List your repositories
.venv/bin/sentinelforge gh-list

# Clone and scan a GitHub repository
.venv/bin/sentinelforge gh-scan owner/repo
```

Set `GITHUB_TOKEN` in your `.env` to authenticate.

## PR generation

SentinelForge can automatically create pull requests with security fixes:

```bash
# Generate a security fix branch and PR
curl -X POST http://localhost:8741/api/github/create-pr \
  -H "Content-Type: application/json" \
  -d '{"repository": "/path/to/repo", "finding": {...}}'
```

Each PR includes a structured body with severity, rule ID, remediation steps, and a SHA-256 patch receipt.

## CI/CD pipeline generation

Generate security-integrated CI/CD pipelines for GitHub Actions, GitLab CI, or pre-commit hooks:

```bash
# Generate GitHub Actions workflow
curl -X POST http://localhost:8741/api/cicd/generate \
  -H "Content-Type: application/json" \
  -d '{"repository": "/path/to/repo", "platform": "github_actions"}'
```

Generated pipelines include automated scanning on PRs, scheduled pentests, and optional auto-patching.

## Ownership proof

Before scanning external targets, prove you own them:

```bash
# Create a file-based ownership challenge
curl -X POST http://localhost:8741/api/ownership/challenge \
  -H "Content-Type: application/json" \
  -d '{"target_path": "/path/to/target", "challenge_type": "file"}'

# Verify ownership after placing the challenge token
curl -X POST http://localhost:8741/api/ownership/verify \
  -H "Content-Type: application/json" \
  -d '{"target_path": "/path/to/target", "challenge_type": "file", "token": "..."}'
```

Supports file, DNS TXT, and HTTP endpoint challenge types.

## Integrations

- **GitHub** - Repository listing, cloning, and automated PR generation
- **NVIDIA Nemotron/NIM** - Agent reasoning, threat analysis, patch generation
- **OpenShell** - Policy-enforced execution sandboxes with deny-by-default
- **HiddenLayer** - Prompt injection and model I/O defense scanning
- **Red Hat Security Data API** - Live CVE/CSAF intelligence for dependency scanning
- **Supabase** - Cloud persistence for pentest results and run history

## Configuration

Copy `.env.example` to `.env` and fill in your keys:

```bash
SUPABASE_URL=...
SUPABASE_PUBLISHABLE_KEY=...
SUPABASE_SECRET_KEY=...
NVIDIA_API_KEY=...
NIM_BASE_URL=https://integrate.api.nvidia.com/v1
NIM_MODEL=nvidia/nemotron-3-nano-30b-a3b
HIDDENLAYER_API_KEY=...
GITHUB_TOKEN=...
```

The CLI and server automatically load a project-local `.env`.

## Safety boundary

SentinelForge targets only explicitly authorized staging environments and controlled repositories. The hackathon build excludes production penetration testing, destructive payloads, denial-of-service, persistence, and real data exfiltration. Merging and deployment always require human approval.

- Deny-by-default policy on all outbound requests
- Attacks only within sandbox/staging scope
- Rate-limited with configurable budgets
- Kill switch for immediate abort
- All actions produce SHA-256 evidence receipts

## What the system proves

- Deterministic BOLA detection from FastAPI routes and Django URL patterns
- Multi-vector exploitation with replayable evidence
- AI-powered threat analysis via NVIDIA Nemotron
- Dependency vulnerability cross-referencing against Red Hat advisories
- Code-level exploit pattern detection (18 patterns)
- Prompt injection defense via HiddenLayer
- Policy enforcement via OpenShell
- Enterprise ownership verification (ACME-style challenge-response)
- Deployment environment detection (dev/staging/production)
- CVE intelligence ingestion from NVD, KEV, and EPSS feeds
- Adaptive payload generation with Thompson Sampling
- Hypothesis-driven zero-day vulnerability exploration
- Persistent engagement memory across scans
- Automated PR generation with security patches and evidence
- CI/CD pipeline generation with built-in security gates
- Release security attestation with evidence hashes

## Architecture

```
sentinelforge/
  agents/           # Attack and analysis agents
    attacker.py     # Cross-tenant BOLA exploitation
    injection.py    # 10 injection payloads
    discovery.py    # Route discovery (OpenAPI + AST)
    dependencies.py # Dependency manifest parsing
    vuln_scanner.py # Red Hat CVE cross-reference
    exploit_patterns.py # 18 code-level patterns
    threat_analyzer.py  # NIM-powered threat analysis
  detectors/        # Framework-specific vulnerability detectors
    fastapi_bola.py # FastAPI route BOLA detection
    django_bola.py  # Django URL pattern + BOLA detection
  integrations/     # External service adapters
    github.py       # GitHub API client (repos, clone)
    hiddenlayer.py  # Prompt injection scanning + environment detection
    openshell.py    # Policy enforcement
    red_hat.py      # Security data API
    supabase.py     # Cloud persistence
  intelligence/     # Adaptive threat intelligence engine
    cve_ingestion.py    # NVD/KEV/EPSS feed ingestion
    threat_learning.py  # Pattern extraction from CVEs and scans
    adaptive_payloads.py # Thompson Sampling-inspired payload selection
    engagement_memory.py # Persistent memory across engagements
    zero_day_hunter.py  # Hypothesis-driven vulnerability exploration
  monitoring/       # Continuous security monitoring
    continuous_scanner.py # Scheduled scan management
    threat_feed.py   # Multi-source threat feed aggregation
  control/          # API and storage
    api.py          # FastAPI control plane (scan, pentest, GitHub, ownership, verification, environment, CI/CD)
    storage.py      # SQLite event store
    models.py       # Pydantic models
  inference/        # NIM patch proposals
    nvidia_nim.py   # NVIDIA NIM adapter
  verification.py   # Enterprise ownership verification (ACME-style challenge-response)
  environment.py    # Deployment environment detection (dev/staging/production)
  web/static/       # Dashboard SPA (5 views: Scan, Release Proof, Pentest, Schedule, Settings)
  orchestrator.py   # Phase-based agent orchestration (14 phases including ownership + environment)
  pentest.py        # Pentest service with ownership and environment handlers
  pentest_modes.py  # 6 enterprise pentest modes with ownership/environment flags
  scheduler.py      # Recurring scan scheduler
  ownership.py      # Ownership proof (file, DNS, HTTP challenges)
  pr_generator.py   # GitHub PR generation with security fixes
  cicd.py           # CI/CD pipeline templates (GitHub Actions, GitLab CI, pre-commit)
  scope.py          # Scope config with allow_production flag
  cli.py            # Command-line interface
```

See [docs/PLAN.md](docs/PLAN.md) for the full implementation plan.

## Iteration policy

Every implementation must pass its relevant checks before it is committed and pushed. Each iteration should be independently demoable or provide a verified foundation for the next vertical slice.
