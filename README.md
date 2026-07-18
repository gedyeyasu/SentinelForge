# SentinelForge

SentinelForge is an autonomous adversarial release gate for teams shipping AI-generated code faster than human security teams can review it.

For every authorized release candidate, it maps the changed attack surface, dispatches bounded red-team agents, validates exploits with replayable evidence, runs NVIDIA Nemotron threat analysis, generates competing patches, attacks the patches again, runs the existing test suite, and produces a release security attestation.

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

1. **Scoping** - Validates target boundaries, allowed hosts, rate limits
2. **Mapping** - Discovers API routes via OpenAPI + AST-based FastAPI scanner
3. **Dependency scan** - Cross-references packages against Red Hat Security Data API
4. **Pattern scan** - Detects 18 code-level exploit patterns (hardcoded secrets, unsafe deserialization, etc.)
5. **Auth attack** - Cross-tenant BOLA exploitation attempts
6. **Injection attack** - 10 payloads: prompt injection, SQL injection, XSS, SSRF, path traversal
7. **HiddenLayer scan** - Prompt injection and model I/O defense scanning
8. **OpenShell audit** - Policy enforcement verification
9. **NIM analysis** - NVIDIA Nemotron threat assessment of all findings
10. **Attestation** - Produces release verdict with evidence hashes

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
| `POST` | `/api/pentest` | Create pentest run |
| `GET` | `/api/pentest` | List pentest runs |
| `GET` | `/api/pentest/{id}` | Get pentest run |
| `GET` | `/api/pentest/modes` | List available modes |
| `POST` | `/api/pentest/schedule` | Create recurring scan |
| `GET` | `/api/pentest/schedule` | List schedules |
| `DELETE` | `/api/pentest/schedule/{id}` | Delete schedule |
| `GET` | `/api/intelligence/redhat` | Query Red Hat advisories |

## Integrations

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

- Deterministic BOLA detection from actual FastAPI routes
- Multi-vector exploitation with replayable evidence
- AI-powered threat analysis via NVIDIA Nemotron
- Dependency vulnerability cross-referencing against Red Hat advisories
- Code-level exploit pattern detection (18 patterns)
- Prompt injection defense via HiddenLayer
- Policy enforcement via OpenShell
- Minimal patched artifact with regression tests
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
  integrations/     # External service adapters
    hiddenlayer.py  # Prompt injection scanning
    openshell.py    # Policy enforcement
    red_hat.py      # Security data API
    supabase.py     # Cloud persistence
  control/          # API and storage
    api.py          # FastAPI control plane
    storage.py      # SQLite event store
    models.py       # Pydantic models
  inference/        # NIM patch proposals
    nvidia_nim.py   # NVIDIA NIM adapter
  web/static/       # Dashboard SPA
  orchestrator.py   # Phase-based agent orchestration
  pentest.py        # Pentest service
  pentest_modes.py  # 6 enterprise pentest modes
  scheduler.py      # Recurring scan scheduler
  cli.py            # Command-line interface
```

See [docs/PLAN.md](docs/PLAN.md) for the full implementation plan.

## Iteration policy

Every implementation must pass its relevant checks before it is committed and pushed. Each iteration should be independently demoable or provide a verified foundation for the next vertical slice.
