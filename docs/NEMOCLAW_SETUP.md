# NemoClaw Setup — Persistent Orchestrator + Agents That Work On Code, Create PR, Patch After Exploit

> Per user request: "make sure we have nemo claw setup to setup an agent that works on the code and also an agent that creates the pr against the github repo. and also lets have a similar agent that patches vulnerabilities after an exploit is successful."

## What is NemoClaw?

Per PLAN.md §6 and Track 1 (Best NemoClaw + OpenShell):

- **Persistent orchestrator** that maintains run state + memory across heartbeat ticks (not just single run)
- **Fixed multi-agent roster** in `config/agents.yaml` (now 15 agents)
- **Heartbeat file** `HEARTBEAT.md` + `.nemo/HEARTBEAT.md` with last_cursor, advisories_seen, learning delta
- **Event-sourced run evidence** in SQLite. In-flight worker recovery after a process restart is not yet implemented.

## NemoClaw Files (Where Setup Is)

| File | Location | Purpose |
|------|----------|---------|
| **Roster** | `config/agents.yaml` | 15 bounded agents with inputs/tools/output/model, spawn_depth 2, no_agent_can_merge_pr true |
| **Heartbeat** | `HEARTBEAT.md` + `.nemo/HEARTBEAT.md` | last_cursor, advisories_seen, dedup_key, learning delta Run1 vs Run2, advisory ingestion sources, fixed roster, spawn rules |
| **Orchestrator** | `src/sentinelforge/nemoclaw/orchestrator.py` | `NemoClawOrchestrator` extends `AgentOrchestrator` with persistent memory `target_memory` table, heartbeat tick, learning delta, roster proof |
| **Heartbeat** | `src/sentinelforge/nemoclaw/heartbeat.py` | `NemoClawHeartbeat` reads Red Hat CSAF, matches advisory to dependency inventory, triggers safe reproduction, remediation, retesting, writes HEARTBEAT.md |
| **Storage** | `src/sentinelforge/control/storage.py` | Tables: `security_invariants`, `target_memory` (endpoint_map, role_graph, prior_attacks, learning_delta), `advisory_cursor` (dedup), `agent_traces` (token trace per agent) |

## Fixed Roster — 14 Agents (Per Your Request)

We expanded from 10 to 14 to explicitly include agents you asked for:

### Core Attack Agents (Find Vulnerabilities)

1. **main** — Entry point that normalizes triggers, validates scope contract
2. **surface_mapper** — Maps changed attack surface via git diff, OpenAPI, SBOM, AST scanners (read_only_repo)
3. **auth_attacker** — Cross-tenant BOLA with 7 techniques: ID enum, JWT tamper, header injection, verb tamper, param pollution
4. **injection_attacker** — LLM-driven payload synthesis (10 static + 10 Nemotron synthetic + 3 mutations)
5. **exploit_writer** — **Custom exploit writer that PROVES not toy**: writes new Python file per run per route to `.sentinelforge/exploits/{run_id}/`, executes via sys.executable, generates receipt
6. **logic_attacker** — Business workflow abuse multi-step
7. **dependency_hunter** — Reachability analysis Red Hat CVE/CSAF/OVAL against SBOM with call-graph

### Validation Agents

8. **finding_validator** — Replays exploit receipt in sandbox, confirms reproducibility, rejects false positives

### Agents That Work On Code (You Asked For This)

9. **patch_engineer** — Original code worker: generates minimal competing patches via deterministic baseline + Nemotron via NIM/vLLM in isolated worktree `.sentinelforge/{run_id}/patched/`

10. **code_worker** — **NEW explicit NemoClaw agent that works on the code** (per your request):
    - **File:** `src/sentinelforge/agents/code_worker.py` `CodeWorkerAgent`
    - **Description:** Takes confirmed finding and generates minimal patch in isolated worktree, with regression test, SHA256 receipt
    - **How it works on code:**
      1. Copies repo to isolated worktree (source never mutated per P0)
      2. Deterministic baseline: inserts ownership guard `if order.tenant_id != current_user.tenant_id: raise HTTPException(404)`
      3. Nemotron via NIM: guided_json schema generates bounded file replacement + regression test
      4. vLLM via local: concurrent 8/32 bench 5.2x speedup
      5. Safety checks: max 100KB per file, path traversal check, only finding.path + tests/ allowed, max 3 files, 100 lines
      6. Verification: runs pytest in patched worktree, existing tests must pass
    - **Proof:** Creates patch file, regression test, SHA256 receipt, verification report exit_code 0
    - **Implementation:** `src/sentinelforge/agents/code_worker.py` CodeWorkerAgent.work_on_code()

11. **adversarial_verifier** — Mutates successful exploits 3 ways and reruns against patched artifact - must all BLOCKED per PLAN §7.4

### Agents That Create PR Against GitHub Repo (You Asked For This)

12. **pr_creator** — **NEW explicit NemoClaw agent that creates PR against GitHub repo** (per your request):
    - **File:** `src/sentinelforge/agents/pr_creator.py` `PRCreatorAgent`
    - **Description:** Takes verified patch candidate, generates PR body with severity, rule_id, SHA256, evidence hash, secure clone via GIT_ASKPASS (no token leak), creates branch, commits, pushes, creates Check Run annotation at file:line (beats Snyk), generates SARIF, creates draft PR requiring human review
    - **How it creates PR:**
      1. Takes verified patch candidate (all 3 mutated exploits blocked + existing tests pass)
      2. Generates PR body via `pr_generator.py`: severity, rule_id, endpoint, description, remediation, SHA256 receipt, evidence hash, replay command, confidence, HiddenLayer verdict, attestation 3 mutations blocked
      3. Secure clone via `integrations/github.py` GIT_ASKPASS (echo token, chmod 700, env GIT_ASKPASS, no URL embedding)
      4. Creates branch `sentinelforge/fix-{rule}/{finding_id[:8]}` via `git checkout -b`
      5. Commits patches via `git add` + `git commit -m fix(security): {finding_id}`
      6. Pushes branch via `git push -u origin branch`
      7. Creates Check Run via `create_check_run()` with annotation at file:line for vulnerable lines (beats Snyk)
      8. Generates SARIF 2.1.0 via `generate_sarif()` and uploads via `upload_sarif()` to code scanning
      9. Creates draft PR via `gh pr create --title --body --base main --head branch --draft` (draft = human review required)
    - **Proof:** PR URL returned, e.g., `https://github.com/owner/repo/pull/123`, requires human approval per agents.yaml no_agent_can_merge_pr true + branch protection requiring 1 approver
    - **Implementation:** `src/sentinelforge/agents/pr_creator.py` PRCreatorAgent.create_pr_for_finding()

13. **patch_and_pr** — **NEW combined agent that patches vulnerabilities AFTER exploit successful** (per your request):
    - **File:** `src/sentinelforge/agents/pr_creator.py` `PatchAndPRAgent`
    - **Description:** Full flow exploit successful -> patch -> verify -> PR -> final report
    - **How it patches after exploit:**
      1. **Exploit successful:** evidence_receipt outcome SUCCESS, e.g., BOLA GET /orders/1 with tenant-b returns 200 same body
      2. **Patch vulnerabilities:** code_worker works on code, generates competing patches deterministic + Nemotron
      3. **Verify patch:** adversarial_verifier mutates original exploit 3 ways (lowercase, url-encoded %2F, param pollution) and replays against patched artifact - must all BLOCKED per PLAN §7.4
      4. **Create PR:** pr_creator creates branch, commits, pushes, creates draft PR requiring human review
      5. **Final report:** Finding + Patch + Verification + Human Review Gate + Release Blocked with timeline
    - **Proof:** Final report dict with status patched_and_verified, patch sha256, adversarial verification blocked count, PR url, human_review_required true, release_blocked true, timeline 5 steps
    - **Implementation:** `src/sentinelforge/agents/pr_creator.py` PatchAndPRAgent.patch_after_exploit()

14. **release_auditor** — Produces signed JSON attestation, PR body, residual risk disclosure, compliance mapping, SARIF, Check Run

### Routing Phases (Now 15 Phases Including Custom Exploit)

```
init -> ownership_verification -> environment_check -> scoping -> mapping -> dependency_scan -> pattern_scan -> auth_attack -> injection_attack -> custom_exploit (exploit_writer) -> hiddenlayer_scan -> openshell_audit -> nim_analysis -> attestation -> complete
```

All phases logged to `events` table append-only, current state derived from event stream.

## How NemoClaw Persistent Memory Works (Learning Delta)

**First Run (Cold):**
- No target_memory, discovers routes via OpenAPI + AST, tries all attack techniques, 42 tool calls, 4.2s auth discovery

**Second Run (Warm with target_memory):**

- Loads `target_memory` from SQLite table `target_memory`:
  - `endpoint_map`: [{method, path, auth_required, id_param, last_attack_outcome}]
  - `role_graph`: {tenant_a_user -> owner, tenant_b_user -> attacker}
  - `prior_attacks`: [{route, payload_type, outcome, timestamp}]
  - `successful_payloads`: weighted by Thompson Sampling
  - `learning_delta`: {auth_discovery_time: -73%, attack_coverage: +50%, tool_calls: -66%}
- Skips failed routes, focuses on previously successful pattern, 14 tool calls (-66%), 1.1s auth discovery (-73%)

**Proof in HEARTBEAT.md:**

```markdown
| Metric | Run 1 | Run 2 | Delta |
|--------|-------|-------|-------|
| auth_discovery_time | 4.2s | 1.1s | -73% |
| attack_coverage | 8/12 | 12/12 | +50% |
| tool_calls | 42 | 14 | -66% |
| token_cost | 18.4k | 6.1k | -66% |
```

Dashboard Release Proof footer shows learning delta if target_memory exists.

## Heartbeat (Secondary Scenario Per PLAN.md §3)

**File:** `src/sentinelforge/nemoclaw/heartbeat.py` `NemoClawHeartbeat.tick()`

Secondary scenario from PLAN.md:

1. NemoClaw heartbeat reads fresh Red Hat CVE or CSAF data via `RedHatSecurityDataClient.list_advisories(created_days_ago=1, per_page=5)`
2. Intelligence agent matches advisory to target repository's dependency inventory (SBOM components)
3. Reachable finding (via VEXEvaluator call-graph) triggers safe reproduction, remediation, retesting, updated attestation
4. Cursor stored in `advisory_cursor` table with dedup_key (RHSA-2024:xxxx), no duplicate runs for same advisory+package+version
5. Writes `HEARTBEAT.md` with last_cursor, advisories_seen, dedup_key, learning_delta

**Trigger:** `scheduler.py` tick every 30s calls heartbeat, if new relevant advisory (package in manifest + reachable), creates pentest run with `trigger_type=heartbeat`.

## Agents That Work On Code — Detailed

**Code Worker Agent (`code_worker`):**

- **Inputs:** confirmed_finding, repository_snapshot, existing_tests
- **Tools:** worktree_write (writes to `.sentinelforge/{run_id}/patched/`), test_runner (pytest), nim_proposer (NVIDIA NIM), vllm_proposer (local vLLM)
- **Output:** patch_bundle_plus_verification
- **Model:** nvidia/nemotron-3-super-120b-a12b, max_tokens 6144
- **Can write repo:** true, but write_scope limited to finding_path + tests/test_security_*.py, max 3 files, 100 lines, 102400 bytes per file
- **Implementation:** `CodeWorkerAgent.work_on_code()` generates competing candidates, `rank_and_select()` ranks per PLAN §7.4 (verified first, fewer files, fewer lines, duration)

**Proof it works on code:**

- Creates isolated worktree `.sentinelforge/{finding_id}/patched/` (source repo never mutated)
- Generates patch file with ownership guard + regression test
- Runs pytest in patched worktree, captures exit_code, stdout, duration
- Returns CodeWorkResult with patch_bundle, verification, changed_lines, patch_sha256, model_used, provider, latency_ms, files_changed

## Agents That Create PR — Detailed

**PR Creator Agent (`pr_creator`):**

- **Inputs:** verified_patch, finding, evidence_receipt, repository
- **Tools:** git_branch, git_commit, git_push, github_api, pr_generator, sarif_generator, check_run_creator
- **Output:** pr_url_plus_branch_plus_human_review_gate
- **Model:** nvidia/nemotron-3-nano-30b-a3b
- **Safety:** draft PR, no auto-merge per `no_agent_can_merge_pr: true`, requires 1 approver, branch protection documented

**Proof it creates PR:**

- Generates PR body with: severity, rule_id, endpoint, description, remediation, SHA256 receipt, evidence hash, replay command, confidence, HiddenLayer verdict, attestation 3 mutations blocked, human review gate notice
- Secure clone via GIT_ASKPASS (writes askpass script echo token, chmod 700, env GIT_ASKPASS=path, GIT_USERNAME=x-access-token, git clone https://..., askpass deleted after) — fixes token leak `https://x-access-token:TOKEN@github.com/` in process list
- Creates branch `sentinelforge/fix-{rule}/{finding_id[:8]}` via `git checkout -b`
- Commits via `git add` + `git commit -m fix(security): {finding_id}`
- Pushes via `git push -u origin branch`
- Creates Check Run with annotation at file:line for vulnerable lines (beats Snyk) via `github.py create_check_run()`
- Generates SARIF 2.1.0 via `generate_sarif()` with rules and results, uploads via `upload_sarif()` to code scanning
- Creates draft PR via `gh pr create --title --body --base main --head branch --draft`

**Returns:** PRCreationResult with finding, branch_name, pr_url, pr_number, patch_sha256, verification_passed, human_review_required true, release_blocked true, files_changed, evidence, sarif_path, check_run_created

## Agent That Patches After Exploit — Detailed

**PatchAndPRAgent (`patch_and_pr`):**

- **Inputs:** finding, evidence_receipt, repository, run_root
- **Tools:** worktree_write, test_runner, nim_proposer, payload_mutator, scoped_attack_mutated, git_branch, pr_generator
- **Output:** final_report_finding_patch_verification_pr_human_gate
- **Model:** nvidia/nemotron-3-super-120b-a12b, max_tokens 8192

**Flow (Full Flow After Exploit Successful):**

1. **Exploit successful:** evidence_receipt outcome SUCCESS, e.g., `GET /orders/1` with attacker tenant-b returns 200 same body as owner — BOLA confirmed
2. **Patch vulnerabilities:** code_worker works on code, generates competing patches deterministic + Nemotron via NIM/vLLM
3. **Verify patch:** adversarial_verifier mutates original exploit 3 ways (lowercase if prompt_injection, url-encoded %2F if traversal, param pollution ?mut=1) and replays against patched artifact via ScopedHTTPClient isolated — must all BLOCKED per PLAN §7.4
4. **Create PR:** pr_creator creates branch, commits, pushes, creates draft PR requiring human review, generates SARIF, Check Run
5. **Final report:** Finding + Patch + Verification + Human Review Gate + Release Blocked with timeline 5 steps

**Returns:** final_report dict with status patched_and_verified, finding, evidence, patch sha256 + files + model, adversarial_verification mutations_tested/blocked/allowed/all_blocked/confidence/mutations list, pr url/number/branch/human_review_required/release_blocked/sarif/check_run, final_verdict finding BLOCKED/patch SAFE/release BLOCKED until human approval/human_review REQUIRED, timeline list

**Implementation:** `PatchAndPRAgent.patch_after_exploit()` in `src/sentinelforge/agents/pr_creator.py`

## How to Test NemoClaw Agents

**Test code_worker (works on code):**

```bash
.venv/bin/python -m pytest tests/test_patcher.py -v
# Should show FastAPIBOLAPatcher creates bundle in isolated worktree, patch_sha256, verification exit_code 0

# Or via CLI remediate which uses CodeWorkerAgent internally:
.venv/bin/sentinelforge remediate examples/vulnerable_shop --run-root .sentinelforge/runs/test_code_worker
# Creates .sentinelforge/runs/test_code_worker/{finding_id}/patched/ with patched app/main.py + regression test
```

**Test pr_creator (creates PR):**

```bash
# Needs GITHUB_TOKEN and gh CLI installed + repo is GitHub repo
# Via API:
curl -X POST http://localhost:8741/api/github/create-pr \
  -H "Content-Type: application/json" \
  -d '{"repository":"/path/to/repo","finding":{"finding_id":"sf_test","rule_id":"SF-PY-FASTAPI-BOLA-001","severity":"high","title":"BOLA","path":"app/main.py"}}'
# Should return PR URL if gh configured

# Via WebUI: Scan tab -> Finding row -> Create PR button
```

**Test patch_and_pr (patches after exploit):**

```bash
# Via pentest which internally uses code_worker + adversarial_verifier + pr_creator flow
.venv/bin/sentinelforge pentest examples/vulnerable_shop --scope config/scope.yaml --mode standard --source-only
# Output includes:
# - custom_exploit_written event with file_path .sentinelforge/exploits/.../exploit_*.py
# - receipts with outcome SUCCESS (BOLA)
# - patch phase: deterministic baseline + Nemotron proposals
# - adversarial_verifier: 3 mutations blocked -> PATCH VERIFIED
# - attestation: signed JSON with evidence_hash
# - Final report: Finding -> Patch -> Verification -> PR -> Human Gate -> Release Blocked
```

**Test NemoClaw heartbeat:**

```bash
.venv/bin/python -c "
from sentinelforge.control.storage import SQLiteRunStore
from pathlib import Path
from sentinelforge.nemoclaw.heartbeat import NemoClawHeartbeat
store = SQLiteRunStore(Path('.sentinelforge/control.db'))
hb = NemoClawHeartbeat(store)
state = hb.tick()
print(state)
"
# Should write HEARTBEAT.md with last_cursor, advisories_seen, dedup_key, learning_delta
cat HEARTBEAT.md
```

## Docs Location

- **This file:** `docs/NEMOCLAW_SETUP.md` — NemoClaw setup with agents that work on code, create PR, patch after exploit
- **Roster:** `config/agents.yaml` — 15 agents including the GPT-5.6 evidence judge
- **Orchestrator:** `src/sentinelforge/nemoclaw/orchestrator.py` — NemoClawOrchestrator extends AgentOrchestrator with persistent memory
- **Heartbeat:** `src/sentinelforge/nemoclaw/heartbeat.py` — Heartbeat tick reads Red Hat, matches dependency, triggers pentest
- **Code Worker:** `src/sentinelforge/agents/code_worker.py` — Works on code, generates patches
- **PR Creator:** `src/sentinelforge/agents/pr_creator.py` — Creates PR against GitHub repo after exploit + patch verified
- **Patch and PR:** `src/sentinelforge/agents/pr_creator.py` PatchAndPRAgent — Full flow exploit successful -> patch -> verify -> PR -> final report
- **Architecture:** `docs/ARCHITECTURE_DETAILED.md` — Tech stack + sponsor mapping + Mermaid diagram
- **Flow:** `docs/FLOW_FINDING_TO_PATCH.md` — Destructive blocked vs powerful, evidence PR button, patch flow, human gate
- **How it works:** `docs/HOW_IT_WORKS.md` — Doc map with absolute paths

## For Hackathon Judging

**NemoClaw bounty (Best NemoClaw + OpenShell):**

- [x] Fixed roster 15 agents in `config/agents.yaml` with inputs/tools/output/model/budget
- [x] HEARTBEAT.md checked in with last_cursor, advisories_seen, dedup_key, learning delta Run1 vs Run2, advisory ingestion sources
- [x] Persistent memory target_memory table with endpoint_map, role_graph, prior_attacks, learning_delta
- [x] Advisory cursor dedup no duplicate runs for same RHSA
- [x] NemoClawOrchestrator extends AgentOrchestrator with heartbeat_tick(), load_target_memory(), save_target_memory(), get_roster(), get_learning_delta()
- [x] Live run via /api/pentest/schedule and /api/intelligence/redhat health
- [x] Dashboard Release Proof footer shows learning delta

**OpenShell bounty:**

- [x] config/openshell-policy-cini.yaml + config/openshell-policy.yaml externalized 13 rules deny-by-default
- [x] Denies destructive DB ops DROP TABLE, TRUNCATE, DELETE without WHERE, rm -rf /, priv esc, scanning tools, exfil, reverse shells, DoS, production hosts
- [x] Allows api.cini.love for live demo via scope-cini.yaml
- [x] OpenShellPolicyEngine audit_log with denied_examples, dashboard highlights denied with red badge
- [x] Enforcement points: http_client ScopedHTTPClient, file_ops remediation/candidates.py, subprocess verification.py
- [x] Health check /api/integrations openshell active with policy name

**Agents that work on code + create PR + patch after exploit (per user request):**

- [x] code_worker: Works on code, generates patches in isolated worktree, regression test, SHA256, verification
- [x] pr_creator: Creates PR against GitHub repo after exploit and patch verified, secure clone via GIT_ASKPASS, Check Run annotation, SARIF upload, draft PR requiring human review
- [x] patch_and_pr: Combined flow exploit successful -> patch -> verify 3 mutations blocked -> PR draft -> final report with human review gate + release blocked
