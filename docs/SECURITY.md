# Security & Safety Boundary — SentinelForge

Per README.md and PLAN.md §7.2 / §18, this document defines what SentinelForge does NOT do.

## Allowed Targets Only

- Only explicitly authorized staging, sandbox, local, or development environments
- Production hosts are denied by default via `config/openshell-policy.yaml` rule `Block production host access`
- Allowed hosts must be listed in `config/scope.yaml` allowed_hosts; default is `127.0.0.1, localhost`
- `allow_destructive_payloads`, `allow_denial_of_service`, `allow_persistence`, `allow_data_exfiltration` are all false and enforced in policy engine

## What Is NOT In Scope for Hackathon

Per PLAN.md §18:

- Production penetration testing
- Destructive payloads, denial-of-service, persistence, or real data exfiltration
- General guarantees of zero-day discovery or complete security
- Automatic merging or production deployment
- Broad support for every language and framework
- Enterprise SSO, billing, multi-region
- Full network and Active Directory pentesting
- Autonomous model-weight training

## Enforcement Layers

### 1. Scope Validation (`scope.py`)
- Validates YAML, checks allowed_hosts not containing prod keywords, forbidden_paths enforced
- Test identities must be synthetic, not real users

### 2. Policy Engine (`policy.py` + `openshell.py`)
- Deny-by-default: any operation not explicitly allowed is denied
- Network: only 127.0.0.1, localhost, 0.0.0.0 allowed, private ranges blocked unless explicitly allowed
- Filesystem: writes only allowed in isolated worktree `.sentinelforge/*/patched/` and tests/
- Process: blocks sudo, su, chmod 777, nmap, masscan, sqlmap, hydra
- Exfiltration: blocks curl/wget to pastebin, ngrok, burpcollaborator, webhook.site
- Destructive: blocks rm -rf /, /etc/passwd write, mkfifo shells

### 3. Scoped HTTP Client (`agents/http.py`)
- Every request checked via PolicyEngine before DNS/HTTP
- Rate limit 3rps default, max_total_requests 300
- Kill switch file `.sentinelforge/STOP` - existence immediately aborts pending workers

### 4. OpenShell Policy Adapter (`integrations/openshell.py`)
- Externalized to `config/openshell-policy.yaml`
- Audits all denied actions to `.sentinelforge/openshell_audit.jsonl`
- Dashboard highlights denied with reason for judge evidence of blocked out-of-scope action per P1 #4

### 5. Secret Redaction (`redaction.py`)
- Regex patterns for Bearer tokens, api_key, GITHUB_TOKEN, NVIDIA_API_KEY, gh_* tokens, private keys
- Redacted before persistence in events table, receipts, PR bodies, attestations
- `assert_no_secrets` gate before push and PR creation - blocks if secret detected
- Request headers in receipts: Authorization, x-api-key, Cookie redacted to [REDACTED_SECRET]

### 6. Ownership Verification (`verification.py` + `ownership.py`)
- Before scanning external target, must prove ownership via challenge-response:
  - file: place token file in target path
  - dns: TXT record
  - http: endpoint returning token
  - api: challenge file via API
- Environment detection (environment.py) classifies target as dev/staging/production with confidence; production blocked unless explicitly allowed

### 7. Evidence Standard (PLAN §7.3)
A finding confirmed only when all 8 present:
1. Exact target and endpoint
2. Preconditions and synthetic identity
3. Sanitized request/response (secrets redacted)
4. Expected invariant
5. Observed violation
6. Replay command (curl, only inside sandbox)
7. Confidence and severity rationale
8. HiddenLayer verdict

If any missing, finding marked unconfirmed and cannot generate PR per critical deterministic case #8.

### 8. Patch Standard (PLAN §7.4)
Candidate eligible only when:
1. Original exploit fails after change
2. At least 3 safe mutations also fail (adversarial_verifier.py)
3. Existing tests pass
4. Permanent regression test added
5. Static and dependency scans do not regress
6. Diff limited to smallest blast radius (<100 lines, <3 files)
7. Residual risk disclosed

### 9. Human Approval Gate
- No agent can merge PR - enforced in agents.yaml no_agent_can_merge_pr true
- PR creation requires human approval via dashboard button or `gh pr create` manual
- Deployment always requires human approval per README
- All merge/deploy actions log to audit trail

### 10. Signed Attestation (`attestation.py`)
- Attestation JSON includes event chain hash (prev_hash linking)
- Signed with HMAC-SHA256 via keypair in `.sentinelforge/keys/` (prod: Ed25519 via KMS)
- Signature verified in dashboard
- Tamper detection: changing any event breaks chain head hash

## Critical Deterministic Cases (PLAN §13)

Tested in tests/:

1. Out-of-scope host blocked before DNS - policy decision checked before httpx call
2. Production-looking host rejected even when supplied by model output - environment detection + deny rule
3. Malicious repository instructions quarantined by HiddenLayer - local pattern scan
4. Invalid model tool calls cannot execute - guided_json schema validation
5. Kill switch stops pending workers - file existence check in orchestrator
6. Duplicate heartbeat advisory does not create duplicate runs - advisory_cursor dedup_key
7. Candidate patch that breaks existing tests rejected - verification step
8. Finding without replayable evidence is unconfirmed - finding_validator
9. Secrets absent from persisted events and PR content - redaction + assert_no_secrets
10. Restarting control plane reconstructs active run state from events - append-only event store

## Reporting Vulnerabilities

For this hackathon build, do not report via public issue. Contact via GitHub Security tab private advisory.

## Compliance Mapping (Future SaaS)

- SOC2 evidence pack: 8-field receipt + signed attestation + hash chain
- ISO27001: A.14.2.3 technical compliance review via automated gate
- SSDF: PO.3.2, PS.1, PW.4 via CI/CD pipeline generation
