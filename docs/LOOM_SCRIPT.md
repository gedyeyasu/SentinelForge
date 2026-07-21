# SentinelForge: four-minute Loom recording script

> **Legacy AITX submission artifact.** Do not use this script for OpenAI Build Week. The current requirement is a public or unlisted YouTube video under three minutes; use [`YOUTUBE_SCRIPT.md`](YOUTUBE_SCRIPT.md).

This is the truth-checked presenter script for the AITX Community x NVIDIA
Claw Agent Hackathon. The target length is four minutes and thirty seconds.
Keep the camera bubble on, speak conversationally, and leave the cursor beside
the evidence you are describing.

## Submission identity

- **Project title:** SentinelForge — Proof-Carrying Autonomous Security Gate
- **Team name:** SentinelForge
- **Track selected:** Red Hat Live Data
- **Sponsor bounties to claim:** Best Nemotron and Most Commercializable
- **Team roster:** Gedeon Tona — product, artificial intelligence, security,
  backend, frontend, and deployment — `gedyeyasu@gmail.com`
- **Public repository:** <https://github.com/gedyeyasu/SentinelForge>
- **Deployed application:** <https://sentinelforge.fly.dev/>

Do not submit for the NemoClaw plus OpenShell, HiddenLayer, or vLLM bounties
unless the runtime status changes described in **Exact sponsor claims** below.

## Before recording

1. Use Loom and confirm the microphone, camera bubble, and screen capture are
   active. The submitted video must be between two and five minutes.
2. Open the deployed application at <https://sentinelforge.fly.dev/> in a
   desktop browser at approximately 90 percent zoom.
3. Open a second tab with this completed run's NVIDIA trace:
   <https://sentinelforge.fly.dev/api/pentest/sf_pentest_b4a98345ae88/traces>.
4. Open a terminal in the SentinelForge repository and increase the font size.
   Do not open `.env`, Fly secrets, GitHub tokens, or private configuration.
5. In the application, open **Scan**, choose **GitHub Repository**, refresh the
   repository list, and filter it to `SentinelForge`. This prevents unrelated
   private repository names from appearing in the video.
6. In a separate application tab, open **Pentest**, select completed run
   `B4A98345AE88`, and scroll to **Custom Exploits Written by Agent**.
7. In another application tab, open **Release Proof** and keep the real Red Hat
   advisory panel visible. Do not start a deployed proof run during the video.
8. Confirm the local deterministic remediation succeeds before recording:

   ```bash
   DEMO_RUN_ROOT=$(mktemp -d /tmp/sentinelforge-loom.XXXXXX)
   .venv/bin/sentinelforge remediate examples/vulnerable_shop \
     --run-root "$DEMO_RUN_ROOT" --timeout 90
   ```

   The final output must say `"status": "verified"`, both verification checks
   must be `true`, and four tests must pass.

## Know the application before recording

- **Scan:** scans a local repository or securely clones an authorized GitHub
  repository. It runs FastAPI and Django authorization detectors, code-pattern
  checks, dependency parsing, and vulnerability correlation.
- **Release Proof:** detects a supported defect, creates a patch in an isolated
  copy, generates a regression test, runs the repository tests, and blocks the
  release if verification fails. The deployed container currently lacks
  `pytest`, so use the verified local command for this portion of the video.
- **Pentest:** maps routes, runs bounded authentication and injection agents in
  parallel, synthesizes new attack hypotheses, generates route-specific Python
  exploit files with Nemotron, applies safety policy, and creates signed
  evidence.
- **Schedule:** stores recurring pentest definitions. The deployed list request
  currently returns 404 because of route ordering, so do not show this view.
- **Settings:** reports GitHub and NVIDIA configuration and generates continuous
  integration and continuous delivery workflow files.

## 0:00–0:30 — Problem, product, and track

**Show:** Start on the deployed dashboard with the SentinelForge name, the
execution lane, and the five application views visible.

**Say:**

> I am Gedeon Tona, and this is SentinelForge, an autonomous security release
> gate for teams shipping artificial-intelligence-generated code faster than a
> human security team can review it. Existing scanners often stop at a ticket.
> SentinelForge turns an authorized release into evidence: detect the defect,
> attempt a bounded exploit, create an isolated patch and regression test,
> verify the exact artifact, and require a human before merge. Our primary
> track is Red Hat Live Data, with NVIDIA Nemotron performing the generative
> security work.

## 0:30–1:05 — Prove GitHub access and scan live

**Show:** In **Scan**, point to the filtered public `gedyeyasu/SentinelForge`
repository. Switch to **Local Repository**, keep
`examples/vulnerable_shop`, and click **Start scan**. Point to the live terminal
and the high-severity result at `app/main.py:44`.

**Say:**

> The GitHub integration can list repositories and clone through Git AskPass,
> so the access token is not embedded in the clone address or process list. For
> a deterministic live example, I am scanning the checked-in vulnerable shop.
> The FastAPI detector finds Broken Object Level Authorization, meaning this
> endpoint loads an order by identifier but never checks that the order belongs
> to the current user's tenant. The scan returns the file, line, invariant,
> confidence, and remediation instead of a vague model opinion.

## 1:05–1:45 — Run the real finding-to-verified-patch loop

**Show:** Switch to the terminal. Run:

```bash
DEMO_RUN_ROOT=$(mktemp -d /tmp/sentinelforge-loom.XXXXXX)
.venv/bin/sentinelforge remediate examples/vulnerable_shop \
  --run-root "$DEMO_RUN_ROOT" --timeout 90
```

Point to `changed_files`, `patch_sha256`, `source_root`, `patched_root`,
`repository_tests: true`, `security_regression: true`, and `4 passed`.

**Say:**

> This is the core action loop live. SentinelForge copies the repository into
> an isolated workspace, adds the tenant ownership guard, creates a permanent
> regression test, hashes the patch, and runs both the existing tests and the
> new security test. Four tests pass. Notice that source root and patched root
> are different: the agent never edits the release candidate in place. A failed
> test produces a blocked release, not a green result.

## 1:45–2:35 — Show the autonomous pentest and novel exploit generation

**Show:** Switch to the prepared **Pentest** result for run `B4A98345AE88`.
Point to the completed phase timeline, 50 discovered routes, three custom
exploit artifacts, and their `blocked` outcomes. If visible, point to the 12
zero-day hypotheses with zero confirmed novel findings.

**Say:**

> The deeper pentest starts from source and OpenAPI route discovery, then
> dispatches parallel, rate-limited workers for cross-tenant authorization,
> injection, dependency reachability, and hypothesis-driven attacks. In this
> completed run, the swarm mapped 50 routes. NVIDIA Nemotron then wrote three
> new route-specific Python exploit files at runtime and the bounded executor
> attempted them. All three were blocked. The novel-attack engine also executed
> 12 hypotheses and confirmed zero new vulnerabilities. That zero matters: the
> agent records negative evidence instead of manufacturing a zero-day claim.

## 2:35–3:05 — Prove NVIDIA inference was real

**Show:** Switch to the prepared `/traces` tab. Point to
`provider: nvidia_nim`, the Nemotron model name, the three exploit-writer
traces, token counts, and measured latency.

**Say:**

> This trace proves the generative work crossed NVIDIA Inference
> Microservices, abbreviated NIM. It records the actual Nemotron model,
> prompt-template version, input and output tokens, latency, agent role, route,
> and generated file. The deterministic detector remains available when model
> inference fails, but these exploit artifacts were generated by Nemotron.

## 3:05–3:35 — Show Red Hat live security intelligence

**Show:** Switch to **Release Proof**, point to **Red Hat Live Security Data**,
and click **Refresh live feed**. Point to the advisory identifiers, severity,
and the current count.

**Say:**

> The Red Hat track is not a logo. SentinelForge reads the public Common
> Security Advisory Framework and Open Vulnerability and Assessment Language
> feeds, correlates advisories with the repository's software bill of
> materials, and produces Vulnerability Exploitability eXchange reachability
> evidence. Fresh advisories can change which dependencies the agent
> investigates, while deduplication prevents the heartbeat from repeating the
> same work.

## 3:35–4:05 — Safety, evidence, and human authority

**Show:** Return to the completed pentest. Point to the signed attestation,
policy-denied actions if visible, and **Human Review Gate — Release Blocked**.
Do not click **Create Patch PR**.

**Say:**

> Every attempt is constrained by an allowlisted host, allowed methods, request
> budgets, a kill-switch file, secret redaction, and deny rules for destructive
> database, file, process, and network actions. The run produces replayable
> receipts and a signed, hash-linked attestation. Agents may prepare a draft
> pull request, but no agent can merge it. Human review remains the authority
> boundary.

## 4:05–4:30 — Close on value and next step

**Show:** End on the live scan result and the human gate, with the public Fly
application address visible.

**Say:**

> SentinelForge is useful after this hackathon because it fits the workflow
> companies already have: repository, release candidate, tests, pull request,
> and approval. It replaces a security ticket containing suspicion with an
> isolated patch and machine-verifiable evidence. The next production step is
> to run every verification against a disposable deployed copy, enable the
> partner security runtimes, and pilot the gate in shadow mode before it is
> allowed to block a real release.

## Exact sponsor and platform claims

| Tool or platform | What is verified now | Why SentinelForge uses it | What to show |
|---|---|---|---|
| NVIDIA NIM and Nemotron | The deployed service is configured for Nemotron; completed run `B4A98345AE88` contains three real `nvidia_nim` exploit-writer traces. The local health check also succeeds. | Generates route-specific exploit code and supports patch and threat-analysis proposals. | `/traces` model, provider, tokens, latency, route, and file. |
| Red Hat Security Data | The deployed application successfully reads the public Common Security Advisory Framework feed. Open Vulnerability and Assessment Language and Vulnerability Exploitability eXchange adapters exist in code. | Supplies fresh vulnerability intelligence and supports dependency reachability decisions. | Live advisory panel and refresh. |
| GitHub | The deployed token can list 30 accessible repositories. Secure cloning uses Git AskPass. Scan, draft-pull-request, Check Run, and Static Analysis Results Interchange Format paths exist. A production pull request was not verified in this audit. | Connects the agent to the existing code-review workflow without giving it merge authority. | Filtered repository list and live scan. |
| Fly.io | The FastAPI application and static dashboard are live and healthy. | Hosts the public demo and persistent SQLite volume. | Public address and `/health`. |
| HiddenLayer | The code supports version-two runtime evaluation and a version-one adapter, but the deployed status is `local_fallback` and the completed run used local scanning. | Intended to protect model input, output, tool calls, tool results, and ingested repository content. | Mention only as an integration-ready boundary; do not claim the partner service is active. |
| OpenShell | SentinelForge currently uses its own Python regular-expression policy engine and YAML rules. The SentinelForge deployment is not running inside an NVIDIA OpenShell sandbox. | Applies a deny-by-default policy and produces an audit trail. | Show policy decisions, but call them SentinelForge policy enforcement. |
| NemoClaw | The repository contains a custom `NemoClawOrchestrator`, a 14-role YAML roster, persistent target memory, and a heartbeat document. The NVIDIA host runtime currently has only the separate Austin FloodOps sandbox. | Defines role boundaries, persistence, and scheduled advisory checks. | Call it a NemoClaw-compatible contract, not a live NVIDIA NemoClaw deployment. |
| vLLM | The deployed status is `awaiting_host`; no live vLLM worker is connected. | Intended as the self-hosted, high-throughput inference path. | Do not claim the vLLM bounty today. |
| Supabase | An adapter and schema are checked in, but no call site persists SentinelForge runs to Supabase in the current code. SQLite is authoritative. | Intended for later multi-tenant hosted persistence. | Do not claim live Supabase persistence. |

## Claims you must not make

- Do not say the deployed Release Proof verified a patch. The current deployed
  image lacks `pytest`, so it correctly blocks verification.
- Do not say the current adversarial verifier replayed mutations against a
  running patched application. It currently performs static guard analysis;
  real HTTP replay is a next step.
- Do not repeat the dashboard's **Patch Verified** summary for the completed
  pentest. That text is stronger than the underlying verification mechanism.
- Do not say HiddenLayer, vLLM, NVIDIA NemoClaw, NVIDIA OpenShell, or Supabase
  are active in the deployed application.
- Do not say the system discovered a zero-day. It generated and executed 12
  hypotheses and confirmed zero novel findings in the audited run.
- Do not say the deployed GitHub session came from OAuth. It currently reports
  a token from the environment; the OAuth application is configured but has no
  stored OAuth token.
- Do not quote fixed cost, speedup, learning, false-positive, or time-saved
  numbers unless the current run visibly contains the measurements.

## Recording recovery plan

- If the GitHub list fails, continue with the checked-in vulnerable shop and
  describe GitHub as temporarily unavailable. Do not show a fabricated list.
- If the live scan fails, stop and record again after `/health` is green. This
  is the shortest, most reliable live proof in the video.
- If the local remediation does not end with four passing tests, do not hide
  the failure. Fix the local environment or use the successful terminal output
  from a fresh rehearsal recorded in the same Loom take.
- If Red Hat is unavailable, leave the degraded state visible and say the
  public feed is temporarily unavailable. Do not substitute fixture data.
- If the completed pentest result is slow to render, open the prepared trace
  tab first, then return to the result after the page finishes loading.
- Never open `.env`, secret-manager pages, private tokens, test-account
  credentials, or an unfiltered private repository list.

## Short submission write-up (240 words)

Artificial-intelligence-assisted development is increasing code velocity faster
than security teams can review releases. Most scanners stop at a finding or a
ticket, leaving an engineer to reproduce the issue, decide whether it is
reachable, build a patch, write a regression test, and assemble evidence for a
pull request. SentinelForge is an autonomous, proof-carrying security release
gate for engineering teams that need that loop to happen continuously without
giving an agent merge authority.

For an authorized repository or staging target, SentinelForge maps FastAPI,
Django, and OpenAPI attack surfaces; correlates dependencies with live Red Hat
security advisories; dispatches bounded authentication, injection, dependency,
and novel-hypothesis workers; and uses NVIDIA Nemotron through NVIDIA Inference
Microservices to generate route-specific exploit artifacts and patch proposals.
Confirmed work is stored as redacted evidence receipts and a signed,
hash-linked attestation. The remediation path operates in an isolated copy,
adds a permanent security regression test, runs the existing tests, and fails
closed when verification is unavailable. GitHub integration can list and scan
repositories and is designed to prepare a draft pull request, while a human
remains responsible for merge and deployment.

The result is a cheaper first line of defense for teams shipping large volumes
of generated code: fewer unverified security tickets, faster reproducibility,
and a review artifact that shows exactly what was detected, changed, tested,
and blocked. The next step is a shadow pilot that runs every attack and replay
inside disposable deployed environments before gating production releases.

## Submission checklist after recording

- [ ] Loom video is between two and five minutes, with camera and microphone on.
- [ ] The video shows a live scan, an isolated verified local remediation, a
  completed bounded pentest, real Nemotron trace data, live Red Hat data, and
  the human gate.
- [ ] No token, password, `.env`, private notification, or unrelated private
  repository appears in any frame.
- [x] Public repository exists: <https://github.com/gedyeyasu/SentinelForge>.
- [x] Deployed application is healthy: <https://sentinelforge.fly.dev/>.
- [x] README contains quick-start commands, architecture, environment-variable
  setup, and demo commands.
- [ ] README still needs an honest **Known limitations** section and a
  **Datasets and synthetic data provenance** section before submission.
- [ ] Replace stale README claims that HiddenLayer, vLLM, NemoClaw, OpenShell,
  and Supabase are active, and replace the old `233 tests` count with the
  current verified `267 tests`.
- [x] Latest application commits and this script are pushed to public
  `origin/main` at commit `2aa801b`.
- [ ] Paste the final Loom link into the Airtable form.
- [ ] Paste the 240-word submission write-up from this document.
