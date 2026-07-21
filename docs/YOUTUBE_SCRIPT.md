# OpenAI Build Week YouTube demo script

Target duration: **2 minutes 40 seconds**. The video must be public or unlisted on
YouTube, shorter than three minutes, and include audible narration explaining both Codex
and GPT-5.6.

## 0:00–0:20 — Problem and track

**Show:** SentinelForge home page and Developer Tools label.

**Say:**

> Teams can now generate code faster than security teams can review it. A scanner alert
> still leaves an engineer to reproduce the issue, patch it, run tests, and assemble
> evidence. SentinelForge is a Developer Tools entry that turns an authorized release
> into a proof-carrying security review.

## 0:20–0:45 — Codex contribution

**Show:** Git history, `docs/CODEX_BUILD_LOG.md`, then the repository map.

**Say:**

> I used Codex as the primary implementation partner. During Build Week it helped turn
> the product plan into the Python control plane, scoped agent workflow, isolated patch
> system, tests, web interface, and Fly.io deployment. It also inspected the live site,
> found a route-ordering bug in scheduling, added the regression test, and built the
> OpenAI-specific evidence-review stage. The dated commits and Codex session are linked
> in the repository.

## 0:45–1:15 — Core loop live

**Show:** Start the prepared `examples/vulnerable_shop` proof run. Point to the finding,
security invariant, isolated patch receipt, and passing verification.

**Say:**

> Here is the core loop. SentinelForge detects a broken object-level authorization flaw,
> explains the invariant, creates a patch in an isolated workspace, adds a permanent
> cross-tenant regression test, and runs the repository tests. The original source is
> never edited in place, and failed verification rejects the patch.

## 1:15–1:50 — Agent flow and safety

**Show:** Pentest phase bar, live events, scope configuration, and OpenShell denial.

**Say:**

> The pentest workflow is an ordered set of bounded agents: ownership and environment
> checks, surface mapping, dependency and source analysis, rate-limited security tests,
> evidence validation, and attestation. Scope, request budgets, a kill switch, secret
> redaction, and deny-by-default execution policies prevent unauthorized actions. Live
> targets require ownership proof.

## 1:50–2:20 — GPT-5.6 differentiation

**Show:** GPT-5.6 integration ready, then the completed evidence decision in the final
report. Briefly show `openai_evidence.py` structured schema.

**Say:**

> GPT-5.6 is the independent evidence judge. It receives only redacted counts, receipt
> identifiers, hashes, policy decisions, test evidence, and the deterministic verdict.
> Through the Responses API it returns a strict structured decision: approve for human
> review, block, or request more evidence. It has no tools and no merge authority. Code
> prevents it from overriding a deterministic block, so the model cannot grade its own
> work green.

## 2:20–2:40 — Result and impact

**Show:** Signed attestation, draft pull request action, and human review gate.

**Say:**

> The output is not another security ticket. It is a replayable evidence bundle, tested
> patch, signed attestation, and optional draft pull request. A human still decides what
> merges. SentinelForge can become a continuous integration and continuous delivery
> gate that gives every development team a bounded first-line security review.

## Recording checklist

- Use YouTube, not Loom.
- Keep the final export below 3:00.
- Confirm microphone audio from beginning to end.
- Do not show `.env`, tokens, customer code, browser credentials, or local home paths.
- Preload one completed run so provider latency cannot consume the video.
- Demonstrate at least one live action.
- Show the GPT-5.6 result only after `OPENAI_API_KEY` is configured and a real call runs.
- Do not describe fixture evidence as a live run.
