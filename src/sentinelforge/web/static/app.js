const ui = {
  form: document.querySelector("#run-form"),
  repository: document.querySelector("#repository"),
  remediate: document.querySelector("#remediate"),
  runButton: document.querySelector("#run-button"),
  error: document.querySelector("#error-banner"),
  empty: document.querySelector("#empty-state"),
  workspace: document.querySelector("#release-proof"),
  lifecycle: document.querySelector("#lifecycle"),
  runId: document.querySelector("#run-id"),
  runRepository: document.querySelector("#run-repository"),
  runUpdated: document.querySelector("#run-updated"),
  candidatePanel: document.querySelector("#candidate-panel"),
  candidateVerdict: document.querySelector("#candidate-verdict"),
  candidateCaption: document.querySelector("#candidate-caption"),
  candidateRef: document.querySelector("#candidate-ref"),
  patchPanel: document.querySelector("#patch-panel"),
  patchVerdict: document.querySelector("#patch-verdict"),
  patchCaption: document.querySelector("#patch-caption"),
  patchRef: document.querySelector("#patch-ref"),
  integrationHealth: document.querySelector("#integration-health"),
  timeline: document.querySelector("#timeline-list"),
  eventCount: document.querySelector("#event-count"),
  findingEmpty: document.querySelector("#finding-empty"),
  findingDetail: document.querySelector("#finding-detail"),
  findingSeverity: document.querySelector("#finding-severity"),
  findingRule: document.querySelector("#finding-rule"),
  findingTitle: document.querySelector("#finding-title"),
  findingDescription: document.querySelector("#finding-description"),
  findingEndpoint: document.querySelector("#finding-endpoint"),
  findingLocation: document.querySelector("#finding-location"),
  findingConfidence: document.querySelector("#finding-confidence"),
  findingInvariant: document.querySelector("#finding-invariant"),
  candidateCount: document.querySelector("#candidate-count"),
  candidateList: document.querySelector("#candidate-list"),
  patchDigest: document.querySelector("#patch-digest"),
  changedFiles: document.querySelector("#changed-files"),
  copyDigest: document.querySelector("#copy-digest"),
  verificationStatus: document.querySelector("#verification-status"),
  testCount: document.querySelector("#test-count"),
  verificationDuration: document.querySelector("#verification-duration"),
  verificationOutput: document.querySelector("#verification-output"),
  downloadEvidence: document.querySelector("#download-evidence"),
  repeatRun: document.querySelector("#repeat-run"),
  connectionDot: document.querySelector("#connection-dot"),
  connectionLabel: document.querySelector("#connection-label"),
  themeToggle: document.querySelector("#theme-toggle"),
  nimIntegration: document.querySelector("#nim-integration"),
  nimIntegrationStatus: document.querySelector("#nim-integration-status"),
  intelligenceForm: document.querySelector("#intelligence-form"),
  intelligencePackage: document.querySelector("#intelligence-package"),
  intelligenceDot: document.querySelector("#intelligence-dot"),
  intelligenceLabel: document.querySelector("#intelligence-label"),
  intelligenceCount: document.querySelector("#intelligence-count"),
  advisoryList: document.querySelector("#advisory-list"),
  pentestForm: document.querySelector("#pentest-form"),
  pentestRepository: document.querySelector("#pentest-repository"),
  pentestScope: document.querySelector("#pentest-scope"),
  pentestMode: document.querySelector("#pentest-mode"),
  pentestButton: document.querySelector("#pentest-button"),
  pentestError: document.querySelector("#pentest-error"),
  pentestEmpty: document.querySelector("#pentest-empty"),
  pentestActive: document.querySelector("#pentest-active"),
  pentestLifecycle: document.querySelector("#pentest-lifecycle"),
  pentestRunId: document.querySelector("#pentest-run-id"),
  pentestRepoLabel: document.querySelector("#pentest-repo-label"),
  pentestModeLabel: document.querySelector("#pentest-mode-label"),
  pentestUpdated: document.querySelector("#pentest-updated"),
  pentestVerdictPanel: document.querySelector("#pentest-verdict-panel"),
  pentestVerdict: document.querySelector("#pentest-verdict"),
  pentestVerdictRef: document.querySelector("#pentest-verdict-ref"),
  pentestVerdictCaption: document.querySelector("#pentest-verdict-caption"),
  pentestPhase: document.querySelector("#pentest-phase"),
  pentestPhaseDetail: document.querySelector("#pentest-phase-detail"),
  pentestTimeline: document.querySelector("#pentest-timeline-list"),
  pentestEventCount: document.querySelector("#pentest-event-count"),
  pentestResultsSummary: document.querySelector("#pentest-results-summary"),
  pentestResultsDetail: document.querySelector("#pentest-results-detail"),
  pentestRoutesCount: document.querySelector("#pentest-routes-count"),
  pentestAuthCount: document.querySelector("#pentest-auth-count"),
  pentestInjectionCount: document.querySelector("#pentest-injection-count"),
  pentestDepVulnCount: document.querySelector("#pentest-dep-vuln-count"),
  pentestPatternCount: document.querySelector("#pentest-pattern-count"),
  pentestHlCount: document.querySelector("#pentest-hl-count"),
  pentestRepeat: document.querySelector("#pentest-repeat"),
  pentestRunsList: document.querySelector("#pentest-runs-list"),
  refreshPentestRuns: document.querySelector("#refresh-pentest-runs"),
  scheduleForm: document.querySelector("#schedule-form"),
  schedRepository: document.querySelector("#sched-repository"),
  schedScope: document.querySelector("#sched-scope"),
  schedMode: document.querySelector("#sched-mode"),
  schedInterval: document.querySelector("#sched-interval"),
  schedButton: document.querySelector("#sched-button"),
  scheduleError: document.querySelector("#schedule-error"),
  schedulesList: document.querySelector("#schedules-list"),
  refreshSchedules: document.querySelector("#refresh-schedules"),
};

const state = {
  currentRun: null,
  currentEvents: [],
  pollTimer: null,
  currentPentestRun: null,
  pentestPollTimer: null,
  currentView: "release",
};

const eventDescriptions = {
  run_queued: ["Run queued", "Authorization and workspace preflight recorded."],
  scan_started: ["Detector started", "Scanning supported source structures."],
  scan_completed: ["Detection complete", "Candidate evidence set finalized."],
  finding_confirmed: ["Security finding confirmed", "Release candidate marked blocked."],
  isolated_patch_started: ["Isolated patch started", "Source repository remains unchanged."],
  model_candidate_started: ["Nemotron candidate started", "Bounded repository context sent to NIM."],
  model_candidate_verified: ["Nemotron candidate verified", "Model patch passed deterministic tests."],
  model_candidate_rejected: ["Nemotron candidate rejected", "Model patch failed deterministic tests."],
  model_candidate_failed: ["Nemotron lane degraded", "Provider failure cannot alter the security verdict."],
  candidate_selected: ["Winning patch selected", "Passing candidates ranked by minimal change."],
  patch_verified: ["Patch verified", "Security regression and repository tests passed."],
  patch_rejected: ["Patch rejected", "Deterministic verification did not pass."],
  run_failed: ["Run failed", "Evidence gathered before failure remains available."],
  pentest_queued: ["Pentest queued", "Scope and repository validated."],
  scope_validated: ["Scope validated", "Target boundaries enforced."],
  routes_discovered: ["Routes discovered", "API attack surface mapped."],
  exploit_attempted: ["Exploit attempted", "Attack agent probed a route."],
  dependency_scan_completed: ["Dependency scan complete", "Red Hat advisory cross-reference finished."],
  dependency_scan_failed: ["Dependency scan failed", "Advisory lookup encountered an error."],
  pattern_scan_completed: ["Pattern scan complete", "Code-level exploit patterns identified."],
  hiddenlayer_safety_scan_completed: ["Safety scan complete", "HiddenLayer injection analysis finished."],
  phase_completed: ["Phase completed", "Orchestrator advanced to next phase."],
  orchestration_started: ["Orchestration started", "Long-running agent workflow initiated."],
  orchestration_completed: ["Orchestration completed", "All phases executed."],
  orchestration_aborted: ["Orchestration aborted", "Phase failure triggered gate."],
};

function text(node, value) {
  node.textContent = value == null ? "—" : String(value);
}

function showError(element, message) {
  text(element, message);
  element.hidden = false;
}

function clearError(element) {
  element.hidden = true;
  text(element, "");
}

function formatTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(date);
}

function basename(value) {
  const parts = String(value || "").split("/").filter(Boolean);
  return parts.at(-1) || value || "repository";
}

function verdictLabel(value) {
  return String(value || "pending").replaceAll("_", " ").toUpperCase();
}

function setVerdict(panel, valueNode, captionNode, verdict, kind) {
  panel.classList.remove("is-blocked", "is-safe", "is-failed");
  text(valueNode, verdictLabel(verdict));
  if (verdict === "blocked") {
    panel.classList.add("is-blocked");
    text(
      captionNode,
      kind === "candidate"
        ? "A supported security invariant is violated. This source artifact is not release-eligible."
        : "Patch verification failed. The candidate remains blocked.",
    );
  } else if (verdict === "safe") {
    panel.classList.add("is-safe");
    text(
      captionNode,
      kind === "candidate"
        ? "No supported finding was detected. Coverage limits still apply."
        : "This exact patch artifact passed the generated security test and repository tests.",
    );
  } else if (verdict === "failed") {
    panel.classList.add("is-failed");
    text(captionNode, "The proof is incomplete. Review the evidence timeline before retrying.");
  } else if (verdict === "not_applicable") {
    text(captionNode, "No patch artifact was required or requested for this run.");
  } else {
    text(
      captionNode,
      kind === "candidate"
        ? "Scanning the candidate for supported security defects."
        : "Safety requires a fresh patch build and passing tests.",
    );
  }
}

function renderRun(run) {
  state.currentRun = run;
  ui.empty.hidden = true;
  ui.workspace.hidden = false;
  text(ui.lifecycle, verdictLabel(run.lifecycle));
  text(ui.runId, run.run_id.toUpperCase());
  text(ui.runRepository, run.repository);
  text(ui.runUpdated, `updated ${formatTime(run.updated_at)}`);
  text(ui.candidateRef, basename(run.repository).toUpperCase());
  setVerdict(ui.candidatePanel, ui.candidateVerdict, ui.candidateCaption, run.candidate_verdict, "candidate");
  setVerdict(ui.patchPanel, ui.patchVerdict, ui.patchCaption, run.patch_verdict, "patch");
  text(ui.integrationHealth, verdictLabel(run.integration_health));
  ui.integrationHealth.style.color =
    run.integration_health === "healthy" ? "var(--safe)" : "var(--warning)";

  const result = run.result || {};
  const finding = Array.isArray(result.findings) ? result.findings[0] : null;
  const bundle = result.patch_bundle || null;
  const verification = result.verification || null;
  renderFinding(finding);
  renderCandidates(result.candidates || [], result.selected_candidate_id);
  renderPatch(bundle);
  renderVerification(verification);
  ui.downloadEvidence.disabled = !run.result;
  if (run.error) showError(ui.error, run.error);
}

function renderCandidates(candidates, selectedId) {
  ui.candidateList.replaceChildren();
  text(ui.candidateCount, `${candidates.length} CANDIDATE${candidates.length === 1 ? "" : "S"}`);
  if (!candidates.length) {
    const empty = document.createElement("li");
    empty.className = "candidate-empty";
    text(empty, "Waiting for isolated patch candidates.");
    ui.candidateList.append(empty);
    return;
  }
  candidates.forEach((candidate) => {
    const row = document.createElement("li");
    row.className = "candidate-row";
    if (candidate.candidate_id === selectedId) row.classList.add("is-selected");
    if (!candidate.verified) row.classList.add("is-rejected");
    const worker = document.createElement("div");
    const workerName = document.createElement("strong");
    const workerModel = document.createElement("small");
    text(workerName, candidate.source === "nvidia_nim" ? "NEMOTRON / NIM" : "DETERMINISTIC CORE");
    text(workerModel, candidate.model || candidate.candidate_id);
    worker.append(workerName, workerModel);
    const verdict = document.createElement("strong");
    verdict.className = `candidate-status ${candidate.verified ? "is-passed" : "is-failed"}`;
    text(verdict, candidate.verified ? "PASSED" : "REJECTED");
    const change = document.createElement("span");
    const files = candidate.patch_bundle?.changed_files?.length || 0;
    text(change, `${candidate.changed_lines} LINES · ${files} FILES`);
    const duration = document.createElement("span");
    text(duration, `${candidate.verification?.duration_ms ?? "—"} MS`);
    const decision = document.createElement("strong");
    decision.className = "candidate-decision";
    text(decision, candidate.candidate_id === selectedId ? "SELECTED" : "NOT SELECTED");
    row.append(worker, verdict, change, duration, decision);
    ui.candidateList.append(row);
  });
}

function renderFinding(finding) {
  if (!finding) {
    ui.findingEmpty.hidden = false;
    ui.findingDetail.hidden = true;
    text(ui.findingSeverity, "PENDING");
    return;
  }
  ui.findingEmpty.hidden = true;
  ui.findingDetail.hidden = false;
  text(ui.findingSeverity, verdictLabel(finding.severity));
  text(ui.findingRule, finding.rule_id);
  text(ui.findingTitle, finding.title);
  text(ui.findingDescription, finding.description);
  text(ui.findingEndpoint, `${finding.method} ${finding.endpoint}`);
  text(ui.findingLocation, `${finding.path}:${finding.line}`);
  text(ui.findingConfidence, `${Math.round(Number(finding.confidence) * 100)}%`);
  text(ui.findingInvariant, finding.invariant);
}

function renderPatch(bundle) {
  if (!bundle) {
    text(ui.patchDigest, "Waiting for a verified patch…");
    text(ui.changedFiles, "—");
    text(ui.patchRef, "AWAITING PROOF");
    ui.copyDigest.disabled = true;
    return;
  }
  text(ui.patchDigest, bundle.patch_sha256);
  text(ui.changedFiles, `${bundle.changed_files.length} FILES`);
  text(ui.patchRef, bundle.patch_sha256.slice(0, 12).toUpperCase());
  ui.copyDigest.disabled = false;
}

function parsedTestCount(output) {
  const match = String(output || "").match(/(\d+) passed/);
  return match ? Number(match[1]) : null;
}

function renderVerification(verification) {
  ui.verificationStatus.classList.remove("is-passed", "is-failed");
  if (!verification) {
    text(ui.verificationStatus, "NOT RUN");
    text(ui.testCount, "—");
    text(ui.verificationDuration, "—");
    text(ui.verificationOutput, "Awaiting isolated patch verification.");
    return;
  }
  const passed = verification.status === "passed";
  ui.verificationStatus.classList.add(passed ? "is-passed" : "is-failed");
  text(ui.verificationStatus, verdictLabel(verification.status));
  const count = parsedTestCount(verification.stdout);
  text(ui.testCount, count == null ? Object.values(verification.checks || {}).filter(Boolean).length : count);
  text(ui.verificationDuration, `${verification.duration_ms} MS`);
  text(ui.verificationOutput, verification.stdout || verification.stderr || "No verifier output.");
}

function eventPayloadSummary(event) {
  const payload = event.payload || {};
  if (event.kind === "routes_discovered") return `${payload.route_count || 0} routes mapped`;
  if (event.kind === "exploit_attempted") return `${payload.agent} · ${payload.route} · ${payload.outcome}`;
  if (event.kind === "dependency_scan_completed") return `${payload.vulnerability_count} vulns in ${payload.unique_packages} packages`;
  if (event.kind === "pattern_scan_completed") return `${payload.finding_count} patterns in ${payload.files_scanned} files`;
  if (event.kind === "hiddenlayer_safety_scan_completed") return `${payload.files_scanned} files scanned`;
  if (event.kind === "phase_completed") return `${payload.phase} · ${payload.success ? "ok" : "failed"} · ${payload.duration_ms}ms`;
  if (event.kind === "orchestration_started") return `mode: ${payload.mode} · ${payload.phases?.length || 0} phases`;
  if (event.kind === "orchestration_completed") return `${payload.phases_completed?.length || 0} phases completed`;
  if (event.kind === "orchestration_aborted") return `aborted at ${payload.phase}: ${payload.error}`;
  if (event.kind === "run_queued") return payload.repository || "authorized repository";
  if (event.kind === "scan_started") return payload.detector || "detector";
  if (event.kind === "scan_completed") return `${payload.finding_count || 0} finding(s)`;
  if (event.kind === "finding_confirmed") return `${payload.rule_id || "finding"} · ${String(payload.severity || "").toUpperCase()}`;
  if (event.kind === "patch_verified" || event.kind === "patch_rejected") {
    const digest = String(payload.patch_sha256 || "").slice(0, 12);
    return `${digest || "patch"} · exit ${payload.exit_code} · ${payload.duration_ms} ms`;
  }
  if (event.kind === "model_candidate_started") return `${payload.model || "configured model"} · isolated lane`;
  if (event.kind === "model_candidate_verified" || event.kind === "model_candidate_rejected") {
    return `${payload.model || "Nemotron"} · exit ${payload.exit_code} · ${payload.generation_latency_ms} ms generation`;
  }
  if (event.kind === "candidate_selected") return `${payload.candidate_id} · ${payload.changed_lines} changed lines`;
  return event.phase;
}

function renderEvents(target, events) {
  target.replaceChildren();
  events.forEach((event, index) => {
    const item = document.createElement("li");
    item.className = "timeline-item";
    item.dataset.kind = event.kind;
    const marker = document.createElement("span");
    marker.className = "timeline-marker";
    text(marker, String(index + 1).padStart(2, "0"));
    const content = document.createElement("div");
    content.className = "timeline-content";
    const title = document.createElement("strong");
    const description = document.createElement("p");
    const labels = eventDescriptions[event.kind] || [event.kind, event.phase];
    text(title, labels[0]);
    text(description, `${labels[1]} · ${eventPayloadSummary(event)}`);
    content.append(title, description);
    const time = document.createElement("time");
    time.className = "timeline-time";
    time.dateTime = event.occurred_at;
    text(time, formatTime(event.occurred_at));
    item.append(marker, content, time);
    target.append(item);
  });
}

async function api(path, options) {
  const response = await fetch(path, options);
  let payload = null;
  try { payload = await response.json(); } catch { payload = null; }
  if (!response.ok) throw new Error(payload?.detail || `Request failed with status ${response.status}`);
  return payload;
}

async function refreshRun(runId) {
  try {
    const [run, events] = await Promise.all([
      api(`/api/runs/${encodeURIComponent(runId)}`),
      api(`/api/runs/${encodeURIComponent(runId)}/events`),
    ]);
    renderRun(run);
    renderEvents(ui.timeline, events);
    clearError(ui.error);
    if (["queued", "running"].includes(run.lifecycle)) {
      state.pollTimer = window.setTimeout(() => refreshRun(runId), 450);
    } else {
      ui.runButton.disabled = false;
      ui.runButton.querySelector("span").textContent = "Start proof run";
    }
  } catch (error) {
    ui.runButton.disabled = false;
    showError(ui.error, error.message);
  }
}

async function createRun(event) {
  event?.preventDefault();
  clearError(ui.error);
  window.clearTimeout(state.pollTimer);
  ui.runButton.disabled = true;
  ui.runButton.querySelector("span").textContent = "Starting…";
  try {
    const run = await api("/api/runs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ repository: ui.repository.value.trim(), remediate: ui.remediate.checked }),
    });
    renderRun(run);
    renderEvents(ui.timeline, []);
    localStorage.setItem("sentinelforge.repository", ui.repository.value.trim());
    await refreshRun(run.run_id);
  } catch (error) {
    ui.runButton.disabled = false;
    ui.runButton.querySelector("span").textContent = "Start proof run";
    showError(ui.error, error.message);
  }
}

function downloadEvidence() {
  if (!state.currentRun) return;
  const payload = { run: state.currentRun, events: state.currentEvents, exported_at: new Date().toISOString() };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `${state.currentRun.run_id}-evidence.json`;
  link.click();
  URL.revokeObjectURL(link.href);
}

async function copyDigest() {
  const digest = ui.patchDigest.textContent;
  if (!digest || digest.includes("Waiting")) return;
  try {
    await navigator.clipboard.writeText(digest);
    text(ui.copyDigest, "Copied");
    window.setTimeout(() => text(ui.copyDigest, "Copy digest"), 1200);
  } catch {
    showError(ui.error, "Clipboard access was denied.");
  }
}

function setTheme(theme) {
  document.documentElement.dataset.theme = theme;
  ui.themeToggle.setAttribute("aria-label", `Use ${theme === "dark" ? "light" : "dark"} mode`);
  localStorage.setItem("sentinelforge.theme", theme);
}

function toggleTheme() {
  setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
}

function switchView(viewName) {
  state.currentView = viewName;
  document.querySelectorAll(".view-panel").forEach((panel) => {
    panel.hidden = true;
  });
  const target = document.getElementById(`view-${viewName}`);
  if (target) target.hidden = false;
  document.querySelectorAll(".rail-nav .nav-item").forEach((item) => {
    const itemView = item.dataset.view;
    item.classList.toggle("active", itemView === viewName);
  });
}

async function checkConnection() {
  try {
    const [, integrations] = await Promise.all([api("/health"), api("/api/integrations")]);
    ui.connectionDot.classList.add("safe");
    ui.connectionDot.classList.remove("offline");
    text(ui.connectionLabel, "CONTROL PLANE ONLINE");
    const nimConfigured = integrations.nvidia_nim?.status === "configured";
    const nimDot = ui.nimIntegration.querySelector(".status-dot");
    nimDot.classList.toggle("safe", nimConfigured);
    nimDot.classList.toggle("waiting", !nimConfigured);
    text(ui.nimIntegrationStatus, nimConfigured ? "READY" : "KEY");
  } catch {
    ui.connectionDot.classList.remove("safe");
    ui.connectionDot.classList.add("offline");
    text(ui.connectionLabel, "CONTROL PLANE OFFLINE");
  }
}

function renderAdvisories(advisories) {
  ui.advisoryList.replaceChildren();
  text(ui.intelligenceCount, `${advisories.length} ADVISOR${advisories.length === 1 ? "Y" : "IES"}`);
  if (!advisories.length) {
    const empty = document.createElement("li");
    empty.className = "advisory-empty";
    text(empty, "No Red Hat advisories matched this package and time window.");
    ui.advisoryList.append(empty);
    return;
  }
  advisories.forEach((advisory) => {
    const row = document.createElement("li");
    row.className = "advisory-row";
    const advisoryId = document.createElement("code");
    const severity = document.createElement("span");
    const cves = document.createElement("span");
    const packageName = document.createElement("span");
    const source = document.createElement("a");
    severity.className = "advisory-severity";
    cves.className = "advisory-cves";
    packageName.className = "advisory-package";
    source.target = "_blank";
    source.rel = "noreferrer";
    source.href = advisory.resource_url;
    text(advisoryId, advisory.advisory_id);
    text(severity, advisory.severity);
    text(cves, advisory.cves.join(" · "));
    text(packageName, advisory.released_packages[0] || "No released package listed");
    text(source, "Open CSAF ↗");
    row.append(advisoryId, severity, cves, packageName, source);
    ui.advisoryList.append(row);
  });
}

async function loadRedHatIntelligence(event) {
  event?.preventDefault();
  const packageName = ui.intelligencePackage.value.trim();
  text(ui.intelligenceLabel, "QUERYING PUBLIC CSAF API");
  ui.intelligenceDot.classList.remove("offline");
  try {
    const query = new URLSearchParams({ days: "90", limit: "3" });
    if (packageName) query.set("package", packageName);
    const advisories = await api(`/api/intelligence/redhat?${query}`);
    renderAdvisories(advisories);
    text(ui.intelligenceLabel, "LIVE · RED HAT SECURITY DATA");
    ui.intelligenceDot.classList.add("safe");
  } catch {
    ui.intelligenceDot.classList.remove("safe");
    ui.intelligenceDot.classList.add("offline");
    text(ui.intelligenceLabel, "RED HAT FEED UNAVAILABLE");
    renderAdvisories([]);
  }
}

function renderPentestRun(data) {
  const run = data.pentest_run;
  if (!run) return;
  state.currentPentestRun = run;
  ui.pentestEmpty.hidden = true;
  ui.pentestActive.hidden = false;
  text(ui.pentestLifecycle, verdictLabel(run.status));
  text(ui.pentestRunId, run.run_id.toUpperCase());
  text(ui.pentestRepoLabel, basename(run.repository));
  text(ui.pentestModeLabel, `mode — ${run.mode || "standard"}`);
  text(ui.pentestUpdated, `updated ${formatTime(run.updated_at)}`);
  text(ui.pentestVerdictRef, run.run_id.slice(-8).toUpperCase());
  setVerdict(ui.pentestVerdictPanel, ui.pentestVerdict, ui.pentestVerdictCaption, run.candidate_verdict, "candidate");
  text(ui.pentestPhase, verdictLabel(run.phase));
  text(ui.pentestPhaseDetail, `Status: ${verdictLabel(run.status)}`);

  const events = data.events || [];
  renderEvents(ui.pentestTimeline, events);
  text(ui.pentestEventCount, `${events.length} EVENT${events.length === 1 ? "" : "S"}`);

  const results = run.results || {};
  if (results.summary || results.routes) {
    ui.pentestResultsSummary.hidden = true;
    ui.pentestResultsDetail.hidden = false;
    text(ui.pentestRoutesCount, String(results.routes?.length || 0));
    const receipts = results.receipts || [];
    text(ui.pentestAuthCount, String(receipts.filter((r) => r.agent === "auth_attacker").length || 0));
    text(ui.pentestInjectionCount, String(results.injection_results?.length || 0));
    const depVulns = results.dependency_vulnerabilities;
    text(ui.pentestDepVulnCount, String(depVulns?.vulnerable_count || 0));
    const patterns = results.exploit_patterns;
    text(ui.pentestPatternCount, String(patterns?.finding_count || 0));
    text(ui.pentestHlCount, String(results.hiddenlayer_scans?.length || 0));
  }

  if (run.error) showError(ui.pentestError, run.error);
}

async function refreshPentestRun(runId) {
  try {
    const data = await api(`/api/pentest/${encodeURIComponent(runId)}`);
    renderPentestRun(data);
    clearError(ui.pentestError);
    const run = data.pentest_run;
    if (run && ["queued", "running"].includes(run.status)) {
      state.pentestPollTimer = window.setTimeout(() => refreshPentestRun(runId), 450);
    } else {
      ui.pentestButton.disabled = false;
      ui.pentestButton.querySelector("span").textContent = "Start pentest";
      loadPentestRuns();
    }
  } catch (error) {
    ui.pentestButton.disabled = false;
    showError(ui.pentestError, error.message);
  }
}

async function createPentest(event) {
  event?.preventDefault();
  clearError(ui.pentestError);
  window.clearTimeout(state.pentestPollTimer);
  ui.pentestButton.disabled = true;
  ui.pentestButton.querySelector("span").textContent = "Starting…";
  try {
    const result = await api("/api/pentest", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        repository: ui.pentestRepository.value.trim(),
        scope_file: ui.pentestScope.value.trim(),
        mode: ui.pentestMode.value,
      }),
    });
    renderPentestRun(result);
    const run = result.pentest_run;
    if (run) await refreshPentestRun(run.run_id);
  } catch (error) {
    ui.pentestButton.disabled = false;
    ui.pentestButton.querySelector("span").textContent = "Start pentest";
    showError(ui.pentestError, error.message);
  }
}

async function loadPentestRuns() {
  try {
    const data = await api("/api/pentest?limit=20");
    ui.pentestRunsList.replaceChildren();
    const runs = data.runs || [];
    if (!runs.length) {
      const empty = document.createElement("li");
      empty.className = "candidate-empty";
      text(empty, "No pentest runs yet.");
      ui.pentestRunsList.append(empty);
      return;
    }
    runs.forEach((run) => {
      const row = document.createElement("li");
      row.className = "candidate-row";
      row.style.cursor = "pointer";
      row.addEventListener("click", () => {
        ui.pentestEmpty.hidden = true;
        ui.pentestActive.hidden = false;
        refreshPentestRun(run.run_id);
      });
      const id = document.createElement("span");
      const mode = document.createElement("span");
      const verdict = document.createElement("strong");
      const status = document.createElement("span");
      const created = document.createElement("span");
      text(id, run.run_id.slice(-12).toUpperCase());
      text(mode, run.mode || "standard");
      verdict.className = `candidate-status ${run.candidate_verdict === "safe" ? "is-passed" : "is-failed"}`;
      text(verdict, verdictLabel(run.candidate_verdict));
      text(status, verdictLabel(run.status));
      text(created, formatTime(run.created_at));
      row.append(id, mode, verdict, status, created);
      ui.pentestRunsList.append(row);
    });
  } catch {}
}

async function createSchedule(event) {
  event?.preventDefault();
  clearError(ui.scheduleError);
  try {
    const params = new URLSearchParams({
      repository: ui.schedRepository.value.trim(),
      scope_file: ui.schedScope.value.trim(),
      mode: ui.schedMode.value,
      interval_minutes: ui.schedInterval.value,
    });
    await api(`/api/pentest/schedule?${params}`, { method: "POST" });
    loadSchedules();
  } catch (error) {
    showError(ui.scheduleError, error.message);
  }
}

async function loadSchedules() {
  try {
    const data = await api("/api/pentest/schedule");
    ui.schedulesList.replaceChildren();
    const schedules = data.schedules || [];
    if (!schedules.length) {
      const empty = document.createElement("li");
      empty.className = "candidate-empty";
      text(empty, "No schedules configured.");
      ui.schedulesList.append(empty);
      return;
    }
    schedules.forEach((sched) => {
      const row = document.createElement("li");
      row.className = "candidate-row";
      const repo = document.createElement("span");
      const mode = document.createElement("span");
      const interval = document.createElement("span");
      const nextRun = document.createElement("span");
      const status = document.createElement("strong");
      const action = document.createElement("button");
      text(repo, basename(sched.repository));
      text(mode, sched.mode);
      text(interval, `${sched.interval_minutes}m`);
      text(nextRun, formatTime(sched.next_run_at));
      status.className = `candidate-status ${sched.enabled ? "is-passed" : "is-failed"}`;
      text(status, sched.enabled ? "ACTIVE" : "PAUSED");
      action.className = "text-button";
      text(action, "Delete");
      action.addEventListener("click", async () => {
        try {
          await api(`/api/pentest/schedule/${sched.schedule_id}`, { method: "DELETE" });
          loadSchedules();
        } catch {}
      });
      row.append(repo, mode, interval, nextRun, status, action);
      ui.schedulesList.append(row);
    });
  } catch {}
}

function initialize() {
  const savedTheme = localStorage.getItem("sentinelforge.theme");
  setTheme(savedTheme || "dark");
  const savedRepository = localStorage.getItem("sentinelforge.repository");
  if (savedRepository) ui.repository.value = savedRepository;
  ui.form.addEventListener("submit", createRun);
  ui.repeatRun.addEventListener("click", () => createRun());
  ui.downloadEvidence.addEventListener("click", downloadEvidence);
  ui.copyDigest.addEventListener("click", copyDigest);
  ui.themeToggle.addEventListener("click", toggleTheme);
  ui.intelligenceForm.addEventListener("submit", loadRedHatIntelligence);
  ui.pentestForm.addEventListener("submit", createPentest);
  ui.pentestRepeat.addEventListener("click", () => createPentest());
  ui.refreshPentestRuns.addEventListener("click", loadPentestRuns);
  ui.scheduleForm.addEventListener("submit", createSchedule);
  ui.refreshSchedules.addEventListener("click", loadSchedules);
  document.querySelectorAll(".rail-nav .nav-item[data-view]").forEach((item) => {
    item.addEventListener("click", (e) => {
      e.preventDefault();
      switchView(item.dataset.view);
    });
  });
  checkConnection();
  loadRedHatIntelligence();
  loadPentestRuns();
  loadSchedules();
}

initialize();
