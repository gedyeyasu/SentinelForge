const ui = {
  // Scan view
  scanLocalForm: document.querySelector("#scan-local-form"),
  scanGithubForm: document.querySelector("#scan-github-form"),
  scanRepoInput: document.querySelector("#scan-repository"),
  scanGithubOwner: document.querySelector("#scan-github-owner"),
  scanGithubRepo: document.querySelector("#scan-github-repo"),
  scanButton: document.querySelector("#scan-button"),
  scanGithubButton: document.querySelector("#scan-github-button"),
  scanError: document.querySelector("#scan-error"),
  scanEmpty: document.querySelector("#scan-empty"),
  scanResults: document.querySelector("#scan-results"),
  scanLifecycle: document.querySelector("#scan-lifecycle"),
  scanRepoName: document.querySelector("#scan-repo-name"),
  scanBolaCount: document.querySelector("#scan-bola-count"),
  scanPatternCount: document.querySelector("#scan-pattern-count"),
  scanDepCount: document.querySelector("#scan-dep-count"),
  scanFindingsList: document.querySelector("#scan-findings-list"),
  scanPrPanel: document.querySelector("#scan-pr-panel"),
  scanCreatePr: document.querySelector("#scan-create-pr"),
  scanPrResult: document.querySelector("#scan-pr-result"),
  scanDownload: document.querySelector("#scan-download"),
  scanRepeat: document.querySelector("#scan-repeat"),
  // Release proof view
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
  githubIntegration: document.querySelector("#github-integration"),
  githubIntegrationStatus: document.querySelector("#github-integration-status"),
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
  ownershipType: document.querySelector("#ownership-type"),
  ownershipChallengeArea: document.querySelector("#ownership-challenge-area"),
  ownershipCreate: document.querySelector("#ownership-create"),
  ownershipChallengeDisplay: document.querySelector("#ownership-challenge-display"),
  ownershipInstruction: document.querySelector("#ownership-instruction"),
  ownershipToken: document.querySelector("#ownership-token"),
  ownershipVerify: document.querySelector("#ownership-verify"),
  ownershipResult: document.querySelector("#ownership-result"),
  scheduleForm: document.querySelector("#schedule-form"),
  schedRepository: document.querySelector("#sched-repository"),
  schedScope: document.querySelector("#sched-scope"),
  schedMode: document.querySelector("#sched-mode"),
  schedInterval: document.querySelector("#sched-interval"),
  schedButton: document.querySelector("#sched-button"),
  scheduleError: document.querySelector("#schedule-error"),
  schedulesList: document.querySelector("#schedules-list"),
  refreshSchedules: document.querySelector("#refresh-schedules"),
  cicdForm: document.querySelector("#cicd-form"),
  cicdRepository: document.querySelector("#cicd-repository"),
  cicdPlatform: document.querySelector("#cicd-platform"),
  cicdResult: document.querySelector("#cicd-result"),
};

const state = {
  currentRun: null,
  currentEvents: [],
  pollTimer: null,
  currentPentestRun: null,
  pentestPollTimer: null,
  currentView: "scan",
  scanResults: null,
  ownershipChallenge: null,
  selectedFinding: null,
};

const eventDescriptions = {
  run_queued: ["Run queued", "Authorization and workspace preflight recorded."],
  scan_started: ["Detector started", "Scanning supported source structures."],
  scan_completed: ["Detection complete", "Candidate evidence set finalized."],
  finding_confirmed: ["Security finding confirmed", "Release candidate marked blocked."],
  isolated_patch_started: ["Isolated patch started", "Source repository remains unchanged."],
  candidate_selected: ["Winning patch selected", "Passing candidates ranked by minimal change."],
  patch_verified: ["Patch verified", "Security regression and repository tests passed."],
  patch_rejected: ["Patch rejected", "Deterministic verification did not pass."],
  run_failed: ["Run failed", "Evidence gathered before failure remains available."],
  pentest_queued: ["Pentest queued", "Scope and repository validated."],
  scope_validated: ["Scope validated", "Target boundaries enforced."],
  routes_discovered: ["Routes discovered", "API attack surface mapped."],
  exploit_attempted: ["Exploit attempted", "Attack agent probed a route."],
  dependency_scan_completed: ["Dependency scan complete", "Red Hat advisory cross-reference finished."],
  pattern_scan_completed: ["Pattern scan complete", "Code-level exploit patterns identified."],
  hiddenlayer_safety_scan_completed: ["Safety scan complete", "HiddenLayer injection analysis finished."],
  phase_completed: ["Phase completed", "Orchestrator advanced to next phase."],
  orchestration_started: ["Orchestration started", "Long-running agent workflow initiated."],
  orchestration_completed: ["Orchestration completed", "All phases executed."],
  nim_threat_analysis_completed: ["NIM analysis complete", "Nemotron threat assessment finished."],
};

function text(node, value) { node.textContent = value == null ? "—" : String(value); }
function showError(el, msg) { text(el, msg); el.hidden = false; }
function clearError(el) { el.hidden = true; text(el, ""); }
function formatTime(v) { if (!v) return "—"; return new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(new Date(v)); }
function basename(v) { return String(v || "").split("/").filter(Boolean).at(-1) || v || "repository"; }
function verdictLabel(v) { return String(v || "pending").replaceAll("_", " ").toUpperCase(); }

async function api(path, opts) {
  const r = await fetch(path, opts);
  let p = null; try { p = await r.json(); } catch { p = null; }
  if (!r.ok) throw new Error(p?.detail || `Request failed with status ${r.status}`);
  return p;
}

function switchView(name) {
  state.currentView = name;
  document.querySelectorAll(".view-panel").forEach(p => p.hidden = true);
  const t = document.getElementById(`view-${name}`);
  if (t) t.hidden = false;
  document.querySelectorAll(".rail-nav .nav-item").forEach(i => i.classList.toggle("active", i.dataset.view === name));
}

function setVerdict(panel, val, cap, verdict, kind) {
  panel.classList.remove("is-blocked", "is-safe", "is-failed");
  text(val, verdictLabel(verdict));
  if (verdict === "blocked") { panel.classList.add("is-blocked"); text(cap, "Security invariant violated."); }
  else if (verdict === "safe") { panel.classList.add("is-safe"); text(cap, "No findings detected."); }
  else if (verdict === "failed") { panel.classList.add("is-failed"); text(cap, "Proof incomplete."); }
  else { text(cap, "Awaiting results."); }
}

function renderEvents(target, events) {
  target.replaceChildren();
  events.forEach((e, i) => {
    const item = document.createElement("li"); item.className = "timeline-item";
    const marker = document.createElement("span"); marker.className = "timeline-marker"; text(marker, String(i + 1).padStart(2, "0"));
    const content = document.createElement("div"); content.className = "timeline-content";
    const title = document.createElement("strong"); const desc = document.createElement("p");
    const labels = eventDescriptions[e.kind] || [e.kind, e.phase];
    text(title, labels[0]); text(desc, `${labels[1]} · ${e.phase}`);
    content.append(title, desc);
    const time = document.createElement("time"); time.className = "timeline-time"; time.dateTime = e.occurred_at; text(time, formatTime(e.occurred_at));
    item.append(marker, content, time); target.append(item);
  });
}

// ===== SCAN =====
function setupScanTabs() {
  document.querySelectorAll(".scan-tab").forEach(tab => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".scan-tab").forEach(t => t.classList.remove("active"));
      tab.classList.add("active");
      const isGithub = tab.dataset.tab === "github";
      ui.scanLocalForm.hidden = isGithub;
      ui.scanGithubForm.hidden = !isGithub;
    });
  });
}

async function runLocalScan(e) {
  e?.preventDefault(); clearError(ui.scanError);
  ui.scanButton.disabled = true; ui.scanButton.querySelector("span").textContent = "Scanning…";
  try {
    const result = await api("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ repository: ui.scanRepoInput.value.trim() }) });
    renderScanResults(result);
  } catch (err) { showError(ui.scanError, err.message); }
  ui.scanButton.disabled = false; ui.scanButton.querySelector("span").textContent = "Start scan";
}

async function runGithubScan(e) {
  e?.preventDefault(); clearError(ui.scanError);
  ui.scanGithubButton.disabled = true; ui.scanGithubButton.querySelector("span").textContent = "Scanning…";
  try {
    const result = await api("/api/scan/github", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ owner: ui.scanGithubOwner.value.trim(), repo: ui.scanGithubRepo.value.trim() }) });
    renderScanResults(result);
  } catch (err) { showError(ui.scanError, err.message); }
  ui.scanGithubButton.disabled = false; ui.scanGithubButton.querySelector("span").textContent = "Scan GitHub repo";
}

function renderScanResults(result) {
  state.scanResults = result;
  ui.scanEmpty.hidden = true; ui.scanResults.hidden = false;
  text(ui.scanRepoName, basename(result.repository));
  const s = result.summary;
  text(ui.scanBolaCount, s.bola_count); text(ui.scanPatternCount, s.pattern_count); text(ui.scanDepCount, s.dep_vuln_count);
  ui.scanBolaCount.style.color = s.bola_count > 0 ? "var(--danger)" : "var(--safe)";
  ui.scanPatternCount.style.color = s.pattern_count > 0 ? "var(--warning)" : "var(--safe)";

  ui.scanFindingsList.replaceChildren();
  const allFindings = [...(result.bola_findings || []), ...(result.pattern_findings?.findings || [])];
  if (!allFindings.length) { const empty = document.createElement("p"); text(empty, "No findings detected."); ui.scanFindingsList.append(empty); return; }

  allFindings.forEach(f => {
    const row = document.createElement("div"); row.className = "finding-row";
    const sev = document.createElement("span"); sev.className = `severity-badge sev-${f.severity}`; text(sev, f.severity?.toUpperCase() || "?");
    const info = document.createElement("div"); info.className = "finding-info";
    const title = document.createElement("strong"); text(title, f.title || f.vulnerability || "Finding");
    const loc = document.createElement("code"); text(loc, `${f.path || f.file_path || ""}:${f.line || ""}`);
    const desc = document.createElement("p"); text(desc, (f.description || "").slice(0, 120));
    info.append(title, loc, desc);
    if (f.severity === "critical" || f.severity === "high") {
      const prBtn = document.createElement("button"); prBtn.className = "text-button"; text(prBtn, "Create PR");
      prBtn.addEventListener("click", () => { state.selectedFinding = f; ui.scanPrPanel.hidden = false; });
      row.append(sev, info, prBtn);
    } else { row.append(sev, info); }
    ui.scanFindingsList.append(row);
  });
}

async function createPRFromScan() {
  if (!state.selectedFinding || !state.scanResults) return;
  try {
    text(ui.scanCreatePr, "Creating PR…"); ui.scanCreatePr.disabled = true;
    const result = await api("/api/github/create-pr", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ repository: state.scanResults.repository, finding: state.selectedFinding }) });
    ui.scanPrResult.hidden = false;
    if (result.pr) { text(ui.scanPrResult, `PR created: ${result.pr.url}`); }
    else { text(ui.scanPrResult, result.error || "PR creation failed"); }
  } catch (err) { ui.scanPrResult.hidden = false; text(ui.scanPrResult, err.message); }
  text(ui.scanCreatePr, "Create PR on GitHub"); ui.scanCreatePr.disabled = false;
}

function downloadScanReport() {
  if (!state.scanResults) return;
  const blob = new Blob([JSON.stringify(state.scanResults, null, 2)], { type: "application/json" });
  const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
  a.download = `sentinelforge-scan-${Date.now()}.json`; a.click();
}

// ===== RELEASE PROOF =====
function renderRun(run) {
  state.currentRun = run; ui.empty.hidden = true; ui.workspace.hidden = false;
  text(ui.lifecycle, verdictLabel(run.lifecycle)); text(ui.runId, run.run_id.toUpperCase());
  text(ui.runRepository, run.repository); text(ui.runUpdated, `updated ${formatTime(run.updated_at)}`);
  text(ui.candidateRef, basename(run.repository).toUpperCase());
  setVerdict(ui.candidatePanel, ui.candidateVerdict, ui.candidateCaption, run.candidate_verdict, "candidate");
  setVerdict(ui.patchPanel, ui.patchVerdict, ui.patchCaption, run.patch_verdict, "patch");
  text(ui.integrationHealth, verdictLabel(run.integration_health));
}

async function refreshRun(runId) {
  try {
    const [run, events] = await Promise.all([api(`/api/runs/${encodeURIComponent(runId)}`), api(`/api/runs/${encodeURIComponent(runId)}/events`)]);
    renderRun(run); renderEvents(ui.timeline, events);
    if (["queued", "running"].includes(run.lifecycle)) state.pollTimer = setTimeout(() => refreshRun(runId), 450);
    else { ui.runButton.disabled = false; ui.runButton.querySelector("span").textContent = "Start proof run"; }
  } catch (err) { ui.runButton.disabled = false; showError(ui.error, err.message); }
}

async function createRun(e) {
  e?.preventDefault(); clearError(ui.error); clearTimeout(state.pollTimer);
  ui.runButton.disabled = true; ui.runButton.querySelector("span").textContent = "Starting…";
  try {
    const run = await api("/api/runs", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ repository: ui.repository.value.trim(), remediate: ui.remediate.checked }) });
    renderRun(run); await refreshRun(run.run_id);
  } catch (err) { ui.runButton.disabled = false; ui.runButton.querySelector("span").textContent = "Start proof run"; showError(ui.error, err.message); }
}

// ===== PENTEST =====
function renderPentestRun(data) {
  const run = data.pentest_run; if (!run) return;
  state.currentPentestRun = run; ui.pentestEmpty.hidden = true; ui.pentestActive.hidden = false;
  text(ui.pentestLifecycle, verdictLabel(run.status)); text(ui.pentestRunId, run.run_id.toUpperCase());
  text(ui.pentestRepoLabel, basename(run.repository)); text(ui.pentestModeLabel, `mode — ${run.mode || "standard"}`);
  text(ui.pentestUpdated, `updated ${formatTime(run.updated_at)}`);
  text(ui.pentestVerdictRef, run.run_id.slice(-8).toUpperCase());
  setVerdict(ui.pentestVerdictPanel, ui.pentestVerdict, ui.pentestVerdictCaption, run.candidate_verdict, "candidate");
  text(ui.pentestPhase, verdictLabel(run.phase));
  const events = data.events || []; renderEvents(ui.pentestTimeline, events);
  text(ui.pentestEventCount, `${events.length} EVENT${events.length === 1 ? "" : "S"}`);
  const results = run.results || {};
  if (results.summary || results.routes) {
    ui.pentestResultsSummary.hidden = true; ui.pentestResultsDetail.hidden = false;
    text(ui.pentestRoutesCount, String(results.routes?.length || 0));
    text(ui.pentestDepVulnCount, String(results.dependency_vulnerabilities?.vulnerable_count || 0));
    text(ui.pentestPatternCount, String(results.exploit_patterns?.finding_count || 0));
    text(ui.pentestHlCount, String(results.hiddenlayer_scans?.length || 0));
  }
}

async function refreshPentestRun(runId) {
  try {
    const data = await api(`/api/pentest/${encodeURIComponent(runId)}`);
    renderPentestRun(data);
    const run = data.pentest_run;
    if (run && ["queued", "running"].includes(run.status)) state.pentestPollTimer = setTimeout(() => refreshPentestRun(runId), 450);
    else { ui.pentestButton.disabled = false; ui.pentestButton.querySelector("span").textContent = "Start pentest"; loadPentestRuns(); }
  } catch (err) { ui.pentestButton.disabled = false; showError(ui.pentestError, err.message); }
}

async function createPentest(e) {
  e?.preventDefault(); clearError(ui.pentestError); clearTimeout(state.pentestPollTimer);
  ui.pentestButton.disabled = true; ui.pentestButton.querySelector("span").textContent = "Starting…";
  try {
    const result = await api("/api/pentest", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ repository: ui.pentestRepository.value.trim(), scope_file: ui.pentestScope.value.trim(), mode: ui.pentestMode.value }) });
    renderPentestRun(result); if (result.pentest_run) await refreshPentestRun(result.pentest_run.run_id);
  } catch (err) { ui.pentestButton.disabled = false; ui.pentestButton.querySelector("span").textContent = "Start pentest"; showError(ui.pentestError, err.message); }
}

async function loadPentestRuns() {
  try {
    const data = await api("/api/pentest?limit=20"); ui.pentestRunsList.replaceChildren();
    const runs = data.runs || [];
    if (!runs.length) { const empty = document.createElement("li"); empty.className = "candidate-empty"; text(empty, "No pentest runs yet."); ui.pentestRunsList.append(empty); return; }
    runs.forEach(run => {
      const row = document.createElement("li"); row.className = "candidate-row"; row.style.cursor = "pointer";
      row.addEventListener("click", () => { ui.pentestEmpty.hidden = true; ui.pentestActive.hidden = false; refreshPentestRun(run.run_id); });
      const id = document.createElement("span"); const mode = document.createElement("span");
      const verdict = document.createElement("strong"); const status = document.createElement("span"); const created = document.createElement("span");
      text(id, run.run_id.slice(-12).toUpperCase()); text(mode, run.mode || "standard");
      verdict.className = `candidate-status ${run.candidate_verdict === "safe" ? "is-passed" : "is-failed"}`;
      text(verdict, verdictLabel(run.candidate_verdict)); text(status, verdictLabel(run.status)); text(created, formatTime(run.created_at));
      row.append(id, mode, verdict, status, created); ui.pentestRunsList.append(row);
    });
  } catch {}
}

// ===== OWNERSHIP =====
async function createOwnershipChallenge() {
  const type = ui.ownershipType.value;
  if (type === "none") { ui.ownershipChallengeArea.hidden = true; return; }
  ui.ownershipChallengeArea.hidden = false;
  try {
    const result = await api("/api/ownership/challenge", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ target_path: ui.pentestRepository.value.trim(), challenge_type: type }) });
    state.ownershipChallenge = result;
    ui.ownershipChallengeDisplay.hidden = false; ui.ownershipVerify.hidden = false;
    text(ui.ownershipInstruction, result.instruction);
    text(ui.ownershipToken, result.token);
  } catch (err) { showError(ui.pentestError, err.message); }
}

async function verifyOwnership() {
  if (!state.ownershipChallenge) return;
  try {
    const result = await api("/api/ownership/verify", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ target_path: ui.pentestRepository.value.trim(), challenge_type: state.ownershipChallenge.challenge_type, token: state.ownershipChallenge.token }) });
    ui.ownershipResult.hidden = false;
    if (result.verified) { text(ui.ownershipResult, "Ownership verified!"); ui.ownershipResult.style.color = "var(--safe)"; }
    else { text(ui.ownershipResult, "Verification failed. Try again."); ui.ownershipResult.style.color = "var(--danger)"; }
  } catch (err) { showError(ui.pentestError, err.message); }
}

// ===== SCHEDULES =====
async function createSchedule(e) {
  e?.preventDefault(); clearError(ui.scheduleError);
  try {
    const params = new URLSearchParams({ repository: ui.schedRepository.value.trim(), scope_file: ui.schedScope.value.trim(), mode: ui.schedMode.value, interval_minutes: ui.schedInterval.value });
    await api(`/api/pentest/schedule?${params}`, { method: "POST" }); loadSchedules();
  } catch (err) { showError(ui.scheduleError, err.message); }
}

async function loadSchedules() {
  try {
    const data = await api("/api/pentest/schedule"); ui.schedulesList.replaceChildren();
    const schedules = data.schedules || [];
    if (!schedules.length) { const empty = document.createElement("li"); empty.className = "candidate-empty"; text(empty, "No schedules configured."); ui.schedulesList.append(empty); return; }
    schedules.forEach(sched => {
      const row = document.createElement("li"); row.className = "candidate-row";
      const repo = document.createElement("span"); const mode = document.createElement("span");
      const interval = document.createElement("span"); const nextRun = document.createElement("span");
      const status = document.createElement("strong"); const action = document.createElement("button");
      text(repo, basename(sched.repository)); text(mode, sched.mode); text(interval, `${sched.interval_minutes}m`);
      text(nextRun, formatTime(sched.next_run_at));
      status.className = `candidate-status ${sched.enabled ? "is-passed" : "is-failed"}`; text(status, sched.enabled ? "ACTIVE" : "PAUSED");
      action.className = "text-button"; text(action, "Delete");
      action.addEventListener("click", async () => { try { await api(`/api/pentest/schedule/${sched.schedule_id}`, { method: "DELETE" }); loadSchedules(); } catch {} });
      row.append(repo, mode, interval, nextRun, status, action); ui.schedulesList.append(row);
    });
  } catch {}
}

// ===== SETTINGS =====
async function checkIntegrations() {
  try {
    const [, integrations] = await Promise.all([api("/health"), api("/api/integrations")]);
    ui.connectionDot.classList.add("safe"); text(ui.connectionLabel, "CONTROL PLANE ONLINE");
    const nimOk = integrations.nvidia_nim?.status === "configured";
    const nimDot = ui.nimIntegration.querySelector(".status-dot");
    nimDot.classList.toggle("safe", nimOk); nimDot.classList.toggle("waiting", !nimOk);
    text(ui.nimIntegrationStatus, nimOk ? "READY" : "KEY");
    const ghStatus = document.querySelector("#github-settings-dot");
    const ghLabel = document.querySelector("#github-settings-status");
    const ghIntDot = ui.githubIntegration.querySelector(".status-dot");
    try { const gh = await api("/api/github/status"); const ok = gh.status === "authenticated"; ghIntDot.classList.toggle("safe", ok); ghIntDot.classList.toggle("waiting", !ok); text(ui.githubIntegrationStatus, ok ? "READY" : "KEY"); if (ghStatus) { ghStatus.classList.toggle("safe", ok); ghStatus.classList.toggle("waiting", !ok); text(ghLabel, ok ? `Connected as ${gh.login}` : "Not configured"); } } catch { ghIntDot.classList.add("waiting"); text(ui.githubIntegrationStatus, "KEY"); }
    const nimSettingsDot = document.querySelector("#nim-settings-dot");
    const nimSettingsLabel = document.querySelector("#nim-settings-status");
    if (nimSettingsDot) { nimSettingsDot.classList.toggle("safe", nimOk); nimSettingsDot.classList.toggle("waiting", !nimOk); text(nimSettingsLabel, nimOk ? `Ready (${integrations.nvidia_nim?.model})` : "Awaiting API key"); }
  } catch { ui.connectionDot.classList.remove("safe"); text(ui.connectionLabel, "CONTROL PLANE OFFLINE"); }
}

async function generateCICD(e) {
  e?.preventDefault();
  try {
    const result = await api("/api/cicd/generate", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ repository: ui.cicdRepository.value.trim(), platform: ui.cicdPlatform.value }) });
    ui.cicdResult.hidden = false; text(ui.cicdResult, `Generated: ${result.file}`);
  } catch (err) { ui.cicdResult.hidden = false; text(ui.cicdResult, err.message); }
}

// ===== INTELLIGENCE =====
async function loadRedHatIntelligence(e) {
  e?.preventDefault();
  try {
    const pkg = ui.intelligencePackage.value.trim();
    const q = new URLSearchParams({ days: "90", limit: "5" }); if (pkg) q.set("package", pkg);
    const advisories = await api(`/api/intelligence/redhat?${q}`);
    ui.advisoryList.replaceChildren(); text(ui.intelligenceCount, `${advisories.length} ADVISORIES`);
    advisories.forEach(a => { const row = document.createElement("li"); row.className = "advisory-row"; const id = document.createElement("code"); const sev = document.createElement("span"); sev.className = "advisory-severity"; text(id, a.advisory_id); text(sev, a.severity); row.append(id, sev); ui.advisoryList.append(row); });
  } catch {}
}

function setTheme(theme) { document.documentElement.dataset.theme = theme; localStorage.setItem("sentinelforge.theme", theme); }
function toggleTheme() { setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark"); }

function initialize() {
  const savedTheme = localStorage.getItem("sentinelforge.theme"); setTheme(savedTheme || "dark");
  ui.themeToggle.addEventListener("click", toggleTheme);
  document.querySelectorAll(".rail-nav .nav-item[data-view]").forEach(i => i.addEventListener("click", e => { e.preventDefault(); switchView(i.dataset.view); }));

  setupScanTabs();
  ui.scanLocalForm.addEventListener("submit", runLocalScan);
  ui.scanGithubForm.addEventListener("submit", runGithubScan);
  ui.scanCreatePr.addEventListener("click", createPRFromScan);
  ui.scanDownload.addEventListener("click", downloadScanReport);
  ui.scanRepeat.addEventListener("click", () => runLocalScan());

  ui.form.addEventListener("submit", createRun);
  ui.repeatRun.addEventListener("click", () => createRun());
  ui.intelligenceForm.addEventListener("submit", loadRedHatIntelligence);

  ui.pentestForm.addEventListener("submit", createPentest);
  ui.pentestRepeat.addEventListener("click", () => createPentest());
  ui.refreshPentestRuns.addEventListener("click", loadPentestRuns);
  ui.ownershipType.addEventListener("change", () => { ui.ownershipChallengeArea.hidden = ui.ownershipType.value === "none"; });
  ui.ownershipCreate.addEventListener("click", createOwnershipChallenge);
  ui.ownershipVerify.addEventListener("click", verifyOwnership);

  ui.scheduleForm.addEventListener("submit", createSchedule);
  ui.refreshSchedules.addEventListener("click", loadSchedules);

  ui.cicdForm.addEventListener("submit", generateCICD);

  checkIntegrations(); loadRedHatIntelligence(); loadPentestRuns(); loadSchedules();
  switchView("scan");
}

initialize();
