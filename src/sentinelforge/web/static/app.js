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
};

const state = {
  currentRun: null,
  currentEvents: [],
  pollTimer: null,
};

const eventDescriptions = {
  run_queued: ["Run queued", "Authorization and workspace preflight recorded."],
  scan_started: ["Detector started", "Scanning supported source structures."],
  scan_completed: ["Detection complete", "Candidate evidence set finalized."],
  finding_confirmed: ["Security finding confirmed", "Release candidate marked blocked."],
  isolated_patch_started: ["Isolated patch started", "Source repository remains unchanged."],
  patch_verified: ["Patch verified", "Security regression and repository tests passed."],
  patch_rejected: ["Patch rejected", "Deterministic verification did not pass."],
  run_failed: ["Run failed", "Evidence gathered before failure remains available."],
};

function text(node, value) {
  node.textContent = value == null ? "—" : String(value);
}

function showError(message) {
  text(ui.error, message);
  ui.error.hidden = false;
}

function clearError() {
  ui.error.hidden = true;
  text(ui.error, "");
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
  setVerdict(
    ui.candidatePanel,
    ui.candidateVerdict,
    ui.candidateCaption,
    run.candidate_verdict,
    "candidate",
  );
  setVerdict(
    ui.patchPanel,
    ui.patchVerdict,
    ui.patchCaption,
    run.patch_verdict,
    "patch",
  );
  text(ui.integrationHealth, verdictLabel(run.integration_health));
  ui.integrationHealth.style.color =
    run.integration_health === "healthy" ? "var(--safe)" : "var(--warning)";

  const result = run.result || {};
  const finding = Array.isArray(result.findings) ? result.findings[0] : null;
  const bundle = result.patch_bundle || null;
  const verification = result.verification || null;
  renderFinding(finding);
  renderPatch(bundle);
  renderVerification(verification);
  ui.downloadEvidence.disabled = !run.result;

  if (run.error) showError(run.error);
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
  if (event.kind === "scan_started") return payload.detector || "detector";
  if (event.kind === "scan_completed") return `${payload.finding_count || 0} finding(s)`;
  if (event.kind === "finding_confirmed") {
    return `${payload.rule_id || "finding"} · ${String(payload.severity || "").toUpperCase()}`;
  }
  if (event.kind === "patch_verified" || event.kind === "patch_rejected") {
    const digest = String(payload.patch_sha256 || "").slice(0, 12);
    return `${digest || "patch"} · exit ${payload.exit_code} · ${payload.duration_ms} ms`;
  }
  if (event.kind === "run_queued") return payload.repository || "authorized repository";
  return event.phase;
}

function renderEvents(events) {
  state.currentEvents = events;
  ui.timeline.replaceChildren();
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
    ui.timeline.append(item);
  });
  text(ui.eventCount, `${events.length} EVENT${events.length === 1 ? "" : "S"}`);
}

async function api(path, options) {
  const response = await fetch(path, options);
  let payload = null;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }
  if (!response.ok) {
    throw new Error(payload?.detail || `Request failed with status ${response.status}`);
  }
  return payload;
}

async function refreshRun(runId) {
  try {
    const [run, events] = await Promise.all([
      api(`/api/runs/${encodeURIComponent(runId)}`),
      api(`/api/runs/${encodeURIComponent(runId)}/events`),
    ]);
    renderRun(run);
    renderEvents(events);
    clearError();
    if (["queued", "running"].includes(run.lifecycle)) {
      state.pollTimer = window.setTimeout(() => refreshRun(runId), 450);
    } else {
      ui.runButton.disabled = false;
      ui.runButton.querySelector("span").textContent = "Start proof run";
    }
  } catch (error) {
    ui.runButton.disabled = false;
    showError(error.message);
  }
}

async function createRun(event) {
  event?.preventDefault();
  clearError();
  window.clearTimeout(state.pollTimer);
  ui.runButton.disabled = true;
  ui.runButton.querySelector("span").textContent = "Starting…";
  try {
    const run = await api("/api/runs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        repository: ui.repository.value.trim(),
        remediate: ui.remediate.checked,
      }),
    });
    renderRun(run);
    renderEvents([]);
    localStorage.setItem("sentinelforge.repository", ui.repository.value.trim());
    await refreshRun(run.run_id);
  } catch (error) {
    ui.runButton.disabled = false;
    ui.runButton.querySelector("span").textContent = "Start proof run";
    showError(error.message);
  }
}

function downloadEvidence() {
  if (!state.currentRun) return;
  const payload = {
    run: state.currentRun,
    events: state.currentEvents,
    exported_at: new Date().toISOString(),
  };
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
    showError("Clipboard access was denied. Select the digest manually.");
  }
}

function setTheme(theme) {
  document.documentElement.dataset.theme = theme;
  ui.themeToggle.setAttribute("aria-label", `Use ${theme === "dark" ? "light" : "dark"} mode`);
  localStorage.setItem("sentinelforge.theme", theme);
}

function toggleTheme() {
  const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  setTheme(next);
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
    ui.nimIntegration.title = nimConfigured
      ? integrations.nvidia_nim.model
      : "Add NVIDIA_API_KEY to the local .env file";
  } catch {
    ui.connectionDot.classList.remove("safe");
    ui.connectionDot.classList.add("offline");
    text(ui.connectionLabel, "CONTROL PLANE OFFLINE");
  }
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
  checkConnection();
}

initialize();
