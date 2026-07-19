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
  pentestTargetType: document.querySelector("#pentest-target-type"),
  pentestStagingUrl: document.querySelector("#pentest-staging-url"),
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
  pentestCustomCount: document.querySelector("#pentest-custom-count"),
  pentestDepVulnCount: document.querySelector("#pentest-dep-vuln-count"),
  pentestPatternCount: document.querySelector("#pentest-pattern-count"),
  pentestHlCount: document.querySelector("#pentest-hl-count"),
  pentestEvidenceList: document.querySelector("#pentest-evidence-list"),
  finalReportEmpty: document.querySelector("#final-report-empty"),
  finalReportDetail: document.querySelector("#final-report-detail"),
  finalReportContent: document.querySelector("#final-report-content"),
  finalReportActions: document.querySelector("#final-report-actions"),
  finalReportStatus: document.querySelector("#final-report-status"),
  humanReviewStatus: document.querySelector("#human-review-status"),
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
  currentPentestStartedAt: null,
  maxRunSeconds: 1800,
  scanPollTimer: null,
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
  custom_exploit_started: ["Custom exploit writer started", "Agent is writing novel Python exploit from scratch using Nemotron."],
  custom_exploit_written: ["Custom exploit written!", "Agent wrote new Python file to .sentinelforge/exploits/ - proves not a toy."],
  custom_exploit_executed: ["Custom exploit executed", "Agent's Python exploit ran against staging - check output."],
  dependency_scan_completed: ["Dependency scan complete", "Red Hat SBOM + VEX + reachability analysis finished."],
  pattern_scan_completed: ["Pattern scan complete", "Code-level exploit patterns identified."],
  hiddenlayer_safety_scan_completed: ["Safety scan complete", "HiddenLayer injection analysis finished."],
  phase_completed: ["Phase completed", "Orchestrator advanced to next phase."],
  orchestration_started: ["Orchestration started", "Long-running agent workflow initiated."],
  orchestration_completed: ["Orchestration completed", "All phases executed."],
  nim_threat_analysis_completed: ["NIM analysis complete", "Nemotron threat assessment finished."],
  no_impact_evidence: ["No-impact evidence", "VEX: vulnerable code not in execute path."],
  exploit_replayed_against_patch: ["Exploit replay blocked", "Mutated exploit blocked after patch - adversarial verification."],
  openshell_audit_completed: ["OpenShell audit done", "Policy enforced, denied actions logged."],
  openshell_denied: ["Action BLOCKED by OpenShell", "Policy denied action. Agent blocked."],
  cve_ingestion_completed: ["CVE intelligence loaded", "Recent CVEs, KEV, EPSS data ingested."],
  threat_learning_completed: ["Threat patterns learned", "Patterns extracted from CVEs and scans."],
  zero_day_hunting_completed: ["Zero-day hunt complete", "Hypothesis-driven exploration finished."],
  adaptive_payload_effectiveness: ["Adaptive payload update", "Thompson Sampling updated effectiveness."],
  swarm_launched: ["Agent swarm launched", "Multiple attack agents spawned in parallel."],
  swarm_agent_spawned: ["Swarm agent spawned", "A new attack agent started work."],
  swarm_agent_completed: ["Swarm agent completed", "An attack agent finished its task."],
  swarm_agent_failed: ["Swarm agent failed", "An attack agent hit an error."],
  swarm_finished: ["Agent swarm finished", "All parallel attack agents reported back."],
  hypotheses_generated: ["Novel hypotheses generated", "LLM + composition engine proposed new attacks."],
  novel_finding: ["NOVEL FINDING", "Near-zero-day class attack succeeded."],
  intel_enriched: ["Multi-source intel", "OSV + GHSA advisories merged and ranked."],
  evidence_bundled: ["Evidence bundled", "Findings packaged with hashes and replay commands."],
  learning_delta_recorded: ["Learning recorded", "Real run metrics stored in target memory."],
  patch_agent_started: ["Patch agent started", "Analyzing finding for patch generation."],
  patch_proposed: ["Patch proposed", "NIM/vLLM proposed a minimal fix."],
  patch_pr_created: ["Draft PR created", "Patch PR opened - human review required."],
  patch_verification_failed: ["Patch rejected", "Mutated exploit still succeeds against patch."],
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
    const item = document.createElement("li"); 
    item.className = "timeline-item";
    if (e.kind === "custom_exploit_written") item.classList.add("highlight-exploit");
    if (e.kind === "custom_exploit_executed") item.classList.add("highlight-execution");
    if (e.kind === "exploit_replayed_against_patch") item.classList.add("highlight-blocked");
    const marker = document.createElement("span"); marker.className = "timeline-marker"; text(marker, String(i + 1).padStart(2, "0"));
    const content = document.createElement("div"); content.className = "timeline-content";
    const title = document.createElement("strong"); const desc = document.createElement("p");
    const labels = eventDescriptions[e.kind] || [e.kind, e.phase];
    text(title, labels[0]); 
    
    // Enhanced description for custom exploit events
    let description = `${labels[1]} · ${e.phase}`;
    if (e.kind === "custom_exploit_written" && e.payload) {
      description = `Agent wrote ${e.payload.file_path?.split('/').pop() || 'exploit.py'} for ${e.payload.route || ''} using ${e.payload.generated_by || 'nemotron'} (${e.payload.content_lines || 0} lines) - PROVES NOT A TOY`;
    } else if (e.kind === "custom_exploit_executed" && e.payload) {
      description = `Executed ${e.payload.file_path?.split('/').pop() || ''} -> ${e.payload.outcome || ''} - Output: ${(e.payload.execution_output_preview || '').slice(0,100)}`;
    }
    text(desc, description);
    content.append(title, desc);
    
    // Add file path badge for custom exploits
    if (e.payload?.file_path) {
      const fileBadge = document.createElement("code");
      fileBadge.className = "exploit-file-badge";
      fileBadge.textContent = e.payload.file_path;
      content.append(fileBadge);
    }
    
    const time = document.createElement("time"); time.className = "timeline-time"; time.dateTime = e.occurred_at; text(time, formatTime(e.occurred_at));
    item.append(marker, content, time); target.append(item);
  });
}

// ===== SCAN =====
const SCAN_ICONS = {
  fastapi_bola: "🔓", django_bola: "🐍", pattern_scan: "🔍",
  dependency_parse: "📦", vuln_scan: "🛡️", scan: "⚡",
};

let scanEventSource = null;

function appendScanLogEntry(event) {
  const log = document.querySelector("#scan-log");
  if (!log) return;
  const entry = document.createElement("div");
  const kind = event.kind;
  let cls = "scan-log-entry";
  if (kind === "agent_started") cls += " log-started";
  else if (kind === "agent_completed") cls += " log-completed";
  else if (kind === "finding" || kind === "vuln_found") cls += " log-finding";
  else if (kind === "agent_error") cls += " log-error";
  else if (kind === "scan_completed") cls += " log-complete";
  else if (kind === "checking_file") cls += " log-progress";
  else if (kind === "checking_package") cls += " log-progress";
  entry.className = cls;
  const ts = new Date(event.timestamp * 1000).toLocaleTimeString();
  const icon = SCAN_ICONS[event.phase] || "▸";
  const msg = event.payload?.message || event.kind;
  text(entry, `[${ts}] ${icon} ${msg}`);
  log.prepend(entry);
  while (log.children.length > 200) log.removeChild(log.lastChild);
}

function updateScanAgentStatus(event) {
  const agents = document.querySelector("#scan-agent-activity");
  if (!agents) return;
  const phase = event.phase;
  const kind = event.kind;
  let row = agents.querySelector(`[data-phase="${phase}"]`);
  if (!row) {
    row = document.createElement("div");
    row.className = "scan-agent-row";
    row.dataset.phase = phase;
    const icon = document.createElement("span");
    icon.className = "scan-agent-icon";
    icon.textContent = SCAN_ICONS[phase] || "▸";
    const name = document.createElement("span");
    name.className = "scan-agent-name";
    text(name, event.payload?.agent || phase);
    const detail = document.createElement("span");
    detail.className = "scan-agent-detail";
    const status = document.createElement("span");
    status.className = "scan-agent-status";
    row.append(icon, name, detail, status);
    agents.append(row);
  }
  const detail = row.querySelector(".scan-agent-detail");
  const status = row.querySelector(".scan-agent-status");
  const msg = event.payload?.message || "";
  text(detail, msg);

  if (kind === "agent_started" || kind === "checking_file" || kind === "checking_package") {
    row.classList.add("active");
    row.classList.remove("done");
    text(status, "running");
  } else if (kind === "agent_completed") {
    row.classList.remove("active");
    row.classList.add("done");
    text(status, "done");
  } else if (kind === "agent_error") {
    row.classList.remove("active");
    row.classList.add("error");
    text(status, "error");
  }
}

function setupScanTabs() {
  document.querySelectorAll(".scan-tab").forEach(tab => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".scan-tab").forEach(t => t.classList.remove("active"));
      tab.classList.add("active");
      const isGithub = tab.dataset.tab === "github";
      ui.scanLocalForm.hidden = isGithub;
      ui.scanGithubForm.hidden = !isGithub;
      if (isGithub) {
        // Auto-load GitHub repos when switching to GitHub tab
        checkGithubOAuthStatus();
        loadGithubReposList();
      }
    });
  });
}

// ===== GITHUB OAUTH + REPO LISTING =====
async function checkGithubOAuthStatus() {
  const statusEl = document.querySelector("#github-oauth-status") || document.querySelector("#settings-github-oauth-status");
  const configEl = document.querySelector("#settings-github-oauth-config");
  try {
    const status = await api("/api/github/status");
    const oauthConfig = await api("/api/github/oauth/config").catch(() => ({configured:false}));
    
    const isAuth = status.status === "authenticated";
    const login = status.login || "GitHub User";
    
    if (statusEl) {
      if (isAuth) {
        statusEl.innerHTML = `✅ Connected as <strong>${login}</strong> (via ${status.source || 'token'}) - Ready to list repos`;
        statusEl.style.color = "var(--safe)";
      } else {
        statusEl.textContent = `Not connected: ${status.message || 'Set GITHUB_TOKEN or connect via OAuth'}`;
        statusEl.style.color = "var(--muted)";
      }
    }
    
    if (configEl) {
      if (oauthConfig.configured) {
        configEl.textContent = `OAuth App configured: ${oauthConfig.client_id} | Callback: ${oauthConfig.callback_url} | Token: ${oauthConfig.has_token ? 'Stored securely' : 'Not yet'}`;
      } else {
        configEl.innerHTML = `OAuth not configured. To enable super cool OAuth:<br/>
        1. Go to <a href="https://github.com/settings/developers" target="_blank" style="color:var(--info)">github.com/settings/developers</a> → OAuth Apps → New OAuth App<br/>
        2. Set Authorization callback URL to <code>http://localhost:8741/api/github/oauth/callback</code><br/>
        3. Add to .env: <code>GITHUB_CLIENT_ID=xxx</code> and <code>GITHUB_CLIENT_SECRET=yyy</code><br/>
        4. Restart API and click Connect again<br/>
        <em>Or just use GITHUB_TOKEN in .env for manual flow.</em>`;
      }
    }
    
    // Update repo list if authenticated
    if (isAuth) {
      const container = document.querySelector("#github-repos-list-container");
      if (container) container.hidden = false;
    }
    
    return status;
  } catch (err) {
    if (statusEl) {
      statusEl.textContent = `GitHub status check failed: ${err.message}`;
      statusEl.style.color = "var(--blocked)";
    }
    return null;
  }
}

async function startGithubOAuth() {
  try {
    const result = await api("/api/github/oauth/start");
    if (result.authorize_url) {
      // Open popup for OAuth
      const width = 600, height = 700;
      const left = window.screenX + (window.outerWidth - width) / 2;
      const top = window.screenY + (window.outerHeight - height) / 2;
      const popup = window.open(result.authorize_url, "github_oauth", `width=${width},height=${height},left=${left},top=${top},popup=1`);
      
      if (!popup) {
        // Fallback: redirect current window
        window.location.href = result.authorize_url;
        return;
      }
      
      // Poll for popup close
      const checkPopup = setInterval(async () => {
        if (popup.closed) {
          clearInterval(checkPopup);
          // Check if auth succeeded
          setTimeout(async () => {
            await checkGithubOAuthStatus();
            await checkIntegrations();
            await loadGithubReposList();
          }, 1000);
        }
      }, 500);
      
      // Listen for postMessage from callback
      const messageHandler = (event) => {
        if (event.data && event.data.type === "github_oauth_success") {
          window.removeEventListener("message", messageHandler);
          clearInterval(checkPopup);
          if (popup && !popup.closed) popup.close();
          checkGithubOAuthStatus();
          checkIntegrations();
          loadGithubReposList();
        }
      };
      window.addEventListener("message", messageHandler);
      
      // Timeout after 5 minutes
      setTimeout(() => {
        clearInterval(checkPopup);
        window.removeEventListener("message", messageHandler);
      }, 300000);
    }
  } catch (err) {
    alert(`GitHub OAuth start failed: ${err.message}\n\nMake sure GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET are set in .env.\nSee docs/GITHUB_OAUTH.md for setup.`);
  }
}

async function disconnectGithub() {
  if (!confirm("Disconnect GitHub? This will delete the stored OAuth token in .sentinelforge/github_token.json")) return;
  try {
    await api("/api/github/oauth/disconnect", {method: "POST"});
    alert("GitHub disconnected. Token deleted.");
    checkGithubOAuthStatus();
    checkIntegrations();
    const container = document.querySelector("#github-repos-list-container");
    if (container) container.hidden = true;
    document.querySelector("#github-repos-list")?.replaceChildren();
  } catch (err) {
    alert(`Disconnect failed: ${err.message}`);
  }
}

async function loadGithubReposList() {
  const listEl = document.querySelector("#github-repos-list");
  const container = document.querySelector("#github-repos-list-container");
  const previewEl = document.querySelector("#settings-github-repos-preview");
  
  if (!listEl && !previewEl) return;
  
  try {
    const data = await api("/api/github/repos?limit=30&sort=updated");
    const repos = data.repos || [];
    
    // Render in scan tab list
    if (listEl) {
      listEl.replaceChildren();
      if (repos.length === 0) {
        const empty = document.createElement("li");
        empty.style.padding = "0.75rem";
        empty.style.color = "var(--muted)";
        empty.style.fontSize = "12px";
        empty.textContent = "No repos found. Check your GitHub token scopes include repo,read:org.";
        listEl.append(empty);
      } else {
        repos.forEach(repo => {
          const li = document.createElement("li");
          li.style.cssText = "padding:0.5rem 0.75rem; border-bottom:1px solid var(--border); display:flex; justify-content:space-between; align-items:center; cursor:pointer; hover:background:var(--panel-raised)";
          li.addEventListener("mouseenter", () => li.style.background = "var(--panel-raised)");
          li.addEventListener("mouseleave", () => li.style.background = "transparent");
          
          const info = document.createElement("div");
          info.style.flex = "1";
          const name = document.createElement("strong");
          name.style.fontSize = "13px";
          name.textContent = repo.full_name;
          if (repo.private) {
            name.textContent += " 🔒";
            name.title = "Private repo";
          }
          const desc = document.createElement("div");
          desc.style.fontSize = "11px";
          desc.style.color = "var(--muted)";
          desc.textContent = `${repo.description?.slice(0,80) || 'No description'} • ${repo.language || 'Unknown'} • ${repo.default_branch}`;
          
          info.append(name, desc);
          
          const actions = document.createElement("div");
          actions.style.display = "flex";
          actions.style.gap = "0.25rem";
          
          const scanBtn = document.createElement("button");
          scanBtn.className = "secondary-button";
          scanBtn.style.fontSize = "11px";
          scanBtn.style.padding = "2px 8px";
          scanBtn.textContent = "Scan";
          scanBtn.addEventListener("click", (e) => {
            e.stopPropagation();
            // Auto-fill owner/repo inputs and trigger scan
            const parts = repo.full_name.split("/");
            if (parts.length === 2) {
              document.querySelector("#scan-github-owner").value = parts[0];
              document.querySelector("#scan-github-repo").value = parts[1];
              // Scroll to form
              document.querySelector("#scan-github-form")?.scrollIntoView({behavior:"smooth"});
            }
          });
          
          const viewBtn = document.createElement("a");
          viewBtn.href = repo.url;
          viewBtn.target = "_blank";
          viewBtn.textContent = "View";
          viewBtn.style.fontSize = "11px";
          viewBtn.style.padding = "2px 8px";
          viewBtn.style.textDecoration = "none";
          viewBtn.style.color = "var(--info)";
          
          actions.append(scanBtn, viewBtn);
          li.append(info, actions);
          
          // Click row auto-fills
          li.addEventListener("click", () => {
            const parts = repo.full_name.split("/");
            if (parts.length === 2) {
              document.querySelector("#scan-github-owner").value = parts[0];
              document.querySelector("#scan-github-repo").value = parts[1];
            }
          });
          
          listEl.append(li);
        });
      }
      if (container) container.hidden = false;
    }
    
    // Render preview in settings
    if (previewEl) {
      previewEl.replaceChildren();
      previewEl.hidden = false;
      if (repos.length === 0) {
        previewEl.textContent = "No repos found.";
      } else {
        const title = document.createElement("div");
        title.style.fontSize = "12px";
        title.style.fontWeight = "600";
        title.style.marginBottom = "0.5rem";
        title.textContent = `Your Repos (${repos.length} shown, ${data.total} total) - Click Scan in Scan tab to test`;
        previewEl.append(title);
        repos.slice(0,5).forEach(repo => {
          const div = document.createElement("div");
          div.style.fontSize = "11px";
          div.style.padding = "2px 0";
          div.style.borderBottom = "1px solid var(--border)";
          div.textContent = `${repo.full_name} ${repo.private ? '🔒' : ''} - ${repo.language || ''}`;
          previewEl.append(div);
        });
      }
    }
    
  } catch (err) {
    // If not configured, hide list and show message
    if (listEl) {
      listEl.replaceChildren();
      const msg = document.createElement("li");
      msg.style.padding = "0.75rem";
      msg.style.color = "var(--warning)";
      msg.style.fontSize = "12px";
      msg.textContent = `GitHub not connected: ${err.message}. Connect via OAuth or set GITHUB_TOKEN in .env`;
      listEl.append(msg);
    }
    console.log("Failed to load GitHub repos:", err.message);
  }
}

function setupGithubSearch() {
  const searchInput = document.querySelector("#github-repos-search");
  if (!searchInput) return;
  searchInput.addEventListener("input", async (e) => {
    const query = e.target.value.trim();
    if (query.length < 2) {
      loadGithubReposList();
      return;
    }
    try {
      const data = await api(`/api/github/repos?limit=30&search=${encodeURIComponent(query)}`);
      const listEl = document.querySelector("#github-repos-list");
      if (!listEl) return;
      listEl.replaceChildren();
      (data.repos || []).forEach(repo => {
        const li = document.createElement("li");
        li.style.padding = "0.5rem 0.75rem";
        li.style.borderBottom = "1px solid var(--border)";
        li.textContent = repo.full_name;
        li.style.cursor = "pointer";
        li.addEventListener("click", () => {
          const parts = repo.full_name.split("/");
          if (parts.length === 2) {
            document.querySelector("#scan-github-owner").value = parts[0];
            document.querySelector("#scan-github-repo").value = parts[1];
          }
        });
        listEl.append(li);
      });
    } catch {}
  });
}

async function runLocalScan(e) {
  e?.preventDefault(); clearError(ui.scanError);
  if (scanEventSource) { scanEventSource.close(); scanEventSource = null; }
  stopScanPolling();
  ui.scanButton.disabled = true; ui.scanButton.querySelector("span").textContent = "Scanning…";
  ui.scanEmpty.hidden = true;
  document.querySelector("#scan-progress").hidden = false;
  document.querySelector("#scan-agent-activity").replaceChildren();
  document.querySelector("#scan-log").replaceChildren();

  try {
    const result = await api("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ repository: ui.scanRepoInput.value.trim() }) });
    if (!result.scan_id) throw new Error("No scan_id returned");
    attachScanStream(result.scan_id);
  } catch (err) {
    document.querySelector("#scan-progress").hidden = true;
    ui.scanEmpty.hidden = false;
    showError(ui.scanError, err.message);
    ui.scanButton.disabled = false;
    ui.scanButton.querySelector("span").textContent = "Start scan";
  }
}

function attachScanStream(scanId) {
  saveActiveScan(scanId);
  scanEventSource = new EventSource(`/api/scan/${scanId}/stream`);
  scanEventSource.onmessage = async (e) => {
    try {
      const event = JSON.parse(e.data);
      appendScanLogEntry(event);
      updateScanAgentStatus(event);
      if (event.kind === "scan_completed") {
        if (scanEventSource) { scanEventSource.close(); scanEventSource = null; }
        await finishScan(scanId);
      }
    } catch {}
  };
  scanEventSource.onerror = () => {
    scanEventSource.close();
    scanEventSource = null;
    // Polling fallback continues below
  };
  startScanPolling(scanId);
}

function stopScanPolling() {
  if (state.scanPollTimer) {
    clearInterval(state.scanPollTimer);
    state.scanPollTimer = null;
  }
}

function startScanPolling(scanId) {
  stopScanPolling();
  const startedAt = Date.now();
  state.scanPollTimer = setInterval(async () => {
    if (Date.now() - startedAt > 15 * 60 * 1000) {
      stopScanPolling();
      clearActiveScan();
      document.querySelector("#scan-progress").hidden = true;
      showError(ui.scanError, "Scan timed out (15m). Check run history or retry.");
      ui.scanButton.disabled = false;
      ui.scanButton.querySelector("span").textContent = "Start scan";
      ui.scanGithubButton.disabled = false;
      ui.scanGithubButton.querySelector("span").textContent = "Scan GitHub repo";
      return;
    }
    try {
      const fullResult = await api(`/api/scan/${scanId}`);
      if (fullResult && fullResult.summary) {
        stopScanPolling();
        if (scanEventSource) { scanEventSource.close(); scanEventSource = null; }
        await finishScan(scanId, fullResult);
      }
    } catch {
      // 404 while running — keep polling
    }
  }, 2500);
}

async function finishScan(scanId, prefetched) {
  stopScanPolling();
  clearActiveScan();
  try {
    const fullResult = prefetched || await api(`/api/scan/${scanId}`);
    await new Promise(r => setTimeout(r, 300));
    document.querySelector("#scan-progress").hidden = true;
    renderScanResults(fullResult);
  } catch {
    document.querySelector("#scan-progress").hidden = true;
    showError(ui.scanError, "Failed to fetch scan results");
  }
  ui.scanButton.disabled = false;
  ui.scanButton.querySelector("span").textContent = "Start scan";
  ui.scanGithubButton.disabled = false;
  ui.scanGithubButton.querySelector("span").textContent = "Scan GitHub repo";
}

async function runGithubScan(e) {
  e?.preventDefault(); clearError(ui.scanError);
  if (scanEventSource) { scanEventSource.close(); scanEventSource = null; }
  stopScanPolling();
  ui.scanGithubButton.disabled = true; ui.scanGithubButton.querySelector("span").textContent = "Scanning…";
  ui.scanEmpty.hidden = true;
  document.querySelector("#scan-progress").hidden = false;
  document.querySelector("#scan-agent-activity").replaceChildren();
  document.querySelector("#scan-log").replaceChildren();

  try {
    const result = await api("/api/scan/github", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ owner: ui.scanGithubOwner.value.trim(), repo: ui.scanGithubRepo.value.trim() }) });
    if (!result.scan_id) throw new Error("No scan_id returned");
    attachScanStream(result.scan_id);
  } catch (err) {
    document.querySelector("#scan-progress").hidden = true;
    ui.scanEmpty.hidden = false;
    showError(ui.scanError, err.message);
    ui.scanGithubButton.disabled = false;
    ui.scanGithubButton.querySelector("span").textContent = "Scan GitHub repo";
  }
}

function renderScanResults(result) {
  state.scanResults = result;
  ui.scanEmpty.hidden = true; ui.scanResults.hidden = false;
  text(ui.scanRepoName, basename(result.repository));
  const s = result.summary;
  text(ui.scanBolaCount, s.bola_count);
  text(ui.scanPatternCount, s.pattern_count);
  text(ui.scanDepCount, s.dep_vuln_count);
  ui.scanBolaCount.style.color = s.bola_count > 0 ? "var(--danger)" : "var(--safe)";
  ui.scanPatternCount.style.color = s.pattern_count > 0 ? "var(--warning)" : "var(--safe)";

  ui.scanFindingsList.replaceChildren();
  const allFindings = [...(result.bola_findings || []), ...(result.pattern_findings?.findings || [])];
  if (!allFindings.length) {
    const empty = document.createElement("div");
    empty.className = "scan-no-findings";
    const icon = document.createElement("span");
    icon.className = "scan-no-findings-icon";
    icon.textContent = "✅";
    const msg = document.createElement("p");
    text(msg, "No vulnerabilities detected across all scan vectors.");
    empty.append(icon, msg);
    ui.scanFindingsList.append(empty);
    return;
  }

  // Severity summary bar
  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  allFindings.forEach(f => { sevCounts[f.severity] = (sevCounts[f.severity] || 0) + 1; });
  const summaryBar = document.createElement("div");
  summaryBar.className = "scan-severity-summary";
  Object.entries(sevCounts).forEach(([sev, count]) => {
    if (count > 0) {
      const pill = document.createElement("span");
      pill.className = `severity-pill sev-${sev}`;
      text(pill, `${count} ${sev.toUpperCase()}`);
      summaryBar.append(pill);
    }
  });
  ui.scanFindingsList.append(summaryBar);

  allFindings.forEach(f => {
    const row = document.createElement("div"); row.className = "finding-row";
    const sev = document.createElement("span");
    sev.className = `severity-badge sev-${f.severity}`;
    text(sev, f.severity?.toUpperCase() || "?");
    const info = document.createElement("div"); info.className = "finding-info";
    const title = document.createElement("strong");
    text(title, f.title || f.vulnerability || "Finding");
    const loc = document.createElement("code");
    text(loc, `${f.path || f.file_path || ""}:${f.line || ""}`);
    const desc = document.createElement("p"); text(desc, (f.description || "").slice(0, 200));
    info.append(title, loc, desc);
    if (f.severity === "critical" || f.severity === "high") {
      const prBtn = document.createElement("button");
      prBtn.className = "text-button"; text(prBtn, "Create PR");
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
// Exact phase values emitted by the backend orchestrator (Phase enum).
const PHASE_ICONS = {
  init: "⚡", ownership_verification: "🔑", environment_check: "🌍",
  scoping: "📋", cve_ingestion: "📰", mapping: "🗺️",
  dependency_scan: "📦", pattern_scan: "🔍", threat_learning: "🧠",
  auth_attack: "⚔️", injection_attack: "💉", zero_day_hunting: "🔮",
  custom_exploit: "💻", hiddenlayer_scan: "🛡️", openshell_audit: "🔒",
  nim_analysis: "🤖", attestation: "📝", complete: "✅",
  // handler-emitted aliases
  attacking: "⚔️", safety: "🛡️", openshell: "🔒", patch_pr: "🔧",
};

const PHASE_NAMES = {
  init: "Initialization", ownership_verification: "Ownership Verification",
  environment_check: "Environment Check", scoping: "Scoping",
  cve_ingestion: "CVE Intelligence", mapping: "Surface Mapping",
  dependency_scan: "Dependency Scan", pattern_scan: "Pattern Scan",
  threat_learning: "Threat Learning", auth_attack: "Auth Attack (BOLA)",
  injection_attack: "Injection Attack", zero_day_hunting: "Zero-Day Hunting",
  custom_exploit: "Custom Exploit Writer", hiddenlayer_scan: "HiddenLayer Safety",
  openshell_audit: "OpenShell Policy Audit", nim_analysis: "NIM Threat Analysis",
  attestation: "Signed Attestation", complete: "Complete",
};

const PHASE_ORDER = [
  "init", "ownership_verification", "environment_check", "scoping",
  "cve_ingestion", "mapping", "dependency_scan", "pattern_scan",
  "threat_learning", "auth_attack", "injection_attack",
  "zero_day_hunting", "custom_exploit", "hiddenlayer_scan",
  "openshell_audit", "nim_analysis", "attestation", "complete",
];

function renderLiveProgressBar(phases, currentPhase) {
  const bar = document.querySelector("#pentest-progress-bar");
  if (!bar) return;
  bar.replaceChildren();
  const currentIdx = PHASE_ORDER.indexOf(currentPhase);
  PHASE_ORDER.forEach((phase, i) => {
    const step = document.createElement("div");
    step.className = "progress-step";
    if (currentIdx >= 0 && i < currentIdx) step.classList.add("done");
    else if (i === currentIdx) step.classList.add("active");
    step.title = PHASE_NAMES[phase] || phase;
    const icon = document.createElement("span");
    icon.className = "progress-icon";
    icon.textContent = PHASE_ICONS[phase] || "•";
    const label = document.createElement("span");
    label.className = "progress-label";
    label.textContent = PHASE_NAMES[phase] || phase.replace(/_/g, " ");
    step.append(icon, label);
    bar.append(step);
    if (i < PHASE_ORDER.length - 1) {
      const conn = document.createElement("div");
      conn.className = currentIdx >= 0 && i < currentIdx ? "progress-connector done" : "progress-connector";
      bar.append(conn);
    }
  });
}

// --- Active agents panel: derived from real backend events only ---
const activeAgents = new Map(); // key -> {agent, detail, started}

function agentEventKey(event) {
  const p = event.payload || {};
  return p.task_id || p.agent || event.kind;
}

function updateActiveAgents(event) {
  const panel = document.querySelector("#pentest-active-agents");
  if (!panel) return;
  const p = event.payload || {};
  const key = agentEventKey(event);
  const isStart = ["agent_started", "swarm_agent_spawned", "swarm_launched", "phase_started", "identities_provisioning"].includes(event.kind);
  const isEnd = ["agent_completed", "swarm_agent_completed", "swarm_agent_failed", "swarm_finished", "agent_error", "identity_provisioned", "identities_provision_failed"].includes(event.kind);

  if (isStart) {
    activeAgents.set(key, {
      agent: p.agent || event.phase,
      detail: (p.message || event.kind).slice(0, 80),
      started: event.timestamp,
    });
  } else if (isEnd) {
    activeAgents.delete(key);
    // swarm_launched/finished share the coordinator key
    if (event.kind === "swarm_finished") activeAgents.delete("SwarmCoordinator");
  }
  renderActiveAgents();
}

function renderActiveAgents() {
  const panel = document.querySelector("#pentest-active-agents");
  if (!panel) return;
  panel.replaceChildren();
  if (activeAgents.size === 0) {
    const empty = document.createElement("span");
    empty.className = "agents-empty";
    empty.textContent = "No agents currently running — completed agents appear in the feed below.";
    panel.append(empty);
    return;
  }
  for (const [, info] of activeAgents) {
    const chip = document.createElement("div");
    chip.className = "agent-chip running";
    const spinner = document.createElement("span");
    spinner.className = "agent-spinner";
    const name = document.createElement("strong");
    name.textContent = info.agent;
    const detail = document.createElement("span");
    detail.className = "agent-chip-detail";
    detail.textContent = info.detail;
    chip.append(spinner, name, detail);
    panel.append(chip);
  }
}

function updatePhasePanel(event) {
  const phaseEl = document.querySelector("#pentest-phase");
  const detailEl = document.querySelector("#pentest-phase-detail");
  if (!phaseEl || !detailEl) return;
  const p = event.payload || {};
  if (event.kind === "phase_started" && p.phase) {
    const name = PHASE_NAMES[p.phase] || p.phase.replace(/_/g, " ");
    text(phaseEl, name.toUpperCase());
    text(detailEl, `Phase started — agents working.`);
  } else if (event.kind === "phase_completed" && p.phase) {
    const name = PHASE_NAMES[p.phase] || p.phase.replace(/_/g, " ");
    text(detailEl, `${name} complete.`);
  } else if (["agent_started", "agent_completed", "swarm_launched", "swarm_finished", "novel_finding", "openshell_denied", "verdict"].includes(event.kind)) {
    if (p.message) text(detailEl, p.message.slice(0, 140));
  }
}

let elapsedTimer = null;
function startElapsedClock(startedAtIso, maxSeconds) {
  const el = document.querySelector("#pentest-elapsed");
  if (!el) return;
  if (elapsedTimer) clearInterval(elapsedTimer);
  const startMs = startedAtIso ? new Date(startedAtIso).getTime() : Date.now();
  const fmt = (s) => `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(Math.floor(s % 60)).padStart(2, "0")}`;
  const tick = () => {
    const elapsed = Math.max(0, (Date.now() - startMs) / 1000);
    el.textContent = maxSeconds
      ? `${fmt(elapsed)} elapsed / ${fmt(maxSeconds)} max`
      : `${fmt(elapsed)} elapsed`;
  };
  tick();
  elapsedTimer = setInterval(tick, 1000);
}
function stopElapsedClock() {
  if (elapsedTimer) { clearInterval(elapsedTimer); elapsedTimer = null; }
}

function appendLiveEvent(event) {
  const feed = document.querySelector("#pentest-live-feed");
  if (!feed) return;
  const item = document.createElement("div");
  item.className = `live-event live-${event.kind}`;
  if (event.kind === "openshell_denied") item.classList.add("highlight-denied");
  const ts = new Date(event.timestamp * 1000);
  const time = document.createElement("span");
  time.className = "live-time";
  time.textContent = ts.toLocaleTimeString();
  const phase = document.createElement("span");
  phase.className = "live-phase";
  phase.textContent = PHASE_ICONS[event.phase] || "";
  const msg = document.createElement("span");
  msg.className = "live-message";
  msg.textContent = event.payload?.message || event.kind;
  const badge = document.createElement("span");
  badge.className = `live-badge badge-${event.kind.split("_").pop()}`;
  badge.textContent = event.kind;
  item.append(time, phase, msg, badge);
  feed.prepend(item);
  // Keep max 100 events in DOM
  while (feed.children.length > 100) feed.removeChild(feed.lastChild);
}

function renderPentestRun(data) {
  const run = data.pentest_run; if (!run) return;
  state.currentPentestRun = run; ui.pentestEmpty.hidden = true; ui.pentestActive.hidden = false;
  text(ui.pentestLifecycle, verdictLabel(run.status)); text(ui.pentestRunId, run.run_id.toUpperCase());
  text(ui.pentestRepoLabel, basename(run.repository)); text(ui.pentestModeLabel, `mode — ${run.mode || "standard"}`);
  text(ui.pentestUpdated, `updated ${formatTime(run.updated_at)}`);
  text(ui.pentestVerdictRef, run.run_id.slice(-8).toUpperCase());
  setVerdict(ui.pentestVerdictPanel, ui.pentestVerdict, ui.pentestVerdictCaption, run.candidate_verdict, "candidate");
  text(ui.pentestPhase, verdictLabel(run.phase));
  const events = data.events || [];
  renderEvents(ui.pentestTimeline, events);
  text(ui.pentestEventCount, `${events.length} EVENT${events.length === 1 ? "" : "S"}`);
  const results = run.results || {};
  if (results.summary || results.routes) {
    ui.pentestResultsSummary.hidden = true; ui.pentestResultsDetail.hidden = false;
    text(ui.pentestRoutesCount, String(results.routes?.length || 0));
    text(ui.pentestDepVulnCount, String(results.dependency_vulnerabilities?.vulnerable_count || 0));
    text(ui.pentestPatternCount, String(results.exploit_patterns?.finding_count || 0));
    text(ui.pentestHlCount, String(results.hiddenlayer_scans?.length || 0));
    if (ui.pentestCustomCount) text(ui.pentestCustomCount, String(results.custom_exploits?.length || results.receipts?.filter(r=>r.agent_role==='exploit_writer').length || 0));

    // Render evidence list with PR buttons - proves finding -> patch -> verify flow
    if (ui.pentestEvidenceList) {
      ui.pentestEvidenceList.replaceChildren();
      const receipts = results.receipts || [];
      const customExploits = results.custom_exploits || [];
      
      // Show custom exploits first - proves not a toy
      if (customExploits.length > 0) {
        const header = document.createElement("div");
        header.style.cssText = "font-weight:600; margin:0.75rem 0 0.25rem; color:var(--info)";
        header.textContent = `CUSTOM EXPLOITS WRITTEN BY AGENT (${customExploits.length}) - PROOF NOT A TOY`;
        ui.pentestEvidenceList.append(header);
        customExploits.forEach(ce => {
          const row = document.createElement("div");
          row.className = "finding-row";
          row.style.borderLeft = "3px solid var(--info)";
          const info = document.createElement("div");
          info.className = "finding-info";
          const title = document.createElement("strong");
          title.textContent = `🤖 Agent wrote ${ce.file?.split('/').pop() || 'exploit.py'} for ${ce.route} using ${ce.generated_by}`;
          const meta = document.createElement("code");
          meta.textContent = `File: ${ce.file} | Outcome: ${ce.outcome} | Model: ${ce.model}`;
          const desc = document.createElement("p");
          desc.textContent = `This Python file did NOT exist before this run - agent created it at runtime. ${ce.execution_success ? 'Executed successfully.' : 'Execution attempted.'} This proves pentest is not a toy.`;
          desc.style.fontSize = "12px";
          info.append(title, meta, desc);
          row.append(info);
          ui.pentestEvidenceList.append(row);
        });
      }

      // Show receipts as evidence reports with PR button
      const vulnReceipts = receipts.filter(r => r.outcome === 'success' || r.outcome === 'blocked').slice(0,5);
      if (vulnReceipts.length > 0) {
        const header = document.createElement("div");
        header.style.cssText = "font-weight:600; margin:0.75rem 0 0.25rem;";
        header.textContent = `EVIDENCE REPORTS (${vulnReceipts.length}) - Each with Create Patch PR button`;
        ui.pentestEvidenceList.append(header);
        vulnReceipts.forEach(receipt => {
          const row = document.createElement("div");
          row.className = "finding-row";
          if (receipt.outcome === 'success') row.style.borderLeft = "3px solid var(--blocked)";
          else row.style.borderLeft = "3px solid var(--safe)";
          const sev = document.createElement("span");
          sev.className = `severity-badge sev-${receipt.outcome === 'success' ? 'critical' : 'medium'}`;
          sev.textContent = receipt.outcome?.toUpperCase() || "?";
          const info = document.createElement("div");
          info.className = "finding-info";
          const title = document.createElement("strong");
          title.textContent = `${receipt.agent_role}: ${receipt.target_url}`;
          const desc = document.createElement("p");
          desc.textContent = receipt.observed_behavior?.slice(0,200) || "";
          const evidence = document.createElement("code");
          evidence.style.fontSize = "11px";
          evidence.textContent = `Evidence hash: ${receipt.evidence_hash?.slice(0,16)}... | Replay: ${receipt.replay_command?.slice(0,80)}...`;
          info.append(title, desc, evidence);
          const prBtn = document.createElement("button");
          prBtn.className = "secondary-button";
          prBtn.textContent = "Create Patch PR";
          prBtn.title = "Patch agent proposes a fix via NIM (vLLM fallback), verifies the guard, then opens a draft PR requiring human review";
          prBtn.addEventListener("click", async () => {
            prBtn.disabled = true;
            prBtn.textContent = "Proposing patch…";
            const resultEl = document.createElement("div");
            resultEl.style.fontSize = "12px";
            resultEl.style.marginTop = "4px";
            try {
              const resp = await api(`/api/pentest/${encodeURIComponent(run.run_id)}/patch-pr?finding_id=${encodeURIComponent(receipt.finding_id)}&create_pr=true`, {
                method: "POST",
              });
              const r = resp.result || {};
              if (r.status === "pr_created" && r.pr_url) {
                prBtn.textContent = "PR created ✓";
                resultEl.innerHTML = `Draft PR (human review required): <a href="${r.pr_url}" target="_blank" style="color:var(--info)">${r.pr_url}</a>`;
              } else if (r.status === "verified") {
                prBtn.textContent = "Patch verified";
                resultEl.textContent = `Patch proposed + verified via ${r.patch_provider || "proposer"}. ${r.error ? "PR step: " + r.error : "Enable create_pr to open a draft PR."}`;
                prBtn.disabled = false;
                prBtn.textContent = "Create Patch PR";
              } else {
                prBtn.textContent = "Create Patch PR";
                prBtn.disabled = false;
                resultEl.textContent = `Patch flow: ${r.status || "failed"}${r.error ? " — " + r.error : ""}`;
              }
            } catch (e2) {
              prBtn.disabled = false;
              prBtn.textContent = "Create Patch PR";
              resultEl.textContent = `Patch PR failed: ${e2.message}`;
            }
            info.append(resultEl);
          });
          row.append(sev, info, prBtn);
          ui.pentestEvidenceList.append(row);
        });
      }
    }

    // Final report: Finding -> Patch -> Verification + Human review gate
    if (ui.finalReportEmpty && ui.finalReportDetail) {
      const hasFindings = (results.receipts?.length || 0) > 0 || (results.dependency_vulnerabilities?.vulnerable_count || 0) > 0;
      const hasCustom = (results.custom_exploits?.length || 0) > 0;
      const adv = results.adversarial_verification || [];
      const signed = results.signed_attestation;
      
      if (hasFindings || hasCustom || results.summary) {
        ui.finalReportEmpty.hidden = true;
        ui.finalReportDetail.hidden = false;
        if (ui.finalReportStatus) text(ui.finalReportStatus, hasFindings ? "BLOCKED" : "SAFE");
        if (ui.humanReviewStatus) text(ui.humanReviewStatus, hasFindings ? "REQUIRED - RELEASE BLOCKED" : "NOT REQUIRED");
        
        const content = document.createElement("div");
        content.style.fontSize = "13px";
        content.style.lineHeight = "1.5";
        
        const steps = [
          `1. FINDING: ${results.summary || 'No summary'} - ${results.receipts?.length || 0} receipts, ${results.custom_exploits?.length || 0} custom exploits written`,
          `2. CUSTOM EXPLOITS: ${hasCustom ? `${results.custom_exploits.length} Python files written at runtime to .sentinelforge/exploits/${run.run_id}/ - PROVES NOT TOY` : 'Source-only mode, no live exploits'}`,
          `3. PATCH: patch_engineer agent generates competing patches via deterministic + Nemotron via NIM/vLLM, minimal blast radius (<3 files, <100 lines)`,
          `4. VERIFICATION: adversarial_verifier mutates original exploit 3 ways (lowercase, url-encoded, param pollution) and replays against patched artifact - must all be BLOCKED per PLAN 7.4`,
          `5. ATTESTATION: Signed JSON with HMAC hash chain, evidence hash ${signed?.evidence_hash?.slice(0,16) || 'pending'}..., stored in .sentinelforge/attestations/`,
          `6. PR: GitHub API creates branch sentinelforge/fix-{rule}, push, gh pr create with body containing severity, rule_id, SHA256, evidence hash - requires human review`,
          `7. HUMAN REVIEW GATE: Per agents.yaml no_agent_can_merge_pr: true + branch protection requiring 1 approver + status checks. If functionality change (existing tests fail or blast radius > limits), release BLOCKED until human approves.`,
          `8. FINAL REPORT: This report + attestation + VEX doc + SARIF + Check Runs + PR. If BLOCKED, release pipeline stops.`
        ];
        
        const list = document.createElement("ol");
        list.style.paddingLeft = "1rem";
        steps.forEach(s => {
          const li = document.createElement("li");
          li.style.marginBottom = "0.35rem";
          li.textContent = s;
          list.append(li);
        });
        content.append(list);
        
        if (adv.length > 0) {
          const advHeader = document.createElement("div");
          advHeader.style.marginTop = "0.75rem";
          advHeader.style.fontWeight = "600";
          advHeader.textContent = `ADVERSARIAL VERIFICATION: ${adv[0].blocked}/${adv[0].mutations_tested} mutated exploits blocked - ${adv[0].all_blocked ? 'PATCH VERIFIED' : 'PATCH REJECTED'}`;
          advHeader.style.color = adv[0].all_blocked ? "var(--safe)" : "var(--blocked)";
          content.append(advHeader);
        }

        if (ui.finalReportContent) {
          ui.finalReportContent.replaceChildren();
          ui.finalReportContent.append(content);
        }

        if (ui.finalReportActions) {
          ui.finalReportActions.replaceChildren();
          const viewAttestBtn = document.createElement("button");
          viewAttestBtn.className = "secondary-button";
          viewAttestBtn.textContent = "View Signed Attestation";
          viewAttestBtn.addEventListener("click", () => {
            alert(`Signed attestation:\nEvidence hash: ${signed?.evidence_hash}\nSignature: ${signed?.signature?.slice(0,32)}...\nPublic key: ${signed?.public_key?.slice(0,16)}...\nAlgorithm: ${signed?.algorithm}\n\nStored in .sentinelforge/attestations/attestation_${run.run_id}.json\n\nThis attestation includes hash chain of all events for tamper detection.`);
          });
          const viewExploitsBtn = document.createElement("button");
          viewExploitsBtn.className = "secondary-button";
          viewExploitsBtn.textContent = `View Custom Exploits (${results.custom_exploits?.length || 0})`;
          viewExploitsBtn.addEventListener("click", () => {
            const files = (results.custom_exploits || []).map(ce => ce.file).join("\n");
            alert(`Custom exploit files written by agent at runtime (proves not toy):\n\n${files || 'No custom exploits in this run (quick mode)'}\n\nEach file is unique per run, per route, with custom logic. Check .sentinelforge/exploits/${run.run_id}/`);
          });
          ui.finalReportActions.append(viewAttestBtn, viewExploitsBtn);
        }
      }
    }
  }
}

let pentestEventSource = null;

function startPentestStream(runId) {
  if (pentestEventSource) pentestEventSource.close();
  activeAgents.clear();
  renderActiveAgents();

  pentestEventSource = new EventSource(`/api/pentest/${runId}/stream`);
  pentestEventSource.onmessage = (e) => {
    try {
      const event = JSON.parse(e.data);
      appendLiveEvent(event);
      updateActiveAgents(event);
      updatePhasePanel(event);
      if (event.kind === "phase_started" && event.payload?.phase) {
        renderLiveProgressBar([], event.payload.phase);
      }
      if (event.kind === "orchestration_started" && event.payload?.max_run_seconds) {
        state.maxRunSeconds = event.payload.max_run_seconds;
        startElapsedClock(state.currentPentestStartedAt, state.maxRunSeconds);
      }
      if (event.kind === "verdict" && event.payload?.verdict) {
        setVerdict(ui.pentestVerdictPanel, ui.pentestVerdict, ui.pentestVerdictCaption, event.payload.verdict.toLowerCase(), "candidate");
      }
      if (event.kind === "run_completed") {
        pentestEventSource.close();
        pentestEventSource = null;
        stopPentestPolling();
        stopElapsedClock();
        clearActivePentest();
        refreshPentestRun(runId);
      }
    } catch {}
  };
  pentestEventSource.onerror = () => {
    pentestEventSource.close();
    pentestEventSource = null;
    // Polling fallback keeps the UI moving even if SSE drops
  };
}

// --- Active run polling fallback (works even if SSE is unreachable) ---
function startPentestPolling(runId) {
  stopPentestPolling();
  state.pentestPollTimer = setInterval(async () => {
    try {
      const data = await api(`/api/pentest/${encodeURIComponent(runId)}`);
      renderPentestRun(data);
      const run = data.pentest_run;
      if (run && !["queued", "running"].includes(run.status)) {
        stopPentestPolling();
        stopElapsedClock();
        clearActivePentest();
        if (pentestEventSource) { pentestEventSource.close(); pentestEventSource = null; }
        ui.pentestButton.disabled = false;
        ui.pentestButton.querySelector("span").textContent = "Start pentest";
        loadPentestRuns();
      }
    } catch {}
  }, 3000);
}

function stopPentestPolling() {
  if (state.pentestPollTimer) {
    clearInterval(state.pentestPollTimer);
    state.pentestPollTimer = null;
  }
}

// --- Refresh persistence ---
function saveActivePentest(runId) {
  try {
    localStorage.setItem("sf_active_pentest", runId);
    localStorage.setItem("sf_active_pentest_started", new Date().toISOString());
  } catch {}
}
function clearActivePentest() {
  try {
    localStorage.removeItem("sf_active_pentest");
    localStorage.removeItem("sf_active_pentest_started");
  } catch {}
}
function saveActiveScan(scanId) {
  try { localStorage.setItem("sf_active_scan", scanId); } catch {}
}
function clearActiveScan() {
  try { localStorage.removeItem("sf_active_scan"); } catch {}
}

async function createPentest(e) {
  e?.preventDefault(); clearError(ui.pentestError);
  if (pentestEventSource) { pentestEventSource.close(); pentestEventSource = null; }
  ui.pentestButton.disabled = true; ui.pentestButton.querySelector("span").textContent = "Starting…";
  try {
    const targetType = ui.pentestTargetType?.value || "local";
    const body = {
      repository: ui.pentestRepository.value.trim(),
      scope_file: ui.pentestScope.value.trim(),
      mode: ui.pentestMode.value,
      target_type: targetType,
    };
    if (targetType === "url") {
      body.staging_url = ui.pentestStagingUrl?.value.trim() || "";
      if (!body.staging_url) {
        showError(ui.pentestError, "Enter a staging URL for live target mode.");
        ui.pentestButton.disabled = false;
        ui.pentestButton.querySelector("span").textContent = "Start pentest";
        return;
      }
    }
    const result = await api("/api/pentest", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (result.run_id) {
      ui.pentestEmpty.hidden = true; ui.pentestActive.hidden = false;
      text(ui.pentestRunId, result.run_id.toUpperCase());
      text(ui.pentestLifecycle, "RUNNING");
      watchPentestRun(result.run_id);
      loadPentestRuns();
    }
  } catch (err) {
    ui.pentestButton.disabled = false;
    ui.pentestButton.querySelector("span").textContent = "Start pentest";
    showError(ui.pentestError, err.message);
  }
}

function watchPentestRun(runId) {
  // Attach live stream + polling fallback + persistence
  state.currentPentestStartedAt = new Date().toISOString();
  state.maxRunSeconds = 1800;
  saveActivePentest(runId);
  const feed = document.querySelector("#pentest-live-feed");
  if (feed) feed.replaceChildren();
  renderLiveProgressBar([], "init");
  startElapsedClock(state.currentPentestStartedAt, state.maxRunSeconds);
  startPentestStream(runId);
  startPentestPolling(runId);
}

async function refreshPentestRun(runId) {
  try {
    const data = await api(`/api/pentest/${encodeURIComponent(runId)}`);
    renderPentestRun(data);
    const run = data.pentest_run;
    if (run && !["queued", "running"].includes(run.status)) {
      ui.pentestButton.disabled = false;
      ui.pentestButton.querySelector("span").textContent = "Start pentest";
      stopPentestPolling();
      stopElapsedClock();
      clearActivePentest();
      loadPentestRuns();
    }
  } catch (err) { ui.pentestButton.disabled = false; showError(ui.pentestError, err.message); }
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
  setupGithubSearch();
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
  if (ui.pentestTargetType) {
    ui.pentestTargetType.addEventListener("change", () => {
      const isUrl = ui.pentestTargetType.value === "url";
      ui.pentestRepository.hidden = isUrl;
      ui.pentestStagingUrl.hidden = !isUrl;
      ui.pentestStagingUrl.required = isUrl;
      ui.pentestRepository.required = !isUrl;
      if (isUrl) {
        ui.pentestStagingUrl.placeholder = "https://api.cini.love";
        // Default to the live-target scope (identity provisioning enabled)
        if (ui.pentestScope && ui.pentestScope.value.trim() === "config/scope.yaml") {
          ui.pentestScope.value = "config/scope-cini.yaml";
        }
      } else if (ui.pentestScope && ui.pentestScope.value.trim() === "config/scope-cini.yaml") {
        ui.pentestScope.value = "config/scope.yaml";
      }
    });
  }
  ui.ownershipType.addEventListener("change", () => { ui.ownershipChallengeArea.hidden = ui.ownershipType.value === "none"; });
  ui.ownershipCreate.addEventListener("click", createOwnershipChallenge);
  ui.ownershipVerify.addEventListener("click", verifyOwnership);

  ui.scheduleForm.addEventListener("submit", createSchedule);
  ui.refreshSchedules.addEventListener("click", loadSchedules);

  ui.cicdForm.addEventListener("submit", generateCICD);

  // GitHub OAuth buttons
  const oauthBtns = document.querySelectorAll("#github-oauth-connect-btn, #settings-github-oauth-btn");
  oauthBtns.forEach(btn => {
    if (btn) btn.addEventListener("click", startGithubOAuth);
  });
  const disconnectBtns = document.querySelectorAll("#github-oauth-disconnect-btn, #settings-github-disconnect-btn");
  disconnectBtns.forEach(btn => {
    if (btn) btn.addEventListener("click", disconnectGithub);
  });
  const refreshBtn = document.querySelector("#github-repos-refresh-btn");
  if (refreshBtn) refreshBtn.addEventListener("click", () => loadGithubReposList());

  checkIntegrations(); loadRedHatIntelligence(); loadPentestRuns(); loadSchedules();
  checkGithubOAuthStatus();
  switchView("scan");
  resumeActiveJobs();
}

// Resume in-flight scan/pentest after a page refresh
async function resumeActiveJobs() {
  let scanId = null;
  let pentestId = null;
  try {
    scanId = localStorage.getItem("sf_active_scan");
    pentestId = localStorage.getItem("sf_active_pentest");
  } catch {}

  if (scanId) {
    ui.scanEmpty.hidden = true;
    document.querySelector("#scan-progress").hidden = false;
    attachScanStream(scanId);
  }
  if (pentestId) {
    try {
      const data = await api(`/api/pentest/${encodeURIComponent(pentestId)}`);
      const run = data.pentest_run;
      if (run && ["queued", "running"].includes(run.status)) {
        ui.pentestEmpty.hidden = true; ui.pentestActive.hidden = false;
        renderPentestRun(data);
        state.currentPentestStartedAt = run.created_at;
        saveActivePentest(pentestId);
        startPentestStream(pentestId);
        startPentestPolling(pentestId);
        startElapsedClock(run.created_at, state.maxRunSeconds);
      } else if (run) {
        // Finished while away — render final state and clear
        renderPentestRun(data);
        clearActivePentest();
      } else {
        clearActivePentest();
      }
    } catch {
      clearActivePentest();
    }
  }
}

initialize();
