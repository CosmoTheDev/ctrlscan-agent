/* --- Theme Toggle --- */
(function initTheme() {
  const saved = localStorage.getItem("ctrlscan-theme") || "dark";
  document.documentElement.setAttribute("data-theme", saved);
  function updateToggleLabel() {
    const current = document.documentElement.getAttribute("data-theme") || "dark";
    const label = document.getElementById("themeToggleLabel");
    if (label) label.textContent = current === "light" ? "Dark Mode" : "Light Mode";
  }
  document.addEventListener("DOMContentLoaded", () => {
    updateToggleLabel();
    document.getElementById("themeToggle")?.addEventListener("click", () => {
      const current = document.documentElement.getAttribute("data-theme") || "dark";
      const next = current === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      localStorage.setItem("ctrlscan-theme", next);
      updateToggleLabel();
    });
  });
})();

const state = {
  view: "overview",
  status: null,
  jobs: [],
  jobsTotal: 0,
  jobsTotalPages: 1,
  selectedScanJobIds: {},
  jobSummary: null,
  selectedJobId: null,
  selectedJob: null,
  selectedJobScanners: [],
  selectedJobFindings: [],
  selectedJobFindingsTotal: 0,
  selectedJobFindingsTotalPages: 1,
  selectedJobFindingsFacets: { kinds: [], scanners: [], severities: [] },
  selectedJobFindingsSeverityTotals: null,
  selectedJobFixes: [],
  selectedJobRemediationRuns: [],
  selectedJobRemediationRunsTotal: 0,
  selectedJobRemediationRunsPage: 1,
  selectedJobRemediationRunsPageSize: 10,
  selectedJobRemediationRunsTotalPages: 1,
  scanDetailRemediationHistoryCollapsed: false,
  scanDetailRemediationExpandedTaskIds: {},
  pathIgnoreRules: [],
  pathIgnoreRulesLoading: false,
  remediationCampaigns: [],
  remediationSelectedCampaignId: null,
  remediationCampaignTasks: [],
  remediationRepoSuggestions: [],
  remediationRepoSuggestionsLoaded: false,
  remediationRepoSuggestionsLoading: false,
  remediationRepoFilter: "",
  remediationDraft: {
    name: "Offline fix run",
    mode: "triage",
    maxRepos: "10",
    autoPR: false,
    startNow: true,
    selectedRepos: [],
  },
  agentWorkers: [],
  schedules: [],
  agent: null,
  config: null,
  configPath: "",
  events: [],
  es: null,
  liveRefreshTimer: null,
  liveRefreshPending: {
    jobs: false,
    detail: false,
    workers: false,
    remediation: false,
  },
  triggerPlan: {
    targets: [],
    workers: "",
    selectedRepoMap: {},
  },
  triggerPreview: {
    loading: false,
    data: null,
    error: "",
  },
  scanDetailFindingsPage: 1,
  scanDetailFindingsPageSize: 25,
  scanDetailFindingsFilters: {
    kind: "",
    scanner: "",
    severity: "",
    title: "",
    path: "",
    q: "",
  },
  scanDetailFindingsDraft: {
    title: "",
    path: "",
    q: "",
  },
  scansPage: 1,
  scansPageSize: 20,
  stopBusy: false,
  scanDetailAiStopBusy: false,
  scanDetailFixesPage: 1,
  scanDetailFixesPageSize: 10,
  scanDetailFixesSearch: "",
  scanDetailFixesStatus: "",
  sweepUi: {
    skipEventCount: 0,
    latestSummary: null,
  },
};

const views = [
  { id: "overview", title: "Overview", subtitle: "Gateway status, agent controls, and scan posture." },
  { id: "scans", title: "Scans", subtitle: "Runs, scanner results, findings, and raw downloads." },
  { id: "scan-detail", title: "Scan Detail", subtitle: "Expanded scan view with per-scanner output and findings.", hidden: true },
  { id: "remediation", title: "Remediation", subtitle: "Offline AI fix/PR campaigns on existing findings and scan jobs." },
  { id: "cron", title: "Cron Jobs", subtitle: "Schedules that trigger discovery and scans." },
  { id: "agents", title: "Agent Runtime", subtitle: "One orchestrator with configurable scan workers." },
  { id: "config", title: "Config", subtitle: "Review and edit gateway config used during onboarding." },
  { id: "events", title: "Events", subtitle: "Live SSE events emitted by the gateway." },
];

const targetMeta = {
  own_repos: { label: "Own Repositories", desc: "List repositories you own." },
  watchlist: { label: "Watchlist", desc: "Configured orgs/repos in your ctrlscan watchlist." },
  cve_search: { label: "CVE Search", desc: "Public repository discovery via CVE/security-focused search queries." },
  all_accessible: { label: "All Accessible", desc: "All repos accessible with your token (owner/collab/org)." },
};

function getScannedRepoLabel(r) {
  const owner = String(r?.owner || "").trim();
  const repo = String(r?.repo || "").trim();
  return owner && repo ? `${owner}/${repo}` : "";
}

function getRemediationRepoSuggestionsFiltered() {
  const q = String(state.remediationRepoFilter || "").trim().toLowerCase();
  const all = Array.isArray(state.remediationRepoSuggestions) ? state.remediationRepoSuggestions : [];
  const selected = new Set((state.remediationDraft?.selectedRepos || []).map(v => String(v).toLowerCase()));
  let items = all.filter(r => !selected.has(getScannedRepoLabel(r).toLowerCase()));
  if (q) items = items.filter(r => getScannedRepoLabel(r).toLowerCase().includes(q));
  return items.slice(0, 12);
}

function escapeHtml(v) {
  return String(v ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function setHtml(el, html) {
  if (!el) return;
  const range = document.createRange();
  range.selectNodeContents(el);
  el.replaceChildren(range.createContextualFragment(String(html ?? "")));
}

function repoSelectionKey(r) {
  return [r.provider || "", r.host || "", r.owner || "", r.name || ""].join("|").toLowerCase();
}

function getPreviewSampleRepos() {
  const targets = state.triggerPreview?.data?.targets;
  if (!Array.isArray(targets)) return [];
  const repos = [];
  for (const t of targets) {
    for (const r of (t.samples || [])) repos.push(r);
  }
  return repos;
}

function getSelectedPreviewRepos() {
  return Object.values(state.triggerPlan.selectedRepoMap || {});
}

function reconcileSelectedPreviewRepos() {
  const visible = new Set(getPreviewSampleRepos().map(repoSelectionKey));
  const next = {};
  for (const [k, v] of Object.entries(state.triggerPlan.selectedRepoMap || {})) {
    if (visible.has(k)) next[k] = v;
  }
  state.triggerPlan.selectedRepoMap = next;
}

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
    ...opts,
  });
  const text = await res.text();
  let data;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!res.ok) {
    const msg = data && typeof data === "object" && data.error ? data.error : `${res.status} ${res.statusText}`;
    throw new Error(msg);
  }
  return data;
}

function fmtDuration(ms) {
  if (!ms && ms !== 0) return "n/a";
  if (ms < 1000) return `${ms}ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)}s`;
  return `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`;
}

function fmtDate(v) {
  if (!v) return "n/a";
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) return v;
  return d.toLocaleString();
}

function normalizeSeverityLabel(v) {
  return String(v || "").trim().toUpperCase();
}

function severityBucket(v) {
  const s = normalizeSeverityLabel(v);
  if (s === "CRITICAL") return "CRITICAL";
  if (s === "HIGH" || s === "ERROR") return "HIGH";
  if (s === "MEDIUM" || s === "WARNING" || s === "WARN") return "MEDIUM";
  if (s === "LOW" || s === "INFO") return "LOW";
  return s;
}

function countFindingsBySeverity(findings) {
  const totals = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings || []) {
    const s = severityBucket(f.severity);
    if (s === "CRITICAL") totals.critical++;
    else if (s === "HIGH") totals.high++;
    else if (s === "MEDIUM") totals.medium++;
    else if (s === "LOW") totals.low++;
  }
  return totals;
}

function statusClass(v) {
  const s = String(v || "").toLowerCase();
  if (s.includes("complete")) return "status-completed";
  if (s.includes("run")) return "status-running";
  if (s.includes("stop")) return "status-stopped";
  if (s.includes("fail")) return "status-failed";
  if (s.includes("partial")) return "status-partial";
  return "";
}

function viewToPath(id) {
  switch (id) {
    case "overview": return "/ui/overview";
    case "scans": return "/ui/scans";
    case "remediation": return "/ui/remediation";
    case "cron": return "/ui/cronjobs";
    case "agents": return "/ui/agents";
    case "config": return "/ui/config";
    case "events": return "/ui/events";
    case "scan-detail":
      if (state.selectedJobId) return `/ui/scans/${state.selectedJobId}`;
      return "/ui/scans";
    default:
      return "/ui";
  }
}

async function applyRouteFromLocation() {
  const path = window.location.pathname || "/ui";
  const parts = path.replace(/^\/+|\/+$/g, "").split("/");
  if (parts[0] !== "ui") {
    setView("overview");
    return;
  }
  const section = parts[1] || "overview";
  if (section === "scans" && parts[2]) {
    const id = Number(parts[2]);
    if (Number.isFinite(id) && id > 0) {
      try {
        await openScanDetailPage(id, { pushHistory: false });
        return;
      } catch (_) {
        // fall through to scans page if deep-link job no longer exists
      }
    }
    setView("scans");
    return;
  }
  if (section === "" || section === "ui" || section === "overview") {
    setView("overview");
    return;
  }
  const alias = {
    cronjobs: "cron",
    cron: "cron",
    remediation: "remediation",
    agents: "agents",
    config: "config",
    events: "events",
    scans: "scans",
  };
  setView(alias[section] || "overview");
}

function setView(id, opts = {}) {
  state.view = id;
  for (const v of views) {
    document.getElementById(`view-${v.id}`).classList.toggle("active", v.id === id);
  }
  const meta = views.find(v => v.id === id);
  document.getElementById("pageTitle").textContent = meta.title;
  document.getElementById("pageSubtitle").textContent = meta.subtitle;
  const path = viewToPath(id);
  if (opts.replaceHistory) {
    history.replaceState({ view: id, jobId: state.selectedJobId || null }, "", path);
  } else if (opts.pushHistory) {
    history.pushState({ view: id, jobId: state.selectedJobId || null }, "", path);
  }
  renderNav();
}

function renderNav() {
  const nav = document.getElementById("nav");
  setHtml(nav, views.filter(v => !v.hidden).map(v => `<button data-view="${v.id}" class="${state.view === v.id ? "active" : ""}">${escapeHtml(v.title)}</button>`).join(""));
  nav.querySelectorAll("button").forEach(btn => btn.addEventListener("click", () => setView(btn.dataset.view, { pushHistory: true })));
}

function pushEvent(evt) {
  state.events.unshift({ at: new Date().toISOString(), ...evt });
  if (state.events.length > 200) state.events.length = 200;
  handleToastForEvent(evt);
  if (evt.type === "status.update" || evt.type === "connected") {
    state.status = evt.payload || state.status;
    renderOverview();
    renderAgents();
    renderHealthPill();
  }
  if (["agent.triggered", "agent.stop_requested", "schedule.fired", "schedule.triggered"].includes(evt.type)) {
    scheduleLiveRefresh({ jobs: true, workers: true });
  }
  if (["fix.approved", "fix.rejected"].includes(evt.type)) {
    scheduleLiveRefresh({ jobs: true, detail: true, workers: true });
  }
  if (["worker.status", "campaign.started", "campaign.completed", "campaign.task.started", "campaign.task.completed", "campaign.task.failed", "campaign.stopped"].includes(evt.type)) {
    scheduleLiveRefresh({ workers: true, remediation: true, detail: true });
  }
  if (["sweep.started", "sweep.completed"].includes(evt.type)) {
    renderOverview();
    renderScans();
    scheduleLiveRefresh({ jobs: true, workers: true, detail: true });
  }
  renderEvents();
}

function showToast({ title, message = "", kind = "info", timeoutMs = 3500 } = {}) {
  const stack = document.getElementById("toastStack");
  if (!stack) return;
  const el = document.createElement("div");
  el.className = `toast toast-${kind}`;
  setHtml(el, `
    <div class="toast-title">${escapeHtml(title || "Notice")}</div>
    ${message ? `<div class="toast-body">${escapeHtml(message)}</div>` : ""}
  `);
  stack.prepend(el);
  const remove = () => {
    if (el.parentNode) el.parentNode.removeChild(el);
  };
  const t = setTimeout(remove, timeoutMs);
  el.addEventListener("click", () => {
    clearTimeout(t);
    remove();
  });
}

function handleToastForEvent(evt) {
  const payload = evt?.payload && typeof evt.payload === "object" ? evt.payload : {};
  switch (evt?.type) {
    case "agent.triggered": {
      state.sweepUi.skipEventCount = 0;
      const selected = Number(payload.selected_repos || 0);
      const workers = Number(payload.workers || 0);
      let msg = selected > 0 ? `Trigger accepted for ${selected} selected repos.` : "Trigger accepted. Discovery and scans will start shortly.";
      if (workers > 0) msg += ` Workers: ${workers}.`;
      showToast({ title: "Sweep Triggered", message: msg, kind: "info", timeoutMs: 3000 });
      break;
    }
    case "sweep.started": {
      state.sweepUi.latestSummary = {
        status: "running",
        started_at: payload.started_at || new Date().toISOString(),
        completed_at: "",
        duration_seconds: 0,
        workers: Number(payload.workers || 0),
        selected_repos: Number(payload.selected_repos || 0),
        scan_targets: Array.isArray(payload.scan_targets) ? payload.scan_targets : [],
        skipped_repos: 0,
        skipped_by_reason: {},
      };
      const workers = Number(payload.workers || 0);
      const selected = Number(payload.selected_repos || 0);
      let msg = workers > 0 ? `${workers} worker${workers === 1 ? "" : "s"} active.` : "Workers active.";
      if (selected > 0) msg += ` Scanning ${selected} selected repos.`;
      showToast({ title: "Sweep Started", message: msg, kind: "success", timeoutMs: 2800 });
      break;
    }
    case "repo.skipped": {
      state.sweepUi.skipEventCount = (state.sweepUi.skipEventCount || 0) + 1;
      break; // avoid spamming a toast per repo; summary shown on sweep.completed
    }
    case "sweep.completed": {
      state.sweepUi.latestSummary = {
        ...(state.sweepUi.latestSummary || {}),
        status: String(payload.status || "completed"),
        started_at: payload.started_at || state.sweepUi.latestSummary?.started_at || "",
        completed_at: payload.completed_at || new Date().toISOString(),
        duration_seconds: Number(payload.duration_seconds || 0),
        skipped_repos: Number(payload.skipped_repos || 0),
        skipped_by_reason: payload.skipped_by_reason && typeof payload.skipped_by_reason === "object" ? payload.skipped_by_reason : {},
      };
      const status = String(payload.status || "completed");
      const skipped = Number(payload.skipped_repos || 0);
      const reasons = payload.skipped_by_reason && typeof payload.skipped_by_reason === "object" ? payload.skipped_by_reason : {};
      const recentSkipped = Number(reasons["recently scanned within 24h"] || 0);
      let title = "Sweep Completed";
      let kind = "success";
      if (status === "cancelled") {
        title = "Sweep Cancelled";
        kind = "warn";
      } else if (status !== "completed") {
        title = `Sweep ${status[0]?.toUpperCase() || ""}${status.slice(1)}`;
        kind = "info";
      }
      let msg = skipped > 0 ? `${skipped} repo${skipped === 1 ? "" : "s"} skipped.` : "No repo skips reported.";
      if (recentSkipped > 0) msg += ` ${recentSkipped} skipped because they were scanned within 24h.`;
      const dur = Number(payload.duration_seconds || 0);
      if (dur > 0) msg += ` Duration: ${dur.toFixed(1)}s.`;
      showToast({ title, message: msg, kind, timeoutMs: 5500 });
      break;
    }
    case "agent.stop_requested": {
      showToast({ title: "Stopping Sweep", message: "Cancellation requested. Running scanners will stop shortly.", kind: "warn", timeoutMs: 3500 });
      break;
    }
  }
}

function renderSweepSummaryCard() {
  const s = state.sweepUi?.latestSummary;
  if (!s) {
    return `
      <div class="card">
        <h3>Latest Sweep Summary</h3>
        <div class="muted">No sweep lifecycle events seen yet in this session. Trigger a scan to populate this panel.</div>
      </div>
    `;
  }
  const status = String(s.status || "unknown");
  const reasons = s.skipped_by_reason && typeof s.skipped_by_reason === "object" ? s.skipped_by_reason : {};
  const reasonParts = Object.entries(reasons)
    .filter(([, n]) => Number(n) > 0)
    .sort((a, b) => Number(b[1]) - Number(a[1]))
    .slice(0, 3)
    .map(([k, n]) => `${n} ${k}`);
  const workers = Number(s.workers || 0);
  const selectedRepos = Number(s.selected_repos || 0);
  const targets = Array.isArray(s.scan_targets) ? s.scan_targets : [];
  return `
    <div class="card">
      <h3>Latest Sweep Summary</h3>
      <div class="stack">
        <div><span class="badge ${statusClass(status)}">${escapeHtml(status)}</span></div>
        <div class="muted">Started ${escapeHtml(fmtDate(s.started_at))}${s.completed_at ? ` • Completed ${escapeHtml(fmtDate(s.completed_at))}` : ""}</div>
        <div>Duration: <strong>${s.duration_seconds ? `${Number(s.duration_seconds).toFixed(1)}s` : "n/a"}</strong></div>
        <div>Skipped repos: <strong>${Number(s.skipped_repos || 0)}</strong></div>
        ${reasonParts.length ? `<div class="muted">Skip reasons: ${escapeHtml(reasonParts.join(" • "))}</div>` : ``}
        <div class="muted">${workers > 0 ? `${workers} worker${workers === 1 ? "" : "s"}` : "Workers unknown"}${selectedRepos > 0 ? ` • ${selectedRepos} selected repos` : ""}${targets.length ? ` • targets: ${targets.join(", ")}` : ""}</div>
      </div>
    </div>
  `;
}

function renderHealthPill() {
  const pill = document.getElementById("healthPill");
  const st = state.status;
  if (!st) {
    pill.textContent = "Health: unknown";
    pill.className = "pill pill-idle";
    return;
  }
  const health = st.running ? (st.paused ? "paused" : "ok") : "idle";
  pill.textContent = `Health: ${health} • workers ${st.workers ?? "?"}`;
  pill.className = health === "ok" ? "pill pill-ok" : health === "paused" ? "pill pill-warn" : "pill pill-idle";
}

function renderOverview() {
  const root = document.getElementById("view-overview");
  const st = state.status || {};
  const sum = state.jobSummary || {};
  const last = state.jobs[0];
  setHtml(root, `
    <div class="grid cols-4">
      <div class="card card-ok"><div class="metric-label">Agent</div><div class="metric-value ${st.paused ? "warn" : "ok"}">${st.paused ? "Paused" : (st.running ? "Ready" : "Idle")}</div></div>
      <div class="card card-accent"><div class="metric-label">Queued Repos</div><div class="metric-value">${st.queued_repos ?? 0}</div></div>
      <div class="card card-purple"><div class="metric-label">Active Jobs</div><div class="metric-value">${st.active_jobs ?? 0}</div></div>
      <div class="card card-orange"><div class="metric-label">Pending Fixes</div><div class="metric-value">${st.pending_fixes ?? 0}</div></div>
    </div>
    <div class="grid cols-4" style="margin-top:12px">
      <div class="card card-high"><div class="metric-label">High (Aggregate)</div><div class="metric-value high">${sum.high ?? 0}</div></div>
      <div class="card card-medium"><div class="metric-label">Medium (Aggregate)</div><div class="metric-value medium">${sum.medium ?? 0}</div></div>
      <div class="card card-low"><div class="metric-label">Low (Aggregate)</div><div class="metric-value low">${sum.low ?? 0}</div></div>
      <div class="card card-critical"><div class="metric-label">Critical (Aggregate)</div><div class="metric-value critical">${sum.critical ?? 0}</div></div>
    </div>
    <div class="grid cols-2" style="margin-top:14px">
      <div class="card">
        <h3>Quick Controls</h3>
        <div class="toolbar">
          <button class="btn btn-primary" id="ovTrigger">Trigger Sweep</button>
          <button class="btn btn-danger ${state.stopBusy ? "is-loading" : ""}" id="ovStop" ${state.stopBusy ? "disabled" : ""}>${state.stopBusy ? "Stopping" : "Stop Sweep"}</button>
          <button class="btn ${st.paused ? "btn-secondary" : "btn-danger"}" id="ovPauseResume">${st.paused ? "Resume" : "Pause"}</button>
          <button class="btn btn-secondary" id="ovRefresh">Refresh Data</button>
        </div>
        <div class="footer-note">Gateway now starts idle by default. Scans run only on manual or cron triggers.</div>
      </div>
      <div class="card">
        <h3>Latest Scan Job</h3>
        ${last ? `
        <div class="stack">
          <div><span class="badge ${statusClass(last.status)}">${escapeHtml(last.status)}</span></div>
          <div><strong>${escapeHtml(last.owner)}/${escapeHtml(last.repo)}</strong> <span class="muted">#${last.id}</span></div>
          <div class="muted">Started ${fmtDate(last.started_at)}</div>
          <div>Severity totals: C ${last.findings_critical} • H ${last.findings_high} • M ${last.findings_medium} • L ${last.findings_low}</div>
          <button class="btn btn-secondary" id="ovOpenLatest">Open in Scans</button>
          <button class="btn btn-secondary" id="ovOpenLatestDetail">Open Detail Page</button>
        </div>` : `<div class="muted">No scan jobs yet.</div>`}
      </div>
    </div>
    <div style="margin-top:14px">
      ${renderSweepSummaryCard()}
    </div>
  `);
  root.querySelector("#ovTrigger")?.addEventListener("click", openTriggerModal);
  root.querySelector("#ovStop")?.addEventListener("click", stopSweep);
  root.querySelector("#ovPauseResume")?.addEventListener("click", async () => {
    await setPaused(!(state.status && state.status.paused));
  });
  root.querySelector("#ovRefresh")?.addEventListener("click", refreshAll);
  root.querySelector("#ovOpenLatest")?.addEventListener("click", async () => {
    setView("scans");
    if (last) {
      await selectJob(last.id);
    }
  });
  root.querySelector("#ovOpenLatestDetail")?.addEventListener("click", async () => {
    if (last) await openScanDetailPage(last.id);
  });
  syncStopButtons();
}

function renderScans() {
  const root = document.getElementById("view-scans");
  const rows = state.jobs || [];
  const pageSize = state.scansPageSize || 20;
  const totalRows = Number(state.jobsTotal || rows.length || 0);
  const totalPages = Math.max(1, Number(state.jobsTotalPages || Math.ceil(totalRows / pageSize) || 1));
  const page = Math.min(Math.max(1, state.scansPage || 1), totalPages);
  state.scansPage = page;
  const pageStart = (page - 1) * pageSize;
  const visibleRows = rows;
  const selectedIds = state.selectedScanJobIds || {};
  const selectedCount = Object.keys(selectedIds).length;
  const visibleSelectedCount = visibleRows.filter(j => selectedIds[j.id]).length;
  const allVisibleSelected = visibleRows.length > 0 && visibleSelectedCount === visibleRows.length;
  const selectedJob = state.selectedJob;
  const scanners = state.selectedJobScanners || [];
  const findings = state.selectedJobFindings || [];
  const scanWorkers = (state.agentWorkers || []).filter((w) => String(w?.kind || "").toLowerCase() === "scan");
  const activeScanWorkers = scanWorkers.filter((w) => {
    const st = String(w?.status || "").toLowerCase();
    return st === "running" || st === "failed";
  });
  setHtml(root, `
    <div class="stack">
      ${renderSweepSummaryCard()}
      <div class="card">
        <div class="toolbar" style="justify-content:space-between">
          <h3 style="margin:0">Active Scan Workers</h3>
          <span class="muted">${activeScanWorkers.length} active • ${scanWorkers.length} total scan workers</span>
        </div>
        <div class="table-wrap" style="max-height:180px">
          <table>
            <thead><tr><th>Name</th><th>Status</th><th>Action</th><th>Repo</th><th>Job</th><th>Message</th><th>Updated</th></tr></thead>
            <tbody>
	              ${scanWorkers.length ? scanWorkers.map(w => `
	                <tr>
	                  <td>${escapeHtml(w.name || "")}</td>
	                  <td><span class="${statusClass(w.status)}">${escapeHtml(w.status || "")}</span></td>
                  <td>${escapeHtml(w.action || "")}</td>
                  <td>${escapeHtml(w.repo || "")}</td>
                  <td>${w.scan_job_id ? `#${w.scan_job_id}` : `<span class="muted">-</span>`}</td>
                  <td class="muted">${escapeHtml(w.message || "")}</td>
                  <td class="muted">${escapeHtml(fmtDate(w.updated_at))}</td>
	                </tr>
	              `).join("") : `<tr><td colspan="7" class="muted">No scan worker telemetry yet. Trigger a scan to populate live worker activity.</td></tr>`}
            </tbody>
          </table>
        </div>
      </div>
      <div class="split">
      <div class="card">
        <div class="toolbar">
          <button id="scansRefresh" class="btn btn-secondary">Refresh Jobs</button>
          <button id="scansDeleteSelected" class="btn btn-danger" ${selectedCount === 0 ? "disabled" : ""}>Delete Selected (${selectedCount})</button>
          <button id="scansDeleteAll" class="btn btn-danger" ${totalRows === 0 ? "disabled" : ""}>Delete All</button>
          <span class="muted">Page ${page} of ${totalPages} • Showing ${totalRows === 0 ? 0 : (pageStart + 1)}-${Math.min(pageStart + pageSize, totalRows)} of ${totalRows}</span>
          <button id="scansPrevPage" class="btn btn-secondary" ${page <= 1 ? "disabled" : ""}>Prev</button>
          <button id="scansNextPage" class="btn btn-secondary" ${page >= totalPages ? "disabled" : ""}>Next</button>
        </div>
        <div class="toolbar">
          <span class="muted">Click a job to inspect details. Use checkboxes for bulk delete.</span>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th style="width:34px"><input type="checkbox" id="scanSelectAll" ${allVisibleSelected ? "checked" : ""} ${visibleRows.length === 0 ? "disabled" : ""}></th>
                <th>ID</th><th>Repo</th><th>Status</th><th>Started</th><th>C/H/M/L</th><th>Actions</th>
              </tr>
            </thead>
            <tbody>
              ${visibleRows.map(j => `
                <tr data-job-id="${j.id}" style="cursor:pointer; ${state.selectedJobId === j.id ? "background:rgba(79,140,255,.08)" : ""}">
                  <td><input type="checkbox" data-job-select="${j.id}" ${selectedIds[j.id] ? "checked" : ""}></td>
                  <td>#${j.id}</td>
                  <td>${escapeHtml(j.owner)}/${escapeHtml(j.repo)}</td>
                  <td><span class="${statusClass(j.status)}">${escapeHtml(j.status)}</span></td>
                  <td>${escapeHtml(fmtDate(j.started_at))}</td>
                  <td>${j.findings_critical}/${j.findings_high}/${j.findings_medium}/${j.findings_low}</td>
                  <td class="row-actions"><button class="btn btn-danger" data-job-delete="${j.id}">Delete</button></td>
                </tr>
              `).join("") || `<tr><td colspan="7" class="muted">No jobs yet</td></tr>`}
            </tbody>
          </table>
        </div>
      </div>

      <div class="card">
        <h3>Job Detail ${selectedJob ? `#${selectedJob.id}` : ""}</h3>
        ${selectedJob ? `
          <div class="stack">
            <div><strong>${escapeHtml(selectedJob.owner)}/${escapeHtml(selectedJob.repo)}</strong> <span class="badge ${statusClass(selectedJob.status)}">${escapeHtml(selectedJob.status)}</span></div>
            <div class="muted">Branch ${escapeHtml(selectedJob.branch)} • Started ${escapeHtml(fmtDate(selectedJob.started_at))}</div>
            <div class="toolbar">
              <button class="btn btn-secondary" id="openDetailPageBtn">Open Full Detail Page</button>
            </div>
            <div class="kicker">Scanners</div>
            <div class="table-wrap">
              <table>
                <thead><tr><th>Scanner</th><th>Status</th><th>Findings</th><th>Duration</th><th>Raw</th></tr></thead>
                <tbody>
                  ${scanners.map(s => `
                    <tr>
                      <td>${escapeHtml(s.scanner_name)} <span class="muted">(${escapeHtml(s.scanner_type)})</span></td>
                      <td><span class="${statusClass(s.status)}">${escapeHtml(s.status)}</span></td>
                      <td>${s.findings_count}</td>
                      <td>${fmtDuration(s.duration_ms)}</td>
                      <td>${s.has_raw ? `<a class="link" href="/api/jobs/${selectedJob.id}/raw/${encodeURIComponent(s.scanner_name)}?download=1">download</a>` : `<span class="muted">n/a</span>`}</td>
                    </tr>`).join("") || `<tr><td colspan="5" class="muted">No per-scanner rows for this job. Legacy jobs (created before the raw/scanner persistence migration) will show limited detail.</td></tr>`}
                </tbody>
              </table>
            </div>
            <div class="kicker">Findings (structured from DB when available, otherwise parsed from raw scanner output)</div>
            <div class="table-wrap compact-findings-wrap" style="max-height:270px">
              <table>
                <thead><tr><th>Kind</th><th>Scanner</th><th>Severity</th><th>Path/Package</th></tr></thead>
                <tbody>
                ${findings.map(f => `<tr>
                  <td>${escapeHtml(f.kind)}</td>
                  <td>${escapeHtml(f.scanner || "")}</td>
                  <td>${escapeHtml(severityBucket ? severityBucket(f.severity) : f.severity)}</td>
                  <td>${escapeHtml(f.file_path || f.package || "")}${f.version ? ` <span class="muted">@${escapeHtml(f.version)}</span>` : ""}</td>
                </tr>`).join("") || `<tr><td colspan="4" class="muted">No findings available for this job yet. For new scans, details are parsed from raw scanner output when normalized DB rows are absent.</td></tr>`}
                </tbody>
              </table>
            </div>
          </div>
        ` : `<div class="muted">Select a scan job to inspect details.</div>`}
      </div>
      </div>
    </div>
  `);
  root.querySelector("#scansRefresh")?.addEventListener("click", refreshJobs);
  root.querySelector("#scansPrevPage")?.addEventListener("click", () => {
    state.scansPage = Math.max(1, (state.scansPage || 1) - 1);
    refreshJobs();
  });
  root.querySelector("#scansNextPage")?.addEventListener("click", () => {
    state.scansPage = (state.scansPage || 1) + 1;
    refreshJobs();
  });
  root.querySelector("#scansDeleteSelected")?.addEventListener("click", deleteSelectedScanJobs);
  root.querySelector("#scansDeleteAll")?.addEventListener("click", deleteAllScanJobs);
  root.querySelector("#scanSelectAll")?.addEventListener("change", (e) => {
    for (const row of visibleRows) {
      if (e.target.checked) {
        state.selectedScanJobIds[row.id] = true;
      } else {
        delete state.selectedScanJobIds[row.id];
      }
    }
    renderScans();
  });
  root.querySelectorAll("[data-job-select]").forEach((cb) => {
    cb.addEventListener("click", (e) => e.stopPropagation());
    cb.addEventListener("change", () => {
      const id = Number(cb.dataset.jobSelect);
      if (cb.checked) {
        state.selectedScanJobIds[id] = true;
      } else {
        delete state.selectedScanJobIds[id];
      }
      renderScans();
    });
  });
  root.querySelectorAll("[data-job-delete]").forEach((btn) => {
    btn.addEventListener("click", async (e) => {
      e.stopPropagation();
      await deleteOneScanJob(Number(btn.dataset.jobDelete));
    });
  });
  root.querySelector("#openDetailPageBtn")?.addEventListener("click", async () => {
    if (selectedJob) await openScanDetailPage(selectedJob.id);
  });
  root.querySelectorAll("[data-job-id]").forEach(tr => {
    tr.addEventListener("click", (e) => {
      if (e.target.closest("button") || e.target.closest("input") || e.target.closest("a")) return;
      selectJob(Number(tr.dataset.jobId));
    });
  });
}

function renderRemediation() {
  const root = document.getElementById("view-remediation");
  if (!root) return;
  const campaigns = state.remediationCampaigns || [];
  const draft = state.remediationDraft || {};
  let selected = campaigns.find(c => c.id === state.remediationSelectedCampaignId) || null;
  if (!selected && campaigns.length > 0) {
    selected = campaigns[0];
    state.remediationSelectedCampaignId = selected.id;
  }
  const tasks = state.remediationCampaignTasks || [];
  const repoSuggest = getRemediationRepoSuggestionsFiltered();
  const selectedRepos = Array.isArray(draft.selectedRepos) ? draft.selectedRepos : [];
  setHtml(root, `
    <div class="stack">
      <div class="split">
        <div class="card">
          <h3>Create Remediation Campaign</h3>
          <div class="form-grid">
            <label>Name<input id="remName" placeholder="Offline fix run" value="${escapeHtml(draft.name || "")}"></label>
            <label>Mode
              <select id="remMode">
                <option value="triage" ${draft.mode === "triage" ? "selected" : ""}>triage</option>
                <option value="semi" ${draft.mode === "semi" ? "selected" : ""}>semi</option>
                <option value="auto" ${draft.mode === "auto" ? "selected" : ""}>auto</option>
              </select>
            </label>
            <label>Max repos<input id="remMaxRepos" type="number" min="0" placeholder="10" value="${escapeHtml(draft.maxRepos ?? "")}"></label>
          </div>
          <div style="margin-top:10px">
            <label>Scanned repos (optional, multi-select)</label>
            <input id="remRepoSearch" placeholder="Type owner/repo to add from scanned repos…" value="${escapeHtml(state.remediationRepoFilter || "")}">
            <div class="toolbar" style="margin-top:8px; flex-wrap:wrap" id="remRepoChips">
              ${selectedRepos.map((repo) => `<span class="badge" style="display:inline-flex;align-items:center;gap:8px">${escapeHtml(repo)} <button class="btn btn-secondary" data-rem-chip-remove="${escapeHtml(repo)}" style="padding:2px 8px;min-height:auto">x</button></span>`).join("") || `<span class="muted">No repos selected. Leave empty to use latest scanned repos (subject to max repos).</span>`}
            </div>
            <div class="card" style="margin-top:8px; padding:8px 10px">
              <div class="toolbar" style="justify-content:space-between">
                <span class="muted">${state.remediationRepoSuggestionsLoading ? "Loading scanned repos…" : "Choose from previously scanned repos"}</span>
                <button id="remRepoReload" class="btn btn-secondary">Reload</button>
              </div>
              <div class="table-wrap" style="max-height:180px; margin-top:8px">
                <table>
                  <thead><tr><th>Repo</th><th>Provider</th><th>Action</th></tr></thead>
                  <tbody>
                    ${repoSuggest.map((r) => `<tr>
                      <td>${escapeHtml(getScannedRepoLabel(r))}</td>
                      <td>${escapeHtml(r.provider || "")}</td>
                      <td><button class="btn btn-secondary" data-rem-repo-add="${escapeHtml(getScannedRepoLabel(r))}">Add</button></td>
                    </tr>`).join("") || `<tr><td colspan="3" class="muted">${state.remediationRepoSuggestionsLoaded ? "No matching scanned repos." : "Repo suggestions not loaded yet."}</td></tr>`}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
          <div class="toolbar" style="margin-top:10px">
            <label style="display:flex; align-items:center; gap:8px; width:auto"><input id="remAutoPR" type="checkbox" ${draft.autoPR ? "checked" : ""}> Auto trigger PR processing</label>
            <label style="display:flex; align-items:center; gap:8px; width:auto"><input id="remStartNow" type="checkbox" ${draft.startNow !== false ? "checked" : ""}> Start immediately</label>
          </div>
          <div class="toolbar">
            <button id="remCreate" class="btn btn-primary">Create Campaign</button>
            <button id="remRefresh" class="btn btn-secondary">Refresh</button>
          </div>
          <div class="footer-note">Uses existing scan jobs/findings in the database. No rescan required.</div>
        </div>
        <div class="card">
          <h3>Worker Activity</h3>
          <div class="table-wrap">
            <table>
              <thead><tr><th>Name</th><th>Kind</th><th>Status</th><th>Action</th><th>Repo</th><th>Updated</th></tr></thead>
              <tbody>
                ${(state.agentWorkers || []).map(w => `<tr>
                  <td>${escapeHtml(w.name)}</td>
                  <td>${escapeHtml(w.kind)}</td>
                  <td><span class="${statusClass(w.status)}">${escapeHtml(w.status)}</span></td>
                  <td>${escapeHtml(w.action || "")}</td>
                  <td>${escapeHtml(w.repo || "")}</td>
                  <td>${escapeHtml(fmtDate(w.updated_at))}</td>
                </tr>`).join("") || `<tr><td colspan="6" class="muted">No worker status yet.</td></tr>`}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <div class="split">
        <div class="card">
          <h3>Campaigns</h3>
          <div class="table-wrap">
            <table>
              <thead><tr><th>ID</th><th>Name</th><th>Status</th><th>Mode</th><th>Tasks</th><th>Actions</th></tr></thead>
              <tbody>
                ${campaigns.map(c => `<tr data-rem-campaign-id="${c.id}" style="cursor:pointer; ${selected && selected.id === c.id ? "background:rgba(79,140,255,.08)" : ""}">
                  <td>#${c.id}</td>
                  <td>${escapeHtml(c.name)}</td>
                  <td><span class="${statusClass(c.status)}">${escapeHtml(c.status)}</span></td>
                  <td>${escapeHtml(c.mode)}</td>
                  <td>${c.completed_tasks}/${c.total_tasks} <span class="muted">(P:${c.pending_tasks} R:${c.running_tasks} F:${c.failed_tasks})</span></td>
                  <td class="row-actions">
                    <button class="btn btn-secondary" data-rem-start="${c.id}" ${c.status === "running" ? "disabled" : ""}>Start</button>
                    <button class="btn btn-danger" data-rem-stop="${c.id}" ${["running","draft"].includes(String(c.status)) ? "" : "disabled"}>Stop</button>
                  </td>
                </tr>`).join("") || `<tr><td colspan="6" class="muted">No remediation campaigns yet.</td></tr>`}
              </tbody>
            </table>
          </div>
        </div>

        <div class="card">
          <h3>Campaign Tasks ${selected ? `#${selected.id}` : ""}</h3>
          <div class="table-wrap">
            <table>
              <thead><tr><th>ID</th><th>Repo</th><th>Scan Job</th><th>Status</th><th>Worker</th><th>Message</th></tr></thead>
              <tbody>
                ${tasks.map(t => `<tr>
                  <td>#${t.id}</td>
                  <td>${escapeHtml(t.owner)}/${escapeHtml(t.repo)}</td>
                  <td>#${t.scan_job_id}</td>
                  <td><span class="${statusClass(t.status)}">${escapeHtml(t.status)}</span></td>
                  <td>${escapeHtml(t.worker_name || "")}</td>
                  <td class="muted">${escapeHtml(t.error_msg || "")}</td>
                </tr>`).join("") || `<tr><td colspan="6" class="muted">Select a campaign to inspect tasks.</td></tr>`}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  `);

  root.querySelector("#remRefresh")?.addEventListener("click", refreshRemediation);
  root.querySelector("#remCreate")?.addEventListener("click", createRemediationCampaign);
  root.querySelector("#remRepoReload")?.addEventListener("click", async () => {
    await refreshRemediationRepoSuggestions(true);
  });
  root.querySelector("#remName")?.addEventListener("input", (e) => { state.remediationDraft.name = e.target.value; });
  root.querySelector("#remMode")?.addEventListener("change", (e) => { state.remediationDraft.mode = e.target.value; });
  root.querySelector("#remMaxRepos")?.addEventListener("input", (e) => { state.remediationDraft.maxRepos = e.target.value; });
  root.querySelector("#remAutoPR")?.addEventListener("change", (e) => { state.remediationDraft.autoPR = !!e.target.checked; });
  root.querySelector("#remStartNow")?.addEventListener("change", (e) => { state.remediationDraft.startNow = !!e.target.checked; });
  root.querySelector("#remRepoSearch")?.addEventListener("input", (e) => {
    state.remediationRepoFilter = e.target.value;
    renderRemediation();
  });
  root.querySelector("#remRepoSearch")?.addEventListener("keydown", (e) => {
    if (e.key !== "Enter") return;
    e.preventDefault();
    const q = String(e.target.value || "").trim();
    const exact = (state.remediationRepoSuggestions || []).find(r => getScannedRepoLabel(r).toLowerCase() === q.toLowerCase());
    if (exact) {
      const label = getScannedRepoLabel(exact);
      if (!state.remediationDraft.selectedRepos.includes(label)) state.remediationDraft.selectedRepos.push(label);
      state.remediationRepoFilter = "";
      renderRemediation();
    }
  });
  root.querySelectorAll("[data-rem-repo-add]").forEach((btn) => btn.addEventListener("click", (e) => {
    e.preventDefault();
    const label = btn.dataset.remRepoAdd;
    if (!label) return;
    if (!state.remediationDraft.selectedRepos.includes(label)) state.remediationDraft.selectedRepos.push(label);
    state.remediationRepoFilter = "";
    renderRemediation();
  }));
  root.querySelectorAll("[data-rem-chip-remove]").forEach((btn) => btn.addEventListener("click", (e) => {
    e.preventDefault();
    const label = btn.dataset.remChipRemove;
    state.remediationDraft.selectedRepos = (state.remediationDraft.selectedRepos || []).filter(r => r !== label);
    renderRemediation();
  }));
  root.querySelectorAll("[data-rem-campaign-id]").forEach((tr) => tr.addEventListener("click", async (e) => {
    if (e.target.closest("button")) return;
    state.remediationSelectedCampaignId = Number(tr.dataset.remCampaignId);
    await refreshRemediationTasks(state.remediationSelectedCampaignId);
    renderRemediation();
  }));
  root.querySelectorAll("[data-rem-start]").forEach((btn) => btn.addEventListener("click", async (e) => {
    e.stopPropagation();
    await startRemediationCampaign(Number(btn.dataset.remStart));
  }));
  root.querySelectorAll("[data-rem-stop]").forEach((btn) => btn.addEventListener("click", async (e) => {
    e.stopPropagation();
    await stopRemediationCampaign(Number(btn.dataset.remStop));
  }));
}

function renderScanDetailPage() {
  const root = document.getElementById("view-scan-detail");
  const selectedJob = state.selectedJob;
  if (!selectedJob) {
    setHtml(root, `<div class="card"><div class="muted">No scan selected. Open a job from the Scans page.</div></div>`);
    return;
  }
  const scanners = state.selectedJobScanners || [];
  const findings = state.selectedJobFindings || [];
  const filters = state.scanDetailFindingsFilters || { kind: "", scanner: "", severity: "", title: "", path: "", q: "" };
  const draft = state.scanDetailFindingsDraft || { title: "", path: "", q: "" };
  const derivedSeverity = countFindingsBySeverity(findings);
  const hasFindings = (state.selectedJobFindingsTotal || 0) > 0 || findings.length > 0;
  const serverSeverity = state.selectedJobFindingsSeverityTotals || null;
  const severityCards = {
    critical: hasFindings ? (serverSeverity?.critical ?? derivedSeverity.critical) : (selectedJob.findings_critical ?? 0),
    high: hasFindings ? (serverSeverity?.high ?? derivedSeverity.high) : (selectedJob.findings_high ?? 0),
    medium: hasFindings ? (serverSeverity?.medium ?? derivedSeverity.medium) : (selectedJob.findings_medium ?? 0),
    low: hasFindings ? (serverSeverity?.low ?? derivedSeverity.low) : (selectedJob.findings_low ?? 0),
  };
  const pageSize = state.scanDetailFindingsPageSize || 25;
  const totalPages = Math.max(1, Number(state.selectedJobFindingsTotalPages || 1));
  const page = Math.min(Math.max(1, state.scanDetailFindingsPage || 1), totalPages);
  state.scanDetailFindingsPage = page;
  const start = (page - 1) * pageSize;
  const visibleFindings = findings;
  const facets = state.selectedJobFindingsFacets || { kinds: [], scanners: [], severities: [] };
  const kindOptions = Array.isArray(facets.kinds) ? facets.kinds : [];
  const scannerOptions = Array.isArray(facets.scanners) ? facets.scanners : [];
  const severityOptions = Array.isArray(facets.severities) ? facets.severities : [];
  const fixes = state.selectedJobFixes || [];
  const fixSearch = String(state.scanDetailFixesSearch || "").trim().toLowerCase();
  const fixStatusFilter = String(state.scanDetailFixesStatus || "").trim().toLowerCase();
  const filteredFixes = fixes.filter((f) => {
    const status = String(f.status || "").toLowerCase();
    if (fixStatusFilter && status !== fixStatusFilter) return false;
    if (!fixSearch) return true;
    const hay = [
      f.id,
      f.finding_type,
      f.status,
      f.pr_title,
      f.pr_url,
      f.pr_body,
    ].map(v => String(v || "")).join(" ").toLowerCase();
    return hay.includes(fixSearch);
  });
  const fixPageSize = Math.max(1, Number(state.scanDetailFixesPageSize || 10));
  const fixTotal = filteredFixes.length;
  const fixTotalPages = Math.max(1, Math.ceil(fixTotal / fixPageSize));
  const fixPage = Math.min(Math.max(1, Number(state.scanDetailFixesPage || 1)), fixTotalPages);
  state.scanDetailFixesPage = fixPage;
  const fixStart = (fixPage - 1) * fixPageSize;
  const visibleFixes = filteredFixes.slice(fixStart, fixStart + fixPageSize);
  const fixStatusOptions = [...new Set(fixes.map(f => String(f.status || "").trim()).filter(Boolean))].sort();
  const remediationRuns = state.selectedJobRemediationRuns || [];
  const remediationRunsTotal = Number(state.selectedJobRemediationRunsTotal || remediationRuns.length || 0);
  const remediationRunsPage = Number(state.selectedJobRemediationRunsPage || 1);
  const remediationRunsTotalPages = Math.max(1, Number(state.selectedJobRemediationRunsTotalPages || 1));
  const remediationHistoryCollapsed = !!state.scanDetailRemediationHistoryCollapsed;
  const remediationExpanded = state.scanDetailRemediationExpandedTaskIds || {};
  const aiEnabled = !!state.agent?.ai_enabled;
  const mode = state.agent?.mode || "triage";
  const pathIgnoreRules = state.pathIgnoreRules || [];
  const activeRemediationWorker = (state.agentWorkers || []).find((w) =>
    w && w.kind === "remediation" &&
    Number(w.scan_job_id || 0) === Number(selectedJob.id) &&
    ["running"].includes(String(w.status || "").toLowerCase())
  );
  const remediationForScanRunning = !!activeRemediationWorker;
  setHtml(root, `
    <div class="scan-detail-layout">
      <div class="card">
        <div class="sticky-actions">
          <div>
            <h3 style="margin-bottom:6px">Scan #${selectedJob.id} · ${escapeHtml(selectedJob.owner)}/${escapeHtml(selectedJob.repo)}</h3>
            <div class="muted">Branch ${escapeHtml(selectedJob.branch)} • Commit ${escapeHtml(selectedJob.commit_sha || "")} • ${escapeHtml(fmtDate(selectedJob.started_at))}</div>
            <div style="margin-top:8px"><span class="badge ${statusClass(selectedJob.status)}">${escapeHtml(selectedJob.status)}</span></div>
          </div>
          <div class="row-actions">
            <button id="detailBackToScans" class="btn btn-secondary">Back To Scans</button>
            <button id="detailRefresh" class="btn btn-secondary">Refresh Detail</button>
          </div>
        </div>
      </div>
      <div class="grid cols-4">
        <div class="card card-critical"><div class="metric-label">Critical</div><div class="metric-value critical">${severityCards.critical}</div></div>
        <div class="card card-high"><div class="metric-label">High</div><div class="metric-value high">${severityCards.high}</div></div>
        <div class="card card-medium"><div class="metric-label">Medium</div><div class="metric-value medium">${severityCards.medium}</div></div>
        <div class="card card-low"><div class="metric-label">Low</div><div class="metric-value low">${severityCards.low}</div></div>
      </div>
      <div class="card">
        <h3>Scanners</h3>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Scanner</th><th>Type</th><th>Status</th><th>Findings</th><th>Duration</th><th>Raw</th></tr></thead>
            <tbody>
              ${scanners.map(s => `<tr>
                <td>${escapeHtml(s.scanner_name)}</td>
                <td>${escapeHtml(s.scanner_type)}</td>
                <td><span class="${statusClass(s.status)}">${escapeHtml(s.status)}</span></td>
                <td>${s.findings_count}</td>
                <td>${fmtDuration(s.duration_ms)}</td>
                <td>${s.has_raw ? `<a class="link" href="/api/jobs/${selectedJob.id}/raw/${encodeURIComponent(s.scanner_name)}?download=1">download</a>` : `<span class="muted">n/a</span>`}</td>
              </tr>`).join("") || `<tr><td colspan="6" class="muted">No scanner rows available.</td></tr>`}
            </tbody>
          </table>
        </div>
      </div>
      <div class="card">
        <div class="toolbar">
          <h3 style="margin:0">Findings</h3>
          <label style="width:auto">
            <select id="detailFindingsKindFilter">
              <option value="">All kinds</option>
              ${kindOptions.map(v => `<option value="${escapeHtml(v)}" ${filters.kind === v ? "selected" : ""}>${escapeHtml(v)}</option>`).join("")}
            </select>
          </label>
          <label style="width:auto">
            <select id="detailFindingsScannerFilter">
              <option value="">All scanners</option>
              ${scannerOptions.map(v => `<option value="${escapeHtml(v)}" ${filters.scanner === v ? "selected" : ""}>${escapeHtml(v)}</option>`).join("")}
            </select>
          </label>
          <label style="width:auto">
            <select id="detailFindingsSeverityFilter">
              <option value="">All severities</option>
              ${severityOptions.map(v => `<option value="${escapeHtml(v)}" ${filters.severity === v ? "selected" : ""}>${escapeHtml(v)}</option>`).join("")}
            </select>
          </label>
          <input id="detailFindingsTitleFilter" placeholder="Title contains…" value="${escapeHtml(draft.title || "")}" style="max-width:220px">
          <input id="detailFindingsPathFilter" placeholder="Path contains…" value="${escapeHtml(draft.path || "")}" style="max-width:220px">
          <input id="detailFindingsSearch" placeholder="Search findings…" value="${escapeHtml(draft.q || "")}" style="min-width:240px">
          <button id="detailFindingsSearchApply" class="btn btn-secondary">Search</button>
          <button id="detailFindingsSearchClear" class="btn btn-secondary">Clear</button>
          <button id="detailPathIgnores" class="btn btn-secondary">Path Ignores (${pathIgnoreRules.length})</button>
          <span class="muted">Showing ${(state.selectedJobFindingsTotal || 0) === 0 ? 0 : (start + 1)}-${Math.min(start + pageSize, Number(state.selectedJobFindingsTotal || 0))} of ${Number(state.selectedJobFindingsTotal || 0)}</span>
          <button id="detailFindingsPrev" class="btn btn-secondary" ${page <= 1 ? "disabled" : ""}>Prev</button>
          <button id="detailFindingsNext" class="btn btn-secondary" ${page >= totalPages ? "disabled" : ""}>Next</button>
        </div>
        <div class="table-wrap findings-table-wrap">
          <table>
            <thead><tr><th>Kind</th><th>Scanner</th><th>Severity</th><th>Title</th><th>Path</th><th>Line</th><th>Detail</th></tr></thead>
            <tbody>
              ${visibleFindings.map(f => `<tr>
                <td>${escapeHtml(f.kind)}</td>
                <td>${escapeHtml(f.scanner || "")}</td>
                <td>${escapeHtml(severityBucket(f.severity))}</td>
                <td>${escapeHtml(f.title)}</td>
                <td>${escapeHtml(f.file_path || f.package || "")}</td>
                <td>${f.line || ""}</td>
                <td class="muted">${escapeHtml(f.fix ? `Fix: ${f.fix}` : (f.message || ""))}</td>
              </tr>`).join("") || `<tr><td colspan="7" class="muted">No findings available.</td></tr>`}
            </tbody>
          </table>
        </div>
        <div class="footer-note">Use raw downloads for exact scanner payloads. Paths are normalized to repo-relative paths when possible. Severity cards above reflect loaded findings when available.</div>
      </div>
      <div class="card">
        <h3>AI Triage / Fix Review</h3>
        ${!aiEnabled ? `
          <div class="muted">AI provider is not configured. Add an OpenAI key (or another provider) in Config to enable triage, patches, and PR actions.</div>
        ` : `
          <div class="footer-note">Mode: ${escapeHtml(mode)}. In triage mode, use "Approve + Create PR" for one-click PR creation.</div>
          <div class="toolbar" style="margin-top:10px">
            <button id="detailLaunchReviewCampaign" class="btn btn-primary ${remediationForScanRunning ? "is-loading" : ""}" ${remediationForScanRunning ? "disabled" : ""}>${remediationForScanRunning ? "AI Reviewing…" : "Launch AI Review Campaign For This Scan"}</button>
            <button id="detailStopReviewCampaign" class="btn btn-danger ${state.scanDetailAiStopBusy ? "is-loading" : ""}" ${(remediationForScanRunning && !state.scanDetailAiStopBusy) ? "" : (state.scanDetailAiStopBusy ? "disabled" : "disabled")}>${state.scanDetailAiStopBusy ? "Stopping" : "Stop AI Review"}</button>
            <span class="muted">Creates an offline remediation campaign pinned to this scan job so AI triage can populate fix reviews without rescanning.</span>
          </div>
          ${remediationForScanRunning ? `
            <div class="ai-runtime-banner">
              <span class="spinner-dot" aria-hidden="true"></span>
              <div>
                <strong>AI remediation agent is working on this scan.</strong>
                <div class="muted">Worker: ${escapeHtml(activeRemediationWorker.name || "remediation")} • ${escapeHtml(activeRemediationWorker.action || "triaging findings")}</div>
              </div>
            </div>
          ` : ``}
          <div class="card" style="margin-top:10px; padding:10px 12px">
            <div class="toolbar" style="justify-content:space-between">
              <div class="kicker" style="margin:0">AI Remediation Campaign History (This Scan)</div>
              <div class="row-actions">
                <span class="muted">Page ${remediationRunsPage} of ${remediationRunsTotalPages} • ${remediationRunsTotal} total</span>
                <button id="detailRemHistoryPrev" class="btn btn-secondary" ${remediationRunsPage <= 1 ? "disabled" : ""}>Prev</button>
                <button id="detailRemHistoryNext" class="btn btn-secondary" ${remediationRunsPage >= remediationRunsTotalPages ? "disabled" : ""}>Next</button>
                <button id="detailRemHistoryToggle" class="btn btn-secondary">${remediationHistoryCollapsed ? "Expand" : "Collapse"}</button>
              </div>
            </div>
            <div class="table-wrap remediation-history-wrap ${remediationHistoryCollapsed ? "hidden" : ""}">
              <table>
                <thead><tr><th>Campaign</th><th>Task</th><th>Status</th><th>AI Outcome</th><th>Started</th><th>Completed</th><th>Message</th><th>Details</th></tr></thead>
                <tbody>
                  ${remediationRuns.map(r => `<tr>
                    <td>#${r.campaign_id} <span class="muted">${escapeHtml(r.campaign_name || "")}</span></td>
                    <td>#${r.task_id}</td>
                    <td>
                      <div><span class="${statusClass(r.task_status)}">${escapeHtml(r.task_status || "")}</span></div>
                      <div class="muted">Campaign: ${escapeHtml(r.campaign_status || "")} (${escapeHtml(r.campaign_mode || "")})</div>
                    </td>
                    <td>
                      <div>${escapeHtml(r.ai_triage_status || "-")}</div>
                      <div class="muted">findings ${Number(r.ai_findings_loaded || 0)} → ${Number(r.ai_findings_deduped || 0)} • batches ${Number(r.ai_triage_batches || 0)}</div>
                      <div class="muted">queued ${Number(r.ai_fix_queued || 0)} / attempted ${Number(r.ai_fix_attempted || 0)} • low-conf ${Number(r.ai_fix_skipped_low_conf || 0)} • failed ${Number(r.ai_fix_failed || 0)}</div>
                    </td>
                    <td>${escapeHtml(fmtDate(r.started_at || r.campaign_started_at || r.created_at))}</td>
                    <td>${escapeHtml(fmtDate(r.completed_at || r.campaign_completed_at || ""))}</td>
                    <td class="muted">${escapeHtml(r.task_message || r.campaign_error || "")}</td>
                    <td><button class="btn btn-secondary" data-rem-task-toggle="${r.task_id}">${remediationExpanded[r.task_id] ? "Hide" : "Show"}</button></td>
                  </tr>
                  ${remediationExpanded[r.task_id] ? `<tr>
                    <td colspan="8">
                      <div class="remediation-outcome-detail">
                        <div class="muted"><strong>AI updated:</strong> ${escapeHtml(fmtDate(r.ai_updated_at || ""))}</div>
                        <div class="muted" style="margin-top:6px"><strong>Triage summary</strong></div>
                        <pre class="code remediation-summary-pre">${escapeHtml(r.ai_triage_summary || "No triage summary saved.")}</pre>
                      </div>
                    </td>
                  </tr>` : ""}`).join("") || `<tr><td colspan="8" class="muted">No AI remediation campaigns have run for this scan yet.</td></tr>`}
                </tbody>
              </table>
            </div>
            <div class="footer-note">This history shows offline AI review campaign runs for this scan even when no fixes were queued (for example, if all fixes were skipped as low confidence).</div>
          </div>
          <div class="card" style="margin-top:10px; padding:10px 12px">
            <div class="toolbar">
              <input id="detailFixesSearch" placeholder="Search fixes / PR title / status..." value="${escapeHtml(state.scanDetailFixesSearch || "")}" style="min-width:260px">
              <label style="width:auto">
                <select id="detailFixesStatusFilter">
                  <option value="">All statuses</option>
                  ${fixStatusOptions.map(v => `<option value="${escapeHtml(v)}" ${String(state.scanDetailFixesStatus||"") === v ? "selected" : ""}>${escapeHtml(v)}</option>`).join("")}
                </select>
              </label>
              <button id="detailFixesSearchClear" class="btn btn-secondary">Clear</button>
              <span class="muted">Showing ${fixTotal === 0 ? 0 : (fixStart + 1)}-${Math.min(fixStart + fixPageSize, fixTotal)} of ${fixTotal}</span>
              <button id="detailFixesPrev" class="btn btn-secondary" ${fixPage <= 1 ? "disabled" : ""}>Prev</button>
              <button id="detailFixesNext" class="btn btn-secondary" ${fixPage >= fixTotalPages ? "disabled" : ""}>Next</button>
            </div>
            <div class="table-wrap">
            <table>
              <thead><tr><th>ID</th><th>Type</th><th>Status</th><th>PR Title</th><th>PR</th><th>Actions</th></tr></thead>
              <tbody>
                ${visibleFixes.map(f => `<tr>
                  <td>#${f.id}</td>
                  <td>${escapeHtml(f.finding_type)}</td>
                  <td><span class="${statusClass(f.status)}">${escapeHtml(f.status)}</span></td>
                  <td>${escapeHtml(f.pr_title || "")}</td>
                  <td>${f.pr_url ? `<a class="link" target="_blank" rel="noreferrer" href="${escapeHtml(f.pr_url)}">Open PR</a>` : `<span class="muted">n/a</span>`}</td>
                  <td class="row-actions">
                    ${["pending", "approved", "pr_failed"].includes(String(f.status || "").toLowerCase()) ? `
                      ${String(f.status || "").toLowerCase() === "pending" ? `<button class="btn btn-secondary" data-fix-action="approve" data-fix-id="${f.id}">Approve</button>` : ``}
                      <button class="btn btn-primary" data-fix-action="approve-run" data-fix-id="${f.id}">${String(f.status || "").toLowerCase() === "pr_failed" ? "Retry Create PR" : (String(f.status || "").toLowerCase() === "approved" ? "Create PR" : "Approve + Create PR")}</button>
                      ${String(f.status || "").toLowerCase() !== "pr_open" ? `<button class="btn btn-danger" data-fix-action="reject" data-fix-id="${f.id}">Reject</button>` : ``}
                    ` : `<span class="muted">-</span>`}
                  </td>
                </tr>`).join("") || `<tr><td colspan="6" class="muted">No AI-generated fixes queued for this scan yet.</td></tr>`}
              </tbody>
            </table>
          </div>
          </div>
        `}
      </div>
    </div>
  `);
  root.querySelector("#detailBackToScans")?.addEventListener("click", () => setView("scans"));
  root.querySelector("#detailRefresh")?.addEventListener("click", async () => {
    if (state.selectedJobId) await selectJob(state.selectedJobId, { preserveFindingsState: true, preserveRemediationState: true });
    renderScanDetailPage();
  });
  root.querySelector("#detailFindingsKindFilter")?.addEventListener("change", async (e) => {
    state.scanDetailFindingsFilters.kind = e.target.value;
    state.scanDetailFindingsPage = 1;
    await loadSelectedJobFindings();
    renderScanDetailPage();
  });
  root.querySelector("#detailFindingsScannerFilter")?.addEventListener("change", async (e) => {
    state.scanDetailFindingsFilters.scanner = e.target.value;
    state.scanDetailFindingsPage = 1;
    await loadSelectedJobFindings();
    renderScanDetailPage();
  });
  root.querySelector("#detailFindingsSeverityFilter")?.addEventListener("change", async (e) => {
    state.scanDetailFindingsFilters.severity = e.target.value;
    state.scanDetailFindingsPage = 1;
    await loadSelectedJobFindings();
    renderScanDetailPage();
  });
  root.querySelector("#detailFindingsTitleFilter")?.addEventListener("input", (e) => {
    state.scanDetailFindingsDraft.title = e.target.value || "";
  });
  root.querySelector("#detailFindingsPathFilter")?.addEventListener("input", (e) => {
    state.scanDetailFindingsDraft.path = e.target.value || "";
  });
  root.querySelector("#detailFindingsSearch")?.addEventListener("input", (e) => {
    state.scanDetailFindingsDraft.q = e.target.value || "";
  });
  root.querySelector("#detailFindingsSearchApply")?.addEventListener("click", async () => {
    state.scanDetailFindingsFilters.title = state.scanDetailFindingsDraft.title || "";
    state.scanDetailFindingsFilters.path = state.scanDetailFindingsDraft.path || "";
    state.scanDetailFindingsFilters.q = state.scanDetailFindingsDraft.q || "";
    state.scanDetailFindingsPage = 1;
    await loadSelectedJobFindings();
    renderScanDetailPage();
  });
  root.querySelector("#detailFindingsSearchClear")?.addEventListener("click", async () => {
    state.scanDetailFindingsDraft.title = "";
    state.scanDetailFindingsDraft.path = "";
    state.scanDetailFindingsDraft.q = "";
    state.scanDetailFindingsFilters.title = "";
    state.scanDetailFindingsFilters.path = "";
    state.scanDetailFindingsFilters.q = "";
    state.scanDetailFindingsPage = 1;
    await loadSelectedJobFindings();
    renderScanDetailPage();
  });
  root.querySelector("#detailPathIgnores")?.addEventListener("click", openPathIgnoreModal);
  ["#detailFindingsTitleFilter", "#detailFindingsPathFilter", "#detailFindingsSearch"].forEach((sel) => {
    root.querySelector(sel)?.addEventListener("keydown", (e) => {
      if (e.key !== "Enter") return;
      e.preventDefault();
      root.querySelector("#detailFindingsSearchApply")?.click();
    });
  });
  root.querySelector("#detailFindingsPrev")?.addEventListener("click", async () => {
    state.scanDetailFindingsPage = Math.max(1, (state.scanDetailFindingsPage || 1) - 1);
    await loadSelectedJobFindings();
    renderScanDetailPage();
  });
  root.querySelector("#detailFindingsNext")?.addEventListener("click", async () => {
    state.scanDetailFindingsPage = (state.scanDetailFindingsPage || 1) + 1;
    await loadSelectedJobFindings();
    renderScanDetailPage();
  });
  root.querySelector("#detailRemHistoryToggle")?.addEventListener("click", () => {
    state.scanDetailRemediationHistoryCollapsed = !state.scanDetailRemediationHistoryCollapsed;
    renderScanDetailPage();
  });
  root.querySelector("#detailRemHistoryPrev")?.addEventListener("click", async () => {
    state.selectedJobRemediationRunsPage = Math.max(1, (state.selectedJobRemediationRunsPage || 1) - 1);
    await loadSelectedJobRemediationRuns();
    renderScanDetailPage();
  });
  root.querySelector("#detailRemHistoryNext")?.addEventListener("click", async () => {
    state.selectedJobRemediationRunsPage = Math.min(Math.max(1, Number(state.selectedJobRemediationRunsTotalPages || 1)), (state.selectedJobRemediationRunsPage || 1) + 1);
    await loadSelectedJobRemediationRuns();
    renderScanDetailPage();
  });
  root.querySelectorAll("[data-rem-task-toggle]").forEach((btn) => btn.addEventListener("click", () => {
    const id = Number(btn.dataset.remTaskToggle);
    state.scanDetailRemediationExpandedTaskIds[id] = !state.scanDetailRemediationExpandedTaskIds[id];
    renderScanDetailPage();
  }));
  root.querySelectorAll("[data-fix-action]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = Number(btn.dataset.fixId);
      const action = btn.dataset.fixAction;
      await handleFixAction(id, action);
    });
  });
  root.querySelector("#detailFixesSearch")?.addEventListener("input", (e) => {
    state.scanDetailFixesSearch = e.target.value || "";
    state.scanDetailFixesPage = 1;
    renderScanDetailPage();
  });
  root.querySelector("#detailFixesStatusFilter")?.addEventListener("change", (e) => {
    state.scanDetailFixesStatus = e.target.value || "";
    state.scanDetailFixesPage = 1;
    renderScanDetailPage();
  });
  root.querySelector("#detailFixesSearchClear")?.addEventListener("click", () => {
    state.scanDetailFixesSearch = "";
    state.scanDetailFixesStatus = "";
    state.scanDetailFixesPage = 1;
    renderScanDetailPage();
  });
  root.querySelector("#detailFixesPrev")?.addEventListener("click", () => {
    state.scanDetailFixesPage = Math.max(1, (state.scanDetailFixesPage || 1) - 1);
    renderScanDetailPage();
  });
  root.querySelector("#detailFixesNext")?.addEventListener("click", () => {
    state.scanDetailFixesPage = Math.min(fixTotalPages, (state.scanDetailFixesPage || 1) + 1);
    renderScanDetailPage();
  });
  root.querySelector("#detailLaunchReviewCampaign")?.addEventListener("click", launchReviewCampaignForSelectedScan);
  root.querySelector("#detailStopReviewCampaign")?.addEventListener("click", stopReviewCampaignForSelectedScan);
}

function renderCron() {
  const root = document.getElementById("view-cron");
  const rows = state.schedules || [];
  setHtml(root, `
    <div class="card">
      <h3>Create Schedule</h3>
      <div class="form-grid">
        <label>Name<input id="cronName" placeholder="Nightly sweep"></label>
        <label>Expression<input id="cronExpr" placeholder="@daily"></label>
        <label>Mode<input id="cronMode" placeholder="triage"></label>
      </div>
      <div class="toolbar" style="margin-top:10px">
        <button id="cronCreate" class="btn btn-primary">Create</button>
        <button id="cronRefresh" class="btn btn-secondary">Refresh</button>
      </div>
      <div class="footer-note">Examples: <code>@daily</code>, <code>@every 6h</code>, <code>0 2 * * *</code></div>
    </div>
    <div class="card" style="margin-top:14px">
      <h3>Schedules</h3>
      <div class="table-wrap">
        <table>
          <thead><tr><th>ID</th><th>Name</th><th>Expr</th><th>Last Run</th><th>Actions</th></tr></thead>
          <tbody>
            ${rows.map(s => `
              <tr>
                <td>#${s.id}</td>
                <td>${escapeHtml(s.name)}</td>
                <td><code>${escapeHtml(s.expr)}</code></td>
                <td>${escapeHtml(fmtDate(s.last_run_at))}</td>
                <td class="row-actions">
                  <button class="btn btn-secondary" data-action="trigger" data-id="${s.id}">Trigger</button>
                  <button class="btn btn-danger" data-action="delete" data-id="${s.id}">Delete</button>
                </td>
              </tr>`).join("") || `<tr><td colspan="5" class="muted">No schedules configured.</td></tr>`}
          </tbody>
        </table>
      </div>
    </div>
  `);
  root.querySelector("#cronRefresh")?.addEventListener("click", refreshCron);
  root.querySelector("#cronCreate")?.addEventListener("click", createCron);
  root.querySelectorAll("[data-action='trigger']").forEach(btn => btn.addEventListener("click", () => triggerCron(Number(btn.dataset.id))));
  root.querySelectorAll("[data-action='delete']").forEach(btn => btn.addEventListener("click", () => deleteCron(Number(btn.dataset.id))));
}

function renderAgents() {
  const root = document.getElementById("view-agents");
  const st = state.status || {};
  const agent = state.agent || {};
  const workers = [...(state.agentWorkers || [])].sort((a, b) => String(a.name || "").localeCompare(String(b.name || "")));
  setHtml(root, `
    <div class="grid cols-3">
      <div class="card card-ok"><div class="metric-label">Runtime</div><div class="metric-value ${st.paused ? "warn" : "ok"}">${st.paused ? "Paused" : (st.running ? "Running" : "Idle")}</div></div>
      <div class="card card-accent"><div class="metric-label">Scan Workers</div><div class="metric-value">${st.workers ?? state.agent?.status?.workers ?? 0}</div></div>
      <div class="card card-purple"><div class="metric-label">Mode</div><div class="metric-value" style="font-size:22px">${escapeHtml(agent.mode || "triage")}</div></div>
    </div>
    <div class="grid cols-2" style="margin-top:14px">
      <div class="card">
        <h3>Controls</h3>
        <div class="toolbar">
          <button id="agentsTrigger" class="btn btn-primary">Trigger Sweep</button>
          <button id="agentsStop" class="btn btn-danger ${state.stopBusy ? "is-loading" : ""}" ${state.stopBusy ? "disabled" : ""}>${state.stopBusy ? "Stopping" : "Stop Sweep"}</button>
          <button id="agentsPause" class="btn ${st.paused ? "btn-secondary" : "btn-danger"}">${st.paused ? "Resume" : "Pause"}</button>
          <button id="agentsRefresh" class="btn btn-secondary">Refresh</button>
        </div>
        <div class="footer-note">This controls one gateway agent orchestrator. Worker count is scanner concurrency within that agent.</div>
      </div>
      <div class="card">
        <h3>Scan Worker Concurrency</h3>
        <div class="toolbar">
          <input id="workersInput" type="number" min="1" max="64" value="${st.workers || 3}" style="max-width:120px">
          <button id="workersSave" class="btn btn-primary">Save Workers</button>
        </div>
        <div class="footer-note">Applies to future sweeps and persists to config.</div>
      </div>
    </div>
    <div class="card" style="margin-top:14px">
      <h3>Background Worker Activity</h3>
      <div class="footer-note">Shows current PR and remediation worker actions in the orchestrator. Scan workers are represented by scan jobs/sweep status above.</div>
      <div class="table-wrap" style="margin-top:10px">
        <table>
          <thead><tr><th>Name</th><th>Kind</th><th>Status</th><th>Action</th><th>Repo</th><th>Campaign</th><th>Task</th><th>Updated</th></tr></thead>
          <tbody>
            ${workers.map(w => `<tr>
              <td>${escapeHtml(w.name)}</td>
              <td>${escapeHtml(w.kind)}</td>
              <td><span class="${statusClass(w.status)}">${escapeHtml(w.status)}</span></td>
              <td>${escapeHtml(w.action || "")}</td>
              <td>${escapeHtml(w.repo || "")}</td>
              <td>${w.campaign_id ? `#${w.campaign_id}` : `<span class="muted">-</span>`}</td>
              <td>${w.task_id ? `#${w.task_id}` : `<span class="muted">-</span>`}</td>
              <td>${escapeHtml(fmtDate(w.updated_at))}</td>
            </tr>`).join("") || `<tr><td colspan="8" class="muted">No background worker activity yet.</td></tr>`}
          </tbody>
        </table>
      </div>
    </div>
  `);
  root.querySelector("#agentsTrigger")?.addEventListener("click", openTriggerModal);
  root.querySelector("#agentsStop")?.addEventListener("click", stopSweep);
  root.querySelector("#agentsPause")?.addEventListener("click", async () => setPaused(!(state.status && state.status.paused)));
  root.querySelector("#agentsRefresh")?.addEventListener("click", refreshAgent);
  root.querySelector("#workersSave")?.addEventListener("click", async () => {
    const workers = Number(root.querySelector("#workersInput").value);
    await api("/api/agent/workers", { method: "PUT", body: JSON.stringify({ workers }) });
    await refreshAgent();
    await refreshStatus();
  });
  syncStopButtons();
}

function renderConfig() {
  const root = document.getElementById("view-config");
  setHtml(root, `
    <div class="card">
      <h3>Gateway Config</h3>
      <div class="muted">Path: ${escapeHtml(state.configPath || "default")}</div>
      <div class="footer-note">Secrets are redacted on read. Saving this JSON preserves unchanged masked secrets.</div>
      <div class="toolbar" style="margin-top:10px">
        <button id="cfgRefresh" class="btn btn-secondary">Refresh</button>
        <button id="cfgSave" class="btn btn-primary">Save</button>
      </div>
      <textarea id="cfgEditor" class="code-edit"></textarea>
    </div>
  `);
  const editor = root.querySelector("#cfgEditor");
  editor.value = state.config ? JSON.stringify(state.config, null, 2) : "{\n}";
  root.querySelector("#cfgRefresh").addEventListener("click", refreshConfig);
  root.querySelector("#cfgSave").addEventListener("click", async () => {
    try {
      const parsed = JSON.parse(editor.value);
      await api("/api/config", { method: "PUT", body: JSON.stringify(parsed) });
      await refreshConfig();
      showNotice("Config Saved", "Configuration saved.");
    } catch (err) {
      showNotice("Config Save Failed", err.message);
    }
  });
}

function renderEvents() {
  const root = document.getElementById("view-events");
  setHtml(root, `
    <div class="card">
      <div class="toolbar">
        <button id="eventsClear" class="btn btn-secondary">Clear</button>
        <span class="muted">Live SSE from <code>/events</code></span>
      </div>
      <pre class="code" id="eventsLog">${escapeHtml(state.events.map(e => `${e.at} ${e.type} ${JSON.stringify(e.payload ?? {})}`).join("\n"))}</pre>
    </div>
  `);
  root.querySelector("#eventsClear")?.addEventListener("click", () => {
    state.events = [];
    renderEvents();
  });
}

async function triggerSweep() {
  try {
    await api("/api/agent/trigger", { method: "POST", body: "{}" });
    await refreshStatus();
  } catch (err) {
    showNotice("Trigger Failed", err.message);
  }
}

async function triggerSweepWithOptions({ scanTargets, workers, selectedRepos }) {
  try {
    const payload = {};
    if (Array.isArray(scanTargets) && scanTargets.length > 0) payload.scan_targets = scanTargets;
    if (workers && Number(workers) > 0) payload.workers = Number(workers);
    if (Array.isArray(selectedRepos) && selectedRepos.length > 0) payload.selected_repos = selectedRepos;
    await api("/api/agent/trigger", { method: "POST", body: JSON.stringify(payload) });
    showToast({ title: "Trigger Submitted", message: "Requested a new scan sweep. Watch the Scans page for live updates.", kind: "info", timeoutMs: 2500 });
    closeTriggerModal();
    await refreshStatus();
    await refreshAgent();
    await refreshJobs();
  } catch (err) {
    showNotice("Trigger Failed", err.message);
  }
}

async function stopSweep() {
  if (state.stopBusy) return;
  state.stopBusy = true;
  syncStopButtons();
  try {
    const res = await api("/api/agent/stop", { method: "POST", body: "{}" });
    if (res.status === "idle") {
      showNotice("Nothing To Stop", "No active sweep is running.");
    }
    await refreshStatus();
  } catch (err) {
    showNotice("Stop Failed", err.message);
  } finally {
    state.stopBusy = false;
    syncStopButtons();
  }
}

async function setPaused(paused) {
  try {
    await api(paused ? "/api/agent/pause" : "/api/agent/resume", { method: "POST", body: "{}" });
    await refreshStatus();
    await refreshAgent();
  } catch (err) {
    showNotice("Agent Update Failed", err.message);
  }
}

async function createCron() {
  const root = document.getElementById("view-cron");
  const name = root.querySelector("#cronName").value.trim();
  const expr = root.querySelector("#cronExpr").value.trim();
  const mode = root.querySelector("#cronMode").value.trim();
  if (!name || !expr) {
    showNotice("Missing Fields", "Name and expression are required.");
    return;
  }
  try {
    await api("/api/schedules", {
      method: "POST",
      body: JSON.stringify({ name, expr, mode, enabled: true, targets: "[]" }),
    });
    root.querySelector("#cronName").value = "";
    await refreshCron();
  } catch (err) {
    showNotice("Create Schedule Failed", err.message);
  }
}

async function triggerCron(id) {
  try {
    await api(`/api/schedules/${id}/trigger`, { method: "POST", body: "{}" });
    await refreshCron();
  } catch (err) {
    showNotice("Trigger Schedule Failed", err.message);
  }
}

async function deleteCron(id) {
  if (!(await showConfirm({ title: "Delete Schedule", message: `Delete schedule #${id}?`, confirmLabel: "Delete" }))) return;
  try {
    await fetch(`/api/schedules/${id}`, { method: "DELETE" });
    await refreshCron();
  } catch (err) {
    showNotice("Delete Schedule Failed", err.message);
  }
}

async function refreshStatus() {
  state.status = await api("/api/status");
  renderHealthPill();
}

async function refreshJobs() {
  const jobsRes = await api(`/api/jobs?page=${state.scansPage || 1}&page_size=${state.scansPageSize || 20}`);
  if (jobsRes && Array.isArray(jobsRes.items)) {
    state.jobs = jobsRes.items;
    state.jobsTotal = Number(jobsRes.total || 0);
    state.jobsTotalPages = Number(jobsRes.total_pages || 1);
    state.scansPage = Number(jobsRes.page || state.scansPage || 1);
    state.scansPageSize = Number(jobsRes.page_size || state.scansPageSize || 20);
  } else {
    state.jobs = Array.isArray(jobsRes) ? jobsRes : [];
    state.jobsTotal = state.jobs.length;
    state.jobsTotalPages = Math.max(1, Math.ceil(state.jobs.length / (state.scansPageSize || 20)));
  }
  state.jobSummary = await api("/api/jobs/summary");
  const totalPages = Math.max(1, Number(state.jobsTotalPages || 1));
  if ((state.scansPage || 1) > totalPages) state.scansPage = totalPages;
  reconcileSelectedJobs();
  if (state.selectedJobId && !state.jobs.some(j => j.id === state.selectedJobId)) {
    clearSelectedJob();
  }
  renderScans();
  renderOverview();
}

async function loadSelectedJobFindings() {
  if (!state.selectedJobId) return;
  const params = new URLSearchParams();
  params.set("status", "open");
  params.set("page", String(state.scanDetailFindingsPage || 1));
  params.set("page_size", String(state.scanDetailFindingsPageSize || 25));
  const filters = state.scanDetailFindingsFilters || {};
  if (filters.kind) params.set("kind", filters.kind);
  if (filters.scanner) params.set("scanner", filters.scanner);
  if (filters.severity) params.set("severity", filters.severity);
  if (filters.title) params.set("title", filters.title);
  if (filters.path) params.set("path", filters.path);
  if (filters.q) params.set("q", filters.q);
  const res = await api(`/api/jobs/${state.selectedJobId}/findings?${params.toString()}`);
  if (res && Array.isArray(res.items)) {
    state.selectedJobFindings = res.items;
    state.selectedJobFindingsTotal = Number(res.total || 0);
    state.selectedJobFindingsTotalPages = Number(res.total_pages || 1);
    state.scanDetailFindingsPage = Number(res.page || state.scanDetailFindingsPage || 1);
    state.scanDetailFindingsPageSize = Number(res.page_size || state.scanDetailFindingsPageSize || 25);
    state.selectedJobFindingsFacets = res.facets || { kinds: [], scanners: [], severities: [] };
    state.selectedJobFindingsSeverityTotals = res.severity_totals || null;
  } else {
    state.selectedJobFindings = Array.isArray(res) ? res : [];
    state.selectedJobFindingsTotal = state.selectedJobFindings.length;
    state.selectedJobFindingsTotalPages = 1;
    state.selectedJobFindingsFacets = {
      kinds: [...new Set(state.selectedJobFindings.map(f => String(f.kind || "")).filter(Boolean))].sort(),
      scanners: [...new Set(state.selectedJobFindings.map(f => String(f.scanner || "")).filter(Boolean))].sort(),
      severities: [...new Set(state.selectedJobFindings.map(f => severityBucket(f.severity)).filter(Boolean))],
    };
    state.selectedJobFindingsSeverityTotals = null;
  }
}

async function loadSelectedJobRemediationRuns() {
  if (!state.selectedJobId) return;
  try {
    const page = Number(state.selectedJobRemediationRunsPage || 1);
    const pageSize = Number(state.selectedJobRemediationRunsPageSize || 10);
    const res = await api(`/api/jobs/${state.selectedJobId}/remediation?page=${page}&page_size=${pageSize}`);
    if (res && Array.isArray(res.items)) {
      state.selectedJobRemediationRuns = res.items;
      state.selectedJobRemediationRunsTotal = Number(res.total || 0);
      state.selectedJobRemediationRunsPage = Number(res.page || page);
      state.selectedJobRemediationRunsPageSize = Number(res.page_size || pageSize);
      state.selectedJobRemediationRunsTotalPages = Number(res.total_pages || 1);
    } else {
      state.selectedJobRemediationRuns = Array.isArray(res) ? res : [];
      state.selectedJobRemediationRunsTotal = state.selectedJobRemediationRuns.length;
      state.selectedJobRemediationRunsTotalPages = 1;
    }
  } catch (_) {
    state.selectedJobRemediationRuns = [];
    state.selectedJobRemediationRunsTotal = 0;
    state.selectedJobRemediationRunsTotalPages = 1;
  }
}

async function selectJob(id, opts = {}) {
  state.selectedJobId = id;
  if (!opts.preserveFindingsState) {
    state.scanDetailFindingsPage = 1;
    state.scanDetailFindingsFilters = { kind: "", scanner: "", severity: "", title: "", path: "", q: "" };
    state.scanDetailFindingsDraft = { title: "", path: "", q: "" };
  }
  if (!opts.preserveFixesState) {
    state.scanDetailFixesPage = 1;
    state.scanDetailFixesSearch = "";
    state.scanDetailFixesStatus = "";
  }
  if (!opts.preserveRemediationState) {
    state.selectedJobRemediationRunsPage = 1;
    state.scanDetailRemediationExpandedTaskIds = {};
  }
  state.selectedJob = await api(`/api/jobs/${id}`);
  state.selectedJobScanners = await api(`/api/jobs/${id}/scanners`);
  await loadSelectedJobFindings();
  state.selectedJobFixes = await api(`/api/jobs/${id}/fixes`);
  await loadSelectedJobRemediationRuns();
  renderScans();
  if (state.view === "scan-detail") renderScanDetailPage();
}

function clearSelectedJob() {
  state.selectedJobId = null;
  state.selectedJob = null;
  state.selectedJobScanners = [];
  state.selectedJobFindings = [];
  state.selectedJobFindingsTotal = 0;
  state.selectedJobFindingsTotalPages = 1;
  state.selectedJobFindingsFacets = { kinds: [], scanners: [], severities: [] };
  state.selectedJobFindingsSeverityTotals = null;
  state.selectedJobFixes = [];
  state.scanDetailFixesPage = 1;
  state.scanDetailFixesSearch = "";
  state.scanDetailFixesStatus = "";
  state.selectedJobRemediationRuns = [];
  state.selectedJobRemediationRunsTotal = 0;
  state.selectedJobRemediationRunsPage = 1;
  state.selectedJobRemediationRunsTotalPages = 1;
  state.scanDetailRemediationExpandedTaskIds = {};
  state.scanDetailFindingsPage = 1;
  state.scanDetailFindingsFilters = { kind: "", scanner: "", severity: "", title: "", path: "", q: "" };
  state.scanDetailFindingsDraft = { title: "", path: "", q: "" };
}

function reconcileSelectedJobs() {
  const visible = new Set((state.jobs || []).map(j => j.id));
  const next = {};
  for (const rawId of Object.keys(state.selectedScanJobIds || {})) {
    const id = Number(rawId);
    if (visible.has(id)) next[id] = true;
  }
  state.selectedScanJobIds = next;
}

async function deleteOneScanJob(id) {
  const job = (state.jobs || []).find(j => j.id === id);
  const label = job ? `${job.owner}/${job.repo}` : `#${id}`;
  if (!(await showConfirm({
    title: "Delete Scan Job",
    message: `Delete scan job #${id} (${label})? This removes stored findings and raw outputs for the job.`,
    confirmLabel: "Delete",
  }))) return;
  try {
    await api(`/api/jobs/${id}`, { method: "DELETE" });
    delete state.selectedScanJobIds[id];
    await refreshJobs();
  } catch (err) {
    showNotice("Delete Failed", err.message);
  }
}

async function deleteSelectedScanJobs() {
  const ids = Object.keys(state.selectedScanJobIds || {}).map(Number).filter(Boolean).sort((a, b) => a - b);
  if (ids.length === 0) return;
  if (!(await showConfirm({
    title: "Delete Selected Scan Jobs",
    message: `Delete ${ids.length} selected scan job${ids.length === 1 ? "" : "s"}? This cannot be undone.`,
    confirmLabel: "Delete Selected",
  }))) return;
  try {
    const res = await api("/api/jobs", {
      method: "DELETE",
      body: JSON.stringify({ ids }),
    });
    if (Array.isArray(res.deleted_ids)) {
      for (const id of res.deleted_ids) delete state.selectedScanJobIds[id];
    } else {
      state.selectedScanJobIds = {};
    }
    await refreshJobs();
    if (Array.isArray(res.not_found_ids) && res.not_found_ids.length > 0) {
      showNotice("Delete Completed", `Deleted ${res.deleted_count || 0} jobs. Not found: ${res.not_found_ids.join(", ")}.`);
    }
  } catch (err) {
    showNotice("Bulk Delete Failed", err.message);
  }
}

async function deleteAllScanJobs() {
  const count = (state.jobs || []).length;
  if (count === 0) return;
  const confirmation = await showPrompt({
    title: "Delete All Scan Jobs",
    message: `Delete ALL ${count} scan jobs and their stored findings/raw outputs? Type DELETE ALL to confirm.`,
    placeholder: "DELETE ALL",
    confirmLabel: "Delete All",
  });
  if (confirmation !== "DELETE ALL") return;
  try {
    await api("/api/jobs", {
      method: "DELETE",
      body: JSON.stringify({ delete_all: true }),
    });
    state.selectedScanJobIds = {};
    clearSelectedJob();
    await refreshJobs();
  } catch (err) {
    showNotice("Delete All Failed", err.message);
  }
}

async function openScanDetailPage(id, opts = {}) {
  await selectJob(id, { preserveFindingsState: false });
  setView("scan-detail", { pushHistory: opts.pushHistory !== false });
  renderScanDetailPage();
}

async function launchReviewCampaignForSelectedScan() {
  const job = state.selectedJob;
  if (!job) return;
  if (!state.agent?.ai_enabled) {
    showNotice("AI Not Enabled", "Configure an AI provider in Config before launching an AI review campaign.");
    return;
  }
  let res = null;
  try {
    res = await api("/api/remediation/campaigns", {
      method: "POST",
      body: JSON.stringify({
        name: `Scan #${job.id} Review · ${job.owner}/${job.repo}`,
        mode: state.agent?.mode || "triage",
        auto_pr: false,
        start_now: true,
        latest_only: false,
        scan_job_ids: [job.id],
        max_repos: 1,
      }),
    });
    showToast({
      title: "AI Review Campaign Started",
      message: `Campaign${res?.id ? ` #${res.id}` : ""} created for scan #${job.id}. Fix reviews will populate as triage runs.`,
      kind: "success",
      timeoutMs: 4200,
    });
  } catch (err) {
    showNotice("Launch Review Campaign Failed", err.message);
    return;
  }

  // The campaign has already been created at this point. Follow-up UI refreshes
  // should not cause a false "launch failed" modal.
  try {
    await Promise.all([refreshRemediation(), refreshAgentWorkers()]);
    if (state.selectedJobId === job.id) {
      setTimeout(async () => {
        try {
          await selectJob(job.id, { preserveFindingsState: true, preserveRemediationState: true });
        } catch (_) {}
      }, 1500);
    }
  } catch (err) {
    showToast({
      title: "Campaign Started (Refresh Issue)",
      message: `Review campaign${res?.id ? ` #${res.id}` : ""} started, but the UI failed to refresh automatically: ${err.message}`,
      kind: "warn",
      timeoutMs: 5200,
    });
  }
}

async function stopReviewCampaignForSelectedScan() {
  const job = state.selectedJob;
  if (!job || state.scanDetailAiStopBusy) return;
  state.scanDetailAiStopBusy = true;
  renderScanDetailPage();
  try {
    const res = await api(`/api/jobs/${job.id}/remediation/stop`, { method: "POST", body: "{}" });
    const n = Number(res?.stopped_count || 0);
    if (n > 0) {
      showToast({
        title: "AI Review Stopped",
        message: `Stopped ${n} remediation campaign${n === 1 ? "" : "s"} for scan #${job.id}.`,
        kind: "warn",
        timeoutMs: 3200,
      });
    } else {
      showNotice("Nothing To Stop", "No running remediation campaign was found for this scan.");
    }
    await Promise.all([refreshRemediation(), refreshAgentWorkers()]);
  } catch (err) {
    showNotice("Stop AI Review Failed", err.message);
  } finally {
    state.scanDetailAiStopBusy = false;
    if (state.view === "scan-detail") renderScanDetailPage();
  }
}

async function refreshCron() {
  state.schedules = await api("/api/schedules");
  renderCron();
}

async function refreshAgent() {
  state.agent = await api("/api/agent");
  renderAgents();
}

async function refreshAgentWorkers() {
  state.agentWorkers = await api("/api/agent/workers");
  renderAgents();
  if (state.view === "scans") renderScans();
  if (state.view === "scan-detail") renderScanDetailPage();
  if (state.view === "remediation") renderRemediation();
}

async function refreshPathIgnoreRules() {
  state.pathIgnoreRulesLoading = true;
  renderPathIgnoreModal();
  try {
    state.pathIgnoreRules = await api("/api/findings/path-ignores");
    if (!Array.isArray(state.pathIgnoreRules)) state.pathIgnoreRules = [];
  } catch (err) {
    showNotice("Path Ignore Rules Failed", err.message);
  } finally {
    state.pathIgnoreRulesLoading = false;
    renderPathIgnoreModal();
    if (state.view === "scan-detail") renderScanDetailPage();
  }
}

async function createPathIgnoreRule(payload) {
  try {
    await api("/api/findings/path-ignores", { method: "POST", body: JSON.stringify(payload || {}) });
    await refreshPathIgnoreRules();
    if (state.selectedJobId) {
      await loadSelectedJobFindings();
      renderScanDetailPage();
    }
    showToast({ title: "Path Ignore Added", message: "Findings were reloaded with the new ignore rule applied.", kind: "success", timeoutMs: 2600 });
  } catch (err) {
    showNotice("Add Ignore Rule Failed", err.message);
  }
}

async function updatePathIgnoreRule(id, payload) {
  try {
    await api(`/api/findings/path-ignores/${id}`, { method: "PUT", body: JSON.stringify(payload || {}) });
    await refreshPathIgnoreRules();
    if (state.selectedJobId) {
      await loadSelectedJobFindings();
      renderScanDetailPage();
    }
  } catch (err) {
    showNotice("Update Ignore Rule Failed", err.message);
  }
}

async function deletePathIgnoreRule(id) {
  try {
    await fetch(`/api/findings/path-ignores/${id}`, { method: "DELETE" });
    await refreshPathIgnoreRules();
    if (state.selectedJobId) {
      await loadSelectedJobFindings();
      renderScanDetailPage();
    }
    showToast({ title: "Path Ignore Deleted", message: "Findings were reloaded.", kind: "info", timeoutMs: 2200 });
  } catch (err) {
    showNotice("Delete Ignore Rule Failed", err.message);
  }
}

async function refreshRemediationTasks(campaignID) {
  if (!campaignID) {
    state.remediationCampaignTasks = [];
    renderRemediation();
    return;
  }
  state.remediationCampaignTasks = await api(`/api/remediation/campaigns/${campaignID}/tasks`);
  renderRemediation();
}

async function refreshRemediationRepoSuggestions(force = false) {
  if (state.remediationRepoSuggestionsLoading) return;
  if (!force && state.remediationRepoSuggestionsLoaded) return;
  state.remediationRepoSuggestionsLoading = true;
  try {
    const res = await api("/api/jobs/repos?page=1&page_size=500");
    state.remediationRepoSuggestions = Array.isArray(res?.items) ? res.items : [];
    state.remediationRepoSuggestionsLoaded = true;
  } catch (err) {
    // Non-fatal for the page; user can still type manually later if we add support.
    showNotice("Repo Suggestions Failed", err.message);
  } finally {
    state.remediationRepoSuggestionsLoading = false;
    if (state.view === "remediation") renderRemediation();
  }
}

async function refreshRemediation() {
  state.remediationCampaigns = await api("/api/remediation/campaigns");
  const ids = new Set((state.remediationCampaigns || []).map(c => c.id));
  if (state.remediationSelectedCampaignId && !ids.has(state.remediationSelectedCampaignId)) {
    state.remediationSelectedCampaignId = null;
  }
  if (!state.remediationSelectedCampaignId && state.remediationCampaigns.length > 0) {
    state.remediationSelectedCampaignId = state.remediationCampaigns[0].id;
  }
  if (state.remediationSelectedCampaignId) {
    state.remediationCampaignTasks = await api(`/api/remediation/campaigns/${state.remediationSelectedCampaignId}/tasks`);
  } else {
    state.remediationCampaignTasks = [];
  }
  if (!state.remediationRepoSuggestionsLoaded) {
    refreshRemediationRepoSuggestions();
  }
  renderRemediation();
}

async function createRemediationCampaign() {
  const draft = state.remediationDraft || {};
  const name = String(draft.name || "").trim();
  const mode = draft.mode || "triage";
  const maxReposRaw = String(draft.maxRepos ?? "").trim();
  const autoPR = !!draft.autoPR;
  const startNow = draft.startNow !== false;

  let maxRepos = 0;
  if (maxReposRaw !== "") {
    maxRepos = Number(maxReposRaw);
    if (!Number.isFinite(maxRepos) || maxRepos < 0) {
      showNotice("Invalid Max Repos", "Max repos must be a non-negative number.");
      return;
    }
  }
  const repos = [...new Set((draft.selectedRepos || []).map(s => String(s || "").trim()).filter(Boolean))];
  const badRepo = repos.find(r => !/^[^/\s]+\/[^/\s]+$/.test(r));
  if (badRepo) {
    showNotice("Invalid Repo List", `Expected owner/repo format. Invalid entry: ${badRepo}`);
    return;
  }

  try {
    const res = await api("/api/remediation/campaigns", {
      method: "POST",
      body: JSON.stringify({
        name,
        mode,
        max_repos: maxRepos,
        repos,
        auto_pr: autoPR,
        start_now: startNow,
        latest_only: true,
      }),
    });
    if (res && res.id) state.remediationSelectedCampaignId = Number(res.id);
    showToast({
      title: startNow ? "Campaign Started" : "Campaign Created",
      message: startNow ? "Offline remediation campaign is running." : "Campaign created in draft state.",
      kind: "success",
      timeoutMs: 3000,
    });
    await refreshRemediation();
    await refreshAgentWorkers();
  } catch (err) {
    showNotice("Create Campaign Failed", err.message);
  }
}

async function startRemediationCampaign(id) {
  try {
    await api(`/api/remediation/campaigns/${id}/start`, { method: "POST", body: "{}" });
    showToast({ title: "Campaign Started", message: `Campaign #${id} is now running.`, kind: "success", timeoutMs: 2800 });
    state.remediationSelectedCampaignId = id;
    await refreshRemediation();
    await refreshAgentWorkers();
  } catch (err) {
    showNotice("Start Campaign Failed", err.message);
  }
}

async function stopRemediationCampaign(id) {
  try {
    await api(`/api/remediation/campaigns/${id}/stop`, { method: "POST", body: "{}" });
    showToast({ title: "Campaign Stopped", message: `Campaign #${id} was stopped.`, kind: "warn", timeoutMs: 2800 });
    await refreshRemediation();
    await refreshAgentWorkers();
  } catch (err) {
    showNotice("Stop Campaign Failed", err.message);
  }
}

async function refreshConfig() {
  const payload = await api("/api/config");
  state.configPath = payload.path || "";
  state.config = payload.config || {};
  renderConfig();
}

async function refreshAll() {
  try {
    await Promise.all([refreshStatus(), refreshJobs(), refreshCron(), refreshAgent(), refreshAgentWorkers(), refreshRemediation()]);
    if (state.selectedJobId) {
      await selectJob(state.selectedJobId, { preserveFindingsState: true, preserveRemediationState: true });
    }
    if (state.view === "config") {
      await refreshConfig();
    } else {
      renderConfig();
    }
  } catch (err) {
    pushEvent({ type: "ui.error", payload: { error: err.message } });
  }
  renderOverview();
  renderScans();
  renderScanDetailPage();
  renderCron();
  renderAgents();
  renderEvents();
}

function connectEvents() {
  if (state.es) state.es.close();
  const es = new EventSource("/events");
  es.onmessage = (e) => {
    try {
      const evt = JSON.parse(e.data);
      pushEvent(evt);
    } catch (_) {}
  };
  es.onerror = () => {
    pushEvent({ type: "events.error", payload: { message: "SSE disconnected; retrying..." } });
  };
  state.es = es;
}

function wireGlobalButtons() {
  document.getElementById("refreshBtn").addEventListener("click", refreshAll);
  document.getElementById("triggerBtn").addEventListener("click", openTriggerModal);
  document.getElementById("stopBtn").addEventListener("click", stopSweep);
  syncStopButtons();
  window.addEventListener("popstate", () => {
    applyRouteFromLocation();
  });
}

function scheduleLiveRefresh(opts = {}) {
  state.liveRefreshPending.jobs = state.liveRefreshPending.jobs || !!opts.jobs;
  state.liveRefreshPending.detail = state.liveRefreshPending.detail || !!opts.detail;
  state.liveRefreshPending.workers = state.liveRefreshPending.workers || !!opts.workers;
  state.liveRefreshPending.remediation = state.liveRefreshPending.remediation || !!opts.remediation;
  if (state.liveRefreshTimer) return;
  state.liveRefreshTimer = setTimeout(async () => {
    state.liveRefreshTimer = null;
    const pending = { ...(state.liveRefreshPending || {}) };
    state.liveRefreshPending = { jobs: false, detail: false, workers: false, remediation: false };
    try {
      const tasks = [];
      if (pending.jobs) tasks.push(refreshJobs());
      if (pending.workers) tasks.push(refreshAgentWorkers());
      if (pending.remediation || state.view === "remediation") tasks.push(refreshRemediation());
      if (tasks.length > 0) await Promise.all(tasks);
      if (pending.detail && state.selectedJobId) {
        await selectJob(state.selectedJobId, { preserveFindingsState: true, preserveRemediationState: true });
      }
    } catch (_) {
      // best-effort live refresh; status stream continues even if this fails
    }
  }, 600);
}

async function handleFixAction(id, action) {
  try {
    let path = "";
    if (action === "approve") path = `/api/fix-queue/${id}/approve`;
    if (action === "approve-run") path = `/api/fix-queue/${id}/approve-and-run`;
    if (action === "reject") path = `/api/fix-queue/${id}/reject`;
    if (!path) return;
    await api(path, { method: "POST", body: "{}" });
    if (state.selectedJobId) {
      await selectJob(state.selectedJobId, { preserveFindingsState: true, preserveRemediationState: true });
    } else {
      await refreshJobs();
    }
    if (action === "approve-run") {
      showNotice("PR Processing Started", "The fix was approved and PR processing has been triggered. Refresh or wait for SSE updates to see PR status.");
    }
  } catch (err) {
    showNotice("Fix Action Failed", err.message);
  }
}

function syncStopButtons() {
  const ids = ["stopBtn", "ovStop", "agentsStop"];
  for (const id of ids) {
    const el = document.getElementById(id);
    if (!el) continue;
    el.disabled = !!state.stopBusy;
    el.classList.toggle("is-loading", !!state.stopBusy);
    if (id === "stopBtn") {
      el.textContent = state.stopBusy ? "Stopping" : "Stop Scan";
    } else {
      el.textContent = state.stopBusy ? "Stopping" : "Stop Sweep";
    }
  }
}

function showNotice(title, message) {
  document.getElementById("noticeModalTitle").textContent = title || "Notice";
  document.getElementById("noticeModalBody").textContent = message || "";
  document.getElementById("noticeModal").classList.remove("hidden");
}

function hideNotice() {
  document.getElementById("noticeModal").classList.add("hidden");
}

function wireNoticeModal() {
  document.getElementById("noticeModalOk").addEventListener("click", hideNotice);
  document.getElementById("noticeModal").addEventListener("click", (e) => {
    if (e.target.id === "noticeModal") hideNotice();
  });
}

let confirmModalResolve = null;
let promptModalResolve = null;

function hideConfirmModal(result) {
  document.getElementById("confirmModal").classList.add("hidden");
  if (confirmModalResolve) {
    const resolve = confirmModalResolve;
    confirmModalResolve = null;
    resolve(!!result);
  }
}

function showConfirm({ title, message, confirmLabel = "OK", danger = true } = {}) {
  document.getElementById("confirmModalTitle").textContent = title || "Confirm";
  document.getElementById("confirmModalBody").textContent = message || "Are you sure?";
  const okBtn = document.getElementById("confirmModalOk");
  okBtn.textContent = confirmLabel;
  okBtn.className = danger ? "btn btn-danger" : "btn btn-primary";
  document.getElementById("confirmModal").classList.remove("hidden");
  return new Promise((resolve) => {
    confirmModalResolve = resolve;
  });
}

function wireConfirmModal() {
  document.getElementById("confirmModalCancel").addEventListener("click", () => hideConfirmModal(false));
  document.getElementById("confirmModalOk").addEventListener("click", () => hideConfirmModal(true));
  document.getElementById("confirmModal").addEventListener("click", (e) => {
    if (e.target.id === "confirmModal") hideConfirmModal(false);
  });
}

function hidePromptModal(result) {
  document.getElementById("promptModal").classList.add("hidden");
  const input = document.getElementById("promptModalInput");
  if (promptModalResolve) {
    const resolve = promptModalResolve;
    promptModalResolve = null;
    resolve(result === null ? null : String(result ?? ""));
  }
  input.value = "";
}

function showPrompt({ title, message, placeholder = "", confirmLabel = "Confirm" } = {}) {
  document.getElementById("promptModalTitle").textContent = title || "Confirm Action";
  document.getElementById("promptModalBody").textContent = message || "";
  const input = document.getElementById("promptModalInput");
  input.value = "";
  input.placeholder = placeholder;
  document.getElementById("promptModalOk").textContent = confirmLabel;
  document.getElementById("promptModal").classList.remove("hidden");
  setTimeout(() => input.focus(), 0);
  return new Promise((resolve) => {
    promptModalResolve = resolve;
  });
}

function wirePromptModal() {
  const input = document.getElementById("promptModalInput");
  document.getElementById("promptModalCancel").addEventListener("click", () => hidePromptModal(null));
  document.getElementById("promptModalOk").addEventListener("click", () => hidePromptModal(input.value));
  document.getElementById("promptModal").addEventListener("click", (e) => {
    if (e.target.id === "promptModal") hidePromptModal(null);
  });
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      hidePromptModal(input.value);
    }
    if (e.key === "Escape") {
      e.preventDefault();
      hidePromptModal(null);
    }
  });
}

function detectPathIgnoreSuggestions() {
  const suggestions = [];
  const seen = new Set();
  const paths = (state.selectedJobFindings || []).map(f => String(f.file_path || f.package || "")).filter(Boolean);
  const common = ["vendor/", "test/", "/testdata/", "node_modules/", ".git/"];
  for (const sub of common) {
    if (paths.some(p => p.toLowerCase().includes(sub.toLowerCase()))) {
      if (!seen.has(sub)) {
        seen.add(sub);
        suggestions.push(sub);
      }
    }
  }
  return suggestions;
}

function renderPathIgnoreModal() {
  const body = document.getElementById("pathIgnoreRulesBody");
  const bar = document.getElementById("pathIgnoreSuggestionBar");
  if (!body || !bar) return;
  const rules = state.pathIgnoreRules || [];
  setHtml(body, state.pathIgnoreRulesLoading
    ? `<tr><td colspan="5" class="muted">Loading rules…</td></tr>`
    : (rules.map((r) => `<tr>
        <td><input type="checkbox" data-path-ignore-toggle="${r.id}" ${r.enabled ? "checked" : ""}></td>
        <td><input data-path-ignore-substring="${r.id}" value="${escapeHtml(r.substring || "")}" /></td>
        <td><input data-path-ignore-note="${r.id}" value="${escapeHtml(r.note || "")}" /></td>
        <td class="muted">${escapeHtml(fmtDate(r.updated_at))}</td>
        <td class="row-actions">
          <button class="btn btn-secondary" data-path-ignore-save="${r.id}">Save</button>
          <button class="btn btn-danger" data-path-ignore-delete="${r.id}">Delete</button>
        </td>
      </tr>`).join("") || `<tr><td colspan="5" class="muted">No path ignore rules configured.</td></tr>`));

  const existingSubs = new Set(rules.map(r => String(r.substring || "").toLowerCase()));
  const suggestions = detectPathIgnoreSuggestions().filter(s => !existingSubs.has(String(s).toLowerCase()));
  setHtml(bar, suggestions.length
    ? suggestions.map(s => `<button class="btn btn-secondary" data-path-ignore-suggest="${escapeHtml(s)}">Suggest: ${escapeHtml(s)}</button>`).join("")
    : `<span class="muted">Suggestions appear when current findings include common noisy paths (e.g. vendor/, test/).</span>`);

  body.querySelectorAll("[data-path-ignore-toggle]").forEach((el) => {
    el.addEventListener("change", async () => {
      const id = Number(el.dataset.pathIgnoreToggle);
      const row = state.pathIgnoreRules.find(r => r.id === id);
      if (!row) return;
      await updatePathIgnoreRule(id, { substring: row.substring, note: row.note || "", enabled: !!el.checked });
    });
  });
  body.querySelectorAll("[data-path-ignore-save]").forEach((btn) => btn.addEventListener("click", async () => {
    const id = Number(btn.dataset.pathIgnoreSave);
    const sub = body.querySelector(`[data-path-ignore-substring="${id}"]`)?.value || "";
    const note = body.querySelector(`[data-path-ignore-note="${id}"]`)?.value || "";
    const enabled = !!body.querySelector(`[data-path-ignore-toggle="${id}"]`)?.checked;
    await updatePathIgnoreRule(id, { substring: sub, note, enabled });
  }));
  body.querySelectorAll("[data-path-ignore-delete]").forEach((btn) => btn.addEventListener("click", async () => {
    const id = Number(btn.dataset.pathIgnoreDelete);
    const row = state.pathIgnoreRules.find(r => r.id === id);
    if (!(await showConfirm({ title: "Delete Path Ignore Rule", message: `Delete ignore rule "${row?.substring || `#${id}`}"?`, confirmLabel: "Delete" }))) return;
    await deletePathIgnoreRule(id);
  }));
  bar.querySelectorAll("[data-path-ignore-suggest]").forEach((btn) => btn.addEventListener("click", () => {
    const sub = btn.dataset.pathIgnoreSuggest || "";
    document.getElementById("pathIgnoreNewSubstring").value = sub;
  }));
}

function openPathIgnoreModal() {
  document.getElementById("pathIgnoreModal").classList.remove("hidden");
  renderPathIgnoreModal();
  refreshPathIgnoreRules();
}

function closePathIgnoreModal() {
  document.getElementById("pathIgnoreModal").classList.add("hidden");
}

function wirePathIgnoreModal() {
  document.getElementById("pathIgnoreModalClose")?.addEventListener("click", closePathIgnoreModal);
  document.getElementById("pathIgnoreModalDone")?.addEventListener("click", closePathIgnoreModal);
  document.getElementById("pathIgnoreModal")?.addEventListener("click", (e) => {
    if (e.target.id === "pathIgnoreModal") closePathIgnoreModal();
  });
  document.getElementById("pathIgnoreAddBtn")?.addEventListener("click", async () => {
    const subEl = document.getElementById("pathIgnoreNewSubstring");
    const noteEl = document.getElementById("pathIgnoreNewNote");
    const substring = subEl?.value || "";
    const note = noteEl?.value || "";
    await createPathIgnoreRule({ substring, note, enabled: true });
    if (subEl) subEl.value = "";
    if (noteEl) noteEl.value = "";
  });
}

function getDefaultTriggerTargets() {
  const current = state.agent?.targets;
  if (Array.isArray(current) && current.length > 0) return [...current];
  return ["own_repos"];
}

function renderTriggerChecklist() {
  const root = document.getElementById("targetChecklist");
  const supported = state.agent?.supported_targets || ["own_repos", "watchlist", "cve_search", "all_accessible"];
  setHtml(root, supported.map((t) => {
    const meta = targetMeta[t] || { label: t, desc: "" };
    const checked = state.triggerPlan.targets.includes(t) ? "checked" : "";
    return `<div class="check-item">
      <label>
        <input type="checkbox" data-target="${t}" ${checked}>
        <span class="label-stack">
          <span>${escapeHtml(meta.label)}</span>
          <small>${escapeHtml(meta.desc)}</small>
        </span>
      </label>
    </div>`;
  }).join(""));
  root.querySelectorAll("input[type='checkbox'][data-target]").forEach((cb) => {
    cb.addEventListener("change", () => {
      const t = cb.dataset.target;
      if (cb.checked) {
        if (!state.triggerPlan.targets.includes(t)) state.triggerPlan.targets.push(t);
      } else {
        state.triggerPlan.targets = state.triggerPlan.targets.filter(x => x !== t);
      }
      if (state.triggerPlan.targets.length === 0) {
        state.triggerPlan.selectedRepoMap = {};
      }
      fetchTriggerPreview();
    });
  });
}

function renderTriggerPreview() {
  const root = document.getElementById("triggerPreviewBody");
  if (!root) return;
  if (state.triggerPreview.loading) {
    setHtml(root, `<div class="muted">Loading preview…</div>`);
    return;
  }
  if (state.triggerPlan.targets.length === 0) {
    setHtml(root, `<div class="muted">No targets selected. Select one or more targets to preview and choose repositories.</div>`);
    return;
  }
  if (state.triggerPreview.error) {
    setHtml(root, `<div class="preview-errors">${escapeHtml(state.triggerPreview.error)}</div>`);
    return;
  }
  const data = state.triggerPreview.data;
  if (!data || !Array.isArray(data.targets)) {
    setHtml(root, `<div class="muted">Preview unavailable.</div>`);
    return;
  }
  const previewRepos = getPreviewSampleRepos();
  const selectedCount = getSelectedPreviewRepos().length;
  const sectionsHtml = data.targets.map((t) => `
    <div class="preview-section">
      <h4>${escapeHtml((targetMeta[t.target]?.label) || t.target)}</h4>
      <div class="preview-meta">${t.repo_count || 0} repositories visible${(t.samples && t.samples.length < (t.repo_count || 0)) ? ` (showing ${t.samples.length})` : ""}</div>
      <div class="preview-list">
        ${(t.samples || []).slice(0, 12).map((r) => `
          <label class="preview-item preview-item-selectable">
            <div class="preview-item-row">
              <input type="checkbox" data-preview-repo="${escapeHtml(repoSelectionKey(r))}" ${state.triggerPlan.selectedRepoMap[repoSelectionKey(r)] ? "checked" : ""}>
              <div class="title">${escapeHtml(r.full_name)}</div>
            </div>
            <div class="sub">${escapeHtml(r.provider)} • ${escapeHtml(r.host || "")}${r.language ? ` • ${escapeHtml(r.language)}` : ""}${(r.stars ?? 0) > 0 ? ` • ★ ${r.stars}` : ""}${r.private ? ` • private` : ""}</div>
          </label>
        `).join("") || `<div class="muted">No repositories matched this target.</div>`}
      </div>
      ${(t.errors && t.errors.length) ? `<div class="preview-errors">${escapeHtml(t.errors.join(" | "))}</div>` : ""}
    </div>
  `).join("");
  const toolbarHtml = `
    <div class="toolbar preview-toolbar">
      <button id="previewReposSelectAll" class="btn btn-secondary" ${previewRepos.length === 0 ? "disabled" : ""}>Select All Shown</button>
      <button id="previewReposSelectNone" class="btn btn-secondary" ${selectedCount === 0 ? "disabled" : ""}>Select None</button>
      <span class="muted">${selectedCount} repo${selectedCount === 1 ? "" : "s"} selected${previewRepos.length ? ` (from ${previewRepos.length} shown)` : ""}. If any are selected, this trigger scans only those repos.</span>
    </div>
  `;
  setHtml(root, toolbarHtml + sectionsHtml);
  root.querySelectorAll("input[type='checkbox'][data-preview-repo]").forEach((cb) => {
    cb.addEventListener("change", () => {
      const key = cb.dataset.previewRepo;
      const repo = previewRepos.find((r) => repoSelectionKey(r) === key);
      if (!repo) return;
      if (cb.checked) {
        state.triggerPlan.selectedRepoMap[key] = {
          provider: repo.provider || "",
          host: repo.host || "",
          owner: repo.owner || "",
          name: repo.name || "",
        };
      } else {
        delete state.triggerPlan.selectedRepoMap[key];
      }
      renderTriggerPreview();
    });
  });
  root.querySelector("#previewReposSelectAll")?.addEventListener("click", () => {
    for (const repo of previewRepos) {
      state.triggerPlan.selectedRepoMap[repoSelectionKey(repo)] = {
        provider: repo.provider || "",
        host: repo.host || "",
        owner: repo.owner || "",
        name: repo.name || "",
      };
    }
    renderTriggerPreview();
  });
  root.querySelector("#previewReposSelectNone")?.addEventListener("click", () => {
    state.triggerPlan.selectedRepoMap = {};
    renderTriggerPreview();
  });
}

async function fetchTriggerPreview() {
  renderTriggerPreview();
  if (state.triggerPlan.targets.length === 0) return;
  state.triggerPreview.loading = true;
  state.triggerPreview.error = "";
  renderTriggerPreview();
  try {
    state.triggerPreview.data = await api("/api/agent/preview", {
      method: "POST",
      body: JSON.stringify({ scan_targets: state.triggerPlan.targets, limit: 10 }),
    });
    reconcileSelectedPreviewRepos();
  } catch (err) {
    state.triggerPreview.error = err.message || String(err);
  } finally {
    state.triggerPreview.loading = false;
    renderTriggerPreview();
  }
}

function openTriggerModal() {
  state.triggerPlan.targets = getDefaultTriggerTargets();
  state.triggerPlan.workers = "";
  state.triggerPlan.selectedRepoMap = {};
  state.triggerPreview = { loading: false, data: null, error: "" };
  document.getElementById("triggerWorkers").value = "";
  renderTriggerChecklist();
  renderTriggerPreview();
  document.getElementById("triggerModal").classList.remove("hidden");
  fetchTriggerPreview();
}

function closeTriggerModal() {
  document.getElementById("triggerModal").classList.add("hidden");
}

function wireTriggerModal() {
  document.getElementById("triggerModalClose").addEventListener("click", closeTriggerModal);
  document.getElementById("triggerModalCancel").addEventListener("click", closeTriggerModal);
  document.getElementById("targetsSelectAll").addEventListener("click", () => {
    state.triggerPlan.targets = [...(state.agent?.supported_targets || Object.keys(targetMeta))];
    renderTriggerChecklist();
    fetchTriggerPreview();
  });
  document.getElementById("targetsSelectNone").addEventListener("click", () => {
    state.triggerPlan.targets = [];
    state.triggerPlan.selectedRepoMap = {};
    renderTriggerChecklist();
    renderTriggerPreview();
  });
  document.getElementById("triggerModalSubmit").addEventListener("click", async () => {
    const workersRaw = document.getElementById("triggerWorkers").value.trim();
    const selectedRepos = getSelectedPreviewRepos();
    if (state.triggerPlan.targets.length === 0 && selectedRepos.length === 0) {
      showNotice("Nothing Selected", "Select at least one scan target or choose one or more preview repos.");
      return;
    }
    if (workersRaw !== "") {
      const n = Number(workersRaw);
      if (!Number.isFinite(n) || n < 1 || n > 64) {
        showNotice("Invalid Workers", "Workers must be between 1 and 64.");
        return;
      }
    }
    await triggerSweepWithOptions({
      scanTargets: state.triggerPlan.targets,
      workers: workersRaw === "" ? 0 : Number(workersRaw),
      selectedRepos,
    });
  });
  document.getElementById("triggerModal").addEventListener("click", (e) => {
    if (e.target.id === "triggerModal") closeTriggerModal();
  });
}

async function bootstrap() {
  renderNav();
  wireGlobalButtons();
  wireNoticeModal();
  wireConfirmModal();
  wirePromptModal();
  wirePathIgnoreModal();
  wireTriggerModal();
  // Initialize view without rewriting the current URL; route parsing below
  // will choose the correct view and preserve deep links on browser refresh.
  setView("overview");
  connectEvents();
  await refreshAll();
  await applyRouteFromLocation();
  setInterval(() => {
    if (document.visibilityState === "hidden") return;
    scheduleLiveRefresh();
  }, 5000);
}

bootstrap();
