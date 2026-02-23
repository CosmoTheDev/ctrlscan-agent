const state = {
  view: "overview",
  status: null,
  jobs: [],
  selectedScanJobIds: {},
  jobSummary: null,
  selectedJobId: null,
  selectedJob: null,
  selectedJobScanners: [],
  selectedJobFindings: [],
  selectedJobFixes: [],
  schedules: [],
  agent: null,
  config: null,
  configPath: "",
  events: [],
  es: null,
  liveRefreshTimer: null,
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
  stopBusy: false,
};

const views = [
  { id: "overview", title: "Overview", subtitle: "Gateway status, agent controls, and scan posture." },
  { id: "scans", title: "Scans", subtitle: "Runs, scanner results, findings, and raw downloads." },
  { id: "scan-detail", title: "Scan Detail", subtitle: "Expanded scan view with per-scanner output and findings.", hidden: true },
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

function escapeHtml(v) {
  return String(v ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
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

function statusClass(v) {
  const s = String(v || "").toLowerCase();
  if (s.includes("complete")) return "status-completed";
  if (s.includes("run")) return "status-running";
  if (s.includes("stop")) return "status-stopped";
  if (s.includes("fail")) return "status-failed";
  if (s.includes("partial")) return "status-partial";
  return "";
}

function setView(id) {
  state.view = id;
  for (const v of views) {
    document.getElementById(`view-${v.id}`).classList.toggle("active", v.id === id);
  }
  const meta = views.find(v => v.id === id);
  document.getElementById("pageTitle").textContent = meta.title;
  document.getElementById("pageSubtitle").textContent = meta.subtitle;
  renderNav();
}

function renderNav() {
  const nav = document.getElementById("nav");
  nav.innerHTML = views.filter(v => !v.hidden).map(v => `<button data-view="${v.id}" class="${state.view === v.id ? "active" : ""}">${escapeHtml(v.title)}</button>`).join("");
  nav.querySelectorAll("button").forEach(btn => btn.addEventListener("click", () => setView(btn.dataset.view)));
}

function pushEvent(evt) {
  state.events.unshift({ at: new Date().toISOString(), ...evt });
  if (state.events.length > 200) state.events.length = 200;
  if (evt.type === "status.update" || evt.type === "connected") {
    state.status = evt.payload || state.status;
    renderOverview();
    renderAgents();
    renderHealthPill();
    scheduleLiveRefresh();
  }
  if (["agent.triggered", "agent.stop_requested", "schedule.fired", "schedule.triggered", "fix.approved", "fix.rejected"].includes(evt.type)) {
    scheduleLiveRefresh();
  }
  renderEvents();
}

function renderHealthPill() {
  const pill = document.getElementById("healthPill");
  const st = state.status;
  if (!st) {
    pill.textContent = "Health: unknown";
    return;
  }
  const health = st.running ? (st.paused ? "paused" : "ok") : "idle";
  pill.textContent = `Health: ${health} • workers ${st.workers ?? "?"}`;
}

function renderOverview() {
  const root = document.getElementById("view-overview");
  const st = state.status || {};
  const sum = state.jobSummary || {};
  const last = state.jobs[0];
  root.innerHTML = `
    <div class="grid cols-4">
      <div class="card"><div class="metric-label">Agent</div><div class="metric-value ${st.paused ? "warn" : "ok"}">${st.paused ? "Paused" : (st.running ? "Ready" : "Idle")}</div></div>
      <div class="card"><div class="metric-label">Queued Repos</div><div class="metric-value">${st.queued_repos ?? 0}</div></div>
      <div class="card"><div class="metric-label">Active Jobs</div><div class="metric-value">${st.active_jobs ?? 0}</div></div>
      <div class="card"><div class="metric-label">Pending Fixes</div><div class="metric-value">${st.pending_fixes ?? 0}</div></div>
    </div>
    <div class="grid cols-4" style="margin-top:14px">
      <div class="card"><div class="metric-label">High (Aggregate)</div><div class="metric-value">${sum.high ?? 0}</div></div>
      <div class="card"><div class="metric-label">Medium (Aggregate)</div><div class="metric-value">${sum.medium ?? 0}</div></div>
      <div class="card"><div class="metric-label">Low (Aggregate)</div><div class="metric-value">${sum.low ?? 0}</div></div>
      <div class="card"><div class="metric-label">Critical (Aggregate)</div><div class="metric-value">${sum.critical ?? 0}</div></div>
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
  `;
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
  const selectedIds = state.selectedScanJobIds || {};
  const selectedCount = rows.filter(j => selectedIds[j.id]).length;
  const allVisibleSelected = rows.length > 0 && selectedCount === rows.length;
  const selectedJob = state.selectedJob;
  const scanners = state.selectedJobScanners || [];
  const findings = state.selectedJobFindings || [];
  root.innerHTML = `
    <div class="split">
      <div class="card">
        <div class="toolbar">
          <button id="scansRefresh" class="btn btn-secondary">Refresh Jobs</button>
          <button id="scansDeleteSelected" class="btn btn-danger" ${selectedCount === 0 ? "disabled" : ""}>Delete Selected (${selectedCount})</button>
          <button id="scansDeleteAll" class="btn btn-danger" ${rows.length === 0 ? "disabled" : ""}>Delete All</button>
          <span class="muted">Click a job to inspect details. Use checkboxes for bulk delete.</span>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th style="width:34px"><input type="checkbox" id="scanSelectAll" ${allVisibleSelected ? "checked" : ""} ${rows.length === 0 ? "disabled" : ""}></th>
                <th>ID</th><th>Repo</th><th>Status</th><th>Started</th><th>C/H/M/L</th><th>Actions</th>
              </tr>
            </thead>
            <tbody>
              ${rows.map(j => `
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
            <div class="table-wrap" style="max-height:270px">
              <table>
                <thead><tr><th>Kind</th><th>Scanner</th><th>Severity</th><th>Title</th><th>Path/Package</th><th>Line</th><th>Detail</th></tr></thead>
                <tbody>
                ${findings.map(f => `<tr>
                  <td>${escapeHtml(f.kind)}</td>
                  <td>${escapeHtml(f.scanner || "")}</td>
                  <td>${escapeHtml(f.severity)}</td>
                  <td>${escapeHtml(f.title)}</td>
                  <td>${escapeHtml(f.file_path || f.package || "")}${f.version ? ` <span class="muted">@${escapeHtml(f.version)}</span>` : ""}</td>
                  <td>${f.line || ""}</td>
                  <td class="muted">${escapeHtml(f.fix ? `Fix: ${f.fix}` : (f.message || ""))}</td>
                </tr>`).join("") || `<tr><td colspan="7" class="muted">No findings available for this job yet. For new scans, details are parsed from raw scanner output when normalized DB rows are absent.</td></tr>`}
                </tbody>
              </table>
            </div>
          </div>
        ` : `<div class="muted">Select a scan job to inspect details.</div>`}
      </div>
    </div>
  `;
  root.querySelector("#scansRefresh")?.addEventListener("click", refreshJobs);
  root.querySelector("#scansDeleteSelected")?.addEventListener("click", deleteSelectedScanJobs);
  root.querySelector("#scansDeleteAll")?.addEventListener("click", deleteAllScanJobs);
  root.querySelector("#scanSelectAll")?.addEventListener("change", (e) => {
    for (const row of rows) {
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

function renderScanDetailPage() {
  const root = document.getElementById("view-scan-detail");
  const selectedJob = state.selectedJob;
  const scanners = state.selectedJobScanners || [];
  const findings = state.selectedJobFindings || [];
  const fixes = state.selectedJobFixes || [];
  const aiEnabled = !!state.agent?.ai_enabled;
  const mode = state.agent?.mode || "triage";
  if (!selectedJob) {
    root.innerHTML = `<div class="card"><div class="muted">No scan selected. Open a job from the Scans page.</div></div>`;
    return;
  }
  root.innerHTML = `
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
        <div class="card"><div class="metric-label">Critical</div><div class="metric-value">${selectedJob.findings_critical ?? 0}</div></div>
        <div class="card"><div class="metric-label">High</div><div class="metric-value">${selectedJob.findings_high ?? 0}</div></div>
        <div class="card"><div class="metric-label">Medium</div><div class="metric-value">${selectedJob.findings_medium ?? 0}</div></div>
        <div class="card"><div class="metric-label">Low</div><div class="metric-value">${selectedJob.findings_low ?? 0}</div></div>
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
        <h3>Findings</h3>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Kind</th><th>Scanner</th><th>Severity</th><th>Title</th><th>Path</th><th>Line</th><th>Detail</th></tr></thead>
            <tbody>
              ${findings.map(f => `<tr>
                <td>${escapeHtml(f.kind)}</td>
                <td>${escapeHtml(f.scanner || "")}</td>
                <td>${escapeHtml(f.severity)}</td>
                <td>${escapeHtml(f.title)}</td>
                <td>${escapeHtml(f.file_path || f.package || "")}</td>
                <td>${f.line || ""}</td>
                <td class="muted">${escapeHtml(f.fix ? `Fix: ${f.fix}` : (f.message || ""))}</td>
              </tr>`).join("") || `<tr><td colspan="7" class="muted">No findings available.</td></tr>`}
            </tbody>
          </table>
        </div>
        <div class="footer-note">Use raw downloads for exact scanner payloads. Paths are normalized to repo-relative paths when possible.</div>
      </div>
      <div class="card">
        <h3>AI Triage / Fix Review</h3>
        ${!aiEnabled ? `
          <div class="muted">AI provider is not configured. Add an OpenAI key (or another provider) in Config to enable triage, patches, and PR actions.</div>
        ` : `
          <div class="footer-note">Mode: ${escapeHtml(mode)}. In triage mode, use "Approve + Create PR" for one-click PR creation.</div>
          <div class="table-wrap" style="margin-top:10px">
            <table>
              <thead><tr><th>ID</th><th>Type</th><th>Status</th><th>PR Title</th><th>PR</th><th>Actions</th></tr></thead>
              <tbody>
                ${fixes.map(f => `<tr>
                  <td>#${f.id}</td>
                  <td>${escapeHtml(f.finding_type)}</td>
                  <td><span class="${statusClass(f.status)}">${escapeHtml(f.status)}</span></td>
                  <td>${escapeHtml(f.pr_title || "")}</td>
                  <td>${f.pr_url ? `<a class="link" target="_blank" rel="noreferrer" href="${escapeHtml(f.pr_url)}">Open PR</a>` : `<span class="muted">n/a</span>`}</td>
                  <td class="row-actions">
                    ${f.status === "pending" ? `
                      <button class="btn btn-secondary" data-fix-action="approve" data-fix-id="${f.id}">Approve</button>
                      <button class="btn btn-primary" data-fix-action="approve-run" data-fix-id="${f.id}">Approve + Create PR</button>
                      <button class="btn btn-danger" data-fix-action="reject" data-fix-id="${f.id}">Reject</button>
                    ` : `<span class="muted">-</span>`}
                  </td>
                </tr>`).join("") || `<tr><td colspan="6" class="muted">No AI-generated fixes queued for this scan yet.</td></tr>`}
              </tbody>
            </table>
          </div>
        `}
      </div>
    </div>
  `;
  root.querySelector("#detailBackToScans")?.addEventListener("click", () => setView("scans"));
  root.querySelector("#detailRefresh")?.addEventListener("click", async () => {
    if (state.selectedJobId) await selectJob(state.selectedJobId);
    renderScanDetailPage();
  });
  root.querySelectorAll("[data-fix-action]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = Number(btn.dataset.fixId);
      const action = btn.dataset.fixAction;
      await handleFixAction(id, action);
    });
  });
}

function renderCron() {
  const root = document.getElementById("view-cron");
  const rows = state.schedules || [];
  root.innerHTML = `
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
  `;
  root.querySelector("#cronRefresh")?.addEventListener("click", refreshCron);
  root.querySelector("#cronCreate")?.addEventListener("click", createCron);
  root.querySelectorAll("[data-action='trigger']").forEach(btn => btn.addEventListener("click", () => triggerCron(Number(btn.dataset.id))));
  root.querySelectorAll("[data-action='delete']").forEach(btn => btn.addEventListener("click", () => deleteCron(Number(btn.dataset.id))));
}

function renderAgents() {
  const root = document.getElementById("view-agents");
  const st = state.status || {};
  const agent = state.agent || {};
  root.innerHTML = `
    <div class="grid cols-3">
      <div class="card"><div class="metric-label">Runtime</div><div class="metric-value ${st.paused ? "warn" : "ok"}">${st.paused ? "Paused" : (st.running ? "Running" : "Idle")}</div></div>
      <div class="card"><div class="metric-label">Scan Workers</div><div class="metric-value">${st.workers ?? state.agent?.status?.workers ?? 0}</div></div>
      <div class="card"><div class="metric-label">Mode</div><div class="metric-value" style="font-size:22px">${escapeHtml(agent.mode || "triage")}</div></div>
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
  `;
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
  root.innerHTML = `
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
  `;
  const editor = root.querySelector("#cfgEditor");
  editor.value = state.config ? JSON.stringify(state.config, null, 2) : "{\n}";
  root.querySelector("#cfgRefresh").addEventListener("click", refreshConfig);
  root.querySelector("#cfgSave").addEventListener("click", async () => {
    try {
      const parsed = JSON.parse(editor.value);
      await api("/api/config", { method: "PUT", body: JSON.stringify(parsed) });
      await refreshConfig();
      alert("Config saved.");
    } catch (err) {
      alert(`Config save failed: ${err.message}`);
    }
  });
}

function renderEvents() {
  const root = document.getElementById("view-events");
  root.innerHTML = `
    <div class="card">
      <div class="toolbar">
        <button id="eventsClear" class="btn btn-secondary">Clear</button>
        <span class="muted">Live SSE from <code>/events</code></span>
      </div>
      <pre class="code" id="eventsLog">${escapeHtml(state.events.map(e => `${e.at} ${e.type} ${JSON.stringify(e.payload ?? {})}`).join("\n"))}</pre>
    </div>
  `;
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
    alert(`Trigger failed: ${err.message}`);
  }
}

async function triggerSweepWithOptions({ scanTargets, workers, selectedRepos }) {
  try {
    const payload = {};
    if (Array.isArray(scanTargets) && scanTargets.length > 0) payload.scan_targets = scanTargets;
    if (workers && Number(workers) > 0) payload.workers = Number(workers);
    if (Array.isArray(selectedRepos) && selectedRepos.length > 0) payload.selected_repos = selectedRepos;
    await api("/api/agent/trigger", { method: "POST", body: JSON.stringify(payload) });
    closeTriggerModal();
    await refreshStatus();
    await refreshAgent();
  } catch (err) {
    alert(`Trigger failed: ${err.message}`);
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
    alert(`Stop failed: ${err.message}`);
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
    alert(`Agent update failed: ${err.message}`);
  }
}

async function createCron() {
  const root = document.getElementById("view-cron");
  const name = root.querySelector("#cronName").value.trim();
  const expr = root.querySelector("#cronExpr").value.trim();
  const mode = root.querySelector("#cronMode").value.trim();
  if (!name || !expr) {
    alert("Name and expression are required.");
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
    alert(`Create schedule failed: ${err.message}`);
  }
}

async function triggerCron(id) {
  try {
    await api(`/api/schedules/${id}/trigger`, { method: "POST", body: "{}" });
    await refreshCron();
  } catch (err) {
    alert(`Trigger schedule failed: ${err.message}`);
  }
}

async function deleteCron(id) {
  if (!confirm(`Delete schedule #${id}?`)) return;
  try {
    await fetch(`/api/schedules/${id}`, { method: "DELETE" });
    await refreshCron();
  } catch (err) {
    alert(`Delete schedule failed: ${err.message}`);
  }
}

async function refreshStatus() {
  state.status = await api("/api/status");
  renderHealthPill();
}

async function refreshJobs() {
  state.jobs = await api("/api/jobs");
  state.jobSummary = await api("/api/jobs/summary");
  reconcileSelectedJobs();
  if (state.selectedJobId && !state.jobs.some(j => j.id === state.selectedJobId)) {
    clearSelectedJob();
  }
  renderScans();
  renderOverview();
}

async function selectJob(id) {
  state.selectedJobId = id;
  state.selectedJob = await api(`/api/jobs/${id}`);
  state.selectedJobScanners = await api(`/api/jobs/${id}/scanners`);
  state.selectedJobFindings = await api(`/api/jobs/${id}/findings?status=open`);
  state.selectedJobFixes = await api(`/api/jobs/${id}/fixes`);
  renderScans();
  if (state.view === "scan-detail") renderScanDetailPage();
}

function clearSelectedJob() {
  state.selectedJobId = null;
  state.selectedJob = null;
  state.selectedJobScanners = [];
  state.selectedJobFindings = [];
  state.selectedJobFixes = [];
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
  if (!confirm(`Delete scan job #${id} (${label})? This removes stored findings and raw outputs for the job.`)) return;
  try {
    await api(`/api/jobs/${id}`, { method: "DELETE" });
    delete state.selectedScanJobIds[id];
    await refreshJobs();
  } catch (err) {
    alert(`Delete failed: ${err.message}`);
  }
}

async function deleteSelectedScanJobs() {
  const ids = Object.keys(state.selectedScanJobIds || {}).map(Number).filter(Boolean).sort((a, b) => a - b);
  if (ids.length === 0) return;
  if (!confirm(`Delete ${ids.length} selected scan job${ids.length === 1 ? "" : "s"}? This cannot be undone.`)) return;
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
    alert(`Bulk delete failed: ${err.message}`);
  }
}

async function deleteAllScanJobs() {
  const count = (state.jobs || []).length;
  if (count === 0) return;
  const confirmation = prompt(`Delete ALL ${count} scan jobs and their stored findings/raw outputs? Type DELETE ALL to confirm.`);
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
    alert(`Delete all failed: ${err.message}`);
  }
}

async function openScanDetailPage(id) {
  await selectJob(id);
  setView("scan-detail");
  renderScanDetailPage();
}

async function refreshCron() {
  state.schedules = await api("/api/schedules");
  renderCron();
}

async function refreshAgent() {
  state.agent = await api("/api/agent");
  renderAgents();
}

async function refreshConfig() {
  const payload = await api("/api/config");
  state.configPath = payload.path || "";
  state.config = payload.config || {};
  renderConfig();
}

async function refreshAll() {
  try {
    await Promise.all([refreshStatus(), refreshJobs(), refreshCron(), refreshAgent()]);
    if (state.selectedJobId) {
      await selectJob(state.selectedJobId);
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
}

function scheduleLiveRefresh() {
  if (state.liveRefreshTimer) return;
  state.liveRefreshTimer = setTimeout(async () => {
    state.liveRefreshTimer = null;
    try {
      await refreshJobs();
      if (state.selectedJobId) {
        await selectJob(state.selectedJobId);
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
      await selectJob(state.selectedJobId);
    } else {
      await refreshJobs();
    }
    if (action === "approve-run") {
      showNotice("PR Processing Started", "The fix was approved and PR processing has been triggered. Refresh or wait for SSE updates to see PR status.");
    }
  } catch (err) {
    alert(`Fix action failed: ${err.message}`);
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

function getDefaultTriggerTargets() {
  const current = state.agent?.targets;
  if (Array.isArray(current) && current.length > 0) return [...current];
  return ["own_repos"];
}

function renderTriggerChecklist() {
  const root = document.getElementById("targetChecklist");
  const supported = state.agent?.supported_targets || ["own_repos", "watchlist", "cve_search", "all_accessible"];
  root.innerHTML = supported.map((t) => {
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
  }).join("");
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
    root.innerHTML = `<div class="muted">Loading preview…</div>`;
    return;
  }
  if (state.triggerPlan.targets.length === 0) {
    root.innerHTML = `<div class="muted">No targets selected. Select one or more targets to preview and choose repositories.</div>`;
    return;
  }
  if (state.triggerPreview.error) {
    root.innerHTML = `<div class="preview-errors">${escapeHtml(state.triggerPreview.error)}</div>`;
    return;
  }
  const data = state.triggerPreview.data;
  if (!data || !Array.isArray(data.targets)) {
    root.innerHTML = `<div class="muted">Preview unavailable.</div>`;
    return;
  }
  const previewRepos = getPreviewSampleRepos();
  const selectedCount = getSelectedPreviewRepos().length;
  root.innerHTML = data.targets.map((t) => `
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
  root.innerHTML = `
    <div class="toolbar preview-toolbar">
      <button id="previewReposSelectAll" class="btn btn-secondary" ${previewRepos.length === 0 ? "disabled" : ""}>Select All Shown</button>
      <button id="previewReposSelectNone" class="btn btn-secondary" ${selectedCount === 0 ? "disabled" : ""}>Select None</button>
      <span class="muted">${selectedCount} repo${selectedCount === 1 ? "" : "s"} selected${previewRepos.length ? ` (from ${previewRepos.length} shown)` : ""}. If any are selected, this trigger scans only those repos.</span>
    </div>
  ` + root.innerHTML;
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
      alert("Select at least one scan target or choose one or more preview repos.");
      return;
    }
    if (workersRaw !== "") {
      const n = Number(workersRaw);
      if (!Number.isFinite(n) || n < 1 || n > 64) {
        alert("Workers must be between 1 and 64.");
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
  wireTriggerModal();
  setView("overview");
  connectEvents();
  await refreshAll();
  setInterval(() => {
    if (document.visibilityState === "hidden") return;
    scheduleLiveRefresh();
  }, 5000);
}

bootstrap();
