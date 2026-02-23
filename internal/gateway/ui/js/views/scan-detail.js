import { state } from '../state.js';
import { escapeHtml, setHtml, fmtDate, fmtDuration, statusClass, severityBucket, countFindingsBySeverity } from '../utils.js';
// Circular imports — all usages are inside function bodies.
import { selectJob, loadSelectedJobFindings, loadSelectedJobRemediationRuns, handleFixAction, launchReviewCampaignForSelectedScan, stopReviewCampaignForSelectedScan } from '../actions.js';
import { openPathIgnoreModal } from '../modals.js';
import { setView } from '../router.js';

export function renderScanDetailPage() {
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
    const hay = [f.id, f.finding_type, f.status, f.pr_title, f.pr_url, f.pr_body]
      .map(v => String(v || "")).join(" ").toLowerCase();
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
    state.selectedJobRemediationRunsPage = Math.min(
      Math.max(1, Number(state.selectedJobRemediationRunsTotalPages || 1)),
      (state.selectedJobRemediationRunsPage || 1) + 1
    );
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
