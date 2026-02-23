// Circular imports — all usages are inside function bodies.
import {
  deleteAllScanJobs,
  deleteOneScanJob,
  deleteSelectedScanJobs,
  openScanDetailPage,
  refreshJobs,
  selectJob,
} from "../actions.js";
import { state } from "../state.js";
import { escapeHtml, fmtDate, fmtDuration, setHtml, severityBucket, statusClass } from "../utils.js";
import { renderSweepSummaryCard } from "./overview.js";

export function renderScans() {
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
  const visibleSelectedCount = visibleRows.filter((j) => selectedIds[j.id]).length;
  const allVisibleSelected = visibleRows.length > 0 && visibleSelectedCount === visibleRows.length;
  const selectedJob = state.selectedJob;
  const scanners = state.selectedJobScanners || [];
  const findings = state.selectedJobFindings || [];
  const scanWorkers = (state.agentWorkers || []).filter((w) => String(w?.kind || "").toLowerCase() === "scan");
  const activeScanWorkers = scanWorkers.filter((w) => {
    const st = String(w?.status || "").toLowerCase();
    return st === "running" || st === "failed";
  });
  setHtml(
    root,
    `
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
	              ${
                  scanWorkers.length
                    ? scanWorkers
                        .map(
                          (w) => `
	                <tr>
	                  <td>${escapeHtml(w.name || "")}</td>
	                  <td><span class="${statusClass(w.status)}">${escapeHtml(w.status || "")}</span></td>
                  <td>${escapeHtml(w.action || "")}</td>
                  <td>${escapeHtml(w.repo || "")}</td>
                  <td>${w.scan_job_id ? `#${w.scan_job_id}` : `<span class="muted">-</span>`}</td>
                  <td class="muted">${escapeHtml(w.message || "")}</td>
                  <td class="muted">${escapeHtml(fmtDate(w.updated_at))}</td>
	                </tr>
	              `
                        )
                        .join("")
                    : `<tr><td colspan="7" class="muted">No scan worker telemetry yet. Trigger a scan to populate live worker activity.</td></tr>`
                }
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
          <span class="muted">Page ${page} of ${totalPages} • Showing ${totalRows === 0 ? 0 : pageStart + 1}-${Math.min(pageStart + pageSize, totalRows)} of ${totalRows}</span>
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
              ${
                visibleRows
                  .map(
                    (j) => `
                <tr data-job-id="${j.id}" style="cursor:pointer; ${state.selectedJobId === j.id ? "background:rgba(79,140,255,.08)" : ""}">
                  <td><input type="checkbox" data-job-select="${j.id}" ${selectedIds[j.id] ? "checked" : ""}></td>
                  <td>#${j.id}</td>
                  <td>${escapeHtml(j.owner)}/${escapeHtml(j.repo)}</td>
                  <td><span class="${statusClass(j.status)}">${escapeHtml(j.status)}</span></td>
                  <td>${escapeHtml(fmtDate(j.started_at))}</td>
                  <td>${j.findings_critical}/${j.findings_high}/${j.findings_medium}/${j.findings_low}</td>
                  <td class="row-actions"><button class="btn btn-danger" data-job-delete="${j.id}">Delete</button></td>
                </tr>
              `
                  )
                  .join("") || `<tr><td colspan="7" class="muted">No jobs yet</td></tr>`
              }
            </tbody>
          </table>
        </div>
      </div>

      <div class="card">
        <h3>Job Detail ${selectedJob ? `#${selectedJob.id}` : ""}</h3>
        ${
          selectedJob
            ? `
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
                  ${
                    scanners
                      .map(
                        (s) => `
                    <tr>
                      <td>${escapeHtml(s.scanner_name)} <span class="muted">(${escapeHtml(s.scanner_type)})</span></td>
                      <td><span class="${statusClass(s.status)}">${escapeHtml(s.status)}</span></td>
                      <td>${s.findings_count}</td>
                      <td>${fmtDuration(s.duration_ms)}</td>
                      <td>${s.has_raw ? `<a class="link" href="/api/jobs/${selectedJob.id}/raw/${encodeURIComponent(s.scanner_name)}?download=1">download</a>` : `<span class="muted">n/a</span>`}</td>
                    </tr>`
                      )
                      .join("") ||
                    `<tr><td colspan="5" class="muted">No per-scanner rows for this job. Legacy jobs (created before the raw/scanner persistence migration) will show limited detail.</td></tr>`
                  }
                </tbody>
              </table>
            </div>
            <div class="kicker">Findings (structured from DB when available, otherwise parsed from raw scanner output)</div>
            <div class="table-wrap compact-findings-wrap" style="max-height:270px">
              <table>
                <thead><tr><th>Kind</th><th>Scanner</th><th>Severity</th><th>Path/Package</th></tr></thead>
                <tbody>
                ${
                  findings
                    .map(
                      (f) => `<tr>
                  <td>${escapeHtml(f.kind)}</td>
                  <td>${escapeHtml(f.scanner || "")}</td>
                  <td>${escapeHtml(severityBucket(f.severity))}</td>
                  <td>${escapeHtml(f.file_path || f.package || "")}${f.version ? ` <span class="muted">@${escapeHtml(f.version)}</span>` : ""}</td>
                </tr>`
                    )
                    .join("") ||
                  `<tr><td colspan="4" class="muted">No findings available for this job yet. For new scans, details are parsed from raw scanner output when normalized DB rows are absent.</td></tr>`
                }
                </tbody>
              </table>
            </div>
          </div>
        `
            : `<div class="muted">Select a scan job to inspect details.</div>`
        }
      </div>
      </div>
    </div>
  `
  );
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
  root.querySelectorAll("[data-job-id]").forEach((tr) => {
    tr.addEventListener("click", (e) => {
      if (e.target.closest("button") || e.target.closest("input") || e.target.closest("a")) return;
      selectJob(Number(tr.dataset.jobId));
    });
  });
}
