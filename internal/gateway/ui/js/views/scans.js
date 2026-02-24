// Circular imports — all usages are inside function bodies.
import {
  deleteAllScanJobs,
  deleteOneScanJob,
  deleteSelectedScanJobs,
  openScanDetailPage,
  refreshJobs,
  refreshScansRepos,
  selectJob,
} from "../actions.js";
import { state } from "../state.js";
import { escapeHtml, fmtDate, fmtDuration, setHtml, severityBucket, statusClass } from "../utils.js";

// ── Inline findings helpers ────────────────────────────────────────────────────

function getInlineFindingsViewModel() {
  const all = state.selectedJobFindings || [];
  const search = String(state.scansInlineFindingsSearch || "").trim().toLowerCase();
  const filtered = search
    ? all.filter((f) => {
        const hay = [f.kind, f.scanner, f.severity, f.file_path, f.package, f.version, f.title, f.message]
          .map((v) => String(v || ""))
          .join(" ")
          .toLowerCase();
        return hay.includes(search);
      })
    : all;
  const pageSize = Math.max(1, Number(state.scansInlineFindingsPageSize || 20));
  const total = filtered.length;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const page = Math.min(Math.max(1, Number(state.scansInlineFindingsPage || 1)), totalPages);
  state.scansInlineFindingsPage = page;
  const start = (page - 1) * pageSize;
  return { filtered: filtered.slice(start, start + pageSize), total, totalPages, page, start, pageSize };
}

// ── Repo multiselect combobox ─────────────────────────────────────────────────

function renderRepoCombo() {
  const selected = state.scansFiltersDraft.repos || [];
  const search = String(state.scansRepoComboSearch || "").trim().toLowerCase();
  const suggestions = state.scansRepoSuggestions || [];
  const isOpen = !!state.scansRepoComboOpen;

  const chips = selected
    .map(
      (r) =>
        `<span class="ms-chip">${escapeHtml(r)}<button type="button" class="ms-chip-remove" data-repo="${escapeHtml(r)}" title="Remove">×</button></span>`
    )
    .join("");

  const filtered = suggestions.filter((r) => !search || r.toLowerCase().includes(search));
  const options = filtered
    .slice(0, 60)
    .map(
      (r) =>
        `<label class="ms-combo-option">
          <input type="checkbox" class="ms-repo-check" data-repo="${escapeHtml(r)}" ${selected.includes(r) ? "checked" : ""}>
          ${escapeHtml(r)}
        </label>`
    )
    .join("");

  return `
    <div class="ms-combo" id="scansRepoCombo">
      <div class="ms-combo-trigger" id="scansRepoComboTrigger">
        ${chips}
        <input type="text" id="scansRepoComboInput" class="ms-combo-input"
          placeholder="${selected.length ? "Add repo…" : "Filter by repo…"}"
          value="${escapeHtml(state.scansRepoComboSearch || "")}"
          autocomplete="off">
      </div>
      ${
        isOpen
          ? `<div class="ms-combo-dropdown" id="scansRepoComboDropdown">
          ${
            suggestions.length === 0
              ? `<div class="ms-combo-empty">${state.scansRepoSuggestionsLoaded ? "No repos found" : "Loading…"}</div>`
              : filtered.length === 0
                ? `<div class="ms-combo-empty">No match</div>`
                : options
          }
        </div>`
          : ""
      }
    </div>
  `;
}

// ── Main render ───────────────────────────────────────────────────────────────

export function renderScans() {
  const root = document.getElementById("view-scans");
  const scansLoading = !!state.scansLoading;
  const scansActionBusy = String(state.scansActionBusy || "");
  const rows = state.jobs || [];
  const pageSize = state.scansPageSize || 20;
  const totalRows = Number(state.jobsTotal || rows.length || 0);
  const totalPages = Math.max(1, Number(state.jobsTotalPages || Math.ceil(totalRows / pageSize) || 1));
  const page = Math.min(Math.max(1, state.scansPage || 1), totalPages);
  state.scansPage = page;
  const pageStart = (page - 1) * pageSize;
  const selectedIds = state.selectedScanJobIds || {};
  const selectedCount = Object.keys(selectedIds).length;
  const visibleRows = rows;
  const visibleSelectedCount = visibleRows.filter((j) => selectedIds[j.id]).length;
  const allVisibleSelected = visibleRows.length > 0 && visibleSelectedCount === visibleRows.length;

  // Job detail state
  const selectedJob = state.selectedJob;
  const selectedJobLoading = !!state.selectedJobLoading;
  const scanners = state.selectedJobScanners || [];
  const { filtered: inlineFindings, total: ifTotal, totalPages: ifTotalPages, page: ifPage, start: ifStart, pageSize: ifPageSize } =
    getInlineFindingsViewModel();

  // Workers
  const scanWorkers = (state.agentWorkers || []).filter((w) => String(w?.kind || "").toLowerCase() === "scan");
  const activeScanWorkers = scanWorkers.filter((w) => {
    const st = String(w?.status || "").toLowerCase();
    return st === "running" || st === "failed";
  });

  // Collapse state
  const sweepCollapsed = !!state.scansSweepCollapsed;
  const workersCollapsed = !!state.scansWorkersCollapsed;

  // Active filters summary
  const f = state.scansFilters || {};
  const activeFilterCount = (f.repos?.length || 0) + (f.status ? 1 : 0) + (f.minHigh ? 1 : 0) + (f.minMedium ? 1 : 0);
  const fd = state.scansFiltersDraft || {};

  // Status options
  const STATUS_OPTIONS = ["", "running", "completed", "failed", "stopped", "partial"];

  setHtml(
    root,
    `
    <div class="stack">

      <!-- Top row: sweep summary + workers side-by-side -->
      <div class="grid cols-2">
        <!-- Sweep Summary (collapsible) -->
        <div class="card scans-top-card">
          <div class="toolbar" style="justify-content:space-between;margin-bottom:${sweepCollapsed ? "0" : "10px"}">
            <h3 style="margin:0">Latest Sweep Summary</h3>
            <button id="scansSweepToggle" class="btn btn-secondary" style="padding:2px 10px;font-size:11px">${sweepCollapsed ? "Expand" : "Collapse"}</button>
          </div>
          ${sweepCollapsed ? "" : renderSweepSummaryCardBody()}
        </div>

        <!-- Active Scan Workers (collapsible) -->
        <div class="card scans-top-card">
          <div class="toolbar" style="justify-content:space-between;margin-bottom:${workersCollapsed ? "0" : "10px"}">
            <h3 style="margin:0">Active Scan Workers</h3>
            <div style="display:flex;gap:8px;align-items:center">
              <span class="muted" style="font-size:12px">${activeScanWorkers.length} active • ${scanWorkers.length} total</span>
              <button id="scansWorkersToggle" class="btn btn-secondary" style="padding:2px 10px;font-size:11px">${workersCollapsed ? "Expand" : "Collapse"}</button>
            </div>
          </div>
          ${
            workersCollapsed
              ? ""
              : `<div class="table-wrap" style="max-height:160px">
              <table>
                <thead><tr><th>Name</th><th>Status</th><th>Action</th><th>Repo</th><th>Message</th><th>Updated</th></tr></thead>
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
                          <td class="muted">${escapeHtml(w.message || "")}</td>
                          <td class="muted">${escapeHtml(fmtDate(w.updated_at))}</td>
                        </tr>`
                          )
                          .join("")
                      : `<tr><td colspan="6" class="muted">No scan worker telemetry yet.</td></tr>`
                  }
                </tbody>
              </table>
            </div>`
          }
        </div>
      </div>

      <!-- Filters bar -->
      <div class="card" style="padding:12px 14px">
        <div class="toolbar" style="flex-wrap:wrap;gap:8px;margin-bottom:8px">
          <strong style="font-size:12px;letter-spacing:.04em;text-transform:uppercase;color:var(--muted-text)">Filters</strong>
          ${renderRepoCombo()}
          <label style="width:auto">
            <select id="scansStatusFilter">
              ${STATUS_OPTIONS.map(
                (s) =>
                  `<option value="${s}" ${fd.status === s ? "selected" : ""}>${s || "All statuses"}</option>`
              ).join("")}
            </select>
          </label>
          <input id="scansMinHigh" type="number" min="0" placeholder="High ≥" value="${escapeHtml(fd.minHigh || "")}" style="width:90px">
          <input id="scansMinMedium" type="number" min="0" placeholder="Medium ≥" value="${escapeHtml(fd.minMedium || "")}" style="width:100px">
          <button id="scansApplyFilters" class="btn btn-primary">Apply${activeFilterCount > 0 ? ` (${activeFilterCount})` : ""}</button>
          <button id="scansClearFilters" class="btn btn-secondary" ${activeFilterCount === 0 ? "disabled" : ""}>Clear Filters</button>
        </div>
      </div>

      <!-- Main split: scans table + job detail -->
      <div class="split scans-main-split">

        <!-- Left: scans table -->
        <div class="card scans-panel">
          <div class="toolbar">
            <button id="scansRefresh" class="btn btn-secondary ${scansLoading ? "is-loading" : ""}" ${scansLoading || scansActionBusy !== "" ? "disabled" : ""}>Refresh</button>
            <button id="scansDeleteSelected" class="btn btn-danger ${scansActionBusy === "delete-selected" ? "is-loading" : ""}" ${selectedCount === 0 || scansActionBusy !== "" ? "disabled" : ""}>Delete (${selectedCount})</button>
            <button id="scansDeleteAll" class="btn btn-danger ${scansActionBusy === "delete-all" ? "is-loading" : ""}" ${totalRows === 0 || scansActionBusy !== "" ? "disabled" : ""}>Delete All</button>
            <span class="muted" style="margin-left:auto">Page ${page}/${totalPages} · ${totalRows === 0 ? 0 : pageStart + 1}-${Math.min(pageStart + pageSize, totalRows)} of ${totalRows}</span>
            <button id="scansPrevPage" class="btn btn-secondary" ${page <= 1 ? "disabled" : ""}>Prev</button>
            <button id="scansNextPage" class="btn btn-secondary" ${page >= totalPages ? "disabled" : ""}>Next</button>
          </div>
          <div class="table-wrap scans-table-fill">
            <table>
              <thead>
                <tr>
                  <th style="width:34px"><input type="checkbox" id="scanSelectAll" ${allVisibleSelected ? "checked" : ""} ${visibleRows.length === 0 ? "disabled" : ""}></th>
                  <th>ID</th><th>Repo</th><th>Status</th><th>Started</th><th>C/H/M/L</th><th>Actions</th>
                </tr>
              </thead>
              <tbody>
                ${
                  scansLoading && visibleRows.length === 0
                    ? new Array(6)
                        .fill(0)
                        .map(
                          () => `<tr class="skeleton-table">
                    <td><span class="skeleton-block" style="width:14px;height:14px"></span></td>
                    <td><span class="skeleton-block" style="width:42px"></span></td>
                    <td><span class="skeleton-block" style="width:160px"></span></td>
                    <td><span class="skeleton-block" style="width:80px"></span></td>
                    <td><span class="skeleton-block" style="width:120px"></span></td>
                    <td><span class="skeleton-block" style="width:90px"></span></td>
                    <td><span class="skeleton-block" style="width:70px"></span></td>
                  </tr>`
                        )
                        .join("")
                    : visibleRows
                        .map(
                          (j) => `
                  <tr data-job-id="${j.id}" style="cursor:pointer; ${state.selectedJobId === j.id ? "background:rgba(79,140,255,.08)" : ""}">
                    <td><input type="checkbox" data-job-select="${j.id}" ${selectedIds[j.id] ? "checked" : ""}></td>
                    <td>#${j.id}</td>
                    <td>${escapeHtml(j.owner)}/${escapeHtml(j.repo)}</td>
                    <td><span class="${statusClass(j.status)}">${escapeHtml(j.status)}</span></td>
                    <td>${escapeHtml(fmtDate(j.started_at))}</td>
                    <td>${j.findings_critical}/${j.findings_high}/${j.findings_medium}/${j.findings_low}</td>
                    <td class="row-actions"><button class="btn btn-danger ${scansActionBusy === `delete:${j.id}` ? "is-loading" : ""}" data-job-delete="${j.id}" ${scansActionBusy !== "" ? "disabled" : ""}>Delete</button></td>
                  </tr>`
                        )
                        .join("") || `<tr><td colspan="7" class="muted">No jobs match current filters.</td></tr>`
                }
              </tbody>
            </table>
          </div>
        </div>

        <!-- Right: job detail -->
        <div class="card scans-panel">
          <h3 style="margin-top:0">Job Detail ${selectedJob ? `#${selectedJob.id}` : ""}</h3>
          ${
            selectedJobLoading
              ? `<div class="stack">
                <div class="skeleton-block" style="width:220px;height:14px"></div>
                <div class="skeleton-block" style="width:320px;height:12px"></div>
              </div>`
              : selectedJob
                ? `<div class="stack" style="height:100%;display:flex;flex-direction:column">
                  <div>
                    <strong>${escapeHtml(selectedJob.owner)}/${escapeHtml(selectedJob.repo)}</strong>
                    <span class="badge ${statusClass(selectedJob.status)}" style="margin-left:6px">${escapeHtml(selectedJob.status)}</span>
                  </div>
                  <div class="muted">Branch ${escapeHtml(selectedJob.branch)} · Started ${escapeHtml(fmtDate(selectedJob.started_at))}</div>
                  <div class="toolbar" style="margin-bottom:4px">
                    <button class="btn btn-secondary" id="openDetailPageBtn">Open Full Detail</button>
                  </div>

                  <div class="kicker">Scanners</div>
                  <div class="table-wrap" style="max-height:130px">
                    <table>
                      <thead><tr><th>Scanner</th><th>Status</th><th>Findings</th><th>Duration</th><th>Raw</th></tr></thead>
                      <tbody>
                        ${
                          scanners
                            .map(
                              (s) => `<tr>
                            <td>${escapeHtml(s.scanner_name)} <span class="muted">(${escapeHtml(s.scanner_type)})</span></td>
                            <td><span class="${statusClass(s.status)}">${escapeHtml(s.status)}</span></td>
                            <td>${s.findings_count}</td>
                            <td>${fmtDuration(s.duration_ms)}</td>
                            <td>${s.has_raw ? `<a class="link" href="/api/jobs/${selectedJob.id}/raw/${encodeURIComponent(s.scanner_name)}?download=1">dl</a>` : `<span class="muted">n/a</span>`}</td>
                          </tr>`
                            )
                            .join("") ||
                          `<tr><td colspan="5" class="muted">No scanner rows. Legacy jobs show limited detail.</td></tr>`
                        }
                      </tbody>
                    </table>
                  </div>

                  <div class="kicker" style="margin-top:8px">Findings</div>
                  <div class="toolbar" style="margin-bottom:6px">
                    <input id="scansInlineFindingsSearch" placeholder="Search findings…"
                      value="${escapeHtml(state.scansInlineFindingsSearch || "")}" style="flex:1;min-width:120px">
                    <button id="scansInlineFindingsClear" class="btn btn-secondary">Clear</button>
                    <span class="muted" style="white-space:nowrap">${ifTotal === 0 ? 0 : ifStart + 1}-${Math.min(ifStart + ifPageSize, ifTotal)} of ${ifTotal}</span>
                    <button id="scansInlinePrev" class="btn btn-secondary" ${ifPage <= 1 ? "disabled" : ""}>Prev</button>
                    <button id="scansInlineNext" class="btn btn-secondary" ${ifPage >= ifTotalPages ? "disabled" : ""}>Next</button>
                  </div>
                  <div class="table-wrap scans-table-fill compact-findings-wrap">
                    <table>
                      <thead><tr><th>Kind</th><th>Scanner</th><th>Severity</th><th>Path/Package</th></tr></thead>
                      <tbody>
                        ${
                          inlineFindings
                            .map(
                              (f) => `<tr>
                            <td>${escapeHtml(f.kind)}</td>
                            <td>${escapeHtml(f.scanner || "")}</td>
                            <td>${escapeHtml(severityBucket(f.severity))}</td>
                            <td>${escapeHtml(f.file_path || f.package || "")}${f.version ? ` <span class="muted">@${escapeHtml(f.version)}</span>` : ""}</td>
                          </tr>`
                            )
                            .join("") ||
                          `<tr><td colspan="4" class="muted">No findings${state.scansInlineFindingsSearch ? " matching search" : " available"}.</td></tr>`
                        }
                      </tbody>
                    </table>
                  </div>
                </div>`
                : `<div class="muted">Select a scan job to inspect details.</div>`
          }
        </div>

      </div>
    </div>
  `
  );

  // ── Event binding ────────────────────────────────────────────────────────────

  // Collapse toggles
  root.querySelector("#scansSweepToggle")?.addEventListener("click", () => {
    state.scansSweepCollapsed = !state.scansSweepCollapsed;
    renderScans();
  });
  root.querySelector("#scansWorkersToggle")?.addEventListener("click", () => {
    state.scansWorkersCollapsed = !state.scansWorkersCollapsed;
    renderScans();
  });

  // Repo combo open/close
  const combo = root.querySelector("#scansRepoCombo");
  const comboInput = root.querySelector("#scansRepoComboInput");
  const comboTrigger = root.querySelector("#scansRepoComboTrigger");

  comboTrigger?.addEventListener("click", (e) => {
    if (e.target.closest(".ms-chip-remove")) return;
    if (!state.scansRepoSuggestionsLoaded) refreshScansRepos();
    state.scansRepoComboOpen = true;
    renderScans();
    root.querySelector("#scansRepoComboInput")?.focus();
  });

  comboInput?.addEventListener("input", (e) => {
    state.scansRepoComboSearch = e.target.value || "";
    state.scansRepoComboOpen = true;
    renderScans();
    root.querySelector("#scansRepoComboInput")?.focus();
  });

  root.querySelectorAll(".ms-repo-check").forEach((cb) => {
    cb.addEventListener("change", () => {
      const r = cb.dataset.repo;
      const sel = state.scansFiltersDraft.repos;
      if (cb.checked) {
        if (!sel.includes(r)) sel.push(r);
      } else {
        const idx = sel.indexOf(r);
        if (idx !== -1) sel.splice(idx, 1);
      }
      renderScans();
      root.querySelector("#scansRepoComboInput")?.focus();
    });
  });

  root.querySelectorAll(".ms-chip-remove").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const r = btn.dataset.repo;
      const sel = state.scansFiltersDraft.repos;
      const idx = sel.indexOf(r);
      if (idx !== -1) sel.splice(idx, 1);
      renderScans();
    });
  });

  // Close combo when clicking outside
  const closeCombo = (e) => {
    if (!combo?.contains(e.target)) {
      if (state.scansRepoComboOpen) {
        state.scansRepoComboOpen = false;
        state.scansRepoComboSearch = "";
        renderScans();
      }
      document.removeEventListener("click", closeCombo, true);
    }
  };
  if (state.scansRepoComboOpen) {
    document.addEventListener("click", closeCombo, true);
  }

  // Filter controls
  root.querySelector("#scansStatusFilter")?.addEventListener("change", (e) => {
    state.scansFiltersDraft.status = e.target.value;
  });
  root.querySelector("#scansMinHigh")?.addEventListener("input", (e) => {
    state.scansFiltersDraft.minHigh = e.target.value;
  });
  root.querySelector("#scansMinMedium")?.addEventListener("input", (e) => {
    state.scansFiltersDraft.minMedium = e.target.value;
  });

  root.querySelector("#scansApplyFilters")?.addEventListener("click", () => {
    state.scansFilters = {
      repos: [...(state.scansFiltersDraft.repos || [])],
      status: state.scansFiltersDraft.status || "",
      minHigh: state.scansFiltersDraft.minHigh || "",
      minMedium: state.scansFiltersDraft.minMedium || "",
    };
    state.scansRepoComboOpen = false;
    state.scansRepoComboSearch = "";
    state.scansPage = 1;
    refreshJobs();
  });

  root.querySelector("#scansClearFilters")?.addEventListener("click", () => {
    state.scansFilters = { repos: [], status: "", minHigh: "", minMedium: "" };
    state.scansFiltersDraft = { repos: [], status: "", minHigh: "", minMedium: "" };
    state.scansRepoComboOpen = false;
    state.scansRepoComboSearch = "";
    state.scansPage = 1;
    refreshJobs();
  });

  // Scans table
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
  root.querySelectorAll("[data-job-id]").forEach((tr) => {
    tr.addEventListener("click", (e) => {
      if (e.target.closest("button") || e.target.closest("input") || e.target.closest("a")) return;
      state.scansInlineFindingsPage = 1;
      state.scansInlineFindingsSearch = "";
      selectJob(Number(tr.dataset.jobId));
    });
  });

  // Job detail
  root.querySelector("#openDetailPageBtn")?.addEventListener("click", async () => {
    if (selectedJob) await openScanDetailPage(selectedJob.id);
  });

  // Inline findings search & pagination
  let ifSearchTimer = null;
  root.querySelector("#scansInlineFindingsSearch")?.addEventListener("input", (e) => {
    state.scansInlineFindingsSearch = e.target.value || "";
    state.scansInlineFindingsPage = 1;
    if (ifSearchTimer) clearTimeout(ifSearchTimer);
    ifSearchTimer = setTimeout(() => renderScans(), 140);
  });
  root.querySelector("#scansInlineFindingsClear")?.addEventListener("click", () => {
    state.scansInlineFindingsSearch = "";
    state.scansInlineFindingsPage = 1;
    renderScans();
  });
  root.querySelector("#scansInlinePrev")?.addEventListener("click", () => {
    state.scansInlineFindingsPage = Math.max(1, (state.scansInlineFindingsPage || 1) - 1);
    renderScans();
  });
  root.querySelector("#scansInlineNext")?.addEventListener("click", () => {
    state.scansInlineFindingsPage = (state.scansInlineFindingsPage || 1) + 1;
    renderScans();
  });
}

// ── Sweep summary body (without the card wrapper, used in collapsible) ────────

function renderSweepSummaryCardBody() {
  const s = state.sweepUi?.latestSummary;
  if (!s) {
    return `<div class="muted">No sweep events yet. Trigger a scan to populate.</div>`;
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
    <div>
      <span class="badge ${statusClass(status)}">${escapeHtml(status)}</span>
    </div>
    <div class="muted">Started ${escapeHtml(fmtDate(s.started_at))}${s.completed_at ? ` · Completed ${escapeHtml(fmtDate(s.completed_at))}` : ""}</div>
    <div>Duration: <strong>${s.duration_seconds ? `${Number(s.duration_seconds).toFixed(1)}s` : "n/a"}</strong></div>
    <div>Skipped repos: <strong>${Number(s.skipped_repos || 0)}</strong></div>
    ${reasonParts.length ? `<div class="muted">Skip reasons: ${escapeHtml(reasonParts.join(" · "))}</div>` : ""}
    <div class="muted">${workers > 0 ? `${workers} worker${workers === 1 ? "" : "s"}` : "Workers unknown"}${selectedRepos > 0 ? ` · ${selectedRepos} selected repos` : ""}${targets.length ? ` · targets: ${targets.join(", ")}` : ""}</div>
  `;
}
