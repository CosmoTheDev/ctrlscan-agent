// Circular imports — all usages are inside function bodies.
import { handleFixAction, openScanDetailPage, refreshVulnerabilities } from "../actions.js";
import { setView } from "../router.js";
import { state } from "../state.js";
import { escapeHtml, setHtml, severityBucket } from "../utils.js";

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const PAGE_SIZE_OPTIONS = [25, 50, 100, 200];

function sevClass(s) {
  const b = severityBucket(s);
  if (b === "CRITICAL") return "critical";
  if (b === "HIGH") return "high";
  if (b === "MEDIUM") return "medium";
  if (b === "LOW") return "low";
  return "";
}

// ── Summary cards ─────────────────────────────────────────────────────────────

function renderSummaryCards() {
  const t = state.vulnerabilitiesSeverityTotals || {};
  const loading = state.vulnerabilitiesLoading;
  const fmt = (n) => (loading ? "…" : Number(n || 0).toLocaleString());
  return `
    <div class="grid cols-5" style="margin-bottom:10px;gap:8px">
      <div class="card card-critical" style="padding:12px 14px;cursor:pointer" id="vulnCardCritical" title="Filter by Critical">
        <div class="metric-label" style="font-size:10px">CRITICAL</div>
        <div class="metric-value critical" style="font-size:22px;margin-top:4px">${fmt(t.critical)}</div>
      </div>
      <div class="card card-high" style="padding:12px 14px;cursor:pointer" id="vulnCardHigh" title="Filter by High">
        <div class="metric-label" style="font-size:10px">HIGH</div>
        <div class="metric-value high" style="font-size:22px;margin-top:4px">${fmt(t.high)}</div>
      </div>
      <div class="card card-medium" style="padding:12px 14px;cursor:pointer" id="vulnCardMedium" title="Filter by Medium">
        <div class="metric-label" style="font-size:10px">MEDIUM</div>
        <div class="metric-value medium" style="font-size:22px;margin-top:4px">${fmt(t.medium)}</div>
      </div>
      <div class="card card-low" style="padding:12px 14px;cursor:pointer" id="vulnCardLow" title="Filter by Low">
        <div class="metric-label" style="font-size:10px">LOW</div>
        <div class="metric-value low" style="font-size:22px;margin-top:4px">${fmt(t.low)}</div>
      </div>
      <div class="card card-ok" style="padding:12px 14px;cursor:pointer" id="vulnCardFixed" title="Show Fixed findings">
        <div class="metric-label" style="font-size:10px">FIXED</div>
        <div class="metric-value ok" style="font-size:22px;margin-top:4px">${fmt(t.fixed)}</div>
      </div>
    </div>
  `;
}

// ── CVE chip input ─────────────────────────────────────────────────────────────

function renderCVEChips() {
  const f = state.vulnerabilitiesFilters;
  const cves = Array.isArray(f.cves) ? f.cves : [];
  const facetCVEs = (state.vulnerabilitiesFacets?.cves || []).slice(0, 300);
  const chips = cves
    .map(
      (c) =>
        `<span class="chip" style="display:inline-flex;align-items:center;gap:4px;background:var(--sev-h-bg);border:1px solid var(--sev-h-bd);color:var(--sev-h);border-radius:4px;padding:2px 8px;font-size:11px;font-weight:600">
          ${escapeHtml(c)}
          <button class="chip-remove" data-cve="${escapeHtml(c)}" style="background:none;border:none;cursor:pointer;color:inherit;padding:0 0 0 2px;font-size:13px;line-height:1" title="Remove">×</button>
        </span>`
    )
    .join("");
  const listId = "vulnCVEDatalist";
  return `
    <div style="display:flex;flex-wrap:wrap;gap:4px;align-items:center;min-height:28px">
      ${chips}
      <div style="position:relative;display:flex;align-items:center;gap:4px;flex:1;min-width:180px">
        <input id="vulnCVEInput" list="${listId}" placeholder="CVE-…  GHSA-… (Enter to add)" style="width:100%;min-width:180px" autocomplete="off">
        <datalist id="${listId}">
          ${facetCVEs.map((c) => `<option value="${escapeHtml(c)}">`).join("")}
        </datalist>
      </div>
    </div>
  `;
}

// ── Filter bar ─────────────────────────────────────────────────────────────────

function renderFiltersBar() {
  const f = state.vulnerabilitiesFilters;
  const total = state.vulnerabilitiesTotal;
  const facets = state.vulnerabilitiesFacets || { severities: [], kinds: [], scanners: [], repos: [] };

  // Build severity options from facets (always show ALL severities so user can switch)
  const availSev = new Set(facets.severities || SEVERITY_ORDER);
  const sevOptions = SEVERITY_ORDER.map((s) => {
    const avail = availSev.has(s);
    return `<option value="${s}" ${f.severity === s ? "selected" : ""} ${!avail && f.severity !== s ? "style='opacity:0.4'" : ""}>${s}</option>`;
  }).join("");

  // Kind options from facets
  const availKinds = new Set(facets.kinds || []);
  const kindMap = { sca: "SCA (Dependencies)", sast: "SAST (Code)", secrets: "Secrets", iac: "IaC" };
  const kindOptions = Object.entries(kindMap)
    .map(([v, label]) => {
      const avail = availKinds.size === 0 || availKinds.has(v);
      return `<option value="${v}" ${f.kind === v ? "selected" : ""} ${!avail && f.kind !== v ? "style='opacity:0.4'" : ""}>${label}</option>`;
    })
    .join("");

  // Scanner options from facets
  const availScanners = new Set(facets.scanners || []);
  const scannerNames = ["grype", "opengrep", "trufflehog", "trivy"];
  const scannerOptions = scannerNames
    .map((v) => {
      const avail = availScanners.size === 0 || availScanners.has(v);
      return `<option value="${v}" ${f.scanner === v ? "selected" : ""} ${!avail && f.scanner !== v ? "style='opacity:0.4'" : ""}>${v}</option>`;
    })
    .join("");

  // Repo combobox — datalist from facets
  const repoListId = "vulnRepoDatalist";
  const repoOptions = (facets.repos || []).map((r) => `<option value="${escapeHtml(r)}">`).join("");

  const pageSize = state.vulnerabilitiesPageSize || 50;
  const pageSizeOptions = PAGE_SIZE_OPTIONS.map(
    (n) => `<option value="${n}" ${pageSize === n ? "selected" : ""}>${n} / page</option>`
  ).join("");

  const countLabel = state.vulnerabilitiesLoading
    ? `<span class="spinner-dot spinner-dot-accent" aria-hidden="true" style="display:inline-block;vertical-align:middle;margin-right:4px"></span><span class="muted">Loading…</span>`
    : `<span class="muted" style="white-space:nowrap">${total.toLocaleString()} result${total === 1 ? "" : "s"}</span>`;

  return `
    <div class="card" style="padding:10px 14px;margin-bottom:8px">
      <div class="toolbar" style="flex-wrap:wrap;gap:8px;align-items:center;row-gap:8px">
        <select id="vulnFilterSeverity" style="width:132px" title="Severity">
          <option value="">All Severities</option>
          ${sevOptions}
        </select>
        <select id="vulnFilterKind" style="width:158px" title="Type">
          <option value="">All Types</option>
          ${kindOptions}
        </select>
        <select id="vulnFilterScanner" style="width:128px" title="Scanner">
          <option value="">All Scanners</option>
          ${scannerOptions}
        </select>
        <select id="vulnFilterStatus" style="width:116px" title="Status">
          <option value="open" ${f.status === "open" ? "selected" : ""}>Open</option>
          <option value="all" ${f.status === "all" ? "selected" : ""}>All Statuses</option>
          <option value="fixed" ${f.status === "fixed" ? "selected" : ""}>Fixed</option>
        </select>
        <input id="vulnFilterRepo" list="${repoListId}" type="text" placeholder="Repo / owner…" value="${escapeHtml(f.repo)}" style="width:170px;flex-shrink:0" title="Filter by repo or owner (type to filter, or select from list)" autocomplete="off">
        <datalist id="${repoListId}">${repoOptions}</datalist>
        <input id="vulnFilterQ" type="text" placeholder="Search title, path, message…" value="${escapeHtml(f.q)}" style="flex:1;min-width:180px" title="Fulltext search">
        <select id="vulnPageSize" style="width:108px" title="Results per page">
          ${pageSizeOptions}
        </select>
        <button id="vulnExportCSV" class="btn btn-secondary" title="Export current filtered results as CSV">Export CSV</button>
        <button id="vulnFilterClear" class="btn btn-secondary">Clear</button>
        ${countLabel}
      </div>
      <div style="margin-top:8px;border-top:1px solid var(--line);padding-top:8px">
        <div class="muted" style="font-size:11px;margin-bottom:4px">CVE / GHSA filter (Enter or comma to add, click × to remove):</div>
        <div id="vulnCVERow">${renderCVEChips()}</div>
      </div>
    </div>
  `;
}

// ── Pagination bar ──────────────────────────────────────────────────────────────

function renderPagination() {
  const page = state.vulnerabilitiesPage;
  const total = state.vulnerabilitiesTotalPages;
  const pageSize = state.vulnerabilitiesPageSize || 50;
  const totalItems = state.vulnerabilitiesTotal;
  const start = (page - 1) * pageSize + 1;
  const end = Math.min(page * pageSize, totalItems);
  return `
    <div class="toolbar" style="padding:6px 0;gap:8px;align-items:center;flex-shrink:0">
      <button class="btn btn-secondary" id="vulnPageFirst" ${page <= 1 ? "disabled" : ""} title="First page">«</button>
      <button class="btn btn-secondary" id="vulnPagePrev" ${page <= 1 ? "disabled" : ""}>← Prev</button>
      <span class="muted" style="white-space:nowrap">Page ${page} of ${total} ${totalItems > 0 ? `(${start}–${end} of ${totalItems.toLocaleString()})` : ""}</span>
      <button class="btn btn-secondary" id="vulnPageNext" ${page >= total ? "disabled" : ""}>Next →</button>
      <button class="btn btn-secondary" id="vulnPageLast" ${page >= total ? "disabled" : ""} title="Last page">»</button>
    </div>
  `;
}

// ── Fix cell ───────────────────────────────────────────────────────────────────

function renderFixCell(v) {
  if (v.fix_pr_url) {
    return `<a href="${escapeHtml(v.fix_pr_url)}" target="_blank" rel="noopener" class="btn btn-secondary" style="font-size:11px;padding:2px 8px">View PR</a>`;
  }
  if (v.fix_queue_id > 0) {
    const s = String(v.fix_status || "");
    if (s === "pending") {
      const busy = state.fixActionBusyKey === `approve-run:${v.fix_queue_id}`;
      return `<button class="btn btn-primary vuln-fix-approve-run ${busy ? "is-loading" : ""}" data-id="${v.fix_queue_id}" style="font-size:11px;padding:2px 8px" ${busy ? "disabled" : ""}>Create PR</button>`;
    }
    if (s === "approved") return `<span class="badge badge-run">Approved</span>`;
    if (s === "rejected") return `<span class="badge badge-danger">Rejected</span>`;
    if (s === "merged" || s === "pr_created") return `<span class="badge badge-ok">PR Created</span>`;
    return `<span class="badge">${escapeHtml(s)}</span>`;
  }
  return `<span class="muted" style="font-size:11px">—</span>`;
}

// ── Table ──────────────────────────────────────────────────────────────────────

function renderTable() {
  const vulns = state.vulnerabilities;
  if (!vulns || vulns.length === 0) {
    return `
      <div style="flex:1;display:flex;align-items:center;justify-content:center">
        <div class="muted" style="text-align:center;padding:40px">No vulnerabilities found matching the current filters.</div>
      </div>
    `;
  }
  const rows = vulns
    .map((v) => {
      const sev = severityBucket(v.severity);
      const repo = `${escapeHtml(v.owner)}/${escapeHtml(v.repo)}`;
      const branch = escapeHtml(v.branch || "");
      const title = escapeHtml(v.title || "");
      const filepath = escapeHtml(v.file_path || v.package || "");
      const scanner = escapeHtml(v.scanner || v.kind || "");
      return `
        <tr class="vuln-row" data-job-id="${v.scan_job_id}" style="cursor:pointer" title="Click to open scan detail">
          <td style="width:90px"><span class="badge badge-${sevClass(sev)}">${escapeHtml(sev)}</span></td>
          <td style="width:68px"><span class="muted">${escapeHtml(v.kind || "")}</span></td>
          <td style="width:90px"><span class="muted" style="font-size:11px">${scanner}</span></td>
          <td style="width:200px">
            <div style="font-weight:500;word-break:break-all">${repo}</div>
            ${branch ? `<div class="muted" style="font-size:11px">${branch}</div>` : ""}
          </td>
          <td>
            <div style="font-weight:500;word-break:break-word">${title}</div>
            ${filepath ? `<div class="muted" style="font-size:11px;word-break:break-all">${filepath}</div>` : ""}
          </td>
          <td style="width:72px"><span class="badge">${escapeHtml(v.status || "open")}</span></td>
          <td style="width:116px;white-space:nowrap">${renderFixCell(v)}</td>
        </tr>
      `;
    })
    .join("");
  return `
    <div class="table-wrap vuln-table-wrap" data-preserve-scroll-key="vuln-table">
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Type</th>
            <th>Scanner</th>
            <th>Repo / Branch</th>
            <th>Title / Path</th>
            <th>Status</th>
            <th>Fix</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  `;
}

// ── Main render ────────────────────────────────────────────────────────────────

export function renderVulnerabilities() {
  const root = document.getElementById("view-vulnerabilities");
  if (!root) return;

  // Preserve table scroll
  const tableWrap = root.querySelector("[data-preserve-scroll-key='vuln-table']");
  const savedScroll = tableWrap ? { top: tableWrap.scrollTop, left: tableWrap.scrollLeft } : null;

  setHtml(
    root,
    `<div class="vuln-layout">
      ${renderSummaryCards()}
      ${renderFiltersBar()}
      ${renderPagination()}
      ${renderTable()}
    </div>`
  );

  // Restore scroll
  if (savedScroll) {
    const tw = root.querySelector("[data-preserve-scroll-key='vuln-table']");
    if (tw) {
      tw.scrollTop = savedScroll.top;
      tw.scrollLeft = savedScroll.left;
    }
  }

  _wireVulnerabilities(root);
}

function _wireVulnerabilities(root) {
  let debounceTimer = null;

  function applyNow() {
    state.vulnerabilitiesPage = 1;
    refreshVulnerabilities();
  }
  function applyDebounced() {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(applyNow, 380);
  }

  // Summary card clicks
  root.querySelector("#vulnCardCritical")?.addEventListener("click", () => {
    state.vulnerabilitiesFilters.severity = state.vulnerabilitiesFilters.severity === "CRITICAL" ? "" : "CRITICAL";
    applyNow();
  });
  root.querySelector("#vulnCardHigh")?.addEventListener("click", () => {
    state.vulnerabilitiesFilters.severity = state.vulnerabilitiesFilters.severity === "HIGH" ? "" : "HIGH";
    applyNow();
  });
  root.querySelector("#vulnCardMedium")?.addEventListener("click", () => {
    state.vulnerabilitiesFilters.severity = state.vulnerabilitiesFilters.severity === "MEDIUM" ? "" : "MEDIUM";
    applyNow();
  });
  root.querySelector("#vulnCardLow")?.addEventListener("click", () => {
    state.vulnerabilitiesFilters.severity = state.vulnerabilitiesFilters.severity === "LOW" ? "" : "LOW";
    applyNow();
  });
  root.querySelector("#vulnCardFixed")?.addEventListener("click", () => {
    state.vulnerabilitiesFilters.status = state.vulnerabilitiesFilters.status === "fixed" ? "open" : "fixed";
    applyNow();
  });

  // Filter dropdowns
  root.querySelector("#vulnFilterSeverity")?.addEventListener("change", (e) => {
    state.vulnerabilitiesFilters.severity = e.target.value;
    applyNow();
  });
  root.querySelector("#vulnFilterKind")?.addEventListener("change", (e) => {
    state.vulnerabilitiesFilters.kind = e.target.value;
    applyNow();
  });
  root.querySelector("#vulnFilterScanner")?.addEventListener("change", (e) => {
    state.vulnerabilitiesFilters.scanner = e.target.value;
    applyNow();
  });
  root.querySelector("#vulnFilterStatus")?.addEventListener("change", (e) => {
    state.vulnerabilitiesFilters.status = e.target.value;
    applyNow();
  });
  root.querySelector("#vulnFilterRepo")?.addEventListener("input", (e) => {
    state.vulnerabilitiesFilters.repo = e.target.value;
    applyDebounced();
  });
  root.querySelector("#vulnFilterQ")?.addEventListener("input", (e) => {
    state.vulnerabilitiesFilters.q = e.target.value;
    applyDebounced();
  });
  root.querySelector("#vulnPageSize")?.addEventListener("change", (e) => {
    state.vulnerabilitiesPageSize = Number(e.target.value) || 50;
    state.vulnerabilitiesPage = 1;
    refreshVulnerabilities();
  });

  // Clear
  root.querySelector("#vulnFilterClear")?.addEventListener("click", () => {
    state.vulnerabilitiesFilters = { severity: "", kind: "", scanner: "", repo: "", q: "", status: "open", cves: [] };
    state.vulnerabilitiesPage = 1;
    refreshVulnerabilities();
  });

  // CVE chip input
  const cveInput = root.querySelector("#vulnCVEInput");
  function addCVEChip(raw) {
    const val = raw.trim().replace(/,$/, "").trim();
    if (!val) return;
    const f = state.vulnerabilitiesFilters;
    if (!Array.isArray(f.cves)) f.cves = [];
    if (!f.cves.includes(val)) {
      f.cves = [...f.cves, val];
      if (cveInput) cveInput.value = "";
      applyNow();
    } else if (cveInput) {
      cveInput.value = "";
    }
  }
  cveInput?.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === ",") {
      e.preventDefault();
      addCVEChip(cveInput.value);
    }
    if (e.key === "Backspace" && cveInput.value === "") {
      const f = state.vulnerabilitiesFilters;
      if (Array.isArray(f.cves) && f.cves.length) {
        f.cves = f.cves.slice(0, -1);
        applyNow();
      }
    }
  });
  // Also trigger on datalist selection (change event fires after selection)
  cveInput?.addEventListener("change", (e) => {
    const val = e.target.value.trim();
    const facetCVEs = state.vulnerabilitiesFacets?.cves || [];
    if (facetCVEs.includes(val)) addCVEChip(val);
  });
  // Chip remove buttons
  root.querySelectorAll(".chip-remove").forEach((btn) => {
    btn.addEventListener("click", () => {
      const c = btn.dataset.cve;
      const f = state.vulnerabilitiesFilters;
      f.cves = (f.cves || []).filter((x) => x !== c);
      applyNow();
    });
  });

  // Pagination
  root.querySelector("#vulnPageFirst")?.addEventListener("click", () => {
    state.vulnerabilitiesPage = 1;
    refreshVulnerabilities();
  });
  root.querySelector("#vulnPagePrev")?.addEventListener("click", () => {
    if (state.vulnerabilitiesPage > 1) {
      state.vulnerabilitiesPage--;
      refreshVulnerabilities();
    }
  });
  root.querySelector("#vulnPageNext")?.addEventListener("click", () => {
    if (state.vulnerabilitiesPage < state.vulnerabilitiesTotalPages) {
      state.vulnerabilitiesPage++;
      refreshVulnerabilities();
    }
  });
  root.querySelector("#vulnPageLast")?.addEventListener("click", () => {
    state.vulnerabilitiesPage = state.vulnerabilitiesTotalPages;
    refreshVulnerabilities();
  });

  // Export CSV
  root.querySelector("#vulnExportCSV")?.addEventListener("click", _exportCSV);

  // Row click → scan detail
  root.querySelectorAll(".vuln-row").forEach((row) => {
    row.addEventListener("click", (e) => {
      if (e.target.closest("a,button")) return;
      const jobId = Number(row.dataset.jobId);
      if (jobId) openScanDetailPage(jobId);
    });
  });

  // Fix approve-and-run
  root.querySelectorAll(".vuln-fix-approve-run").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const fqId = Number(btn.dataset.id);
      if (fqId) handleFixAction(fqId, "approve-run");
    });
  });
}

// ── CSV export ─────────────────────────────────────────────────────────────────

async function _exportCSV() {
  const { api } = await import("../api.js");
  const { showToast } = await import("../toast.js");
  try {
    const f = state.vulnerabilitiesFilters || {};
    const params = new URLSearchParams();
    params.set("page", "1");
    params.set("page_size", "10000");
    if (f.severity) params.set("severity", f.severity);
    if (f.kind) params.set("kind", f.kind);
    if (f.scanner) params.set("scanner", f.scanner);
    if (f.status) params.set("status", f.status);
    if (f.repo) params.set("repo", f.repo);
    if (f.q) params.set("q", f.q);
    if (Array.isArray(f.cves)) f.cves.forEach((c) => params.append("cves", c));
    const res = await api(`/api/vulnerabilities?${params.toString()}`);
    const items = Array.isArray(res?.items) ? res.items : [];
    if (!items.length) {
      showToast({ message: "No data to export.", kind: "warn" });
      return;
    }

    const cols = [
      "id",
      "scan_job_id",
      "severity",
      "kind",
      "scanner",
      "owner",
      "repo",
      "branch",
      "title",
      "file_path",
      "line",
      "message",
      "package",
      "version",
      "status",
      "first_seen",
      "fix_status",
      "fix_pr_url",
    ];
    const csvEscape = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    const lines = [cols.join(",")];
    for (const row of items) {
      lines.push(cols.map((c) => csvEscape(row[c] ?? "")).join(","));
    }
    const blob = new Blob([lines.join("\r\n")], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `vulnerabilities-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
      URL.revokeObjectURL(url);
      a.remove();
    }, 1000);
    showToast({ message: `Exported ${items.length} rows as CSV.`, kind: "success" });
  } catch (err) {
    const { showToast: st } = await import("../toast.js");
    st({ message: `CSV export failed: ${err.message}`, kind: "error" });
  }
}

// ── Navigation helper ──────────────────────────────────────────────────────────

export function openVulnerabilitiesWithFilters(filters = {}) {
  const newFilters = { severity: "", kind: "", scanner: "", repo: "", q: "", status: "open", cves: [], ...filters };
  state.vulnerabilitiesFilters = newFilters;
  state.vulnerabilitiesPage = 1;
  const p = new URLSearchParams();
  if (newFilters.severity) p.set("severity", newFilters.severity);
  if (newFilters.kind) p.set("kind", newFilters.kind);
  if (newFilters.scanner) p.set("scanner", newFilters.scanner);
  if (newFilters.repo) p.set("repo", newFilters.repo);
  if (newFilters.q) p.set("q", newFilters.q);
  if (newFilters.status && newFilters.status !== "open") p.set("status", newFilters.status);
  const qs = p.toString() ? `?${p.toString()}` : "";
  history.pushState({ view: "vulnerabilities" }, "", `/ui/vulnerabilities${qs}`);
  setView("vulnerabilities", {});
  refreshVulnerabilities();
}
