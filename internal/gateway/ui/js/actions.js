import { api } from "./api.js";
// Circular imports — all usages are inside function bodies.
import {
  closeTriggerModal,
  openCronRepoPicker,
  renderPathIgnoreModal,
  showConfirm,
  showNotice,
  showPrompt,
} from "./modals.js";
import { setView } from "./router.js";
import { state } from "./state.js";
import { handleToastForEvent, showToast } from "./toast.js";
import { severityBucket } from "./utils.js";
import { renderAgents } from "./views/agents.js";
import { renderConfig } from "./views/config.js";
import { loadCronScopeBuilders, renderCron } from "./views/cron.js";
import { renderEvents } from "./views/events.js";
import { renderHealthPill, renderOverview } from "./views/overview.js";
import { renderRemediation } from "./views/remediation.js";
import { renderScanDetailPage } from "./views/scan-detail.js";
import { renderScans } from "./views/scans.js";

/* ---- SSE / Events ---- */

export function pushEvent(evt) {
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
  if (
    [
      "worker.status",
      "campaign.started",
      "campaign.completed",
      "campaign.task.started",
      "campaign.task.progress",
      "campaign.task.completed",
      "campaign.task.failed",
      "campaign.stopped",
    ].includes(evt.type)
  ) {
    scheduleLiveRefresh({ workers: true, remediation: true, detail: true });
  }
  if (["sweep.started", "sweep.completed"].includes(evt.type)) {
    renderOverview();
    renderScans();
    scheduleLiveRefresh({ jobs: true, workers: true, detail: true });
  }
  renderEvents();
}

export function connectEvents() {
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

/* ---- Live Refresh ---- */

export function scheduleLiveRefresh(opts = {}) {
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

/* ---- Stop Button Sync ---- */

export function syncStopButtons() {
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

function syncRefreshButton() {
  const el = document.getElementById("refreshBtn");
  if (!el) return;
  el.disabled = !!state.refreshBusy;
  el.classList.toggle("is-loading", !!state.refreshBusy);
  el.textContent = state.refreshBusy ? "Refreshing" : "Refresh";
}

export function showGlobalLoading(message = "Loading…") {
  state.globalLoadingCount = Number(state.globalLoadingCount || 0) + 1;
  state.globalLoadingMessage = message || "Loading…";
  const overlay = document.getElementById("globalLoadingOverlay");
  const label = document.getElementById("globalLoadingMessage");
  if (label) label.textContent = state.globalLoadingMessage;
  if (overlay) overlay.classList.remove("hidden");
}

export function hideGlobalLoading() {
  state.globalLoadingCount = Math.max(0, Number(state.globalLoadingCount || 0) - 1);
  if (state.globalLoadingCount > 0) return;
  const overlay = document.getElementById("globalLoadingOverlay");
  if (overlay) overlay.classList.add("hidden");
}

/* ---- Status ---- */

export async function refreshStatus() {
  state.status = await api("/api/status");
  renderHealthPill();
}

/* ---- Jobs ---- */

function reconcileSelectedJobs() {
  const visible = new Set((state.jobs || []).map((j) => j.id));
  const next = {};
  for (const rawId of Object.keys(state.selectedScanJobIds || {})) {
    const id = Number(rawId);
    if (visible.has(id)) next[id] = true;
  }
  state.selectedScanJobIds = next;
}

export async function refreshJobs() {
  state.scansLoading = true;
  renderScans();
  try {
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
    // Do not clear selected job just because it is not present on the current paginated jobs page.
    // The scan may still exist and be open in `/ui/scans/:id`; absence here only means "not on this page".
  } finally {
    state.scansLoading = false;
    renderScans();
    renderOverview();
  }
}

export async function loadSelectedJobFindings() {
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
      kinds: [...new Set(state.selectedJobFindings.map((f) => String(f.kind || "")).filter(Boolean))].sort(),
      scanners: [...new Set(state.selectedJobFindings.map((f) => String(f.scanner || "")).filter(Boolean))].sort(),
      severities: [...new Set(state.selectedJobFindings.map((f) => severityBucket(f.severity)).filter(Boolean))],
    };
    state.selectedJobFindingsSeverityTotals = null;
  }
}

export async function loadSelectedJobRemediationRuns() {
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

export async function loadSelectedJobCommitHistory() {
  if (!state.selectedJobId) return;
  const params = new URLSearchParams();
  params.set("limit", "25");
  try {
    const res = await api(`/api/jobs/${state.selectedJobId}/history?${params.toString()}`);
    state.selectedJobCommitHistory = Array.isArray(res?.history) ? res.history : [];
    state.selectedJobCommitHistoryLookup = res?.lookup || null;
  } catch (_) {
    state.selectedJobCommitHistory = [];
    state.selectedJobCommitHistoryLookup = null;
  }
}

export async function selectJob(id, opts = {}) {
  const showLoading = !!opts.showLoading;
  const switchingJobs = Number(state.selectedJobId || 0) !== Number(id || 0);
  const hasExistingDetail = !!state.selectedJob;
  const shouldShowInlineLoading = switchingJobs || !hasExistingDetail;
  const shouldShowBackgroundSync = !shouldShowInlineLoading;
  if (showLoading) showGlobalLoading("Loading scan detail…");
  state.selectedJobLoading = shouldShowInlineLoading;
  state.selectedJobSyncing = shouldShowBackgroundSync;
  if (state.view === "scan-detail" && shouldShowInlineLoading) renderScanDetailPage();
  if (state.view === "scan-detail" && shouldShowBackgroundSync) renderScanDetailPage();
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
  try {
    state.selectedJob = await api(`/api/jobs/${id}`);
    await loadSelectedJobCommitHistory();
    state.selectedJobScanners = await api(`/api/jobs/${id}/scanners`);
    await loadSelectedJobFindings();
    state.selectedJobFixes = await api(`/api/jobs/${id}/fixes`);
    await loadSelectedJobRemediationRuns();
    renderScans();
    if (state.view === "scan-detail") renderScanDetailPage();
  } finally {
    state.selectedJobLoading = false;
    state.selectedJobSyncing = false;
    if (state.view === "scan-detail") renderScanDetailPage();
    if (showLoading) hideGlobalLoading();
  }
}

export function clearSelectedJob() {
  state.selectedJobId = null;
  state.selectedJob = null;
  state.selectedJobCommitHistory = [];
  state.selectedJobCommitHistoryLookup = null;
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
  state.selectedJobSyncing = false;
}

export async function deleteOneScanJob(id) {
  state.scansActionBusy = `delete:${id}`;
  renderScans();
  const job = (state.jobs || []).find((j) => j.id === id);
  const label = job ? `${job.owner}/${job.repo}` : `#${id}`;
  if (
    !(await showConfirm({
      title: "Delete Scan Job",
      message: `Delete scan job #${id} (${label})? This removes stored findings and raw outputs for the job.`,
      confirmLabel: "Delete",
    }))
  ) {
    state.scansActionBusy = "";
    renderScans();
    return;
  }
  try {
    await api(`/api/jobs/${id}`, { method: "DELETE" });
    delete state.selectedScanJobIds[id];
    await refreshJobs();
  } catch (err) {
    showNotice("Delete Failed", err.message);
  } finally {
    state.scansActionBusy = "";
    renderScans();
  }
}

export async function deleteSelectedScanJobs() {
  state.scansActionBusy = "delete-selected";
  renderScans();
  const ids = Object.keys(state.selectedScanJobIds || {})
    .map(Number)
    .filter(Boolean)
    .sort((a, b) => a - b);
  if (ids.length === 0) {
    state.scansActionBusy = "";
    renderScans();
    return;
  }
  if (
    !(await showConfirm({
      title: "Delete Selected Scan Jobs",
      message: `Delete ${ids.length} selected scan job${ids.length === 1 ? "" : "s"}? This cannot be undone.`,
      confirmLabel: "Delete Selected",
    }))
  ) {
    state.scansActionBusy = "";
    renderScans();
    return;
  }
  try {
    const res = await api("/api/jobs", { method: "DELETE", body: JSON.stringify({ ids }) });
    if (Array.isArray(res.deleted_ids)) {
      for (const id of res.deleted_ids) delete state.selectedScanJobIds[id];
    } else {
      state.selectedScanJobIds = {};
    }
    await refreshJobs();
    if (Array.isArray(res.not_found_ids) && res.not_found_ids.length > 0) {
      showNotice(
        "Delete Completed",
        `Deleted ${res.deleted_count || 0} jobs. Not found: ${res.not_found_ids.join(", ")}.`
      );
    }
  } catch (err) {
    showNotice("Bulk Delete Failed", err.message);
  } finally {
    state.scansActionBusy = "";
    renderScans();
  }
}

export async function deleteAllScanJobs() {
  state.scansActionBusy = "delete-all";
  renderScans();
  const count = (state.jobs || []).length;
  if (count === 0) {
    state.scansActionBusy = "";
    renderScans();
    return;
  }
  const confirmation = await showPrompt({
    title: "Delete All Scan Jobs",
    message: `Delete ALL ${count} scan jobs and their stored findings/raw outputs? Type DELETE ALL to confirm.`,
    placeholder: "DELETE ALL",
    confirmLabel: "Delete All",
  });
  if (confirmation !== "DELETE ALL") {
    state.scansActionBusy = "";
    renderScans();
    return;
  }
  try {
    await api("/api/jobs", { method: "DELETE", body: JSON.stringify({ delete_all: true }) });
    state.selectedScanJobIds = {};
    clearSelectedJob();
    await refreshJobs();
  } catch (err) {
    showNotice("Delete All Failed", err.message);
  } finally {
    state.scansActionBusy = "";
    renderScans();
  }
}

export async function openScanDetailPage(id, opts = {}) {
  await selectJob(id, { preserveFindingsState: false, showLoading: opts.showLoading !== false });
  setView("scan-detail", { pushHistory: opts.pushHistory !== false });
  renderScanDetailPage();
}

export async function openScanDetailByLookup({ source, repo, branch, commit }, opts = {}) {
  const showLoading = opts.showLoading !== false;
  if (showLoading) showGlobalLoading("Resolving scan from repo/branch…");
  const params = new URLSearchParams();
  if (source) params.set("source", source);
  if (repo) params.set("repo", repo);
  if (branch) params.set("branch", branch);
  if (commit) params.set("commit", commit);
  try {
    const res = await api(`/api/jobs/lookup?${params.toString()}`);
    const id = Number(res?.job?.id || 0);
    if (!Number.isFinite(id) || id <= 0) {
      throw new Error("No matching scan job found");
    }
    await openScanDetailPage(id, { ...opts, showLoading: false });
  } finally {
    if (showLoading) hideGlobalLoading();
  }
}

/* ---- Sweep Actions ---- */

export async function triggerSweep() {
  try {
    await api("/api/agent/trigger", { method: "POST", body: "{}" });
    await refreshStatus();
  } catch (err) {
    showNotice("Trigger Failed", err.message);
  }
}

export async function triggerSweepWithOptions({ scanTargets, workers, selectedRepos, forceScan }) {
  try {
    const payload = {};
    if (Array.isArray(scanTargets) && scanTargets.length > 0) payload.scan_targets = scanTargets;
    if (workers && Number(workers) > 0) payload.workers = Number(workers);
    if (Array.isArray(selectedRepos) && selectedRepos.length > 0) payload.selected_repos = selectedRepos;
    if (forceScan) payload.force_scan = true;
    await api("/api/agent/trigger", { method: "POST", body: JSON.stringify(payload) });
    showToast({
      title: "Trigger Submitted",
      message: "Requested a new scan sweep. Watch the Scans page for live updates.",
      kind: "info",
      timeoutMs: 2500,
    });
    closeTriggerModal();
    await refreshStatus();
    await refreshAgent();
    await refreshJobs();
  } catch (err) {
    showNotice("Trigger Failed", err.message);
  }
}

export async function stopSweep() {
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

export async function setPaused(paused) {
  try {
    await api(paused ? "/api/agent/pause" : "/api/agent/resume", { method: "POST", body: "{}" });
    await refreshStatus();
    await refreshAgent();
  } catch (err) {
    showNotice("Agent Update Failed", err.message);
  }
}

/* ---- Cron ---- */

function parseCronMultiline(raw) {
  return String(raw || "")
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
}

function parseRepoLine(line) {
  const idx = line.indexOf(":");
  if (idx <= 0) throw new Error(`Invalid repo selector "${line}" (expected provider:owner/repo)`);
  const providerHost = line.slice(0, idx).trim();
  const rest = line.slice(idx + 1).trim();
  const slash = rest.lastIndexOf("/");
  if (slash <= 0 || slash === rest.length - 1) {
    throw new Error(`Invalid repo selector "${line}" (expected provider:owner/repo)`);
  }
  let provider = providerHost;
  let host = "";
  const at = providerHost.indexOf("@");
  if (at > 0) {
    provider = providerHost.slice(0, at).trim();
    host = providerHost.slice(at + 1).trim();
  }
  return {
    provider,
    host,
    owner: rest.slice(0, slash).trim(),
    name: rest.slice(slash + 1).trim(),
  };
}

function parseOwnerLine(line) {
  const idx = line.indexOf(":");
  if (idx <= 0) throw new Error(`Invalid owner selector "${line}" (expected provider:owner)`);
  const providerHost = line.slice(0, idx).trim();
  const owner = line.slice(idx + 1).trim();
  if (!owner) throw new Error(`Invalid owner selector "${line}" (missing owner)`);
  let provider = providerHost;
  let host = "";
  const at = providerHost.indexOf("@");
  if (at > 0) {
    provider = providerHost.slice(0, at).trim();
    host = providerHost.slice(at + 1).trim();
  }
  return { provider, host, owner };
}

function readCronForm() {
  const root = document.getElementById("view-cron");
  if (!root) throw new Error("cron view not mounted");
  const editingId = Number(root.querySelector("#cronId")?.value || 0);
  const name = root.querySelector("#cronName").value.trim();
  const expr = root.querySelector("#cronExpr").value.trim();
  const mode = root.querySelector("#cronMode").value.trim();
  const repoLines = parseCronMultiline(root.querySelector("#cronRepos").value);
  const ownerLines = parseCronMultiline(root.querySelector("#cronOwners").value);
  const ownerPrefixLines = parseCronMultiline(root.querySelector("#cronOwnerPrefixes").value);
  const targets = [...root.querySelectorAll("input[type='checkbox'][data-cron-target]:checked")].map(
    (el) => el.dataset.cronTarget
  );
  const enabled = !!root.querySelector("#cronEnabled")?.checked;
  if (!name || !expr) {
    throw new Error("Name and expression are required.");
  }
  const selectedRepos = repoLines.map(parseRepoLine);
  const owners = ownerLines.map(parseOwnerLine);
  const ownerPrefixes = ownerPrefixLines.map(parseOwnerLine);
  const scope = {
    targets,
    mode,
    repos: selectedRepos,
    owners,
    owner_prefixes: ownerPrefixes,
  };
  return {
    root,
    editingId,
    payload: {
      name,
      expr,
      mode,
      enabled,
      scope_json: JSON.stringify(scope),
      targets: JSON.stringify(targets),
      selected_repos: JSON.stringify(selectedRepos),
    },
  };
}

export function resetCronForm() {
  const root = document.getElementById("view-cron");
  if (!root) return;
  root.querySelector("#cronId").value = "";
  root.querySelector("#cronName").value = "";
  root.querySelector("#cronExpr").value = "";
  root.querySelector("#cronExprPreset").value = "daily";
  root.querySelector("#cronExprTZ").value = "browser";
  root.querySelector("#cronExprTime").value = "02:00";
  root.querySelector("#cronExprMinute").value = "0";
  root.querySelector("#cronExprWeekday").value = "1";
  root.querySelector("#cronExprMonthday").value = "1";
  root.querySelector("#cronExprInterval").value = "1";
  root.querySelector("#cronMode").value = "";
  root.querySelectorAll("input[type='checkbox'][data-cron-target]").forEach((cb) => {
    cb.checked = false;
  });
  root.querySelector("#cronRepos").value = "";
  root.querySelector("#cronOwners").value = "";
  root.querySelector("#cronOwnerPrefixes").value = "";
  root.querySelector("#cronEnabled").checked = true;
  const adv = root.querySelector("#cronAdvancedScope");
  if (adv) adv.open = false;
  loadCronScopeBuilders();
  const saveBtn = root.querySelector("#cronCreate");
  if (saveBtn) saveBtn.textContent = "Create";
}

export function editCron(id) {
  const root = document.getElementById("view-cron");
  const sched = (state.schedules || []).find((s) => Number(s.id) === Number(id));
  if (!root || !sched) return;
  root.querySelector("#cronId").value = String(sched.id);
  root.querySelector("#cronName").value = sched.name || "";
  root.querySelector("#cronExpr").value = sched.expr || "";
  root.querySelector("#cronExprPreset").value = "custom";
  root.querySelector("#cronMode").value = sched.mode || "";
  let scope = null;
  try {
    scope = sched.scope_json ? JSON.parse(sched.scope_json) : null;
  } catch {
    scope = null;
  }
  if (scope && Array.isArray(scope.targets)) {
    const selected = new Set(scope.targets.map((v) => String(v)));
    root.querySelectorAll("input[type='checkbox'][data-cron-target]").forEach((cb) => {
      cb.checked = selected.has(cb.dataset.cronTarget);
    });
  } else {
    try {
      const targets = JSON.parse(sched.targets || "[]");
      const selected = new Set((Array.isArray(targets) ? targets : []).map((v) => String(v)));
      root.querySelectorAll("input[type='checkbox'][data-cron-target]").forEach((cb) => {
        cb.checked = selected.has(cb.dataset.cronTarget);
      });
    } catch {
      root.querySelectorAll("input[type='checkbox'][data-cron-target]").forEach((cb) => {
        cb.checked = false;
      });
    }
  }
  const repos = Array.isArray(scope?.repos)
    ? scope.repos
    : (() => {
        try {
          const parsed = JSON.parse(sched.selected_repos || "[]");
          return Array.isArray(parsed) ? parsed : [];
        } catch {
          return [];
        }
      })();
  root.querySelector("#cronRepos").value = repos
    .map((r) => `${r.provider || ""}${r.host ? `@${r.host}` : ""}:${r.owner || ""}/${r.name || ""}`)
    .join("\n");
  root.querySelector("#cronOwners").value = Array.isArray(scope?.owners)
    ? scope.owners.map((o) => `${o.provider || ""}${o.host ? `@${o.host}` : ""}:${o.owner || ""}`).join("\n")
    : "";
  root.querySelector("#cronOwnerPrefixes").value = Array.isArray(scope?.owner_prefixes)
    ? scope.owner_prefixes.map((o) => `${o.provider || ""}${o.host ? `@${o.host}` : ""}:${o.owner || ""}`).join("\n")
    : "";
  const hasAdvancedScope =
    (root.querySelector("#cronRepos").value || "").trim() !== "" ||
    (root.querySelector("#cronOwners").value || "").trim() !== "" ||
    (root.querySelector("#cronOwnerPrefixes").value || "").trim() !== "";
  const adv = root.querySelector("#cronAdvancedScope");
  if (adv) adv.open = hasAdvancedScope;
  loadCronScopeBuilders();
  root.querySelector("#cronEnabled").checked = sched.enabled !== false;
  const saveBtn = root.querySelector("#cronCreate");
  if (saveBtn) saveBtn.textContent = "Update";
}

export async function browseCronRepos() {
  const root = document.getElementById("view-cron");
  if (!root) return;
  const currentTargets = [...root.querySelectorAll("input[type='checkbox'][data-cron-target]:checked")].map(
    (el) => el.dataset.cronTarget
  );
  let selectedRepos = [];
  try {
    selectedRepos = parseCronMultiline(root.querySelector("#cronRepos").value).map(parseRepoLine);
  } catch (err) {
    showNotice("Invalid Repo Entries", err.message);
    return;
  }
  const result = await openCronRepoPicker({ targets: currentTargets, selectedRepos });
  if (!result) return;
  const nextTargets = new Set((result.targets || []).map((v) => String(v)));
  root.querySelectorAll("input[type='checkbox'][data-cron-target]").forEach((cb) => {
    cb.checked = nextTargets.has(cb.dataset.cronTarget);
  });
  root.querySelector("#cronRepos").value = (result.selectedRepos || [])
    .map((r) => `${r.provider || ""}${r.host ? `@${r.host}` : ""}:${r.owner || ""}/${r.name || ""}`)
    .join("\n");
  loadCronScopeBuilders();
}

export async function createCron() {
  state.cronActionBusy = "create";
  renderCron();
  let form;
  try {
    form = readCronForm();
  } catch (err) {
    state.cronActionBusy = "";
    renderCron();
    showNotice("Invalid Schedule", err.message);
    return;
  }
  const { root, editingId, payload } = form;
  try {
    if (editingId > 0) {
      await api(`/api/schedules/${editingId}`, { method: "PUT", body: JSON.stringify(payload) });
    } else {
      await api("/api/schedules", { method: "POST", body: JSON.stringify(payload) });
    }
    resetCronForm();
    await refreshCron();
  } catch (err) {
    showNotice(editingId > 0 ? "Update Schedule Failed" : "Create Schedule Failed", err.message);
    if (root) root.querySelector("#cronId").value = editingId > 0 ? String(editingId) : "";
  } finally {
    state.cronActionBusy = "";
    renderCron();
  }
}

export async function triggerCron(id) {
  state.cronActionBusy = `trigger:${id}`;
  renderCron();
  try {
    await api(`/api/schedules/${id}/trigger`, { method: "POST", body: "{}" });
    await refreshCron();
  } catch (err) {
    showNotice("Trigger Schedule Failed", err.message);
  } finally {
    state.cronActionBusy = "";
    renderCron();
  }
}

export async function deleteCron(id) {
  state.cronActionBusy = `delete:${id}`;
  renderCron();
  if (!(await showConfirm({ title: "Delete Schedule", message: `Delete schedule #${id}?`, confirmLabel: "Delete" }))) {
    state.cronActionBusy = "";
    renderCron();
    return;
  }
  try {
    await api(`/api/schedules/${id}`, { method: "DELETE" });
    await refreshCron();
  } catch (err) {
    showNotice("Delete Schedule Failed", err.message);
  } finally {
    state.cronActionBusy = "";
    renderCron();
  }
}

export async function refreshCron() {
  const preserve = state.cronActionBusy;
  if (!preserve) {
    state.cronActionBusy = "refresh";
    renderCron();
  }
  try {
    state.schedules = await api("/api/schedules");
    renderCron();
  } finally {
    if (!preserve) {
      state.cronActionBusy = "";
      renderCron();
    }
  }
}

/* ---- Agent ---- */

export async function refreshAgent() {
  state.agent = await api("/api/agent");
  renderAgents();
}

export async function refreshAgentWorkers() {
  state.agentWorkers = await api("/api/agent/workers");
  renderAgents();
  if (state.view === "scans") renderScans();
  if (state.view === "scan-detail") renderScanDetailPage();
  if (state.view === "remediation") renderRemediation();
}

/* ---- Fix Queue ---- */

export async function handleFixAction(id, action) {
  state.fixActionBusyKey = `${action}:${id}`;
  if (state.view === "scan-detail") renderScanDetailPage();
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
      showNotice(
        "PR Processing Started",
        "The fix was approved and PR processing has been triggered. Refresh or wait for SSE updates to see PR status."
      );
    }
  } catch (err) {
    showNotice("Fix Action Failed", err.message);
  } finally {
    state.fixActionBusyKey = "";
    if (state.view === "scan-detail") renderScanDetailPage();
  }
}

/* ---- Remediation ---- */

export async function refreshRemediation() {
  state.remediationCampaigns = await api("/api/remediation/campaigns");
  const ids = new Set((state.remediationCampaigns || []).map((c) => c.id));
  if (state.remediationSelectedCampaignId && !ids.has(state.remediationSelectedCampaignId)) {
    state.remediationSelectedCampaignId = null;
  }
  if (!state.remediationSelectedCampaignId && state.remediationCampaigns.length > 0) {
    state.remediationSelectedCampaignId = state.remediationCampaigns[0].id;
  }
  if (state.remediationSelectedCampaignId) {
    state.remediationCampaignTasks = await api(
      `/api/remediation/campaigns/${state.remediationSelectedCampaignId}/tasks`
    );
  } else {
    state.remediationCampaignTasks = [];
  }
  if (!state.remediationRepoSuggestionsLoaded) {
    refreshRemediationRepoSuggestions();
  }
  renderRemediation();
}

export async function refreshRemediationTasks(campaignID) {
  if (!campaignID) {
    state.remediationCampaignTasks = [];
    renderRemediation();
    return;
  }
  state.remediationCampaignTasks = await api(`/api/remediation/campaigns/${campaignID}/tasks`);
  renderRemediation();
}

export async function refreshRemediationRepoSuggestions(force = false) {
  if (state.remediationRepoSuggestionsLoading) return;
  if (!force && state.remediationRepoSuggestionsLoaded) return;
  state.remediationRepoSuggestionsLoading = true;
  try {
    const res = await api("/api/jobs/repos?page=1&page_size=500");
    state.remediationRepoSuggestions = Array.isArray(res?.items) ? res.items : [];
    state.remediationRepoSuggestionsLoaded = true;
  } catch (err) {
    showNotice("Repo Suggestions Failed", err.message);
  } finally {
    state.remediationRepoSuggestionsLoading = false;
    if (state.view === "remediation") renderRemediation();
  }
}

export async function createRemediationCampaign() {
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
  const repos = [...new Set((draft.selectedRepos || []).map((s) => String(s || "").trim()).filter(Boolean))];
  const badRepo = repos.find((r) => !/^[^/\s]+\/[^/\s]+$/.test(r));
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
    if (res?.id) state.remediationSelectedCampaignId = Number(res.id);
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

export async function startRemediationCampaign(id) {
  try {
    await api(`/api/remediation/campaigns/${id}/start`, { method: "POST", body: "{}" });
    showToast({
      title: "Campaign Started",
      message: `Campaign #${id} is now running.`,
      kind: "success",
      timeoutMs: 2800,
    });
    state.remediationSelectedCampaignId = id;
    await refreshRemediation();
    await refreshAgentWorkers();
  } catch (err) {
    showNotice("Start Campaign Failed", err.message);
  }
}

export async function stopRemediationCampaign(id) {
  try {
    await api(`/api/remediation/campaigns/${id}/stop`, { method: "POST", body: "{}" });
    showToast({ title: "Campaign Stopped", message: `Campaign #${id} was stopped.`, kind: "warn", timeoutMs: 2800 });
    await refreshRemediation();
    await refreshAgentWorkers();
  } catch (err) {
    showNotice("Stop Campaign Failed", err.message);
  }
}

export async function launchReviewCampaignForSelectedScan() {
  const job = state.selectedJob;
  if (!job) return;
  if (!state.agent?.ai_enabled) {
    showNotice("AI Not Enabled", "Configure an AI provider in Config before launching an AI review campaign.");
    return;
  }
  let forceCreate = false;
  try {
    const runsRes = await api(`/api/jobs/${job.id}/remediation?page=1&page_size=25`);
    const runs = Array.isArray(runsRes?.items) ? runsRes.items : Array.isArray(runsRes) ? runsRes : [];
    const activeRuns = runs.filter((r) => ["draft", "running"].includes(String(r.campaign_status || "").toLowerCase()));
    if (activeRuns.length > 0) {
      const labels = activeRuns
        .slice(0, 3)
        .map((r) => `#${Number(r.campaign_id || 0)} (${String(r.campaign_status || "").toLowerCase() || "active"})`)
        .join(", ");
      const confirmed = await showConfirm({
        title: "Existing AI Review Campaign Found",
        message: `Scan #${job.id} already has an active review campaign (${labels}${activeRuns.length > 3 ? ", ..." : ""}). Launch another anyway?`,
        confirmLabel: "Force Launch",
      });
      if (!confirmed) return;
      forceCreate = true;
    }
  } catch (_) {
    // Best effort pre-check; backend also enforces duplicate prevention unless force=true.
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
        force: forceCreate,
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

  // Campaign created — follow-up UI refreshes; don't propagate errors as launch failures.
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

export async function stopReviewCampaignForSelectedScan() {
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

/* ---- Path Ignore Rules ---- */

export async function refreshPathIgnoreRules() {
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

export async function createPathIgnoreRule(payload) {
  try {
    await api("/api/findings/path-ignores", { method: "POST", body: JSON.stringify(payload || {}) });
    await refreshPathIgnoreRules();
    if (state.selectedJobId) {
      await loadSelectedJobFindings();
      renderScanDetailPage();
    }
    showToast({
      title: "Path Ignore Added",
      message: "Findings were reloaded with the new ignore rule applied.",
      kind: "success",
      timeoutMs: 2600,
    });
  } catch (err) {
    showNotice("Add Ignore Rule Failed", err.message);
  }
}

export async function updatePathIgnoreRule(id, payload) {
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

export async function deletePathIgnoreRule(id) {
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

/* ---- Config ---- */

export async function refreshConfig() {
  const payload = await api("/api/config");
  state.configPath = payload.path || "";
  state.config = payload.config || {};
  renderConfig();
}

/* ---- Refresh All ---- */

export async function refreshAll() {
  if (state.refreshBusy) return;
  state.refreshBusy = true;
  syncRefreshButton();
  showGlobalLoading("Refreshing dashboard…");
  try {
    await Promise.all([
      refreshStatus(),
      refreshJobs(),
      refreshCron(),
      refreshAgent(),
      refreshAgentWorkers(),
      refreshRemediation(),
    ]);
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
  } finally {
    hideGlobalLoading();
    state.refreshBusy = false;
    syncRefreshButton();
  }
  renderOverview();
  renderScans();
  renderScanDetailPage();
  renderCron();
  renderAgents();
  renderEvents();
}
