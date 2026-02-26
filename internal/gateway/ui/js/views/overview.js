import { openScanDetailPage, refreshAll, selectJob, setPaused, stopSweep, syncStopButtons } from "../actions.js";
// Circular imports — all usages are inside function bodies, safe for ESM live bindings.
import { openTriggerModal } from "../modals.js";
import { setView } from "../router.js";
import { state } from "../state.js";
import { escapeHtml, fmtDate, setHtml, statusClass } from "../utils.js";
import { openVulnerabilitiesWithFilters } from "./vulnerabilities.js";

export function renderSweepSummaryCard() {
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
        ${reasonParts.length ? `<div class="muted">Skip reasons: ${escapeHtml(reasonParts.join(" • "))}</div>` : ""}
        <div class="muted">${workers > 0 ? `${workers} worker${workers === 1 ? "" : "s"}` : "Workers unknown"}${selectedRepos > 0 ? ` • ${selectedRepos} selected repos` : ""}${targets.length ? ` • targets: ${targets.join(", ")}` : ""}</div>
      </div>
    </div>
  `;
}

export function renderHealthPill() {
  const pill = document.getElementById("healthPill");
  const st = state.status;
  const hb = state.agentHealth;
  if (!st) {
    pill.textContent = "Health: unknown";
    pill.className = "pill pill-idle";
    return;
  }
  // Prefer heartbeat status when available; fall back to running flag.
  const hbStatus = hb?.status;
  let health, pillClass;
  if (hbStatus === "alive") {
    health = "active"; pillClass = "pill-ok";
  } else if (hbStatus === "stuck") {
    health = "stuck"; pillClass = "pill-warn";
  } else if (hbStatus === "dead") {
    health = "dead"; pillClass = "pill-danger";
  } else if (st.paused) {
    health = "paused"; pillClass = "pill-warn";
  } else if (st.running) {
    health = "ok"; pillClass = "pill-ok";
  } else {
    health = "idle"; pillClass = "pill-idle";
  }
  pill.textContent = `Health: ${health} • workers ${st.workers ?? "?"}`;
  pill.className = `pill ${pillClass}`;
}

function heartbeatCardHtml() {
  const hb = state.agentHealth;
  const st = state.status;
  if (!hb && !st) return "";
  const status = hb?.status ?? (st?.running ? "alive" : "idle");
  const dot = { alive: "🟢", idle: "⚪", stuck: "🟡", dead: "🔴" }[status] ?? "⚪";
  const label = { alive: "Active", idle: "Idle", stuck: "Stuck", dead: "Unresponsive" }[status] ?? status;
  const stuckSecs = hb?.stuck_for_seconds;
  const stuckNote = stuckSecs ? ` (${Math.round(stuckSecs / 60)}m)` : "";
  const msg = hb?.message ? `<div class="muted" style="font-size:0.8em;margin-top:4px">${escapeHtml(hb.message)}</div>` : "";
  const restartBtn = status === "stuck"
    ? `<button class="btn btn-secondary" style="margin-top:6px;font-size:0.8em" id="hbRestart">Restart Agent</button>`
    : "";
  return `
    <div class="card" style="padding:10px 14px">
      <div class="metric-label">Agent Heartbeat</div>
      <div class="metric-value" style="font-size:1.1em">${dot} ${escapeHtml(label)}${escapeHtml(stuckNote)}</div>
      ${msg}${restartBtn}
    </div>`;
}

export function renderOverview() {
  const root = document.getElementById("view-overview");
  const st = state.status || {};
  const sum = state.jobSummary || {};
  const last = state.jobs[0];
  setHtml(
    root,
    `
    <div class="grid cols-4">
      <div class="card card-ok"><div class="metric-label">Agent</div><div class="metric-value ${st.paused ? "warn" : "ok"}">${st.paused ? "Paused" : st.running ? "Ready" : "Idle"}</div></div>
      <div class="card card-accent"><div class="metric-label">Queued Repos</div><div class="metric-value">${st.queued_repos ?? 0}</div></div>
      <div class="card card-purple"><div class="metric-label">Active Jobs</div><div class="metric-value">${st.active_jobs ?? 0}</div></div>
      <div class="card card-orange"><div class="metric-label">Pending Fixes</div><div class="metric-value">${st.pending_fixes ?? 0}</div></div>
    </div>
    <div class="grid cols-1" style="margin-top:8px">
      ${heartbeatCardHtml()}
    </div>
    <div class="grid cols-4" style="margin-top:12px">
      <div class="card card-high" id="ovCardHigh" style="cursor:pointer" title="View High severity vulnerabilities"><div class="metric-label">High (Aggregate)</div><div class="metric-value high">${sum.high ?? 0}</div></div>
      <div class="card card-medium" id="ovCardMedium" style="cursor:pointer" title="View Medium severity vulnerabilities"><div class="metric-label">Medium (Aggregate)</div><div class="metric-value medium">${sum.medium ?? 0}</div></div>
      <div class="card card-low" id="ovCardLow" style="cursor:pointer" title="View Low severity vulnerabilities"><div class="metric-label">Low (Aggregate)</div><div class="metric-value low">${sum.low ?? 0}</div></div>
      <div class="card card-critical" id="ovCardCritical" style="cursor:pointer" title="View Critical severity vulnerabilities"><div class="metric-label">Critical (Aggregate)</div><div class="metric-value critical">${sum.critical ?? 0}</div></div>
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
        ${
          last
            ? `
        <div class="stack">
          <div><span class="badge ${statusClass(last.status)}">${escapeHtml(last.status)}</span></div>
          <div><strong>${escapeHtml(last.owner)}/${escapeHtml(last.repo)}</strong> <span class="muted">#${last.id}</span></div>
          <div class="muted">Started ${fmtDate(last.started_at)}</div>
          <div>Severity totals: C ${last.findings_critical} • H ${last.findings_high} • M ${last.findings_medium} • L ${last.findings_low}</div>
          <button class="btn btn-secondary" id="ovOpenLatest">Open in Scans</button>
          <button class="btn btn-secondary" id="ovOpenLatestDetail">Open Detail Page</button>
        </div>`
            : `<div class="muted">No scan jobs yet.</div>`
        }
      </div>
    </div>
    <div style="margin-top:14px">
      ${renderSweepSummaryCard()}
    </div>
  `
  );
  root.querySelector("#hbRestart")?.addEventListener("click", async () => {
    await fetch("/api/agent/trigger", { method: "POST" });
  });
  root.querySelector("#ovTrigger")?.addEventListener("click", openTriggerModal);
  root.querySelector("#ovStop")?.addEventListener("click", stopSweep);
  root.querySelector("#ovPauseResume")?.addEventListener("click", async () => {
    await setPaused(!state.status?.paused);
  });
  root.querySelector("#ovRefresh")?.addEventListener("click", refreshAll);
  root.querySelector("#ovOpenLatest")?.addEventListener("click", async () => {
    setView("scans");
    if (last) await selectJob(last.id);
  });
  root.querySelector("#ovOpenLatestDetail")?.addEventListener("click", async () => {
    if (last) await openScanDetailPage(last.id);
  });
  // Severity cards → vulnerabilities view with pre-set filter
  root
    .querySelector("#ovCardHigh")
    ?.addEventListener("click", () => openVulnerabilitiesWithFilters({ severity: "HIGH" }));
  root
    .querySelector("#ovCardMedium")
    ?.addEventListener("click", () => openVulnerabilitiesWithFilters({ severity: "MEDIUM" }));
  root
    .querySelector("#ovCardLow")
    ?.addEventListener("click", () => openVulnerabilitiesWithFilters({ severity: "LOW" }));
  root
    .querySelector("#ovCardCritical")
    ?.addEventListener("click", () => openVulnerabilitiesWithFilters({ severity: "CRITICAL" }));
  syncStopButtons();
}
