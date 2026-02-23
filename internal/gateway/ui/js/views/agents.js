import { refreshAgent, refreshStatus, setPaused, stopSweep, syncStopButtons } from "../actions.js";
import { api } from "../api.js";
// Circular imports — all usages are inside function bodies.
import { openTriggerModal } from "../modals.js";
import { state } from "../state.js";
import { escapeHtml, fmtDate, setHtml, statusClass } from "../utils.js";

export function renderAgents() {
  const root = document.getElementById("view-agents");
  const st = state.status || {};
  const agent = state.agent || {};
  const workers = [...(state.agentWorkers || [])].sort((a, b) =>
    String(a.name || "").localeCompare(String(b.name || ""))
  );
  setHtml(
    root,
    `
    <div class="grid cols-3">
      <div class="card card-ok"><div class="metric-label">Runtime</div><div class="metric-value ${st.paused ? "warn" : "ok"}">${st.paused ? "Paused" : st.running ? "Running" : "Idle"}</div></div>
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
            ${
              workers
                .map(
                  (w) => `<tr>
              <td>${escapeHtml(w.name)}</td>
              <td>${escapeHtml(w.kind)}</td>
              <td><span class="${statusClass(w.status)}">${escapeHtml(w.status)}</span></td>
              <td>${escapeHtml(w.action || "")}</td>
              <td>${escapeHtml(w.repo || "")}</td>
              <td>${w.campaign_id ? `#${w.campaign_id}` : `<span class="muted">-</span>`}</td>
              <td>${w.task_id ? `#${w.task_id}` : `<span class="muted">-</span>`}</td>
              <td>${escapeHtml(fmtDate(w.updated_at))}</td>
            </tr>`
                )
                .join("") || `<tr><td colspan="8" class="muted">No background worker activity yet.</td></tr>`
            }
          </tbody>
        </table>
      </div>
    </div>
  `
  );
  root.querySelector("#agentsTrigger")?.addEventListener("click", openTriggerModal);
  root.querySelector("#agentsStop")?.addEventListener("click", stopSweep);
  root.querySelector("#agentsPause")?.addEventListener("click", async () => setPaused(!state.status?.paused));
  root.querySelector("#agentsRefresh")?.addEventListener("click", refreshAgent);
  root.querySelector("#workersSave")?.addEventListener("click", async () => {
    const n = Number(root.querySelector("#workersInput").value);
    await api("/api/agent/workers", { method: "PUT", body: JSON.stringify({ workers: n }) });
    await refreshAgent();
    await refreshStatus();
  });
  syncStopButtons();
}
