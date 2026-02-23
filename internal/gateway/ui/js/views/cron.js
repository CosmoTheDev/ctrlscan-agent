// Circular imports — all usages are inside function bodies.
import { createCron, deleteCron, refreshCron, triggerCron } from "../actions.js";
import { state } from "../state.js";
import { escapeHtml, fmtDate, setHtml } from "../utils.js";

export function renderCron() {
  const root = document.getElementById("view-cron");
  const rows = state.schedules || [];
  setHtml(
    root,
    `
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
            ${
              rows
                .map(
                  (s) => `
              <tr>
                <td>#${s.id}</td>
                <td>${escapeHtml(s.name)}</td>
                <td><code>${escapeHtml(s.expr)}</code></td>
                <td>${escapeHtml(fmtDate(s.last_run_at))}</td>
                <td class="row-actions">
                  <button class="btn btn-secondary" data-action="trigger" data-id="${s.id}">Trigger</button>
                  <button class="btn btn-danger" data-action="delete" data-id="${s.id}">Delete</button>
                </td>
              </tr>`
                )
                .join("") || `<tr><td colspan="5" class="muted">No schedules configured.</td></tr>`
            }
          </tbody>
        </table>
      </div>
    </div>
  `
  );
  root.querySelector("#cronRefresh")?.addEventListener("click", refreshCron);
  root.querySelector("#cronCreate")?.addEventListener("click", createCron);
  root
    .querySelectorAll("[data-action='trigger']")
    .forEach((btn) => btn.addEventListener("click", () => triggerCron(Number(btn.dataset.id))));
  root
    .querySelectorAll("[data-action='delete']")
    .forEach((btn) => btn.addEventListener("click", () => deleteCron(Number(btn.dataset.id))));
}
