// Circular imports — all usages are inside function bodies.
import {
  createRemediationCampaign,
  openScanDetailPage,
  refreshRemediation,
  refreshRemediationRepoSuggestions,
  refreshRemediationTasks,
  startRemediationCampaign,
  stopRemediationCampaign,
} from "../actions.js";
import { state } from "../state.js";
import { escapeHtml, fmtDate, setHtml, statusClass } from "../utils.js";

function capturePreservedScroll(root) {
  if (!root) return {};
  const saved = {};
  root.querySelectorAll("[data-preserve-scroll-key]").forEach((el) => {
    const key = String(el.getAttribute("data-preserve-scroll-key") || "").trim();
    if (!key) return;
    saved[key] = { top: Number(el.scrollTop || 0), left: Number(el.scrollLeft || 0) };
  });
  return saved;
}

function restorePreservedScroll(root, saved) {
  if (!root || !saved) return;
  root.querySelectorAll("[data-preserve-scroll-key]").forEach((el) => {
    const key = String(el.getAttribute("data-preserve-scroll-key") || "").trim();
    if (!key || !saved[key]) return;
    el.scrollTop = Number(saved[key].top || 0);
    el.scrollLeft = Number(saved[key].left || 0);
  });
}

function getScannedRepoLabel(r) {
  const owner = String(r?.owner || "").trim();
  const repo = String(r?.repo || "").trim();
  return owner && repo ? `${owner}/${repo}` : "";
}

function getRemediationRepoSuggestionsFiltered() {
  const q = String(state.remediationRepoFilter || "")
    .trim()
    .toLowerCase();
  const all = Array.isArray(state.remediationRepoSuggestions) ? state.remediationRepoSuggestions : [];
  const selected = new Set((state.remediationDraft?.selectedRepos || []).map((v) => String(v).toLowerCase()));
  let items = all.filter((r) => !selected.has(getScannedRepoLabel(r).toLowerCase()));
  if (q) items = items.filter((r) => getScannedRepoLabel(r).toLowerCase().includes(q));
  return items.slice(0, 12);
}

function formatAIOrigin(r) {
  const provider = String(r?.ai_provider || "").trim();
  const model = String(r?.ai_model || "").trim();
  const endpoint = String(r?.ai_endpoint || "").trim();
  const endpointLabel = endpoint ? endpoint.replace(/^https?:\/\//i, "").replace(/\/v1\/?$/i, "") : "";
  const pm = [provider, model].filter(Boolean).join(" / ");
  if (pm && endpointLabel) return `${pm} @ ${endpointLabel}`;
  if (pm) return pm;
  if (endpointLabel) return endpointLabel;
  return "-";
}

function formatProgress(r) {
  const pct = Number(r?.ai_progress_percent || 0);
  const current = Number(r?.ai_progress_current || 0);
  const total = Number(r?.ai_progress_total || 0);
  const phase = String(r?.ai_progress_phase || "").trim();
  const note = String(r?.ai_progress_note || "").trim();
  const parts = [];
  if (phase) parts.push(phase);
  if (total > 0) parts.push(`${current}/${total}`);
  if (pct > 0 || total > 0) parts.push(`${pct}%`);
  let out = parts.join(" • ");
  if (!out && !note) return "-";
  if (note) out = out ? `${out} — ${note}` : note;
  return out;
}

export function renderRemediation() {
  const root = document.getElementById("view-remediation");
  if (!root) return;
  const preservedScroll = capturePreservedScroll(root);
  const campaigns = state.remediationCampaigns || [];
  const draft = state.remediationDraft || {};
  let selected = campaigns.find((c) => c.id === state.remediationSelectedCampaignId) || null;
  if (!selected && campaigns.length > 0) {
    selected = campaigns[0];
    state.remediationSelectedCampaignId = selected.id;
  }
  const tasks = state.remediationCampaignTasks || [];
  const repoSuggest = getRemediationRepoSuggestionsFiltered();
  const selectedRepos = Array.isArray(draft.selectedRepos) ? draft.selectedRepos : [];
  setHtml(
    root,
    `
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
              <div class="table-wrap" data-preserve-scroll-key="remediation:repo-suggestions" style="max-height:180px; margin-top:8px">
                <table>
                  <thead><tr><th>Repo</th><th>Provider</th><th>Action</th></tr></thead>
                  <tbody>
                    ${
                      repoSuggest
                        .map(
                          (r) => `<tr>
                      <td>${escapeHtml(getScannedRepoLabel(r))}</td>
                      <td>${escapeHtml(r.provider || "")}</td>
                      <td><button class="btn btn-secondary" data-rem-repo-add="${escapeHtml(getScannedRepoLabel(r))}">Add</button></td>
                    </tr>`
                        )
                        .join("") ||
                      `<tr><td colspan="3" class="muted">${state.remediationRepoSuggestionsLoaded ? "No matching scanned repos." : "Repo suggestions not loaded yet."}</td></tr>`
                    }
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
          <div class="table-wrap" data-preserve-scroll-key="remediation:workers">
            <table>
              <thead><tr><th>Name</th><th>Kind</th><th>Status</th><th>Action</th><th>Repo</th><th>Updated</th></tr></thead>
              <tbody>
                ${
                  (state.agentWorkers || [])
                    .map(
                      (w) => `<tr>
                  <td>${escapeHtml(w.name)}</td>
                  <td>${escapeHtml(w.kind)}</td>
                  <td><span class="${statusClass(w.status)}">${escapeHtml(w.status)}</span></td>
                  <td>${escapeHtml(w.action || "")}</td>
                  <td>${escapeHtml(w.repo || "")}</td>
                  <td>${escapeHtml(fmtDate(w.updated_at))}</td>
                </tr>`
                    )
                    .join("") || `<tr><td colspan="6" class="muted">No worker status yet.</td></tr>`
                }
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <div class="split">
        <div class="card">
          <h3>Campaigns</h3>
          <div class="table-wrap" data-preserve-scroll-key="remediation:campaigns">
            <table>
              <thead><tr><th>ID</th><th>Name</th><th>Status</th><th>Mode</th><th>Tasks</th><th>Actions</th></tr></thead>
              <tbody>
                ${
                  campaigns
                    .map(
                      (
                        c
                      ) => `<tr data-rem-campaign-id="${c.id}" style="cursor:pointer; ${selected && selected.id === c.id ? "background:rgba(79,140,255,.08)" : ""}">
                  <td>#${c.id}</td>
                  <td>${escapeHtml(c.name)}</td>
                  <td><span class="${statusClass(c.status)}">${escapeHtml(c.status)}</span></td>
                  <td>${escapeHtml(c.mode)}</td>
                  <td>${c.completed_tasks}/${c.total_tasks} <span class="muted">(P:${c.pending_tasks} R:${c.running_tasks} F:${c.failed_tasks})</span></td>
                  <td class="row-actions">
                    <button class="btn btn-secondary" data-rem-start="${c.id}" ${c.status === "running" ? "disabled" : ""}>Start</button>
                    <button class="btn btn-danger" data-rem-stop="${c.id}" ${["running", "draft"].includes(String(c.status)) ? "" : "disabled"}>Stop</button>
                  </td>
                </tr>`
                    )
                    .join("") || `<tr><td colspan="6" class="muted">No remediation campaigns yet.</td></tr>`
                }
              </tbody>
            </table>
          </div>
        </div>

        <div class="card">
          <h3>Campaign Tasks ${selected ? `#${selected.id}` : ""}</h3>
          <div class="table-wrap" data-preserve-scroll-key="remediation:tasks">
            <table>
              <thead><tr><th>ID</th><th>Repo</th><th>Scan Job</th><th>Status</th><th>AI Model</th><th>Progress</th><th>Worker</th><th>Message</th></tr></thead>
              <tbody>
                ${
                  tasks
                    .map(
                      (t) => `<tr data-rem-task-scan-job-id="${Number(t.scan_job_id || 0)}" style="cursor:pointer">
                  <td>#${t.id}</td>
                  <td>${escapeHtml(t.owner)}/${escapeHtml(t.repo)}</td>
                  <td>#${t.scan_job_id}</td>
                  <td><span class="${statusClass(t.status)}">${escapeHtml(t.status)}</span></td>
                  <td class="muted">${escapeHtml(formatAIOrigin(t))}</td>
                  <td class="muted">${escapeHtml(formatProgress(t))}</td>
                  <td>${escapeHtml(t.worker_name || "")}</td>
                  <td class="muted">${escapeHtml(t.error_msg || "")}</td>
                </tr>`
                    )
                    .join("") || `<tr><td colspan="8" class="muted">Select a campaign to inspect tasks.</td></tr>`
                }
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  `
  );
  restorePreservedScroll(root, preservedScroll);

  root.querySelector("#remRefresh")?.addEventListener("click", refreshRemediation);
  root.querySelector("#remCreate")?.addEventListener("click", createRemediationCampaign);
  root.querySelector("#remRepoReload")?.addEventListener("click", async () => {
    await refreshRemediationRepoSuggestions(true);
  });
  root.querySelector("#remName")?.addEventListener("input", (e) => {
    state.remediationDraft.name = e.target.value;
  });
  root.querySelector("#remMode")?.addEventListener("change", (e) => {
    state.remediationDraft.mode = e.target.value;
  });
  root.querySelector("#remMaxRepos")?.addEventListener("input", (e) => {
    state.remediationDraft.maxRepos = e.target.value;
  });
  root.querySelector("#remAutoPR")?.addEventListener("change", (e) => {
    state.remediationDraft.autoPR = !!e.target.checked;
  });
  root.querySelector("#remStartNow")?.addEventListener("change", (e) => {
    state.remediationDraft.startNow = !!e.target.checked;
  });
  root.querySelector("#remRepoSearch")?.addEventListener("input", (e) => {
    state.remediationRepoFilter = e.target.value;
    renderRemediation();
  });
  root.querySelector("#remRepoSearch")?.addEventListener("keydown", (e) => {
    if (e.key !== "Enter") return;
    e.preventDefault();
    const q = String(e.target.value || "").trim();
    const exact = (state.remediationRepoSuggestions || []).find(
      (r) => getScannedRepoLabel(r).toLowerCase() === q.toLowerCase()
    );
    if (exact) {
      const label = getScannedRepoLabel(exact);
      if (!state.remediationDraft.selectedRepos.includes(label)) state.remediationDraft.selectedRepos.push(label);
      state.remediationRepoFilter = "";
      renderRemediation();
    }
  });
  root.querySelectorAll("[data-rem-repo-add]").forEach((btn) =>
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      const label = btn.dataset.remRepoAdd;
      if (!label) return;
      if (!state.remediationDraft.selectedRepos.includes(label)) state.remediationDraft.selectedRepos.push(label);
      state.remediationRepoFilter = "";
      renderRemediation();
    })
  );
  root.querySelectorAll("[data-rem-chip-remove]").forEach((btn) =>
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      const label = btn.dataset.remChipRemove;
      state.remediationDraft.selectedRepos = (state.remediationDraft.selectedRepos || []).filter((r) => r !== label);
      renderRemediation();
    })
  );
  root.querySelectorAll("[data-rem-campaign-id]").forEach((tr) =>
    tr.addEventListener("click", async (e) => {
      if (e.target.closest("button")) return;
      state.remediationSelectedCampaignId = Number(tr.dataset.remCampaignId);
      await refreshRemediationTasks(state.remediationSelectedCampaignId);
      renderRemediation();
    })
  );
  root.querySelectorAll("[data-rem-start]").forEach((btn) =>
    btn.addEventListener("click", async (e) => {
      e.stopPropagation();
      await startRemediationCampaign(Number(btn.dataset.remStart));
    })
  );
  root.querySelectorAll("[data-rem-stop]").forEach((btn) =>
    btn.addEventListener("click", async (e) => {
      e.stopPropagation();
      await stopRemediationCampaign(Number(btn.dataset.remStop));
    })
  );
  root.querySelectorAll("[data-rem-task-scan-job-id]").forEach((tr) =>
    tr.addEventListener("click", async () => {
      const scanJobID = Number(tr.dataset.remTaskScanJobId || 0);
      if (!scanJobID) return;
      await openScanDetailPage(scanJobID, { pushHistory: true });
    })
  );
}
