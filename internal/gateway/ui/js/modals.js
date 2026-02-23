// Circular imports — all usages are inside function bodies.
import {
  createPathIgnoreRule,
  deletePathIgnoreRule,
  refreshPathIgnoreRules,
  triggerSweepWithOptions,
  updatePathIgnoreRule,
} from "./actions.js";
import { api } from "./api.js";
import { state, targetMeta } from "./state.js";
import { escapeHtml, fmtDate, repoSelectionKey, setHtml } from "./utils.js";

/* ---- Notice Modal ---- */

export function showNotice(title, message) {
  document.getElementById("noticeModalTitle").textContent = title || "Notice";
  document.getElementById("noticeModalBody").textContent = message || "";
  document.getElementById("noticeModal").classList.remove("hidden");
}

function hideNotice() {
  document.getElementById("noticeModal").classList.add("hidden");
}

export function wireNoticeModal() {
  document.getElementById("noticeModalOk").addEventListener("click", hideNotice);
  document.getElementById("noticeModal").addEventListener("click", (e) => {
    if (e.target.id === "noticeModal") hideNotice();
  });
}

let triggerModalMode = "sweep";
let triggerPickerResolve = null;

/* ---- Confirm Modal ---- */

let confirmModalResolve = null;

function hideConfirmModal(result) {
  document.getElementById("confirmModal").classList.add("hidden");
  if (confirmModalResolve) {
    const resolve = confirmModalResolve;
    confirmModalResolve = null;
    resolve(!!result);
  }
}

export function showConfirm({ title, message, confirmLabel = "OK", danger = true } = {}) {
  document.getElementById("confirmModalTitle").textContent = title || "Confirm";
  document.getElementById("confirmModalBody").textContent = message || "Are you sure?";
  const okBtn = document.getElementById("confirmModalOk");
  okBtn.textContent = confirmLabel;
  okBtn.className = danger ? "btn btn-danger" : "btn btn-primary";
  document.getElementById("confirmModal").classList.remove("hidden");
  return new Promise((resolve) => {
    confirmModalResolve = resolve;
  });
}

export function wireConfirmModal() {
  document.getElementById("confirmModalCancel").addEventListener("click", () => hideConfirmModal(false));
  document.getElementById("confirmModalOk").addEventListener("click", () => hideConfirmModal(true));
  document.getElementById("confirmModal").addEventListener("click", (e) => {
    if (e.target.id === "confirmModal") hideConfirmModal(false);
  });
}

/* ---- Prompt Modal ---- */

let promptModalResolve = null;

function hidePromptModal(result) {
  document.getElementById("promptModal").classList.add("hidden");
  const input = document.getElementById("promptModalInput");
  if (promptModalResolve) {
    const resolve = promptModalResolve;
    promptModalResolve = null;
    resolve(result === null ? null : String(result ?? ""));
  }
  input.value = "";
}

export function showPrompt({ title, message, placeholder = "", confirmLabel = "Confirm" } = {}) {
  document.getElementById("promptModalTitle").textContent = title || "Confirm Action";
  document.getElementById("promptModalBody").textContent = message || "";
  const input = document.getElementById("promptModalInput");
  input.value = "";
  input.placeholder = placeholder;
  document.getElementById("promptModalOk").textContent = confirmLabel;
  document.getElementById("promptModal").classList.remove("hidden");
  setTimeout(() => input.focus(), 0);
  return new Promise((resolve) => {
    promptModalResolve = resolve;
  });
}

export function wirePromptModal() {
  const input = document.getElementById("promptModalInput");
  document.getElementById("promptModalCancel").addEventListener("click", () => hidePromptModal(null));
  document.getElementById("promptModalOk").addEventListener("click", () => hidePromptModal(input.value));
  document.getElementById("promptModal").addEventListener("click", (e) => {
    if (e.target.id === "promptModal") hidePromptModal(null);
  });
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      hidePromptModal(input.value);
    }
    if (e.key === "Escape") {
      e.preventDefault();
      hidePromptModal(null);
    }
  });
}

/* ---- Path Ignore Modal ---- */

function detectPathIgnoreSuggestions() {
  const suggestions = [];
  const seen = new Set();
  const paths = (state.selectedJobFindings || []).map((f) => String(f.file_path || f.package || "")).filter(Boolean);
  const common = ["vendor/", "test/", "/testdata/", "node_modules/", ".git/"];
  for (const sub of common) {
    if (paths.some((p) => p.toLowerCase().includes(sub.toLowerCase()))) {
      if (!seen.has(sub)) {
        seen.add(sub);
        suggestions.push(sub);
      }
    }
  }
  return suggestions;
}

export function renderPathIgnoreModal() {
  const body = document.getElementById("pathIgnoreRulesBody");
  const bar = document.getElementById("pathIgnoreSuggestionBar");
  if (!body || !bar) return;
  const rules = state.pathIgnoreRules || [];
  setHtml(
    body,
    state.pathIgnoreRulesLoading
      ? `<tr><td colspan="5" class="muted">Loading rules…</td></tr>`
      : rules
          .map(
            (r) => `<tr>
        <td><input type="checkbox" data-path-ignore-toggle="${r.id}" ${r.enabled ? "checked" : ""}></td>
        <td><input data-path-ignore-substring="${r.id}" value="${escapeHtml(r.substring || "")}" /></td>
        <td><input data-path-ignore-note="${r.id}" value="${escapeHtml(r.note || "")}" /></td>
        <td class="muted">${escapeHtml(fmtDate(r.updated_at))}</td>
        <td class="row-actions">
          <button class="btn btn-secondary" data-path-ignore-save="${r.id}">Save</button>
          <button class="btn btn-danger" data-path-ignore-delete="${r.id}">Delete</button>
        </td>
      </tr>`
          )
          .join("") || `<tr><td colspan="5" class="muted">No path ignore rules configured.</td></tr>`
  );

  const existingSubs = new Set(rules.map((r) => String(r.substring || "").toLowerCase()));
  const suggestions = detectPathIgnoreSuggestions().filter((s) => !existingSubs.has(String(s).toLowerCase()));
  setHtml(
    bar,
    suggestions.length
      ? suggestions
          .map(
            (s) =>
              `<button class="btn btn-secondary" data-path-ignore-suggest="${escapeHtml(s)}">Suggest: ${escapeHtml(s)}</button>`
          )
          .join("")
      : `<span class="muted">Suggestions appear when current findings include common noisy paths (e.g. vendor/, test/).</span>`
  );

  body.querySelectorAll("[data-path-ignore-toggle]").forEach((el) => {
    el.addEventListener("change", async () => {
      const id = Number(el.dataset.pathIgnoreToggle);
      const row = state.pathIgnoreRules.find((r) => r.id === id);
      if (!row) return;
      await updatePathIgnoreRule(id, { substring: row.substring, note: row.note || "", enabled: !!el.checked });
    });
  });
  body.querySelectorAll("[data-path-ignore-save]").forEach((btn) =>
    btn.addEventListener("click", async () => {
      const id = Number(btn.dataset.pathIgnoreSave);
      const sub = body.querySelector(`[data-path-ignore-substring="${id}"]`)?.value || "";
      const note = body.querySelector(`[data-path-ignore-note="${id}"]`)?.value || "";
      const enabled = !!body.querySelector(`[data-path-ignore-toggle="${id}"]`)?.checked;
      await updatePathIgnoreRule(id, { substring: sub, note, enabled });
    })
  );
  body.querySelectorAll("[data-path-ignore-delete]").forEach((btn) =>
    btn.addEventListener("click", async () => {
      const id = Number(btn.dataset.pathIgnoreDelete);
      const row = state.pathIgnoreRules.find((r) => r.id === id);
      if (
        !(await showConfirm({
          title: "Delete Path Ignore Rule",
          message: `Delete ignore rule "${row?.substring || `#${id}`}"?`,
          confirmLabel: "Delete",
        }))
      )
        return;
      await deletePathIgnoreRule(id);
    })
  );
  bar.querySelectorAll("[data-path-ignore-suggest]").forEach((btn) =>
    btn.addEventListener("click", () => {
      const sub = btn.dataset.pathIgnoreSuggest || "";
      document.getElementById("pathIgnoreNewSubstring").value = sub;
    })
  );
}

export function openPathIgnoreModal() {
  document.getElementById("pathIgnoreModal").classList.remove("hidden");
  renderPathIgnoreModal();
  refreshPathIgnoreRules();
}

export function closePathIgnoreModal() {
  document.getElementById("pathIgnoreModal").classList.add("hidden");
}

export function wirePathIgnoreModal() {
  document.getElementById("pathIgnoreModalClose")?.addEventListener("click", closePathIgnoreModal);
  document.getElementById("pathIgnoreModalDone")?.addEventListener("click", closePathIgnoreModal);
  document.getElementById("pathIgnoreModal")?.addEventListener("click", (e) => {
    if (e.target.id === "pathIgnoreModal") closePathIgnoreModal();
  });
  document.getElementById("pathIgnoreAddBtn")?.addEventListener("click", async () => {
    const subEl = document.getElementById("pathIgnoreNewSubstring");
    const noteEl = document.getElementById("pathIgnoreNewNote");
    const substring = subEl?.value || "";
    const note = noteEl?.value || "";
    await createPathIgnoreRule({ substring, note, enabled: true });
    if (subEl) subEl.value = "";
    if (noteEl) noteEl.value = "";
  });
}

/* ---- Trigger Modal ---- */

function getDefaultTriggerTargets() {
  const current = state.agent?.targets;
  if (Array.isArray(current) && current.length > 0) return [...current];
  return ["own_repos"];
}

function getPreviewSampleRepos() {
  const targets = state.triggerPreview?.data?.targets;
  if (!Array.isArray(targets)) return [];
  const repos = [];
  for (const t of targets) {
    for (const r of t.samples || []) repos.push(r);
  }
  return repos;
}

function repoMatchesPreviewSearch(repo, rawSearch) {
  const q = String(rawSearch || "")
    .trim()
    .toLowerCase();
  if (!q) return true;
  const hay = [repo.full_name, repo.owner, repo.name, repo.provider, repo.host, repo.language]
    .map((v) => String(v || "").toLowerCase())
    .join(" ");
  return hay.includes(q);
}

function getSelectedPreviewRepos() {
  return Object.values(state.triggerPlan.selectedRepoMap || {});
}

function syncTriggerSubmitButton() {
  const btn = document.getElementById("triggerModalSubmit");
  if (!btn) return;
  const busy = !!state.triggerSubmitBusy;
  const baseLabel = triggerModalMode === "cron-picker" ? "Use Selected Repos" : "Start Sweep";
  btn.disabled = busy;
  btn.classList.toggle("is-loading", busy);
  btn.textContent = busy ? (triggerModalMode === "cron-picker" ? "Applying" : "Starting") : baseLabel;
}

function reconcileSelectedPreviewRepos() {
  const visible = new Set(getPreviewSampleRepos().map(repoSelectionKey));
  const next = {};
  for (const [k, v] of Object.entries(state.triggerPlan.selectedRepoMap || {})) {
    if (visible.has(k)) next[k] = v;
  }
  state.triggerPlan.selectedRepoMap = next;
}

export function renderTriggerChecklist() {
  const root = document.getElementById("targetChecklist");
  const supported = state.agent?.supported_targets || ["own_repos", "watchlist", "cve_search", "all_accessible"];
  setHtml(
    root,
    supported
      .map((t) => {
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
      })
      .join("")
  );
  root.querySelectorAll("input[type='checkbox'][data-target]").forEach((cb) => {
    cb.addEventListener("change", () => {
      const t = cb.dataset.target;
      if (cb.checked) {
        if (!state.triggerPlan.targets.includes(t)) state.triggerPlan.targets.push(t);
      } else {
        state.triggerPlan.targets = state.triggerPlan.targets.filter((x) => x !== t);
      }
      if (state.triggerPlan.targets.length === 0) {
        state.triggerPlan.selectedRepoMap = {};
      }
      fetchTriggerPreview();
    });
  });
}

export function renderTriggerPreview() {
  const root = document.getElementById("triggerPreviewBody");
  if (!root) return;
  if (state.triggerPreview.loading) {
    setHtml(
      root,
      `<div class="preview-loading"><div class="spinner-row"><span class="spinner-dot spinner-dot-accent" aria-hidden="true"></span><span>Loading preview…</span></div></div>`
    );
    return;
  }
  if (state.triggerPlan.targets.length === 0) {
    setHtml(
      root,
      `<div class="muted">No targets selected. Select one or more targets to preview and choose repositories.</div>`
    );
    return;
  }
  if (state.triggerPreview.error) {
    setHtml(root, `<div class="preview-errors">${escapeHtml(state.triggerPreview.error)}</div>`);
    return;
  }
  const data = state.triggerPreview.data;
  if (!data || !Array.isArray(data.targets)) {
    setHtml(root, `<div class="muted">Preview unavailable.</div>`);
    return;
  }
  const previewRepos = getPreviewSampleRepos().filter((r) => repoMatchesPreviewSearch(r, state.triggerPreview.search));
  const selectedCount = getSelectedPreviewRepos().length;
  const searchValue = state.triggerPreview.search || "";
  const currentLimit = Number(state.triggerPreview.limit || 10);
  const canShowMore = currentLimit < 50;
  const sectionsHtml = data.targets
    .map((t) => {
      const targetRepos = (t.samples || []).filter((r) => repoMatchesPreviewSearch(r, searchValue));
      return `
    <div class="preview-section">
      <h4>${escapeHtml(targetMeta[t.target]?.label || t.target)}</h4>
      <div class="preview-meta">${t.repo_count || 0} repositories visible${t.samples && t.samples.length < (t.repo_count || 0) ? ` (showing ${t.samples.length})` : ""}${searchValue ? ` • filtered to ${targetRepos.length}` : ""}</div>
      <div class="preview-list">
        ${
          targetRepos
            .map(
              (r) => `
          <label class="preview-item preview-item-selectable">
            <div class="preview-item-row">
              <input type="checkbox" data-preview-repo="${escapeHtml(repoSelectionKey(r))}" ${state.triggerPlan.selectedRepoMap[repoSelectionKey(r)] ? "checked" : ""}>
              <div class="title">${escapeHtml(r.full_name)}</div>
            </div>
            <div class="sub">${escapeHtml(r.provider)} • ${escapeHtml(r.host || "")}${r.language ? ` • ${escapeHtml(r.language)}` : ""}${(r.stars ?? 0) > 0 ? ` • ★ ${r.stars}` : ""}${r.private ? " • private" : ""}</div>
          </label>
        `
            )
            .join("") ||
          `<div class="muted">${searchValue ? "No repositories matched this filter." : "No repositories matched this target."}</div>`
        }
      </div>
      ${t.errors?.length ? `<div class="preview-errors">${escapeHtml(t.errors.join(" | "))}</div>` : ""}
    </div>
  `;
    })
    .join("");
  const toolbarHtml = `
    <div class="toolbar preview-toolbar">
      <button id="previewReposSelectAll" class="btn btn-secondary" ${previewRepos.length === 0 ? "disabled" : ""}>Select All Shown</button>
      <button id="previewReposSelectNone" class="btn btn-secondary" ${selectedCount === 0 ? "disabled" : ""}>Select None</button>
      <input id="previewRepoSearch" placeholder="Search repos" value="${escapeHtml(searchValue)}" style="max-width:220px">
      <button id="previewShowMore" class="btn btn-secondary" ${canShowMore ? "" : "disabled"}>Show More</button>
      <span class="muted">${selectedCount} repo${selectedCount === 1 ? "" : "s"} selected${previewRepos.length ? ` (from ${previewRepos.length} shown)` : ""}. If any are selected, this trigger scans only those repos.</span>
    </div>
  `;
  setHtml(root, toolbarHtml + sectionsHtml);
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
  root.querySelector("#previewRepoSearch")?.addEventListener("input", (e) => {
    state.triggerPreview.search = e.target.value || "";
    renderTriggerPreview();
  });
  root.querySelector("#previewShowMore")?.addEventListener("click", () => {
    const current = Number(state.triggerPreview.limit || 10);
    const next = current < 10 ? 10 : current < 25 ? 25 : 50;
    if (next === current) return;
    state.triggerPreview.limit = next;
    fetchTriggerPreview();
  });
}

export async function fetchTriggerPreview() {
  renderTriggerPreview();
  if (state.triggerPlan.targets.length === 0) return;
  state.triggerPreview.loading = true;
  state.triggerPreview.error = "";
  renderTriggerPreview();
  try {
    state.triggerPreview.data = await api("/api/agent/preview", {
      method: "POST",
      body: JSON.stringify({
        scan_targets: state.triggerPlan.targets,
        limit: Number(state.triggerPreview.limit || 10),
      }),
    });
    reconcileSelectedPreviewRepos();
  } catch (err) {
    state.triggerPreview.error = err.message || String(err);
  } finally {
    state.triggerPreview.loading = false;
    renderTriggerPreview();
  }
}

export function openTriggerModal() {
  triggerModalMode = "sweep";
  triggerPickerResolve = null;
  state.triggerPlan.targets = getDefaultTriggerTargets();
  state.triggerPlan.workers = "";
  state.triggerPlan.selectedRepoMap = {};
  state.triggerPlan.forceScan = false;
  state.triggerPreview = { loading: false, data: null, error: "", limit: 10, search: "" };
  document.getElementById("triggerWorkers").value = "";
  document.getElementById("triggerForceScan").checked = false;
  document.getElementById("triggerModalTitle").textContent = "Trigger Scan Sweep";
  document.querySelector("#triggerModal .modal-header p").textContent =
    "Choose which discovery targets to scan for this run and optionally override worker concurrency.";
  document.getElementById("triggerModalSubmit").textContent = "Start Sweep";
  document.getElementById("triggerWorkersWrap").classList.remove("hidden");
  document.getElementById("triggerForceWrap").classList.remove("hidden");
  state.triggerSubmitBusy = false;
  renderTriggerChecklist();
  renderTriggerPreview();
  syncTriggerSubmitButton();
  document.getElementById("triggerModal").classList.remove("hidden");
  fetchTriggerPreview();
}

export function openCronRepoPicker({ targets = [], selectedRepos = [] } = {}) {
  triggerModalMode = "cron-picker";
  state.triggerPlan.targets = Array.isArray(targets) && targets.length > 0 ? [...targets] : getDefaultTriggerTargets();
  state.triggerPlan.workers = "";
  state.triggerPlan.selectedRepoMap = {};
  for (const r of Array.isArray(selectedRepos) ? selectedRepos : []) {
    const key = repoSelectionKey(r);
    state.triggerPlan.selectedRepoMap[key] = {
      provider: r.provider || "",
      host: r.host || "",
      owner: r.owner || "",
      name: r.name || "",
    };
  }
  state.triggerPlan.forceScan = false;
  state.triggerPreview = { loading: false, data: null, error: "", limit: 10, search: "" };
  document.getElementById("triggerWorkers").value = "";
  document.getElementById("triggerForceScan").checked = false;
  document.getElementById("triggerModalTitle").textContent = "Browse Repositories For Cron";
  document.querySelector("#triggerModal .modal-header p").textContent =
    "Pick scan targets, preview repositories, and select the exact repos this cron should scan.";
  document.getElementById("triggerModalSubmit").textContent = "Use Selected Repos";
  document.getElementById("triggerWorkersWrap").classList.add("hidden");
  document.getElementById("triggerForceWrap").classList.add("hidden");
  state.triggerSubmitBusy = false;
  renderTriggerChecklist();
  renderTriggerPreview();
  syncTriggerSubmitButton();
  document.getElementById("triggerModal").classList.remove("hidden");
  fetchTriggerPreview();
  return new Promise((resolve) => {
    triggerPickerResolve = resolve;
  });
}

export function closeTriggerModal() {
  document.getElementById("triggerModal").classList.add("hidden");
  state.triggerSubmitBusy = false;
  syncTriggerSubmitButton();
  if (triggerModalMode === "cron-picker" && triggerPickerResolve) {
    const resolve = triggerPickerResolve;
    triggerPickerResolve = null;
    resolve(null);
  }
  triggerModalMode = "sweep";
}

export function wireTriggerModal() {
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
    if (state.triggerSubmitBusy) return;
    const workersRaw = document.getElementById("triggerWorkers").value.trim();
    const forceScan = !!document.getElementById("triggerForceScan")?.checked;
    const selectedRepos = getSelectedPreviewRepos();
    if (triggerModalMode === "cron-picker") {
      if (selectedRepos.length === 0) {
        showNotice("No Repositories Selected", "Select one or more repositories from the preview list.");
        return;
      }
      if (triggerPickerResolve) {
        const resolve = triggerPickerResolve;
        triggerPickerResolve = null;
        resolve({ targets: [...state.triggerPlan.targets], selectedRepos });
      }
      closeTriggerModal();
      return;
    }
    if (state.triggerPlan.targets.length === 0 && selectedRepos.length === 0) {
      showNotice("Nothing Selected", "Select at least one scan target or choose one or more preview repos.");
      return;
    }
    if (workersRaw !== "") {
      const n = Number(workersRaw);
      if (!Number.isFinite(n) || n < 1 || n > 64) {
        showNotice("Invalid Workers", "Workers must be between 1 and 64.");
        return;
      }
    }
    state.triggerSubmitBusy = true;
    syncTriggerSubmitButton();
    try {
      await triggerSweepWithOptions({
        scanTargets: state.triggerPlan.targets,
        workers: workersRaw === "" ? 0 : Number(workersRaw),
        selectedRepos,
        forceScan,
      });
    } finally {
      if (!document.getElementById("triggerModal").classList.contains("hidden")) {
        state.triggerSubmitBusy = false;
        syncTriggerSubmitButton();
      }
    }
  });
  document.getElementById("triggerModal").addEventListener("click", (e) => {
    if (e.target.id === "triggerModal") closeTriggerModal();
  });
}
