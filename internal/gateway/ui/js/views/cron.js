// Circular imports — all usages are inside function bodies.
import { browseCronRepos, createCron, deleteCron, editCron, refreshCron, resetCronForm, triggerCron } from "../actions.js";
import { state, targetMeta } from "../state.js";
import { escapeHtml, fmtDate, setHtml } from "../utils.js";

function summarizeTargets(raw) {
  try {
    const arr = JSON.parse(raw || "[]");
    return Array.isArray(arr) && arr.length ? arr.join(", ") : "defaults";
  } catch {
    return "invalid";
  }
}

function parseScopeJSON(raw) {
  try {
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

function countSelectedRepos(raw, scopeRaw) {
  const scope = parseScopeJSON(scopeRaw);
  if (scope && Array.isArray(scope.repos)) return scope.repos.length;
  try {
    const arr = JSON.parse(raw || "[]");
    return Array.isArray(arr) ? arr.length : 0;
  } catch {
    return 0;
  }
}

function parseLines(raw) {
  return String(raw || "")
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
}

function setLines(el, lines) {
  if (!el) return;
  el.value = (lines || []).join("\n");
}

function getCronBuilderTimezoneValue(root) {
  const raw = root.querySelector("#cronExprTZ")?.value || "server";
  if (raw === "browser") {
    try {
      return Intl.DateTimeFormat().resolvedOptions().timeZone || "";
    } catch {
      return "";
    }
  }
  if (raw === "server") return "";
  return raw;
}

function getCronPreviewTimezone(root) {
  const preset = root.querySelector("#cronExprPreset")?.value || "daily";
  if (preset === "custom") {
    const expr = (root.querySelector("#cronExpr")?.value || "").trim();
    const m = expr.match(/^CRON_TZ=([^\s]+)\s+/);
    if (m) return { kind: "iana", value: m[1] };
    return { kind: "browser", value: "" };
  }
  const raw = root.querySelector("#cronExprTZ")?.value || "server";
  if (raw === "server") return { kind: "server", value: "" };
  if (raw === "browser") return { kind: "browser", value: "" };
  return { kind: "iana", value: raw };
}

function parseCronFieldBasic(token, min, max) {
  const t = String(token || "").trim();
  if (t === "*") return { kind: "any" };
  if (/^\*\/\d+$/.test(t)) {
    const step = Number(t.slice(2));
    if (!Number.isFinite(step) || step <= 0) throw new Error(`invalid step "${t}"`);
    return { kind: "step", step };
  }
  if (/^\d+$/.test(t)) {
    const value = Number(t);
    if (value < min || value > max) throw new Error(`value out of range "${t}"`);
    return { kind: "exact", value };
  }
  throw new Error(`unsupported cron token "${t}"`);
}

function parseBasicCronExpression(expr) {
  let body = String(expr || "").trim();
  if (!body) throw new Error("empty expression");
  let tz = "";
  const m = body.match(/^CRON_TZ=([^\s]+)\s+(.+)$/);
  if (m) {
    tz = m[1];
    body = m[2];
  }
  const parts = body.split(/\s+/);
  if (parts.length !== 5) throw new Error("only simple 5-field cron expressions are previewed");
  return {
    tz,
    minute: parseCronFieldBasic(parts[0], 0, 59),
    hour: parseCronFieldBasic(parts[1], 0, 23),
    day: parseCronFieldBasic(parts[2], 1, 31),
    month: parseCronFieldBasic(parts[3], 1, 12),
    weekday: parseCronFieldBasic(parts[4], 0, 7),
  };
}

function cronFieldMatches(field, value) {
  if (field.kind === "any") return true;
  if (field.kind === "step") return value % field.step === 0;
  if (field.kind === "exact") {
    if (field.value === 7 && value === 0) return true;
    return field.value === value;
  }
  return false;
}

function getDatePartsForTimezone(date, tzInfo) {
  if (tzInfo.kind === "server") return null;
  const timeZone = tzInfo.kind === "iana" ? tzInfo.value : undefined;
  const fmt = new Intl.DateTimeFormat("en-US", {
    timeZone,
    year: "numeric",
    month: "numeric",
    day: "numeric",
    hour: "numeric",
    minute: "numeric",
    hour12: false,
    weekday: "short",
  });
  const parts = {};
  for (const p of fmt.formatToParts(date)) {
    if (p.type !== "literal") parts[p.type] = p.value;
  }
  const weekdayMap = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };
  return {
    month: Number(parts.month),
    day: Number(parts.day),
    hour: Number(parts.hour),
    minute: Number(parts.minute),
    weekday: weekdayMap[parts.weekday] ?? 0,
  };
}

function formatDateForTimezone(date, tzInfo) {
  const timeZone = tzInfo.kind === "iana" ? tzInfo.value : undefined;
  return new Intl.DateTimeFormat(undefined, {
    timeZone,
    weekday: "short",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

function computeNextCronRuns(expr, tzInfo, count = 5) {
  if (tzInfo.kind === "server") return { error: "Preview unavailable for Server Local timezone in browser." };
  let parsed;
  try {
    parsed = parseBasicCronExpression(expr);
  } catch (err) {
    return { error: `Preview unavailable: ${err.message}` };
  }
  const effectiveTZ = parsed.tz ? { kind: "iana", value: parsed.tz } : tzInfo;
  const start = new Date();
  start.setSeconds(0, 0);
  const out = [];
  for (let i = 1; i <= 60 * 24 * 365 && out.length < count; i++) {
    const d = new Date(start.getTime() + i * 60 * 1000);
    const p = getDatePartsForTimezone(d, effectiveTZ);
    if (!p) break;
    if (!cronFieldMatches(parsed.minute, p.minute)) continue;
    if (!cronFieldMatches(parsed.hour, p.hour)) continue;
    if (!cronFieldMatches(parsed.day, p.day)) continue;
    if (!cronFieldMatches(parsed.month, p.month)) continue;
    if (!cronFieldMatches(parsed.weekday, p.weekday)) continue;
    out.push(d);
  }
  return out.length ? { runs: out, tz: effectiveTZ } : { error: "No upcoming runs found in preview window." };
}

function buildCronExpressionFromControls(root) {
  const preset = root.querySelector("#cronExprPreset")?.value || "daily";
  if (preset === "custom") return null;
  const interval = Math.max(1, Number(root.querySelector("#cronExprInterval")?.value || "1"));
  const minuteValue = Math.max(0, Math.min(59, Number(root.querySelector("#cronExprMinute")?.value || "0")));
  const timeRaw = root.querySelector("#cronExprTime")?.value || "02:00";
  const [hourStr, minuteStr] = String(timeRaw).split(":");
  const hour = Math.max(0, Math.min(23, Number(hourStr || "2")));
  const minute = Math.max(0, Math.min(59, Number(minuteStr || "0")));
  const weekday = root.querySelector("#cronExprWeekday")?.value || "1";
  const monthday = Math.max(1, Math.min(28, Number(root.querySelector("#cronExprMonthday")?.value || "1")));

  let expr = "";
  if (preset === "hourly") {
    expr = interval > 1 ? `${minuteValue} */${interval} * * *` : `${minuteValue} * * * *`;
  } else if (preset === "daily") {
    expr = interval > 1 ? `${minute} ${hour} */${interval} * *` : `${minute} ${hour} * * *`;
  } else if (preset === "weekly") {
    expr = `${minute} ${hour} * * ${weekday}`;
  } else if (preset === "monthly") {
    expr = interval > 1 ? `${minute} ${hour} ${monthday} */${interval} *` : `${minute} ${hour} ${monthday} * *`;
  }
  const tz = getCronBuilderTimezoneValue(root);
  return tz ? `CRON_TZ=${tz} ${expr}` : expr;
}

function refreshCronExpressionBuilderUI(root) {
  const preset = root.querySelector("#cronExprPreset")?.value || "daily";
  root.querySelector("#cronExprCustomHint")?.classList.toggle("hidden", preset !== "custom");
  root.querySelector("#cronExprTZWrap")?.classList.toggle("hidden", preset === "custom");
  root.querySelector("#cronExprTimeWrap")?.classList.toggle("hidden", !(preset === "daily" || preset === "weekly" || preset === "monthly"));
  root.querySelector("#cronExprMinuteWrap")?.classList.toggle("hidden", preset !== "hourly");
  root.querySelector("#cronExprWeekdayWrap")?.classList.toggle("hidden", preset !== "weekly");
  root.querySelector("#cronExprMonthdayWrap")?.classList.toggle("hidden", preset !== "monthly");
  root.querySelector("#cronExprIntervalWrap")?.classList.toggle("hidden", !(preset === "hourly" || preset === "daily" || preset === "monthly"));
  if (preset === "weekly") {
    root.querySelector("#cronExprIntervalHelp")?.classList.add("hidden");
  } else {
    root.querySelector("#cronExprIntervalHelp")?.classList.remove("hidden");
  }
  const exprInput = root.querySelector("#cronExpr");
  if (exprInput) exprInput.readOnly = preset !== "custom";
  if (preset !== "custom") {
    const expr = buildCronExpressionFromControls(root);
    if (expr && exprInput) exprInput.value = expr;
  }
  const previewEl = root.querySelector("#cronExprPreview");
  if (previewEl) {
    const expr = (exprInput?.value || "").trim();
    if (!expr) {
      setHtml(previewEl, `<span class="muted">Next runs preview appears here.</span>`);
    } else {
      const preview = computeNextCronRuns(expr, getCronPreviewTimezone(root), 5);
      if (preview.error) {
        setHtml(previewEl, `<span class="muted">${escapeHtml(preview.error)}</span>`);
      } else {
        const tzLabel = preview.tz.kind === "browser" ? "Browser Local" : preview.tz.value;
        setHtml(
          previewEl,
          `<div class="muted">Next 5 runs (${escapeHtml(tzLabel)}):</div>${preview.runs
            .map((d) => `<div style="font-size:12px; padding-top:3px">${escapeHtml(formatDateForTimezone(d, preview.tz))}</div>`)
            .join("")}`
        );
      }
    }
  }
}

function wireCronExpressionBuilder(root) {
  const tzSelect = root.querySelector("#cronExprTZ");
  if (tzSelect) {
    const browserTZ = (() => {
      try {
        return Intl.DateTimeFormat().resolvedOptions().timeZone || "";
      } catch {
        return "";
      }
    })();
    const browserOpt = tzSelect.querySelector("option[value='browser']");
    if (browserOpt && browserTZ) browserOpt.textContent = `Browser Local (${browserTZ})`;
  }
  [
    "#cronExprPreset",
    "#cronExprTZ",
    "#cronExprTime",
    "#cronExprMinute",
    "#cronExprWeekday",
    "#cronExprMonthday",
    "#cronExprInterval",
  ].forEach((sel) => root.querySelector(sel)?.addEventListener("change", () => refreshCronExpressionBuilderUI(root)));
  root.querySelector("#cronExprTime")?.addEventListener("input", () => refreshCronExpressionBuilderUI(root));
  root.querySelector("#cronExprMinute")?.addEventListener("input", () => refreshCronExpressionBuilderUI(root));
  root.querySelector("#cronExprMonthday")?.addEventListener("input", () => refreshCronExpressionBuilderUI(root));
  root.querySelector("#cronExprInterval")?.addEventListener("input", () => refreshCronExpressionBuilderUI(root));
  root.querySelector("#cronExpr")?.addEventListener("input", () => refreshCronExpressionBuilderUI(root));
  refreshCronExpressionBuilderUI(root);
}

function updateCronSelectionPanel(root) {
  const panel = root.querySelector("#cronSelectionPanel");
  if (!panel) return;
  const repos = parseLines(root.querySelector("#cronRepos")?.value || "");
  const owners = parseLines(root.querySelector("#cronOwners")?.value || "");
  const prefixes = parseLines(root.querySelector("#cronOwnerPrefixes")?.value || "");
  const targets = [...root.querySelectorAll("input[type='checkbox'][data-cron-target]:checked")].map((el) => el.dataset.cronTarget);
  setHtml(
    panel,
    `
    <div class="stack">
      <div class="muted">Targets: ${targets.length ? escapeHtml(targets.join(", ")) : "defaults"}</div>
      <div class="muted">${repos.length} exact repos selected</div>
      <div class="muted">${owners.length} owner/project filters • ${prefixes.length} prefix filters</div>
      ${
        repos.length
          ? `<div style="max-height:360px; overflow:auto; border:1px solid var(--line); border-radius:8px; padding:8px; background:var(--nav-hover-bg)">
              ${repos
                .map(
                  (line, idx) =>
                    `<div style="padding:4px 0; ${idx < repos.length - 1 ? "border-bottom:1px solid var(--line);" : ""} font-size:12px">${escapeHtml(line)}</div>`
                )
                .join("")}
            </div>`
          : `<div class="muted" style="padding:10px; border:1px dashed var(--line); border-radius:8px">No exact repos selected yet. Use "Browse Repos" or add repos manually.</div>`
      }
      ${
        owners.length || prefixes.length
          ? `<div class="footer-note">Dynamic owner/prefix filters can add more repos at runtime than the exact list shown here.</div>`
          : ""
      }
    </div>
  `
  );
}

function updateCronRepoSelectionSummary(root) {
  const hidden = root.querySelector("#cronRepos");
  const countEl = root.querySelector("#cronSelectedRepoCount");
  const clearBtn = root.querySelector("#cronClearSelectedRepos");
  if (!hidden || !countEl) return;
  const count = parseLines(hidden.value).length;
  countEl.textContent = `${count} repo${count === 1 ? "" : "s"} selected`;
  if (clearBtn) clearBtn.disabled = count === 0;
  updateCronSelectionPanel(root);
}

function renderLineChipList(root, hiddenId, listId) {
  const hidden = root.querySelector(`#${hiddenId}`);
  const list = root.querySelector(`#${listId}`);
  if (!hidden || !list) return;
  const lines = parseLines(hidden.value);
  setHtml(
    list,
    lines.length
      ? lines
          .map(
            (line, idx) =>
              `<button type="button" class="btn btn-secondary" data-cron-chip-remove="${hiddenId}" data-index="${idx}" title="Remove">${escapeHtml(line)} ✕</button>`
          )
          .join("")
      : `<span class="muted">None added.</span>`
  );
  list.querySelectorAll("[data-cron-chip-remove]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const current = parseLines(hidden.value);
      const idx = Number(btn.dataset.index);
      current.splice(idx, 1);
      setLines(hidden, current);
      renderLineChipList(root, hiddenId, listId);
    });
  });
  if (hiddenId === "cronRepos") updateCronRepoSelectionSummary(root);
  else updateCronSelectionPanel(root);
}

function appendLineFromInputs(root, hiddenId, fieldIds) {
  const hidden = root.querySelector(`#${hiddenId}`);
  if (!hidden) return;
  const values = fieldIds.map((id) => (root.querySelector(`#${id}`)?.value || "").trim());
  if (hiddenId === "cronRepos") {
    const [provider, host, owner, repo] = values;
    if (!provider || !owner || !repo) return;
    const line = `${provider}${host ? `@${host}` : ""}:${owner}/${repo}`;
    const lines = parseLines(hidden.value);
    if (!lines.includes(line)) lines.push(line);
    setLines(hidden, lines);
    root.querySelector("#cronRepoHost").value = "";
    root.querySelector("#cronRepoOwner").value = "";
    root.querySelector("#cronRepoName").value = "";
    renderLineChipList(root, "cronRepos", "cronReposList");
    return;
  }
  const [provider, host, owner] = values;
  if (!provider || !owner) return;
  const line = `${provider}${host ? `@${host}` : ""}:${owner}`;
  const lines = parseLines(hidden.value);
  if (!lines.includes(line)) lines.push(line);
  setLines(hidden, lines);
  if (hiddenId === "cronOwners") {
    root.querySelector("#cronOwnerHost").value = "";
    root.querySelector("#cronOwnerValue").value = "";
    renderLineChipList(root, "cronOwners", "cronOwnersList");
  } else {
    root.querySelector("#cronPrefixHost").value = "";
    root.querySelector("#cronPrefixValue").value = "";
    renderLineChipList(root, "cronOwnerPrefixes", "cronOwnerPrefixesList");
  }
}

function wireCronBuilder(root) {
  ["cronRepos", "cronOwners", "cronOwnerPrefixes"].forEach((id) => {
    renderLineChipList(root, id, `${id}List`);
  });
  root.querySelector("#cronAddRepo")?.addEventListener("click", () => {
    appendLineFromInputs(root, "cronRepos", ["cronRepoProvider", "cronRepoHost", "cronRepoOwner", "cronRepoName"]);
  });
  root.querySelector("#cronAddOwner")?.addEventListener("click", () => {
    appendLineFromInputs(root, "cronOwners", ["cronOwnerProvider", "cronOwnerHost", "cronOwnerValue"]);
  });
  root.querySelector("#cronAddOwnerPrefix")?.addEventListener("click", () => {
    appendLineFromInputs(root, "cronOwnerPrefixes", ["cronPrefixProvider", "cronPrefixHost", "cronPrefixValue"]);
  });
  root.querySelectorAll("input[type='checkbox'][data-cron-target]").forEach((cb) => {
    cb.addEventListener("change", () => updateCronSelectionPanel(root));
  });
  root.querySelector("#cronClearSelectedRepos")?.addEventListener("click", () => {
    const reposHidden = root.querySelector("#cronRepos");
    if (!reposHidden) return;
    reposHidden.value = "";
    renderLineChipList(root, "cronRepos", "cronReposList");
  });
  wireCronExpressionBuilder(root);
  updateCronRepoSelectionSummary(root);
  updateCronSelectionPanel(root);
}

export function loadCronScopeBuilders() {
  const root = document.getElementById("view-cron");
  if (!root) return;
  wireCronBuilder(root);
}

function renderTargetMultiSelect() {
  const supported = state.agent?.supported_targets || ["own_repos", "watchlist", "cve_search", "all_accessible"];
  return `
    <div id="cronTargetsChecklist" class="check-grid">
      ${supported
        .map((t) => {
          const meta = targetMeta[t] || { label: t, desc: "" };
          return `<div class="check-item">
            <label>
              <input type="checkbox" data-cron-target="${escapeHtml(t)}">
              <span class="label-stack">
                <span>${escapeHtml(meta.label)}</span>
                <small>${escapeHtml(meta.desc)}</small>
              </span>
            </label>
          </div>`;
        })
        .join("")}
    </div>
  `;
}

export function renderCron() {
  const root = document.getElementById("view-cron");
  const cronBusy = String(state.cronActionBusy || "");
  const rows = state.schedules || [];
  setHtml(
    root,
    `
    <div style="display:grid; grid-template-columns: minmax(0, 1.45fr) minmax(280px, .95fr); gap:14px; align-items:start">
    <div class="card">
      <h3>Create Schedule</h3>
      <input id="cronId" type="hidden" value="">
      <textarea id="cronRepos" style="display:none"></textarea>
      <textarea id="cronOwners" style="display:none"></textarea>
      <textarea id="cronOwnerPrefixes" style="display:none"></textarea>
      <div class="form-grid">
        <label>Name<input id="cronName" placeholder="Nightly sweep"></label>
        <label>Schedule Type
          <select id="cronExprPreset">
            <option value="daily">Daily</option>
            <option value="weekly">Weekly</option>
            <option value="monthly">Monthly</option>
            <option value="hourly">Hourly</option>
            <option value="custom">Custom Expression</option>
          </select>
        </label>
        <label>Mode
          <select id="cronMode">
            <option value="">Use default</option>
            <option value="triage">triage</option>
            <option value="semi">semi</option>
            <option value="auto">auto</option>
          </select>
        </label>
        <label style="display:flex;align-items:center;gap:8px;margin-top:26px">
          <input id="cronEnabled" type="checkbox" checked>
          <span>Enabled</span>
        </label>
        <label id="cronExprTZWrap">Timezone
          <select id="cronExprTZ">
            <option value="browser">Browser Local</option>
            <option value="server">Server Local</option>
            <option value="UTC">UTC</option>
            <option value="America/New_York">US Eastern</option>
            <option value="America/Chicago">US Central</option>
            <option value="America/Denver">US Mountain</option>
            <option value="America/Los_Angeles">US Pacific</option>
            <option value="Europe/London">Europe/London</option>
            <option value="Europe/Berlin">Europe/Berlin</option>
            <option value="Asia/Tokyo">Asia/Tokyo</option>
          </select>
        </label>
        <label id="cronExprTimeWrap">At Time
          <input id="cronExprTime" type="time" value="02:00">
        </label>
        <label id="cronExprMinuteWrap" class="hidden">Minute of Hour
          <input id="cronExprMinute" type="number" min="0" max="59" value="0">
        </label>
        <label id="cronExprWeekdayWrap" class="hidden">Day of Week
          <select id="cronExprWeekday">
            <option value="1">Monday</option>
            <option value="2">Tuesday</option>
            <option value="3">Wednesday</option>
            <option value="4">Thursday</option>
            <option value="5">Friday</option>
            <option value="6">Saturday</option>
            <option value="0">Sunday</option>
          </select>
        </label>
        <label id="cronExprMonthdayWrap" class="hidden">Day of Month
          <input id="cronExprMonthday" type="number" min="1" max="28" value="1">
        </label>
        <label id="cronExprIntervalWrap">Repeat Every
          <input id="cronExprInterval" type="number" min="1" max="24" value="1">
          <small id="cronExprIntervalHelp" class="muted">Units depend on schedule type (hours/days/months).</small>
        </label>
        <label style="grid-column:1 / -1">Expression
          <input id="cronExpr" placeholder="@daily">
          <small id="cronExprCustomHint" class="muted hidden">Custom mode is enabled. You can type any valid cron expression (including <code>CRON_TZ=Zone</code> prefixes).</small>
          <div id="cronExprPreview" class="footer-note" style="margin-top:6px">Next runs preview appears here.</div>
        </label>
        <label style="grid-column:1 / -1">Targets (multi-select)
          ${renderTargetMultiSelect()}
        </label>
        <div style="grid-column:1 / -1" class="toolbar">
          <button type="button" id="cronBrowseRepos" class="btn btn-secondary">Browse Repos</button>
          <button type="button" id="cronClearSelectedRepos" class="btn btn-secondary">Clear Selected Repos</button>
          <span id="cronSelectedRepoCount" class="muted">0 repos selected</span>
          <span class="muted">Opens the repo preview picker so you can click-select exact repositories.</span>
        </div>
      </div>

      <details id="cronAdvancedScope" style="margin-top:12px">
        <summary style="cursor:pointer;color:var(--text)">Advanced Scope Filters (optional)</summary>
        <div style="margin-top:10px; display:grid; gap:12px">
          <div>
            <div class="muted" style="margin-bottom:6px">Exact Repositories (click to add)</div>
            <div class="toolbar">
              <select id="cronRepoProvider">
                <option value="github">GitHub</option>
                <option value="gitlab">GitLab</option>
                <option value="azure">Azure DevOps</option>
              </select>
              <input id="cronRepoHost" placeholder="Host (optional)">
              <input id="cronRepoOwner" placeholder="Owner / org/project">
              <input id="cronRepoName" placeholder="Repo name">
              <button type="button" id="cronAddRepo" class="btn btn-secondary">Add Repo</button>
            </div>
            <div id="cronReposList" class="toolbar" style="margin-top:6px; flex-wrap:wrap"></div>
          </div>

          <div>
            <div class="muted" style="margin-bottom:6px">Owners / Projects (exact match)</div>
            <div class="toolbar">
              <select id="cronOwnerProvider">
                <option value="github">GitHub</option>
                <option value="gitlab">GitLab</option>
                <option value="azure">Azure DevOps</option>
              </select>
              <input id="cronOwnerHost" placeholder="Host (optional)">
              <input id="cronOwnerValue" placeholder="Owner (Azure: org/project)">
              <button type="button" id="cronAddOwner" class="btn btn-secondary">Add Owner/Project</button>
            </div>
            <div id="cronOwnersList" class="toolbar" style="margin-top:6px; flex-wrap:wrap"></div>
          </div>

          <div>
            <div class="muted" style="margin-bottom:6px">Owner Prefixes (dynamic subgroup/project prefixes)</div>
            <div class="toolbar">
              <select id="cronPrefixProvider">
                <option value="github">GitHub</option>
                <option value="gitlab">GitLab</option>
                <option value="azure">Azure DevOps</option>
              </select>
              <input id="cronPrefixHost" placeholder="Host (optional)">
              <input id="cronPrefixValue" placeholder="Prefix (e.g. platform/ or org/)">
              <button type="button" id="cronAddOwnerPrefix" class="btn btn-secondary">Add Prefix</button>
            </div>
            <div id="cronOwnerPrefixesList" class="toolbar" style="margin-top:6px; flex-wrap:wrap"></div>
          </div>
        </div>
      </details>

      <div class="toolbar" style="margin-top:10px">
        <button id="cronCreate" class="btn btn-primary ${cronBusy === "create" ? "is-loading" : ""}" ${cronBusy !== "" ? "disabled" : ""}>Create</button>
        <button id="cronReset" class="btn btn-secondary">Reset</button>
        <button id="cronRefresh" class="btn btn-secondary ${cronBusy === "refresh" ? "is-loading" : ""}" ${cronBusy !== "" ? "disabled" : ""}>Refresh</button>
      </div>
      <div class="footer-note">Pick targets with checkboxes. Advanced filters are optional. Azure owner uses <code>org/project</code>.</div>
    </div>
    <div class="card">
      <h3>Selected Repositories</h3>
      <div id="cronSelectionPanel"></div>
    </div>
    </div>
    <div class="card" style="margin-top:14px">
      <h3>Schedules</h3>
      <div class="table-wrap">
        <table>
          <thead><tr><th>ID</th><th>Name</th><th>Expr</th><th>Mode</th><th>Scope</th><th>Last Run</th><th>Actions</th></tr></thead>
          <tbody>
            ${
              rows
                .map((s) => {
                  const scopeObj = parseScopeJSON(s.scope_json);
                  const selectedCount = countSelectedRepos(s.selected_repos, s.scope_json);
                  const ownerCount = Array.isArray(scopeObj?.owners) ? scopeObj.owners.length : 0;
                  const prefixCount = Array.isArray(scopeObj?.owner_prefixes) ? scopeObj.owner_prefixes.length : 0;
                  const scope = `${summarizeTargets(s.targets)}${selectedCount ? ` • ${selectedCount} repos` : ""}${ownerCount ? ` • ${ownerCount} owners` : ""}${prefixCount ? ` • ${prefixCount} prefixes` : ""}`;
                  return `
              <tr>
                <td>#${s.id}</td>
                <td>${escapeHtml(s.name)}${s.enabled === false ? ` <span class="muted">(disabled)</span>` : ""}</td>
                <td><code>${escapeHtml(s.expr)}</code></td>
                <td>${escapeHtml(s.mode || "default")}</td>
                <td class="muted">${escapeHtml(scope)}</td>
                <td>${escapeHtml(fmtDate(s.last_run_at))}</td>
                <td class="row-actions">
                  <button class="btn btn-secondary" data-action="edit" data-id="${s.id}" ${cronBusy !== "" ? "disabled" : ""}>Edit</button>
                  <button class="btn btn-secondary ${cronBusy === `trigger:${s.id}` ? "is-loading" : ""}" data-action="trigger" data-id="${s.id}" ${cronBusy !== "" ? "disabled" : ""}>Trigger</button>
                  <button class="btn btn-danger ${cronBusy === `delete:${s.id}` ? "is-loading" : ""}" data-action="delete" data-id="${s.id}" ${cronBusy !== "" ? "disabled" : ""}>Delete</button>
                </td>
              </tr>`;
                })
                .join("") || `<tr><td colspan="7" class="muted">No schedules configured.</td></tr>`
            }
          </tbody>
        </table>
      </div>
    </div>
  `
  );
  wireCronBuilder(root);
  root.querySelector("#cronRefresh")?.addEventListener("click", refreshCron);
  root.querySelector("#cronCreate")?.addEventListener("click", createCron);
  root.querySelector("#cronBrowseRepos")?.addEventListener("click", browseCronRepos);
  root.querySelector("#cronReset")?.addEventListener("click", resetCronForm);
  root.querySelectorAll("[data-action='edit']").forEach((btn) => {
    btn.addEventListener("click", () => editCron(Number(btn.dataset.id)));
  });
  root.querySelectorAll("[data-action='trigger']").forEach((btn) => {
    btn.addEventListener("click", () => triggerCron(Number(btn.dataset.id)));
  });
  root.querySelectorAll("[data-action='delete']").forEach((btn) => {
    btn.addEventListener("click", () => deleteCron(Number(btn.dataset.id)));
  });
}
