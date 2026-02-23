import { state } from './state.js';
import { escapeHtml, setHtml } from './utils.js';

export function showToast({ title, message = "", kind = "info", timeoutMs = 3500 } = {}) {
  const stack = document.getElementById("toastStack");
  if (!stack) return;
  const el = document.createElement("div");
  el.className = `toast toast-${kind}`;
  setHtml(el, `
    <div class="toast-title">${escapeHtml(title || "Notice")}</div>
    ${message ? `<div class="toast-body">${escapeHtml(message)}</div>` : ""}
  `);
  stack.prepend(el);
  const remove = () => {
    if (el.parentNode) el.parentNode.removeChild(el);
  };
  const t = setTimeout(remove, timeoutMs);
  el.addEventListener("click", () => {
    clearTimeout(t);
    remove();
  });
}

export function handleToastForEvent(evt) {
  const payload = evt?.payload && typeof evt.payload === "object" ? evt.payload : {};
  switch (evt?.type) {
    case "agent.triggered": {
      state.sweepUi.skipEventCount = 0;
      const selected = Number(payload.selected_repos || 0);
      const workers = Number(payload.workers || 0);
      let msg = selected > 0 ? `Trigger accepted for ${selected} selected repos.` : "Trigger accepted. Discovery and scans will start shortly.";
      if (workers > 0) msg += ` Workers: ${workers}.`;
      showToast({ title: "Sweep Triggered", message: msg, kind: "info", timeoutMs: 3000 });
      break;
    }
    case "sweep.started": {
      state.sweepUi.latestSummary = {
        status: "running",
        started_at: payload.started_at || new Date().toISOString(),
        completed_at: "",
        duration_seconds: 0,
        workers: Number(payload.workers || 0),
        selected_repos: Number(payload.selected_repos || 0),
        scan_targets: Array.isArray(payload.scan_targets) ? payload.scan_targets : [],
        skipped_repos: 0,
        skipped_by_reason: {},
      };
      const workers = Number(payload.workers || 0);
      const selected = Number(payload.selected_repos || 0);
      let msg = workers > 0 ? `${workers} worker${workers === 1 ? "" : "s"} active.` : "Workers active.";
      if (selected > 0) msg += ` Scanning ${selected} selected repos.`;
      showToast({ title: "Sweep Started", message: msg, kind: "success", timeoutMs: 2800 });
      break;
    }
    case "repo.skipped": {
      state.sweepUi.skipEventCount = (state.sweepUi.skipEventCount || 0) + 1;
      break; // avoid spamming a toast per repo; summary shown on sweep.completed
    }
    case "sweep.completed": {
      state.sweepUi.latestSummary = {
        ...(state.sweepUi.latestSummary || {}),
        status: String(payload.status || "completed"),
        started_at: payload.started_at || state.sweepUi.latestSummary?.started_at || "",
        completed_at: payload.completed_at || new Date().toISOString(),
        duration_seconds: Number(payload.duration_seconds || 0),
        skipped_repos: Number(payload.skipped_repos || 0),
        skipped_by_reason: payload.skipped_by_reason && typeof payload.skipped_by_reason === "object" ? payload.skipped_by_reason : {},
      };
      const status = String(payload.status || "completed");
      const skipped = Number(payload.skipped_repos || 0);
      const reasons = payload.skipped_by_reason && typeof payload.skipped_by_reason === "object" ? payload.skipped_by_reason : {};
      const recentSkipped = Number(reasons["recently scanned within 24h"] || 0);
      let title = "Sweep Completed";
      let kind = "success";
      if (status === "cancelled") {
        title = "Sweep Cancelled";
        kind = "warn";
      } else if (status !== "completed") {
        title = `Sweep ${status[0]?.toUpperCase() || ""}${status.slice(1)}`;
        kind = "info";
      }
      let msg = skipped > 0 ? `${skipped} repo${skipped === 1 ? "" : "s"} skipped.` : "No repo skips reported.";
      if (recentSkipped > 0) msg += ` ${recentSkipped} skipped because they were scanned within 24h.`;
      const dur = Number(payload.duration_seconds || 0);
      if (dur > 0) msg += ` Duration: ${dur.toFixed(1)}s.`;
      showToast({ title, message: msg, kind, timeoutMs: 5500 });
      break;
    }
    case "agent.stop_requested": {
      showToast({ title: "Stopping Sweep", message: "Cancellation requested. Running scanners will stop shortly.", kind: "warn", timeoutMs: 3500 });
      break;
    }
  }
}
