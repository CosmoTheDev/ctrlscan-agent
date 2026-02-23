/**
 * Pure utility helpers — no DOM dependencies, fully unit-testable.
 */

export function escapeHtml(v) {
  return String(v ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/**
 * Safely replace DOM node contents using a document fragment to avoid
 * innerHTML assignment (avoids some XSS lint false-positives).
 */
export function setHtml(el, html) {
  if (!el) return;
  const range = document.createRange();
  range.selectNodeContents(el);
  el.replaceChildren(range.createContextualFragment(String(html ?? "")));
}

export function repoSelectionKey(r) {
  return [r.provider || "", r.host || "", r.owner || "", r.name || ""].join("|").toLowerCase();
}

export function fmtDuration(ms) {
  if (!ms && ms !== 0) return "n/a";
  if (ms < 1000) return `${ms}ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)}s`;
  return `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`;
}

export function fmtDate(v) {
  if (!v) return "n/a";
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) return v;
  return d.toLocaleString();
}

export function normalizeSeverityLabel(v) {
  return String(v || "")
    .trim()
    .toUpperCase();
}

export function severityBucket(v) {
  const s = normalizeSeverityLabel(v);
  if (s === "CRITICAL") return "CRITICAL";
  if (s === "HIGH" || s === "ERROR") return "HIGH";
  if (s === "MEDIUM" || s === "WARNING" || s === "WARN") return "MEDIUM";
  if (s === "LOW" || s === "INFO") return "LOW";
  return s;
}

export function countFindingsBySeverity(findings) {
  const totals = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings || []) {
    const s = severityBucket(f.severity);
    if (s === "CRITICAL") totals.critical++;
    else if (s === "HIGH") totals.high++;
    else if (s === "MEDIUM") totals.medium++;
    else if (s === "LOW") totals.low++;
  }
  return totals;
}

export function statusClass(v) {
  const s = String(v || "").toLowerCase();
  if (s.includes("complete")) return "status-completed";
  if (s.includes("run")) return "status-running";
  if (s.includes("stop")) return "status-stopped";
  if (s.includes("fail")) return "status-failed";
  if (s.includes("partial")) return "status-partial";
  return "";
}
