// Circular import: openScanDetailPage is only called inside applyRouteFromLocation (a function body),
// so ESM live bindings resolve correctly before any call happens.
import { openScanDetailPage } from "./actions.js";
import { state } from "./state.js";
import { escapeHtml, setHtml } from "./utils.js";

export const views = [
  { id: "overview", title: "Overview", subtitle: "Gateway status, agent controls, and scan posture." },
  { id: "scans", title: "Scans", subtitle: "Runs, scanner results, findings, and raw downloads." },
  {
    id: "scan-detail",
    title: "Scan Detail",
    subtitle: "Expanded scan view with per-scanner output and findings.",
    hidden: true,
  },
  {
    id: "remediation",
    title: "Remediation",
    subtitle: "Offline AI fix/PR campaigns on existing findings and scan jobs.",
  },
  { id: "cron", title: "Cron Jobs", subtitle: "Schedules that trigger discovery and scans." },
  { id: "agents", title: "Agent Runtime", subtitle: "One orchestrator with configurable scan workers." },
  { id: "config", title: "Config", subtitle: "Review and edit gateway config used during onboarding." },
  { id: "events", title: "Events", subtitle: "Live SSE events emitted by the gateway." },
];

export function viewToPath(id) {
  switch (id) {
    case "overview":
      return "/ui/overview";
    case "scans":
      return "/ui/scans";
    case "remediation":
      return "/ui/remediation";
    case "cron":
      return "/ui/cronjobs";
    case "agents":
      return "/ui/agents";
    case "config":
      return "/ui/config";
    case "events":
      return "/ui/events";
    case "scan-detail":
      if (state.selectedJobId) return `/ui/scans/${state.selectedJobId}`;
      return "/ui/scans";
    default:
      return "/ui";
  }
}

export function setView(id, opts = {}) {
  state.view = id;
  for (const v of views) {
    document.getElementById(`view-${v.id}`).classList.toggle("active", v.id === id);
  }
  const meta = views.find((v) => v.id === id);
  document.getElementById("pageTitle").textContent = meta.title;
  document.getElementById("pageSubtitle").textContent = meta.subtitle;
  const path = viewToPath(id);
  if (opts.replaceHistory) {
    history.replaceState({ view: id, jobId: state.selectedJobId || null }, "", path);
  } else if (opts.pushHistory) {
    history.pushState({ view: id, jobId: state.selectedJobId || null }, "", path);
  }
  renderNav();
}

export function renderNav() {
  const nav = document.getElementById("nav");
  setHtml(
    nav,
    views
      .filter((v) => !v.hidden)
      .map(
        (v) =>
          `<button data-view="${v.id}" class="${state.view === v.id ? "active" : ""}">${escapeHtml(v.title)}</button>`
      )
      .join("")
  );
  nav
    .querySelectorAll("button")
    .forEach((btn) => btn.addEventListener("click", () => setView(btn.dataset.view, { pushHistory: true })));
}

export async function applyRouteFromLocation() {
  const path = window.location.pathname || "/ui";
  const parts = path.replace(/^\/+|\/+$/g, "").split("/");
  if (parts[0] !== "ui") {
    setView("overview");
    return;
  }
  const section = parts[1] || "overview";
  if (section === "scans" && parts[2]) {
    const id = Number(parts[2]);
    if (Number.isFinite(id) && id > 0) {
      try {
        await openScanDetailPage(id, { pushHistory: false });
        return;
      } catch (_) {
        // fall through to scans page if deep-link job no longer exists
      }
    }
    setView("scans");
    return;
  }
  if (section === "" || section === "ui" || section === "overview") {
    setView("overview");
    return;
  }
  const alias = {
    cronjobs: "cron",
    cron: "cron",
    remediation: "remediation",
    agents: "agents",
    config: "config",
    events: "events",
    scans: "scans",
  };
  setView(alias[section] || "overview");
}
