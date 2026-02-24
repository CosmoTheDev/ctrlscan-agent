// Circular imports are only used inside function bodies, so ESM live bindings are safe here.
import { openScanDetailByLookup, openScanDetailPage } from "./actions.js";
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
    id: "vulnerabilities",
    title: "Vulnerabilities",
    subtitle: "Cross-repo vulnerability database with filters and AI fix status.",
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

export function viewToPath(id, opts = {}) {
  switch (id) {
    case "overview":
      return "/ui/overview";
    case "scans":
      return "/ui/scans";
    case "vulnerabilities": {
      const params = opts.params ? "?" + new URLSearchParams(opts.params).toString() : "";
      return "/ui/vulnerabilities" + params;
    }
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
  const prevView = state.view;
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
  // Trigger data load when switching to vulnerabilities view
  if (id === "vulnerabilities" && prevView !== "vulnerabilities") {
    import("./actions.js").then(({ refreshVulnerabilities }) => refreshVulnerabilities()).catch(() => {});
  }
  // Load repo suggestions when switching to scans view
  if (id === "scans" && !state.scansRepoSuggestionsLoaded) {
    import("./actions.js").then(({ refreshScansRepos }) => refreshScansRepos()).catch(() => {});
  }
}

export function renderNav() {
  const nav = document.getElementById("nav");
  setHtml(
    nav,
    views
      .filter((v) => !v.hidden)
      .map(
        (v) =>
          `<button data-view="${v.id}" class="${state.view === v.id ? "active" : ""} ${state.navPendingView === v.id ? "is-loading" : ""}">${escapeHtml(v.title)}</button>`
      )
      .join("")
  );
  nav.querySelectorAll("button").forEach((btn) =>
    btn.addEventListener("click", () => {
      const target = btn.dataset.view;
      if (!target || target === state.view) {
        setView(target || state.view, { pushHistory: true });
        return;
      }
      state.navPendingView = target;
      renderNav();
      requestAnimationFrame(() => {
        setView(target, { pushHistory: true });
        state.navPendingView = "";
        renderNav();
      });
    })
  );
}

export async function applyRouteFromLocation() {
  const path = window.location.pathname || "/ui";
  const parts = path.replace(/^\/+|\/+$/g, "").split("/");
  if (parts[0] !== "ui") {
    setView("overview");
    return;
  }
  const section = parts[1] || "overview";
  if (section === "scans" && parts[2] === "details") {
    const q = new URLSearchParams(window.location.search || "");
    const source = q.get("source") || q.get("provider") || "";
    const repo = q.get("repo") || "";
    const branch = q.get("branch") || "";
    const commit = q.get("commit") || q.get("commit_sha") || "";
    if (source && repo) {
      try {
        await openScanDetailByLookup({ source, repo, branch, commit }, { pushHistory: false });
        return;
      } catch (_) {
        // fall through to scans page if lookup does not resolve
      }
    }
    setView("scans");
    return;
  }
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
  if (section === "vulnerabilities") {
    const urlParams = new URLSearchParams(window.location.search || "");
    // Circular import — used inside function body, safe.
    const { applyVulnerabilitiesUrlParams } = await import("./actions.js");
    applyVulnerabilitiesUrlParams(urlParams);
    setView("vulnerabilities");
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
