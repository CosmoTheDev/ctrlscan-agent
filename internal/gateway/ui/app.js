/* --- Theme Toggle (runs immediately at parse time, before DOMContentLoaded) --- */
(function initTheme() {
  const saved = localStorage.getItem("ctrlscan-theme") || "dark";
  document.documentElement.setAttribute("data-theme", saved);
  function updateToggleLabel() {
    const current = document.documentElement.getAttribute("data-theme") || "dark";
    const label = document.getElementById("themeToggleLabel");
    if (label) label.textContent = current === "light" ? "Dark Mode" : "Light Mode";
  }
  document.addEventListener("DOMContentLoaded", () => {
    updateToggleLabel();
    document.getElementById("themeToggle")?.addEventListener("click", () => {
      const current = document.documentElement.getAttribute("data-theme") || "dark";
      const next = current === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      localStorage.setItem("ctrlscan-theme", next);
      updateToggleLabel();
    });
  });
})();

import { connectEvents, refreshAll, scheduleLiveRefresh } from "./js/actions.js";
import { stopSweep } from "./js/actions.js";
import {
  openTriggerModal,
  wireConfirmModal,
  wireNoticeModal,
  wirePathIgnoreModal,
  wirePromptModal,
  wireTriggerModal,
} from "./js/modals.js";
/* --- ES Module Imports --- */
import { applyRouteFromLocation, renderNav, setView } from "./js/router.js";

/* --- Bootstrap --- */
async function bootstrap() {
  renderNav();
  wireGlobalButtons();
  wireNoticeModal();
  wireConfirmModal();
  wirePromptModal();
  wirePathIgnoreModal();
  wireTriggerModal();
  // Initialize view without rewriting the current URL; route parsing below
  // will choose the correct view and preserve deep links on browser refresh.
  setView("overview");
  connectEvents();
  await refreshAll();
  await applyRouteFromLocation();
  setInterval(() => {
    if (document.visibilityState === "hidden") return;
    scheduleLiveRefresh();
  }, 5000);
}

function wireGlobalButtons() {
  document.getElementById("refreshBtn").addEventListener("click", refreshAll);
  document.getElementById("triggerBtn").addEventListener("click", openTriggerModal);
  document.getElementById("stopBtn").addEventListener("click", stopSweep);
  window.addEventListener("popstate", () => {
    applyRouteFromLocation();
  });
}

bootstrap();
