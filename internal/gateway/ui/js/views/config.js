import { refreshConfig } from "../actions.js";
import { api } from "../api.js";
// Circular imports — all usages are inside function bodies.
import { showNotice } from "../modals.js";
import { state } from "../state.js";
import { escapeHtml, setHtml } from "../utils.js";

export function renderConfig() {
  const root = document.getElementById("view-config");
  setHtml(
    root,
    `
    <div class="card">
      <h3>Gateway Config</h3>
      <div class="muted">Path: ${escapeHtml(state.configPath || "default")}</div>
      <div class="footer-note">Secrets are redacted on read. Saving this JSON preserves unchanged masked secrets.</div>
      <div class="toolbar" style="margin-top:10px">
        <button id="cfgRefresh" class="btn btn-secondary">Refresh</button>
        <button id="cfgSave" class="btn btn-primary">Save</button>
      </div>
      <textarea id="cfgEditor" class="code-edit"></textarea>
    </div>
  `
  );
  const editor = root.querySelector("#cfgEditor");
  editor.value = state.config ? JSON.stringify(state.config, null, 2) : "{\n}";
  root.querySelector("#cfgRefresh").addEventListener("click", refreshConfig);
  root.querySelector("#cfgSave").addEventListener("click", async () => {
    try {
      const parsed = JSON.parse(editor.value);
      await api("/api/config", { method: "PUT", body: JSON.stringify(parsed) });
      await refreshConfig();
      showNotice("Config Saved", "Configuration saved.");
    } catch (err) {
      showNotice("Config Save Failed", err.message);
    }
  });
}
