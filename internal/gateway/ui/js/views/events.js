import { state } from '../state.js';
import { escapeHtml, setHtml } from '../utils.js';

export function renderEvents() {
  const root = document.getElementById("view-events");
  setHtml(root, `
    <div class="card">
      <div class="toolbar">
        <button id="eventsClear" class="btn btn-secondary">Clear</button>
        <span class="muted">Live SSE from <code>/events</code></span>
      </div>
      <pre class="code" id="eventsLog">${escapeHtml(state.events.map(e => `${e.at} ${e.type} ${JSON.stringify(e.payload ?? {})}`).join("\n"))}</pre>
    </div>
  `);
  root.querySelector("#eventsClear")?.addEventListener("click", () => {
    state.events = [];
    renderEvents();
  });
}
