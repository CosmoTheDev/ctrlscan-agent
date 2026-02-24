/**
 * Unit tests for js/utils.js — pure functions with no DOM or network dependencies.
 *
 * Run in browser via test.html, or with any ES-module-capable test runner
 * (e.g. Vitest, web-test-runner, Deno test).
 *
 * Test format: each test() call registers an assertion group.
 * The harness is self-contained so no external framework is needed to
 * view results in a browser (open test.html served under /ui/js/tests/).
 */

import {
  escapeHtml,
  fmtDuration,
  fmtDate,
  normalizeSeverityLabel,
  severityBucket,
  countFindingsBySeverity,
  statusClass,
  repoSelectionKey,
} from '../utils.js';

/* ---- Tiny test harness ---- */

let passed = 0;
let failed = 0;
const results = [];

function assert(description, got, expected) {
  const ok = JSON.stringify(got) === JSON.stringify(expected);
  if (ok) {
    passed++;
    results.push({ ok: true, description });
  } else {
    failed++;
    results.push({ ok: false, description, got, expected });
    console.error(`FAIL: ${description}\n  got:      ${JSON.stringify(got)}\n  expected: ${JSON.stringify(expected)}`);
  }
}

function assertTrue(description, value) {
  assert(description, !!value, true);
}

/* ---- escapeHtml ---- */

assert("escapeHtml: ampersand", escapeHtml("a & b"), "a &amp; b");
assert("escapeHtml: less-than", escapeHtml("<script>"), "&lt;script&gt;");
assert("escapeHtml: double-quote", escapeHtml('"hello"'), "&quot;hello&quot;");
assert("escapeHtml: null/undefined coerces", escapeHtml(null), "");
assert("escapeHtml: number coerces", escapeHtml(42), "42");
assert("escapeHtml: clean string unchanged", escapeHtml("hello world"), "hello world");

/* ---- fmtDuration ---- */

assert("fmtDuration: 0ms", fmtDuration(0), "0ms");
assert("fmtDuration: 500ms", fmtDuration(500), "500ms");
assert("fmtDuration: 1500ms → seconds", fmtDuration(1500), "1.5s");
assert("fmtDuration: 60000ms → minutes", fmtDuration(60000), "1m 0s");
assert("fmtDuration: 90500ms → 1m 30s", fmtDuration(90500), "1m 31s");
assert("fmtDuration: null → n/a", fmtDuration(null), "n/a");
assert("fmtDuration: undefined → n/a", fmtDuration(undefined), "n/a");

/* ---- normalizeSeverityLabel ---- */

assert("normalizeSeverityLabel: lowercases and trims", normalizeSeverityLabel("  high  "), "HIGH");
assert("normalizeSeverityLabel: empty", normalizeSeverityLabel(""), "");
assert("normalizeSeverityLabel: null", normalizeSeverityLabel(null), "");

/* ---- severityBucket ---- */

assert("severityBucket: CRITICAL", severityBucket("CRITICAL"), "CRITICAL");
assert("severityBucket: critical (lowercase)", severityBucket("critical"), "CRITICAL");
assert("severityBucket: HIGH", severityBucket("HIGH"), "HIGH");
assert("severityBucket: ERROR → HIGH", severityBucket("ERROR"), "HIGH");
assert("severityBucket: MEDIUM", severityBucket("MEDIUM"), "MEDIUM");
assert("severityBucket: WARNING → MEDIUM", severityBucket("WARNING"), "MEDIUM");
assert("severityBucket: WARN → MEDIUM", severityBucket("WARN"), "MEDIUM");
assert("severityBucket: LOW", severityBucket("LOW"), "LOW");
assert("severityBucket: INFO → LOW", severityBucket("INFO"), "LOW");
assert("severityBucket: unknown passthrough", severityBucket("CUSTOM"), "CUSTOM");
assert("severityBucket: empty string", severityBucket(""), "");

/* ---- countFindingsBySeverity ---- */

assert("countFindingsBySeverity: empty", countFindingsBySeverity([]), { critical: 0, high: 0, medium: 0, low: 0 });
assert("countFindingsBySeverity: mixed", countFindingsBySeverity([
  { severity: "CRITICAL" },
  { severity: "HIGH" },
  { severity: "ERROR" },
  { severity: "MEDIUM" },
  { severity: "LOW" },
  { severity: "INFO" },
]), { critical: 1, high: 2, medium: 1, low: 2 });
assert("countFindingsBySeverity: null input", countFindingsBySeverity(null), { critical: 0, high: 0, medium: 0, low: 0 });

/* ---- statusClass ---- */

assert("statusClass: completed", statusClass("completed"), "status-completed");
assert("statusClass: COMPLETED uppercase", statusClass("COMPLETED"), "status-completed");
assert("statusClass: running", statusClass("running"), "status-running");
assert("statusClass: stopped", statusClass("stopped"), "status-stopped");
assert("statusClass: failed", statusClass("failed"), "status-failed");
assert("statusClass: partial", statusClass("partial"), "status-partial");
assert("statusClass: unknown → empty", statusClass("unknown"), "");
assert("statusClass: empty → empty", statusClass(""), "");

/* ---- repoSelectionKey ---- */

assert("repoSelectionKey: full repo", repoSelectionKey({ provider: "github", host: "github.com", owner: "Acme", name: "Repo" }), "github|github.com|acme|repo");
assert("repoSelectionKey: missing fields", repoSelectionKey({}), "|||");
assert("repoSelectionKey: lowercases", repoSelectionKey({ provider: "GITHUB", host: "GITHUB.COM", owner: "User", name: "Proj" }), "github|github.com|user|proj");

/* ---- fmtDate ---- */

assert("fmtDate: null → n/a", fmtDate(null), "n/a");
assert("fmtDate: empty → n/a", fmtDate(""), "n/a");
assertTrue("fmtDate: valid ISO string returns non-empty", fmtDate("2026-02-23T00:00:00Z").length > 0);
assert("fmtDate: invalid string returns original", fmtDate("not-a-date"), "not-a-date");

/* ---- Summary ---- */

console.log(`\nTest results: ${passed} passed, ${failed} failed`);

export { passed, failed, results };
