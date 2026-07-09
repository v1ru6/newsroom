/* NewsRoom console - logic for the "Newsroom Dashboard" design.
   Data access is isolated in `api`: live /api/* endpoints first
   (newsroom serve/watch), static data.json as fallback. All untrusted
   strings are rendered via textContent. */
"use strict";

async function fetchJson(path) {
  const res = await fetch(path, { cache: "no-store" });
  if (!res.ok) throw new Error(path + " " + res.status);
  return res.json();
}

function parseJsonList(value) {
  if (Array.isArray(value)) return value;
  try {
    const parsed = JSON.parse(value || "[]");
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

const api = {
  async summary() {
    try {
      return await this.live();
    } catch {
      return fetchJson("data.json");
    }
  },
  async live() {
    const [summary, alerts, decisions, sources, kev, runs] = await Promise.all([
      fetchJson("/api/summary"), fetchJson("/api/alerts?limit=50"),
      fetchJson("/api/decisions?limit=200"), fetchJson("/api/sources"),
      fetchJson("/api/kev?limit=8"), fetchJson("/api/runs?limit=5"),
    ]);
    return {
      generated_at: summary.last_run
        ? (summary.last_run.finished_at || summary.last_run.started_at)
        : new Date().toISOString(),
      threat_level: summary.threat_level,
      timeline: summary.timeline,
      alerts: alerts.map((a) => ({
        alert_id: a.alert_id, title: a.article_title || "",
        severity: a.severity, score: a.last_score, source: a.source_id,
        url: a.url, why: a.why_it_matters,
        evidence: JSON.parse(a.evidence_json || "[]"),
        results: parseJsonList(a.results_json),
        safety_notes: parseJsonList(a.safety_notes_json),
        first_alerted_at: a.first_alerted_at, last_seen_at: a.last_seen_at,
        max_score: a.max_score, events: a.event_count,
        review_status: a.review_status || "auto",
      })),
      watchlist: decisions.filter((d) => d.decision === "watchlist")
        .map((d) => ({ title: d.title, score: d.average_score,
                       threshold: d.threshold || 0.55, source: d.source_id,
                       url: d.url, gate_status: d.gate_status,
                       results: parseJsonList(d.results_json),
                       safety_notes: parseJsonList(d.safety_notes_json),
                       suppression_reason: d.suppression_reason || "" })),
      suppressed_count: decisions.filter((d) => d.decision === "suppressed").length,
      sources: sources.map((s) => ({ source_id: s.source_id, status: s.status,
        items: s.items_fetched, error: s.error })),
      kev, runs,
    };
  },
};

const $ = (sel) => document.querySelector(sel);
const CVE_RE = /CVE-\d{4}-\d{4,7}/i;
const POSTURE = [
  { max: 0.20, name: "LOW", cls: "green" },
  { max: 0.30, name: "GUARDED", cls: "blue" },
  { max: 0.40, name: "ELEVATED", cls: "orange" },
  { max: 0.55, name: "HIGH", cls: "red" },
  { max: 9.99, name: "SEVERE", cls: "red" },
];
const COLORS = { green: "var(--green)", blue: "var(--blue)", orange: "var(--orange)",
                 red: "var(--red)", yellow: "var(--yellow)" };

const state = { data: null, filter: "all", query: "", selected: -1, expanded: null,
                watchExpanded: null,
                theme: localStorage.getItem("nr-theme") || "dark" };

function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text;  // untrusted-safe
  return node;
}

function link(href, cls, text) {
  const a = el("a", cls, text);
  a.href = href;
  a.target = "_blank";
  a.rel = "noopener noreferrer";
  a.addEventListener("click", (e) => e.stopPropagation());
  return a;
}

function fmtAge(iso) {
  const ms = Date.now() - Date.parse(iso);
  if (!Number.isFinite(ms)) return "";
  const m = Math.max(0, Math.round(ms / 60000));
  if (m < 60) return m + "m";
  const h = Math.round(m / 60);
  if (h < 48) return h + "h";
  return Math.round(h / 24) + "d";
}

function score100(x) { return Math.round((x || 0) * 100); }

function isPromoted(item) {
  return (item.safety_notes || []).some((note) => note.startsWith("promoted:"));
}

function activeAttackWasLlmReviewed(result) {
  return result && result.classifier === "active_attack" &&
    (result.reasons || []).some((reason) => reason.toLowerCase().startsWith("llm:"));
}

function llmReviewInfo(item) {
  const results = item.results || [];
  const sources = [];
  if (results.some(activeAttackWasLlmReviewed)) sources.push("active-attack expert");
  if (results.some((r) => r.classifier === "llm_triage")) sources.push("triage reviewer");
  return {
    reviewed: sources.length > 0,
    label: "LLM EXPERT",
    detail: sources.join(", "),
  };
}

function routeCode(item, prefix) {
  return `${prefix}${score100(item.score)}`;
}

function routeLabel(item, kind) {
  if (kind === "alert") return isPromoted(item) ? "PROMOTED" : "ALERT";
  return score100(item.score) >= 45 ? "WATCH HIGH" : "WATCH";
}

function postureFor(level) {
  const idx = POSTURE.findIndex((b) => level < b.max);
  return { idx: Math.max(idx, 0), ...POSTURE[Math.max(idx, 0)] };
}

function cveOf(item) {
  const evidence = (item.evidence || []).join(" ");
  const results = (item.results || []).flatMap((r) =>
    [...(r.evidence || []), ...(r.reasons || [])]).join(" ");
  const hit = (item.title.match(CVE_RE) || evidence.match(CVE_RE) ||
    results.match(CVE_RE) || [])[0];
  return hit ? hit.toUpperCase() : null;
}

/* Enrich alerts with KEV corroboration using the KEV list already fetched. */
function annotate(d) {
  const kevById = new Map((d.kev || []).map((k) => [k.cve_id, k]));
  [...(d.alerts || []), ...(d.watchlist || [])].forEach((a) => {
    a.cve = cveOf(a);
    a.kevEntry = a.cve ? kevById.get(a.cve) || null : null;
  });
}

function activeAlerts() {
  return (state.data.alerts || []).filter((a) => a.review_status !== "dismissed");
}

function visibleAlerts() {
  const q = state.query.toLowerCase();
  return (state.data.alerts || []).filter((a) =>
    (state.filter === "all" || a.severity === state.filter) &&
    (!q || a.title.toLowerCase().includes(q) || (a.cve || "").toLowerCase().includes(q)));
}

/* ---------- topbar + posture ---------- */

function renderTop() {
  const d = state.data;
  $("#status-run").textContent = "last run " + fmtAge(d.generated_at) + " ago";
  const live = (d.sources || []).filter((s) => s.status === "ok" || s.status === "fixture").length;
  const total = (d.sources || []).length;
  $("#sources-live").textContent = `${live}/${total} sources live`;
  $("#status-sources").querySelector(".dot").className =
    "dot " + (live === total && total > 0 ? "ok" : "err");
}

function renderPosture() {
  const d = state.data;
  const level = d.threat_level ?? 0;
  const p = postureFor(level);

  const word = $("#posture-word");
  word.textContent = p.name;
  word.style.color = COLORS[p.cls];

  // trend vs. the previous day's average score, when history exists
  const days = (d.timeline || []).filter((t) => t.avg_score != null);
  const prev = days.length >= 2 ? postureFor(days[days.length - 2].avg_score) : null;
  const trend = $("#posture-trend");
  if (prev && prev.idx !== p.idx) {
    const up = p.idx > prev.idx;
    trend.textContent = `${up ? "▲ up" : "▼ down"} from ${prev.name.charAt(0) + prev.name.slice(1).toLowerCase()}`;
    trend.style.color = up ? COLORS[p.cls] : COLORS.green;
  } else {
    trend.textContent = days.length >= 2 ? "- holding" : "";
    trend.style.color = "var(--faint)";
  }

  const segs = $("#posture-meter").children;
  const scale = $("#posture-scale").children;
  for (let i = 0; i < 5; i++) {
    const seg = segs[i];
    seg.className = "";
    seg.style.background = "var(--chip)";
    seg.style.boxShadow = "none";
    scale[i].style.color = "var(--faint)";
    if (i < p.idx) {
      seg.className = "past";
      seg.style.background = `color-mix(in srgb, ${COLORS[POSTURE[i].cls]} 28%, transparent)`;
    } else if (i === p.idx) {
      seg.className = "now";
      seg.style.background = COLORS[p.cls];
      seg.style.boxShadow = `0 0 16px color-mix(in srgb, ${COLORS[p.cls]} 55%, transparent)`;
      scale[i].style.color = COLORS[p.cls];
    }
  }

  const act = activeAlerts();
  $("#stat-action").textContent = act.length;
  $("#stat-watch").textContent = (d.watchlist || []).length;
  $("#stat-filtered").textContent = d.suppressed_count ?? 0;

  renderNarrative(act);
}

function renderNarrative(act) {
  const n = $("#narrative");
  n.replaceChildren();
  const crit = act.filter((a) => a.severity === "critical");
  const kevHits = act.filter((a) => a.kevEntry);
  const pending = act.filter((a) => a.review_status === "pending").length;

  if (!act.length) {
    n.append("No alerts above threshold - volume is normal. ",
      el("span", null, `${(state.data.watchlist || []).length} items on the watchlist.`));
    return;
  }
  if (crit.length) {
    n.append(`${crit.length === 1 ? "One" : crit.length} `);
    n.append(Object.assign(el("b", "red"), { textContent:
      `critical alert${crit.length === 1 ? "" : "s"}` }));
    n.append(kevHits.length
      ? ` ${crit.length === 1 ? "is" : "include CVEs"} on the CISA Known Exploited list.`
      : " needs attention.");
  } else {
    n.append(`${act.length} `);
    n.append(Object.assign(el("b", "orange"), { textContent: "active alerts" }));
    n.append(kevHits.length ? " - KEV-corroborated exploitation in the mix." : " - none critical.");
  }
  if (pending) n.append(` ${pending} flagged by injection tripwires await your review.`);
  else n.append(" Otherwise volume is normal.");
}

/* ---------- alert cards ---------- */

function tagChips(alert) {
  const tags = (alert.why || "").split(";").map((s) => s.trim()).filter(Boolean).slice(0, 3);
  const wrap = el("div", "card-tags");
  tags.forEach((t) => wrap.append(el("span", "chip-tag", t)));
  if (alert.kevEntry) wrap.append(el("span", "chip-tag kev", "In CISA KEV"));
  return wrap;
}

function alertCard(a, i) {
  const card = el("article", "card " + a.severity);
  if (a.review_status === "dismissed") card.classList.add("dismissed");
  if (i === state.selected) card.classList.add("sel");
  const llmInfo = llmReviewInfo(a);

  const top = el("div", "card-top");
  const route = isPromoted(a) ? "promoted" : "alert";
  top.append(el("span", `badge route ${route}`,
    `${routeCode(a, isPromoted(a) ? "P" : "A")} · ${routeLabel(a, "alert")}`));
  top.append(el("span", "badge " + a.severity, a.severity.toUpperCase()));
  if (llmInfo.reviewed) {
    const badge = el("span", "badge llm", llmInfo.label);
    badge.title = "Reviewed by " + llmInfo.detail;
    top.append(badge);
  }
  if (a.cve) top.append(el("span", "card-cve", a.cve));
  if (a.kevEntry) top.append(el("span", "card-product",
    `${a.kevEntry.vendor} ${a.kevEntry.product}`.trim()));
  if (a.review_status === "pending") top.append(el("span", "badge review", "NEEDS REVIEW"));
  top.append(el("span", "card-src",
    `${a.source} · ${fmtAge(a.last_seen_at || a.first_alerted_at)}`));
  card.append(top);

  card.append(link(a.url, "card-title", a.title));
  if (a.why) card.append(el("div", "card-why", a.why));
  card.append(tagChips(a));

  const actions = el("div", "card-actions");
  actions.append(link(a.url, "btn primary", "Open source ↗"));
  const detailsBtn = el("button", "btn", state.expanded === a.alert_id ? "Hide details" : "Details");
  detailsBtn.addEventListener("click", () => {
    state.expanded = state.expanded === a.alert_id ? null : a.alert_id;
    renderAlerts();
  });
  actions.append(detailsBtn);
  if (a.review_status !== "dismissed") {
    const suppress = el("button", "btn quiet", "Suppress");
    suppress.addEventListener("click", () => reviewAlert(a.alert_id, "dismissed"));
    actions.append(suppress);
  }
  card.append(actions);

  if (state.expanded === a.alert_id) {
    const det = el("div", "card-details");
    const bits = [`first seen ${fmtAge(a.first_alerted_at)} ago`];
    bits.push(`score ${score100(a.score)}`);
    if (a.max_score && a.max_score !== a.score) bits.push(`max score ${score100(a.max_score)}`);
    if (a.events > 1) bits.push(`${a.events} lifecycle events`);
    if (llmInfo.reviewed) bits.push(`LLM reviewed: ${llmInfo.detail}`);
    det.append(el("div", "card-meta", bits.join(" · ")));
    (a.safety_notes || []).forEach((note) => det.append(el("div", "evidence", note)));
    (a.evidence || []).forEach((ev) => det.append(el("div", "evidence", "· " + ev)));
    if (a.review_status === "pending") {
      const strip = el("div", "review-strip");
      strip.append(el("span", null, "Injection tripwires fired - verify at the source before trusting:"));
      const ok = el("button", "btn", "Approve");
      ok.addEventListener("click", () => reviewAlert(a.alert_id, "approved"));
      const no = el("button", "btn quiet", "Dismiss");
      no.addEventListener("click", () => reviewAlert(a.alert_id, "dismissed"));
      strip.append(ok, no);
      det.append(strip);
    } else if (a.review_status !== "auto") {
      det.append(el("div", "card-meta", "review: " + a.review_status));
    }
    card.append(det);
  }

  card.addEventListener("click", () => { state.selected = i; restyleSelection(); });
  return card;
}

function renderAlerts() {
  const list = $("#alert-list");
  list.replaceChildren();
  const rows = visibleAlerts();
  const pending = rows.filter((a) => a.review_status === "pending").length;
  const pill = $("#review-pill");
  pill.hidden = pending === 0;
  pill.textContent = `${pending} promoted for review`;
  if (!rows.length) { list.append(el("div", "empty", "no alerts match")); return; }
  rows.forEach((a, i) => list.append(alertCard(a, i)));
}

function restyleSelection() {
  document.querySelectorAll("#alert-list .card").forEach((c, i) =>
    c.classList.toggle("sel", i === state.selected));
}

/* ---------- watch table + rail ---------- */

function renderWatch() {
  const table = $("#watch-list");
  table.replaceChildren();
  const rows = [...(state.data.watchlist || [])].sort((a, b) =>
    (b.score || 0) - (a.score || 0) ||
    (a.title || "").localeCompare(b.title || ""));
  if (!rows.length) { table.append(el("div", "empty", "watchlist is empty")); return; }
  rows.forEach((w) => {
    const shell = el("div", "watch-item");
    const row = el("div", "watch-row");
    const key = watchKey(w);
    if (state.watchExpanded === key) row.classList.add("open");
    row.tabIndex = 0;
    row.setAttribute("role", "button");
    row.setAttribute("aria-expanded", String(state.watchExpanded === key));
    const sevName = w.score >= 0.45 ? "near" : "watch";
    const sev = el("span", "watch-sev " + sevName);
    sev.append(el("span", "dot"), el("span", null,
      `${routeCode(w, "W")} · ${routeLabel(w, "watch")}`));
    row.append(sev);
    row.append(link(w.url, "watch-title", w.title));
    row.append(el("span", "watch-src", w.source || ""));
    row.append(el("span", "watch-score", String(score100(w.score))));
    row.addEventListener("click", () => toggleWatch(key));
    row.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        toggleWatch(key);
      }
    });
    shell.append(row);
    if (state.watchExpanded === key) shell.append(watchDetails(w));
    table.append(shell);
  });
}

function watchKey(w) {
  return w.url || w.title;
}

function toggleWatch(key) {
  state.watchExpanded = state.watchExpanded === key ? null : key;
  renderWatch();
}

function expertResult(w, name) {
  return (w.results || []).find((r) => r.classifier === name) || null;
}

function expertSummary(result) {
  if (!result) return "0 - no signal";
  const reasons = (result.reasons || []).join("; ") || "no signal";
  return `${score100(result.score)} - ${reasons}`;
}

function watchReason(w) {
  const gap = Math.max(0, score100(w.threshold || 0.55) - score100(w.score));
  const confidence = expertResult(w, "confidence");
  const notes = [];
  if (gap > 0) notes.push(`below alert threshold by ${gap} points`);
  if (confidence && !(confidence.reasons || []).includes("recent, substantive, unhedged item")) {
    notes.push((confidence.reasons || []).join("; "));
  }
  if (w.kevEntry || (w.safety_notes || []).some((n) => n.includes("kev_corroboration"))) {
    notes.push("CISA KEV corroborated");
  } else if (w.cve) {
    notes.push("CVE seen, no KEV corroboration recorded");
  }
  if (!notes.length) notes.push("watch-level aggregate signal, not alert-level signal");
  return notes.join("; ");
}

function watchDetails(w) {
  const det = el("div", "watch-details");
  const llmInfo = llmReviewInfo(w);
  det.append(el("div", "watch-why", "Why not alert: " + watchReason(w)));
  const meta = el("div", "watch-meta");
  meta.append(el("span", null, `score ${score100(w.score)}`));
  meta.append(el("span", null, `alert threshold ${score100(w.threshold || 0.55)}`));
  meta.append(el("span", null, `gate ${w.gate_status || "pass"}`));
  if (llmInfo.reviewed) meta.append(el("span", "llm-reviewed",
    `LLM reviewed: ${llmInfo.detail}`));
  if (w.cve) meta.append(el("span", null, w.cve));
  det.append(meta);
  const grid = el("div", "expert-grid");
  [
    ["vulnerability", "Vuln"],
    ["active_attack", "Attack"],
    ["breach_impact", "Breach"],
    ["confidence", "Confidence"],
  ].forEach(([id, label]) => {
    const result = expertResult(w, id);
    const cell = el("div", "expert-cell");
    const title = id === "active_attack" && activeAttackWasLlmReviewed(result)
      ? label + " (LLM)"
      : label;
    cell.append(el("b", null, title));
    cell.append(el("span", null, expertSummary(result)));
    grid.append(cell);
  });
  det.append(grid);
  (w.safety_notes || []).forEach((note) =>
    det.append(el("div", "watch-note", note)));
  det.append(link(w.url, "btn quiet", "Open source"));
  return det;
}

function fmtDue(iso) {
  if (!iso) return null;
  const days = Math.ceil((Date.parse(iso) - Date.now()) / 86400000);
  if (!Number.isFinite(days)) return null;
  return days;
}

function renderKev() {
  const list = $("#kev-list");
  list.replaceChildren();
  const rows = state.data.kev || [];
  if (!rows.length) { list.append(el("div", "empty", "catalog not fetched yet")); return; }
  rows.forEach((k) => {
    const row = el("div", "kev-row");
    row.append(link(`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(k.cve_id)}`,
                    "kev-cve", k.cve_id));
    row.append(el("span", "kev-product", `${k.vendor} ${k.product}`.trim()));
    if (k.seen_in_stream) row.append(el("span", "kev-stream", "IN STREAM"));
    const due = fmtDue(k.due_date);
    if (due !== null) {
      const cls = due < 0 ? "overdue" : due <= 10 ? "soon" : "";
      row.append(el("span", "kev-due " + cls,
        due < 0 ? `overdue ${-due}d` : `due ${due}d`));
    } else {
      row.append(el("span", "kev-due", k.date_added ? fmtAge(k.date_added) : ""));
    }
    list.append(row);
  });
}

function renderSources() {
  const grid = $("#source-list");
  grid.replaceChildren();
  (state.data.sources || []).forEach((s) => {
    const cell = el("div", "source-cell");
    const ok = s.status === "ok" || s.status === "fixture";
    cell.append(el("span", "dot " + (ok ? "ok" : "err")));
    cell.append(el("span", null, s.source_id));
    if (s.error) cell.title = s.error;
    grid.append(cell);
  });
}

function renderRuns() {
  const list = $("#run-list");
  list.replaceChildren();
  (state.data.runs || []).forEach((r) => {
    const row = el("div", "run-row");
    const left = el("span");
    left.append(`run ${r.run_id} · `);
    if (r.new_articles > 0) left.append(Object.assign(el("b"), { textContent: `${r.new_articles} new` }));
    else left.append(`${r.new_articles} new`);
    left.append(` · ${r.suppressed_count} filtered`);
    const errs = JSON.parse(r.errors_json || "[]");
    if (errs.length) left.append(" · ", Object.assign(el("span", "err"),
      { textContent: `${errs.length} err` }));
    row.append(left);
    row.append(el("span", null, fmtAge(r.finished_at || r.started_at)));
    list.append(row);
  });
}

function renderAll() {
  annotate(state.data);
  renderTop();
  renderPosture();
  renderAlerts();
  renderWatch();
  renderKev();
  renderSources();
  renderRuns();
}

/* ---------- actions ---------- */

async function reviewAlert(alertId, action) {
  try {
    const res = await fetch(`/api/alerts/${encodeURIComponent(alertId)}/review`, {
      method: "POST",
      headers: { "X-NewsRoom": "review", "Content-Type": "application/json" },
      body: JSON.stringify({ action }),
    });
    if (!res.ok) throw new Error("review " + res.status);
    await load();
  } catch (err) {
    $("#status-run").textContent = "review failed: " + err.message;
  }
}

function applyTheme() {
  document.documentElement.dataset.theme = state.theme;
  $("#theme-btn").textContent = state.theme === "dark" ? "☀ Light" : "☾ Dark";
  localStorage.setItem("nr-theme", state.theme);
}

function bind() {
  $("#refresh-btn").addEventListener("click", load);
  $("#theme-btn").addEventListener("click", () => {
    state.theme = state.theme === "dark" ? "light" : "dark";
    applyTheme();
  });
  $("#search").addEventListener("input", (e) => { state.query = e.target.value; renderAlerts(); });
  document.querySelectorAll(".seg-btn").forEach((btn) =>
    btn.addEventListener("click", () => {
      document.querySelectorAll(".seg-btn").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      state.filter = btn.dataset.filter;
      renderAlerts();
    }));
  document.addEventListener("keydown", (e) => {
    if (e.target.tagName === "INPUT") { if (e.key === "Escape") e.target.blur(); return; }
    if (e.key === "/") { e.preventDefault(); $("#search").focus(); }
    if (e.key === "j") { state.selected = Math.min(state.selected + 1, visibleAlerts().length - 1); restyleSelection(); }
    if (e.key === "k") { state.selected = Math.max(state.selected - 1, 0); restyleSelection(); }
    if (e.key === "Enter" && state.selected >= 0) {
      const a = visibleAlerts()[state.selected];
      if (a) window.open(a.url, "_blank", "noopener");
    }
  });
}

async function load() {
  try {
    state.data = await api.summary();
    renderAll();
  } catch (err) {
    $("#status-run").textContent = "load failed: " + err.message;
  }
}

applyTheme();
bind();
load();
setInterval(load, 30000);
