"use strict";

// ── Constants ─────────────────────────────────────────────────────────────────
const TAB_ID  = chrome.devtools.inspectedWindow.tabId;
const METHODS = ["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"];
const REQUIRED_HDRS = [
  "content-security-policy","strict-transport-security","x-frame-options",
  "x-content-type-options","referrer-policy","permissions-policy",
];

// ── State ─────────────────────────────────────────────────────────────────────
let state = {
  attached: false, intercepting: false,
  endpoints: [], technologies: [], headers: {},
};
let intercepted = [];  // paused requests
let editingReq  = null;
let pollTimer   = null;
let histTimer   = null;
let filterEp    = "";
let filterEpType = "";
let filterHist     = "";
let filterHistMeth = "";
let filterHistStat = "";
let filterHistMime = "";
let filterHistScope = false;
let filterHistExt = "";
let filterHistReflect = false;
let activeSubResp = "body";
let historyData = [];
let histDetailEntry = null;
let histSortKey = "id";
let histSortAsc = false; // false = newest first by default

// ── Repeater tabs state ──────────────────────────────────────────────────────
let repTabs = [{ id: 0, label: "1", method: "GET", url: "", headers: "", body: "", response: null, autoCookie: false, targetHost: "", targetPort: "", targetTls: true }];
let repActiveTab = 0;
let repNextId = 1;

// ── Intruder state ───────────────────────────────────────────────────────────
let intrRunning = false;
let intrAbort = null;
let intrResults = [];
let intrPayloadSets = [""]; // one textarea per position
let intrActiveSet = 0;

// ── Messaging to background (with auto-retry on SW restart) ──────────────────
function sendMsg(msg) {
  return new Promise(resolve =>
    chrome.runtime.sendMessage({ ...msg, tabId: TAB_ID }, r => {
      if (chrome.runtime.lastError) { resolve(null); return; }
      resolve(r ?? null);
    })
  );
}

async function bg(msg, retries = 3) {
  for (let i = 0; i < retries; i++) {
    const res = await sendMsg(msg);
    if (res !== null) return res;
    await new Promise(r => setTimeout(r, 300));
  }
  return null;
}

// Wake up the service worker before doing heavy work
async function wakeSW() {
  for (let i = 0; i < 4; i++) {
    const r = await sendMsg({ type: "PING" });
    if (r?.ok) return true;
    await new Promise(r => setTimeout(r, 200));
  }
  return false;
}

// ── DOM helpers ───────────────────────────────────────────────────────────────
function el(tag, cls) { const e = document.createElement(tag); if (cls) e.className = cls; return e; }
function txt(tag, cls, t) { const e = el(tag, cls); e.textContent = t; return e; }
function ap(p, ...kids) { kids.forEach(k => p.appendChild(k)); return p; }

// ── Tab switching ─────────────────────────────────────────────────────────────
function showTab(name) {
  document.querySelectorAll(".tab").forEach(t => t.classList.toggle("active", t.dataset.tab === name));
  document.querySelectorAll(".tab-panel").forEach(p => {
    p.classList.toggle("active",  p.id === `tab-${name}`);
    p.classList.toggle("hidden",  p.id !== `tab-${name}`);
  });
  if (name === "intercept") startPoll(); else stopPoll();
  if (name === "history") startHistPoll(); else stopHistPoll();
  if (name === "target") { pollHistory().then(() => renderSiteMap()); renderEndpoints(); }
  if (name === "probe" && probeInjected) probeStartPoll(); else probeStopPoll();
}

// ── Polling for paused requests ───────────────────────────────────────────────
function startPoll() {
  if (pollTimer) return;
  pollTimer = setInterval(async () => {
    const res = await bg({ type: "GET_INTERCEPTED" });
    if (!res) return;
    intercepted = res.requests || [];
    renderInterceptList();
    updateInterceptBadge();
  }, 600);
}
function stopPoll() { clearInterval(pollTimer); pollTimer = null; }

function startHistPoll() {
  if (histTimer) return;
  pollHistory();
  histTimer = setInterval(pollHistory, 800);
}
function stopHistPoll() { clearInterval(histTimer); histTimer = null; }
async function pollHistory() {
  const res = await bg({ type: "GET_HISTORY" });
  if (!res) return;
  historyData = res.history || [];
  renderHistory();
  setBadge("bdg-history", historyData.length);
}

// ── Load all data ─────────────────────────────────────────────────────────────
async function loadAll() {
  // Wake SW first, then inject content script
  await wakeSW();
  try { await chrome.scripting.executeScript({ target: { tabId: TAB_ID }, files: ["content.js"] }); } catch {}
  await new Promise(r => setTimeout(r, 400));

  const [d, ic, hst] = await Promise.all([
    bg({ type: "GET_DATA" }),
    bg({ type: "GET_INTERCEPTED" }),
    bg({ type: "GET_HISTORY" }),
  ]);

  if (d) {
    state = { ...state, ...d };
    chrome.tabs.get(TAB_ID, tab => {
      try { document.getElementById("site-host").textContent = new URL(tab.url).hostname; } catch {}
    });
  }
  if (ic) intercepted = ic.requests || [];
  if (hst) historyData = hst.history || [];

  renderInterceptStatus();
  renderInterceptList();
  renderHistory();
  renderEndpoints();
  renderHeaders();
  updateBadges();
}

// ── Badges ────────────────────────────────────────────────────────────────────
function updateBadges() {
  updateInterceptBadge();
  setBadge("bdg-history",   historyData.length);
  setBadge("bdg-endpoints", state.endpoints.length);
}
function setBadge(id, n) {
  const b = document.getElementById(id);
  b.textContent = n;
  b.className   = n > 0 ? "bdg has-data" : "bdg";
}
function updateInterceptBadge() {
  const b = document.getElementById("bdg-intercept");
  if (intercepted.length > 0) { b.textContent = intercepted.length; b.className = "bdg has-warn"; }
  else { b.className = "bdg hidden"; }
}

// ═══════════════════════════ INTERCEPT ════════════════════════════════════════

function renderInterceptStatus() {
  const dot   = document.getElementById("dbg-dot");
  const label = document.getElementById("dbg-label");
  const btnA  = document.getElementById("btn-attach");
  const btnI  = document.getElementById("btn-intercept");
  const btnF  = document.getElementById("btn-fwd-all");
  const warn  = document.getElementById("warn-bar");

  dot.className = "dot";
  if (!state.attached) {
    dot.classList.add("dot-off");
    label.textContent = "Detached";
    btnA.textContent  = "Attach Debugger";
    btnA.className    = "btn";
    btnI.textContent  = "Intercept: OFF";
    btnI.disabled     = true;
    btnF.disabled     = true;
    warn.classList.add("hidden");
  } else if (!state.intercepting) {
    dot.classList.add("dot-attached");
    label.textContent = "Attached";
    btnA.textContent  = "Detach";
    btnA.className    = "btn btn-danger";
    btnI.textContent  = "Intercept: OFF";
    btnI.disabled     = false;
    btnF.disabled     = true;
    warn.classList.remove("hidden");
  } else {
    dot.classList.add("dot-intercepting");
    label.textContent = `Intercepting — ${intercepted.length} paused`;
    btnA.textContent  = "Detach";
    btnA.className    = "btn btn-danger";
    btnI.textContent  = "Intercept: ON";
    btnI.disabled     = false;
    btnF.disabled     = intercepted.length === 0;
    warn.classList.remove("hidden");
  }
}

function renderInterceptList() {
  renderInterceptStatus();
  updateInterceptBadge();

  const list   = document.getElementById("ic-list");
  const empty  = document.getElementById("ic-empty");
  const editor = document.getElementById("ic-editor");

  if (editingReq) {
    list.classList.add("hidden");
    empty.classList.add("hidden");
    editor.classList.remove("hidden");
    return;
  }
  editor.classList.add("hidden");
  list.classList.remove("hidden");
  list.replaceChildren();

  if (!intercepted.length) { empty.classList.remove("hidden"); return; }
  empty.classList.add("hidden");

  intercepted.forEach(req => {
    const row = el("div", "req-row");
    ap(row,
      txt("span", `method-pill m-${req.method.toLowerCase()}`, req.method),
      txt("span", "req-type",  req.resourceType || "other"),
      txt("span", "req-url",   req.url),
    );
    const acts = el("div", "req-actions");
    const btnEdit = txt("button", "btn btn-xs btn-ghost",   "Edit");
    const btnRep  = txt("button", "btn btn-xs btn-ghost",   "→ Rep");
    const btnIntr = txt("button", "btn btn-xs btn-ghost",   "→ Intr");
    const btnOpen = txt("button", "btn btn-xs btn-ghost",   "↗"); btnOpen.title = "Open in new tab";
    const btnFwd  = txt("button", "btn btn-xs btn-success", "Forward →");
    const btnDrop = txt("button", "btn btn-xs btn-danger",  "Drop");

    btnEdit.addEventListener("click", e => { e.stopPropagation(); openEditor(req); });
    btnRep.addEventListener("click",  e => { e.stopPropagation(); sendToRepeater(req); });
    btnIntr.addEventListener("click", e => { e.stopPropagation(); intrSendToIntruder(req); });
    btnOpen.addEventListener("click", e => { e.stopPropagation(); chrome.tabs.create({ url: req.url }); });
    btnFwd.addEventListener("click",  e => { e.stopPropagation(); doForward(req.requestId, null); });
    btnDrop.addEventListener("click", e => { e.stopPropagation(); doDrop(req.requestId); });

    ap(acts, btnEdit, btnRep, btnIntr, btnOpen, btnFwd, btnDrop);
    row.appendChild(acts);
    row.addEventListener("click", () => openEditor(req));
    list.appendChild(row);
  });
}

// ── Editor ────────────────────────────────────────────────────────────────────
function openEditor(req) {
  editingReq = req;

  const mSel = document.getElementById("ed-method");
  mSel.replaceChildren();
  METHODS.forEach(m => {
    const o = el("option"); o.value = m; o.textContent = m;
    if (m === req.method) o.selected = true;
    mSel.appendChild(o);
  });

  document.getElementById("ed-url").value     = req.url;
  document.getElementById("ed-headers").value = headersToRaw(req.headers || {});
  document.getElementById("ed-body").value    = req.body || "";

  renderInterceptList();
}

function closeEditor() { editingReq = null; renderInterceptList(); }

function headersToRaw(headers) {
  return Object.entries(headers).map(([k,v]) => `${k}: ${v}`).join("\n");
}
function rawToHeaders(raw) {
  const h = {};
  raw.split("\n").forEach(line => {
    const i = line.indexOf(":");
    if (i > 0) h[line.slice(0,i).trim()] = line.slice(i+1).trim();
  });
  return h;
}

async function doForward(requestId, overrides) {
  intercepted = intercepted.filter(r => r.requestId !== requestId);
  await bg({ type: "FORWARD", requestId, overrides: overrides || {} });
  renderInterceptList();
}

async function doDrop(requestId) {
  intercepted = intercepted.filter(r => r.requestId !== requestId);
  await bg({ type: "DROP", requestId });
  renderInterceptList();
}

async function forwardFromEditor() {
  if (!editingReq) return;
  const overrides = {
    url:     document.getElementById("ed-url").value.trim(),
    method:  document.getElementById("ed-method").value,
    headers: rawToHeaders(document.getElementById("ed-headers").value),
    body:    document.getElementById("ed-body").value,
  };
  const id = editingReq.requestId;
  editingReq = null;
  await doForward(id, overrides);
}

async function dropFromEditor() {
  if (!editingReq) return;
  const id = editingReq.requestId;
  editingReq = null;
  await doDrop(id);
}

// ═══════════════════════════ HISTORY ════════════════════════════════════════

function renderHistory() {
  const tbody = document.getElementById("hist-tbody");
  const empty = document.getElementById("hist-empty");
  const table = document.getElementById("hist-table");
  const detail = document.getElementById("hist-detail");

  if (histDetailEntry) return; // detail pane is open, don't re-render table

  let items = historyData;

  // Dropdown filters
  if (filterHistMeth) {
    items = items.filter(e => e.method === filterHistMeth);
  }
  if (filterHistStat) {
    const prefix = filterHistStat.charAt(0); // "1","2","3","4","5"
    items = items.filter(e => e.status && String(e.status).charAt(0) === prefix);
  }
  if (filterHistMime) {
    const q = filterHistMime.toLowerCase();
    items = items.filter(e => (e.mimeType || "").toLowerCase().includes(q));
  }
  if (filterHistScope) {
    items = items.filter(e => tgtIsInScope(e.url));
  }
  if (filterHistExt === "no-static") {
    items = items.filter(e => !/\.(js|mjs|css|png|jpe?g|gif|webp|ico|svg|woff2?|ttf|eot|map)(\?|$)/i.test(e.path));
  }
  if (filterHistReflect) {
    items = items.filter(e => hasReflections(e));
  }

  // Text search — matches against everything
  if (filterHist) {
    const q = filterHist.toLowerCase();
    items = items.filter(e => {
      const haystack = [
        e.url, e.method, e.host, e.path,
        String(e.status || ""), e.statusText,
        e.mimeType || "", e.resourceType || "",
        // Search in request headers
        ...Object.entries(e.headers || {}).map(([k,v]) => `${k}: ${v}`),
        // Search in response headers
        ...Object.entries(e.respHeaders || {}).map(([k,v]) => `${k}: ${v}`),
        // Search in body
        e.body || "", e.respBody || "",
      ].join("\n").toLowerCase();
      return haystack.includes(q);
    });
  }

  tbody.replaceChildren();

  if (!items.length) {
    empty.classList.remove("hidden");
    table.parentElement.classList.add("hidden");
    return;
  }
  empty.classList.add("hidden");
  table.parentElement.classList.remove("hidden");

  // Assign IDs based on original order, then sort
  const indexed = items.map((e, i) => ({ ...e, _idx: historyData.indexOf(e) + 1 }));

  indexed.sort((a, b) => {
    let va, vb;
    switch (histSortKey) {
      case "id":       va = a._idx; vb = b._idx; break;
      case "method":   va = a.method; vb = b.method; break;
      case "host":     va = a.host; vb = b.host; break;
      case "path":     va = a.path; vb = b.path; break;
      case "status":   va = a.status || 0; vb = b.status || 0; break;
      case "mimeType": va = a.mimeType || ""; vb = b.mimeType || ""; break;
      case "length":   va = a.length || 0; vb = b.length || 0; break;
      case "elapsed":  va = a.elapsed || 0; vb = b.elapsed || 0; break;
      case "time":     va = a.time || 0; vb = b.time || 0; break;
      default:         va = a._idx; vb = b._idx;
    }
    if (typeof va === "string") { va = va.toLowerCase(); vb = vb.toLowerCase(); }
    if (va < vb) return histSortAsc ? -1 : 1;
    if (va > vb) return histSortAsc ? 1 : -1;
    return 0;
  });

  // Update sort indicators in headers
  document.querySelectorAll(".hist-th-sortable").forEach(th => {
    const key = th.dataset.sort;
    const arrow = key === histSortKey ? (histSortAsc ? " ▴" : " ▾") : "";
    th.textContent = th.textContent.replace(/ [▴▾]$/, "") + arrow;
  });

  for (const entry of indexed) {
    const tr = document.createElement("tr");

    const statusCls = !entry.status ? "hist-td-status-wait"
      : entry.status < 300 ? "hist-td-status-ok"
      : entry.status < 400 ? "hist-td-status-rdir"
      : "hist-td-status-err";

    const len = entry.length > 1024 ? `${(entry.length / 1024).toFixed(1)}k` : entry.length || "";
    const ts = entry.time ? fmtTime(entry.time) : "";

    tr.innerHTML = `
      <td class="hist-td-num">${entry._idx}</td>
      <td><span class="method-pill m-${entry.method.toLowerCase()}">${entry.method}</span></td>
      <td title="${esc(entry.host)}">${esc(entry.host)}</td>
      <td title="${esc(entry.path)}">${esc(entry.path)}</td>
      <td class="${statusCls}">${entry.status ?? "…"}</td>
      <td class="hist-td-mime">${esc(shortMime(entry.mimeType))}</td>
      <td class="hist-td-len">${len}</td>
      <td class="hist-td-elapsed">${entry.elapsed ? entry.elapsed : ""}</td>
      <td class="hist-td-timestamp">${ts}</td>
    `;
    if (entry.respBody && hasReflections(entry)) {
      const dot = document.createElement("span");
      dot.className = "hist-reflect-dot";
      dot.title = "Reflections detected";
      tr.querySelector("td:nth-child(5)").appendChild(dot);
    }
    tr.addEventListener("click", () => openHistDetail(entry));
    tbody.appendChild(tr);
  }
}

function esc(s) { return (s || "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;"); }
function shortMime(m) {
  if (!m) return "";
  return m.replace(/^application\//, "").replace(/^text\//, "").split(";")[0];
}
function fmtTime(ts) {
  const d = new Date(ts);
  const pad = n => String(n).padStart(2, "0");
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())} ${pad(d.getDate())}/${pad(d.getMonth()+1)}`;
}

function openHistDetail(entry) {
  histDetailEntry = entry;
  const detail = document.getElementById("hist-detail");
  const title  = document.getElementById("hist-detail-title");

  title.textContent = `${entry.status || "…"} ${entry.method} ${entry.url}`;

  // Request headers
  let reqHdrs = `${entry.method} ${entry.path} HTTP/1.1\nHost: ${entry.host}\n`;
  reqHdrs += Object.entries(entry.headers || {}).map(([k,v]) => `${k}: ${v}`).join("\n");
  document.getElementById("hist-req-headers-pre").textContent = reqHdrs;

  // Request body
  document.getElementById("hist-req-body-pre").textContent = entry.body || "(empty)";

  // Response headers
  let resHdrs = entry.status ? `HTTP/1.1 ${entry.status} ${entry.statusText}\n` : "(no response yet)\n";
  resHdrs += Object.entries(entry.respHeaders || {}).map(([k,v]) => `${k}: ${v}`).join("\n");
  document.getElementById("hist-resp-headers-pre").textContent = resHdrs;

  // Response body
  const respBody = entry.respBody || "(body not captured yet)";
  const ct = entry.respHeaders?.["content-type"] || entry.respHeaders?.["Content-Type"] || "";
  document.getElementById("hist-resp-body-pre").textContent = tryPretty(respBody, ct);

  // Reset sub-tabs to headers active
  detail.querySelectorAll(".hist-sub-pane").forEach(p => p.classList.add("hidden"));
  detail.querySelectorAll(".hist-detail-sub-tabs .sub-tab").forEach(t => t.classList.remove("active"));
  document.getElementById("hist-req-headers-pane").classList.remove("hidden");
  document.getElementById("hist-resp-headers-pane").classList.remove("hidden");
  detail.querySelectorAll('.sub-tab[data-histpane$="-headers"]').forEach(t => t.classList.add("active"));

  detail.classList.remove("hidden");
  document.getElementById("hist-table").parentElement.classList.add("hidden");
  document.getElementById("hist-empty").classList.add("hidden");

  // Highlight reflections + clear search
  highlightReflections(entry);
  document.getElementById("hist-detail-search").value = "";
  document.getElementById("hist-detail-search-count").textContent = "";
}

function closeHistDetail() {
  histDetailEntry = null;
  document.getElementById("hist-detail").classList.add("hidden");
  renderHistory();
}

function histDetailToRepeater() {
  if (!histDetailEntry) return;
  sendToRepeater({
    method:  histDetailEntry.method,
    url:     histDetailEntry.url,
    headers: histDetailEntry.headers || {},
    body:    histDetailEntry.body || "",
  });
  closeHistDetail();
}

// ── Send to Repeater ──────────────────────────────────────────────────────────
function sendToRepeater(req) {
  const method  = req.method || "GET";
  const url     = req.url    || "";
  const rawHdrs = req.rawHeaders || headersToRaw(req.headers || {});
  const body    = req.body   || "";

  // Save current tab state before switching
  saveRepTabState();

  // Create a new repeater tab
  const newTab = {
    id: repNextId++,
    label: repTabs.length + 1 + "",
    method, url, headers: rawHdrs, body, response: null, autoCookie: false,
    targetHost: "", targetPort: "", targetTls: true,
  };
  repTabs.push(newTab);
  repActiveTab = newTab.id;
  renderRepTabs();
  loadRepTab(newTab);

  showTab("repeater");
}

// ═══════════════════════════ REPEATER ════════════════════════════════════════

// ── Repeater tab management ──────────────────────────────────────────────────
function saveRepTabState() {
  const tab = repTabs.find(t => t.id === repActiveTab);
  if (!tab) return;
  tab.method     = document.getElementById("rep-method").value;
  tab.url        = document.getElementById("rep-url").value;
  tab.headers    = document.getElementById("rep-headers").value;
  tab.body       = document.getElementById("rep-body-ta").value;
  tab.autoCookie = document.getElementById("rep-autocookie").checked;
  tab.targetHost = document.getElementById("rep-target-host").value;
  tab.targetPort = document.getElementById("rep-target-port").value;
  tab.targetTls  = document.getElementById("rep-target-tls").checked;
}

function loadRepTab(tab) {
  const mSel = document.getElementById("rep-method");
  for (const o of mSel.options) { if (o.value === tab.method) { o.selected = true; break; } }
  document.getElementById("rep-url").value        = tab.url;
  document.getElementById("rep-headers").value    = tab.headers;
  document.getElementById("rep-body-ta").value    = tab.body;
  document.getElementById("rep-autocookie").checked = !!tab.autoCookie;
  document.getElementById("rep-target-host").value  = tab.targetHost || "";
  document.getElementById("rep-target-port").value  = tab.targetPort || "";
  document.getElementById("rep-target-tls").checked = tab.targetTls !== false;
  // Show/hide target bar
  const hasTarget = !!(tab.targetHost);
  document.getElementById("rep-target-bar").classList.toggle("hidden", !hasTarget);
  document.getElementById("rep-target-toggle").classList.toggle("active", hasTarget);

  // Restore response if saved
  clearRespPanes();
  const subTabs = document.getElementById("resp-sub-tabs");
  const empty   = document.getElementById("resp-empty");
  const label   = document.getElementById("resp-label");

  if (tab.response) {
    const r = tab.response;
    label.textContent = `RESPONSE — ${r.status} ${r.statusText}${r.size ? ` ${(r.size/1024).toFixed(1)} KB` : ""}${r.elapsed ? ` ${r.elapsed}ms` : ""}`;
    document.getElementById("resp-body-pre").textContent = tryPretty(r.body || "(empty body)", r.headers?.["content-type"] || "");
    const hdrsText = Object.entries(r.headers || {}).map(([k,v]) => `${k}: ${v}`).join("\n");
    document.getElementById("resp-hdrs-pre").textContent = hdrsText || "(no headers)";
    document.getElementById("resp-raw-pre").textContent  = `HTTP/1.1 ${r.status} ${r.statusText}\n${hdrsText}\n\n${r.body || ""}`;
    subTabs.classList.remove("hidden");
    empty.classList.add("hidden");
    switchRespPane(activeSubResp);
  } else {
    label.textContent = "RESPONSE";
    subTabs.classList.add("hidden");
    empty.classList.remove("hidden");
  }
}

function renderRepTabs() {
  const bar = document.getElementById("rep-tabs-bar");
  const addBtn = document.getElementById("rep-tab-add");
  // Remove all tab buttons (keep the + button)
  bar.querySelectorAll(".rep-tab-btn").forEach(b => b.remove());

  repTabs.forEach(tab => {
    const btn = document.createElement("button");
    btn.className = "rep-tab-btn" + (tab.id === repActiveTab ? " active" : "");
    btn.dataset.reptab = tab.id;

    // Label — show short path if available
    let label = tab.label;
    if (tab.url) {
      try { const u = new URL(tab.url); label = u.pathname.split("/").pop() || tab.label; } catch {}
    }
    btn.textContent = label;

    // Close button (only if more than 1 tab)
    if (repTabs.length > 1) {
      const x = document.createElement("span");
      x.className = "rep-tab-close";
      x.textContent = "×";
      x.addEventListener("click", e => {
        e.stopPropagation();
        closeRepTab(tab.id);
      });
      btn.appendChild(x);
    }

    btn.addEventListener("click", () => switchRepTab(tab.id));
    bar.insertBefore(btn, addBtn);
  });
}

function switchRepTab(id) {
  if (id === repActiveTab) return;
  saveRepTabState();
  repActiveTab = id;
  renderRepTabs();
  const tab = repTabs.find(t => t.id === id);
  if (tab) loadRepTab(tab);
}

function closeRepTab(id) {
  if (repTabs.length <= 1) return;
  const idx = repTabs.findIndex(t => t.id === id);
  repTabs.splice(idx, 1);
  if (repActiveTab === id) {
    repActiveTab = repTabs[Math.min(idx, repTabs.length - 1)].id;
    loadRepTab(repTabs.find(t => t.id === repActiveTab));
  }
  renderRepTabs();
}

function addRepTab() {
  saveRepTabState();
  const newTab = { id: repNextId++, label: repTabs.length + 1 + "", method: "GET", url: "", headers: "", body: "", response: null };
  repTabs.push(newTab);
  repActiveTab = newTab.id;
  renderRepTabs();
  loadRepTab(newTab);
}

async function doSend() {
  const method     = document.getElementById("rep-method").value;
  const url        = document.getElementById("rep-url").value.trim();
  let   rawHeaders = document.getElementById("rep-headers").value;
  const body       = document.getElementById("rep-body-ta").value;

  if (!url) { document.getElementById("rep-url").focus(); return; }

  // Auto-cookie: fetch cookies from browser and inject/replace Cookie header
  if (document.getElementById("rep-autocookie").checked) {
    const ck = await bg({ type: "GET_COOKIES", url });
    if (ck?.cookies) {
      const lines = rawHeaders.split("\n");
      const idx = lines.findIndex(l => /^cookie\s*:/i.test(l));
      if (idx >= 0) { lines[idx] = `Cookie: ${ck.cookies}`; }
      else { lines.push(`Cookie: ${ck.cookies}`); }
      rawHeaders = lines.join("\n");
      document.getElementById("rep-headers").value = rawHeaders;
    }
  }

  const sendBtn   = document.getElementById("rep-send");
  const respLabel = document.getElementById("resp-label");
  const loading   = document.getElementById("resp-loading");
  const empty     = document.getElementById("resp-empty");
  const subTabs   = document.getElementById("resp-sub-tabs");

  sendBtn.disabled   = true;
  sendBtn.textContent = "Sending…";
  loading.classList.remove("hidden");
  empty.classList.add("hidden");
  subTabs.classList.add("hidden");
  respLabel.textContent = "RESPONSE — waiting…";
  clearRespPanes();

  // Target override: connect to different host/IP while keeping Host header from URL
  const targetHost = document.getElementById("rep-target-host").value.trim();
  const targetPort = document.getElementById("rep-target-port").value.trim();
  const targetTls  = document.getElementById("rep-target-tls").checked;

  const res = await bg({
    type: "SEND_REQUEST", url, method, rawHeaders, body,
    targetOverride: targetHost ? { host: targetHost, port: targetPort, tls: targetTls } : null,
  });

  sendBtn.disabled    = false;
  sendBtn.textContent = "Send";
  loading.classList.add("hidden");

  if (!res || !res.ok) {
    respLabel.textContent = "RESPONSE — error";
    document.getElementById("resp-body-pre").textContent = res?.error || "No response from background service worker.";
    switchRespPane("body");
    subTabs.classList.remove("hidden");
    return;
  }

  const kb   = res.size ? ` ${(res.size / 1024).toFixed(1)} KB` : "";
  const ms   = res.elapsed ? ` ${res.elapsed}ms` : "";
  respLabel.textContent = `RESPONSE — ${res.status} ${res.statusText}${kb}${ms}`;

  // Body pane
  const bodyText = tryPretty(res.body || "(empty body)", res.headers?.["content-type"] || "");
  document.getElementById("resp-body-pre").textContent = bodyText;

  // Headers pane
  const hdrsText = Object.entries(res.headers || {}).map(([k,v]) => `${k}: ${v}`).join("\n");
  document.getElementById("resp-hdrs-pre").textContent = hdrsText || "(no headers)";

  // Raw pane
  const rawText = `HTTP/1.1 ${res.status} ${res.statusText}\n${hdrsText}\n\n${res.body || ""}`;
  document.getElementById("resp-raw-pre").textContent = rawText;

  subTabs.classList.remove("hidden");
  switchRespPane(activeSubResp);

  // Save response to current repeater tab
  const curTab = repTabs.find(t => t.id === repActiveTab);
  if (curTab) {
    curTab.response = res;
    saveRepTabState();
  }
}

function tryPretty(body, contentType) {
  if (/json/i.test(contentType)) {
    try { return JSON.stringify(JSON.parse(body), null, 2); } catch {}
  }
  return body;
}

function clearRespPanes() {
  ["resp-body-pre","resp-hdrs-pre","resp-raw-pre"].forEach(id => {
    document.getElementById(id).textContent = "";
  });
}

function switchRespPane(name) {
  activeSubResp = name;
  document.querySelectorAll("#resp-sub-tabs .sub-tab").forEach(t => t.classList.toggle("active", t.dataset.resp === name));
  document.querySelectorAll("#rep-resp-pane .resp-pane").forEach(p => {
    p.classList.toggle("active", p.id === `resp-pane-${name}`);
    p.classList.toggle("hidden", p.id !== `resp-pane-${name}`);
  });
}

// Resizable split pane (horizontal)
function initResizer() {
  const handle   = document.getElementById("rep-resizer");
  const reqPane  = document.getElementById("rep-req-pane");
  const repBody  = document.querySelector(".rep-body");
  let dragging = false, startX = 0, startW = 0;

  handle.addEventListener("mousedown", e => {
    dragging = true;
    startX   = e.clientX;
    startW   = reqPane.getBoundingClientRect().width;
    document.body.style.userSelect = "none";
    document.body.style.cursor     = "col-resize";
  });
  document.addEventListener("mousemove", e => {
    if (!dragging) return;
    const total = repBody.getBoundingClientRect().width;
    const newW  = Math.max(200, Math.min(total - 200, startW + e.clientX - startX));
    reqPane.style.flex  = "none";
    reqPane.style.width = `${newW}px`;
  });
  document.addEventListener("mouseup", () => {
    dragging = false;
    document.body.style.userSelect = "";
    document.body.style.cursor     = "";
  });
}

// ═══════════════════════════ ENDPOINTS ═══════════════════════════════════════

function renderEndpoints() {
  const list  = document.getElementById("ep-list");
  const empty = document.getElementById("ep-empty");

  let items = state.endpoints || [];
  if (filterEp)     items = items.filter(e => e.url.toLowerCase().includes(filterEp));
  if (filterEpType) items = items.filter(e => e.type === filterEpType);

  setBadge("bdg-endpoints", (state.endpoints || []).length);
  list.replaceChildren();

  if (!items.length) { empty.classList.remove("hidden"); return; }
  empty.classList.add("hidden");

  items.forEach(ep => {
    const row    = el("div", "req-row");
    const method = ep.method || "GET";
    ap(row,
      txt("span", `method-pill m-${method.toLowerCase()}`, method),
      txt("span", `req-type ${ep.type || ""}`, ep.type || "link"),
      txt("span", "req-url", ep.url),
    );
    const acts   = el("div", "req-actions");
    const cpyBtn = txt("button", "btn btn-xs btn-ghost", "Copy");
    const repBtn = txt("button", "btn btn-xs btn-ghost", "→ Rep");

    cpyBtn.addEventListener("click", () => {
      navigator.clipboard.writeText(ep.url).then(() => {
        cpyBtn.textContent = "✓";
        setTimeout(() => { cpyBtn.textContent = "Copy"; }, 1200);
      });
    });
    const intrBtn = txt("button", "btn btn-xs btn-ghost", "→ Intr");
    const openBtn = txt("button", "btn btn-xs btn-ghost", "↗"); openBtn.title = "Open in new tab";
    repBtn.addEventListener("click", () => sendToRepeater(ep));
    intrBtn.addEventListener("click", () => intrSendToIntruder(ep));
    openBtn.addEventListener("click", () => chrome.tabs.create({ url: ep.url }));

    ap(acts, cpyBtn, repBtn, intrBtn, openBtn);
    row.appendChild(acts);
    list.appendChild(row);
  });
}

// ═══════════════════════════ REFLECTIONS & SEARCH ════════════════════════════

function extractReqValues(entry) {
  const vals = new Set();
  // URL params
  try {
    const u = new URL(entry.url);
    u.searchParams.forEach(v => { if (v.length >= 3) vals.add(v); });
  } catch {}
  // Body params (form-encoded)
  if (entry.body) {
    try {
      new URLSearchParams(entry.body).forEach(v => { if (v.length >= 3) vals.add(v); });
    } catch {}
    // JSON body values
    try {
      const j = JSON.parse(entry.body);
      const extract = obj => {
        for (const v of Object.values(obj)) {
          if (typeof v === "string" && v.length >= 3) vals.add(v);
          else if (typeof v === "object" && v) extract(v);
        }
      };
      extract(j);
    } catch {}
  }
  // Cookie values
  const cookieHdr = entry.headers?.["Cookie"] || entry.headers?.["cookie"] || "";
  cookieHdr.split(";").forEach(c => {
    const v = c.split("=").slice(1).join("=").trim();
    if (v.length >= 3 && v.length < 200) vals.add(v);
  });
  return [...vals];
}

function detectReflections(entry) {
  const vals = extractReqValues(entry);
  if (!vals.length) return [];
  const respText = (entry.respBody || "") +
    Object.entries(entry.respHeaders || {}).map(([k,v]) => `${k}: ${v}`).join("\n");
  if (!respText) return [];
  return vals.filter(v => respText.includes(v));
}

function hasReflections(entry) {
  return detectReflections(entry).length > 0;
}

// ── Search within <pre> elements with highlight and auto-scroll ─────────────
let detailSearchMatches = [];
let detailSearchIdx = -1;

function detailSearch(query) {
  // Clear previous highlights
  document.querySelectorAll("#hist-detail .raw-pre").forEach(pre => {
    if (pre._origText !== undefined) pre.textContent = pre._origText;
  });
  detailSearchMatches = [];
  detailSearchIdx = -1;
  const countEl = document.getElementById("hist-detail-search-count");

  if (!query || query.length < 2) { countEl.textContent = ""; return; }

  const q = query.toLowerCase();
  document.querySelectorAll("#hist-detail .hist-sub-pane:not(.hidden) .raw-pre").forEach(pre => {
    const text = pre.textContent;
    pre._origText = text;
    if (!text.toLowerCase().includes(q)) return;

    // Build highlighted HTML
    const frag = document.createDocumentFragment();
    let lastIdx = 0;
    const lower = text.toLowerCase();
    let pos;
    while ((pos = lower.indexOf(q, lastIdx)) !== -1) {
      if (pos > lastIdx) frag.appendChild(document.createTextNode(text.slice(lastIdx, pos)));
      const mark = document.createElement("mark");
      mark.className = "search-hl";
      mark.textContent = text.slice(pos, pos + query.length);
      frag.appendChild(mark);
      detailSearchMatches.push(mark);
      lastIdx = pos + query.length;
    }
    if (lastIdx < text.length) frag.appendChild(document.createTextNode(text.slice(lastIdx)));
    pre.textContent = "";
    pre.appendChild(frag);
  });

  countEl.textContent = detailSearchMatches.length ? `${detailSearchMatches.length} found` : "0 found";
  if (detailSearchMatches.length) detailSearchNav(0);
}

function detailSearchNav(idx) {
  if (!detailSearchMatches.length) return;
  if (detailSearchMatches[detailSearchIdx]) detailSearchMatches[detailSearchIdx].className = "search-hl";
  detailSearchIdx = ((idx % detailSearchMatches.length) + detailSearchMatches.length) % detailSearchMatches.length;
  const m = detailSearchMatches[detailSearchIdx];
  m.className = "search-hl search-hl-current";
  m.scrollIntoView({ behavior: "smooth", block: "center" });
  document.getElementById("hist-detail-search-count").textContent =
    `${detailSearchIdx + 1}/${detailSearchMatches.length}`;
}

function highlightReflections(entry) {
  const reflections = detectReflections(entry);
  const badge = document.getElementById("hist-reflect-badge");
  if (!reflections.length) { badge.classList.add("hidden"); return; }

  badge.classList.remove("hidden");
  badge.textContent = `${reflections.length} reflection${reflections.length > 1 ? "s" : ""}`;

  // Highlight reflected values in response panes
  document.querySelectorAll("#hist-detail .hist-detail-pane:last-child .raw-pre").forEach(pre => {
    const text = pre.textContent;
    pre._origText = text;
    let result = text;
    for (const val of reflections) {
      result = result.split(val).join(`\x00RSTART\x00${val}\x00REND\x00`);
    }
    if (result === text) return;

    const frag = document.createDocumentFragment();
    const parts = result.split("\x00");
    let inReflect = false;
    for (const part of parts) {
      if (part === "RSTART") { inReflect = true; continue; }
      if (part === "REND") { inReflect = false; continue; }
      if (inReflect) {
        const mark = document.createElement("mark");
        mark.className = "reflect-hl";
        mark.textContent = part;
        mark.title = "Reflected from request";
        frag.appendChild(mark);
      } else {
        frag.appendChild(document.createTextNode(part));
      }
    }
    pre.textContent = "";
    pre.appendChild(frag);
  });
}


// ═══════════════════════════ HEADERS ═════════════════════════════════════════

// ── Security header checks (from BB Security Analyzer) ──────────────────────
const SEC_CHECKS = [
  { name: "content-security-policy", label: "Content-Security-Policy", desc: "Controls resources the browser is allowed to load",
    check(v) {
      if (!v) return { st: "fail", note: "Missing" };
      const iss = [];
      if (v.includes("unsafe-inline")) iss.push("unsafe-inline");
      if (v.includes("unsafe-eval")) iss.push("unsafe-eval");
      if (/(?:^|[\s;])default-src[^;]*\*/.test(v)) iss.push("wildcard in default-src");
      else if (v.includes("*")) iss.push("wildcard source");
      if (!v.includes("frame-ancestors")) iss.push("no frame-ancestors");
      if (!v.includes("object-src")) iss.push("no object-src");
      if (!iss.length) return { st: "pass", note: "Well configured" };
      if (iss.includes("unsafe-inline") || iss.includes("unsafe-eval") || iss.includes("wildcard in default-src"))
        return { st: "warn", note: iss.join(", ") };
      return { st: "pass", note: "OK. Minor: " + iss.join(", ") };
    }},
  { name: "strict-transport-security", label: "Strict-Transport-Security", desc: "Enforces HTTPS connections",
    check(v) {
      if (!v) return { st: "fail", note: "Missing" };
      const m = v.match(/max-age=(\d+)/); const age = m ? parseInt(m[1]) : 0;
      if (age < 31536000) return { st: "warn", note: `max-age too low (${age}s)` };
      const extras = [v.includes("includeSubDomains") && "includeSubDomains", v.includes("preload") && "preload"].filter(Boolean);
      return { st: "pass", note: extras.length ? extras.join(" + ") : "OK" };
    }},
  { name: "x-frame-options", label: "X-Frame-Options", desc: "Prevents clickjacking via iframes",
    check(v, all) {
      const csp = all["content-security-policy"] || "";
      if (!v && /frame-ancestors/.test(csp)) return { st: "pass", note: "CSP frame-ancestors covers it" };
      if (!v) return { st: "fail", note: "Missing" };
      if (v.toUpperCase() === "DENY") return { st: "pass", note: "DENY" };
      if (v.toUpperCase() === "SAMEORIGIN") return { st: "pass", note: "SAMEORIGIN" };
      return { st: "warn", note: v };
    }},
  { name: "referrer-policy", label: "Referrer-Policy", desc: "Controls Referer header information",
    check(v) {
      if (!v) return { st: "warn", note: "Missing (browser default)" };
      if (["no-referrer","same-origin","strict-origin","strict-origin-when-cross-origin"].includes(v.toLowerCase()))
        return { st: "pass", note: v };
      if (v.toLowerCase() === "unsafe-url") return { st: "fail", note: "unsafe-url (leaks full URL)" };
      return { st: "warn", note: v };
    }},
  { name: "x-content-type-options", label: "X-Content-Type-Options", desc: "Prevents MIME-type sniffing",
    check(v) {
      if (!v) return { st: "fail", note: "Missing" };
      return v.toLowerCase() === "nosniff" ? { st: "pass", note: "nosniff" } : { st: "warn", note: v };
    }},
  { name: "permissions-policy", label: "Permissions-Policy", desc: "Controls browser features (camera, mic, etc.)",
    check(v) {
      if (!v) return { st: "warn", note: "Missing" };
      return { st: "pass", note: v.length > 60 ? v.slice(0, 57) + "…" : v };
    }},
];

function renderHeaders() {
  const hdrs  = state.headers || {};
  const keys  = Object.keys(hdrs);
  const empty = document.getElementById("hdr-empty");

  // Security grid
  const grid = document.getElementById("hdr-sec-grid");
  grid.replaceChildren();

  const results = SEC_CHECKS.map(h => ({ ...h, value: hdrs[h.name] || null, ...h.check(hdrs[h.name] || null, hdrs) }));
  const fails = results.filter(r => r.st === "fail").length;
  const warns = results.filter(r => r.st === "warn").length;

  const summary = el("div", "hdr-sec-summary");
  summary.textContent = `${fails} missing · ${warns} warnings · ${results.length - fails - warns} OK`;
  grid.appendChild(summary);

  const tilesWrap = el("div", "hdr-sec-tiles");
  results.forEach(r => {
    const tile = el("div", `hdr-sec-tile hdr-sec-${r.st}`);
    tile.innerHTML = `
      <div class="hdr-sec-top"><span class="hdr-sec-badge hdr-sec-badge-${r.st}">${r.st.toUpperCase()}</span><span class="hdr-sec-note">${esc(r.note)}</span></div>
      <div class="hdr-sec-name">${r.label}</div>
      <div class="hdr-sec-desc">${r.desc}</div>
      ${r.value ? `<div class="hdr-sec-val">${esc(r.value.length > 120 ? r.value.slice(0,117)+"…" : r.value)}</div>` : ""}
    `;
    tilesWrap.appendChild(tile);
  });
  grid.appendChild(tilesWrap);

  // All headers list
  const allList = document.getElementById("hdr-all-list");
  allList.replaceChildren();

  const sorted = keys.sort();
  sorted.forEach(k => {
    const row = el("div", "hdr-row");
    ap(row, txt("span", "hdr-key", k), txt("span", "hdr-val", hdrs[k]));
    allList.appendChild(row);
  });

  empty.classList.toggle("hidden", keys.length > 0 || results.length > 0);
}

// ═══════════════════════════ TARGET / SITE MAP ════════════════════════════════

let tgtSelectedPath = null;
let tgtFilter = "";
let tgtInScopeOnly = false;

function tgtBuildTree(entries) {
  // Build a hierarchical tree: protocol+host → path segments → leaf
  const tree = {}; // host → { children: { segment → ... }, entries: [] }

  entries.forEach(entry => {
    try {
      const u = new URL(entry.url);
      const host = u.protocol + "//" + u.host;
      if (!tree[host]) tree[host] = { children: {}, entries: [] };

      const segments = u.pathname.split("/").filter(Boolean);
      let node = tree[host];

      segments.forEach(seg => {
        if (!node.children[seg]) node.children[seg] = { children: {}, entries: [] };
        node = node.children[seg];
      });

      node.entries.push(entry);
    } catch {}
  });

  return tree;
}

function tgtIsInScope(url) {
  const inc = (document.getElementById("tgt-scope-include")?.value || "").trim();
  const exc = (document.getElementById("tgt-scope-exclude")?.value || "").trim();
  if (exc) {
    const pats = exc.split("\n").map(p => p.trim()).filter(Boolean);
    if (pats.some(p => tgtMatchWild(url, p))) return false;
  }
  if (inc) {
    const pats = inc.split("\n").map(p => p.trim()).filter(Boolean);
    return pats.some(p => tgtMatchWild(url, p));
  }
  return true; // no include patterns = everything in scope
}

function tgtMatchWild(str, pattern) {
  const re = new RegExp("^" + pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*") + "$", "i");
  return re.test(str);
}

function tgtCountEntries(node) {
  let count = node.entries.length;
  for (const child of Object.values(node.children)) count += tgtCountEntries(child);
  return count;
}

function tgtCollectEntries(node) {
  let all = [...node.entries];
  for (const child of Object.values(node.children)) all = all.concat(tgtCollectEntries(child));
  return all;
}

function tgtFileIcon(name) {
  const n = name.toLowerCase();
  if (/\.html?$/.test(n))                      return { label: "HTML", cls: "tgt-badge-html" };
  if (/\.js$|\.mjs$/.test(n))                  return { label: "JS",   cls: "tgt-badge-js" };
  if (/\.css$/.test(n))                        return { label: "CSS",  cls: "tgt-badge-css" };
  if (/\.json$/.test(n))                       return { label: "JSON", cls: "tgt-badge-json" };
  if (/\.xml$/.test(n))                        return { label: "XML",  cls: "tgt-badge-xml" };
  if (/\.svg$/.test(n))                        return { label: "SVG",  cls: "tgt-badge-img" };
  if (/\.png$|\.jpe?g$|\.gif$|\.webp$|\.ico$/.test(n)) return { label: "IMG", cls: "tgt-badge-img" };
  if (/\.woff2?$|\.ttf$|\.eot$/.test(n))       return { label: "FONT", cls: "tgt-badge-font" };
  if (/\.pdf$/.test(n))                        return { label: "PDF",  cls: "tgt-badge-pdf" };
  if (/\.php$|\.asp$|\.jsp$/.test(n))          return { label: "SRV",  cls: "tgt-badge-srv" };
  if (/\/api\/|\/v\d+\/|graphql/.test(n))      return { label: "API",  cls: "tgt-badge-api" };
  return null;
}

function renderSiteMap() {
  // Merge history + endpoint data for a complete site map
  let entries = [...historyData];

  // Add endpoints that aren't already in history (by URL)
  const histUrls = new Set(entries.map(e => e.url));
  for (const ep of (state.endpoints || [])) {
    if (ep?.url && !histUrls.has(ep.url)) {
      entries.push({
        url: ep.url, method: ep.method || "GET",
        host: "", path: "", status: null, statusText: "",
        headers: {}, respHeaders: {}, body: "", respBody: "",
        length: 0, mimeType: "", time: 0, elapsed: 0,
        resourceType: ep.type || "other",
      });
      // Parse host/path
      try {
        const u = new URL(ep.url);
        entries[entries.length - 1].host = u.host;
        entries[entries.length - 1].path = u.pathname + u.search;
      } catch {}
    }
  }

  if (tgtFilter) {
    const q = tgtFilter.toLowerCase();
    entries = entries.filter(e => e.url.toLowerCase().includes(q));
  }

  if (tgtInScopeOnly) {
    entries = entries.filter(e => tgtIsInScope(e.url));
  }

  // Deduplicate by URL+method for tree (keep all for table)
  const tree = tgtBuildTree(entries);
  const container = document.getElementById("tgt-tree");
  container.replaceChildren();

  // Sort hosts
  const hosts = Object.keys(tree).sort();
  hosts.forEach(host => {
    const hostNode = tgtRenderNode(host, tree[host], 0, host, true);
    container.appendChild(hostNode);
  });
}

function tgtRenderNode(label, node, depth, fullPath, isHost) {
  const div = document.createElement("div");
  div.className = "tgt-node";

  const hasChildren = Object.keys(node.children).length > 0;
  const count = tgtCountEntries(node);
  const inScope = isHost ? tgtIsInScope(fullPath + "/anything") : tgtIsInScope(fullPath);

  const row = document.createElement("div");
  row.className = "tgt-node-row " + (inScope ? "in-scope" : "out-scope");
  if (fullPath === tgtSelectedPath) row.classList.add("selected");
  row.style.setProperty("--depth", depth);

  const toggle = document.createElement("span");
  toggle.className = "tgt-toggle";
  toggle.textContent = hasChildren ? "▸" : " ";

  const icon = document.createElement("span");
  icon.className = "tgt-icon";
  if (isHost) { icon.textContent = "\u{1F310}"; }
  else if (hasChildren) { icon.textContent = ""; }
  else {
    const ftype = tgtFileIcon(label);
    if (ftype) {
      icon.textContent = "";
      const badge = document.createElement("span");
      badge.className = "tgt-file-badge " + ftype.cls;
      badge.textContent = ftype.label;
      icon.appendChild(badge);
      icon.style.width = "auto";
    } else {
      icon.textContent = "─";
    }
  }

  const lbl = document.createElement("span");
  lbl.className = "tgt-label";
  lbl.textContent = isHost ? label : "/" + label;

  const cnt = document.createElement("span");
  cnt.className = "tgt-count";
  cnt.textContent = count > 0 ? `(${count})` : "";

  row.appendChild(toggle);
  row.appendChild(icon);
  row.appendChild(lbl);
  row.appendChild(cnt);
  div.appendChild(row);

  // Children container
  const childrenDiv = document.createElement("div");
  childrenDiv.className = "tgt-children" + (depth < 1 ? " open" : "");
  if (depth < 1) toggle.textContent = hasChildren ? "▾" : " ";

  const childKeys = Object.keys(node.children).sort();
  childKeys.forEach(seg => {
    const childPath = fullPath + "/" + seg;
    childrenDiv.appendChild(tgtRenderNode(seg, node.children[seg], depth + 1, childPath, false));
  });
  div.appendChild(childrenDiv);

  // Click: toggle children + select node
  row.addEventListener("click", () => {
    if (hasChildren) {
      const isOpen = childrenDiv.classList.toggle("open");
      toggle.textContent = isOpen ? "▾" : "▸";
    }
    tgtSelectedPath = fullPath;
    // Highlight selected
    document.querySelectorAll(".tgt-node-row.selected").forEach(r => r.classList.remove("selected"));
    row.classList.add("selected");
    // Show entries in table
    const allEntries = tgtCollectEntries(node);
    tgtRenderTable(allEntries);
  });

  return div;
}

function tgtRenderTable(entries) {
  const tbody = document.getElementById("tgt-table-body");
  const empty = document.getElementById("tgt-table-empty");
  tbody.replaceChildren();

  if (!entries.length) { empty.classList.remove("hidden"); return; }
  empty.classList.add("hidden");

  // Newest first
  const sorted = [...entries].sort((a, b) => (b.time || 0) - (a.time || 0));

  sorted.forEach(entry => {
    const tr = document.createElement("tr");
    const statusCls = !entry.status ? "hist-td-status-wait"
      : entry.status < 300 ? "hist-td-status-ok"
      : entry.status < 400 ? "hist-td-status-rdir" : "hist-td-status-err";
    const len = entry.length > 1024 ? `${(entry.length/1024).toFixed(1)}k` : entry.length || "";

    tr.innerHTML = `
      <td><span class="method-pill m-${entry.method.toLowerCase()}">${entry.method}</span></td>
      <td title="${esc(entry.url)}" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(entry.url)}</td>
      <td class="${statusCls}">${entry.status ?? "…"}</td>
      <td class="hist-td-len">${len}</td>
      <td class="hist-td-mime">${esc(shortMime(entry.mimeType))}</td>
    `;

    // Actions cell
    const actTd = document.createElement("td");
    actTd.style.whiteSpace = "nowrap";
    const repBtn = txt("button", "btn btn-xs btn-ghost", "→ Rep");
    const intrBtn = txt("button", "btn btn-xs btn-ghost", "→ Intr");
    const openBtn = txt("button", "btn btn-xs btn-ghost", "↗");
    openBtn.title = "Open in new tab";
    repBtn.addEventListener("click", e => { e.stopPropagation(); sendToRepeater({ method: entry.method, url: entry.url, headers: entry.headers || {}, body: entry.body || "" }); });
    intrBtn.addEventListener("click", e => { e.stopPropagation(); intrSendToIntruder({ method: entry.method, url: entry.url, headers: entry.headers || {}, body: entry.body || "" }); });
    openBtn.addEventListener("click", e => { e.stopPropagation(); chrome.tabs.create({ url: entry.url }); });
    ap(actTd, repBtn, intrBtn, openBtn);
    tr.appendChild(actTd);
    tr.style.cursor = "pointer";
    tbody.appendChild(tr);
  });
}

// ═══════════════════════════ INTRUDER ═════════════════════════════════════════

function intrCountPositions() {
  const raw = document.getElementById("intr-request").value;
  const matches = raw.match(/§[^§]*§/g);
  const n = matches ? matches.length : 0;
  document.getElementById("intr-pos-count").textContent = `${n} position${n !== 1 ? "s" : ""}`;

  // Update payload set tabs
  const needed = Math.max(1, n);
  while (intrPayloadSets.length < needed) intrPayloadSets.push("");
  renderPayloadSetTabs(needed);
}

function renderPayloadSetTabs(count) {
  const container = document.getElementById("intr-payload-tabs");
  container.replaceChildren();
  for (let i = 0; i < count; i++) {
    const btn = document.createElement("button");
    btn.className = "sub-tab" + (i === intrActiveSet ? " active" : "");
    btn.dataset.plset = i;
    btn.textContent = `Set ${i + 1}`;
    btn.addEventListener("click", () => {
      intrPayloadSets[intrActiveSet] = document.getElementById("intr-payloads").value;
      intrActiveSet = i;
      document.getElementById("intr-payloads").value = intrPayloadSets[i] || "";
      renderPayloadSetTabs(count);
    });
    container.appendChild(btn);
  }
}

function intrExpandPayloads(raw) {
  const lines = raw.split("\n").map(l => l.trim()).filter(Boolean);
  const result = [];
  for (const line of lines) {
    const rangeMatch = line.match(/^\{\{(\d+)-(\d+)\}\}$/);
    if (rangeMatch) {
      const start = parseInt(rangeMatch[1]);
      const end   = parseInt(rangeMatch[2]);
      for (let i = start; i <= end; i++) result.push(String(i));
    } else {
      result.push(line);
    }
  }
  return result;
}

function intrBuildRequests(template, attackType, payloadSets) {
  const posRegex = /§([^§]*)§/g;
  const positions = [];
  let m;
  while ((m = posRegex.exec(template)) !== null) {
    positions.push({ start: m.index, end: m.index + m[0].length, original: m[1] });
  }

  if (!positions.length) return [];

  const expanded = payloadSets.map(ps => intrExpandPayloads(ps));
  const requests = [];

  if (attackType === "sniper") {
    // One position at a time, all payloads
    for (let pi = 0; pi < positions.length; pi++) {
      const payloads = expanded[Math.min(pi, expanded.length - 1)];
      for (const payload of payloads) {
        let req = template;
        positions.forEach((pos, idx) => {
          req = req.replace(`§${pos.original}§`, idx === pi ? payload : pos.original);
        });
        requests.push({ payload, posIndex: pi, raw: req });
      }
    }
  } else if (attackType === "battering-ram") {
    // Same payload in all positions
    const payloads = expanded[0] || [];
    for (const payload of payloads) {
      let req = template;
      positions.forEach(pos => {
        req = req.replace(`§${pos.original}§`, payload);
      });
      requests.push({ payload, posIndex: -1, raw: req });
    }
  } else if (attackType === "pitchfork") {
    // Parallel: one payload per set, iterate in lockstep
    const maxLen = Math.max(...expanded.map(e => e.length));
    for (let i = 0; i < maxLen; i++) {
      let req = template;
      const payloadParts = [];
      positions.forEach((pos, idx) => {
        const set = expanded[Math.min(idx, expanded.length - 1)];
        const p = set[Math.min(i, set.length - 1)] || "";
        req = req.replace(`§${pos.original}§`, p);
        payloadParts.push(p);
      });
      requests.push({ payload: payloadParts.join(" | "), posIndex: -1, raw: req });
    }
  }

  return requests;
}

function intrParseRaw(rawRequest, methodOverride, urlOverride) {
  // Parse a raw HTTP-like request text into method, url, headers, body
  const lines = rawRequest.split("\n");
  let method = methodOverride || "GET";
  let url = urlOverride || "";
  const headers = {};
  let body = "";
  let inBody = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (inBody) {
      body += (body ? "\n" : "") + line;
    } else if (line.trim() === "") {
      inBody = true;
    } else {
      const ci = line.indexOf(":");
      if (ci > 0) {
        headers[line.slice(0, ci).trim()] = line.slice(ci + 1).trim();
      }
    }
  }

  return { method, url, headers: Object.entries(headers).map(([k,v]) => `${k}: ${v}`).join("\n"), body };
}

async function intrStart() {
  // Save current payload set
  intrPayloadSets[intrActiveSet] = document.getElementById("intr-payloads").value;

  const template   = document.getElementById("intr-request").value;
  const method     = document.getElementById("intr-method").value;
  const url        = document.getElementById("intr-url").value.trim();
  const attackType = document.getElementById("intr-attack").value;
  const threads    = Math.max(1, Math.min(20, parseInt(document.getElementById("intr-threads").value) || 1));
  const delay      = Math.max(0, parseInt(document.getElementById("intr-delay").value) || 0);
  const autoCookie = document.getElementById("intr-autocookie").checked;

  if (!url) { document.getElementById("intr-url").focus(); return; }

  const requests = intrBuildRequests(template, attackType, intrPayloadSets);
  if (!requests.length) { document.getElementById("intr-status").textContent = "No positions/payloads"; return; }

  intrResults = [];
  intrRunning = true;
  intrAbort = new AbortController();
  const tbody = document.getElementById("intr-results");
  tbody.replaceChildren();

  document.getElementById("intr-start").disabled = true;
  document.getElementById("intr-stop").disabled  = false;

  // Get cookies once if auto-cookie enabled
  let cookieStr = "";
  if (autoCookie) {
    const ck = await bg({ type: "GET_COOKIES", url });
    if (ck?.cookies) cookieStr = ck.cookies;
  }

  let completed = 0;
  const total = requests.length;
  const status = document.getElementById("intr-status");

  // Process in chunks of `threads`
  const queue = [...requests];
  while (queue.length > 0 && !intrAbort.signal.aborted) {
    const batch = queue.splice(0, threads);
    const promises = batch.map(async (req, batchIdx) => {
      const parsed = intrParseRaw(req.raw, method, url);

      // Inject cookies
      let rawHdrs = parsed.headers;
      if (cookieStr) {
        const hdrLines = rawHdrs.split("\n");
        const ci = hdrLines.findIndex(l => /^cookie\s*:/i.test(l));
        if (ci >= 0) hdrLines[ci] = `Cookie: ${cookieStr}`;
        else hdrLines.push(`Cookie: ${cookieStr}`);
        rawHdrs = hdrLines.join("\n");
      }

      const res = await bg({
        type: "SEND_REQUEST",
        url: parsed.url || url,
        method: parsed.method || method,
        rawHeaders: rawHdrs,
        body: parsed.body,
      });

      completed++;
      status.textContent = `${completed}/${total}`;

      const entry = {
        id: completed,
        payload: req.payload,
        status: res?.status ?? "err",
        statusText: res?.statusText || "",
        length: res?.size || 0,
        elapsed: res?.elapsed || 0,
        body: res?.body || res?.error || "",
      };
      intrResults.push(entry);

      // Add row to table
      const tr = document.createElement("tr");
      const statusCls = !res?.ok ? "hist-td-status-err"
        : res.status < 300 ? "hist-td-status-ok"
        : res.status < 400 ? "hist-td-status-rdir" : "hist-td-status-err";
      const lenStr = entry.length > 1024 ? `${(entry.length/1024).toFixed(1)}k` : entry.length;
      const preview = (entry.body || "").slice(0, 120).replace(/\n/g, " ");
      tr.innerHTML = `
        <td class="hist-td-num">${entry.id}</td>
        <td title="${esc(entry.payload)}">${esc(entry.payload)}</td>
        <td class="${statusCls}">${entry.status}</td>
        <td class="hist-td-len">${lenStr}</td>
        <td class="hist-td-elapsed">${entry.elapsed}</td>
        <td class="hist-td-mime" title="${esc(preview)}">${esc(preview)}</td>
      `;
      tbody.appendChild(tr);
    });

    await Promise.all(promises);

    if (delay > 0 && queue.length > 0 && !intrAbort.signal.aborted) {
      await new Promise(r => setTimeout(r, delay));
    }
  }

  intrRunning = false;
  document.getElementById("intr-start").disabled = false;
  document.getElementById("intr-stop").disabled  = true;
  status.textContent = `Done — ${completed}/${total}`;
}

function intrStop() {
  if (intrAbort) intrAbort.abort();
  intrRunning = false;
  document.getElementById("intr-start").disabled = false;
  document.getElementById("intr-stop").disabled  = true;
  document.getElementById("intr-status").textContent = "Stopped";
}

function intrSendToIntruder(req) {
  const method = req.method || "GET";
  const url    = req.url || "";
  const rawHdrs = req.rawHeaders || headersToRaw(req.headers || {});
  const body   = req.body || "";

  const mSel = document.getElementById("intr-method");
  for (const o of mSel.options) { if (o.value === method) { o.selected = true; break; } }
  document.getElementById("intr-url").value = url;

  // Build raw request template
  let raw = "";
  if (rawHdrs) raw += rawHdrs;
  if (body) raw += "\n\n" + body;
  document.getElementById("intr-request").value = raw;
  intrCountPositions();
  showTab("intruder");
}

// ═══════════════════════════ PROBE (DOM XSS Hunter) ══════════════════════════

let probeInjected = false;
let probeLogFrom = 0;
let probePollTimer = null;
let probeFindingsData = null;

function probeScan() {
  const btn = document.getElementById("probe-scan");
  btn.disabled = true; btn.textContent = "Scanning\u2026";
  bg({ type: "PROBE_INJECT" }).then(res => {
    btn.disabled = false; btn.textContent = "Scan Page";
    if (res?.ok) {
      probeInjected = true; probeUpdateStatus("scanning");
      document.getElementById("probe-empty").classList.add("hidden");
      document.getElementById("probe-rescan").disabled = false;
      probeStartPoll();
    } else { probeUpdateStatus("error", res?.error); }
  });
}

function probeCmd(command, args) { bg({ type: "PROBE_CMD", command, args: args ?? null }); }

function probeUpdateStatus(status, error) {
  const dot = document.getElementById("probe-dot");
  const label = document.getElementById("probe-label");
  dot.className = "dot";
  if (status === "error") { dot.classList.add("dot-off"); label.textContent = "Error: " + (error || "unknown"); }
  else if (status === "scanning") { dot.classList.add("dot-scanning"); label.textContent = "Scanning\u2026"; }
  else if (status === "ready") { dot.classList.add("dot-intercepting"); label.textContent = "Scan complete"; }
  else { dot.classList.add("dot-off"); label.textContent = "Ready to scan"; }
}

function probeUpdateStats(data) {
  if (!data?.injected) return;
  document.getElementById("probe-stats").classList.remove("hidden");
  document.getElementById("probe-sources").textContent = data.sources || 0;
  document.getElementById("probe-sinks").textContent = data.sinks || 0;
  document.getElementById("probe-flows").textContent = data.flows || 0;
  document.getElementById("probe-likely").textContent = data.likelyFlows || 0;
  document.getElementById("probe-runtime").textContent = data.runtimeCalls || 0;
  setBadge("bdg-p-src", data.sources || 0); setBadge("bdg-p-snk", data.sinks || 0);
  setBadge("bdg-p-flw", data.flows || 0); setBadge("bdg-p-rt", data.runtimeCalls || 0);
  setBadge("bdg-probe", (data.likelyFlows || 0) > 0 ? data.likelyFlows : (data.flows || 0));
  document.getElementById("probe-empty").classList.add("hidden");
}

function probeStartPoll() { if (probePollTimer) return; probePollTimer = setInterval(probePollStatus, 1200); probePollStatus(); }
function probeStopPoll() { clearInterval(probePollTimer); probePollTimer = null; }

let probePrevTotal = -1;
let probeStableCount = 0;

async function probePollStatus() {
  const res = await bg({ type: "PROBE_STATUS", logFrom: probeLogFrom });
  if (!res) return;
  if (res.injected) {
    probeUpdateStats(res);
    // Auto-load findings when counts change or stabilize after scan
    const curTotal = (res.sources || 0) + (res.sinks || 0);
    if (curTotal !== probePrevTotal) {
      probeStableCount = 0;
      probePrevTotal = curTotal;
      if (curTotal > 0) probeLoadFindings();
    } else if (probeStableCount < 3) {
      probeStableCount++;
      if (probeStableCount === 2) probeUpdateStatus("ready");
    }
  }
  if (res.log?.length > 0) { probeRenderLog(res.log); probeLogFrom = res.log[res.log.length - 1].id + 1; }
}

// ── Structured findings ──────────────────────────────────────────────────────

async function probeLoadFindings() {
  const data = await bg({ type: "PROBE_FINDINGS" });
  if (!data) return;
  probeFindingsData = data;
  probeRenderSources(data.sources); probeRenderSinks(data.sinks);
  probeRenderFlows(data.flows); probeRenderRuntime(data.runtimeCalls);
  probeRenderFrameworks(data.frameworks);
}

function probeManipIcon(m) { return m === "full" ? "\u{1F3AF}" : m === "partial" ? "\u26A0\uFE0F" : "\u2014"; }
function probeManipCls(m) { return m === "full" ? "probe-manip-full" : m === "partial" ? "probe-manip-partial" : "probe-manip-none"; }
function probeSevCls(s) { return (s === "critical" || s === "high") ? "probe-sev-critical" : s === "medium" ? "probe-sev-medium" : "probe-sev-low"; }
function probeShortFile(f) { return !f ? "" : f.length > 30 ? "\u2026" + f.slice(-30) : f; }

function probeRenderSources(sources) {
  const tbody = document.getElementById("probe-src-tbody");
  const empty = document.getElementById("probe-src-empty");
  tbody.replaceChildren();
  if (!sources?.length) { empty.classList.remove("hidden"); return; }
  empty.classList.add("hidden");
  const sorted = [...sources].sort((a, b) => ({ full: 0, partial: 1 }[a.manipulable] ?? 2) - ({ full: 0, partial: 1 }[b.manipulable] ?? 2));
  for (const s of sorted) {
    const tr = document.createElement("tr");
    tr.style.cursor = "pointer";
    ap(tr,
      txt("td", "hist-td-num", String(s.id)),
      txt("td", probeManipCls(s.manipulable), probeManipIcon(s.manipulable)),
      txt("td", probeSevCls(s.sev), (s.sev || "").toUpperCase()),
      txt("td", "", s.cat),
      txt("td", "", s.match),
      txt("td", "hist-td-mime", probeShortFile(s.file)),
      txt("td", "hist-td-num", String(s.line)),
    );
    tr.title = s.file + ":" + s.line;
    tr.addEventListener("click", () => probeShowDetail("source", s));
    tbody.appendChild(tr);
  }
}

function probeRenderSinks(sinks) {
  const tbody = document.getElementById("probe-snk-tbody");
  const empty = document.getElementById("probe-snk-empty");
  tbody.replaceChildren();
  if (!sinks?.length) { empty.classList.remove("hidden"); return; }
  empty.classList.add("hidden");
  for (const s of sinks) {
    const tr = document.createElement("tr");
    tr.style.cursor = "pointer";
    ap(tr,
      txt("td", "hist-td-num", String(s.id)),
      txt("td", probeSevCls(s.sev), (s.sev || "").toUpperCase()),
      txt("td", "", s.cat),
      txt("td", "", s.match),
      txt("td", "hist-td-mime", probeShortFile(s.file)),
      txt("td", "hist-td-num", String(s.line)),
    );
    tr.title = s.file + ":" + s.line;
    tr.addEventListener("click", () => probeShowDetail("sink", s));
    tbody.appendChild(tr);
  }
}

function probeRenderFlows(flows) {
  const tbody = document.getElementById("probe-flw-tbody");
  const empty = document.getElementById("probe-flw-empty");
  tbody.replaceChildren();
  if (!flows?.length) { empty.classList.remove("hidden"); return; }
  empty.classList.add("hidden");
  const sorted = [...flows].sort((a, b) => ({ likely: 0, possible: 1 }[a.expl] ?? 2) - ({ likely: 0, possible: 1 }[b.expl] ?? 2));
  for (const f of sorted) {
    const tr = document.createElement("tr");
    tr.style.cursor = "pointer";
    const explIcon = f.expl === "likely" ? "\uD83D\uDD25" : f.expl === "possible" ? "\u26A0\uFE0F" : "\u2753";
    const explCls = f.expl === "likely" ? "probe-expl-likely" : f.expl === "possible" ? "probe-expl-possible" : "probe-expl-unlikely";
    ap(tr,
      txt("td", explCls, explIcon),
      txt("td", "", f.srcMatch),
      txt("td", probeManipCls(f.srcManip), probeManipIcon(f.srcManip)),
      txt("td", "", f.snkMatch),
      txt("td", "", f.snkCat),
      txt("td", "hist-td-mime", probeShortFile(f.file)),
      txt("td", "hist-td-num", f.dist === 0 ? "\u26A1SAME" : f.dist + "L"),
      txt("td", "hist-td-num", String(f.score ?? "")),
    );
    tr.addEventListener("click", () => probeShowDetail("flow", f));
    tbody.appendChild(tr);
  }
}

function probeRenderRuntime(calls) {
  const tbody = document.getElementById("probe-rt-tbody");
  const empty = document.getElementById("probe-rt-empty");
  tbody.replaceChildren();
  if (!calls?.length) { empty.classList.remove("hidden"); return; }
  empty.classList.add("hidden");
  for (const r of calls) {
    const tr = document.createElement("tr");
    ap(tr,
      txt("td", "hist-td-num", String(r.id)),
      txt("td", probeSevCls(r.sev), (r.sev || "").toUpperCase()),
      txt("td", "", r.hook),
      txt("td", "", (r.value || "").slice(0, 100)),
    );
    tbody.appendChild(tr);
  }
}

function probeRenderFrameworks(fw) {
  const c = document.getElementById("probe-fw-pills");
  c.replaceChildren();
  if (!fw) return;
  for (const [name, info] of Object.entries(fw)) {
    if (!info.detected) continue;
    const pill = el("span", "probe-fw-pill");
    pill.textContent = name.charAt(0).toUpperCase() + name.slice(1) + (info.version ? " " + info.version : "");
    c.appendChild(pill);
  }
}

// ── Detail pane (DOM-built, no innerHTML) ────────────────────────────────────

function probeDetailKV(pairs) {
  const dl = el("dl", "probe-detail-kv");
  for (const [k, v, cls] of pairs) {
    const dt = el("dt"); dt.textContent = k;
    const dd = el("dd"); dd.textContent = v; if (cls) dd.className = cls;
    ap(dl, dt, dd);
  }
  return dl;
}

function probeDetailCode(label, code) {
  const sec = el("div", "probe-detail-section");
  ap(sec, txt("div", "probe-detail-section-title", label));
  const pre = el("div", "probe-detail-code"); pre.textContent = code;
  sec.appendChild(pre);
  return sec;
}

function probeShowDetail(type, item) {
  const pane = document.getElementById("probe-detail");
  const title = document.getElementById("probe-detail-title");
  const body = document.getElementById("probe-detail-body");
  body.replaceChildren();

  if (type === "source") {
    title.textContent = "Source #" + item.id + " \u2014 " + item.match;
    const sec = el("div", "probe-detail-section");
    sec.appendChild(probeDetailKV([
      ["ID", item.id], ["Severity", (item.sev || "").toUpperCase(), probeSevCls(item.sev)],
      ["Category", item.cat], ["Controllable", probeManipIcon(item.manipulable) + " " + item.manipulable, probeManipCls(item.manipulable)],
      ["File", item.file], ["Line", item.line], ["Why", item.why],
    ]));
    body.appendChild(sec);
    body.appendChild(probeDetailCode("Match", item.match));
    if (item.code) body.appendChild(probeDetailCode("Code Context", item.code));
    if (item.context) body.appendChild(probeDetailCode("Context", item.context));
    // Nearby sinks
    if (probeFindingsData?.sinks) {
      const nearby = probeFindingsData.sinks.filter(s => s.file === item.file && Math.abs(s.line - item.line) <= 10);
      if (nearby.length) {
        const nsec = el("div", "probe-detail-section");
        const ntitle = el("div", "probe-detail-section-title"); ntitle.textContent = "Nearby Sinks (within 10 lines)"; ntitle.style.color = "var(--red)";
        nsec.appendChild(ntitle);
        for (const s of nearby) {
          const d = Math.abs(s.line - item.line);
          const row = el("div"); row.style.cssText = "padding:2px 0";
          row.textContent = "[" + s.id + "] L" + s.line + " " + s.match + " (" + s.cat + ") \u2014 " + (d === 0 ? "\u26A1 SAME LINE" : d + " lines away");
          nsec.appendChild(row);
        }
        body.appendChild(nsec);
      }
    }
  } else if (type === "sink") {
    title.textContent = "Sink #" + item.id + " \u2014 " + item.match;
    const sec = el("div", "probe-detail-section");
    sec.appendChild(probeDetailKV([
      ["ID", item.id], ["Severity", (item.sev || "").toUpperCase(), probeSevCls(item.sev)],
      ["Category", item.cat], ["File", item.file], ["Line", item.line],
    ]));
    body.appendChild(sec);
    if (item.code) body.appendChild(probeDetailCode("Code", item.code));
  } else if (type === "flow") {
    const explIcon = item.expl === "likely" ? "\uD83D\uDD25" : item.expl === "possible" ? "\u26A0\uFE0F" : "\u2753";
    title.textContent = "Flow \u2014 " + explIcon + " " + (item.expl || "").toUpperCase();
    const srcSec = el("div", "probe-detail-section");
    const srcTitle = txt("div", "probe-detail-section-title", "Source \u2192 [" + item.srcId + "] " + item.srcMatch);
    srcTitle.style.color = "var(--accent)";
    srcSec.appendChild(srcTitle);
    srcSec.appendChild(probeDetailKV([
      ["Line", item.srcLine], ["Controllable", probeManipIcon(item.srcManip) + " " + item.srcManip, probeManipCls(item.srcManip)],
      ["Why", item.srcWhy],
    ]));
    body.appendChild(srcSec);
    const snkSec = el("div", "probe-detail-section");
    const snkTitle = txt("div", "probe-detail-section-title", "Sink \u2192 [" + item.snkId + "] " + item.snkMatch);
    snkTitle.style.color = "var(--red)";
    snkSec.appendChild(snkTitle);
    snkSec.appendChild(probeDetailKV([["Line", item.snkLine], ["Category", item.snkCat]]));
    body.appendChild(snkSec);
    const metaSec = el("div", "probe-detail-section");
    metaSec.appendChild(probeDetailKV([
      ["File", item.file], ["Distance", item.dist === 0 ? "\u26A1 SAME LINE" : item.dist + " lines"],
      ["Score", item.score ?? "N/A"],
      ["Exploitability", explIcon + " " + (item.expl || "").toUpperCase(),
        item.expl === "likely" ? "probe-expl-likely" : item.expl === "possible" ? "probe-expl-possible" : ""],
    ]));
    body.appendChild(metaSec);
  }
  pane.classList.remove("hidden");
}

function probeCloseDetail() { document.getElementById("probe-detail").classList.add("hidden"); }

// ── Sub-tab switching ────────────────────────────────────────────────────────

function probeSwitchSub(name) {
  document.querySelectorAll(".probe-sub-bar .sub-tab").forEach(t => t.classList.toggle("active", t.dataset.probesub === name));
  document.querySelectorAll(".probe-sub-panel").forEach(p => {
    p.classList.toggle("active", p.id === "probe-" + name);
    p.classList.toggle("hidden", p.id !== "probe-" + name);
  });
}

function probeSwitchFind(name) {
  probeCloseDetail();
  document.querySelectorAll(".probe-findings-bar .sub-tab").forEach(t => t.classList.toggle("active", t.dataset.findtab === name));
  document.querySelectorAll(".probe-find-panel").forEach(p => {
    p.classList.toggle("active", p.id === "probe-find-" + name);
    p.classList.toggle("hidden", p.id !== "probe-find-" + name);
  });
}

// ── Console ──────────────────────────────────────────────────────────────────

function probeRenderLog(entries) {
  const container = document.getElementById("probe-console");
  const autoScroll = document.getElementById("probe-autoscroll").checked;
  const wasAtBottom = container.scrollHeight - container.scrollTop - container.clientHeight < 30;
  for (const entry of entries) {
    if (entry.type === "clear") { container.replaceChildren(); continue; }
    if (entry.type === "groupEnd") continue;
    const div = el("div");
    if (entry.type === "table") {
      div.className = "probe-line probe-line-table";
      try {
        const data = JSON.parse(entry.text);
        if (typeof data === "object" && data !== null) {
          const lines = [];
          if (Array.isArray(data)) {
            for (const row of data) { lines.push(typeof row === "object" && row !== null ? Object.entries(row).map(([k,v]) => k + ": " + (v ?? "")).join("  |  ") : String(row)); }
          } else { for (const [k, v] of Object.entries(data)) lines.push("  " + k + ": " + v); }
          div.textContent = lines.join("\n");
        } else { div.textContent = entry.text; }
      } catch { div.textContent = entry.text; }
      container.appendChild(div); continue;
    }
    div.className = "probe-line" + (entry.type === "warn" ? " probe-line-warn" : "") + (entry.type === "group" ? " probe-line-group" : "");
    if (entry.styles?.length > 0 && entry.text.includes("\x00STYLE\x00")) {
      const parts = entry.text.split("\x00STYLE\x00");
      for (let i = 0; i < parts.length; i++) {
        if (!parts[i]) continue;
        const span = el("span", "probe-s"); span.textContent = parts[i];
        if (i > 0 && i - 1 < entry.styles.length) {
          const style = entry.styles[i - 1];
          if (style) {
            const cm = style.match(/color\s*:\s*([^;]+)/), wm = style.match(/font-weight\s*:\s*([^;]+)/), sm = style.match(/font-size\s*:\s*([^;]+)/);
            if (cm) span.style.color = cm[1].trim(); if (wm) span.style.fontWeight = wm[1].trim(); if (sm) span.style.fontSize = sm[1].trim();
          }
        }
        div.appendChild(span);
      }
    } else { div.textContent = entry.text; }
    container.appendChild(div);
  }
  if (autoScroll && wasAtBottom) container.scrollTop = container.scrollHeight;
  if (container.children.length > 0) document.getElementById("probe-empty").classList.add("hidden");
}

function probeClearConsole() { document.getElementById("probe-console").replaceChildren(); probeLogFrom = 0; }

function probeClearAll() {
  probeStopPoll();
  probeCmd("clear"); probeClearConsole();
  probeInjected = false; probeFindingsData = null;
  probePrevTotal = -1; probeStableCount = 0;
  probeUpdateStatus("idle");
  document.getElementById("probe-stats").classList.add("hidden");
  document.getElementById("probe-rescan").disabled = true;
  setBadge("bdg-probe", 0);
  ["probe-src-tbody","probe-snk-tbody","probe-flw-tbody","probe-rt-tbody"].forEach(id => document.getElementById(id).replaceChildren());
  ["probe-src-empty","probe-snk-empty","probe-flw-empty","probe-rt-empty"].forEach(id => document.getElementById(id).classList.remove("hidden"));
  document.getElementById("probe-fw-pills").replaceChildren();
  document.getElementById("probe-empty").classList.remove("hidden");
  probeCloseDetail();
}

// ═══════════════════════════ DECODER ══════════════════════════════════════════

function decOp(op, input) {
  try {
    switch (op) {
      // Encode
      case "b64-enc":     return btoa(unescape(encodeURIComponent(input)));
      case "url-enc":     return encodeURIComponent(input);
      case "url-enc2":    return encodeURIComponent(encodeURIComponent(input));
      case "html-enc":    return input.replace(/[&<>"'/]/g, c => `&#${c.charCodeAt(0)};`);
      case "hex-enc":     return [...input].map(c => c.charCodeAt(0).toString(16).padStart(2,"0")).join(" ");
      case "unicode-enc": return [...input].map(c => "\\u" + c.charCodeAt(0).toString(16).padStart(4,"0")).join("");
      case "js-enc":      return input.replace(/[\\'"\n\r\t\x00-\x1f]/g, c => "\\x" + c.charCodeAt(0).toString(16).padStart(2,"0"));
      case "ascii-hex":   return [...input].map(c => "%" + c.charCodeAt(0).toString(16).padStart(2,"0")).join("");

      // Decode
      case "b64-dec":     return decodeURIComponent(escape(atob(input.trim())));
      case "url-dec":     return decodeURIComponent(input);
      case "html-dec":    { const t = document.createElement("textarea"); t.innerHTML = input; return t.value; }
      case "hex-dec":     return input.replace(/\s+/g," ").split(" ").filter(Boolean).map(h => String.fromCharCode(parseInt(h,16))).join("");
      case "unicode-dec": return input.replace(/\\u([0-9a-fA-F]{4})/g, (_,h) => String.fromCharCode(parseInt(h,16)));
      case "js-dec":      return input.replace(/\\x([0-9a-fA-F]{2})/g, (_,h) => String.fromCharCode(parseInt(h,16)))
                                      .replace(/\\u([0-9a-fA-F]{4})/g, (_,h) => String.fromCharCode(parseInt(h,16)))
                                      .replace(/\\n/g,"\n").replace(/\\r/g,"\r").replace(/\\t/g,"\t").replace(/\\\\/g,"\\");
      case "jwt-dec": {
        const parts = input.trim().split(".");
        if (parts.length < 2) return "Invalid JWT";
        const dec = p => decodeURIComponent(escape(atob(p.replace(/-/g,"+").replace(/_/g,"/"))));
        return "=== HEADER ===\n" + JSON.stringify(JSON.parse(dec(parts[0])),null,2) +
               "\n\n=== PAYLOAD ===\n" + JSON.stringify(JSON.parse(dec(parts[1])),null,2) +
               (parts[2] ? "\n\n=== SIGNATURE ===\n" + parts[2] : "");
      }

      // Hash (Web Crypto API)
      case "md5":    return "Use SHA — MD5 not available in browser crypto";
      case "sha1":   return cryptoHash("SHA-1", input);
      case "sha256": return cryptoHash("SHA-256", input);

      default: return input;
    }
  } catch (e) { return `Error: ${e.message}`; }
}

async function cryptoHash(algo, input) {
  const buf = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest(algo, buf);
  return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2,"0")).join("");
}

// ═══════════════════════════ SETTINGS ═════════════════════════════════════════

const DEFAULT_SETTINGS = {
  matchReplace: [],
  autoHeaders: "",
  proxyEnabled: false,
  proxyHost: "127.0.0.1",
  proxyPort: "8080",
  proxyType: "http",
  scopeInclude: "",
  scopeExclude: "",
  followRedirects: true,
  timeout: "30000",
};

let settings = { ...DEFAULT_SETTINGS };

function loadSettings() {
  return new Promise(resolve => {
    chrome.storage.local.get("voidSettings", r => {
      if (r.voidSettings) settings = { ...DEFAULT_SETTINGS, ...r.voidSettings };
      resolve();
    });
  });
}

function saveSettings() {
  // Read current UI state into settings
  settings.autoHeaders    = document.getElementById("cfg-auto-headers").value;
  settings.proxyEnabled   = document.getElementById("cfg-proxy-enabled").checked;
  settings.proxyHost      = document.getElementById("cfg-proxy-host").value;
  settings.proxyPort      = document.getElementById("cfg-proxy-port").value;
  settings.proxyType      = document.getElementById("cfg-proxy-type").value;
  settings.scopeInclude   = document.getElementById("cfg-scope-include").value;
  settings.scopeExclude   = document.getElementById("cfg-scope-exclude").value;
  settings.followRedirects = document.getElementById("cfg-follow-redirects").checked;
  settings.timeout        = document.getElementById("cfg-timeout").value;
  settings.matchReplace   = readMRRules();

  chrome.storage.local.set({ voidSettings: settings });

  // Push to background
  bg({ type: "UPDATE_SETTINGS", settings });

  const st = document.getElementById("cfg-status");
  st.textContent = "Saved";
  setTimeout(() => { st.textContent = ""; }, 1500);
}

function loadSettingsUI() {
  document.getElementById("cfg-auto-headers").value    = settings.autoHeaders;
  document.getElementById("cfg-proxy-enabled").checked  = settings.proxyEnabled;
  document.getElementById("cfg-proxy-host").value       = settings.proxyHost;
  document.getElementById("cfg-proxy-port").value       = settings.proxyPort;
  document.getElementById("cfg-proxy-type").value       = settings.proxyType;
  document.getElementById("cfg-scope-include").value    = settings.scopeInclude;
  document.getElementById("cfg-scope-exclude").value    = settings.scopeExclude;
  document.getElementById("cfg-follow-redirects").checked = settings.followRedirects;
  document.getElementById("cfg-timeout").value          = settings.timeout;
  renderMRRules();
}

// ── Match & Replace UI ───────────────────────────────────────────────────────
function renderMRRules() {
  const container = document.getElementById("mr-rules");
  container.replaceChildren();

  (settings.matchReplace || []).forEach((rule, i) => {
    const div = document.createElement("div");
    div.className = "mr-rule" + (rule.enabled === false ? " mr-disabled" : "");
    div.innerHTML = `
      <div class="mr-fields">
        <div class="mr-row">
          <label>Type</label>
          <select class="mr-sel" data-idx="${i}" data-field="type">
            <option value="req-header" ${rule.type==="req-header"?"selected":""}>Request Header</option>
            <option value="req-body" ${rule.type==="req-body"?"selected":""}>Request Body</option>
            <option value="resp-header" ${rule.type==="resp-header"?"selected":""}>Response Header</option>
            <option value="resp-body" ${rule.type==="resp-body"?"selected":""}>Response Body</option>
            <option value="url" ${rule.type==="url"?"selected":""}>URL</option>
          </select>
        </div>
        <div class="mr-row">
          <label>Match</label>
          <input class="mr-inp" data-idx="${i}" data-field="match" value="${esc(rule.match||"")}" placeholder="Regex or string (empty = add)" spellcheck="false">
        </div>
        <div class="mr-row">
          <label>Replace</label>
          <input class="mr-inp" data-idx="${i}" data-field="replace" value="${esc(rule.replace||"")}" placeholder="Replacement value" spellcheck="false">
        </div>
        <div class="mr-row">
          <label>Scope</label>
          <input class="mr-inp" data-idx="${i}" data-field="scope" value="${esc(rule.scope||"")}" placeholder="URL pattern (empty = all)" spellcheck="false">
        </div>
      </div>
      <div class="mr-actions">
        <button class="mr-toggle ${rule.enabled!==false?"on":""}" data-idx="${i}" title="Toggle">${rule.enabled!==false?"ON":"OFF"}</button>
        <button class="mr-del" data-idx="${i}" title="Delete">✕</button>
      </div>
    `;
    container.appendChild(div);
  });

  // Event delegation
  container.onclick = e => {
    const toggle = e.target.closest(".mr-toggle");
    if (toggle) {
      const idx = +toggle.dataset.idx;
      settings.matchReplace[idx].enabled = !settings.matchReplace[idx].enabled;
      renderMRRules();
      return;
    }
    const del = e.target.closest(".mr-del");
    if (del) {
      settings.matchReplace.splice(+del.dataset.idx, 1);
      renderMRRules();
    }
  };
  container.oninput = e => {
    const inp = e.target;
    if (inp.dataset.idx !== undefined && inp.dataset.field) {
      settings.matchReplace[+inp.dataset.idx][inp.dataset.field] = inp.value;
    }
  };
  container.onchange = e => {
    const sel = e.target;
    if (sel.dataset.idx !== undefined && sel.dataset.field) {
      settings.matchReplace[+sel.dataset.idx][sel.dataset.field] = sel.value;
    }
  };
}

function readMRRules() {
  return (settings.matchReplace || []).map(r => ({ ...r }));
}

function addMRRule() {
  settings.matchReplace = settings.matchReplace || [];
  settings.matchReplace.push({ enabled: true, type: "req-header", match: "", replace: "", scope: "" });
  renderMRRules();
}

// ═══════════════════════════ INIT ════════════════════════════════════════════

document.addEventListener("DOMContentLoaded", () => {

  // Tab switching
  document.querySelectorAll(".tab[data-tab]").forEach(t =>
    t.addEventListener("click", () => showTab(t.dataset.tab))
  );

  // Method select for repeater
  const mSel = document.getElementById("rep-method");
  METHODS.forEach(m => { const o = el("option"); o.value = m; o.textContent = m; mSel.appendChild(o); });

  // Repeater send
  document.getElementById("rep-send").addEventListener("click", doSend);
  document.getElementById("rep-url").addEventListener("keydown", e => {
    if (e.key === "Enter" && !e.shiftKey) doSend();
  });

  // Repeater target override toggle
  document.getElementById("rep-target-toggle").addEventListener("click", () => {
    const bar = document.getElementById("rep-target-bar");
    const btn = document.getElementById("rep-target-toggle");
    const hidden = bar.classList.toggle("hidden");
    btn.classList.toggle("active", !hidden);
    if (hidden) {
      document.getElementById("rep-target-host").value = "";
      document.getElementById("rep-target-port").value = "";
    }
  });

  // Repeater tabs
  document.getElementById("rep-tab-add").addEventListener("click", addRepTab);
  renderRepTabs();

  // Response sub-tabs
  document.querySelectorAll(".sub-tab[data-resp]").forEach(t =>
    t.addEventListener("click", () => switchRespPane(t.dataset.resp))
  );

  // History sortable columns
  document.querySelectorAll(".hist-th-sortable").forEach(th =>
    th.addEventListener("click", () => {
      const key = th.dataset.sort;
      if (histSortKey === key) { histSortAsc = !histSortAsc; }
      else { histSortKey = key; histSortAsc = (key === "id" ? false : true); }
      renderHistory();
    })
  );

  // Headers sub-tabs
  document.querySelectorAll(".hdr-sub-bar .sub-tab[data-hdrsub]").forEach(t =>
    t.addEventListener("click", () => {
      document.querySelectorAll(".hdr-sub-bar .sub-tab").forEach(b => b.classList.remove("active"));
      t.classList.add("active");
      document.querySelectorAll(".hdr-sub-panel").forEach(p => {
        p.classList.toggle("active", p.id === `hdr-${t.dataset.hdrsub}`);
        p.classList.toggle("hidden", p.id !== `hdr-${t.dataset.hdrsub}`);
      });
    })
  );

  // History filter + dropdowns + clear + detail
  document.getElementById("hist-filter").addEventListener("input", e => {
    filterHist = e.target.value; renderHistory();
  });
  document.getElementById("hist-flt-method").addEventListener("change", e => {
    filterHistMeth = e.target.value; renderHistory();
  });
  document.getElementById("hist-flt-status").addEventListener("change", e => {
    filterHistStat = e.target.value; renderHistory();
  });
  document.getElementById("hist-flt-mime").addEventListener("change", e => {
    filterHistMime = e.target.value; renderHistory();
  });
  document.getElementById("hist-inscope-only").addEventListener("change", e => {
    filterHistScope = e.target.checked; renderHistory();
  });
  document.getElementById("hist-flt-ext").addEventListener("change", e => {
    filterHistExt = e.target.value; renderHistory();
  });
  document.getElementById("hist-clear").addEventListener("click", async () => {
    await bg({ type: "CLEAR_HISTORY" });
    historyData = [];
    renderHistory();
    setBadge("bdg-history", 0);
  });
  document.getElementById("hist-reflect-only").addEventListener("change", e => {
    filterHistReflect = e.target.checked; renderHistory();
  });
  document.getElementById("hist-detail-close").addEventListener("click", closeHistDetail);
  document.getElementById("hist-detail-to-rep").addEventListener("click", histDetailToRepeater);

  // Detail search
  document.getElementById("hist-detail-search").addEventListener("input", e => detailSearch(e.target.value));
  document.getElementById("hist-detail-search-next").addEventListener("click", () => detailSearchNav(detailSearchIdx + 1));
  document.getElementById("hist-detail-search-prev").addEventListener("click", () => detailSearchNav(detailSearchIdx - 1));
  document.getElementById("hist-detail-search").addEventListener("keydown", e => {
    if (e.key === "Enter") { e.preventDefault(); detailSearchNav(e.shiftKey ? detailSearchIdx - 1 : detailSearchIdx + 1); }
  });
  document.getElementById("hist-detail-to-intr").addEventListener("click", () => {
    if (!histDetailEntry) return;
    intrSendToIntruder({
      method: histDetailEntry.method,
      url: histDetailEntry.url,
      headers: histDetailEntry.headers || {},
      body: histDetailEntry.body || "",
    });
    closeHistDetail();
  });
  document.getElementById("hist-detail-open").addEventListener("click", () => {
    if (histDetailEntry?.url) chrome.tabs.create({ url: histDetailEntry.url });
  });

  // History detail sub-tab switching (request and response sides)
  document.getElementById("hist-detail").addEventListener("click", e => {
    const btn = e.target.closest(".sub-tab[data-histpane]");
    if (!btn) return;
    const paneId = btn.dataset.histpane;
    // Find which side (parent .hist-detail-pane)
    const side = btn.closest(".hist-detail-pane");
    side.querySelectorAll(".sub-tab").forEach(t => t.classList.remove("active"));
    btn.classList.add("active");
    side.querySelectorAll(".hist-sub-pane").forEach(p => p.classList.add("hidden"));
    side.querySelector(`#hist-${paneId}-pane`).classList.remove("hidden");
  });

  // Attach / detach
  document.getElementById("btn-attach").addEventListener("click", async () => {
    if (state.attached) {
      await bg({ type: "DETACH" });
      state.attached = false; state.intercepting = false;
    } else {
      const res = await bg({ type: "ATTACH" });
      state.attached = !!(res?.ok);
    }
    renderInterceptStatus();
  });

  // Intercept toggle
  document.getElementById("btn-intercept").addEventListener("click", async () => {
    if (state.intercepting) {
      await bg({ type: "INTERCEPT_OFF" });
      state.intercepting = false;
    } else {
      const res = await bg({ type: "INTERCEPT_ON" });
      state.intercepting = !!(res?.ok);
    }
    renderInterceptStatus();
  });

  // Forward all
  document.getElementById("btn-fwd-all").addEventListener("click", async () => {
    const ids = intercepted.map(r => r.requestId);
    intercepted = [];
    await Promise.all(ids.map(id => bg({ type: "FORWARD", requestId: id, overrides: {} })));
    renderInterceptList();
  });

  // Editor buttons
  document.getElementById("ed-back").addEventListener("click",    closeEditor);
  document.getElementById("ed-forward").addEventListener("click", forwardFromEditor);
  document.getElementById("ed-drop").addEventListener("click",    dropFromEditor);
  document.getElementById("ed-to-rep").addEventListener("click",  () => {
    if (!editingReq) return;
    sendToRepeater({
      ...editingReq,
      method:     document.getElementById("ed-method").value,
      url:        document.getElementById("ed-url").value,
      rawHeaders: document.getElementById("ed-headers").value,
      body:       document.getElementById("ed-body").value,
    });
    closeEditor();
  });

  // Endpoint filters
  document.getElementById("ep-filter").addEventListener("input", e => {
    filterEp = e.target.value.toLowerCase(); renderEndpoints();
  });
  document.getElementById("ep-type").addEventListener("change", e => {
    filterEpType = e.target.value; renderEndpoints();
  });
  document.getElementById("ep-copy-all").addEventListener("click", () => {
    const urls = (state.endpoints || []).map(e => e.url).join("\n");
    navigator.clipboard.writeText(urls);
  });

  // ── Crawl ──────────────────────────────────────────────────────────────────
  let crawlRunning = false;

  function setCrawlUI(running) {
    crawlRunning = running;
    const btn  = document.getElementById("ep-crawl");
    const bar  = document.getElementById("ep-crawl-bar");
    btn.disabled = running;
    btn.style.opacity = running ? "0.5" : "";
    bar.classList.toggle("hidden", !running);
    if (!running) {
      document.getElementById("ep-crawl-fill").style.width = "0%";
      document.getElementById("ep-crawl-status").textContent = "";
    }
  }

  document.getElementById("ep-crawl").addEventListener("click", async () => {
    const tab = await new Promise(r => chrome.tabs.get(TAB_ID, r));
    let origin;
    try { origin = new URL(tab.url).origin; } catch { return; }

    // Use already-discovered link endpoints as seeds + the current page URL
    const seeds = [tab.url, ...(state.endpoints || [])
      .filter(e => e.type === "link" || e.type === "api")
      .map(e => e.url)
      .filter(u => u.startsWith(origin))
    ].filter((u, i, a) => a.indexOf(u) === i).slice(0, 80);

    setCrawlUI(true);
    document.getElementById("ep-crawl-status").textContent = "Starting crawl…";

    bg({ type: "CRAWL_START", origin, seeds, maxPages: 60 });
  });

  document.getElementById("ep-crawl-stop").addEventListener("click", () => {
    bg({ type: "CRAWL_STOP" });
    setCrawlUI(false);
  });

  // Listen for crawl progress messages from background
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === "CRAWL_PROGRESS") {
      const pct = msg.total > 0 ? Math.round((msg.visited / msg.total) * 100) : 0;
      document.getElementById("ep-crawl-fill").style.width = `${pct}%`;
      document.getElementById("ep-crawl-status").textContent =
        `Crawling… ${msg.visited}${msg.total ? "/" + msg.total : ""} pages`;

      if (msg.newEndpoints && msg.newEndpoints.length) {
        const seen = new Set((state.endpoints || []).map(e => e.url));
        let added = false;
        for (const ep of msg.newEndpoints) {
          if (!seen.has(ep.url)) {
            state.endpoints = state.endpoints || [];
            state.endpoints.push(ep);
            seen.add(ep.url);
            added = true;
          }
        }
        if (added) renderEndpoints();
      }
    }

    if (msg.type === "CRAWL_DONE") {
      const status = document.getElementById("ep-crawl-status");
      status.textContent = `Done — ${msg.visited} pages crawled`;
      document.getElementById("ep-crawl-fill").style.width = "100%";
      setTimeout(() => setCrawlUI(false), 2000);
      renderEndpoints();
    }
  });

  // Refresh / Export
  document.getElementById("btn-refresh").addEventListener("click", loadAll);
  document.getElementById("btn-export").addEventListener("click", async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const payload = { url: tab?.url, timestamp: new Date().toISOString(), ...state };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const a    = el("a");
    a.href     = URL.createObjectURL(blob);
    try { a.download = `void-${new URL(tab?.url || "http://x").hostname}-${Date.now()}.json`; }
    catch { a.download = `void-${Date.now()}.json`; }
    a.click();
    URL.revokeObjectURL(a.href);
  });

  // Resizable split
  initResizer();

  // Target sub-tabs
  document.querySelectorAll(".tgt-sub-bar .sub-tab[data-tgtsub]").forEach(t =>
    t.addEventListener("click", () => {
      document.querySelectorAll(".tgt-sub-bar .sub-tab").forEach(b => b.classList.remove("active"));
      t.classList.add("active");
      document.querySelectorAll(".tgt-sub-panel").forEach(p => {
        p.classList.toggle("active", p.id === `tgt-${t.dataset.tgtsub}`);
        p.classList.toggle("hidden", p.id !== `tgt-${t.dataset.tgtsub}`);
      });
    })
  );
  document.getElementById("tgt-filter").addEventListener("input", e => {
    tgtFilter = e.target.value;
    renderSiteMap();
  });
  document.getElementById("tgt-inscope-only").addEventListener("change", e => {
    tgtInScopeOnly = e.target.checked;
    renderSiteMap();
  });
  document.getElementById("tgt-scope-save").addEventListener("click", () => {
    // Sync scope to Settings too
    document.getElementById("cfg-scope-include").value = document.getElementById("tgt-scope-include").value;
    document.getElementById("cfg-scope-exclude").value = document.getElementById("tgt-scope-exclude").value;
    saveSettings();
    renderSiteMap();
    const st = document.getElementById("tgt-scope-status");
    st.textContent = "Saved";
    setTimeout(() => { st.textContent = ""; }, 1500);
  });

  // Target tree resizer
  (function() {
    const handle = document.getElementById("tgt-resizer");
    const pane   = document.getElementById("tgt-tree-pane");
    let dragging = false, startX = 0, startW = 0;
    handle.addEventListener("mousedown", e => {
      dragging = true; startX = e.clientX; startW = pane.getBoundingClientRect().width;
      document.body.style.userSelect = "none"; document.body.style.cursor = "col-resize";
    });
    document.addEventListener("mousemove", e => {
      if (!dragging) return;
      pane.style.flex = "none";
      pane.style.width = Math.max(150, startW + e.clientX - startX) + "px";
    });
    document.addEventListener("mouseup", () => {
      if (!dragging) return;
      dragging = false; document.body.style.userSelect = ""; document.body.style.cursor = "";
    });
  })();

  // Intruder
  const intrMSel = document.getElementById("intr-method");
  METHODS.forEach(m => { const o = el("option"); o.value = m; o.textContent = m; intrMSel.appendChild(o); });
  document.getElementById("intr-request").addEventListener("input", intrCountPositions);
  document.getElementById("intr-add-pos").addEventListener("click", () => {
    const ta = document.getElementById("intr-request");
    const start = ta.selectionStart;
    const end = ta.selectionEnd;
    const val = ta.value;
    const selected = val.slice(start, end) || "payload";
    ta.value = val.slice(0, start) + `§${selected}§` + val.slice(end);
    ta.selectionStart = start + 1;
    ta.selectionEnd   = start + 1 + selected.length;
    ta.focus();
    intrCountPositions();
  });
  document.getElementById("intr-clear-pos").addEventListener("click", () => {
    const ta = document.getElementById("intr-request");
    ta.value = ta.value.replace(/§/g, "");
    intrCountPositions();
  });
  document.getElementById("intr-start").addEventListener("click", intrStart);
  document.getElementById("intr-stop").addEventListener("click", intrStop);

  // Decoder
  document.querySelectorAll(".dec-btn").forEach(btn =>
    btn.addEventListener("click", async () => {
      const input = document.getElementById("dec-input").value;
      const result = decOp(btn.dataset.op, input);
      document.getElementById("dec-output").value = (result instanceof Promise) ? await result : result;
    })
  );
  document.getElementById("dec-swap").addEventListener("click", () => {
    const inp = document.getElementById("dec-input");
    const out = document.getElementById("dec-output");
    const tmp = inp.value;
    inp.value = out.value;
    out.value = tmp;
  });
  document.getElementById("dec-clear").addEventListener("click", () => {
    document.getElementById("dec-input").value = "";
    document.getElementById("dec-output").value = "";
  });

  // Settings
  document.getElementById("mr-add").addEventListener("click", addMRRule);
  document.getElementById("cfg-save").addEventListener("click", saveSettings);
  document.getElementById("cfg-reset").addEventListener("click", () => {
    settings = { ...DEFAULT_SETTINGS };
    loadSettingsUI();
    saveSettings();
  });

  // ── Probe tab ───────────────────────────────────────────────────────────────
  document.getElementById("probe-scan").addEventListener("click", probeScan);
  document.getElementById("probe-rescan").addEventListener("click", () => { probeCmd("scan"); probePrevTotal = -1; probeStableCount = 0; });
  document.getElementById("probe-export").addEventListener("click", () => probeCmd("export"));
  document.getElementById("probe-clear").addEventListener("click", probeClearAll);
  document.getElementById("probe-console-clear").addEventListener("click", probeClearConsole);
  document.getElementById("probe-detail-close").addEventListener("click", probeCloseDetail);

  // Sub-tab switching
  document.querySelectorAll(".probe-sub-bar .sub-tab[data-probesub]").forEach(t =>
    t.addEventListener("click", () => probeSwitchSub(t.dataset.probesub))
  );
  document.querySelectorAll(".probe-findings-bar .sub-tab[data-findtab]").forEach(t =>
    t.addEventListener("click", () => probeSwitchFind(t.dataset.findtab))
  );

  // Command buttons
  document.querySelectorAll(".probe-btn[data-cmd]").forEach(btn =>
    btn.addEventListener("click", () => probeCmd(btn.dataset.cmd))
  );

  // Toggles
  const probeToggleMap = [
    ["probe-autofill", "probeAutofill", "autofill.toggle"],
    ["probe-csti", "probeCsti", "csti.toggle"],
    ["probe-ssti", "probeSsti", "ssti.toggle"],
    ["probe-protopoll", "probeProtoPollution", "protopollution.toggle"],
  ];
  for (const [elId, storageKey, cmd] of probeToggleMap) {
    document.getElementById(elId).addEventListener("change", e => {
      chrome.storage.local.set({ [storageKey]: e.target.checked });
      probeCmd(cmd, e.target.checked);
    });
  }
  chrome.storage.local.get(["probeAutofill", "probeCsti", "probeSsti", "probeProtoPollution"], r => {
    if (r.probeAutofill) document.getElementById("probe-autofill").checked = true;
    if (r.probeCsti) document.getElementById("probe-csti").checked = true;
    if (r.probeSsti) document.getElementById("probe-ssti").checked = true;
    if (r.probeProtoPollution) document.getElementById("probe-protopoll").checked = true;
  });

  // Boot
  loadSettings().then(() => {
    loadSettingsUI();
    // Sync scope to Target tab
    document.getElementById("tgt-scope-include").value = settings.scopeInclude || "";
    document.getElementById("tgt-scope-exclude").value = settings.scopeExclude || "";
    bg({ type: "UPDATE_SETTINGS", settings });
  });
  loadAll();
  startPoll();
});
