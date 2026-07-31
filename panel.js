"use strict";

// ── Suppress "Extension context invalidated" errors after extension reload ───
window.addEventListener("unhandledrejection", e => {
  if (e.reason?.message && /context invalidated|disconnected/i.test(e.reason.message)) {
    e.preventDefault();
  }
});

// ── Constants ─────────────────────────────────────────────────────────────────
const TAB_ID  = chrome.devtools.inspectedWindow.tabId;
const METHODS = ["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS","TRACE","CONNECT"];
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
// Remember which sub-tab is active per side across request clicks
let historyData = [];
let histDetailEntry = null;
let histSortKey = "id";
let histSortAsc = false; // false = newest first by default
let histColFilters = {};

// ── Repeater tabs state ──────────────────────────────────────────────────────
let repTabs = [{ id: 0, label: "1", method: "GET", url: "", headers: "", body: "", response: null, autoCookie: false, targetHost: "", targetPort: "", targetTls: true, history: [], histIdx: -1 }];
let repActiveTab = 0;
let repNextId = 1;

// ── Intruder state ───────────────────────────────────────────────────────────
let intrRunning = false;
let intrAbort = null;
let intrResults = [];
let intrPayloadSets = [""]; // one textarea per position
let intrActiveSet = 0;
let intrSortKey = "id";
let intrSortAsc = true;
let intrColFilters = {};

// ── WebSocket History state ──────────────────────────────────────────────────
let wsFrames = [];
let wsConnections = {};
let wsDetailFrame = null;
let wsSortKey = "id";
let wsSortAsc = false;
let wsFilterText = "";
let wsFilterDir = "";
let wsFilterType = "";
let wsFilterConn = "";
let wsTimer = null;

// ── Sequencer state ─────────────────────────────────────────────────────────
let seqTokens = [];
let seqRunning = false;
let seqAbort = null;

// ── Notes state ─────────────────────────────────────────────────────────────
let notes = [];
let notesNextId = 1;
let notesFilterText = "";
let notesFilterSev = "";
let notesFilterHost = "";
let notesEditingId = null;

// ── Messaging to background (with auto-retry on SW restart) ──────────────────
let _contextDead = false;
let bgSyncTimer = null;
let logSyncTimer = null;

function sendMsg(msg) {
  if (_contextDead) return Promise.resolve(null);
  return new Promise(resolve => {
    try {
      chrome.runtime.sendMessage({ ...msg, tabId: TAB_ID }, r => {
        if (chrome.runtime.lastError) {
          const err = chrome.runtime.lastError.message || "";
          if (/context invalidated|disconnected/i.test(err)) {
            _contextDead = true;
            stopAllTimers();
          }
          resolve(null);
          return;
        }
        resolve(r ?? null);
      });
    } catch (e) {
      if (/context invalidated|disconnected/i.test(e.message || "")) {
        _contextDead = true;
        stopAllTimers();
      }
      resolve(null);
    }
  });
}

function stopAllTimers() {
  clearInterval(pollTimer);   pollTimer = null;
  clearInterval(histTimer);   histTimer = null;
  clearInterval(bgSyncTimer); bgSyncTimer = null;
  clearInterval(logSyncTimer); logSyncTimer = null;
  clearInterval(wsTimer);     wsTimer = null;
  if (logSyncWs) { logSyncWs.close(); logSyncWs = null; }
}

async function bg(msg, retries = 3) {
  if (_contextDead) return null;
  for (let i = 0; i < retries; i++) {
    const res = await sendMsg(msg);
    if (res !== null) return res;
    if (_contextDead) return null;
    await new Promise(r => setTimeout(r, 300));
  }
  return null;
}

// Wake up the service worker before doing heavy work
async function wakeSW() {
  for (let i = 0; i < 4; i++) {
    const r = await sendMsg({ type: "PING" });
    if (r?.ok) return true;
    if (_contextDead) return false;
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
  if (name === "logger") { logSyncLocal(); logRender(); startLogSync(); logSyncConnect(); } else stopLogSync();
  if (name === "target") { pollHistory().then(() => renderSiteMap()); renderEndpoints(); }
  if (name === "headers") pollHistory().then(renderHeaders);
  if (name === "ws") startWsPoll(); else stopWsPoll();
  if (name === "notes") { notesRender(); }
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

// ── Background state sync (runs always, keeps badges/data fresh) ─────────────
function startBgSync() {
  if (bgSyncTimer) return;
  bgSyncTimer = setInterval(async () => {
    if (_contextDead) { stopAllTimers(); return; }
    const d = await sendMsg({ type: "GET_DATA" });
    if (!d) return; // SW might be restarting, skip this tick
    const wasAttached = state.attached;
    state = { ...state, ...d };
    if (state.attached !== wasAttached) renderInterceptStatus();
    const hst = await sendMsg({ type: "GET_HISTORY" });
    if (hst) {
      historyData = hst.history || [];
      setBadge("bdg-history", historyData.length);
    }
    setBadge("bdg-endpoints", (state.endpoints || []).length);
    // renderHeaders used to run only at load, so a tab opened before any traffic
    // stayed empty forever. Repaint while the tab is actually on screen.
    if (!document.getElementById("tab-headers").classList.contains("hidden")) renderHeaders();
  }, 2000);
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
  startBgSync();
}

// ── Badges ────────────────────────────────────────────────────────────────────
function updateBadges() {
  updateInterceptBadge();
  setBadge("bdg-history",   historyData.length);
  setBadge("bdg-endpoints", state.endpoints.length);
  setBadge("bdg-ws",        wsFrames.length);
  setBadge("bdg-notes",     notes.length);
}
function setBadge(id, n) {
  const b = document.getElementById(id);
  if (!b) return;
  b.textContent = n;
  b.className   = n > 0 ? "bdg has-data" : "bdg";
}
function updateInterceptBadge() {
  const b = document.getElementById("bdg-intercept");
  if (!b) return;
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

  list.replaceChildren();

  const queue = [...intercepted, ...proxyPending];
  if (!queue.length) { empty.classList.remove("hidden"); return; }
  empty.classList.add("hidden");

  queue.forEach(req => {
    const row = el("div", "req-row");
    if (editingReq && editingReq.requestId === req.requestId) row.classList.add("hist-selected");
    ap(row,
      txt("span", `method-pill m-${req.method.toLowerCase()}`, req.method),
      txt("span", "req-type",  req.resourceType || "other"),
      txt("span", "req-url",   req.url),
    );
    // Say which side held it — the actions differ underneath
    if (req._via === "proxy") row.appendChild(txt("span", "req-via", "PROXY"));
    const acts = el("div", "req-actions");
    const btnRep  = txt("button", "btn btn-xs btn-ghost",   "→ Rep");
    const btnIntr = txt("button", "btn btn-xs btn-ghost",   "→ Intr");
    const btnOpen = txt("button", "btn btn-xs btn-ghost",   "↗"); btnOpen.title = "Open in new tab";
    const btnFwd  = txt("button", "btn btn-xs btn-success", "Forward →");
    const btnDrop = txt("button", "btn btn-xs btn-danger",  "Drop");

    btnRep.addEventListener("click",  e => { e.stopPropagation(); sendToRepeater(req); });
    btnIntr.addEventListener("click", e => { e.stopPropagation(); intrSendToIntruder(req); });
    btnOpen.addEventListener("click", e => { e.stopPropagation(); chrome.tabs.create({ url: req.url }); });
    btnFwd.addEventListener("click",  e => { e.stopPropagation(); doForward(req.requestId, null); });
    btnDrop.addEventListener("click", e => { e.stopPropagation(); doDrop(req.requestId); });

    ap(acts, btnRep, btnIntr, btnOpen, btnFwd, btnDrop);
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

  const edUrl = document.getElementById("ed-url");
  edUrl.value     = req.url;
  autoSizeUrlInput(edUrl);
  document.getElementById("ed-headers").value = headersToRaw(req.headers || {});
  document.getElementById("ed-body").value    = req.body || "";

  const editor = document.getElementById("ic-editor");
  editor.classList.remove("hidden");
  editor.classList.add("visible");
  document.getElementById("ic-resizer").classList.add("visible");
  renderInterceptList();
}

function closeEditor() {
  editingReq = null;
  const editor = document.getElementById("ic-editor");
  editor.classList.add("hidden");
  editor.classList.remove("visible");
  document.getElementById("ic-resizer").classList.remove("visible");
  renderInterceptList();
}

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

// ── External proxy (void-proxy-server.js) ───────────────────────────────────
// An MV3 extension cannot listen on a port, so requests from clients outside
// Chrome (curl, Postman, a phone) are held by the Node proxy and mirrored into
// this same Intercept queue over a control WebSocket.
const PROXY_CTRL_URL = "ws://localhost:8082";
let proxyWs = null;
let proxyPending = [];          // paused proxy requests, shaped like `intercepted`
let proxyIntercepting = false;
let proxyInfo = null;           // { proxyPort, caPath }
// "unreachable" (server not running) reads very differently from "disconnected"
// (server up, Void just not watching), so they are tracked apart.
let proxyStatus = "disconnected"; // disconnected | connecting | connected | unreachable

function proxySend(msg) {
  if (proxyWs && proxyWs.readyState === 1) proxyWs.send(JSON.stringify(msg));
}

function proxyConnect() {
  if (proxyWs && proxyWs.readyState <= 1) return;
  try {
    proxyStatus = "connecting";
    proxyUpdateUI();
    proxyWs = new WebSocket(PROXY_CTRL_URL);
    proxyWs.onopen = () => { proxyStatus = "connected"; proxyUpdateUI(); };
    proxyWs.onmessage = (ev) => {
      let msg; try { msg = JSON.parse(ev.data); } catch { return; }

      if (msg.type === "hello") {
        proxyInfo = { proxyPort: msg.proxyPort, caPath: msg.caPath };
        proxyIntercepting = !!msg.intercepting;
        proxyPending = (msg.pending || []).map(proxyReqShape);
        renderInterceptList();
      } else if (msg.type === "state") {
        proxyIntercepting = !!msg.intercepting;
        if (!proxyIntercepting) proxyPending = [];
        renderInterceptList();
      } else if (msg.type === "paused") {
        proxyPending.push(proxyReqShape(msg.req));
        renderInterceptList();
      } else if (msg.type === "resolved") {
        proxyPending = proxyPending.filter(r => r.requestId !== msg.id);
        renderInterceptList();
      } else if (msg.type === "txn") {
        // Park it in the SW so it survives the panel's history polling
        bg({ type: "PROXY_TXN", entry: msg.entry });
      }
      proxyUpdateUI();
    };
    // A socket that closes without ever opening means nothing is listening.
    proxyWs.onclose = () => {
      if (proxyStatus !== "disconnected") proxyStatus = proxyStatus === "connected" ? "disconnected" : "unreachable";
      proxyWs = null; proxyReset();
    };
    proxyWs.onerror = () => { proxyStatus = "unreachable"; proxyWs = null; proxyReset(); };
  } catch { proxyStatus = "unreachable"; proxyWs = null; proxyReset(); }
}

function proxyReset() {
  proxyIntercepting = false;
  proxyPending = [];
  proxyUpdateUI();
  renderInterceptList();
}

function proxyDisconnect() {
  if (proxyWs) { proxySend({ type: "intercept", on: false }); proxyWs.close(); }
  proxyStatus = "disconnected";
  proxyWs = null;
  proxyReset();
}

// The proxy sends headers as raw text; the editor and the send-to helpers all
// expect a header object, so normalise once here.
function proxyReqShape(req) {
  return {
    requestId:    req.id,
    method:       req.method,
    url:          req.url,
    headers:      rawToHeaders(req.headers || ""),
    body:         req.body || "",
    resourceType: "proxy",
    _via:         "proxy",
  };
}

function proxyUpdateUI() {
  const bar   = document.getElementById("proxy-bar");
  const dot   = document.getElementById("proxy-dot");
  const label = document.getElementById("proxy-label");
  const hint  = document.getElementById("proxy-hint");
  const btn   = document.getElementById("btn-proxy");

  const copyBtn = document.getElementById("proxy-copy");
  const connected = !!(proxyWs && proxyWs.readyState === 1);
  bar.classList.toggle("hidden", !connected && proxyStatus === "disconnected" && !proxyInfo);
  // The hint is a runnable command in every state except plain "not connected",
  // where it is an explanatory sentence — nothing to copy.
  copyBtn.classList.toggle("hidden", !connected && proxyStatus === "disconnected");
  dot.className = "dot " + (connected ? (proxyIntercepting ? "dot-intercepting" : "dot-attached") : "dot-off");

  if (!connected) {
    btn.textContent = "Proxy: connect";
    btn.classList.remove("btn-success");
    if (proxyStatus === "connecting") {
      label.textContent = "Connecting…";
      hint.textContent = "";
    } else if (proxyStatus === "unreachable") {
      label.textContent = "Proxy not running";
      hint.textContent = "node void-proxy-server.js";
    } else {
      // Disconnecting Void does NOT stop the proxy — say so, or "off" reads as
      // "traffic is no longer being proxied", which is wrong.
      label.textContent = "Not connected";
      hint.textContent = "Proxy keeps passing traffic if the server is up — it just isn't recorded here";
    }
    return;
  }
  label.textContent = proxyIntercepting
    ? "Intercepting — requests are held until you Forward or Drop"
    : "Logging — traffic passes through and is recorded in History";
  hint.textContent = proxyInfo
    ? `curl -x http://127.0.0.1:${proxyInfo.proxyPort} --cacert ${proxyInfo.caPath} https://target/`
    : "";
  btn.textContent = proxyIntercepting ? "Proxy: intercepting" : "Proxy: logging";
  btn.classList.toggle("btn-success", proxyIntercepting);
}

async function doForward(requestId, overrides) {
  const px = proxyPending.find(r => r.requestId === requestId);
  if (px) {
    proxyPending = proxyPending.filter(r => r.requestId !== requestId);
    proxySend({
      type: "forward", id: requestId,
      method:  overrides?.method  ?? px.method,
      url:     overrides?.url     ?? px.url,
      headers: overrides?.headers != null ? headersToRaw(overrides.headers) : headersToRaw(px.headers),
      body:    overrides?.body    ?? px.body,
    });
    renderInterceptList();
    return;
  }
  intercepted = intercepted.filter(r => r.requestId !== requestId);
  await bg({ type: "FORWARD", requestId, overrides: overrides || {} });
  renderInterceptList();
}

async function doDrop(requestId) {
  if (proxyPending.some(r => r.requestId === requestId)) {
    proxyPending = proxyPending.filter(r => r.requestId !== requestId);
    proxySend({ type: "drop", id: requestId });
    renderInterceptList();
    return;
  }
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

// ═══════════════════════════ LOGGER (cross-container aggregator) ═════════════

let logEntries = [];       // all entries from all sources
let logDetailEntry = null;
let logSortKey = "id";
let logSortAsc = false;
let logColFilters = {};
let logFilterText = "";
let logFilterMeth = "";
let logFilterStat = "";
let logFilterSource = "";
let logScopeOnly = false;
let logNextId = 1;

// Sync local history into logger (idempotent — uses stable IDs)
function logSyncLocal() {
  // Track what's already in the logger from local sources
  const existingUrls = new Set(logEntries.filter(e => e._logSource === "local").map(e => e._logStableKey));

  for (const e of historyData) {
    const key = `${e.time}_${e.method}_${e.url}`;
    if (existingUrls.has(key)) continue;
    logEntries.push({ ...e, _logId: logNextId++, _logSource: "local", _logLabel: "Proxy", _logStableKey: key });
    existingUrls.add(key);
  }

  // Add repeater entries (use tab id as stable key)
  const existingRep = new Set(logEntries.filter(e => e._logSource === "repeater").map(e => e._logStableKey));
  for (const tab of repTabs) {
    if (!tab.response || !tab.url) continue;
    const key = `rep_${tab.id}_${tab.response?.status}_${tab.response?.elapsed}`;
    if (existingRep.has(key)) continue;
    const r = tab.response;
    const entry = {
      method: tab.method, url: tab.url, host: "", path: "",
      headers: {}, body: tab.body, status: r.status, statusText: r.statusText || "",
      respHeaders: r.headers || {}, respBody: r.body || "",
      length: r.size || 0, mimeType: r.headers?.["content-type"] || "",
      time: 0, elapsed: r.elapsed || 0,
      _logId: logNextId++, _logSource: "repeater", _logLabel: tab.customLabel || "Repeater", _logStableKey: key,
    };
    try { const u = new URL(tab.url); entry.host = u.host; entry.path = u.pathname + u.search; } catch {}
    logEntries.push(entry);
  }
}

function logImportFile(file) {
  return file.text().then(text => {
    const data = JSON.parse(text);
    const imported = data.history || [];
    if (!imported.length) return;
    const name = data.name || file.name.replace(/\.json$/, "");
    // Dedup against existing entries
    const existing = new Set(logEntries.map(e => e._logStableKey).filter(Boolean));
    let added = 0;
    for (const e of imported) {
      const key = `${e.time || 0}_${e.method}_${e.url}_${name}`;
      if (existing.has(key)) continue;
      logEntries.push({ ...e, _logId: logNextId++, _logSource: "container", _logLabel: name, _logStableKey: key });
      existing.add(key);
      added++;
    }
    logAddSourceOption(name);
  });
}

function logRender() {
  const tbody = document.getElementById("log-tbody");
  const empty = document.getElementById("log-empty");
  tbody.replaceChildren();

  let items = [...logEntries];

  // Filters
  if (logFilterMeth) items = items.filter(e => e.method === logFilterMeth);
  if (logFilterStat) items = items.filter(e => e.status && String(e.status).startsWith(logFilterStat));
  if (logFilterSource) items = items.filter(e => e._logSource === logFilterSource || e._logLabel === logFilterSource);
  if (logScopeOnly) items = items.filter(e => tgtIsInScope(e.url));
  for (const [field, allowed] of Object.entries(logColFilters)) {
    if (!allowed) continue;
    items = items.filter(e => {
      const val = field === "source" ? (e._logLabel || "") : field === "status" ? String(e.status ?? "") : String(e[field] ?? "");
      return allowed.has(val);
    });
  }

  // Advanced text search (same field:value syntax as History)
  if (logFilterText) {
    const fieldRe = /(\w+):(\S+)/g;
    const fieldFilters = [];
    let plain = logFilterText;
    let fm;
    while ((fm = fieldRe.exec(logFilterText)) !== null) {
      fieldFilters.push({ field: fm[1].toLowerCase(), value: fm[2].toLowerCase() });
      plain = plain.replace(fm[0], "");
    }
    plain = plain.trim().toLowerCase();
    items = items.filter(e => {
      for (const { field, value } of fieldFilters) {
        switch (field) {
          case "host":   if (!(e.host||"").toLowerCase().includes(value)) return false; break;
          case "path":   if (!(e.path||"").toLowerCase().includes(value)) return false; break;
          case "url":    if (!(e.url||"").toLowerCase().includes(value)) return false; break;
          case "method": if ((e.method||"").toLowerCase() !== value) return false; break;
          case "status": if (!String(e.status||"").startsWith(value)) return false; break;
          case "body":   if (!(e.body||"").toLowerCase().includes(value) && !(e.respBody||"").toLowerCase().includes(value)) return false; break;
          case "header": {
            const h = [...Object.entries(e.headers||{}), ...Object.entries(e.respHeaders||{})].map(([k,v])=>`${k}: ${v}`).join("\n").toLowerCase();
            if (!h.includes(value)) return false; break;
          }
          case "source": if (!(e._logLabel||"").toLowerCase().includes(value) && !(e._logSource||"").toLowerCase().includes(value)) return false; break;
        }
      }
      if (plain) {
        const hay = [e.url, e.method, e.host, String(e.status||""), e.body||"", e.respBody||"",
          ...Object.entries(e.headers||{}).map(([k,v])=>`${k}:${v}`),
          ...Object.entries(e.respHeaders||{}).map(([k,v])=>`${k}:${v}`),
        ].join("\n").toLowerCase();
        if (!hay.includes(plain)) return false;
      }
      return true;
    });
  }

  // Sort
  items.sort((a, b) => {
    let va, vb;
    switch (logSortKey) {
      case "id":      va = a._logId; vb = b._logId; break;
      case "source":  va = a._logLabel||""; vb = b._logLabel||""; break;
      case "method":  va = a.method; vb = b.method; break;
      case "host":    va = a.host||""; vb = b.host||""; break;
      case "path":    va = a.path||""; vb = b.path||""; break;
      case "status":  va = a.status||0; vb = b.status||0; break;
      case "length":  va = a.length||0; vb = b.length||0; break;
      case "elapsed": va = a.elapsed||0; vb = b.elapsed||0; break;
      case "time":    va = a.time||0; vb = b.time||0; break;
      default:        va = a._logId; vb = b._logId;
    }
    if (typeof va === "string") { va = va.toLowerCase(); vb = vb.toLowerCase(); }
    return (va < vb ? -1 : va > vb ? 1 : 0) * (logSortAsc ? 1 : -1);
  });

  // Sort indicators
  document.querySelectorAll("#log-table .hist-th-sortable").forEach(th => {
    const key = th.dataset.logsort;
    const arrow = key === logSortKey ? (logSortAsc ? " \u25B4" : " \u25BE") : "";
    let sp = th.querySelector(".sort-label");
    if (!sp) { sp = document.createElement("span"); sp.className = "sort-label"; const raw = th.firstChild?.nodeType === 3 ? th.firstChild.textContent.trim() : ""; if (th.firstChild?.nodeType === 3) th.firstChild.remove(); th.insertBefore(sp, th.firstChild); sp.textContent = raw; }
    sp.textContent = sp.textContent.replace(/ [\u25B4\u25BE]$/, "") + arrow;
  });

  setBadge("bdg-logger", logEntries.length);

  if (!items.length) { empty.classList.remove("hidden"); document.getElementById("log-table").parentElement.classList.add("hidden"); return; }
  empty.classList.add("hidden");
  document.getElementById("log-table").parentElement.classList.remove("hidden");

  const SRC_COLORS = { proxy: "hist-src-proxy", repeater: "hist-src-repeater", container: "hist-src-container" };
  for (const e of items.slice(0, 3000)) {
    const tr = document.createElement("tr");
    tr.className = "tgt-clickable";
    const statusCls = !e.status ? "hist-td-status-wait" : e.status < 300 ? "hist-td-status-ok" : e.status < 400 ? "hist-td-status-rdir" : "hist-td-status-err";
    const len = e.length > 1024 ? `${(e.length/1024).toFixed(1)}k` : e.length || "";
    const ts = e.time ? fmtTime(e.time) : "";
    const srcCls = SRC_COLORS[e._logSource] || "hist-src-proxy";
    const srcLbl = (e._logLabel || "PRX").slice(0, 5);
    const mCls = esc((e.method||"").toLowerCase().replace(/[^a-z]/g, ""));
    tr.innerHTML = `
      <td class="hist-td-num">${Number(e._logId)||0}</td>
      <td><span class="hist-src-badge ${srcCls}">${esc(srcLbl)}</span></td>
      <td><span class="method-pill m-${mCls}">${esc(e.method)}</span></td>
      <td title="${esc(e.host)}">${esc(e.host)}</td>
      <td title="${esc(e.path)}">${esc(e.path)}</td>
      <td class="${statusCls}">${esc(String(e.status ?? "\u2026"))}</td>
      <td class="hist-td-len">${esc(String(len))}</td>
      <td class="hist-td-elapsed">${e.elapsed ? Number(e.elapsed)||"" : ""}</td>
      <td class="hist-td-timestamp">${esc(ts)}</td>
    `;
    tr._logEntry = e;
    if (logDetailEntry === e) tr.classList.add("hist-selected");
    tr.addEventListener("click", () => logOpenDetail(e));
    tbody.appendChild(tr);
  }
}

function logOpenDetail(entry) {
  logDetailEntry = entry;
  const detail = document.getElementById("log-detail");
  document.getElementById("log-detail-title").textContent = `[${entry._logLabel}] ${entry.status||"\u2026"} ${entry.method} ${entry.url}`;
  document.getElementById("log-req-pre").textContent  = rawRequestText(entry);
  document.getElementById("log-resp-pre").textContent = rawResponseText(entry);
  detail.classList.remove("hidden"); detail.classList.add("visible");
  document.getElementById("log-resizer").classList.add("visible");
  document.querySelectorAll("#log-tbody tr").forEach(r => r.classList.remove("hist-selected"));
  document.querySelectorAll("#log-tbody tr").forEach(r => { if (r._logEntry === entry) r.classList.add("hist-selected"); });
}

function logCloseDetail() {
  logDetailEntry = null;
  document.getElementById("log-detail").classList.add("hidden");
  document.getElementById("log-detail").classList.remove("visible");
  document.getElementById("log-resizer").classList.remove("visible");
}

function startLogSync() {
  if (logSyncTimer) return;
  logSyncTimer = setInterval(() => {
    logSyncLocal();
    logPushToSync();
    logRender();
    // Auto-reconnect if WS dropped while Logger is active
    if (!logSyncWs || logSyncWs.readyState > 1) logSyncConnect();
  }, 3000);
}
function stopLogSync() { clearInterval(logSyncTimer); logSyncTimer = null; }

// ── WebSocket sync client (runs in panel — stays alive while DevTools is open) ──
let logSyncWs = null;
let logSyncName = "main";
let logSyncLastPush = 0;

function logSyncConnect() {
  if (logSyncWs && logSyncWs.readyState <= 1) return; // already connected/connecting
  try {
    logSyncWs = new WebSocket("ws://localhost:17580");
    logSyncWs.onopen = () => {
      chrome.storage.local.get("voidContainerName", r => {
        logSyncName = r.voidContainerName || "main";
        logSyncWs.send(JSON.stringify({ type: "register", name: logSyncName }));
        logPushToSync(); // push our history immediately
      });
      logSyncUpdateUI(true);
    };
    logSyncWs.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data);
        if (msg.type === "init" || msg.type === "update") {
          logMergeRemoteEntries(msg.entries || [], msg.from);
          logRender();
        }
      } catch {}
    };
    logSyncWs.onclose = () => { logSyncWs = null; logSyncUpdateUI(false); };
    logSyncWs.onerror = () => { logSyncWs = null; logSyncUpdateUI(false); };
  } catch { logSyncWs = null; logSyncUpdateUI(false); }
}

function logSyncDisconnect() {
  if (logSyncWs) { logSyncWs.close(); logSyncWs = null; }
  logSyncUpdateUI(false);
}

function logSyncUpdateUI(connected) {
  const dot = document.getElementById("log-sync-dot");
  const label = document.getElementById("log-sync-label");
  const btn = document.getElementById("log-sync");
  if (!dot || !label) return;
  dot.className = connected ? "dot dot-intercepting" : "dot dot-off";
  label.textContent = connected ? "Connected" : "Disconnected";
  if (btn) btn.textContent = connected ? "Disconnect" : "Sync";
}

function logPushToSync() {
  if (!logSyncWs || logSyncWs.readyState !== 1) return;
  // Push local history (proxy + repeater) to sync server
  const localEntries = logEntries.filter(e => e._logSource === "local" || e._logSource === "repeater");
  if (localEntries.length === logSyncLastPush) return; // no change
  logSyncLastPush = localEntries.length;
  logSyncWs.send(JSON.stringify({ type: "history", entries: localEntries }));
}

function logMergeRemoteEntries(entries, fromLabel) {
  const existing = new Set(logEntries.filter(e => e._logSource === "container").map(e => e._logStableKey));
  for (const e of entries) {
    const key = `${e.time || 0}_${e.method}_${e.url}_${e._logLabel || fromLabel || ""}`;
    if (existing.has(key)) continue;
    // Ensure container source metadata
    const entry = { ...e, _logId: logNextId++, _logSource: e._logSource || "container", _logLabel: e._logLabel || fromLabel || "container", _logStableKey: key };
    logEntries.push(entry);
    existing.add(key);
    // Add source label to filter dropdown
    logAddSourceOption(entry._logLabel);
  }
}

function logAddSourceOption(label) {
  if (!label) return;
  const sel = document.getElementById("log-flt-source");
  if (!sel) return;
  if (![...sel.options].some(o => o.value === label)) {
    const o = el("option"); o.value = label; o.textContent = label;
    sel.appendChild(o);
  }
}

function logExport() {
  const data = { version: 1, name: "Logger Export", timestamp: new Date().toISOString(), history: logEntries };
  const blob = new Blob([JSON.stringify(data)], { type: "application/json" });
  const a = el("a"); a.href = URL.createObjectURL(blob);
  a.download = `void-logger-${new Date().toISOString().slice(0,10)}.json`; a.click();
  URL.revokeObjectURL(a.href);
}

// ═══════════════════════════ HISTORY ════════════════════════════════════════

function renderHistory() {
  const tbody = document.getElementById("hist-tbody");
  const empty = document.getElementById("hist-empty");
  const table = document.getElementById("hist-table");
  const detail = document.getElementById("hist-detail");

  // Allow table re-render even when detail is open (split view)

  let items = historyData;

  // Dropdown filters
  if (filterHistMeth) items = items.filter(e => e.method === filterHistMeth);
  if (filterHistStat) {
    const prefix = filterHistStat.charAt(0);
    items = items.filter(e => e.status && String(e.status).charAt(0) === prefix);
  }
  if (filterHistMime) {
    const q = filterHistMime.toLowerCase();
    items = items.filter(e => (e.mimeType || "").toLowerCase().includes(q));
  }
  if (filterHistScope) items = items.filter(e => tgtIsInScope(e.url));
  if (filterHistExt === "no-static") {
    items = items.filter(e => !/\.(js|mjs|css|png|jpe?g|gif|webp|ico|svg|woff2?|ttf|eot|map)(\?|$)/i.test(e.path));
  }
  if (filterHistReflect) items = items.filter(e => hasReflections(e));
  // Column checkbox filters
  for (const [field, allowed] of Object.entries(histColFilters)) {
    if (!allowed) continue;
    items = items.filter(e => {
      const val = field === "mimeType" ? shortMime(e.mimeType) : String(e[field] ?? "");
      return allowed.has(val);
    });
  }

  // Advanced text search — supports field:value syntax AND plain text
  if (filterHist) {
    const fieldRe = /(\w+):(\S+)/g;
    const fieldFilters = [];
    let plainQuery = filterHist;
    let fm;
    while ((fm = fieldRe.exec(filterHist)) !== null) {
      fieldFilters.push({ field: fm[1].toLowerCase(), value: fm[2].toLowerCase() });
      plainQuery = plainQuery.replace(fm[0], "");
    }
    plainQuery = plainQuery.trim().toLowerCase();

    items = items.filter(e => {
      // Field-specific filters
      for (const { field, value } of fieldFilters) {
        switch (field) {
          case "host":   if (!(e.host || "").toLowerCase().includes(value)) return false; break;
          case "path":   if (!(e.path || "").toLowerCase().includes(value)) return false; break;
          case "url":    if (!(e.url || "").toLowerCase().includes(value)) return false; break;
          case "method": if ((e.method || "").toLowerCase() !== value) return false; break;
          case "status": if (!String(e.status || "").startsWith(value)) return false; break;
          case "type":   if (!(e.mimeType || "").toLowerCase().includes(value)) return false; break;
          case "body":   if (!(e.body || "").toLowerCase().includes(value) && !(e.respBody || "").toLowerCase().includes(value)) return false; break;
          case "header": {
            const allHdrs = [...Object.entries(e.headers || {}), ...Object.entries(e.respHeaders || {})].map(([k,v]) => `${k}: ${v}`).join("\n").toLowerCase();
            if (!allHdrs.includes(value)) return false; break;
          }
          case "source": if ((e._source || "").toLowerCase() !== value) return false; break;
          default:       if (!(e.url || "").toLowerCase().includes(`${field}:${value}`)) return false;
        }
      }
      // Plain text search on everything
      if (plainQuery) {
        const haystack = [
          e.url, e.method, e.host, e.path,
          String(e.status || ""), e.mimeType || "",
          ...Object.entries(e.headers || {}).map(([k,v]) => `${k}: ${v}`),
          ...Object.entries(e.respHeaders || {}).map(([k,v]) => `${k}: ${v}`),
          e.body || "", e.respBody || "",
        ].join("\n").toLowerCase();
        if (!haystack.includes(plainQuery)) return false;
      }
      return true;
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
  document.querySelectorAll("#hist-table .hist-th-sortable").forEach(th => {
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

    const safeMethod = esc(entry.method);
    const safeMethodCls = esc(entry.method.toLowerCase().replace(/[^a-z]/g, ""));
    tr.innerHTML = `
      <td class="hist-td-num">${Number(entry._idx) || 0}</td>
      <td><span class="method-pill m-${safeMethodCls}">${safeMethod}</span></td>
      <td title="${esc(entry.host)}">${esc(entry.host)}</td>
      <td title="${esc(entry.path)}">${esc(entry.path)}</td>
      <td class="${statusCls}">${esc(String(entry.status ?? "…"))}</td>
      <td class="hist-td-mime">${esc(shortMime(entry.mimeType))}</td>
      <td class="hist-td-len">${esc(String(len))}</td>
      <td class="hist-td-elapsed">${entry.elapsed ? Number(entry.elapsed) || "" : ""}</td>
      <td class="hist-td-timestamp">${esc(ts)}</td>
    `;
    if (entry.respBody && hasReflections(entry)) {
      const dot = document.createElement("span");
      dot.className = "hist-reflect-dot";
      dot.title = "Reflections detected";
      tr.querySelector("td:nth-child(5)").appendChild(dot);
    }
    tr._histEntry = entry;
    if (histDetailEntry && entry === histDetailEntry) tr.classList.add("hist-selected");
    tr.addEventListener("click", () => openHistDetail(entry));
    tbody.appendChild(tr);
  }
}

// Response bodies only exist on debugger-captured entries — the webRequest passive
// capture cannot read them at all, so say that instead of implying one is coming.
function respBodyOr(entry) {
  if (entry?.respBody) return entry.respBody;
  return entry?.capture === "passive"
    ? "(no body — passive capture; click Attach to capture response bodies)"
    : "(body not captured)";
}

// ── Raw request/response text ───────────────────────────────────────────────
// Every detail pane shows one merged view per side (request line + headers +
// blank line + body) instead of separate Headers/Body sub-tabs.
function entryHost(entry) {
  if (entry.host) return entry.host;
  try { return new URL(entry.url).host; } catch { return ""; }
}

function rawRequestText(entry) {
  let path = entry.path || "";
  if (!path) {
    try { const u = new URL(entry.url); path = u.pathname + u.search; }
    catch { path = entry.url || "/"; }
  }
  const hdrs = entry.headers || {};
  let out = `${entry.method || "GET"} ${path} HTTP/1.1\n`;
  // background.js normally injects Host at capture time; synthesise it here too
  // so restored sessions and hand-built entries still show it.
  if (!Object.keys(hdrs).some(k => k.toLowerCase() === "host")) {
    const host = entryHost(entry);
    if (host) out += `Host: ${host}\n`;
  }
  out += Object.entries(hdrs).map(([k, v]) => `${k}: ${v}`).join("\n");
  if (entry.body) out += `\n\n${entry.body}`;
  return out;
}

function rawResponseText(entry) {
  let out = entry.status
    ? `HTTP/1.1 ${entry.status} ${entry.statusText || ""}\n`
    : "(no response)\n";
  out += Object.entries(entry.respHeaders || {}).map(([k, v]) => `${k}: ${v}`).join("\n");
  const ct = entry.respHeaders?.["content-type"] || entry.respHeaders?.["Content-Type"] || "";
  return `${out}\n\n${tryPretty(respBodyOr(entry), ct)}`;
}

function esc(s) { return (s || "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;"); }
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

  document.getElementById("hist-req-pre").textContent  = rawRequestText(entry);
  document.getElementById("hist-resp-pre").textContent = rawResponseText(entry);

  detail.classList.remove("hidden");
  detail.classList.add("visible");
  document.getElementById("hist-resizer").classList.add("visible");

  // Highlight selected row
  document.querySelectorAll("#hist-tbody tr").forEach(r => r.classList.remove("hist-selected"));
  const rows = document.querySelectorAll("#hist-tbody tr");
  for (const r of rows) {
    if (r._histEntry === entry) { r.classList.add("hist-selected"); break; }
  }

  // Clear search first, then lay down the reflection highlight underneath it
  if (histReqSearch) histReqSearch.clear();
  if (histRespSearch) histRespSearch.clear();
  histReflectBar?.update(entry);

  const nRefl = histReflectBar?.count() ?? 0;
  const badge = document.getElementById("hist-reflect-badge");
  badge.classList.toggle("hidden", nRefl === 0);
  if (nRefl) badge.textContent = `${nRefl} reflection${nRefl > 1 ? "s" : ""}`;
}

function closeHistDetail() {
  histDetailEntry = null;
  const detail = document.getElementById("hist-detail");
  detail.classList.add("hidden");
  detail.classList.remove("visible");
  document.getElementById("hist-resizer").classList.remove("visible");
  document.querySelectorAll("#hist-tbody tr").forEach(r => r.classList.remove("hist-selected"));
}

function histDetailToRepeater() {
  if (!histDetailEntry) return;
  sendToRepeater({
    method:  histDetailEntry.method,
    url:     histDetailEntry.url,
    headers: histDetailEntry.headers || {},
    body:    histDetailEntry.body || "",
  });
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
    targetHost: "", targetPort: "", targetTls: true, history: [], histIdx: -1,
  };
  repTabs.push(newTab);
  repActiveTab = newTab.id;
  renderRepTabs();
  loadRepTab(newTab);

  // Flash the Repeater badge to notify the user
  const bdg = document.getElementById("bdg-repeater");
  const pending = repTabs.filter(t => !t.response).length;
  bdg.textContent = "+" + repTabs.length;
  bdg.className = "bdg has-data";
  clearTimeout(bdg._timer);
  bdg._timer = setTimeout(() => { bdg.className = "bdg hidden"; }, 3000);
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

// Ensure a method exists in a <select> dropdown, add if missing
function ensureMethod(selectEl, method) {
  if (!method) return;
  for (const o of selectEl.options) { if (o.value === method) return; }
  const o = el("option"); o.value = method; o.textContent = method;
  selectEl.appendChild(o);
}

// Fast load for history navigation — direct .value, no focus/select overhead
function loadRepTabFast(tab) {
  const mSel = document.getElementById("rep-method");
  ensureMethod(mSel, tab.method);
  mSel.value = tab.method;
  document.getElementById("rep-url").value = tab.url;
  document.getElementById("rep-headers").value = tab.headers;
  document.getElementById("rep-body-ta").value = tab.body;
  autoSizeUrlInput(document.getElementById("rep-url"));

  clearRespPanes();
  const empty   = document.getElementById("resp-empty");
  const label   = document.getElementById("resp-label");

  if (tab.response) {
    const r = tab.response;
    label.textContent = `RESPONSE — ${r.status} ${r.statusText}${r.size ? ` ${(r.size/1024).toFixed(1)} KB` : ""}${r.elapsed ? ` ${r.elapsed}ms` : ""}`;
    document.getElementById("resp-body-pre").textContent = repRawResponse(r);
    empty.classList.add("hidden");
    repReflectBar?.update(repReflectEntry(r));
  } else {
    label.textContent = "RESPONSE";
    empty.classList.remove("hidden");
    repReflectBar?.update(null);
  }
  updateRepHistButtons();
}

// Set input/textarea value preserving undo history.
// Assigning .value directly wipes the browser's native undo stack, so Ctrl+Z
// does nothing afterwards. execCommand keeps it — deprecated, but it is still
// the only way to script an edit the undo stack knows about.
function setFieldValue(field, val) {
  if (field.value === val) return;
  const active = document.activeElement;
  field.focus();
  field.select();
  const ok = val
    ? document.execCommand("insertText", false, val)
    : document.execCommand("delete"); // insertText("") is a no-op, so clear explicitly
  if (!ok) field.value = val; // fallback: content is right, undo stack is lost
  if (active && active !== field && typeof active.focus === "function") active.focus();
}

function loadRepTab(tab) {
  const mSel = document.getElementById("rep-method");
  ensureMethod(mSel, tab.method);
  mSel.value = tab.method;
  const repUrl = document.getElementById("rep-url");
  setFieldValue(repUrl, tab.url);
  setFieldValue(document.getElementById("rep-headers"), tab.headers);
  setFieldValue(document.getElementById("rep-body-ta"), tab.body);
  autoSizeUrlInput(repUrl);
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
  const empty   = document.getElementById("resp-empty");
  const label   = document.getElementById("resp-label");

  if (tab.response) {
    const r = tab.response;
    label.textContent = `RESPONSE — ${r.status} ${r.statusText}${r.size ? ` ${(r.size/1024).toFixed(1)} KB` : ""}${r.elapsed ? ` ${r.elapsed}ms` : ""}`;
    document.getElementById("resp-body-pre").textContent = repRawResponse(r);
    empty.classList.add("hidden");
    repReflectBar?.update(repReflectEntry(r));
  } else {
    label.textContent = "RESPONSE";
    empty.classList.remove("hidden");
    repReflectBar?.update(null);
  }
  updateRepHistButtons();
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

    // Label — custom name or short path
    let label = tab.customLabel || tab.label;
    if (!tab.customLabel && tab.url) {
      try { const u = new URL(tab.url); label = u.pathname.split("/").pop() || tab.label; } catch {}
    }

    const labelSpan = document.createElement("span");
    labelSpan.textContent = label;
    btn.appendChild(labelSpan);

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

    // Double-click to rename
    btn.addEventListener("dblclick", e => {
      e.stopPropagation();
      const input = document.createElement("input");
      input.type = "text";
      input.className = "rep-tab-rename";
      input.value = tab.customLabel || label;
      input.size = Math.max(4, input.value.length + 1);
      labelSpan.replaceWith(input);
      input.focus();
      input.select();
      const finish = () => {
        const val = input.value.trim();
        if (val) { tab.customLabel = val; }
        renderRepTabs();
      };
      input.addEventListener("blur", finish);
      input.addEventListener("keydown", ev => {
        if (ev.key === "Enter") { ev.preventDefault(); input.blur(); }
        if (ev.key === "Escape") { ev.preventDefault(); input.value = ""; input.blur(); }
      });
    });

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
  const newTab = { id: repNextId++, label: repTabs.length + 1 + "", method: "GET", url: "", headers: "", body: "", response: null, history: [], histIdx: -1 };
  repTabs.push(newTab);
  repActiveTab = newTab.id;
  renderRepTabs();
  loadRepTab(newTab);
}

// ── Repeater history navigation ──────────────────────────────────────────────
function repHistPush(tab) {
  const snap = { method: tab.method, url: tab.url, headers: tab.headers, body: tab.body, response: tab.response };
  if (!tab.history) { tab.history = []; tab.histIdx = -1; }
  // Trim forward history if we're not at the end
  if (tab.histIdx < tab.history.length - 1) {
    tab.history = tab.history.slice(0, tab.histIdx + 1);
  }
  tab.history.push(snap);
  tab.histIdx = tab.history.length - 1;
  updateRepHistButtons();
}

function repHistBack() {
  const tab = repTabs.find(t => t.id === repActiveTab);
  if (!tab || !tab.history || tab.histIdx <= 0) return;
  saveRepTabState();
  tab.histIdx--;
  const snap = tab.history[tab.histIdx];
  tab.method = snap.method; tab.url = snap.url; tab.headers = snap.headers; tab.body = snap.body; tab.response = snap.response;
  loadRepTabFast(tab);
  updateRepHistButtons();
}

function repHistForward() {
  const tab = repTabs.find(t => t.id === repActiveTab);
  if (!tab || !tab.history || tab.histIdx >= tab.history.length - 1) return;
  saveRepTabState();
  tab.histIdx++;
  const snap = tab.history[tab.histIdx];
  tab.method = snap.method; tab.url = snap.url; tab.headers = snap.headers; tab.body = snap.body; tab.response = snap.response;
  loadRepTabFast(tab);
  updateRepHistButtons();
}

function updateRepHistButtons() {
  const tab = repTabs.find(t => t.id === repActiveTab);
  const backBtn = document.getElementById("rep-hist-back");
  const fwdBtn  = document.getElementById("rep-hist-fwd");
  if (!backBtn || !fwdBtn) return;
  const hasHist = tab && tab.history && tab.history.length > 0;
  backBtn.disabled = !hasHist || tab.histIdx <= 0;
  fwdBtn.disabled  = !hasHist || tab.histIdx >= tab.history.length - 1;
}

// ── URL input auto-sizer ────────────────────────────────────────────────────
const _urlSizer = document.createElement("span");
_urlSizer.className = "url-sizer";
document.body.appendChild(_urlSizer);

function autoSizeUrlInput(inp) {
  _urlSizer.textContent = inp.value || inp.placeholder || "";
  const w = _urlSizer.scrollWidth + 18; // 18 = padding
  inp.style.minWidth = Math.max(120, Math.min(w, inp.parentElement.clientWidth * 0.85)) + "px";
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

  sendBtn.disabled   = true;
  sendBtn.textContent = "Sending…";
  loading.classList.remove("hidden");
  empty.classList.add("hidden");
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
    repReflectBar?.update(null);
    return;
  }

  const kb   = res.size ? ` ${(res.size / 1024).toFixed(1)} KB` : "";
  const ms   = res.elapsed ? ` ${res.elapsed}ms` : "";
  respLabel.textContent = `RESPONSE — ${res.status} ${res.statusText}${kb}${ms}`;

  document.getElementById("resp-body-pre").textContent = repRawResponse(res);
  repReflectBar?.update(repReflectEntry(res));

  // Save response to current repeater tab + push to history
  const curTab = repTabs.find(t => t.id === repActiveTab);
  if (curTab) {
    curTab.response = res;
    saveRepTabState();
    repHistPush(curTab);
  }
}

function tryPretty(body, contentType) {
  if (/json/i.test(contentType)) {
    try { return JSON.stringify(JSON.parse(body), null, 2); } catch {}
  }
  return body;
}

function clearRespPanes() {
  ["resp-body-pre"].forEach(id => {
    const pre = document.getElementById(id);
    pre.textContent = "";
    delete pre._reflectOrig; // drop the stale reflection baseline with the text
    delete pre._origText;
  });
}

// Repeater has no history entry to hand the reflection engine, so synthesise the
// shape detectReflections() expects from the live editors + last response.
function repReflectEntry(res) {
  if (!res) return null;
  const headers = {};
  document.getElementById("rep-headers").value.split("\n").forEach(line => {
    const i = line.indexOf(":");
    if (i > 0) headers[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  });
  return {
    url:         document.getElementById("rep-url").value.trim(),
    headers,
    body:        document.getElementById("rep-body-ta").value,
    respBody:    res.body || "",
    respHeaders: res.headers || {},
  };
}

// Repeater shows one merged response view (status line + headers + body)
// instead of Body/Headers/Raw sub-tabs.
function repRawResponse(r) {
  const hdrsText = Object.entries(r.headers || {}).map(([k, v]) => `${k}: ${v}`).join("\n");
  const body = tryPretty(r.body || "(empty body)", r.headers?.["content-type"] || "");
  return `HTTP/1.1 ${r.status} ${r.statusText || ""}\n${hdrsText}\n\n${body}`;
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

function guessEpType(entry) {
  const u = (entry.url || "").toLowerCase();
  const rt = entry.resourceType || "";
  if (rt === "XHR" || rt === "Fetch" || /\/api\/|\/v\d+\/|\/graphql|\/rest\//.test(u)) return "api";
  if (/\.(js|mjs)(\?|$)/.test(u) || rt === "Script") return "script";
  if (/\.(css|woff2?|ttf|eot|png|jpe?g|gif|webp|ico|svg|map)(\?|$)/.test(u)) return null;
  if (rt === "Document") return "link";
  return "link";
}

function renderEndpoints() {
  const list  = document.getElementById("ep-list");
  const empty = document.getElementById("ep-empty");

  // Merge state.endpoints + historyData (deduplicated by URL+method)
  const seen = new Set();
  let items = [];
  for (const ep of (state.endpoints || [])) {
    const key = `${ep.method || "GET"}|${ep.url}`;
    if (seen.has(key)) continue;
    seen.add(key);
    items.push(ep);
  }
  for (const h of historyData) {
    const key = `${h.method}|${h.url}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const t = guessEpType(h);
    if (!t) continue; // skip static assets
    items.push({ url: h.url, method: h.method, type: t });
  }
  if (filterEp)     items = items.filter(e => e.url.toLowerCase().includes(filterEp));
  if (filterEpType) items = items.filter(e => e.type === filterEpType);
  if (tgtInScopeOnly) items = items.filter(e => tgtIsInScope(e.url));

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

    cpyBtn.addEventListener("click", e => {
      e.stopPropagation();
      navigator.clipboard.writeText(ep.url).then(() => {
        cpyBtn.textContent = "✓";
        setTimeout(() => { cpyBtn.textContent = "Copy"; }, 1200);
      });
    });
    const intrBtn = txt("button", "btn btn-xs btn-ghost", "→ Intr");
    const openBtn = txt("button", "btn btn-xs btn-ghost", "↗"); openBtn.title = "Open in new tab";
    repBtn.addEventListener("click", e => { e.stopPropagation(); sendToRepeater(ep); });
    intrBtn.addEventListener("click", e => { e.stopPropagation(); intrSendToIntruder(ep); });
    openBtn.addEventListener("click", e => { e.stopPropagation(); chrome.tabs.create({ url: ep.url }); });

    ap(acts, cpyBtn, repBtn, intrBtn, openBtn);
    row.appendChild(acts);
    row.addEventListener("click", () => openEpDetail(ep));
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
      const extract = (obj, depth) => {
        if (depth > 5) return;
        for (const v of Object.values(obj)) {
          if (typeof v === "string" && v.length >= 3) vals.add(v);
          else if (typeof v === "object" && v) extract(v, depth + 1);
        }
      };
      extract(j, 0);
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

// ── Reusable search within <pre> elements ────────────────────────────────────
function createPaneSearch(container, inputEl, countEl) {
  const state = { matches: [], idx: -1 };

  // Auto-inject ▲▼ nav buttons after the count element
  const prevBtn = document.createElement("button");
  prevBtn.className = "btn btn-xs btn-ghost search-nav-btn";
  prevBtn.textContent = "\u25B2";
  prevBtn.title = "Previous match (Shift+Enter)";
  const nextBtn = document.createElement("button");
  nextBtn.className = "btn btn-xs btn-ghost search-nav-btn";
  nextBtn.textContent = "\u25BC";
  nextBtn.title = "Next match (Enter)";
  countEl.after(nextBtn);
  countEl.after(prevBtn);

  function clearHighlights() {
    container.querySelectorAll(".raw-pre").forEach(pre => {
      if (pre._origText !== undefined) { pre.textContent = pre._origText; delete pre._origText; }
    });
    state.matches = []; state.idx = -1;
    reflectReapply.get(container)?.(); // put the reflection layer back underneath
  }

  function doSearch(query) {
    clearHighlights();
    if (!query || query.length < 2) { countEl.textContent = ""; return; }
    const q = query.toLowerCase();
    container.querySelectorAll(".raw-pre").forEach(pre => {
      const text = pre.textContent;
      if (!text.toLowerCase().includes(q)) return;
      pre._origText = text;
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
        state.matches.push(mark);
        lastIdx = pos + query.length;
      }
      if (lastIdx < text.length) frag.appendChild(document.createTextNode(text.slice(lastIdx)));
      pre.textContent = "";
      pre.appendChild(frag);
    });
    countEl.textContent = state.matches.length ? `${state.matches.length} found` : "0";
    if (state.matches.length) doNav(0);
  }

  function doNav(idx) {
    if (!state.matches.length) return;
    if (state.matches[state.idx]) state.matches[state.idx].className = "search-hl";
    state.idx = ((idx % state.matches.length) + state.matches.length) % state.matches.length;
    const m = state.matches[state.idx];
    m.className = "search-hl search-hl-current";
    m.scrollIntoView({ behavior: "smooth", block: "center" });
    countEl.textContent = `${state.idx + 1}/${state.matches.length}`;
  }

  inputEl.addEventListener("input", () => doSearch(inputEl.value));
  inputEl.addEventListener("keydown", e => {
    if (e.key === "Enter") { e.preventDefault(); doNav(state.idx + (e.shiftKey ? -1 : 1)); }
  });
  prevBtn.addEventListener("click", () => doNav(state.idx - 1));
  nextBtn.addEventListener("click", () => doNav(state.idx + 1));

  return { search: doSearch, nav: doNav, clear() { clearHighlights(); inputEl.value = ""; countEl.textContent = ""; } };
}

let histReqSearch, histRespSearch;

// ── Reflection highlighting ─────────────────────────────────────────────────
// Each distinct reflected value gets its own palette slot, so you can tell at a
// glance which request value landed where. Slot N ↔ CSS class .reflect-cN.
const REFLECT_HEX = ["#f85149", "#58a6ff", "#3fb950", "#e3b341",
                     "#bc8cff", "#39c5cf", "#ff7b9c", "#ff9f45"];
const REFLECT_MAX_SPANS = 5000; // guard against pathological responses

function computeReflections(entry) {
  // Longest first: a short value nested inside a longer one must not steal its
  // span (e.g. "admin" inside "administrator"). The overlap pass below relies
  // on this ordering for priority.
  const uniq = [...new Set(detectReflections(entry))]
    .filter(Boolean)
    .sort((a, b) => b.length - a.length);
  return uniq.map((value, i) => ({
    value,
    cls:   `reflect-c${i % REFLECT_HEX.length}`,
    color: REFLECT_HEX[i % REFLECT_HEX.length],
  }));
}

function reflectMarkPre(pre, reflections) {
  const text = pre._reflectOrig !== undefined ? pre._reflectOrig : pre.textContent;
  if (!text) return 0;

  const spans = [];
  for (const r of reflections) {
    let pos = 0;
    while ((pos = text.indexOf(r.value, pos)) !== -1) {
      spans.push({ start: pos, end: pos + r.value.length, r });
      pos += r.value.length;
      if (spans.length >= REFLECT_MAX_SPANS) break;
    }
    if (spans.length >= REFLECT_MAX_SPANS) break;
  }
  if (!spans.length) return 0;

  // spans arrive longest-value-first; keep that priority, drop anything overlapping
  const kept = [];
  for (const s of spans) {
    if (kept.some(k => s.start < k.end && k.start < s.end)) continue;
    kept.push(s);
  }
  kept.sort((a, b) => a.start - b.start);

  const frag = document.createDocumentFragment();
  let last = 0;
  for (const s of kept) {
    if (s.start > last) frag.appendChild(document.createTextNode(text.slice(last, s.start)));
    const mark = document.createElement("mark");
    mark.className = `reflect-hl ${s.r.cls}`;
    mark.textContent = text.slice(s.start, s.end);
    mark.title = `Reflected from request: ${s.r.value}`;
    frag.appendChild(mark);
    last = s.end;
  }
  if (last < text.length) frag.appendChild(document.createTextNode(text.slice(last)));

  pre._reflectOrig = text;
  pre.textContent = "";
  pre.appendChild(frag);
  return kept.length;
}

// container element → re-apply fn, so a search clearing its own highlights can
// put the reflection layer back underneath instead of wiping it.
const reflectReapply = new WeakMap();

function reflectClear(container) {
  container.querySelectorAll(".raw-pre").forEach(pre => {
    if (pre._reflectOrig !== undefined) {
      pre.textContent = pre._reflectOrig;
      delete pre._reflectOrig;
    }
  });
}

function reflectApply(container, reflections) {
  reflectClear(container);
  let n = 0;
  if (reflections.length) {
    container.querySelectorAll(".raw-pre").forEach(pre => { n += reflectMarkPre(pre, reflections); });
  }
  return n;
}

// Wires one checkbox + chip legend to a set of panes. getContainers() is a thunk
// because some panes (intruder detail) only exist once a row is opened.
function createReflectBar(toggleId, chipsId, getContainers) {
  const toggle = document.getElementById(toggleId);
  const chips  = document.getElementById(chipsId);
  let current = [];

  function paint() {
    const on = toggle.checked;
    for (const c of getContainers()) {
      if (!c) continue;
      if (on) reflectApply(c, current); else reflectClear(c);
      reflectReapply.set(c, on ? () => reflectApply(c, current) : null);
    }
    chips.classList.toggle("hidden", !on);
  }

  function update(entry) {
    current = entry ? computeReflections(entry) : [];
    chips.replaceChildren();
    if (!current.length) {
      const none = document.createElement("span");
      none.className = "reflect-bar-none";
      none.textContent = "no reflections";
      chips.appendChild(none);
    } else {
      for (const r of current) {
        const chip = document.createElement("span");
        chip.className = "reflect-chip";
        chip.title = r.value;
        const dot = document.createElement("span");
        dot.className = "reflect-chip-dot";
        dot.style.background = r.color;
        chip.appendChild(dot);
        chip.appendChild(document.createTextNode(
          r.value.length > 28 ? `${r.value.slice(0, 28)}…` : r.value));
        chips.appendChild(chip);
      }
    }
    paint();
  }

  toggle.addEventListener("change", paint);
  return { update, repaint: paint, count: () => current.length };
}

// Built in setup() once the DOM exists; call sites use ?. because repeater tab
// restore can fire during session load, before setup has run.
let histReflectBar = null, repReflectBar = null, intrReflectBar = null;


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

function lowerKeys(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj || {})) out[k.toLowerCase()] = v;
  return out;
}

// Where the Headers tab gets its data.
//
// state.docHeaders / state.headers are filled only by the debugger's
// Network.responseReceived. Since passive webRequest capture became the default
// that leaves this tab blank unless you press Attach — even though historyData
// is full of entries carrying respHeaders. So fall back to history: pick the
// most recent main-document response and use its headers.
function headerSources() {
  const stateDoc = state.docHeaders && Object.keys(state.docHeaders).length
    ? state.docHeaders : null;
  if (stateDoc) {
    return {
      docHdrs: stateDoc, docUrl: state.docUrl || "", docStatus: state.docStatus,
      merged: state.headers || {}, headerSrc: state.headerSrc || {}, from: "debugger",
    };
  }

  // Passive capture is cross-tab, so historyData can hold another tab's
  // navigation. This tab is the one being described. Entries with no tabId
  // (restored sessions) are kept rather than silently dropped.
  const mine = historyData.filter(e => e.tabId === undefined || e.tabId === TAB_ID);

  // "Document" is the CDP resource type, "main_frame" the webRequest one.
  // History is time-sorted, so the last match is the current page.
  const docs = mine.filter(e =>
    (e.resourceType === "Document" || e.resourceType === "main_frame") &&
    e.respHeaders && Object.keys(e.respHeaders).length);
  const doc = docs.length ? docs[docs.length - 1] : null;

  // All headers seen anywhere in this tab, newest wins, each tagged with its URL.
  const merged = {}, headerSrc = {};
  for (const e of mine) {
    for (const [k, v] of Object.entries(e.respHeaders || {})) {
      const lk = k.toLowerCase();
      merged[lk] = v;
      headerSrc[lk] = e.url || "";
    }
  }

  return {
    docHdrs:   doc ? lowerKeys(doc.respHeaders) : null,
    docUrl:    doc ? doc.url : "",
    docStatus: doc ? doc.status : null,
    merged, headerSrc, from: "history",
  };
}

function renderHeaders() {
  // Which header set is authoritative?
  //
  // The merged map is every response seen in the tab, so a third-party iframe or
  // a CDN asset can overwrite the values the top-level page actually sent.
  // Judging CSP / HSTS / X-Frame-Options off that is misleading — those headers
  // only mean anything for the main document. So the analysis runs on the
  // navigation response whenever we have one, and the UI says which URL it is
  // describing.
  const src       = headerSources();
  const docHdrs   = src.docHdrs;
  const merged    = src.merged;
  const usingDoc  = !!docHdrs && Object.keys(docHdrs).length > 0;
  const hdrs      = usingDoc ? docHdrs : merged;
  const keys      = Object.keys(hdrs);
  const empty     = document.getElementById("hdr-empty");
  const grid      = document.getElementById("hdr-sec-grid");
  const allList   = document.getElementById("hdr-all-list");

  // ── Reference bar ─────────────────────────────────────────────────────────
  const refUrl  = document.getElementById("hdr-ref-url");
  const refStat = document.getElementById("hdr-ref-status");
  const refWarn = document.getElementById("hdr-ref-warn");

  if (usingDoc) {
    refUrl.textContent  = src.docUrl || "(unknown URL)";
    refUrl.title        = src.docUrl || "";
    refStat.textContent = src.docStatus ? `HTTP ${src.docStatus}` : "";
    refWarn.classList.add("hidden");
  } else if (keys.length) {
    // Happens when the debugger attached after the page had already navigated,
    // so we never saw the top-level response.
    refUrl.textContent  = "no main-document response seen — reload the page to capture it";
    refUrl.title        = "";
    refStat.textContent = "";
    refWarn.textContent = "merged from all responses — values may come from sub-frames or third-party assets";
    refWarn.classList.remove("hidden");
  } else {
    refUrl.textContent  = "—";
    refUrl.title        = "";
    refStat.textContent = "";
    refWarn.classList.add("hidden");
  }

  // Nothing captured at all: don't render a wall of "Missing" tiles, which reads
  // as "this site ships no security headers" when the truth is "we saw nothing".
  grid.replaceChildren();
  allList.replaceChildren();
  if (!keys.length) {
    empty.classList.remove("hidden");
    return;
  }
  empty.classList.add("hidden");

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

  // ── All headers ───────────────────────────────────────────────────────────
  // Default: just the main document's headers, so what you read is what the page
  // sent. Toggle on to fold in every other response, each labelled with the URL
  // it came from — a value from another origin is flagged, since that is exactly
  // the case that used to silently corrupt this view.
  const showAll = document.getElementById("hdr-show-all").checked;
  let docHost = "";
  try { docHost = new URL(src.docUrl).host; } catch {}

  const rows = new Map(); // name → { value, from }
  for (const k of Object.keys(hdrs)) rows.set(k, { value: hdrs[k], from: src.docUrl || "" });
  if (showAll) {
    for (const k of Object.keys(merged)) {
      if (rows.has(k)) continue;
      rows.set(k, { value: merged[k], from: src.headerSrc?.[k] || "" });
    }
  }

  for (const k of [...rows.keys()].sort()) {
    const { value, from } = rows.get(k);
    const row = el("div", "hdr-row");
    ap(row, txt("span", "hdr-key", k), txt("span", "hdr-val", value));
    if (showAll && from) {
      let srcHost = "";
      try { srcHost = new URL(from).host; } catch {}
      const foreign = docHost && srcHost && srcHost !== docHost;
      const s = txt("span", `hdr-src${foreign ? " hdr-src-foreign" : ""}`,
        `${foreign ? "⚠ " : ""}from ${from}`);
      s.title = from;
      row.appendChild(s);
    }
    allList.appendChild(row);
  }
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

    const smCls = esc(entry.method.toLowerCase().replace(/[^a-z]/g, ""));
    tr.innerHTML = `
      <td><span class="method-pill m-${smCls}">${esc(entry.method)}</span></td>
      <td title="${esc(entry.url)}" class="tgt-url-cell">${esc(entry.url)}</td>
      <td class="${statusCls}">${esc(String(entry.status ?? "…"))}</td>
      <td class="hist-td-len">${esc(String(len))}</td>
      <td class="hist-td-mime">${esc(shortMime(entry.mimeType))}</td>
    `;

    // Actions cell
    const actTd = document.createElement("td");
    actTd.className = "tgt-act-cell";
    const repBtn = txt("button", "btn btn-xs btn-ghost", "→ Rep");
    const intrBtn = txt("button", "btn btn-xs btn-ghost", "→ Intr");
    const openBtn = txt("button", "btn btn-xs btn-ghost", "↗");
    openBtn.title = "Open in new tab";
    repBtn.addEventListener("click", e => { e.stopPropagation(); sendToRepeater({ method: entry.method, url: entry.url, headers: entry.headers || {}, body: entry.body || "" }); });
    intrBtn.addEventListener("click", e => { e.stopPropagation(); intrSendToIntruder({ method: entry.method, url: entry.url, headers: entry.headers || {}, body: entry.body || "" }); });
    openBtn.addEventListener("click", e => { e.stopPropagation(); chrome.tabs.create({ url: entry.url }); });
    ap(actTd, repBtn, intrBtn, openBtn);
    tr.appendChild(actTd);
    tr.className = "tgt-clickable";
    tr._entry = entry;
    if (tgtDetailEntry && tgtDetailEntry === entry) tr.classList.add("hist-selected");
    tr.addEventListener("click", () => openTgtDetail(entry));
    tbody.appendChild(tr);
  });
}

// ── Target/Endpoint detail pane ──────────────────────────────────────────────
let tgtDetailEntry = null;
let epDetailEntry  = null;

function openTgtDetail(entry) {
  tgtDetailEntry = entry;
  const detail = document.getElementById("tgt-detail");
  document.getElementById("tgt-detail-title").textContent = `${entry.status || "…"} ${entry.method} ${entry.url}`;

  document.getElementById("tgt-req-pre").textContent  = rawRequestText(entry);
  document.getElementById("tgt-resp-pre").textContent = rawResponseText(entry);

  detail.classList.remove("hidden");
  detail.classList.add("visible");
  document.getElementById("tgt-detail-resizer").classList.add("visible");

  // Highlight selected row
  document.querySelectorAll("#tgt-table-body tr").forEach(r => r.classList.remove("hist-selected"));
  document.querySelectorAll("#tgt-table-body tr").forEach(r => {
    if (r._entry === entry) r.classList.add("hist-selected");
  });
}

function closeTgtDetail() {
  tgtDetailEntry = null;
  const detail = document.getElementById("tgt-detail");
  detail.classList.add("hidden");
  detail.classList.remove("visible");
  document.getElementById("tgt-detail-resizer").classList.remove("visible");
  document.querySelectorAll("#tgt-table-body tr").forEach(r => r.classList.remove("hist-selected"));
}

function openEpDetail(entry) {
  epDetailEntry = entry;
  // Find matching history entry for full data
  const histEntry = historyData.find(h => h.url === entry.url && h.method === (entry.method || "GET")) || entry;

  const detail = document.getElementById("ep-detail");
  document.getElementById("ep-detail-title").textContent = `${histEntry.status || "…"} ${histEntry.method || entry.method || "GET"} ${entry.url}`;

  document.getElementById("ep-req-pre").textContent  = rawRequestText(histEntry);
  document.getElementById("ep-resp-pre").textContent = rawResponseText(histEntry);

  detail.classList.remove("hidden");
  detail.classList.add("visible");
  document.getElementById("ep-resizer").classList.add("visible");
}

function closeEpDetail() {
  epDetailEntry = null;
  const detail = document.getElementById("ep-detail");
  detail.classList.add("hidden");
  detail.classList.remove("visible");
  document.getElementById("ep-resizer").classList.remove("visible");
}

// ═══════════════════════════ INTRUDER ═════════════════════════════════════════

let intrDetailEntry = null;
let intrReflectOnly = false;
let intrReqSearch, intrRespSearch;

// The intruder builds requests from a raw template rather than history entries,
// so reshape a result into what detectReflections() expects.
function intrReflectEntry(e) {
  const headers = {};
  (e.reqHeaders || "").split("\n").forEach(line => {
    const i = line.indexOf(":");
    if (i > 0) headers[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  });
  return {
    url:         e.reqUrl || "",
    headers,
    body:        e.reqBody || "",
    respBody:    e.body || "",
    respHeaders: e.respHeaders || {},
  };
}

function intrOpenDetail(entry) {
  intrDetailEntry = entry;
  const detail = document.getElementById("intr-detail");

  document.getElementById("intr-detail-title").textContent =
    `${entry.status} ${entry.reqMethod || "GET"} — ${entry.payload}`;

  // The intruder keeps its request as raw header text, so build the view from
  // that rather than from a header map.
  let host = "", path = entry.reqUrl || "/";
  try { const u = new URL(entry.reqUrl); host = u.host; path = u.pathname + u.search; } catch {}
  let req = `${entry.reqMethod || "GET"} ${path} HTTP/1.1\n`;
  if (host && !/^host\s*:/im.test(entry.reqHeaders || "")) req += `Host: ${host}\n`;
  req += entry.reqHeaders || "";
  if (entry.reqBody) req += `\n\n${entry.reqBody}`;
  document.getElementById("intr-req-pre").textContent = req;

  document.getElementById("intr-resp-pre").textContent = rawResponseText({
    status: entry.status, statusText: entry.statusText,
    respHeaders: entry.respHeaders, respBody: entry.body,
  });

  detail.classList.remove("hidden");
  document.querySelectorAll("#intr-results tr").forEach(r =>
    r.classList.toggle("intr-selected", r._intrEntry === entry));

  if (intrReqSearch)  intrReqSearch.clear();
  if (intrRespSearch) intrRespSearch.clear();
  intrReflectBar?.update(intrReflectEntry(entry));
}

function intrCloseDetail() {
  intrDetailEntry = null;
  document.getElementById("intr-detail").classList.add("hidden");
  document.querySelectorAll("#intr-results tr").forEach(r => r.classList.remove("intr-selected"));
}

function intrRenderResults() {
  const tbody = document.getElementById("intr-results");
  tbody.replaceChildren();
  let filtered = intrResults;
  if (intrReflectOnly) filtered = filtered.filter(e => e.reflected);
  for (const [field, allowed] of Object.entries(intrColFilters)) {
    if (allowed) filtered = filtered.filter(e => allowed.has(String(e[field] ?? "")));
  }
  const sorted = [...filtered].sort((a, b) => {
    let va, vb;
    switch (intrSortKey) {
      case "id":      va = a.id; vb = b.id; break;
      case "payload": va = a.payload; vb = b.payload; break;
      case "status":  va = a.status || 0; vb = b.status || 0; break;
      case "length":  va = a.length || 0; vb = b.length || 0; break;
      case "elapsed": va = a.elapsed || 0; vb = b.elapsed || 0; break;
      default:        va = a.id; vb = b.id;
    }
    if (typeof va === "string") { va = va.toLowerCase(); vb = vb.toLowerCase(); }
    if (va < vb) return intrSortAsc ? -1 : 1;
    if (va > vb) return intrSortAsc ? 1 : -1;
    return 0;
  });
  // Update sort indicators
  document.querySelectorAll("#intr-table .hist-th-sortable").forEach(th => {
    const key = th.dataset.intrsort;
    const arrow = key === intrSortKey ? (intrSortAsc ? " \u25B4" : " \u25BE") : "";
    let sp = th.querySelector(".sort-label");
    if (!sp) { sp = document.createElement("span"); sp.className = "sort-label"; const raw = th.firstChild?.nodeType === 3 ? th.firstChild.textContent.trim() : ""; if (th.firstChild?.nodeType === 3) th.firstChild.remove(); th.insertBefore(sp, th.firstChild); sp.textContent = raw; }
    sp.textContent = sp.textContent.replace(/ [\u25B4\u25BE]$/, "") + arrow;
  });
  for (const entry of sorted) {
    const tr = document.createElement("tr");
    const statusCls = entry.status === "err" ? "hist-td-status-err"
      : entry.status < 300 ? "hist-td-status-ok"
      : entry.status < 400 ? "hist-td-status-rdir" : "hist-td-status-err";
    const lenStr = entry.length > 1024 ? `${(entry.length/1024).toFixed(1)}k` : entry.length;
    const preview = (entry.body || "").slice(0, 120).replace(/\n/g, " ");
    tr.innerHTML = `
      <td class="hist-td-num">${Number(entry.id) || 0}</td>
      <td title="${esc(entry.payload)}">${esc(entry.payload)}</td>
      <td class="${statusCls}">${esc(String(entry.status))}</td>
      <td class="hist-td-len">${esc(String(lenStr))}</td>
      <td class="hist-td-elapsed">${Number(entry.elapsed) || 0}</td>
      <td class="hist-td-mime" title="${esc(preview)}">${esc(preview)}</td>
    `;
    if (entry.reflected) {
      const dot = document.createElement("span");
      dot.className = "hist-reflect-dot";
      dot.title = `${entry.reflected} reflection${entry.reflected > 1 ? "s" : ""} in response`;
      tr.querySelector("td:nth-child(2)").appendChild(dot);
    }
    tr._intrEntry = entry;
    if (entry === intrDetailEntry) tr.classList.add("intr-selected");
    tr.addEventListener("click", () => intrOpenDetail(entry));
    tbody.appendChild(tr);
  }
}

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
  intrColFilters = {};
  document.querySelectorAll("#intr-table .colfilter-drop").forEach(d => d.remove());
  document.querySelectorAll("#intr-table .colfilter-ico").forEach(i => i.classList.remove("active"));
  intrRunning = true;
  intrAbort = new AbortController();
  const tbody = document.getElementById("intr-results");
  tbody.replaceChildren();
  intrCloseDetail(); // previous run's rows are gone

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
        // kept so the detail pane can rebuild the exact request that was sent
        reqUrl:      parsed.url || url,
        reqMethod:   parsed.method || method,
        reqHeaders:  rawHdrs,
        reqBody:     parsed.body || "",
        respHeaders: res?.headers || {},
      };
      // Computed once here rather than per render — the row indicator and the
      // Reflections filter both read it.
      entry.reflected = detectReflections(intrReflectEntry(entry)).length;
      intrResults.push(entry);

      // Add row to table
      const tr = document.createElement("tr");
      const statusCls = !res?.ok ? "hist-td-status-err"
        : res.status < 300 ? "hist-td-status-ok"
        : res.status < 400 ? "hist-td-status-rdir" : "hist-td-status-err";
      const lenStr = entry.length > 1024 ? `${(entry.length/1024).toFixed(1)}k` : entry.length;
      const preview = (entry.body || "").slice(0, 120).replace(/\n/g, " ");
      tr.innerHTML = `
        <td class="hist-td-num">${Number(entry.id) || 0}</td>
        <td title="${esc(entry.payload)}">${esc(entry.payload)}</td>
        <td class="${statusCls}">${esc(String(entry.status))}</td>
        <td class="hist-td-len">${esc(String(lenStr))}</td>
        <td class="hist-td-elapsed">${Number(entry.elapsed) || 0}</td>
        <td class="hist-td-mime" title="${esc(preview)}">${esc(preview)}</td>
      `;
      if (entry.reflected) {
        const dot = document.createElement("span");
        dot.className = "hist-reflect-dot";
        dot.title = `${entry.reflected} reflection${entry.reflected > 1 ? "s" : ""} in response`;
        tr.querySelector("td:nth-child(2)").appendChild(dot);
      }
      tr._intrEntry = entry;
      tr.addEventListener("click", () => intrOpenDetail(entry));
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
  ensureMethod(mSel, method);
  mSel.value = method;
  const intrUrlInp = document.getElementById("intr-url");
  setFieldValue(intrUrlInp, url);
  autoSizeUrlInput(intrUrlInp);

  // Build raw request template
  let raw = "";
  if (rawHdrs) raw += rawHdrs;
  if (body) raw += "\n\n" + body;
  setFieldValue(document.getElementById("intr-request"), raw); // keeps Ctrl+Z working
  intrCountPositions();

  // Flash the Intruder badge rather than switching tabs — same as sendToRepeater.
  // Jumping tabs mid-triage loses your place in whatever list you were working.
  const bdg = document.getElementById("bdg-intruder");
  bdg.textContent = "+1";
  bdg.className = "bdg has-data";
  clearTimeout(bdg._timer);
  bdg._timer = setTimeout(() => { bdg.className = "bdg hidden"; }, 3000);
}

// Strip § position markers — the repeater has no concept of them
function intrStripPositions(raw) { return (raw || "").replace(/§/g, ""); }

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

function probeIsControllable(m) { return m === "full" || m === "partial"; }

function probeRenderSources(sources) {
  const tbody = document.getElementById("probe-src-tbody");
  const empty = document.getElementById("probe-src-empty");
  tbody.replaceChildren();
  const ctrlOnly = document.getElementById("probe-ctrl-only")?.checked;
  let filtered = sources || [];
  if (ctrlOnly) filtered = filtered.filter(s => probeIsControllable(s.manipulable));
  setBadge("bdg-p-src", filtered.length);
  if (!filtered.length) { empty.classList.remove("hidden"); return; }
  empty.classList.add("hidden");
  const sorted = [...filtered].sort((a, b) => ({ full: 0, partial: 1 }[a.manipulable] ?? 2) - ({ full: 0, partial: 1 }[b.manipulable] ?? 2));
  for (const s of sorted) {
    const tr = document.createElement("tr");
    tr.className = "tgt-clickable";
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
    tr.className = "tgt-clickable";
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
  const ctrlOnly = document.getElementById("probe-ctrl-only")?.checked;
  let filtered = flows || [];
  if (ctrlOnly) filtered = filtered.filter(f => probeIsControllable(f.srcManip));
  setBadge("bdg-p-flw", filtered.length);
  if (!filtered.length) { empty.classList.remove("hidden"); return; }
  empty.classList.add("hidden");
  const sorted = [...filtered].sort((a, b) => ({ likely: 0, possible: 1 }[a.expl] ?? 2) - ({ likely: 0, possible: 1 }[b.expl] ?? 2));
  for (const f of sorted) {
    const tr = document.createElement("tr");
    tr.className = "tgt-clickable";
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
        const ntitle = el("div", "probe-detail-section-title probe-color-red"); ntitle.textContent = "Nearby Sinks (within 10 lines)";
        nsec.appendChild(ntitle);
        for (const s of nearby) {
          const d = Math.abs(s.line - item.line);
          const row = el("div", "probe-nearby-row");
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
    srcTitle.classList.add("probe-color-accent");
    srcSec.appendChild(srcTitle);
    srcSec.appendChild(probeDetailKV([
      ["Line", item.srcLine], ["Controllable", probeManipIcon(item.srcManip) + " " + item.srcManip, probeManipCls(item.srcManip)],
      ["Why", item.srcWhy],
    ]));
    body.appendChild(srcSec);
    const snkSec = el("div", "probe-detail-section");
    const snkTitle = txt("div", "probe-detail-section-title", "Sink \u2192 [" + item.snkId + "] " + item.snkMatch);
    snkTitle.classList.add("probe-color-red");
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
      case "html-dec":    { const dp = new DOMParser(); const d = dp.parseFromString(`<!DOCTYPE html><body>${input}`, "text/html"); return d.body.textContent || ""; }
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

// ═══════════════════════════ CONTAINERS ═══════════════════════════════════════

const CNT_COLORS = {
  blue:   { bg: "#4285f4", label: "Blue" },
  red:    { bg: "#ea4335", label: "Red" },
  green:  { bg: "#34a853", label: "Green" },
  yellow: { bg: "#fbbc04", label: "Yellow" },
  purple: { bg: "#a142f4", label: "Purple" },
  pink:   { bg: "#f538a0", label: "Pink" },
  cyan:   { bg: "#24c1e0", label: "Cyan" },
  orange: { bg: "#fa903e", label: "Orange" },
  grey:   { bg: "#9aa0a6", label: "Grey" },
};

let containers = []; // { id, name, color, startUrl }
let cntNextId = 1;
let cntEditId = null; // null = creating, number = editing
let cntExtPath = ""; // path to void-extension on disk

function loadContainers() {
  return new Promise(r => chrome.storage.local.get("voidContainers", res => {
    if (res.voidContainers) {
      containers = res.voidContainers.list || [];
      cntNextId = res.voidContainers.nextId || containers.length + 1;
      cntExtPath = res.voidContainers.extPath || "";
    }
    r();
  }));
}

function saveContainers() {
  chrome.storage.local.set({ voidContainers: { list: containers, nextId: cntNextId, extPath: cntExtPath } });
}

function renderContainers() {
  const list = document.getElementById("cnt-list");
  const empty = document.getElementById("cnt-empty");
  list.replaceChildren();

  if (!containers.length) { empty.classList.remove("hidden"); return; }
  empty.classList.add("hidden");

  containers.forEach(cnt => {
    const card = el("div", "cnt-card");
    card.style.borderLeftColor = CNT_COLORS[cnt.color]?.bg || "#888";

    const icon = el("div", "cnt-card-icon");
    icon.style.background = CNT_COLORS[cnt.color]?.bg || "#888";
    icon.textContent = (cnt.name || "?").slice(0, 2).toUpperCase();

    const info = el("div", "cnt-card-info");
    const name = el("div", "cnt-card-name");
    name.textContent = cnt.name;
    const meta = el("div", "cnt-card-meta");
    meta.textContent = cnt.startUrl || "no URL set";
    info.appendChild(name);
    info.appendChild(meta);

    const actions = el("div", "cnt-card-actions");

    const launchBtn = txt("button", "btn btn-sm btn-accent", "Launch");
    launchBtn.title = "Open isolated Chrome instance";
    launchBtn.addEventListener("click", () => cntLaunch(cnt));

    const copyWinBtn = txt("button", "btn btn-xs btn-ghost", "Win");
    copyWinBtn.title = "Copy PowerShell launch command";
    copyWinBtn.addEventListener("click", () => {
      navigator.clipboard.writeText(cntBuildCmd(cnt, "win")).then(() => {
        copyWinBtn.textContent = "Copied!";
        setTimeout(() => { copyWinBtn.textContent = "Win"; }, 1500);
      });
    });
    const copyLinBtn = txt("button", "btn btn-xs btn-ghost", "Linux");
    copyLinBtn.title = "Copy Bash launch command";
    copyLinBtn.addEventListener("click", () => {
      navigator.clipboard.writeText(cntBuildCmd(cnt, "linux")).then(() => {
        copyLinBtn.textContent = "Copied!";
        setTimeout(() => { copyLinBtn.textContent = "Linux"; }, 1500);
      });
    });

    const editBtn = txt("button", "btn btn-xs btn-ghost", "Edit");
    editBtn.addEventListener("click", () => cntShowForm(cnt));

    const delBtn = txt("button", "btn btn-xs btn-danger", "Del");
    delBtn.addEventListener("click", () => {
      containers = containers.filter(c => c.id !== cnt.id);
      saveContainers();
      renderContainers();
    });

    ap(actions, launchBtn, copyWinBtn, copyLinBtn, editBtn, delBtn);
    ap(card, icon, info, actions);
    list.appendChild(card);
  });
}

// Chrome autogenerated theme colors (R,G,B as 0-255)
const CNT_THEME_RGB = {
  blue:   "30,80,180",
  red:    "180,30,30",
  green:  "25,120,50",
  yellow: "180,140,0",
  purple: "100,40,180",
  pink:   "180,40,120",
  cyan:   "0,140,170",
  orange: "200,100,20",
  grey:   "80,85,90",
};

function cntDetectOS() {
  const ua = navigator.userAgent;
  if (/Windows/i.test(ua)) return "win";
  if (/Mac/i.test(ua)) return "mac";
  return "linux";
}

function cntBuildCmd(cnt, os) {
  const safeName = (cnt.name || "container").replace(/[^a-zA-Z0-9_-]/g, "_");
  const url = cnt.startUrl || "about:blank";
  const rgb = CNT_THEME_RGB[cnt.color] || CNT_THEME_RGB.blue;
  const extPath = cntExtPath || "";
  if (!os) os = cntDetectOS();

  if (os === "win") {
    // PowerShell command for Windows
    // Use $dataDir variable so paths expand correctly (single quotes don't expand $env: in PS)
    const BT = "`"; // PowerShell escape char (backtick)
    const Q = BT + '"'; // escaped double quote inside PS double-quoted string
    const lines = [];
    lines.push('$dataDir = "$env:USERPROFILE\\.void-containers\\' + safeName + '"');
    lines.push('New-Item -ItemType Directory -Force -Path "$dataDir\\Default" | Out-Null');
    lines.push('if (-not (Test-Path "$dataDir\\Default\\Preferences")) { \'{"extensions":{"ui":{"developer_mode":true}}}\' | Out-File -Encoding UTF8 "$dataDir\\Default\\Preferences" }');
    lines.push('"' + safeName + '" | Out-File -Encoding UTF8 "$dataDir\\_void_container_name"');

    // Find chrome.exe (prefer Chromium — no enterprise policy restrictions)
    lines.push('$chrome = $null');
    lines.push('@("$env:USERPROFILE\\Downloads\\chrome-win\\chrome-win\\chrome.exe","$env:USERPROFILE\\Downloads\\chromium\\chrome.exe","$env:LOCALAPPDATA\\Chromium\\Application\\chrome.exe","$env:ProgramFiles\\Google\\Chrome\\Application\\chrome.exe","${env:ProgramFiles(x86)}\\Google\\Chrome\\Application\\chrome.exe","$env:LOCALAPPDATA\\Google\\Chrome\\Application\\chrome.exe") | ForEach-Object { if (Test-Path $_) { $chrome = $_ } }');
    lines.push('if (-not $chrome) { Write-Host "Chrome/Chromium not found"; exit 1 }');

    let extFlag = "";
    if (extPath) {
      extFlag = " --disable-extensions-except=" + Q + extPath + Q + " --load-extension=" + Q + extPath + Q;
    }
    // Use double quotes so $dataDir expands; backtick-quote inner quotes for Chrome args
    const args = "--user-data-dir=" + Q + "$dataDir" + Q +
      " --no-first-run --no-default-browser-check --new-window" +
      " --install-autogenerated-theme=" + Q + rgb + Q +
      extFlag + " " + Q + url + Q;
    lines.push('Start-Process $chrome -ArgumentList "' + args + '"');

    return lines.join("; ");
  }

  // Linux / macOS
  const dataDir = `$HOME/.void-containers/${safeName}`;
  const prefsFile = `${dataDir}/Default/Preferences`;
  const chromeCmd = os === "mac" ? '"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"' : "google-chrome";
  const lines = [`mkdir -p "${dataDir}/Default"`];

  if (extPath) {
    lines.push(`VOID_EXT="${extPath}"`);
  } else {
    lines.push(`VOID_EXT=""; for d in "$HOME/void-extension" "$HOME/projects/void-extension" "/opt/void-extension"; do [ -f "$d/manifest.json" ] && VOID_EXT="$d" && break; done`);
  }

  lines.push(`[ -f "${prefsFile}" ] || echo '{"extensions":{"ui":{"developer_mode":true}}}' > "${prefsFile}"`);
  lines.push(`echo '${safeName}' > "${dataDir}/_void_container_name"`);
  lines.push(`${chromeCmd} --user-data-dir="${dataDir}" --no-first-run --no-default-browser-check --install-autogenerated-theme="${rgb}" \${VOID_EXT:+--disable-extensions-except="$VOID_EXT" --load-extension="$VOID_EXT"} "${url}" &`);

  return lines.join(" && ");
}

async function cntLaunch(cnt) {
  if (!cntExtPath) {
    const st = document.querySelector(".cnt-info");
    if (st) st.textContent = "Set the Extension path first! The container needs it to load Void Extension.";
    document.getElementById("cnt-ext-path").focus();
    return;
  }
  const os = cntDetectOS();
  const cmd = cntBuildCmd(cnt, os);
  navigator.clipboard.writeText(cmd);

  const st = document.querySelector(".cnt-info");
  const shell = os === "win" ? "PowerShell" : "terminal";
  if (st) {
    st.textContent = `Command copied! Paste in ${shell} to launch "${cnt.name}"`;
    setTimeout(() => { st.textContent = "Each container launches an isolated Chrome with its own cookies. Set the extension path once below."; }, 4000);
  }
}

function cntShowForm(cnt) {
  cntEditId = cnt ? cnt.id : null;
  const form = document.getElementById("cnt-form");
  document.getElementById("cnt-name").value = cnt ? cnt.name : "";
  document.getElementById("cnt-start-url").value = cnt ? (cnt.startUrl || "") : "";
  document.getElementById("cnt-form-save").textContent = cnt ? "Save" : "Create";

  // Set color
  const color = cnt ? cnt.color : "blue";
  document.querySelectorAll("#cnt-colors .cnt-color-btn").forEach(b => {
    b.classList.toggle("active", b.dataset.color === color);
  });

  form.classList.remove("hidden");
}

function cntHideForm() {
  document.getElementById("cnt-form").classList.add("hidden");
  cntEditId = null;
}

function cntSaveForm() {
  const name = document.getElementById("cnt-name").value.trim();
  if (!name) return;
  const color = document.querySelector("#cnt-colors .cnt-color-btn.active")?.dataset.color || "blue";
  const startUrl = document.getElementById("cnt-start-url").value.trim();

  if (cntEditId !== null) {
    const cnt = containers.find(c => c.id === cntEditId);
    if (cnt) { cnt.name = name; cnt.color = color; cnt.startUrl = startUrl; }
  } else {
    containers.push({ id: cntNextId++, name, color, startUrl, cookies: [], tabs: [] });
  }

  saveContainers();
  renderContainers();
  cntHideForm();
}

// ═══════════════════════════ SENSITIVE DISCOVERER ═════════════════════════════

let sensFindings = [];
let sensFilterCat = "";
let sensFilterSev = "";
let sensFilterText = "";
let sensScopeOnly = false;
let sensCustomRules = []; // { desc, regex, severity, section, isRegex }
let sensSortKey = "id";
let sensSortAsc = true;
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
// Column filters: { cat: Set|null, desc: Set|null, section: Set|null }
let sensColFilters = {};

// ── Generic column filter dropdown system ────────────────────────────────────
function colFilterInit(tableId, items, getField, filterState, onFilter) {
  document.querySelectorAll(`#${tableId} .colfilter-th[data-colfilter]`).forEach(th => {
    const field = th.dataset.colfilter;
    const ico = th.querySelector(".colfilter-ico");

    th.addEventListener("click", e => {
      if (!e.target.closest(".colfilter-ico")) return;
      e.stopPropagation();
      document.querySelectorAll(".colfilter-drop.open").forEach(d => d.classList.remove("open"));

      let drop = th.querySelector(".colfilter-drop");
      if (drop) { drop.remove(); } // rebuild with fresh values

      drop = document.createElement("div");
      drop.className = "colfilter-drop open";

      const actions = document.createElement("div");
      actions.className = "colfilter-actions";
      const allBtn = document.createElement("button");
      allBtn.className = "btn btn-xs btn-ghost"; allBtn.textContent = "All";
      const noneBtn = document.createElement("button");
      noneBtn.className = "btn btn-xs btn-ghost"; noneBtn.textContent = "None";
      const invertBtn = document.createElement("button");
      invertBtn.className = "btn btn-xs btn-ghost"; invertBtn.textContent = "Invert";
      actions.append(allBtn, noneBtn, invertBtn);
      drop.appendChild(actions);

      const values = [...new Set(items().map(f => String(getField(f, field) ?? "")))].filter(Boolean).sort();
      const activeSet = filterState[field];
      const checkboxes = [];

      for (const val of values) {
        const label = document.createElement("label");
        const cb = document.createElement("input");
        cb.type = "checkbox";
        cb.checked = !activeSet || activeSet.has(val);
        cb.dataset.val = val;
        const span = document.createElement("span");
        span.textContent = val.length > 35 ? val.slice(0, 32) + "\u2026" : val;
        span.title = val;
        label.append(cb, span);
        drop.appendChild(label);
        checkboxes.push(cb);
        cb.addEventListener("change", () => applyFilter());
      }

      function applyFilter() {
        const checked = checkboxes.filter(c => c.checked).map(c => c.dataset.val);
        if (checked.length === values.length) {
          delete filterState[field];
          ico.classList.remove("active");
        } else {
          filterState[field] = new Set(checked);
          ico.classList.add("active");
        }
        onFilter();
      }

      allBtn.addEventListener("click", e => { e.stopPropagation(); checkboxes.forEach(c => c.checked = true); applyFilter(); });
      noneBtn.addEventListener("click", e => { e.stopPropagation(); checkboxes.forEach(c => c.checked = false); applyFilter(); });
      invertBtn.addEventListener("click", e => { e.stopPropagation(); checkboxes.forEach(c => c.checked = !c.checked); applyFilter(); });

      th.appendChild(drop);
      const closeHandler = ev => {
        if (!drop.contains(ev.target) && ev.target !== ico) {
          drop.classList.remove("open");
          document.removeEventListener("click", closeHandler);
        }
      };
      setTimeout(() => document.addEventListener("click", closeHandler), 0);
    });
  });
}

function sensScan() {
  sensFindings = [];
  sensColFilters = {};
  // Remove old filter dropdowns so they rebuild with new values
  document.querySelectorAll("#sens-table .colfilter-drop").forEach(d => d.remove());
  document.querySelectorAll("#sens-table .colfilter-ico").forEach(i => i.classList.remove("active"));
  const status = document.getElementById("sens-status");
  status.textContent = "Scanning…";

  const items = sensScopeOnly ? historyData.filter(e => tgtIsInScope(e.url)) : historyData;

  // Compile built-in regexes
  const rules = typeof SENSITIVE_RULES !== "undefined" ? SENSITIVE_RULES : [];
  const compiled = rules.filter(r => r.active !== false).map(r => {
    // r.flags lets a rule opt into "m" so a ^ anchor means "start of header line"
    // rather than "start of the whole joined header block"
    try { return { ...r, re: new RegExp(r.regex, r.flags || "gi"), refRe: r.refiner ? new RegExp(r.refiner, "gi") : null }; }
    catch { return null; }
  }).filter(Boolean);

  // Add custom rules
  for (const cr of sensCustomRules) {
    try {
      const pattern = cr.isRegex ? cr.regex : cr.regex.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const sections = cr.section === "all" ? ["req_url","req_headers","req_body","resp_headers","resp_body"] : [cr.section];
      compiled.push({ cat: "Custom", desc: cr.desc, severity: cr.severity, sections, re: new RegExp(pattern, "gi"), refRe: null });
    } catch {}
  }

  let id = 0;
  for (const entry of items) {
    const sections = {
      req_url: entry.url || "",
      req_headers: Object.entries(entry.headers || {}).map(([k,v]) => `${k}: ${v}`).join("\n"),
      req_body: entry.body || "",
      resp_headers: Object.entries(entry.respHeaders || {}).map(([k,v]) => `${k}: ${v}`).join("\n"),
      resp_body: entry.respBody || "",
    };

    for (const rule of compiled) {
      const targetSections = rule.sections || ["resp_body", "resp_headers"];
      for (const sec of targetSections) {
        const text = sections[sec];
        if (!text) continue;
        rule.re.lastIndex = 0;
        let m;
        while ((m = rule.re.exec(text)) !== null) {
          let matchStr = m[0];
          // Apply refiner regex if present
          if (rule.refRe) {
            rule.refRe.lastIndex = 0;
            const rm = rule.refRe.exec(matchStr);
            if (rm) matchStr = rm[0] + matchStr;
          }
          sensFindings.push({
            id: ++id,
            severity: rule.severity || "medium",
            cat: rule.cat,
            desc: rule.desc,
            match: matchStr.slice(0, 200),
            section: sec,
            url: entry.url,
            method: entry.method,
          });
          // Limit matches per rule per entry
          if (sensFindings.length > 10000) break;
        }
        if (sensFindings.length > 10000) break;
      }
      if (sensFindings.length > 10000) break;
    }
    if (sensFindings.length > 10000) break;
  }

  status.textContent = `Done — ${sensFindings.length} findings in ${items.length} requests`;
  setTimeout(() => { status.textContent = ""; }, 3000);

  sensRender();
  setBadge("bdg-sensitive", sensFindings.length);
}

function sensRender() {
  const tbody = document.getElementById("sens-tbody");
  const empty = document.getElementById("sens-empty");
  const stats = document.getElementById("sens-stats");
  tbody.replaceChildren();

  let items = sensFindings;
  if (sensFilterCat) items = items.filter(f => f.cat === sensFilterCat);
  if (sensFilterSev) items = items.filter(f => f.severity === sensFilterSev);
  if (sensFilterText) {
    const q = sensFilterText.toLowerCase();
    items = items.filter(f => f.desc.toLowerCase().includes(q) || f.match.toLowerCase().includes(q) || f.url.toLowerCase().includes(q));
  }
  // Column checkbox filters
  for (const [field, allowed] of Object.entries(sensColFilters)) {
    if (allowed) items = items.filter(f => allowed.has(f[field]));
  }

  // Stats
  const crit = sensFindings.filter(f => f.severity === "critical").length;
  const high = sensFindings.filter(f => f.severity === "high").length;
  const med  = sensFindings.filter(f => f.severity === "medium").length;
  const low  = sensFindings.filter(f => f.severity === "low").length;
  document.getElementById("sens-total").textContent = sensFindings.length;
  document.getElementById("sens-crit").textContent = crit;
  document.getElementById("sens-high").textContent = high;
  document.getElementById("sens-med").textContent = med;
  document.getElementById("sens-low").textContent = low;
  stats.classList.toggle("hidden", !sensFindings.length);

  // Sort
  items = [...items].sort((a, b) => {
    let va, vb;
    switch (sensSortKey) {
      case "id":       va = a.id; vb = b.id; break;
      case "severity": va = SEV_ORDER[a.severity] ?? 9; vb = SEV_ORDER[b.severity] ?? 9; break;
      case "cat":      va = a.cat; vb = b.cat; break;
      case "desc":     va = a.desc; vb = b.desc; break;
      case "match":    va = a.match; vb = b.match; break;
      case "section":  va = a.section; vb = b.section; break;
      case "url":      va = a.url; vb = b.url; break;
      default:         va = a.id; vb = b.id;
    }
    if (typeof va === "string") { va = va.toLowerCase(); vb = vb.toLowerCase(); }
    if (va < vb) return sensSortAsc ? -1 : 1;
    if (va > vb) return sensSortAsc ? 1 : -1;
    return 0;
  });

  // Update sort indicators
  document.querySelectorAll("#sens-table .hist-th-sortable").forEach(th => {
    const key = th.dataset.senssort;
    const arrow = key === sensSortKey ? (sensSortAsc ? " \u25B4" : " \u25BE") : "";
    let sp = th.querySelector(".sort-label");
    if (!sp) { sp = document.createElement("span"); sp.className = "sort-label"; const raw = th.firstChild?.nodeType === 3 ? th.firstChild.textContent.trim() : ""; if (th.firstChild?.nodeType === 3) th.firstChild.remove(); th.insertBefore(sp, th.firstChild); sp.textContent = raw; }
    sp.textContent = sp.textContent.replace(/ [\u25B4\u25BE]$/, "") + arrow;
  });

  if (!items.length) {
    empty.classList.remove("hidden");
    document.getElementById("sens-table").parentElement.classList.add("hidden");
    return;
  }
  empty.classList.add("hidden");
  document.getElementById("sens-table").parentElement.classList.remove("hidden");

  for (const f of items.slice(0, 2000)) {
    const tr = document.createElement("tr");
    tr.className = "tgt-clickable";
    const sevCls = `sens-sev-${esc(f.severity)}`;
    tr.innerHTML = `
      <td class="hist-td-num">${Number(f.id)}</td>
      <td class="${sevCls}">${esc(f.severity)}</td>
      <td>${esc(f.cat)}</td>
      <td>${esc(f.desc)}</td>
      <td title="${esc(f.match)}" class="hist-td-mime">${esc(f.match.slice(0, 80))}</td>
      <td class="hist-td-mime">${esc(f.section)}</td>
      <td title="${esc(f.url)}" class="hist-td-mime">${esc(f.url.slice(0, 60))}</td>
    `;
    tr._finding = f;
    if (sensDetailEntry?._finding === f) tr.classList.add("hist-selected");
    tr.addEventListener("click", () => sensOpenDetail(f));
    tbody.appendChild(tr);
  }
}

function sensLoadCustomRules() {
  chrome.storage.local.get("voidSensCustom", r => {
    sensCustomRules = r.voidSensCustom || [];
    sensRenderCustomRules();
  });
}

function sensSaveCustomRules() {
  chrome.storage.local.set({ voidSensCustom: sensCustomRules });
}

function sensRenderCustomRules() {
  const list = document.getElementById("sens-custom-list");
  list.replaceChildren();
  sensCustomRules.forEach((cr, i) => {
    const row = el("div", "sens-custom-rule");
    const label = el("span"); label.textContent = `[${cr.severity}] ${cr.desc}: ${cr.regex}`;
    label.title = `${cr.isRegex ? "Regex" : "Text"} | ${cr.section}`;
    const del = txt("button", "btn btn-xs btn-danger", "×");
    del.addEventListener("click", () => { sensCustomRules.splice(i, 1); sensSaveCustomRules(); sensRenderCustomRules(); });
    ap(row, label, del);
    list.appendChild(row);
  });
}

function sensAddCustomRule() {
  const desc = document.getElementById("sens-custom-desc").value.trim();
  const regex = document.getElementById("sens-custom-regex").value.trim();
  if (!regex) return;
  const severity = document.getElementById("sens-custom-sev").value;
  const section = document.getElementById("sens-custom-section").value;
  const isRegex = document.getElementById("sens-custom-isregex").checked;

  // Validate regex
  if (isRegex) { try { new RegExp(regex); } catch (e) { alert("Invalid regex: " + e.message); return; } }

  sensCustomRules.push({ desc: desc || regex.slice(0, 30), regex, severity, section, isRegex });
  sensSaveCustomRules();
  sensRenderCustomRules();
  document.getElementById("sens-custom-desc").value = "";
  document.getElementById("sens-custom-regex").value = "";
}

let sensDetailEntry = null;
let sensReqSearch = null, sensRespSearch = null;

function sensOpenDetail(finding) {
  // Find the original history entry for this finding
  const entry = historyData.find(e => e.url === finding.url && e.method === finding.method) || {
    method: finding.method || "GET", url: finding.url, host: "", path: "",
    headers: {}, body: "", status: null, respHeaders: {}, respBody: "",
  };
  try { const u = new URL(entry.url); if (!entry.host) entry.host = u.host; if (!entry.path) entry.path = u.pathname + u.search; } catch {}

  sensDetailEntry = { ...entry, _finding: finding };
  const detail = document.getElementById("sens-detail");
  document.getElementById("sens-detail-title").textContent =
    `[${finding.severity.toUpperCase()}] ${finding.desc} — ${finding.match.slice(0, 60)}`;

  document.getElementById("sens-req-pre").textContent  = rawRequestText(entry);
  document.getElementById("sens-resp-pre").textContent = rawResponseText(entry);

  detail.classList.remove("hidden");
  detail.classList.add("visible");
  document.getElementById("sens-resizer").classList.add("visible");

  // Highlight selected row
  document.querySelectorAll("#sens-tbody tr").forEach(r => r.classList.remove("hist-selected"));
  document.querySelectorAll("#sens-tbody tr").forEach(r => {
    if (r._finding === finding) r.classList.add("hist-selected");
  });

  // Auto-search: put the finding match in the correct search box and trigger
  const matchText = finding.match || "";
  const sec = finding.section || "";
  // Headers and body now share one pane per side, so only the side matters —
  // the search below scrolls to the match wherever it sits.
  const isReqSide = sec.startsWith("req_");

  // Trigger search with the match text in the correct pane
  setTimeout(() => {
    if (isReqSide && sensReqSearch) {
      document.getElementById("sens-req-search").value = matchText;
      sensReqSearch.search(matchText);
    } else if (!isReqSide && sensRespSearch) {
      document.getElementById("sens-resp-search").value = matchText;
      sensRespSearch.search(matchText);
    }
    // Clear the other side
    if (isReqSide && sensRespSearch) sensRespSearch.clear();
    else if (!isReqSide && sensReqSearch) sensReqSearch.clear();
  }, 50);
}

function sensCloseDetail() {
  sensDetailEntry = null;
  const detail = document.getElementById("sens-detail");
  detail.classList.add("hidden");
  detail.classList.remove("visible");
  document.getElementById("sens-resizer").classList.remove("visible");
  document.querySelectorAll("#sens-tbody tr").forEach(r => r.classList.remove("hist-selected"));
}

function sensExportCSV() {
  if (!sensFindings.length) return;
  const rows = [["#","Severity","Category","Description","Match","Section","URL"].join(",")];
  for (const f of sensFindings) {
    rows.push([f.id, f.severity, `"${f.cat}"`, `"${f.desc}"`, `"${f.match.replace(/"/g,'""')}"`, f.section, `"${f.url}"`].join(","));
  }
  const blob = new Blob([rows.join("\n")], { type: "text/csv" });
  const a = el("a");
  a.href = URL.createObjectURL(blob);
  a.download = `void-sensitive-${Date.now()}.csv`;
  a.click();
  URL.revokeObjectURL(a.href);
}

// ═══════════════════════════ SESSION SAVE / LOAD ═════════════════════════════

function buildSessionData() {
  // Capture current UI state
  saveRepTabState();
  intrPayloadSets[intrActiveSet] = document.getElementById("intr-payloads").value;

  return {
    version: 1,
    timestamp: new Date().toISOString(),
    // History
    history: historyData,
    // Repeater
    repeater: {
      tabs: repTabs.map(t => ({
        id: t.id, label: t.label, customLabel: t.customLabel || null,
        method: t.method, url: t.url, headers: t.headers, body: t.body,
        response: t.response, autoCookie: t.autoCookie,
        targetHost: t.targetHost, targetPort: t.targetPort, targetTls: t.targetTls,
        history: t.history, histIdx: t.histIdx,
      })),
      activeTab: repActiveTab,
      nextId: repNextId,
    },
    // Intruder
    intruder: {
      method:     document.getElementById("intr-method").value,
      url:        document.getElementById("intr-url").value,
      request:    document.getElementById("intr-request").value,
      attack:     document.getElementById("intr-attack").value,
      threads:    document.getElementById("intr-threads").value,
      delay:      document.getElementById("intr-delay").value,
      payloads:   intrPayloadSets,
      activeSet:  intrActiveSet,
      autocookie: document.getElementById("intr-autocookie").checked,
    },
    // Endpoints & technologies
    endpoints:    state.endpoints || [],
    technologies: state.technologies || [],
    headers:      state.headers || {},
    // Settings
    settings,
    // Target scope
    scopeInclude: document.getElementById("tgt-scope-include").value,
    scopeExclude: document.getElementById("tgt-scope-exclude").value,
    // Notes
    notes: notes,
  };
}

// ── Save to browser (chrome.storage.local) ──────────────────────────────────
async function saveSessionToBrowser() {
  const nameInp = document.getElementById("session-name");
  let name = nameInp.value.trim();
  if (!name) {
    let host = "session";
    try { host = new URL(repTabs.find(t => t.url)?.url || "").hostname || "session"; } catch {}
    name = `${host} — ${new Date().toISOString().slice(0,16).replace("T"," ")}`;
  }
  const data = buildSessionData();
  data.name = name;

  // Load existing list, append, save
  const stored = await new Promise(r => chrome.storage.local.get("voidSessions", r));
  const sessions = stored.voidSessions || {};
  const key = "s_" + Date.now();
  sessions[key] = data;
  await new Promise(r => chrome.storage.local.set({ voidSessions: sessions }, r));

  nameInp.value = "";
  refreshSessionList();
  sessionStatus(`Saved: ${name}`);
}

// ── Export to .json file ─────────────────────────────────────────────────────
function exportSession() {
  const data = buildSessionData();
  const blob = new Blob([JSON.stringify(data)], { type: "application/json" });
  const a = el("a");
  a.href = URL.createObjectURL(blob);
  let host = "session";
  try { host = new URL(repTabs.find(t => t.url)?.url || "").hostname || "session"; } catch {}
  a.download = `void-${host}-${new Date().toISOString().slice(0,10)}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
  sessionStatus("Exported");
}

// ── Delete saved session ─────────────────────────────────────────────────────
async function deleteSelectedSession() {
  const sel = document.getElementById("session-configs");
  const key = sel.value;
  if (!key) return;
  const stored = await new Promise(r => chrome.storage.local.get("voidSessions", r));
  const sessions = stored.voidSessions || {};
  delete sessions[key];
  await new Promise(r => chrome.storage.local.set({ voidSessions: sessions }, r));
  refreshSessionList();
  sessionStatus("Deleted");
}

// ── Refresh dropdown with saved sessions ─────────────────────────────────────
async function refreshSessionList() {
  const sel = document.getElementById("session-configs");
  sel.replaceChildren();
  const def = el("option"); def.value = ""; def.textContent = "Saved sessions…"; sel.appendChild(def);

  const stored = await new Promise(r => chrome.storage.local.get("voidSessions", r));
  const sessions = stored.voidSessions || {};
  const keys = Object.keys(sessions).sort().reverse(); // newest first
  for (const key of keys) {
    const s = sessions[key];
    const o = el("option");
    o.value = key;
    const histCount = (s.history || []).length;
    const repCount = s.repeater?.tabs?.length || 0;
    o.textContent = `${s.name || key} (${histCount} hist, ${repCount} rep)`;
    sel.appendChild(o);
  }
}

// ── Load session from saved or file ──────────────────────────────────────────
async function loadSelectedSession() {
  const sel = document.getElementById("session-configs");
  const key = sel.value;
  if (!key) return;
  const stored = await new Promise(r => chrome.storage.local.get("voidSessions", r));
  const data = (stored.voidSessions || {})[key];
  if (!data) { sessionStatus("Session not found"); return; }
  await applySessionData(data);
}

async function importSessionFile(file) {
  try {
    const text = await file.text();
    const data = JSON.parse(text);
    if (!data.version) throw new Error("Invalid session file");
    await applySessionData(data);
  } catch (e) {
    sessionStatus("Error: " + e.message);
  }
}

function sessionStatus(msg) {
  const st = document.getElementById("session-status");
  st.textContent = msg;
  setTimeout(() => { st.textContent = ""; }, 3000);
}

async function applySessionData(data) {
  // Restore history
  if (data.history) {
    historyData = data.history;
    await bg({ type: "RESTORE_HISTORY", history: data.history });
    renderHistory();
    setBadge("bdg-history", historyData.length);
  }

  // Restore repeater
  if (data.repeater && data.repeater.tabs && data.repeater.tabs.length) {
    repTabs = data.repeater.tabs.map(t => ({
      id: t.id, label: t.label || "1", customLabel: t.customLabel || null,
      method: t.method || "GET", url: t.url || "", headers: t.headers || "", body: t.body || "",
      response: t.response || null, autoCookie: !!t.autoCookie,
      targetHost: t.targetHost || "", targetPort: t.targetPort || "", targetTls: t.targetTls !== false,
      history: t.history || [], histIdx: t.histIdx ?? -1,
    }));
    repNextId = data.repeater.nextId || (Math.max(...repTabs.map(t => t.id)) + 1);
    repActiveTab = data.repeater.activeTab;
    if (!repTabs.find(t => t.id === repActiveTab)) repActiveTab = repTabs[0].id;
    renderRepTabs();
    loadRepTabFast(repTabs.find(t => t.id === repActiveTab));
  }

  // Restore intruder
  if (data.intruder) {
    const d = data.intruder;
    const mSel = document.getElementById("intr-method");
    ensureMethod(mSel, d.method);
    mSel.value = d.method || "GET";
    document.getElementById("intr-url").value = d.url || "";
    document.getElementById("intr-request").value = d.request || "";
    document.getElementById("intr-attack").value = d.attack || "sniper";
    document.getElementById("intr-threads").value = d.threads || "1";
    document.getElementById("intr-delay").value = d.delay || "0";
    document.getElementById("intr-autocookie").checked = !!d.autocookie;
    intrPayloadSets = d.payloads || [""];
    intrActiveSet = d.activeSet || 0;
    document.getElementById("intr-payloads").value = intrPayloadSets[intrActiveSet] || "";
    intrCountPositions();
  }

  // Restore endpoints/technologies
  if (data.endpoints) {
    state.endpoints = data.endpoints;
    await bg({ type: "RESTORE_ENDPOINTS", endpoints: data.endpoints });
    renderEndpoints();
    setBadge("bdg-endpoints", state.endpoints.length);
  }
  if (data.technologies) state.technologies = data.technologies;
  if (data.headers) state.headers = data.headers;

  // Restore settings
  if (data.settings) {
    settings = { ...DEFAULT_SETTINGS, ...data.settings };
    loadSettingsUI();
    saveSettings();
  }

  // Restore scope
  if (data.scopeInclude !== undefined) {
    document.getElementById("tgt-scope-include").value = data.scopeInclude;
    document.getElementById("cfg-scope-include").value = data.scopeInclude;
  }
  if (data.scopeExclude !== undefined) {
    document.getElementById("tgt-scope-exclude").value = data.scopeExclude;
    document.getElementById("cfg-scope-exclude").value = data.scopeExclude;
  }

  // Notes
  if (data.notes) {
    notes = data.notes;
    notesNextId = notes.reduce((max, n) => Math.max(max, n.id), 0) + 1;
  }

  renderHeaders();
  updateBadges();
  sessionStatus(`Loaded — ${historyData.length} history, ${repTabs.length} repeater tabs`);
}

// ═══════════════════════════ WEBSOCKET HISTORY ═════════════════════════

function startWsPoll() {
  if (wsTimer) return;
  pollWsFrames();
  wsTimer = setInterval(pollWsFrames, 800);
}
function stopWsPoll() { clearInterval(wsTimer); wsTimer = null; }

async function pollWsFrames() {
  const res = await bg({ type: "GET_WS_HISTORY" });
  if (!res) return;
  wsFrames = res.frames || [];
  wsConnections = res.connections || {};
  renderWsHistory();
  setBadge("bdg-ws", wsFrames.length);
}

function renderWsHistory() {
  const tbody = document.getElementById("ws-tbody");
  const empty = document.getElementById("ws-empty");
  const connBar = document.getElementById("ws-conn-bar");
  const connInfo = document.getElementById("ws-conn-info");
  tbody.replaceChildren();

  // Connection status pills
  const conns = Object.entries(wsConnections);
  if (conns.length) {
    connBar.classList.remove("hidden");
    connInfo.replaceChildren();
    for (const [, c] of conns) {
      const pill = el("span", `ws-conn-pill ws-conn-${c.status === "open" ? "open" : "closed"}`);
      let label = "";
      try { label = new URL(c.url).host; } catch { label = c.url; }
      pill.textContent = `${c.status === "open" ? "\u25CF" : "\u25CB"} ${label}`;
      pill.title = c.url;
      connInfo.appendChild(pill);
    }
  } else {
    connBar.classList.add("hidden");
  }

  // Populate connection filter
  const connSel = document.getElementById("ws-flt-conn");
  const existingOpts = new Set([...connSel.options].map(o => o.value));
  for (const [, c] of conns) {
    if (!existingOpts.has(c.url)) {
      const o = el("option"); o.value = c.url;
      try { o.textContent = new URL(c.url).host; } catch { o.textContent = c.url; }
      connSel.appendChild(o); existingOpts.add(c.url);
    }
  }

  let items = [...wsFrames];
  if (wsFilterDir) items = items.filter(f => f.direction === wsFilterDir);
  if (wsFilterType) items = items.filter(f => String(f.opcode) === wsFilterType);
  if (wsFilterConn) items = items.filter(f => f.url === wsFilterConn);
  if (wsFilterText) {
    const q = wsFilterText.toLowerCase();
    items = items.filter(f => (f.data || "").toLowerCase().includes(q) || (f.url || "").toLowerCase().includes(q));
  }

  items.sort((a, b) => {
    let va, vb;
    const ai = wsFrames.indexOf(a), bi = wsFrames.indexOf(b);
    switch (wsSortKey) {
      case "id":        va = ai; vb = bi; break;
      case "direction": va = a.direction; vb = b.direction; break;
      case "url":       va = a.url; vb = b.url; break;
      case "opcode":    va = a.opcode; vb = b.opcode; break;
      case "length":    va = a.length; vb = b.length; break;
      case "time":      va = a.time; vb = b.time; break;
      default:          va = ai; vb = bi;
    }
    if (typeof va === "string") { va = va.toLowerCase(); vb = vb.toLowerCase(); }
    return (va < vb ? -1 : va > vb ? 1 : 0) * (wsSortAsc ? 1 : -1);
  });

  if (!items.length) { empty.classList.remove("hidden"); document.getElementById("ws-table").parentElement.classList.add("hidden"); return; }
  empty.classList.add("hidden");
  document.getElementById("ws-table").parentElement.classList.remove("hidden");

  for (let i = 0; i < Math.min(items.length, 3000); i++) {
    const f = items[i];
    const tr = document.createElement("tr");
    tr.className = "tgt-clickable";
    const dirCls = f.direction === "sent" ? "ws-dir-sent" : "ws-dir-recv";
    const dirIcon = f.direction === "sent" ? "\u2191" : "\u2193";
    const typeStr = f.opcode === 2 ? "Binary" : "Text";
    const preview = esc((f.data || "").slice(0, 120));
    const len = f.length > 1024 ? `${(f.length / 1024).toFixed(1)}k` : f.length || 0;
    tr.appendChild(txt("td", "hist-td-num", String(wsFrames.indexOf(f) + 1)));
    const dirTd = txt("td", dirCls, dirIcon); dirTd.title = f.direction; tr.appendChild(dirTd);
    const urlTd = txt("td", "", wsShortUrl(f.url)); urlTd.title = f.url; tr.appendChild(urlTd);
    tr.appendChild(txt("td", "", typeStr));
    tr.appendChild(txt("td", "hist-td-len", String(len)));
    const dataTd = txt("td", "ws-data-preview", (f.data || "").slice(0, 120)); dataTd.title = preview; tr.appendChild(dataTd);
    tr.appendChild(txt("td", "hist-td-timestamp", fmtTime(f.time)));
    tr._wsFrame = f;
    if (wsDetailFrame === f) tr.classList.add("hist-selected");
    tr.addEventListener("click", () => wsOpenDetail(f));
    tbody.appendChild(tr);
  }
}

function wsShortUrl(url) {
  try { const u = new URL(url); return u.host + u.pathname; } catch { return url; }
}

function wsOpenDetail(frame) {
  wsDetailFrame = frame;
  const detail = document.getElementById("ws-detail");
  document.getElementById("ws-detail-title").textContent = `${frame.direction === "sent" ? "\u2191 Sent" : "\u2193 Received"} \u2014 ${wsShortUrl(frame.url)}`;
  let display = frame.data || "";
  try { const parsed = JSON.parse(display); display = JSON.stringify(parsed, null, 2); } catch {}
  document.getElementById("ws-detail-pre").textContent = display;
  detail.classList.remove("hidden"); detail.classList.add("visible");
  document.getElementById("ws-resizer").classList.add("visible");
  document.querySelectorAll("#ws-tbody tr").forEach(r => r.classList.remove("hist-selected"));
  document.querySelectorAll("#ws-tbody tr").forEach(r => { if (r._wsFrame === frame) r.classList.add("hist-selected"); });
}

function wsCloseDetail() {
  wsDetailFrame = null;
  document.getElementById("ws-detail").classList.add("hidden");
  document.getElementById("ws-detail").classList.remove("visible");
  document.getElementById("ws-resizer").classList.remove("visible");
}

// ═══════════════════════════ PoC GENERATOR (CSRF + Clickjacking) ══════

// Shared escape helpers
function pocEscHtml(s) { return (s || "").replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/'/g, "&#39;"); }
function pocEscJs(s) { return (s || "").replace(/\\/g, "\\\\").replace(/'/g, "\\'").replace(/\n/g, "\\n").replace(/<\//g, "<\\/"); }
function pocEscAttr(s) { return (s || "").replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }

function pocParseUrlEncoded(body) {
  if (!body) return [];
  return body.split("&").map(p => {
    const i = p.indexOf("=");
    if (i < 0) return [decodeURIComponent(p), ""];
    return [decodeURIComponent(p.slice(0, i)), decodeURIComponent(p.slice(i + 1))];
  });
}

function pocParseMultipart(body, ct) {
  const fields = [];
  const bm = (ct || "").match(/boundary=(.+)/i);
  if (!bm || !body) return fields;
  const boundary = bm[1].replace(/^["']|["']$/g, "");
  for (const part of body.split("--" + boundary)) {
    const nm = part.match(/name="([^"]+)"/);
    if (!nm) continue;
    const vs = part.indexOf("\r\n\r\n");
    fields.push({ name: nm[1], value: vs >= 0 ? part.slice(vs + 4).replace(/\r\n$/, "") : "" });
  }
  return fields;
}

// Load a request entry into the PoC config panel
let pocEntry = null;

function pocLoadEntry(entry) {
  pocEntry = entry;
  const url = entry.url || "";
  const method = (entry.method || "GET").toUpperCase();
  const body = entry.body || "";
  const headers = entry.headers || {};
  const ct = Object.entries(headers).find(([k]) => k.toLowerCase() === "content-type")?.[1] || "";

  // Fill CSRF config
  document.getElementById("poc-csrf-url").value = url;
  document.getElementById("poc-csrf-method").value = method === "GET" ? "GET" : method;
  document.getElementById("poc-csrf-body").value = body;
  document.getElementById("poc-csrf-ct").value = ct;

  // Fill Clickjacking config
  document.getElementById("poc-cj-url").value = url;

  // Auto-select best CSRF technique
  const sel = document.getElementById("poc-csrf-technique");
  if (method === "GET") sel.value = "auto-form-get";
  else if (ct.includes("application/json")) sel.value = "fetch-no-cors";
  else if (ct.includes("multipart")) sel.value = "multipart";
  else sel.value = "auto-form";

  // Auto-detect: strip CSRF tokens if present
  const hasCsrfInBody = /csrf|xsrf|_token|authenticity_token/i.test(body);
  document.getElementById("poc-csrf-strip-token").checked = hasCsrfInBody;

  // Update label
  document.getElementById("poc-req-label").textContent = `${method} ${url}`;

  showTab("poc");
  pocCsrfGenerate(); // auto-generate on load
}

// ── CSRF PoC Generation ─────────────────────────────────────────────

function pocCsrfGenerate() {
  let url = document.getElementById("poc-csrf-url").value.trim();
  if (!url) { pocCsrfStatus("Enter a URL"); return; }
  const method = document.getElementById("poc-csrf-method").value;
  let body = document.getElementById("poc-csrf-body").value;
  const ct = document.getElementById("poc-csrf-ct").value;
  const technique = document.getElementById("poc-csrf-technique").value;
  const autoSubmit = document.getElementById("poc-csrf-autosubmit").checked;
  const noReferrer = document.getElementById("poc-csrf-no-referrer").checked;
  const stripToken = document.getElementById("poc-csrf-strip-token").checked;
  const sandbox = document.getElementById("poc-csrf-sandbox").checked;

  // Strip CSRF token params from body
  if (stripToken && body) {
    body = body.split("&").filter(p => !/csrf|xsrf|_token|authenticity_token/i.test(p.split("=")[0])).join("&");
  }

  // Warnings
  const warnings = [];
  const origBody = document.getElementById("poc-csrf-body").value;
  if (/csrf|xsrf|_token|authenticity_token/i.test(origBody) && !stripToken) {
    warnings.push({ type: "alert", text: "CSRF token detected in body \u2014 enable 'Strip CSRF token params' or PoC may fail." });
  }
  if (method === "GET" && technique !== "auto-form-get" && technique !== "method-override") {
    warnings.push({ type: "info", text: "GET request \u2014 consider 'GET (img + iframe)' technique." });
  }
  if (ct.includes("application/json") && technique === "auto-form") {
    warnings.push({ type: "alert", text: "JSON body with auto-form \u2014 server may reject. Use 'XHR (text/plain)' or 'Fetch' technique." });
  }
  if (technique === "xhr-text-plain" || technique === "fetch-no-cors") {
    warnings.push({ type: "info", text: "Content-Type: text/plain \u2014 bypasses CORS preflight. Server must accept text/plain." });
  }
  if (technique === "method-override") {
    warnings.push({ type: "info", text: "Uses _method=POST override in a GET form \u2014 works with Symfony, Laravel, Rails." });
  }

  // Build head
  let head = "<title>CSRF PoC</title>\n";
  if (noReferrer) head += '  <meta name="referrer" content="no-referrer">\n';

  let html = "";
  const safeUrl = pocEscAttr(url);
  const submitScript = autoSubmit ? "\n  <script>document.getElementById('poc-form').submit();<\\/script>" : "";

  switch (technique) {
    case "auto-form-get": {
      html = `<html>\n<head>\n  ${head}</head>\n<body>\n  <h1>CSRF PoC</h1>\n  <img src="${safeUrl}" style="display:none" />\n  <iframe src="${safeUrl}" style="width:0;height:0;border:0"></iframe>\n</body>\n</html>`;
      break;
    }
    case "xhr-text-plain": {
      // XHR with text/plain Content-Type — bypasses CORS preflight
      // The body is sent as-is; to send form-encoded params via text/plain, we
      // craft the body so the first param contains "=" (required for text/plain trick)
      html = `<html>\n<head>\n  ${head}</head>\n<body>\n  <h1>CSRF PoC</h1>\n  <script>\n    var xhr = new XMLHttpRequest();\n    xhr.open('${pocEscJs(method)}', '${pocEscJs(url)}', true);\n    xhr.withCredentials = true;\n    xhr.setRequestHeader('Content-Type', 'text/plain');\n    xhr.send('${pocEscJs(body)}');\n  <\\/script>\n</body>\n</html>`;
      break;
    }
    case "fetch-no-cors": {
      // Fetch with no-cors mode — sends request but can't read response
      html = `<html>\n<head>\n  ${head}</head>\n<body>\n  <h1>CSRF PoC</h1>\n  <script>\n    fetch('${pocEscJs(url)}', {\n      method: '${pocEscJs(method)}',\n      mode: 'no-cors',\n      credentials: 'include',\n      headers: { 'Content-Type': 'text/plain' },\n      body: '${pocEscJs(body)}'\n    });\n  <\\/script>\n</body>\n</html>`;
      break;
    }
    case "method-override": {
      // SameSite Lax bypass: GET form with _method=POST (Symfony/Laravel/Rails)
      const params = pocParseUrlEncoded(body);
      let fields = `    <input type="hidden" name="_method" value="${pocEscAttr(method)}" />\n`;
      fields += params.map(([k, v]) => `    <input type="hidden" name="${pocEscAttr(k)}" value="${pocEscAttr(v)}" />`).join("\n");
      html = `<html>\n<head>\n  ${head}</head>\n<body>\n  <h1>CSRF PoC</h1>\n  <form id="poc-form" action="${safeUrl}" method="GET">\n${fields}\n    <input type="submit" value="Submit" />\n  </form>${submitScript}\n</body>\n</html>`;
      break;
    }
    case "multipart": {
      const fields = pocParseMultipart(body, ct).map(f =>
        `    <input type="hidden" name="${pocEscAttr(f.name)}" value="${pocEscAttr(f.value)}" />`
      ).join("\n");
      html = `<html>\n<head>\n  ${head}</head>\n<body>\n  <h1>CSRF PoC</h1>\n  <form id="poc-form" action="${safeUrl}" method="POST" enctype="multipart/form-data">\n${fields}\n    <input type="submit" value="Submit" />\n  </form>${submitScript}\n</body>\n</html>`;
      break;
    }
    default: { // auto-form
      const params = pocParseUrlEncoded(body);
      const fields = params.map(([k, v]) => `    <input type="hidden" name="${pocEscAttr(k)}" value="${pocEscAttr(v)}" />`).join("\n");
      html = `<html>\n<head>\n  ${head}</head>\n<body>\n  <h1>CSRF PoC</h1>\n  <form id="poc-form" action="${safeUrl}" method="${pocEscAttr(method)}">\n${fields}\n    <input type="submit" value="Submit" />\n  </form>${submitScript}\n</body>\n</html>`;
      break;
    }
  }

  // Wrap in sandbox iframe if requested
  if (sandbox && technique !== "auto-form-get") {
    const inner = html.replace(/"/g, "&quot;");
    html = `<html>\n<head>\n  ${head}</head>\n<body>\n  <h1>CSRF PoC (sandboxed)</h1>\n  <iframe sandbox="allow-forms allow-scripts" srcdoc="${inner}" style="width:0;height:0;border:0"></iframe>\n</body>\n</html>`;
  }

  // Render
  const warnEl = document.getElementById("poc-csrf-warnings");
  warnEl.replaceChildren();
  for (const w of warnings) {
    const div = el("div", `csrf-warn-item csrf-warn-${w.type}`);
    div.textContent = (w.type === "alert" ? "\u26A0 " : "\u2713 ") + w.text;
    warnEl.appendChild(div);
  }
  document.getElementById("poc-csrf-code").textContent = html;
  document.getElementById("poc-csrf-code")._html = html;
}

function pocCsrfStatus(msg) {
  document.getElementById("poc-csrf-status").textContent = msg;
  setTimeout(() => { document.getElementById("poc-csrf-status").textContent = ""; }, 3000);
}

// ── Clickjacking PoC Generation ─────────────────────────────────────

function pocCjGenerate() {
  let url = document.getElementById("poc-cj-url").value.trim();
  if (!url) { pocCjStatus("Enter a target URL"); return; }
  const technique = document.getElementById("poc-cj-technique").value;
  const params = document.getElementById("poc-cj-params").value.trim();
  const top1 = document.getElementById("poc-cj-top1").value || 300;
  const left1 = document.getElementById("poc-cj-left1").value || 60;
  const text1 = document.getElementById("poc-cj-text1").value || "Click me";
  const top2 = document.getElementById("poc-cj-top2").value || 285;
  const left2 = document.getElementById("poc-cj-left2").value || 225;
  const text2 = document.getElementById("poc-cj-text2").value || "Click me next";
  const iframeW = document.getElementById("poc-cj-width").value || 500;
  const iframeH = document.getElementById("poc-cj-height").value || 700;
  const opacity = document.getElementById("poc-cj-opacity").value || "0.0001";

  // Append prefill params to URL
  if (params) {
    const sep = url.includes("?") ? "&" : "?";
    url += sep + params;
  }

  const safeUrl = pocEscAttr(url);
  const sandboxAttr = technique === "framebuster" ? ' sandbox="allow-forms"' : "";

  let decoys = `  <div class="decoy1">${pocEscHtml(text1)}</div>`;
  let decoyStyles = `  .decoy1 {\n    position: absolute;\n    top: ${top1}px;\n    left: ${left1}px;\n    z-index: 1;\n    cursor: pointer;\n    font-size: 20px;\n    font-family: sans-serif;\n    padding: 10px 20px;\n    background: #4CAF50;\n    color: white;\n    border: none;\n    border-radius: 5px;\n  }`;

  if (technique === "multistep") {
    decoys += `\n  <div class="decoy2">${pocEscHtml(text2)}</div>`;
    decoyStyles += `\n  .decoy2 {\n    position: absolute;\n    top: ${top2}px;\n    left: ${left2}px;\n    z-index: 1;\n    cursor: pointer;\n    font-size: 20px;\n    font-family: sans-serif;\n    padding: 10px 20px;\n    background: #2196F3;\n    color: white;\n    border: none;\n    border-radius: 5px;\n  }`;
  }

  const html = `<html>\n<head>\n  <title>Clickjacking PoC</title>\n  <style>\n  iframe {\n    position: relative;\n    width: ${iframeW}px;\n    height: ${iframeH}px;\n    opacity: ${opacity};\n    z-index: 2;\n  }\n${decoyStyles}\n  </style>\n</head>\n<body>\n${decoys}\n  <iframe src="${safeUrl}"${sandboxAttr}></iframe>\n</body>\n</html>`;

  document.getElementById("poc-cj-code").textContent = html;
  document.getElementById("poc-cj-code")._html = html;
}

function pocCjStatus(msg) {
  document.getElementById("poc-cj-status").textContent = msg;
  setTimeout(() => { document.getElementById("poc-cj-status").textContent = ""; }, 3000);
}

// ── PoC shared helpers ──────────────────────────────────────────────

function pocCopy(preId) {
  const pre = document.getElementById(preId);
  navigator.clipboard.writeText(pre._html || pre.textContent || "").then(() => {
    const statusId = preId.includes("csrf") ? "poc-csrf-status" : "poc-cj-status";
    document.getElementById(statusId).textContent = "Copied!";
    setTimeout(() => { document.getElementById(statusId).textContent = ""; }, 2000);
  });
}

function pocDownload(preId, filename) {
  const pre = document.getElementById(preId);
  const blob = new Blob([pre._html || pre.textContent || ""], { type: "text/html" });
  const a = el("a"); a.href = URL.createObjectURL(blob);
  a.download = filename; a.click(); URL.revokeObjectURL(a.href);
}

// ═══════════════════════════ SEQUENCER ═════════════════════════════════

async function seqStartCollection() {
  const url = document.getElementById("seq-url").value.trim();
  if (!url) { seqStatus("Enter a URL"); return; }
  const method = document.getElementById("seq-method").value;
  const rawHeaders = document.getElementById("seq-headers").value;
  const body = document.getElementById("seq-body").value;
  const extractType = document.getElementById("seq-extract").value;
  const tokenName = document.getElementById("seq-token-name").value.trim();
  const count = parseInt(document.getElementById("seq-count").value) || 100;
  const delay = parseInt(document.getElementById("seq-delay").value) || 0;
  if (!tokenName) { seqStatus("Enter a token name or regex pattern"); return; }

  seqTokens = [];
  seqRunning = true;
  seqAbort = new AbortController();
  document.getElementById("seq-start").disabled = true;
  document.getElementById("seq-stop").disabled = false;
  document.getElementById("seq-progress").classList.remove("hidden");

  for (let i = 0; i < count; i++) {
    if (!seqRunning) break;
    document.getElementById("seq-progress-fill").style.width = `${((i + 1) / count) * 100}%`;
    document.getElementById("seq-progress-text").textContent = `${i + 1} / ${count}`;

    try {
      const res = await bg({ type: "SEND_REQUEST", url, method, rawHeaders, body: body || undefined });
      if (!res || res.error) continue;
      let token = null;
      if (extractType === "cookie") {
        const setCookies = Object.entries(res.headers || {}).filter(([k]) => k.toLowerCase() === "set-cookie").map(([, v]) => v);
        const allCookies = setCookies.join("; ");
        const re = new RegExp(`(?:^|;\\s*)${tokenName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}=([^;]+)`);
        const m = allCookies.match(re);
        if (m) token = m[1];
      } else if (extractType === "header") {
        token = Object.entries(res.headers || {}).find(([k]) => k.toLowerCase() === tokenName.toLowerCase())?.[1] || null;
      } else if (extractType === "body-regex") {
        try { const re = new RegExp(tokenName); const m = (res.body || "").match(re); token = m ? (m[1] || m[0]) : null; }
        catch { seqStatus("Invalid regex"); break; }
      }
      if (token) seqTokens.push(token);
    } catch {}
    if (delay > 0 && seqRunning) await new Promise(r => setTimeout(r, delay));
  }

  seqRunning = false;
  document.getElementById("seq-start").disabled = false;
  document.getElementById("seq-stop").disabled = true;
  seqStatus(`Done \u2014 ${seqTokens.length} tokens collected`);
  if (seqTokens.length) seqAnalyze();
}

function seqStopCollection() {
  seqRunning = false;
  if (seqAbort) { seqAbort.abort(); seqAbort = null; }
  document.getElementById("seq-start").disabled = false;
  document.getElementById("seq-stop").disabled = true;
  seqStatus("Stopped");
  if (seqTokens.length) seqAnalyze();
}

function seqStatus(msg) {
  document.getElementById("seq-collect-status").textContent = msg;
  setTimeout(() => { document.getElementById("seq-collect-status").textContent = ""; }, 4000);
}

function seqAnalyze() {
  if (!seqTokens.length) return;
  document.getElementById("seq-empty").classList.add("hidden");
  document.getElementById("seq-score-card").classList.remove("hidden");
  document.getElementById("seq-tests").classList.remove("hidden");
  document.getElementById("seq-chart-wrap").classList.remove("hidden");
  document.getElementById("seq-tokens-wrap").classList.remove("hidden");

  const tokens = seqTokens;
  const unique = new Set(tokens);
  const avgLen = tokens.reduce((s, t) => s + t.length, 0) / tokens.length;

  // Character frequency
  const charFreq = {};
  let totalChars = 0;
  for (const t of tokens) for (const c of t) { charFreq[c] = (charFreq[c] || 0) + 1; totalChars++; }
  const charSet = Object.keys(charFreq).sort();

  // Shannon entropy per character position
  const maxLen = Math.max(...tokens.map(t => t.length));
  let totalEntropy = 0, posCount = 0;
  for (let pos = 0; pos < maxLen; pos++) {
    const freq = {};
    let n = 0;
    for (const t of tokens) { if (pos < t.length) { freq[t[pos]] = (freq[t[pos]] || 0) + 1; n++; } }
    if (n < 2) continue;
    let h = 0;
    for (const c in freq) { const p = freq[c] / n; if (p > 0) h -= p * Math.log2(p); }
    totalEntropy += h; posCount++;
  }
  const avgEntropy = posCount > 0 ? totalEntropy / posCount : 0;
  const maxPossible = Math.log2(charSet.length || 1);
  const entropyPct = maxPossible > 0 ? (avgEntropy / maxPossible) * 100 : 0;

  let rating, ratingCls;
  if (entropyPct >= 85) { rating = "Excellent"; ratingCls = "seq-rating-excellent"; }
  else if (entropyPct >= 60) { rating = "Good"; ratingCls = "seq-rating-good"; }
  else { rating = "Poor"; ratingCls = "seq-rating-poor"; }

  document.getElementById("seq-score-value").textContent = `${avgEntropy.toFixed(3)} bits/char`;
  const ratingEl = document.getElementById("seq-score-rating");
  ratingEl.textContent = `${rating} (${entropyPct.toFixed(1)}%)`;
  ratingEl.className = `seq-score-rating ${ratingCls}`;
  document.getElementById("seq-token-count").textContent = tokens.length;
  document.getElementById("seq-unique-count").textContent = unique.size;
  document.getElementById("seq-avg-len").textContent = avgLen.toFixed(1);
  document.getElementById("seq-charset-size").textContent = charSet.length;

  seqRunTests(tokens);
  seqDrawChart(charFreq, totalChars);

  const tokenList = document.getElementById("seq-token-list");
  tokenList.replaceChildren();
  tokens.forEach((t, i) => { tokenList.appendChild(txt("div", "", `${String(i + 1).padStart(4)} ${t}`)); });
}

function seqRunTests(tokens) {
  const container = document.getElementById("seq-test-results");
  container.replaceChildren();
  const bits = tokens.map(t => { let b = ""; for (const c of t) b += c.charCodeAt(0).toString(2).padStart(8, "0"); return b; }).join("");
  const tests = [];

  if (bits.length >= 100) {
    const ones = [...bits].filter(b => b === "1").length;
    const ratio = ones / bits.length;
    tests.push({ name: "Monobit (proportion of 1s)", result: `${(ratio * 100).toFixed(1)}%`, pass: ratio > 0.45 && ratio < 0.55 });
  }

  const uniqueRatio = new Set(tokens).size / tokens.length;
  tests.push({ name: "Uniqueness", result: `${(uniqueRatio * 100).toFixed(1)}%`, pass: uniqueRatio > 0.95 });

  if (tokens.length >= 20) {
    const cf = {};
    let tot = 0;
    for (const t of tokens) for (const c of t) { cf[c] = (cf[c] || 0) + 1; tot++; }
    const cc = Object.keys(cf).length;
    const exp = tot / cc;
    let chi = 0;
    for (const c in cf) chi += Math.pow(cf[c] - exp, 2) / exp;
    tests.push({ name: "Character distribution (\u03C7\u00B2)", result: (chi / (cc - 1 || 1)).toFixed(2), pass: chi / (cc - 1 || 1) < 3.0 });
  }

  if (bits.length >= 200) {
    let sum = 0;
    for (let i = 0; i < bits.length - 1; i++) sum += (bits[i] === bits[i + 1]) ? 1 : 0;
    const sc = sum / (bits.length - 1);
    tests.push({ name: "Serial correlation", result: sc.toFixed(4), pass: sc > 0.45 && sc < 0.55 });
  }

  if (bits.length >= 100) {
    let runs = 1;
    for (let i = 1; i < bits.length; i++) if (bits[i] !== bits[i - 1]) runs++;
    const er = (2 * bits.length - 1) / 3;
    tests.push({ name: "Runs test", result: `${runs} (expected ~${Math.round(er)})`, pass: runs / er > 0.85 && runs / er < 1.15 });
  }

  for (const t of tests) {
    const row = el("div", "seq-test-row");
    row.appendChild(txt("span", "", t.name));
    row.appendChild(txt("span", t.pass ? "seq-test-pass" : "seq-test-fail", `${t.pass ? "\u2713" : "\u2717"} ${t.result}`));
    container.appendChild(row);
  }
}

function seqDrawChart(charFreq, total) {
  const canvas = document.getElementById("seq-chart");
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth;
  const h = 200;
  canvas.width = w * dpr; canvas.height = h * dpr;
  ctx.scale(dpr, dpr); ctx.clearRect(0, 0, w, h);

  const chars = Object.entries(charFreq).sort((a, b) => a[0].localeCompare(b[0]));
  if (!chars.length) return;
  const barW = Math.max(2, (w - 40) / chars.length - 1);
  const maxFreq = Math.max(...chars.map(([, v]) => v));
  const chartH = h - 30;
  const dimColor = getComputedStyle(document.body).getPropertyValue("--muted").trim() || "#888";

  for (let i = 0; i < chars.length; i++) {
    const [ch, freq] = chars[i];
    const barH = (freq / maxFreq) * chartH;
    const x = 20 + i * (barW + 1);
    const pct = freq / total;
    ctx.fillStyle = pct > 0.05 ? "rgba(231,76,60,.7)" : pct > 0.02 ? "rgba(232,168,56,.6)" : "rgba(88,214,141,.5)";
    ctx.fillRect(x, chartH - barH, barW, barH);
    if (chars.length <= 40 || i % Math.ceil(chars.length / 40) === 0) {
      ctx.fillStyle = dimColor; ctx.font = "9px monospace"; ctx.fillText(ch, x, h - 4);
    }
  }
}

function seqExport() {
  if (!seqTokens.length) return;
  const csv = "index,token\n" + seqTokens.map((t, i) => `${i + 1},"${t.replace(/"/g, '""')}"`).join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const a = el("a"); a.href = URL.createObjectURL(blob);
  a.download = `void-sequencer-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click(); URL.revokeObjectURL(a.href);
}

function seqFromHistory() {
  for (let i = historyData.length - 1; i >= 0; i--) {
    const e = historyData[i];
    const setCookie = Object.entries(e.respHeaders || {}).find(([k]) => k.toLowerCase() === "set-cookie");
    if (setCookie) {
      document.getElementById("seq-url").value = e.url;
      document.getElementById("seq-method").value = e.method || "GET";
      document.getElementById("seq-headers").value = headersToRaw(e.headers || {});
      document.getElementById("seq-body").value = e.body || "";
      document.getElementById("seq-extract").value = "cookie";
      document.getElementById("seq-token-name").value = setCookie[1].split("=")[0].trim();
      seqStatus(`Loaded from history: ${setCookie[1].split("=")[0].trim()}`);
      return;
    }
  }
  seqStatus("No Set-Cookie entries found in history");
}

// ═══════════════════════════ NOTES ═════════════════════════════════════

function notesAdd(data) {
  const note = {
    id: notesNextId++,
    title: data.title || "Untitled",
    severity: data.severity || "info",
    host: data.host || "",
    url: data.url || "",
    body: data.body || "",
    time: Date.now(),
  };
  notes.unshift(note);
  notesRender(); notesSave();
  setBadge("bdg-notes", notes.length);
}

function notesDelete(id) {
  notes = notes.filter(n => n.id !== id);
  notesRender(); notesSave();
  setBadge("bdg-notes", notes.length);
}

function notesRender() {
  const list = document.getElementById("notes-list");
  const empty = document.getElementById("notes-empty");
  list.replaceChildren();

  let items = [...notes];
  if (notesFilterSev) items = items.filter(n => n.severity === notesFilterSev);
  if (notesFilterHost) items = items.filter(n => n.host === notesFilterHost);
  if (notesFilterText) {
    const q = notesFilterText.toLowerCase();
    items = items.filter(n => (n.title || "").toLowerCase().includes(q) || (n.body || "").toLowerCase().includes(q) || (n.url || "").toLowerCase().includes(q) || (n.host || "").toLowerCase().includes(q));
  }

  if (!items.length) { empty.classList.remove("hidden"); return; }
  empty.classList.add("hidden");

  // Populate host filter
  const hostSel = document.getElementById("notes-flt-host");
  const existingHosts = new Set([...hostSel.options].map(o => o.value));
  for (const n of notes) {
    if (n.host && !existingHosts.has(n.host)) {
      const o = el("option"); o.value = n.host; o.textContent = n.host;
      hostSel.appendChild(o); existingHosts.add(n.host);
    }
  }

  for (const n of items) {
    const card = el("div", "note-card");
    const header = el("div", "note-header");
    header.appendChild(txt("span", "note-title", n.title));
    header.appendChild(txt("span", `note-sev note-sev-${n.severity}`, n.severity));
    card.appendChild(header);
    const meta = el("div", "note-meta");
    const ts = new Date(n.time);
    meta.textContent = `${n.host || "no host"} \u2014 ${ts.toLocaleDateString()} ${ts.toLocaleTimeString()}`;
    card.appendChild(meta);
    if (n.body) card.appendChild(txt("div", "note-body", n.body));
    if (n.url) card.appendChild(txt("div", "note-url", n.url));
    const actions = el("div", "note-actions");
    const btnEdit = txt("button", "btn btn-xs btn-ghost", "\u270E");
    const btnDel = txt("button", "btn btn-xs btn-danger", "\u2717");
    btnEdit.addEventListener("click", () => notesStartEdit(n));
    btnDel.addEventListener("click", () => notesDelete(n.id));
    ap(actions, btnEdit, btnDel); card.appendChild(actions);
    list.appendChild(card);
  }
}

function notesStartEdit(note) {
  notesEditingId = note.id;
  document.getElementById("notes-title").value = note.title;
  document.getElementById("notes-sev").value = note.severity;
  document.getElementById("notes-host").value = note.host;
  document.getElementById("notes-url").value = note.url;
  document.getElementById("notes-body").value = note.body;
  document.getElementById("notes-form").classList.remove("hidden");
  document.getElementById("notes-form-save").textContent = "Update";
}

function notesSaveForm() {
  const title = document.getElementById("notes-title").value.trim();
  const severity = document.getElementById("notes-sev").value;
  const host = document.getElementById("notes-host").value.trim();
  const url = document.getElementById("notes-url").value.trim();
  const body = document.getElementById("notes-body").value;
  if (!title) { document.getElementById("notes-form-status").textContent = "Title required"; return; }
  if (notesEditingId) {
    const note = notes.find(n => n.id === notesEditingId);
    if (note) { note.title = title; note.severity = severity; note.host = host; note.url = url; note.body = body; }
    notesEditingId = null;
  } else {
    notesAdd({ title, severity, host, url, body });
  }
  notesCancelForm(); notesRender(); notesSave();
}

function notesCancelForm() {
  notesEditingId = null;
  document.getElementById("notes-form").classList.add("hidden");
  document.getElementById("notes-title").value = "";
  document.getElementById("notes-body").value = "";
  document.getElementById("notes-url").value = "";
  document.getElementById("notes-host").value = "";
  document.getElementById("notes-form-save").textContent = "Save";
}

function notesFromEntry(entry) {
  let host = "";
  try { host = new URL(entry.url).hostname; } catch {}
  document.getElementById("notes-title").value = `${entry.method} ${entry.url}`;
  document.getElementById("notes-host").value = host;
  document.getElementById("notes-url").value = entry.url || "";
  document.getElementById("notes-sev").value = "info";
  document.getElementById("notes-body").value = "";
  document.getElementById("notes-form").classList.remove("hidden");
  document.getElementById("notes-form-save").textContent = "Save";
  notesEditingId = null;
  showTab("notes");
}

function notesSave() { chrome.storage.local.set({ voidNotes: notes }); }

async function notesLoad() {
  const stored = await new Promise(r => chrome.storage.local.get("voidNotes", r));
  if (stored.voidNotes) {
    notes = stored.voidNotes;
    notesNextId = notes.reduce((max, n) => Math.max(max, n.id), 0) + 1;
    setBadge("bdg-notes", notes.length);
  }
}

function notesExport() {
  if (!notes.length) return;
  let md = "# Void Extension \u2014 Notes\n\n";
  const byHost = {};
  for (const n of notes) { const h = n.host || "General"; (byHost[h] = byHost[h] || []).push(n); }
  for (const [host, items] of Object.entries(byHost)) {
    md += `## ${host}\n\n`;
    for (const n of items) {
      md += `### [${n.severity.toUpperCase()}] ${n.title}\n`;
      if (n.url) md += `**URL:** ${n.url}\n`;
      md += `**Date:** ${new Date(n.time).toISOString()}\n\n`;
      if (n.body) md += `${n.body}\n\n`;
      md += "---\n\n";
    }
  }
  const blob = new Blob([md], { type: "text/markdown" });
  const a = el("a"); a.href = URL.createObjectURL(blob);
  a.download = `void-notes-${new Date().toISOString().slice(0, 10)}.md`;
  a.click(); URL.revokeObjectURL(a.href);
}

// ═══════════════════════════ COMPARER ════════════════════════════════════

let cmpLeft = null;   // { method, url, host, path, headers, body, status, statusText, respHeaders, respBody }
let cmpRight = null;

function cmpEntryToText(entry, section) {
  if (!entry) return "";
  if (section === "req") {
    let text = `${entry.method} ${entry.path || "/"} HTTP/1.1\nHost: ${entry.host}\n`;
    text += Object.entries(entry.headers || {}).map(([k,v]) => `${k}: ${v}`).join("\n");
    if (entry.body) text += "\n\n" + entry.body;
    return text;
  } else {
    let text = entry.status ? `HTTP/1.1 ${entry.status} ${entry.statusText || ""}\n` : "(no response)\n";
    text += Object.entries(entry.respHeaders || {}).map(([k,v]) => `${k}: ${v}`).join("\n");
    const ct = entry.respHeaders?.["content-type"] || entry.respHeaders?.["Content-Type"] || "";
    text += "\n\n" + tryPretty(entry.respBody || "(empty)", ct);
    return text;
  }
}

function cmpSendTo(side, entry) {
  const data = {
    method: entry.method || "GET",
    url: entry.url || "",
    host: entry.host || "",
    path: entry.path || "",
    headers: entry.headers || {},
    body: entry.body || "",
    status: entry.status || null,
    statusText: entry.statusText || "",
    respHeaders: entry.respHeaders || {},
    respBody: entry.respBody || "",
  };
  if (!data.host || !data.path) {
    try { const u = new URL(data.url); data.host = u.host; data.path = u.pathname + u.search; } catch {}
  }
  if (side === "left") cmpLeft = data; else cmpRight = data;
  cmpRenderSide(side);
  showTab("comparer");
}

function cmpRenderSide(side) {
  const entry = side === "left" ? cmpLeft : cmpRight;
  const titleEl = document.getElementById(`cmp-${side}-title`);
  const reqPre = document.getElementById(`cmp-${side}-req-pre`);
  const respPre = document.getElementById(`cmp-${side}-resp-pre`);

  if (!entry) {
    titleEl.textContent = `(empty — send a request here with → Cmp ${side === "left" ? "L" : "R"})`;
    reqPre.textContent = "";
    respPre.textContent = "";
    return;
  }

  titleEl.textContent = `${entry.status || "…"} ${entry.method} ${entry.url}`;
  reqPre.textContent = cmpEntryToText(entry, "req");
  respPre.textContent = cmpEntryToText(entry, "resp");
}

function cmpDoDiff() {
  if (!cmpLeft || !cmpRight) {
    document.getElementById("cmp-status").textContent = "Need both Left and Right to diff";
    setTimeout(() => { document.getElementById("cmp-status").textContent = ""; }, 2000);
    return;
  }

  const ignoreCase = document.getElementById("cmp-ignore-case").checked;
  const ignoreHdrOrder = document.getElementById("cmp-ignore-headers").checked;

  // Diff both request and response
  const activeLeft = document.querySelector("#cmp-left .cmp-sub-tabs .sub-tab.active");
  const activeRight = document.querySelector("#cmp-right .cmp-sub-tabs .sub-tab.active");
  const section = activeLeft?.dataset.cmppane?.includes("resp") ? "resp" : "req";

  // Sync both sides to same view
  cmpSwitchPane("left", section);
  cmpSwitchPane("right", section);

  let leftText = cmpEntryToText(cmpLeft, section);
  let rightText = cmpEntryToText(cmpRight, section);

  if (ignoreHdrOrder) {
    leftText = cmpSortHeaders(leftText);
    rightText = cmpSortHeaders(rightText);
  }

  const leftLines = leftText.split("\n");
  const rightLines = rightText.split("\n");

  const diff = cmpLineDiff(leftLines, rightLines, ignoreCase);

  document.getElementById(`cmp-left-${section}-pre`).replaceChildren();
  document.getElementById(`cmp-right-${section}-pre`).replaceChildren();

  cmpRenderDiff(document.getElementById(`cmp-left-${section}-pre`), diff.left);
  cmpRenderDiff(document.getElementById(`cmp-right-${section}-pre`), diff.right);

  const changes = diff.left.filter(d => d.type !== "same").length + diff.right.filter(d => d.type !== "same").length;
  document.getElementById("cmp-status").textContent = changes === 0 ? "Identical" : `${changes} differences`;
  setTimeout(() => { document.getElementById("cmp-status").textContent = ""; }, 4000);
}

function cmpSortHeaders(text) {
  const parts = text.split("\n\n");
  if (parts.length < 2) {
    // Sort all lines after the first (request/status line)
    const lines = text.split("\n");
    const first = lines.shift();
    lines.sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase()));
    return [first, ...lines].join("\n");
  }
  // Sort header block, keep body as-is
  const headerBlock = parts[0].split("\n");
  const first = headerBlock.shift();
  headerBlock.sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase()));
  return [first, ...headerBlock].join("\n") + "\n\n" + parts.slice(1).join("\n\n");
}

function cmpLineDiff(leftLines, rightLines, ignoreCase) {
  // LCS-based diff
  const norm = ignoreCase ? s => s.toLowerCase() : s => s;
  const m = leftLines.length, n = rightLines.length;

  // Build LCS table (optimize: limit to reasonable size)
  const maxLines = 2000;
  const lL = leftLines.slice(0, maxLines);
  const rL = rightLines.slice(0, maxLines);
  const ml = lL.length, nl = rL.length;

  // Use simple O(mn) LCS for reasonable sizes, else fall back to line-by-line
  if (ml * nl > 4000000) {
    return cmpSimpleDiff(leftLines, rightLines, ignoreCase);
  }

  const dp = Array.from({ length: ml + 1 }, () => new Uint16Array(nl + 1));
  for (let i = 1; i <= ml; i++) {
    for (let j = 1; j <= nl; j++) {
      dp[i][j] = norm(lL[i - 1]) === norm(rL[j - 1]) ? dp[i - 1][j - 1] + 1 : Math.max(dp[i - 1][j], dp[i][j - 1]);
    }
  }

  // Backtrack
  const left = [], right = [];
  let i = ml, j = nl;
  const pairs = [];
  while (i > 0 && j > 0) {
    if (norm(lL[i - 1]) === norm(rL[j - 1])) {
      pairs.unshift({ li: i - 1, ri: j - 1, type: "same" });
      i--; j--;
    } else if (dp[i - 1][j] >= dp[i][j - 1]) {
      pairs.unshift({ li: i - 1, ri: -1, type: "del" });
      i--;
    } else {
      pairs.unshift({ li: -1, ri: j - 1, type: "add" });
      j--;
    }
  }
  while (i > 0) { pairs.unshift({ li: i - 1, ri: -1, type: "del" }); i--; }
  while (j > 0) { pairs.unshift({ li: -1, ri: j - 1, type: "add" }); j--; }

  for (const p of pairs) {
    if (p.type === "same") {
      left.push({ text: lL[p.li], type: "same", num: p.li + 1 });
      right.push({ text: rL[p.ri], type: "same", num: p.ri + 1 });
    } else if (p.type === "del") {
      left.push({ text: lL[p.li], type: "del", num: p.li + 1 });
      right.push({ text: "", type: "pad", num: "" });
    } else {
      left.push({ text: "", type: "pad", num: "" });
      right.push({ text: rL[p.ri], type: "add", num: p.ri + 1 });
    }
  }

  return { left, right };
}

function cmpSimpleDiff(leftLines, rightLines, ignoreCase) {
  const norm = ignoreCase ? s => s.toLowerCase() : s => s;
  const maxLen = Math.max(leftLines.length, rightLines.length);
  const left = [], right = [];
  for (let i = 0; i < maxLen; i++) {
    const l = i < leftLines.length ? leftLines[i] : null;
    const r = i < rightLines.length ? rightLines[i] : null;
    if (l !== null && r !== null) {
      const same = norm(l) === norm(r);
      left.push({ text: l, type: same ? "same" : "chg", num: i + 1 });
      right.push({ text: r, type: same ? "same" : "chg", num: i + 1 });
    } else if (l !== null) {
      left.push({ text: l, type: "del", num: i + 1 });
      right.push({ text: "", type: "pad", num: "" });
    } else {
      left.push({ text: "", type: "pad", num: "" });
      right.push({ text: r, type: "add", num: i + 1 });
    }
  }
  return { left, right };
}

function cmpRenderDiff(pre, lines) {
  const frag = document.createDocumentFragment();
  for (const line of lines) {
    const div = document.createElement("div");
    if (line.type === "del") div.className = "cmp-line-del";
    else if (line.type === "add") div.className = "cmp-line-add";
    else if (line.type === "chg") div.className = "cmp-line-chg";
    else if (line.type === "pad") { div.textContent = "\u00A0"; frag.appendChild(div); continue; }

    const numSpan = document.createElement("span");
    numSpan.className = "cmp-line-num";
    numSpan.textContent = line.num || "";
    div.appendChild(numSpan);
    div.appendChild(document.createTextNode(line.text));
    frag.appendChild(div);
  }
  pre.appendChild(frag);
}

function cmpSwitchPane(side, section) {
  const container = document.getElementById(`cmp-${side}`);
  container.querySelectorAll(".cmp-sub-tabs .sub-tab").forEach(t => {
    const paneSection = t.dataset.cmppane.includes("resp") ? "resp" : "req";
    t.classList.toggle("active", paneSection === section);
  });
  container.querySelectorAll(".cmp-pane").forEach(p => {
    const isTarget = p.id === `cmp-${side}-${section}-pane`;
    p.classList.toggle("active", isTarget);
    p.classList.toggle("hidden", !isTarget);
  });
}

function cmpSwap() {
  const tmp = cmpLeft;
  cmpLeft = cmpRight;
  cmpRight = tmp;
  cmpRenderSide("left");
  cmpRenderSide("right");
}

function cmpClear() {
  cmpLeft = null; cmpRight = null;
  cmpRenderSide("left");
  cmpRenderSide("right");
}

// ═══════════════════════════ INIT ════════════════════════════════════════════

document.addEventListener("DOMContentLoaded", () => {

  // Helper: register init blocks safely — one failing block won't kill the rest
  function initBlock(name, fn) {
    try { fn(); } catch (e) { console.error(`[Void] init "${name}" failed:`, e); }
  }

  // ── Scoped Ctrl+A: select only the pane under the mouse ────────────────────
  let _hoveredPane = null;
  document.addEventListener("mouseover", e => {
    _hoveredPane = e.target.closest(".raw-pre, .raw-ta, .resp-pane");
  });
  document.addEventListener("keydown", e => {
    if (!e.ctrlKey && !e.metaKey) return;
    if (e.key === "a" && _hoveredPane) {
      e.preventDefault();
      const sel = window.getSelection();
      const range = document.createRange();
      // Select the innermost pre/textarea content
      const target = _hoveredPane.querySelector(".raw-pre") || _hoveredPane;
      if (target.tagName === "TEXTAREA") {
        target.focus();
        target.select();
      } else {
        range.selectNodeContents(target);
        sel.removeAllRanges();
        sel.addRange(range);
      }
    }
  });

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

  // Repeater history navigation
  document.getElementById("rep-hist-back").addEventListener("click", repHistBack);
  document.getElementById("rep-hist-fwd").addEventListener("click", repHistForward);

  // URL auto-size on all url inputs
  document.querySelectorAll(".url-inp").forEach(inp => {
    inp.addEventListener("input", () => autoSizeUrlInput(inp));
    autoSizeUrlInput(inp);
  });

  // Repeater tabs
  document.getElementById("rep-tab-add").addEventListener("click", addRepTab);
  renderRepTabs();

  // Response sub-tabs

  // History sortable columns + column filters
  document.querySelectorAll("#hist-table .hist-th-sortable").forEach(th =>
    th.addEventListener("click", e => {
      if (e.target.closest(".colfilter-ico") || e.target.closest(".colfilter-drop")) return;
      const key = th.dataset.sort;
      if (histSortKey === key) { histSortAsc = !histSortAsc; }
      else { histSortKey = key; histSortAsc = (key === "id" ? false : true); }
      renderHistory();
    })
  );
  colFilterInit("hist-table", () => historyData, (e, f) => {
    if (f === "mimeType") return shortMime(e.mimeType);
    if (f === "status") return String(e.status ?? "");
    return String(e[f] ?? "");
  }, histColFilters, renderHistory);

  // Headers: the two panes are now side by side, so the only control left is
  // whether the All Headers list folds in sub-resource responses.
  document.getElementById("hdr-show-all").addEventListener("change", renderHeaders);

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
    histColFilters = {};
    document.querySelectorAll("#hist-table .colfilter-drop").forEach(d => d.remove());
    document.querySelectorAll("#hist-table .colfilter-ico").forEach(i => i.classList.remove("active"));
    renderHistory();
    setBadge("bdg-history", 0);
  });
  document.getElementById("hist-reflect-only").addEventListener("change", e => {
    filterHistReflect = e.target.checked; renderHistory();
  });
  document.getElementById("hist-detail-close").addEventListener("click", closeHistDetail);
  document.getElementById("hist-detail-to-rep").addEventListener("click", histDetailToRepeater);

  // Per-pane search bars (history)
  histReqSearch = createPaneSearch(
    document.getElementById("hist-req-side"),
    document.getElementById("hist-req-search"),
    document.getElementById("hist-req-search-count")
  );
  histRespSearch = createPaneSearch(
    document.getElementById("hist-resp-side"),
    document.getElementById("hist-resp-search"),
    document.getElementById("hist-resp-search-count")
  );
  // Per-pane search bars (target detail)
  createPaneSearch(
    document.getElementById("tgt-req-side"),
    document.getElementById("tgt-req-search"),
    document.getElementById("tgt-req-search-count")
  );
  createPaneSearch(
    document.getElementById("tgt-resp-side"),
    document.getElementById("tgt-resp-search"),
    document.getElementById("tgt-resp-search-count")
  );
  // Per-pane search bars (endpoint detail)
  createPaneSearch(
    document.getElementById("ep-req-side"),
    document.getElementById("ep-req-search"),
    document.getElementById("ep-req-search-count")
  );
  createPaneSearch(
    document.getElementById("ep-resp-side"),
    document.getElementById("ep-resp-search"),
    document.getElementById("ep-resp-search-count")
  );
  // Per-pane search (repeater response)
  createPaneSearch(
    document.getElementById("rep-resp-pane"),
    document.getElementById("rep-resp-search"),
    document.getElementById("rep-resp-search-count")
  );
  // Per-pane search (intruder result detail)
  intrReqSearch = createPaneSearch(
    document.getElementById("intr-req-side"),
    document.getElementById("intr-req-search"),
    document.getElementById("intr-req-search-count")
  );
  intrRespSearch = createPaneSearch(
    document.getElementById("intr-resp-side"),
    document.getElementById("intr-resp-search"),
    document.getElementById("intr-resp-search-count")
  );

  // ── Reflection highlight bars ──────────────────────────────────────────────
  histReflectBar = createReflectBar("hist-reflect-hl", "hist-reflect-chips",
    () => [document.getElementById("hist-req-side"), document.getElementById("hist-resp-side")]);
  // Repeater's request side is a pair of editable <textarea>s, which cannot hold
  // <mark> nodes — the chip legend covers that side, the response is marked inline.
  repReflectBar = createReflectBar("rep-reflect-hl", "rep-reflect-chips",
    () => [document.getElementById("rep-resp-pane")]);
  intrReflectBar = createReflectBar("intr-reflect-hl", "intr-reflect-chips",
    () => [document.getElementById("intr-req-side"), document.getElementById("intr-resp-side")]);

  // ── Intruder result detail ─────────────────────────────────────────────────
  document.getElementById("intr-detail-close").addEventListener("click", intrCloseDetail);
  document.getElementById("intr-detail-to-rep").addEventListener("click", () => {
    if (!intrDetailEntry) return;
    sendToRepeater({
      method:     intrDetailEntry.reqMethod || "GET",
      url:        intrDetailEntry.reqUrl || "",
      rawHeaders: intrDetailEntry.reqHeaders || "",
      body:       intrDetailEntry.reqBody || "",
    });
  });

  document.getElementById("hist-detail-to-intr").addEventListener("click", () => {
    if (!histDetailEntry) return;
    intrSendToIntruder({
      method: histDetailEntry.method,
      url: histDetailEntry.url,
      headers: histDetailEntry.headers || {},
      body: histDetailEntry.body || "",
    });
  });
  document.getElementById("hist-detail-open").addEventListener("click", () => {
    if (histDetailEntry?.url) chrome.tabs.create({ url: histDetailEntry.url });
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
    if (proxyPending.length) { proxySend({ type: "forwardAll" }); proxyPending = []; }
    const ids = intercepted.map(r => r.requestId);
    intercepted = [];
    await Promise.all(ids.map(id => bg({ type: "FORWARD", requestId: id, overrides: {} })));
    renderInterceptList();
  });

  // Editor buttons
  document.getElementById("ed-back").addEventListener("click",    closeEditor);
  // ── External proxy toggle ─────────────────────────────────────────────────
  document.getElementById("btn-proxy").addEventListener("click", () => {
    const connected = proxyWs && proxyWs.readyState === 1;
    if (!connected) {
      document.getElementById("proxy-bar").classList.remove("hidden");
      proxyConnect();
    } else if (!proxyIntercepting) {
      proxySend({ type: "intercept", on: true });
    } else {
      proxySend({ type: "intercept", on: false });
      proxyDisconnect();
    }
    proxyUpdateUI();
  });
  document.getElementById("proxy-copy").addEventListener("click", () => {
    const hint = document.getElementById("proxy-hint").textContent;
    if (hint) navigator.clipboard.writeText(hint).catch(() => {});
  });

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
    renderEndpoints();
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

  // Target detail pane handlers
  document.getElementById("tgt-detail-close").addEventListener("click", closeTgtDetail);
  document.getElementById("tgt-detail-to-rep").addEventListener("click", () => {
    if (!tgtDetailEntry) return;
    sendToRepeater({ method: tgtDetailEntry.method, url: tgtDetailEntry.url, headers: tgtDetailEntry.headers || {}, body: tgtDetailEntry.body || "" });
  });
  document.getElementById("tgt-detail-to-intr").addEventListener("click", () => {
    if (!tgtDetailEntry) return;
    intrSendToIntruder({ method: tgtDetailEntry.method, url: tgtDetailEntry.url, headers: tgtDetailEntry.headers || {}, body: tgtDetailEntry.body || "" });
  });

  // Endpoint detail pane handlers
  document.getElementById("ep-detail-close").addEventListener("click", closeEpDetail);
  document.getElementById("ep-detail-to-rep").addEventListener("click", () => {
    if (!epDetailEntry) return;
    const h = historyData.find(he => he.url === epDetailEntry.url) || epDetailEntry;
    sendToRepeater({ method: h.method || epDetailEntry.method || "GET", url: epDetailEntry.url, headers: h.headers || {}, body: h.body || "" });
  });
  document.getElementById("ep-detail-to-intr").addEventListener("click", () => {
    if (!epDetailEntry) return;
    const h = historyData.find(he => he.url === epDetailEntry.url) || epDetailEntry;
    intrSendToIntruder({ method: h.method || epDetailEntry.method || "GET", url: epDetailEntry.url, headers: h.headers || {}, body: h.body || "" });
  });

  // Target detail resizer
  (function() {
    const handle = document.getElementById("tgt-detail-resizer");
    const pane   = document.getElementById("tgt-table-pane");
    let dragging = false, startX = 0, startW = 0;
    handle.addEventListener("mousedown", e => {
      dragging = true; startX = e.clientX; startW = pane.getBoundingClientRect().width;
      document.body.style.userSelect = "none"; document.body.style.cursor = "col-resize";
    });
    document.addEventListener("mousemove", e => {
      if (!dragging) return;
      pane.style.flex = "none";
      pane.style.width = Math.max(200, startW + e.clientX - startX) + "px";
    });
    document.addEventListener("mouseup", () => {
      if (!dragging) return;
      dragging = false; document.body.style.userSelect = ""; document.body.style.cursor = "";
    });
  })();

  // Endpoint split resizer
  (function() {
    const handle = document.getElementById("ep-resizer");
    const left   = document.getElementById("ep-split-left");
    let dragging = false, startX = 0, startW = 0;
    handle.addEventListener("mousedown", e => {
      dragging = true; startX = e.clientX; startW = left.getBoundingClientRect().width;
      document.body.style.userSelect = "none"; document.body.style.cursor = "col-resize";
    });
    document.addEventListener("mousemove", e => {
      if (!dragging) return;
      left.style.flex = "none";
      left.style.width = Math.max(200, startW + e.clientX - startX) + "px";
    });
    document.addEventListener("mouseup", () => {
      if (!dragging) return;
      dragging = false; document.body.style.userSelect = ""; document.body.style.cursor = "";
    });
  })();

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

  // Intercept split resizer
  (function() {
    const handle = document.getElementById("ic-resizer");
    const left   = document.getElementById("ic-split-left");
    let dragging = false, startX = 0, startW = 0;
    handle.addEventListener("mousedown", e => {
      dragging = true; startX = e.clientX; startW = left.getBoundingClientRect().width;
      document.body.style.userSelect = "none"; document.body.style.cursor = "col-resize";
    });
    document.addEventListener("mousemove", e => {
      if (!dragging) return;
      left.style.flex = "none";
      left.style.width = Math.max(200, startW + e.clientX - startX) + "px";
    });
    document.addEventListener("mouseup", () => {
      if (!dragging) return;
      dragging = false; document.body.style.userSelect = ""; document.body.style.cursor = "";
    });
  })();

  // History split resizer
  (function() {
    const handle = document.getElementById("hist-resizer");
    const left   = document.getElementById("hist-split-left");
    let dragging = false, startX = 0, startW = 0;
    handle.addEventListener("mousedown", e => {
      dragging = true; startX = e.clientX; startW = left.getBoundingClientRect().width;
      document.body.style.userSelect = "none"; document.body.style.cursor = "col-resize";
    });
    document.addEventListener("mousemove", e => {
      if (!dragging) return;
      left.style.flex = "none";
      left.style.width = Math.max(200, startW + e.clientX - startX) + "px";
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
    setFieldValue(ta, intrStripPositions(ta.value)); // undoable
    intrCountPositions();
  });

  // ── Cross-send between Repeater and Intruder ───────────────────────────────
  document.getElementById("rep-to-intr").addEventListener("click", () => {
    intrSendToIntruder({
      method:     document.getElementById("rep-method").value,
      url:        document.getElementById("rep-url").value.trim(),
      rawHeaders: document.getElementById("rep-headers").value,
      body:       document.getElementById("rep-body-ta").value,
    });
  });
  document.getElementById("intr-to-rep").addEventListener("click", () => {
    const parsed = intrParseRaw(
      intrStripPositions(document.getElementById("intr-request").value),
      document.getElementById("intr-method").value,
      document.getElementById("intr-url").value.trim()
    );
    sendToRepeater({
      method:     parsed.method,
      url:        parsed.url,
      rawHeaders: parsed.headers,
      body:       parsed.body,
    });
  });
  document.getElementById("intr-reflect-only").addEventListener("change", e => {
    intrReflectOnly = e.target.checked;
    intrRenderResults();
  });
  document.getElementById("intr-start").addEventListener("click", intrStart);
  document.getElementById("intr-stop").addEventListener("click", intrStop);
  // Intruder sortable columns
  document.querySelectorAll("#intr-table .hist-th-sortable").forEach(th => {
    th.addEventListener("click", e => {
      if (e.target.closest(".colfilter-ico") || e.target.closest(".colfilter-drop")) return;
      const key = th.dataset.intrsort;
      if (intrSortKey === key) { intrSortAsc = !intrSortAsc; }
      else { intrSortKey = key; intrSortAsc = true; }
      intrRenderResults();
    });
  });
  colFilterInit("intr-table", () => intrResults, (e, f) => String(e[f] ?? ""), intrColFilters, intrRenderResults);

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
  // Auto Headers preset dropdown
  document.getElementById("cfg-hdr-preset").addEventListener("change", e => {
    const val = e.target.value;
    if (!val) return;
    const ta = document.getElementById("cfg-auto-headers");
    const hdrName = val.split(":")[0].toLowerCase();
    // Replace existing header with same name, or append
    const lines = ta.value.split("\n").filter(l => l.trim());
    const idx = lines.findIndex(l => l.toLowerCase().startsWith(hdrName + ":"));
    if (idx >= 0) { lines[idx] = val; } else { lines.push(val); }
    ta.value = lines.join("\n");
    e.target.value = ""; // reset dropdown
  });

  document.getElementById("cfg-save").addEventListener("click", saveSettings);
  document.getElementById("cfg-reset").addEventListener("click", () => {
    settings = { ...DEFAULT_SETTINGS };
    loadSettingsUI();
    saveSettings();
  });

  // Session management (Project → Session tab)
  initBlock("session", () => {
    document.getElementById("session-save").addEventListener("click", saveSessionToBrowser);
    document.getElementById("session-export").addEventListener("click", exportSession);
    document.getElementById("session-import").addEventListener("click", () => {
      document.getElementById("session-file").click();
    });
    document.getElementById("session-file").addEventListener("change", e => {
      const file = e.target.files[0];
      if (file) importSessionFile(file);
      e.target.value = "";
    });
    document.getElementById("session-config-load").addEventListener("click", loadSelectedSession);
    document.getElementById("session-config-del").addEventListener("click", deleteSelectedSession);
    refreshSessionList();
  });

  // ── Logger ─────────────────────────────────────────────────────────────────
  initBlock("logger", () => {
    document.getElementById("log-filter").addEventListener("input", e => { logFilterText = e.target.value; logRender(); });
    document.getElementById("log-flt-method").addEventListener("change", e => { logFilterMeth = e.target.value; logRender(); });
    document.getElementById("log-flt-status").addEventListener("change", e => { logFilterStat = e.target.value; logRender(); });
    document.getElementById("log-flt-source").addEventListener("change", e => { logFilterSource = e.target.value; logRender(); });
    document.getElementById("log-scope-only").addEventListener("change", e => { logScopeOnly = e.target.checked; logRender(); });
    // Sync toggle: connect/disconnect WebSocket to sync server
    document.getElementById("log-sync").addEventListener("click", () => {
      if (logSyncWs && logSyncWs.readyState <= 1) {
        logSyncDisconnect();
      } else {
        logSyncConnect();
      }
    });
    document.getElementById("log-merge").addEventListener("click", () => document.getElementById("log-merge-file").click());
    document.getElementById("log-merge-file").addEventListener("change", async e => {
      for (const file of e.target.files) await logImportFile(file);
      e.target.value = "";
      logRender();
    });
    document.getElementById("log-export").addEventListener("click", logExport);
    document.getElementById("log-clear").addEventListener("click", () => { logEntries = []; logNextId = 1; logRender(); logCloseDetail(); });
    document.getElementById("log-detail-close").addEventListener("click", logCloseDetail);
    document.getElementById("log-detail-to-rep").addEventListener("click", () => {
      if (!logDetailEntry) return;
      sendToRepeater({ method: logDetailEntry.method, url: logDetailEntry.url, headers: logDetailEntry.headers||{}, body: logDetailEntry.body||"" });
    });
    document.getElementById("log-detail-to-intr").addEventListener("click", () => {
      if (!logDetailEntry) return;
      intrSendToIntruder({ method: logDetailEntry.method, url: logDetailEntry.url, headers: logDetailEntry.headers||{}, body: logDetailEntry.body||"" });
    });
    document.getElementById("log-detail-open").addEventListener("click", () => {
      if (logDetailEntry?.url) chrome.tabs.create({ url: logDetailEntry.url });
    });
    document.querySelectorAll("#log-table .hist-th-sortable").forEach(th => {
      th.addEventListener("click", e => {
        if (e.target.closest(".colfilter-ico") || e.target.closest(".colfilter-drop")) return;
        const key = th.dataset.logsort;
        if (logSortKey === key) logSortAsc = !logSortAsc;
        else { logSortKey = key; logSortAsc = key === "id" ? false : true; }
        logRender();
      });
    });
    colFilterInit("log-table", () => logEntries, (e, f) => {
      if (f === "source") return e._logLabel || "";
      if (f === "status") return String(e.status ?? "");
      return String(e[f] ?? "");
    }, logColFilters, logRender);
    createPaneSearch(document.getElementById("log-req-side"), document.getElementById("log-req-search"), document.getElementById("log-req-search-count"));
    createPaneSearch(document.getElementById("log-resp-side"), document.getElementById("log-resp-search"), document.getElementById("log-resp-search-count"));
    // Resizer
    (function() {
      const handle = document.getElementById("log-resizer"), left = document.getElementById("log-split-left");
      let dragging = false, startX = 0, startW = 0;
      handle.addEventListener("mousedown", e => { dragging = true; startX = e.clientX; startW = left.getBoundingClientRect().width; document.body.style.userSelect = "none"; document.body.style.cursor = "col-resize"; });
      document.addEventListener("mousemove", e => { if (!dragging) return; left.style.flex = "none"; left.style.width = Math.max(200, startW + e.clientX - startX) + "px"; });
      document.addEventListener("mouseup", () => { if (!dragging) return; dragging = false; document.body.style.userSelect = ""; document.body.style.cursor = ""; });
    })();
  });

  // ── Sensitive Discoverer ────────────────────────────────────────────────────
  initBlock("sensitive", () => {
    document.getElementById("sens-scan").addEventListener("click", sensScan);
    document.getElementById("sens-clear").addEventListener("click", () => {
      sensFindings = [];
      sensRender();
      setBadge("bdg-sensitive", 0);
    });
    document.getElementById("sens-export").addEventListener("click", sensExportCSV);
    document.getElementById("sens-scope-only").addEventListener("change", e => { sensScopeOnly = e.target.checked; });
    document.getElementById("sens-flt-cat").addEventListener("change", e => { sensFilterCat = e.target.value; sensRender(); });
    document.getElementById("sens-flt-sev").addEventListener("change", e => { sensFilterSev = e.target.value; sensRender(); });
    document.getElementById("sens-filter").addEventListener("input", e => { sensFilterText = e.target.value; sensRender(); });
    // Sortable columns (skip if clicking filter icon)
    document.querySelectorAll("#sens-table .hist-th-sortable").forEach(th => {
      th.addEventListener("click", e => {
        if (e.target.closest(".colfilter-ico") || e.target.closest(".colfilter-drop")) return;
        const key = th.dataset.senssort;
        if (sensSortKey === key) { sensSortAsc = !sensSortAsc; }
        else { sensSortKey = key; sensSortAsc = key === "severity"; }
        sensRender();
      });
    });
    // Column filter dropdowns
    colFilterInit("sens-table",
      () => sensFindings,
      (f, field) => f[field],
      sensColFilters,
      () => sensRender()
    );
    document.getElementById("sens-custom-toggle").addEventListener("click", () => {
      const panel = document.getElementById("sens-custom");
      const btn = document.getElementById("sens-custom-toggle");
      const hidden = panel.classList.toggle("hidden");
      btn.textContent = hidden ? "Custom Rules \u25B8" : "Custom Rules \u25BE";
    });
    document.getElementById("sens-custom-add").addEventListener("click", sensAddCustomRule);
    // Detail pane
    document.getElementById("sens-detail-close").addEventListener("click", sensCloseDetail);
    document.getElementById("sens-detail-to-rep").addEventListener("click", () => {
      if (!sensDetailEntry) return;
      sendToRepeater({ method: sensDetailEntry.method, url: sensDetailEntry.url, headers: sensDetailEntry.headers || {}, body: sensDetailEntry.body || "" });
    });
    document.getElementById("sens-detail-to-intr").addEventListener("click", () => {
      if (!sensDetailEntry) return;
      intrSendToIntruder({ method: sensDetailEntry.method, url: sensDetailEntry.url, headers: sensDetailEntry.headers || {}, body: sensDetailEntry.body || "" });
    });
    document.getElementById("sens-detail-open").addEventListener("click", () => {
      if (sensDetailEntry?.url) chrome.tabs.create({ url: sensDetailEntry.url });
    });
    // Search bars (store refs for auto-search on finding click)
    sensReqSearch = createPaneSearch(
      document.getElementById("sens-req-side"),
      document.getElementById("sens-req-search"),
      document.getElementById("sens-req-search-count")
    );
    sensRespSearch = createPaneSearch(
      document.getElementById("sens-resp-side"),
      document.getElementById("sens-resp-search"),
      document.getElementById("sens-resp-search-count")
    );
    // Resizer
    (function() {
      const handle = document.getElementById("sens-resizer");
      const left = document.getElementById("sens-split-left");
      let dragging = false, startX = 0, startW = 0;
      handle.addEventListener("mousedown", e => {
        dragging = true; startX = e.clientX; startW = left.getBoundingClientRect().width;
        document.body.style.userSelect = "none"; document.body.style.cursor = "col-resize";
      });
      document.addEventListener("mousemove", e => {
        if (!dragging) return;
        left.style.flex = "none";
        left.style.width = Math.max(200, startW + e.clientX - startX) + "px";
      });
      document.addEventListener("mouseup", () => {
        if (!dragging) return;
        dragging = false; document.body.style.userSelect = ""; document.body.style.cursor = "";
      });
    })();
    sensLoadCustomRules();
  });

  // ── Containers ──────────────────────────────────────────────────────────────
  initBlock("containers", () => {
    document.getElementById("cnt-add").addEventListener("click", () => cntShowForm(null));
    document.getElementById("cnt-form-save").addEventListener("click", cntSaveForm);
    document.getElementById("cnt-form-cancel").addEventListener("click", cntHideForm);
    document.querySelectorAll("#cnt-colors .cnt-color-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        document.querySelectorAll("#cnt-colors .cnt-color-btn").forEach(b => b.classList.remove("active"));
        btn.classList.add("active");
      });
    });
    document.getElementById("cnt-ext-path-save").addEventListener("click", () => {
      cntExtPath = document.getElementById("cnt-ext-path").value.trim();
      saveContainers();
    });
    // Register this instance as a container (run in container windows)
    document.getElementById("cnt-register-save").addEventListener("click", () => {
      const name = document.getElementById("cnt-register-name").value.trim();
      if (!name) return;
      chrome.storage.local.set({ voidContainerName: name });
      // Trigger immediate export
      bg({ type: "CNT_AUTO_EXPORT", name });
      document.getElementById("cnt-register-name").placeholder = `Registered as "${name}" — syncing`;
    });
    // Load current registration
    chrome.storage.local.get("voidContainerName", r => {
      if (r.voidContainerName) {
        document.getElementById("cnt-register-name").value = r.voidContainerName;
        document.getElementById("cnt-register-name").placeholder = `Registered as "${r.voidContainerName}"`;
      }
    });
    loadContainers().then(() => {
      const inp = document.getElementById("cnt-ext-path");
      if (!cntExtPath) {
        // Auto-detect: try to get the extension's install path
        // chrome.runtime.getURL gives us the extension URL; on --load-extension installs
        // the ID is derived from the disk path, but we can't reverse it.
        // Best we can do: suggest common paths based on OS
        const os = cntDetectOS();
        const hint = os === "win" ? "C:\\tmp\\void-extension" : "~/void-extension";
        inp.placeholder = hint + " — REQUIRED for containers to load the extension";
        inp.value = hint;
        cntExtPath = hint;
        saveContainers();
      } else {
        inp.value = cntExtPath;
      }
      renderContainers();
    });
  });

  // ── Probe tab ───────────────────────────────────────────────────────────────
  initBlock("probe", () => {
  document.getElementById("probe-scan").addEventListener("click", probeScan);
  document.getElementById("probe-ctrl-only").addEventListener("change", () => {
    if (probeFindingsData) { probeRenderSources(probeFindingsData.sources); probeRenderFlows(probeFindingsData.flows); }
  });
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

  }); // end initBlock("probe")

  // ── Comparer ──────────────────────────────────────────────────────────────
  initBlock("comparer", () => {
    document.getElementById("cmp-diff").addEventListener("click", cmpDoDiff);
    document.getElementById("cmp-swap").addEventListener("click", cmpSwap);
    document.getElementById("cmp-clear").addEventListener("click", cmpClear);

    // Sub-tab switching (left/right × req/resp)
    document.querySelectorAll(".cmp-sub-tabs .sub-tab[data-cmppane]").forEach(t => {
      t.addEventListener("click", () => {
        const pane = t.dataset.cmppane;
        const side = pane.startsWith("left") ? "left" : "right";
        const section = pane.includes("resp") ? "resp" : "req";
        cmpSwitchPane(side, section);
      });
    });

    // Resizer
    (function() {
      const handle = document.getElementById("cmp-resizer");
      const left = document.getElementById("cmp-left");
      let dragging = false, startX = 0, startW = 0;
      handle.addEventListener("mousedown", e => {
        dragging = true; startX = e.clientX; startW = left.getBoundingClientRect().width;
        document.body.style.userSelect = "none"; document.body.style.cursor = "col-resize";
      });
      document.addEventListener("mousemove", e => {
        if (!dragging) return;
        left.style.flex = "none";
        left.style.width = Math.max(200, startW + e.clientX - startX) + "px";
      });
      document.addEventListener("mouseup", () => {
        if (!dragging) return;
        dragging = false; document.body.style.userSelect = ""; document.body.style.cursor = "";
      });
    })();

    // "→ Cmp L/R" buttons from History detail
    document.getElementById("hist-detail-cmp-l").addEventListener("click", () => { if (histDetailEntry) cmpSendTo("left", histDetailEntry); });
    document.getElementById("hist-detail-cmp-r").addEventListener("click", () => { if (histDetailEntry) cmpSendTo("right", histDetailEntry); });

    // "→ Cmp L/R" from Logger detail
    document.getElementById("log-detail-cmp-l").addEventListener("click", () => { if (logDetailEntry) cmpSendTo("left", logDetailEntry); });
    document.getElementById("log-detail-cmp-r").addEventListener("click", () => { if (logDetailEntry) cmpSendTo("right", logDetailEntry); });

    // "→ Cmp L/R" from Sensitive detail
    document.getElementById("sens-detail-cmp-l").addEventListener("click", () => { if (sensDetailEntry) cmpSendTo("left", sensDetailEntry); });
    document.getElementById("sens-detail-cmp-r").addEventListener("click", () => { if (sensDetailEntry) cmpSendTo("right", sensDetailEntry); });

    // "→ Cmp L/R" from Target detail
    document.getElementById("tgt-detail-cmp-l").addEventListener("click", () => { if (tgtDetailEntry) cmpSendTo("left", tgtDetailEntry); });
    document.getElementById("tgt-detail-cmp-r").addEventListener("click", () => { if (tgtDetailEntry) cmpSendTo("right", tgtDetailEntry); });

    // "→ Cmp L/R" from Endpoint detail
    document.getElementById("ep-detail-cmp-l").addEventListener("click", () => {
      if (!epDetailEntry) return;
      const h = historyData.find(he => he.url === epDetailEntry.url) || epDetailEntry;
      cmpSendTo("left", h);
    });
    document.getElementById("ep-detail-cmp-r").addEventListener("click", () => {
      if (!epDetailEntry) return;
      const h = historyData.find(he => he.url === epDetailEntry.url) || epDetailEntry;
      cmpSendTo("right", h);
    });
  });

  // ── WebSocket History ────────────────────────────────────────────────────
  initBlock("ws", () => {
    document.getElementById("ws-filter").addEventListener("input", e => { wsFilterText = e.target.value; renderWsHistory(); });
    document.getElementById("ws-flt-dir").addEventListener("change", e => { wsFilterDir = e.target.value; renderWsHistory(); });
    document.getElementById("ws-flt-type").addEventListener("change", e => { wsFilterType = e.target.value; renderWsHistory(); });
    document.getElementById("ws-flt-conn").addEventListener("change", e => { wsFilterConn = e.target.value; renderWsHistory(); });
    document.getElementById("ws-clear").addEventListener("click", () => { wsFrames = []; wsConnections = {}; renderWsHistory(); setBadge("bdg-ws", 0); });
    document.getElementById("ws-detail-close").addEventListener("click", wsCloseDetail);
    document.querySelectorAll("#ws-table .hist-th-sortable").forEach(th => {
      th.addEventListener("click", () => {
        const key = th.dataset.wssort;
        if (wsSortKey === key) wsSortAsc = !wsSortAsc; else { wsSortKey = key; wsSortAsc = true; }
        renderWsHistory();
      });
    });
    (function() {
      const handle = document.getElementById("ws-resizer");
      const left = document.getElementById("ws-split-left");
      let dragging = false, startX = 0, startW = 0;
      handle.addEventListener("mousedown", e => { dragging = true; startX = e.clientX; startW = left.getBoundingClientRect().width; document.body.style.userSelect = "none"; document.body.style.cursor = "col-resize"; });
      document.addEventListener("mousemove", e => { if (!dragging) return; left.style.flex = "none"; left.style.width = Math.max(200, startW + e.clientX - startX) + "px"; });
      document.addEventListener("mouseup", () => { if (!dragging) return; dragging = false; document.body.style.userSelect = ""; document.body.style.cursor = ""; });
    })();
    document.getElementById("ws-detail-cmp-l").addEventListener("click", () => {
      if (!wsDetailFrame) return;
      cmpSendTo("left", { method: "WS", url: wsDetailFrame.url, host: "", path: "", headers: {}, body: wsDetailFrame.data, status: null, respHeaders: {}, respBody: "" });
    });
    document.getElementById("ws-detail-cmp-r").addEventListener("click", () => {
      if (!wsDetailFrame) return;
      cmpSendTo("right", { method: "WS", url: wsDetailFrame.url, host: "", path: "", headers: {}, body: wsDetailFrame.data, status: null, respHeaders: {}, respBody: "" });
    });
  });

  // ── PoC Generator ───────────────────────────────────────────────────
  initBlock("poc", () => {
    // Sub-tab switching
    document.querySelectorAll(".poc-sub-bar .sub-tab[data-pocsub]").forEach(t => {
      t.addEventListener("click", () => {
        document.querySelectorAll(".poc-sub-bar .sub-tab").forEach(s => s.classList.remove("active"));
        t.classList.add("active");
        document.querySelectorAll(".poc-sub-panel").forEach(p => { p.classList.remove("active"); p.classList.add("hidden"); });
        const panel = document.getElementById("poc-" + t.dataset.pocsub);
        panel.classList.add("active"); panel.classList.remove("hidden");
      });
    });

    // CSRF
    document.getElementById("poc-csrf-generate").addEventListener("click", pocCsrfGenerate);
    document.getElementById("poc-csrf-copy").addEventListener("click", () => pocCopy("poc-csrf-code"));
    document.getElementById("poc-csrf-download").addEventListener("click", () => pocDownload("poc-csrf-code", "csrf-poc.html"));
    // Re-generate on technique/evasion change
    document.getElementById("poc-csrf-technique").addEventListener("change", pocCsrfGenerate);
    ["poc-csrf-autosubmit", "poc-csrf-no-referrer", "poc-csrf-strip-token", "poc-csrf-sandbox"].forEach(id => {
      document.getElementById(id).addEventListener("change", pocCsrfGenerate);
    });

    // Clickjacking
    document.getElementById("poc-cj-generate").addEventListener("click", pocCjGenerate);
    document.getElementById("poc-cj-copy").addEventListener("click", () => pocCopy("poc-cj-code"));
    document.getElementById("poc-cj-download").addEventListener("click", () => pocDownload("poc-cj-code", "clickjacking-poc.html"));
    // Show/hide step 2 for multistep
    document.getElementById("poc-cj-technique").addEventListener("change", () => {
      document.getElementById("poc-cj-step2").classList.toggle("hidden", document.getElementById("poc-cj-technique").value !== "multistep");
    });

    // → PoC buttons from all detail panes
    document.getElementById("hist-detail-poc").addEventListener("click", () => { if (histDetailEntry) pocLoadEntry(histDetailEntry); });
    document.getElementById("log-detail-poc").addEventListener("click", () => { if (logDetailEntry) pocLoadEntry(logDetailEntry); });
    document.getElementById("sens-detail-poc").addEventListener("click", () => { if (sensDetailEntry) pocLoadEntry(sensDetailEntry); });
    document.getElementById("tgt-detail-poc").addEventListener("click", () => { if (tgtDetailEntry) pocLoadEntry(tgtDetailEntry); });
    document.getElementById("ep-detail-poc").addEventListener("click", () => {
      if (!epDetailEntry) return;
      const h = historyData.find(he => he.url === epDetailEntry.url) || epDetailEntry;
      pocLoadEntry(h);
    });
    document.getElementById("intr-detail-poc").addEventListener("click", () => {
      const sel = document.querySelector("#intr-results tr.hist-selected");
      if (sel && sel._intrResult) pocLoadEntry(sel._intrResult);
    });
  });

  // ── Sequencer ──────────────────────────────────────────────────────────
  initBlock("sequencer", () => {
    document.getElementById("seq-start").addEventListener("click", seqStartCollection);
    document.getElementById("seq-stop").addEventListener("click", seqStopCollection);
    document.getElementById("seq-from-hist").addEventListener("click", seqFromHistory);
    document.getElementById("seq-export").addEventListener("click", seqExport);
  });

  // ── Notes ──────────────────────────────────────────────────────────────
  initBlock("notes", () => {
    notesLoad();
    document.getElementById("notes-filter").addEventListener("input", e => { notesFilterText = e.target.value; notesRender(); });
    document.getElementById("notes-flt-sev").addEventListener("change", e => { notesFilterSev = e.target.value; notesRender(); });
    document.getElementById("notes-flt-host").addEventListener("change", e => { notesFilterHost = e.target.value; notesRender(); });
    document.getElementById("notes-add").addEventListener("click", () => { notesCancelForm(); document.getElementById("notes-form").classList.remove("hidden"); });
    document.getElementById("notes-form-save").addEventListener("click", notesSaveForm);
    document.getElementById("notes-form-cancel").addEventListener("click", notesCancelForm);
    document.getElementById("notes-export").addEventListener("click", notesExport);
    document.getElementById("notes-clear").addEventListener("click", () => { notes = []; notesRender(); notesSave(); setBadge("bdg-notes", 0); });
    document.getElementById("hist-detail-notes").addEventListener("click", () => { if (histDetailEntry) notesFromEntry(histDetailEntry); });
    document.getElementById("log-detail-notes").addEventListener("click", () => { if (logDetailEntry) notesFromEntry(logDetailEntry); });
    document.getElementById("sens-detail-notes").addEventListener("click", () => { if (sensDetailEntry) notesFromEntry(sensDetailEntry); });
    document.getElementById("tgt-detail-notes").addEventListener("click", () => { if (tgtDetailEntry) notesFromEntry(tgtDetailEntry); });
    document.getElementById("ep-detail-notes").addEventListener("click", () => {
      if (!epDetailEntry) return;
      const h = historyData.find(he => he.url === epDetailEntry.url) || epDetailEntry;
      notesFromEntry(h);
    });
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

  // startPoll is called by showTab("intercept") — don't start it unconditionally
});
