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
let filterEp    = "";
let filterEpType = "";
let activeSubResp = "body";

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
  if (name === "tech") {
    const host = document.getElementById("site-host").textContent;
    const lbl  = document.getElementById("tech-domain-label");
    if (lbl) lbl.textContent = host || "—";
  }
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

// ── Load all data ─────────────────────────────────────────────────────────────
async function loadAll() {
  // Wake SW first, then inject content script
  await wakeSW();
  try { await chrome.scripting.executeScript({ target: { tabId: TAB_ID }, files: ["content.js"] }); } catch {}
  await new Promise(r => setTimeout(r, 400));

  const [d, ic] = await Promise.all([
    bg({ type: "GET_DATA" }),
    bg({ type: "GET_INTERCEPTED" }),
  ]);

  if (d) {
    state = { ...state, ...d };
    chrome.tabs.get(TAB_ID, tab => {
      try { document.getElementById("site-host").textContent = new URL(tab.url).hostname; } catch {}
    });
  }
  if (ic) intercepted = ic.requests || [];

  renderInterceptStatus();
  renderInterceptList();
  renderEndpoints();
  renderTech();
  renderHeaders();
  updateBadges();
}

// ── Badges ────────────────────────────────────────────────────────────────────
function updateBadges() {
  updateInterceptBadge();
  setBadge("bdg-endpoints", state.endpoints.length);
  setBadge("bdg-tech",      state.technologies.length);
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
    const btnFwd  = txt("button", "btn btn-xs btn-success", "Forward →");
    const btnDrop = txt("button", "btn btn-xs btn-danger",  "Drop");

    btnEdit.addEventListener("click", e => { e.stopPropagation(); openEditor(req); });
    btnRep.addEventListener("click",  e => { e.stopPropagation(); sendToRepeater(req); });
    btnFwd.addEventListener("click",  e => { e.stopPropagation(); doForward(req.requestId, null); });
    btnDrop.addEventListener("click", e => { e.stopPropagation(); doDrop(req.requestId); });

    ap(acts, btnEdit, btnRep, btnFwd, btnDrop);
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

// ── Send to Repeater ──────────────────────────────────────────────────────────
function sendToRepeater(req) {
  const method = req.method || "GET";
  const url    = req.url    || "";
  const rawHdrs = req.rawHeaders || headersToRaw(req.headers || {});
  const body   = req.body   || "";

  // set method
  const mSel = document.getElementById("rep-method");
  for (const o of mSel.options) { if (o.value === method) { o.selected = true; break; } }

  document.getElementById("rep-url").value     = url;
  document.getElementById("rep-headers").value = rawHdrs;
  document.getElementById("rep-body-ta").value = body;

  showTab("repeater");
}

// ═══════════════════════════ REPEATER ════════════════════════════════════════

async function doSend() {
  const method     = document.getElementById("rep-method").value;
  const url        = document.getElementById("rep-url").value.trim();
  const rawHeaders = document.getElementById("rep-headers").value;
  const body       = document.getElementById("rep-body-ta").value;

  if (!url) { document.getElementById("rep-url").focus(); return; }

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

  const res = await bg({ type: "SEND_REQUEST", url, method, rawHeaders, body });

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
  document.querySelectorAll(".sub-tab").forEach(t => t.classList.toggle("active", t.dataset.resp === name));
  document.querySelectorAll(".resp-pane").forEach(p => {
    p.classList.toggle("active", p.id === `resp-pane-${name}`);
    p.classList.toggle("hidden", p.id !== `resp-pane-${name}`);
  });
}

// Resizable split pane
function initResizer() {
  const handle   = document.getElementById("rep-resizer");
  const reqPane  = document.getElementById("rep-req-pane");
  const repBody  = document.querySelector(".rep-body");
  let dragging = false, startY = 0, startH = 0;

  handle.addEventListener("mousedown", e => {
    dragging = true;
    startY   = e.clientY;
    startH   = reqPane.getBoundingClientRect().height;
    document.body.style.userSelect = "none";
    document.body.style.cursor     = "row-resize";
  });
  document.addEventListener("mousemove", e => {
    if (!dragging) return;
    const total = repBody.getBoundingClientRect().height;
    const newH  = Math.max(80, Math.min(total - 80, startH + e.clientY - startY));
    reqPane.style.flex   = "none";
    reqPane.style.height = `${newH}px`;
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
    repBtn.addEventListener("click", () => sendToRepeater(ep));

    ap(acts, cpyBtn, repBtn);
    row.appendChild(acts);
    list.appendChild(row);
  });
}

// ═══════════════════════════ TECH ════════════════════════════════════════════

// Category display order
const CAT_ORDER = [
  "Miscellaneous", "Web Server", "Hosting", "Programming Language",
  "Frontend Framework", "Meta-Framework", "Framework", "CMS", "Website Builder",
  "Headless CMS", "E-commerce", "CDN / Security", "CDN", "Cloud", "Cache",
  "Security", "Auth / IAM", "Backend-as-a-Service", "Analytics", "Monitoring",
  "Customer Support", "Payment", "CSS Framework", "CSS-in-JS", "UI Library",
  "Build Tool", "JavaScript Library", "Realtime", "Maps", "Data Viz", "3D/WebGL",
  "Rich Text Editor", "API Protocol", "Database", "Video Player", "Icon Library",
  "Font Service", "SEO", "Form Builder", "Email", "WordPress Plugin",
  "LMS", "Membership", "Forum", "Community", "Performance", "Other",
];

// Category accent colour (card top-border + header text)
const CAT_COLORS = {
  "Miscellaneous":         "#8b949e",
  "Web Server":            "#58a6ff",
  "Hosting":               "#3fb950",
  "Programming Language":  "#bc8cff",
  "Frontend Framework":    "#79c0ff",
  "Meta-Framework":        "#79c0ff",
  "Framework":             "#e3b341",
  "CMS":                   "#d2a8ff",
  "Website Builder":       "#d2a8ff",
  "Headless CMS":          "#d2a8ff",
  "E-commerce":            "#3fb950",
  "CDN / Security":        "#f85149",
  "CDN":                   "#f0883e",
  "Cloud":                 "#58a6ff",
  "Cache":                 "#e3b341",
  "Security":              "#f85149",
  "Auth / IAM":            "#bc8cff",
  "Backend-as-a-Service":  "#58a6ff",
  "Analytics":             "#e3b341",
  "Monitoring":            "#f0883e",
  "Customer Support":      "#58a6ff",
  "Payment":               "#3fb950",
  "CSS Framework":         "#56d364",
  "CSS-in-JS":             "#79c0ff",
  "UI Library":            "#ffa657",
  "Build Tool":            "#8b949e",
  "JavaScript Library":    "#e3b341",
  "Realtime":              "#58a6ff",
  "Maps":                  "#3fb950",
  "Data Viz":              "#ffa657",
  "3D/WebGL":              "#79c0ff",
  "Rich Text Editor":      "#8b949e",
  "API Protocol":          "#58a6ff",
  "Database":              "#f0883e",
  "Video Player":          "#f85149",
  "Icon Library":          "#bc8cff",
  "Font Service":          "#8b949e",
  "SEO":                   "#3fb950",
  "Form Builder":          "#e3b341",
  "Email":                 "#58a6ff",
  "WordPress Plugin":      "#00b4d8",
  "LMS":                   "#e3b341",
  "Membership":            "#bc8cff",
  "Forum":                 "#8b949e",
  "Community":             "#8b949e",
  "Performance":           "#3fb950",
  "Other":                 "#8b949e",
};

// ── Category accent colours (6 groups only) ──────────────────────────────────
// Override the CAT_COLORS already defined above with a simplified 6-colour palette
Object.assign(CAT_COLORS, {
  // Infrastructure — blue
  "Web Server":            "#58a6ff",
  "Hosting":               "#58a6ff",
  "Cloud":                 "#58a6ff",
  "CDN":                   "#58a6ff",
  "Cache":                 "#58a6ff",
  "Backend-as-a-Service":  "#58a6ff",
  "Database":              "#58a6ff",
  "API Protocol":          "#58a6ff",
  "Realtime":              "#58a6ff",
  "Email":                 "#58a6ff",
  // Security — red
  "CDN / Security":        "#f85149",
  "Security":              "#f85149",
  "Auth / IAM":            "#f85149",
  // Frontend / Dev — muted blue
  "Programming Language":  "#79c0ff",
  "Frontend Framework":    "#79c0ff",
  "Meta-Framework":        "#79c0ff",
  "Framework":             "#79c0ff",
  "CSS Framework":         "#79c0ff",
  "CSS-in-JS":             "#79c0ff",
  "UI Library":            "#79c0ff",
  "JavaScript Library":    "#79c0ff",
  "Build Tool":            "#79c0ff",
  "3D/WebGL":              "#79c0ff",
  "Rich Text Editor":      "#79c0ff",
  // Content / Commerce — green
  "CMS":                   "#3fb950",
  "Headless CMS":          "#3fb950",
  "Website Builder":       "#3fb950",
  "E-commerce":            "#3fb950",
  "WordPress Plugin":      "#3fb950",
  "SEO":                   "#3fb950",
  "Form Builder":          "#3fb950",
  "Maps":                  "#3fb950",
  "LMS":                   "#3fb950",
  // Analytics / Business — amber
  "Analytics":             "#e3b341",
  "Monitoring":            "#e3b341",
  "Customer Support":      "#e3b341",
  "Payment":               "#e3b341",
  "Data Viz":              "#e3b341",
  "Video Player":          "#e3b341",
  "Icon Library":          "#e3b341",
  "Font Service":          "#e3b341",
  "Membership":            "#e3b341",
  "Forum":                 "#e3b341",
  "Community":             "#e3b341",
  "Performance":           "#e3b341",
  // Neutral — gray
  "Miscellaneous":         "#8b949e",
  "Other":                 "#8b949e",
});

// ── Heroicons SVG paths per category (24×24 outline) ─────────────────────────
// Returns an <svg> HTML string for a given category name
function catIcon(cat) {
  const ic = CAT_ICON_PATHS[cat] || CAT_ICON_PATHS["_default"];
  return `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">${ic}</svg>`;
}

const CAT_ICON_PATHS = {
  // server racks
  "Web Server":
    '<rect x="2" y="4.5" width="20" height="5" rx="1.5"/><rect x="2" y="14.5" width="20" height="5" rx="1.5"/><circle cx="18.5" cy="7" r="1" fill="currentColor"/><circle cx="18.5" cy="17" r="1" fill="currentColor"/>',

  // globe / network
  "Hosting":
    '<circle cx="12" cy="12" r="9"/><path d="M3.6 9h16.8M3.6 15h16.8M12 3c-2.4 3-3.6 5.7-3.6 9s1.2 6 3.6 9 3.6-5.7 3.6-9-1.2-6-3.6-9z"/>',

  "Cloud":
    '<path d="M2.25 15a4.5 4.5 0 004.5 4.5H18a3.75 3.75 0 001.332-7.257 3 3 0 00-3.758-3.848 5.25 5.25 0 00-10.233 2.33A4.502 4.502 0 002.25 15z"/>',

  "CDN":
    '<circle cx="12" cy="12" r="9"/><path d="M3.6 9h16.8M3.6 15h16.8M12 3c-2.4 3-3.6 5.7-3.6 9s1.2 6 3.6 9 3.6-5.7 3.6-9-1.2-6-3.6-9z"/>',

  "Cache":
    '<path d="M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75z"/>',

  // database cylinder
  "Database":
    '<ellipse cx="12" cy="5.5" rx="9" ry="3"/><path d="M3 5.5v5c0 1.657 4.03 3 9 3s9-1.343 9-3v-5M3 10.5v5c0 1.657 4.03 3 9 3s9-1.343 9-3v-5"/>',

  "Backend-as-a-Service":
    '<path d="M5.25 14.25h13.5m-13.5 0a3 3 0 01-3-3m3 3a3 3 0 100 6h13.5a3 3 0 100-6m-16.5-3a3 3 0 013-3h13.5a3 3 0 013 3m-19.5 0a4.5 4.5 0 01.9-2.7L5.737 5.1a3.375 3.375 0 012.7-1.35h7.126c1.062 0 2.062.5 2.7 1.35l2.587 3.45a4.5 4.5 0 01.9 2.7m0 0a3 3 0 01-3 3m0 3h.008v.008h-.008v-.008zm0-6h.008v.008h-.008v-.008zm-3 6h.008v.008h-.008v-.008zm0-6h.008v.008h-.008v-.008z"/>',

  "Realtime":
    '<path d="M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75z"/>',

  "API Protocol":
    '<path d="M14.25 9.75L16.5 12l-2.25 2.25m-4.5 0L7.5 12l2.25-2.25M6 20.25h12A2.25 2.25 0 0020.25 18V6A2.25 2.25 0 0018 3.75H6A2.25 2.25 0 003.75 6v12A2.25 2.25 0 006 20.25z"/>',

  "Email":
    '<path d="M21.75 6.75v10.5a2.25 2.25 0 01-2.25 2.25h-15a2.25 2.25 0 01-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0019.5 4.5h-15a2.25 2.25 0 00-2.25 2.25m19.5 0v.243a2.25 2.25 0 01-1.07 1.916l-7.5 4.615a2.25 2.25 0 01-2.36 0L3.32 8.91a2.25 2.25 0 01-1.07-1.916V6.75"/>',

  // shields
  "CDN / Security":
    '<path d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"/>',

  "Security":
    '<path d="M12 2.25c-5.385 0-9.75 4.365-9.75 9.75s4.365 9.75 9.75 9.75 9.75-4.365 9.75-9.75S17.385 2.25 12 2.25zm0 8.625a1.125 1.125 0 110 2.25 1.125 1.125 0 010-2.25zM12 6.75a.75.75 0 01.75.75v3.75a.75.75 0 01-1.5 0V7.5a.75.75 0 01.75-.75z"/>',

  "Auth / IAM":
    '<path d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z"/>',

  // code brackets
  "Programming Language":
    '<path d="M17.25 6.75L22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3l-4.5 16.5"/>',

  "JavaScript Library":
    '<path d="M12 6.042A8.967 8.967 0 006 3.75c-1.052 0-2.062.18-3 .512v14.25A8.987 8.987 0 016 18c2.305 0 4.408.867 6 2.292m0-14.25a8.966 8.966 0 016-2.292c1.052 0 2.062.18 3 .512v14.25A8.987 8.987 0 0018 18a8.967 8.967 0 00-6 2.292m0-14.25v14.25"/>',

  "Build Tool":
    '<path d="M11.42 15.17L17.25 21A2.652 2.652 0 0021 17.25l-5.877-5.877M11.42 15.17l2.496-3.03c.317-.384.74-.626 1.208-.766M11.42 15.17l-4.655 5.653a2.548 2.548 0 11-3.586-3.586l6.837-5.63m5.108-.233c.55-.164 1.163-.188 1.743-.14a4.5 4.5 0 004.486-6.336l-3.276 3.277a3.004 3.004 0 01-2.25-2.25l3.276-3.276a4.5 4.5 0 00-6.336 4.486c.091 1.076-.071 2.264-.904 2.95l-.102.085m-1.745 1.437L5.909 7.5H4.5L2.25 3.75l1.5-1.5L7.5 4.5v1.409l4.26 4.26m-1.745 1.437l1.745-1.437m6.615 8.206L15.75 15.75M4.867 19.125h.008v.008h-.008v-.008z"/>',

  // atom / component
  "Frontend Framework":
    '<circle cx="12" cy="12" r="2.25"/><ellipse cx="12" cy="12" rx="9.75" ry="3.75"/><ellipse cx="12" cy="12" rx="9.75" ry="3.75" transform="rotate(60 12 12)"/><ellipse cx="12" cy="12" rx="9.75" ry="3.75" transform="rotate(120 12 12)"/>',

  // lightning bolt
  "Meta-Framework":
    '<path d="M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75z"/>',

  "Cache_shared": // alias, assigned below
    '<path d="M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75z"/>',

  // layers
  "Framework":
    '<path d="M6.429 9.75L2.25 12l4.179 2.25m0-4.5l5.571 3 5.571-3m-11.142 0L2.25 7.5 12 2.25l9.75 5.25-4.179 2.25m0 0L21.75 12l-4.179 2.25m0 0l4.179 2.25L12 21.75 2.25 16.5l4.179-2.25m11.142 0l-5.571 3-5.571-3"/>',

  // paint / css
  "CSS Framework":
    '<path d="M4.098 19.902a3.75 3.75 0 005.304 0l6.401-6.402M6.75 21A3.75 3.75 0 013 17.25V4.125C3 3.504 3.504 3 4.125 3h5.25c.621 0 1.125.504 1.125 1.125v4.072M6.75 21a3.75 3.75 0 003.75-3.75V8.197M6.75 21h13.125c.621 0 1.125-.504 1.125-1.125v-5.25c0-.621-.504-1.125-1.125-1.125h-4.072M10.5 8.197l2.88-2.88c.438-.439 1.15-.439 1.59 0l3.712 3.713c.44.44.44 1.152 0 1.59l-2.879 2.88M6.75 17.25h.008v.008H6.75v-.008z"/>',

  "CSS-in-JS":
    '<path d="M14.25 9.75L16.5 12l-2.25 2.25m-4.5 0L7.5 12l2.25-2.25M6 20.25h12A2.25 2.25 0 0020.25 18V6A2.25 2.25 0 0018 3.75H6A2.25 2.25 0 003.75 6v12A2.25 2.25 0 006 20.25z"/>',

  // puzzle
  "UI Library":
    '<path d="M14.25 6.087c0-.355.186-.676.401-.959.221-.29.349-.634.349-1.003 0-1.036-1.007-1.875-2.25-1.875s-2.25.84-2.25 1.875c0 .369.128.713.349 1.003.215.283.401.604.401.959v0a.64.64 0 01-.657.643 48.39 48.39 0 01-4.163-.3c.186 1.613.293 3.25.315 4.907a.656.656 0 01-.658.663v0c-.355 0-.676-.186-.959-.401a1.647 1.647 0 00-1.003-.349c-1.036 0-1.875 1.007-1.875 2.25s.84 2.25 1.875 2.25c.369 0 .713-.128 1.003-.349.283-.215.604-.401.959-.401v0c.31 0 .555.26.532.57a48.039 48.039 0 01-.642 5.056c1.518.19 3.058.309 4.616.354a.64.64 0 00.657-.643v0c0-.355-.186-.676-.401-.959a1.647 1.647 0 01-.349-1.003c0-1.035 1.008-1.875 2.25-1.875 1.243 0 2.25.84 2.25 1.875 0 .369-.128.713-.349 1.003-.215.283-.4.604-.4.959v0c0 .333.277.599.61.58a48.1 48.1 0 005.427-.63 48.05 48.05 0 00.582-4.717.532.532 0 00-.533-.57v0c-.355 0-.676.186-.959.401-.29.221-.634.349-1.003.349-1.035 0-1.875-1.007-1.875-2.25s.84-2.25 1.875-2.25c.37 0 .713.128 1.003.349.283.215.604.401.96.401v0a.656.656 0 00.658-.663 48.422 48.422 0 00-.37-5.36c-1.886.342-3.81.574-5.766.689a.578.578 0 01-.61-.58v0z"/>',

  "3D/WebGL":
    '<path d="M21 7.5l-9-5.25L3 7.5m18 0l-9 5.25m9-5.25v9l-9 5.25M3 7.5l9 5.25M3 7.5v9l9 5.25m0-9v9"/>',

  "Rich Text Editor":
    '<path d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931zm0 0L19.5 7.125M18 14v4.75A2.25 2.25 0 0115.75 21H5.25A2.25 2.25 0 013 18.75V8.25A2.25 2.25 0 015.25 6H10"/>',

  // document
  "CMS":
    '<path d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z"/>',

  "Headless CMS":
    '<path d="M20.25 7.5l-.625 10.632a2.25 2.25 0 01-2.247 2.118H6.622a2.25 2.25 0 01-2.247-2.118L3.75 7.5M10 11.25h4M3.375 7.5h17.25c.621 0 1.125-.504 1.125-1.125v-1.5c0-.621-.504-1.125-1.125-1.125H3.375c-.621 0-1.125.504-1.125 1.125v1.5c0 .621.504 1.125 1.125 1.125z"/>',

  "Website Builder":
    '<path d="M6.75 7.5l3 2.25-3 2.25m4.5 0h3m-9 8.25h13.5A2.25 2.25 0 0021 18V6a2.25 2.25 0 00-2.25-2.25H5.25A2.25 2.25 0 003 6v12a2.25 2.25 0 002.25 2.25z"/>',

  // cart
  "E-commerce":
    '<path d="M2.25 3h1.386c.51 0 .955.343 1.087.835l.383 1.437M7.5 14.25a3 3 0 00-3 3h15.75m-12.75-3h11.218c1.121-2.3 2.1-4.684 2.924-7.138a60.114 60.114 0 00-16.536-1.84M7.5 14.25L5.106 5.272M6 20.25a.75.75 0 11-1.5 0 .75.75 0 011.5 0zm12.75 0a.75.75 0 11-1.5 0 .75.75 0 011.5 0z"/>',

  "WordPress Plugin":
    '<path d="M14.25 9.75L16.5 12l-2.25 2.25m-4.5 0L7.5 12l2.25-2.25M6 20.25h12A2.25 2.25 0 0020.25 18V6A2.25 2.25 0 0018 3.75H6A2.25 2.25 0 003.75 6v12A2.25 2.25 0 006 20.25z"/>',

  "SEO":
    '<path d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 15.803 7.5 7.5 0 0015.803 15.803z"/>',

  "Form Builder":
    '<path d="M9 12h3.75M9 15h3.75M9 18h3.75m3 .75H18a2.25 2.25 0 002.25-2.25V6.108c0-1.135-.845-2.098-1.976-2.192a48.424 48.424 0 00-1.123-.08m-5.801 0c-.065.21-.1.433-.1.664 0 .414.336.75.75.75h4.5a.75.75 0 00.75-.75 2.25 2.25 0 00-.1-.664m-5.8 0A2.251 2.251 0 0113.5 2.25H15c1.012 0 1.867.668 2.15 1.586m-5.8 0c-.376.023-.75.05-1.124.08C9.095 4.01 8.25 4.973 8.25 6.108V8.25m0 0H4.875c-.621 0-1.125.504-1.125 1.125v11.25c0 .621.504 1.125 1.125 1.125h9.75c.621 0 1.125-.504 1.125-1.125V9.375c0-.621-.504-1.125-1.125-1.125H8.25zM6.75 12h.008v.008H6.75V12zm0 3h.008v.008H6.75V15zm0 3h.008v.008H6.75V18z"/>',

  "Maps":
    '<path d="M15 10.5a3 3 0 11-6 0 3 3 0 016 0z"/><path d="M19.5 10.5c0 7.142-7.5 11.25-7.5 11.25S4.5 17.642 4.5 10.5a7.5 7.5 0 1115 0z"/>',

  "LMS":
    '<path d="M4.26 10.147a60.436 60.436 0 00-.491 6.347A48.627 48.627 0 0112 20.904a48.627 48.627 0 018.232-4.41 60.46 60.46 0 00-.491-6.347m-15.482 0a50.57 50.57 0 00-2.658-.813A59.905 59.905 0 0112 3.493a59.902 59.902 0 0110.399 5.84c-.896.248-1.783.52-2.658.814m-15.482 0A50.697 50.697 0 0112 13.489a50.702 50.702 0 017.74-3.342M6.75 15a.75.75 0 100-1.5.75.75 0 000 1.5zm0 0v-3.675A55.378 55.378 0 0112 8.443m-7.007 11.55A5.981 5.981 0 006.75 15.75v-1.5"/>',

  // chart bars
  "Analytics":
    '<path d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v6.75C7.5 20.496 6.996 21 6.375 21h-2.25A1.125 1.125 0 013 19.875v-6.75zM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v11.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V8.625zM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v15.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V4.125z"/>',

  // pulse wave
  "Monitoring":
    '<path d="M3.75 12h3l2.25-6 3 12 2.25-7.5 1.5 4.5H20.25"/>',

  // chat bubble
  "Customer Support":
    '<path d="M7.5 8.25h9m-9 3H12m-9.75 1.51c0 1.6 1.123 2.994 2.707 3.227 1.129.166 2.27.293 3.423.379.35.026.67.21.865.501L12 21l2.755-4.133a1.14 1.14 0 01.865-.501 48.172 48.172 0 003.423-.379c1.584-.233 2.707-1.626 2.707-3.228V6.741c0-1.602-1.123-2.995-2.707-3.228A48.394 48.394 0 0012 3c-2.392 0-4.744.175-7.043.513C3.373 3.746 2.25 5.14 2.25 6.741v6.018z"/>',

  // credit card
  "Payment":
    '<path d="M2.25 8.25h19.5M2.25 9h19.5m-16.5 5.25h6m-6 2.25h3m-3.75 3h15a2.25 2.25 0 002.25-2.25V6.75A2.25 2.25 0 0019.5 4.5h-15a2.25 2.25 0 00-2.25 2.25v10.5A2.25 2.25 0 004.5 19.5z"/>',

  // bar chart (data viz)
  "Data Viz":
    '<path d="M7.5 14.25v2.25m3-4.5v4.5m3-6.75v6.75m3-9v9M6 20.25h12A2.25 2.25 0 0020.25 18V6A2.25 2.25 0 0018 3.75H6A2.25 2.25 0 003.75 6v12A2.25 2.25 0 006 20.25z"/>',

  // play
  "Video Player":
    '<path d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/><path d="M15.91 11.672a.375.375 0 010 .656l-5.603 3.113a.375.375 0 01-.557-.328V8.887c0-.286.307-.466.557-.327l5.603 3.112z"/>',

  // star
  "Icon Library":
    '<path d="M11.48 3.499a.562.562 0 011.04 0l2.125 5.111a.563.563 0 00.475.345l5.518.442c.499.04.701.663.321.988l-4.204 3.602a.563.563 0 00-.182.557l1.285 5.385a.562.562 0 01-.84.61l-4.725-2.885a.563.563 0 00-.586 0L6.982 20.54a.562.562 0 01-.84-.61l1.285-5.386a.562.562 0 00-.182-.557l-4.204-3.602a.563.563 0 01.321-.988l5.518-.442a.563.563 0 00.475-.345L11.48 3.5z"/>',

  // text / font
  "Font Service":
    '<path d="M11.25 11.25l.041-.02a.75.75 0 011.063.852l-.708 2.836a.75.75 0 001.063.853l.041-.021M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9-3.75h.008v.008H12V8.25z"/>',

  // person
  "Membership":
    '<path d="M15.75 6a3.75 3.75 0 11-7.5 0 3.75 3.75 0 017.5 0zM4.501 20.118a7.5 7.5 0 0114.998 0A17.933 17.933 0 0112 21.75c-2.676 0-5.216-.584-7.499-1.632z"/>',

  // speech bubbles
  "Forum":
    '<path d="M20.25 8.511c.884.284 1.5 1.128 1.5 2.097v4.286c0 1.136-.847 2.1-1.98 2.193-.34.027-.68.052-1.02.072v3.091l-3-3c-1.354 0-2.694-.055-4.02-.163a2.115 2.115 0 01-.825-.242m9.345-8.334a2.126 2.126 0 00-.476-.095 48.64 48.64 0 00-8.048 0c-1.131.094-1.976 1.057-1.976 2.192v4.286c0 .837.46 1.58 1.155 1.951m9.345-8.334V6.637c0-1.621-1.152-3.026-2.76-3.235A48.455 48.455 0 0011.25 3c-2.115 0-4.198.137-6.24.402-1.608.209-2.76 1.614-2.76 3.235v6.226c0 1.621 1.152 3.026 2.76 3.235.577.075 1.157.14 1.74.194V21l4.155-4.155"/>',

  // users
  "Community":
    '<path d="M18 18.72a9.094 9.094 0 003.741-.479 3 3 0 00-4.682-2.72m.94 3.198l.001.031c0 .225-.012.447-.037.666A11.944 11.944 0 0112 21c-2.17 0-4.207-.576-5.963-1.584A6.062 6.062 0 016 18.719m12 0a5.971 5.971 0 00-.941-3.197m0 0A5.995 5.995 0 0012 12.75a5.995 5.995 0 00-5.058 2.772m0 0a3 3 0 00-4.681 2.72 8.986 8.986 0 003.74.477m.94-3.197a5.971 5.971 0 00-.94 3.197M15 6.75a3 3 0 11-6 0 3 3 0 016 0zm6 3a2.25 2.25 0 11-4.5 0 2.25 2.25 0 014.5 0zm-13.5 0a2.25 2.25 0 11-4.5 0 2.25 2.25 0 014.5 0z"/>',

  // gauge / sun rays
  "Performance":
    '<path d="M12 3v2.25m6.364.386l-1.591 1.591M21 12h-2.25m-.386 6.364l-1.591-1.591M12 18.75V21m-4.773-4.227l-1.591 1.591M5.25 12H3m4.227-4.773L5.636 5.636M15.75 12a3.75 3.75 0 11-7.5 0 3.75 3.75 0 017.5 0z"/>',

  // gear
  "Miscellaneous":
    '<path d="M9.594 3.94c.09-.542.56-.94 1.11-.94h2.593c.55 0 1.02.398 1.11.94l.213 1.281c.063.374.313.686.645.87.074.04.147.083.22.127.324.196.72.257 1.075.124l1.217-.456a1.125 1.125 0 011.37.49l1.296 2.247a1.125 1.125 0 01-.26 1.431l-1.003.827c-.293.24-.438.613-.431.992a6.759 6.759 0 010 .255c-.007.378.138.75.43.99l1.005.828c.424.35.534.954.26 1.43l-1.298 2.247a1.125 1.125 0 01-1.369.491l-1.217-.456c-.355-.133-.75-.072-1.076.124a6.57 6.57 0 01-.22.128c-.331.183-.581.495-.644.869l-.213 1.28c-.09.543-.56.941-1.11.941h-2.594c-.55 0-1.02-.398-1.11-.94l-.213-1.281c-.062-.374-.312-.686-.644-.87a6.52 6.52 0 01-.22-.127c-.325-.196-.72-.257-1.076-.124l-1.217.456a1.125 1.125 0 01-1.369-.49l-1.297-2.247a1.125 1.125 0 01.26-1.431l1.004-.827c.292-.24.437-.613.43-.992a6.932 6.932 0 010-.255c.007-.378-.138-.75-.43-.99l-1.004-.828a1.125 1.125 0 01-.26-1.43l1.297-2.247a1.125 1.125 0 011.37-.491l1.216.456c.356.133.751.072 1.076-.124.072-.044.146-.087.22-.128.332-.183.582-.495.644-.869l.214-1.281z"/><path d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>',

  // 3 dots
  "_default":
    '<circle cx="5" cy="12" r="1.5" fill="currentColor"/><circle cx="12" cy="12" r="1.5" fill="currentColor"/><circle cx="19" cy="12" r="1.5" fill="currentColor"/>',

  "Other": '<circle cx="5" cy="12" r="1.5" fill="currentColor"/><circle cx="12" cy="12" r="1.5" fill="currentColor"/><circle cx="19" cy="12" r="1.5" fill="currentColor"/>',
};

// Brand colours per technology (used for the icon badge background)
const TECH_BRAND_COLORS = {
  // Web Servers
  "Nginx":                  "#009639",
  "Apache":                 "#D22128",
  "LiteSpeed":              "#0095D5",
  "Caddy":                  "#1F88C7",
  "IIS":                    "#0078D4",
  // Languages
  "PHP":                    "#777BB4",
  "Python":                 "#3776AB",
  "Ruby":                   "#CC342D",
  "Node.js":                "#339933",
  "TypeScript":             "#3178C6",
  "JavaScript":             "#c8a400",
  "Go":                     "#00ADD8",
  "Java":                   "#007396",
  "Rust":                   "#ce412b",
  "Perl":                   "#39457e",
  // Frontend Frameworks
  "React":                  "#00b4d4",
  "Angular":                "#DD0031",
  "Vue.js":                 "#4FC08D",
  "Svelte":                 "#FF3E00",
  "Ember.js":               "#E04E39",
  "Alpine.js":              "#8BC0D0",
  "Backbone.js":            "#0071B5",
  "Preact":                 "#673AB8",
  // Meta-Frameworks
  "Next.js":                "#eeeeee",
  "Nuxt.js":                "#00DC82",
  "Gatsby":                 "#663399",
  "Remix":                  "#d4d4d4",
  "Astro":                  "#FF5D01",
  "SvelteKit":              "#FF3E00",
  // CMS
  "WordPress":              "#21759B",
  "Drupal":                 "#0678BE",
  "Joomla":                 "#F44321",
  "Ghost":                  "#738a94",
  "Contentful":             "#2478CC",
  "Sanity":                 "#F36458",
  "DatoCMS":                "#FF7751",
  "Strapi":                 "#4945FF",
  "Prismic":                "#5163BA",
  "Storyblok":              "#09B3AF",
  "Webflow":                "#146EF5",
  // E-commerce
  "Shopify":                "#96BF48",
  "WooCommerce":            "#96588A",
  "Magento":                "#EE672F",
  "BigCommerce":            "#121118",
  "PrestaShop":             "#DF0067",
  // JS Libraries
  "jQuery":                 "#0769AD",
  "jQuery UI":              "#0769AD",
  "jQuery Migrate":         "#0769AD",
  "jQuery Form":            "#0769AD",
  "jQuery Validation":      "#0769AD",
  "jQuery Cookie":          "#0769AD",
  "core-js":                "#e8551d",
  "Zone.js":                "#DD0031",
  "Lodash":                 "#3492FF",
  "Underscore.js":          "#0371ad",
  "Moment.js":              "#222",
  // CSS
  "Tailwind CSS":           "#06B6D4",
  "Bootstrap":              "#7952B3",
  "Bulma":                  "#00D1B2",
  "Foundation":             "#1779ba",
  "Materialize":            "#ee6e73",
  "Sass":                   "#CC6699",
  "Less":                   "#1d365d",
  // CSS-in-JS
  "Emotion":                "#CB0059",
  "styled-components":      "#DB7093",
  // UI Libraries
  "Material UI":            "#007FFF",
  "Ant Design":             "#1677FF",
  "Chakra UI":              "#319795",
  "shadcn/ui":              "#aaaaaa",
  "Radix UI":               "#eeeeee",
  "Headless UI":            "#66e3ff",
  "Mantine":                "#339AF0",
  // CDN / Security
  "Cloudflare":             "#F38020",
  "AWS CloudFront":         "#FF9900",
  "Fastly":                 "#FF282D",
  "Akamai":                 "#009BDE",
  "jsDelivr":               "#E84D3D",
  "cdnjs":                  "#f16822",
  "unpkg":                  "#e95420",
  // Cloud / Hosting
  "AWS":                    "#FF9900",
  "Google Cloud":           "#4285F4",
  "Microsoft Azure":        "#0078D4",
  "DigitalOcean":           "#0080FF",
  "Vercel":                 "#eeeeee",
  "Netlify":                "#00C7B7",
  "Heroku":                 "#430098",
  "Hostinger":              "#673DE6",
  "Render":                 "#46E3B7",
  "Hetzner":                "#D50C2D",
  "Linode / Akamai":        "#00b159",
  "Vultr":                  "#007BFC",
  "OVH":                    "#123F6D",
  "Rackspace":              "#c7002e",
  "SiteGround":             "#F57921",
  "WP Engine":              "#40BAC8",
  "Kinsta":                 "#1D4ED8",
  "Railway":                "#0B0D0E",
  "GoDaddy":                "#1bdbdb",
  "Bluehost":               "#003087",
  // Cloud DNS / Email
  "AWS Route 53":           "#FF9900",
  "Google Cloud DNS":       "#4285F4",
  "Azure DNS":              "#0078D4",
  "Google Workspace":       "#4285F4",
  "Microsoft 365":          "#D83B01",
  "Amazon SES":             "#FF9900",
  "Mailgun":                "#F06B66",
  "SendGrid":               "#1A82E2",
  // Cache
  "Redis":                  "#DC382D",
  "Varnish":                "#4ba7c2",
  // Database
  "MySQL":                  "#4479A1",
  "PostgreSQL":             "#336791",
  "MongoDB":                "#47A248",
  "Supabase":               "#3ECF8E",
  "Firebase":               "#FFCA28",
  // Auth
  "Auth0":                  "#EB5424",
  "Okta":                   "#007DC1",
  "Clerk":                  "#6C47FF",
  // Analytics
  "Google Analytics":       "#E37400",
  "Google Tag Manager":     "#4285F4",
  "Hotjar":                 "#FD3A5C",
  "Segment":                "#52BD94",
  "Mixpanel":               "#7856FF",
  "Amplitude":              "#197EEB",
  "Matomo":                 "#3152A0",
  "PostHog":                "#F54E00",
  "Plausible":              "#5850EC",
  "Fathom":                 "#9187FF",
  "Heap":                   "#E1436A",
  "Pendo":                  "#FF4876",
  // Monitoring
  "Sentry":                 "#362D59",
  "Datadog":                "#632CA6",
  "LogRocket":              "#7B52F6",
  "Bugsnag":                "#4949E4",
  "FullStory":              "#A855F7",
  "New Relic":              "#1CE783",
  // Customer Support
  "Intercom":               "#286EFA",
  "Zendesk":                "#03363D",
  "Drift":                  "#17494D",
  "HubSpot":                "#FF7A59",
  "Crisp":                  "#1972F5",
  "Freshdesk":              "#25c16f",
  // Payment
  "Stripe":                 "#635BFF",
  "PayPal":                 "#003087",
  "Braintree":              "#1C3E73",
  "Square":                 "#3E4348",
  "Paddle":                 "#1a1a2e",
  "Adyen":                  "#0ABF53",
  // Media
  "Brightcove":             "#CF1F2A",
  "Vimeo":                  "#1AB7EA",
  "Wistia":                 "#54BBFF",
  "YouTube":                "#FF0000",
  "Lottie":                 "#00dba8",
  // Build Tools
  "Webpack":                "#8DD6F9",
  "Vite":                   "#646CFF",
  "Rollup":                 "#EC4A3F",
  "Parcel":                 "#b35000",
  "Turbopack":              "#eeeeee",
  // API
  "GraphQL":                "#E10098",
  "gRPC":                   "#244c5a",
  "REST":                   "#3fb950",
  // Icons / Fonts
  "Font Awesome":           "#528DD3",
  "Google Fonts":           "#4285F4",
  // Misc
  "PWA":                    "#5A0FC8",
  "Open Graph":             "#4267B2",
  "Twitter Cards":          "#1DA1F2",
  "HTTP/3":                 "#39d353",
  "Priority Hints":         "#8b949e",
  "RSS":                    "#FFA500",
};

// Returns true if a hex colour is light (needs dark text)
function isLight(hex) {
  if (!hex) return false;
  const r = parseInt(hex.slice(1, 3), 16) || 0;
  const g = parseInt(hex.slice(3, 5), 16) || 0;
  const b = parseInt(hex.slice(5, 7), 16) || 0;
  return (0.299 * r + 0.587 * g + 0.114 * b) > 155;
}

// Build a 24×24 icon badge element for a given tech name
function iconFor(name, catColor) {
  const bg  = TECH_BRAND_COLORS[name] || catColor || "#8b949e";
  const fg  = isLight(bg) ? "#111" : "#fff";

  // Compute 2-char initials
  const words = name.replace(/[^a-zA-Z0-9.\s]/g, " ").trim().split(/\s+/);
  const init  = words.length >= 2
    ? (words[0][0] + words[1][0]).toUpperCase()
    : name.slice(0, 2).toUpperCase();

  const badge = el("div", "tech-icon-badge");
  badge.style.background = bg;
  badge.style.color      = fg;
  badge.textContent      = init;
  return badge;
}

function renderTech() {
  const stack = document.getElementById("tech-stack");
  const empty = document.getElementById("tech-empty");
  const items = state.technologies || [];

  setBadge("bdg-tech", items.length);

  // Update domain label
  const host = (() => {
    try { return new URL(document.getElementById("site-host").textContent.includes("://")
      ? document.getElementById("site-host").textContent
      : `https://${document.getElementById("site-host").textContent}`).hostname;
    } catch { return document.getElementById("site-host").textContent; }
  })();
  const domLabel = document.getElementById("tech-domain-label");
  if (domLabel) domLabel.textContent = host || "—";

  stack.replaceChildren();

  if (!items.length) {
    if (empty) empty.classList.remove("hidden");
    return;
  }
  if (empty) empty.classList.add("hidden");

  // Group by category
  const groups = new Map();
  for (const t of items) {
    const cat = t.cat || t.category || "Other";
    if (!groups.has(cat)) groups.set(cat, []);
    groups.get(cat).push(t);
  }

  // Sort by CAT_ORDER, unknown categories go to bottom
  const sorted = [...groups.entries()].sort(([a], [b]) => {
    const ai = CAT_ORDER.indexOf(a);
    const bi = CAT_ORDER.indexOf(b);
    if (ai === -1 && bi === -1) return a.localeCompare(b);
    if (ai === -1) return 1;
    if (bi === -1) return -1;
    return ai - bi;
  });

  for (const [cat, techs] of sorted) {
    const color = CAT_COLORS[cat] || "#8b949e";
    // ── Category card ────────────────────────────────────────────
    const card = el("div", "tech-card");
    card.style.borderTopColor = color;

    // Card header
    const head = el("div", "tech-card-head");
    head.style.borderLeftColor = color;

    // SVG icon — content is static hardcoded paths, not user input (safe)
    const iconEl = el("span", "cat-icon");
    iconEl.style.color = color;
    iconEl.innerHTML = catIcon(cat); // eslint-disable-line -- static SVG paths only
    const nameEl   = txt("span", "cat-head-name", cat);
    nameEl.style.color = color;
    const countEl  = txt("span", "cat-head-count", String(techs.length));
    countEl.style.color        = color;
    countEl.style.borderColor  = `${color}55`;
    ap(head, iconEl, nameEl, countEl);
    card.appendChild(head);

    // Tech item rows
    const list = el("div", "tech-list");
    for (const t of techs) {
      const row = el("div", "tech-list-item");
      if (t.evidence) row.title = t.evidence;

      row.appendChild(iconFor(t.name, color));

      const nameSpan = txt("span", "tli-name", t.name);
      row.appendChild(nameSpan);

      if (t.version) row.appendChild(txt("span", "tli-ver", t.version));

      list.appendChild(row);
    }
    card.appendChild(list);
    stack.appendChild(card);
  }
}

// ── WHOIS / DNS / IP lookup ───────────────────────────────────────────────────

let lookupDomain = "";

async function doLookup() {
  const host   = document.getElementById("site-host").textContent.trim();
  const status = document.getElementById("lookup-status");
  const btnL   = document.getElementById("btn-lookup");

  if (!host || host === "—") {
    status.textContent = "No domain — open a page first";
    setTimeout(() => { status.textContent = ""; }, 3000);
    return;
  }

  btnL.disabled      = true;
  status.textContent = `Scanning ${host}…`;

  await wakeSW();
  const res = await bg({ type: "LOOKUP", domain: host });

  btnL.disabled = false;

  if (!res) {
    status.textContent = "Background not responding — try reloading extension";
    setTimeout(() => { status.textContent = ""; }, 5000);
    return;
  }
  if (!res.ok) {
    status.textContent = `Error: ${res.error || "unknown"}`;
    setTimeout(() => { status.textContent = ""; }, 5000);
    return;
  }

  lookupDomain = res.domain || host;

  // Show partial results — render whatever came back
  const sections = [];
  if (res.ip)   { renderIpInfo(res.ip);   injectHostingTech(res.ip); sections.push("IP"); }
  else          { clearSection("ip"); }
  if (res.dns)  { renderDns(res.dns);     injectDnsTech(res.dns); sections.push("DNS"); }
  else          { clearSection("dns"); }
  if (res.rdap) { renderWhois(res.rdap);  sections.push("WHOIS"); }
  else          { clearSection("whois"); }

  status.textContent = sections.length
    ? `Done ✓ — ${sections.join(", ")}`
    : "Done — no data returned (rate limited?)";
  setTimeout(() => { status.textContent = ""; }, 5000);
}

// Inject hosting provider detected from IP/ISP into the tech stack
function injectHostingTech(ip) {
  if (!ip || typeof ip !== "object") return;
  const probe = `${typeof ip.isp === "string" ? ip.isp : ""} ${typeof ip.org === "string" ? ip.org : ""}`.toLowerCase();
  const map = [
    [/hostinger/,     "Hostinger"],
    [/digitalocean/,  "DigitalOcean"],
    [/amazon|aws/,    "AWS"],
    [/google.*cloud|gcp/, "Google Cloud"],
    [/microsoft|azure/, "Microsoft Azure"],
    [/cloudflare/,    "Cloudflare"],
    [/fastly/,        "Fastly"],
    [/hetzner/,       "Hetzner"],
    [/linode|akamai/, "Linode / Akamai"],
    [/vultr/,         "Vultr"],
    [/ovh/,           "OVH"],
    [/rackspace/,     "Rackspace"],
    [/siteground/,    "SiteGround"],
    [/bluehost/,      "Bluehost"],
    [/godaddy/,       "GoDaddy"],
    [/wpengine/,      "WP Engine"],
    [/kinsta/,        "Kinsta"],
    [/vercel/,        "Vercel"],
    [/netlify/,       "Netlify"],
    [/heroku/,        "Heroku"],
    [/railway/,       "Railway"],
    [/render\.com|render inc/, "Render"],
  ];
  let added = false;
  for (const [re, name] of map) {
    if (re.test(probe) && !state.technologies.some(t => t.name === name)) {
      state.technologies.push({ name, cat: "Hosting", version: null, evidence: "IP / ISP lookup" });
      added = true;
    }
  }
  if (added) renderTech();
}

// Inject CDN/security tech detected from DNS records (e.g. Cloudflare NS)
function injectDnsTech(dns) {
  if (!dns || typeof dns !== "object") return;
  const nsNames = (dns.ns || []).map(r => (typeof r.data === "string" ? r.data : "").toLowerCase());
  const mxNames = (dns.mx || []).map(r => (typeof r.data === "string" ? r.data : "").toLowerCase());
  const allNames = [...nsNames, ...mxNames];

  const map = [
    [/cloudflare/,          "Cloudflare",    "CDN / Security"],
    [/awsdns/,              "AWS Route 53",  "Cloud"],
    [/google/,              "Google Cloud DNS", "Cloud"],
    [/azure-dns/,           "Azure DNS",     "Cloud"],
    [/ns\.fastly/,          "Fastly",        "CDN"],
    [/google.*mail|gmail/,  "Google Workspace", "Email"],
    [/outlook|protection\.outlook/, "Microsoft 365", "Email"],
    [/amazonses/,           "Amazon SES",    "Email"],
    [/mailgun/,             "Mailgun",        "Email"],
    [/sendgrid/,            "SendGrid",       "Email"],
  ];
  let added = false;
  for (const [re, name, cat] of map) {
    if (allNames.some(n => re.test(n)) && !state.technologies.some(t => t.name === name)) {
      state.technologies.push({ name, cat, version: null, evidence: "DNS record" });
      added = true;
    }
  }
  if (added) renderTech();
}

function clearSection(name) {
  const rows  = document.getElementById(`${name}-rows`);
  const empty = document.getElementById(`${name}-empty`);
  if (rows)  rows.replaceChildren();
  if (empty) empty.classList.remove("hidden");
}

// ── Shared helpers for info cards ────────────────────────────────────────────

function fmtTtl(sec) {
  if (!sec && sec !== 0) return "";
  const s = parseInt(sec);
  if (s >= 86400) return `${Math.round(s / 86400)}d`;
  if (s >= 3600)  return `${Math.round(s / 3600)}h`;
  if (s >= 60)    return `${Math.round(s / 60)}m`;
  return `${s}s`;
}

function addRow(container, key, value, cls) {
  if (!value && value !== 0) return;
  const row = el("div", cls ? `info-row ${cls}` : "info-row");
  ap(row, txt("span", "info-key", key), txt("span", "info-val", String(value)));
  container.appendChild(row);
}

function addGroupTitle(container, title) {
  container.appendChild(txt("div", "info-group-title", title));
}

// ─────────────────────────────────────────────────────────────────────────────

function renderIpInfo(ip) {
  const rows  = document.getElementById("ip-rows");
  const empty = document.getElementById("ip-empty");
  rows.replaceChildren();
  if (!ip) { empty.classList.remove("hidden"); return; }
  empty.classList.add("hidden");

  // ── Network ──────────────────────────────────────────────────
  addGroupTitle(rows, "Network");
  addRow(rows, "IP Address", ip.ip);
  addRow(rows, "IP Type",    ip.type);
  addRow(rows, "PTR",        ip.ptr);
  addRow(rows, "ASN",        ip.asn);
  addRow(rows, "ISP",        ip.isp);
  addRow(rows, "Org",        ip.org);
  addRow(rows, "Domain",     ip.domain);

  // ── Location ─────────────────────────────────────────────────
  addGroupTitle(rows, "Location");
  if (ip.flag || ip.country) {
    const row = el("div", "info-row");
    ap(row,
      txt("span", "info-key", "Country"),
      txt("span", "info-val", [ip.flag, ip.country, ip.country_code ? `(${ip.country_code})` : ""].filter(Boolean).join(" "))
    );
    rows.appendChild(row);
  }
  addRow(rows, "Continent",  ip.continent);
  addRow(rows, "Region",     ip.region_code ? `${ip.region} (${ip.region_code})` : ip.region);
  addRow(rows, "City",       ip.city);
  addRow(rows, "Postal",     ip.postal);
  addRow(rows, "Coordinates",
    ip.latitude && ip.longitude ? `${ip.latitude}, ${ip.longitude}` : null);
  addRow(rows, "Capital",    ip.capital);
  addRow(rows, "Calling",    ip.calling_code);

  // ── Time ─────────────────────────────────────────────────────
  if (ip.timezone) {
    addGroupTitle(rows, "Time");
    addRow(rows, "Timezone",   ip.tz_utc ? `${ip.timezone}  ${ip.tz_utc}` : ip.timezone);
  }
}

// ─────────────────────────────────────────────────────────────────────────────

function renderDns(dns) {
  const rows  = document.getElementById("dns-rows");
  const empty = document.getElementById("dns-empty");
  rows.replaceChildren();
  if (!dns) { empty.classList.remove("hidden"); return; }

  let hasAny = false;

  // ── Helper: one DNS record row ──────────────────────────────
  function dnsRow(typeKey, label, data, opts = {}) {
    hasAny = true;
    const row = el("div", "info-row dns-record-row");

    // Type badge
    const badge = txt("span", `dns-type dns-${typeKey}`, label);
    row.appendChild(badge);

    // Extra badge (MX priority / TXT subtype)
    if (opts.subBadge) {
      const sb = txt("span", `dns-sub-badge ${opts.subClass || ""}`, opts.subBadge);
      row.appendChild(sb);
    }

    // Value
    const val = txt("span", "dns-val", data);
    row.appendChild(val);

    // TTL
    if (opts.ttl != null) {
      row.appendChild(txt("span", "dns-ttl", fmtTtl(opts.ttl)));
    }

    rows.appendChild(row);
  }

  // A / AAAA
  for (const r of (dns.a || []))    dnsRow("a",    "A",    r.data, { ttl: r.ttl });
  for (const r of (dns.aaaa || [])) dnsRow("aaaa", "AAAA", r.data, { ttl: r.ttl });

  // PTR (reverse DNS)
  if (dns.ptr?.length) {
    for (const r of dns.ptr) dnsRow("ptr", "PTR", r.data, { ttl: r.ttl });
  }

  // CNAME
  for (const r of (dns.cname || [])) dnsRow("cname", "CNAME", r.data, { ttl: r.ttl });

  // NS
  if ((dns.ns || []).length) {
    for (const r of dns.ns)
      dnsRow("ns", "NS", r.data.replace(/\.$/, ""), { ttl: r.ttl });
  }

  // MX (sorted by priority, already done in background.js)
  for (const r of (dns.mx || []))
    dnsRow("mx", "MX", r.data, { ttl: r.ttl, subBadge: String(r.priority), subClass: "dns-mx-prio" });

  // TXT — SPF / DMARC / DKIM / generic
  for (const r of (dns.txt || []))
    dnsRow("txt", r.txtype, r.data, { ttl: r.ttl });

  // CAA
  for (const r of (dns.caa || []))
    dnsRow("caa", "CAA", r.value, { ttl: r.ttl, subBadge: r.tag, subClass: "dns-caa-tag" });

  // SOA — expanded block
  if (dns.soa) {
    const s = dns.soa;
    hasAny = true;
    const block = el("div", "dns-soa-block");
    block.appendChild(txt("div", "dns-soa-title", `SOA  (TTL ${fmtTtl(s.ttl)})`));
    const grid = el("div", "dns-soa-grid");
    function soaField(k, v) {
      if (!v) return;
      const cell = el("div", "dns-soa-cell");
      ap(cell, txt("span", "dns-soa-key", k), txt("span", "dns-soa-val", v));
      grid.appendChild(cell);
    }
    soaField("Primary NS", s.primary);
    soaField("Admin",      s.admin);
    soaField("Serial",     s.serial);
    soaField("Refresh",    s.refresh ? fmtTtl(+s.refresh) : null);
    soaField("Retry",      s.retry   ? fmtTtl(+s.retry)   : null);
    soaField("Expire",     s.expire  ? fmtTtl(+s.expire)  : null);
    soaField("Min TTL",    s.minimum ? fmtTtl(+s.minimum) : null);
    block.appendChild(grid);
    rows.appendChild(block);
  }

  empty.classList.toggle("hidden", hasAny);
  if (!hasAny) empty.classList.remove("hidden");
}

// ─────────────────────────────────────────────────────────────────────────────

function renderWhois(rdap) {
  const parsed = document.getElementById("whois-parsed");
  const rawEl  = document.getElementById("whois-raw");
  const empty  = document.getElementById("whois-empty");

  parsed.replaceChildren();
  if (!rdap) { empty.classList.remove("hidden"); return; }
  empty.classList.add("hidden");

  // ── Registration ─────────────────────────────────────────────
  addGroupTitle(parsed, "Registration");
  addRow(parsed, "Domain",      rdap.domain);
  addRow(parsed, "Registry ID", rdap.registryDomainId);
  addRow(parsed, "DNSSEC",      rdap.dnssec);
  addRow(parsed, "Status",      rdap.status);
  addRow(parsed, "Created",     rdap.created);
  addRow(parsed, "Updated",     rdap.updated);
  addRow(parsed, "Expires",     rdap.expires);
  addRow(parsed, "Last Check",  rdap.lastChecked);
  if (rdap.nameservers) {
    // one row per NS
    rdap.nameservers.split(", ").forEach((ns, i) =>
      addRow(parsed, i === 0 ? "Nameservers" : "", ns)
    );
  }

  // ── Registrar ────────────────────────────────────────────────
  addGroupTitle(parsed, "Registrar");
  addRow(parsed, "Name",        rdap.registrar);
  addRow(parsed, "IANA ID",     rdap.registrarIanaId);
  addRow(parsed, "WHOIS",       rdap.registrarWhois);
  addRow(parsed, "URL",         rdap.registrarUrl);
  addRow(parsed, "Abuse Email", rdap.registrarAbuse);
  addRow(parsed, "Abuse Phone", rdap.registrarAbusePhone);

  // ── Registrant ───────────────────────────────────────────────
  if (rdap.registrant || rdap.registrantOrg || rdap.registrantEmail) {
    addGroupTitle(parsed, "Registrant");
    addRow(parsed, "Name",  rdap.registrant);
    addRow(parsed, "Org",   rdap.registrantOrg);
    addRow(parsed, "Email", rdap.registrantEmail);
  }

  // ── Admin / Tech Contacts ────────────────────────────────────
  if (rdap.adminName || rdap.adminEmail || rdap.techName || rdap.techEmail) {
    addGroupTitle(parsed, "Contacts");
    addRow(parsed, "Admin Name",  rdap.adminName);
    addRow(parsed, "Admin Email", rdap.adminEmail);
    addRow(parsed, "Tech Name",   rdap.techName);
    addRow(parsed, "Tech Email",  rdap.techEmail);
  }

  rawEl.textContent = JSON.stringify(rdap, null, 2);
}

// ═══════════════════════════ HEADERS ═════════════════════════════════════════

function renderHeaders() {
  const list  = document.getElementById("hdr-list");
  const empty = document.getElementById("hdr-empty");
  const hdrs  = state.headers || {};
  const keys  = Object.keys(hdrs);

  list.replaceChildren();

  const missing = REQUIRED_HDRS.filter(h => !hdrs[h]);
  if (missing.length) {
    const sec = el("div", "hdr-section");
    sec.appendChild(txt("div", "hdr-section-title", "Missing Security Headers"));
    missing.forEach(h => {
      sec.appendChild(txt("div", "hdr-missing", `⚠ ${h}`));
    });
    list.appendChild(sec);
  }

  if (keys.length) {
    const sec = el("div", "hdr-section");
    sec.appendChild(txt("div", "hdr-section-title", "Captured Headers"));
    keys.forEach(k => {
      const row = el("div", "hdr-row");
      ap(row, txt("span", "hdr-key", k), txt("span", "hdr-val", hdrs[k]));
      sec.appendChild(row);
    });
    list.appendChild(sec);
  }

  const hasContent = missing.length > 0 || keys.length > 0;
  empty.classList.toggle("hidden", hasContent);
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

  // Repeater clear
  document.getElementById("rep-clear").addEventListener("click", () => {
    clearRespPanes();
    document.getElementById("resp-label").textContent   = "RESPONSE";
    document.getElementById("resp-sub-tabs").classList.add("hidden");
    document.getElementById("resp-empty").classList.remove("hidden");
  });

  // Response sub-tabs
  document.querySelectorAll(".sub-tab[data-resp]").forEach(t =>
    t.addEventListener("click", () => switchRespPane(t.dataset.resp))
  );

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

  // Tech tab: WHOIS scan + raw toggle
  document.getElementById("btn-lookup").addEventListener("click", doLookup);
  document.getElementById("whois-toggle").addEventListener("click", () => {
    const raw   = document.getElementById("whois-raw");
    const btn   = document.getElementById("whois-toggle");
    const shown = !raw.classList.contains("hidden");
    raw.classList.toggle("hidden", shown);
    btn.textContent = shown ? "▼" : "▲";
  });

  // Header / Refresh / Export
  document.getElementById("btn-refresh").addEventListener("click", loadAll);
  document.getElementById("btn-export").addEventListener("click", async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const payload = { url: tab?.url, timestamp: new Date().toISOString(), ...state };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const a    = el("a");
    a.href     = URL.createObjectURL(blob);
    try { a.download = `bughunter-${new URL(tab?.url || "http://x").hostname}-${Date.now()}.json`; }
    catch { a.download = `bughunter-${Date.now()}.json`; }
    a.click();
    URL.revokeObjectURL(a.href);
  });

  // Resizable split
  initResizer();

  // Social links — open in a new Chrome tab
  const SOCIAL = {
    "link-x":     "https://x.com/0x4161",
    "link-insta":  "https://instagram.com/fx_py3",
    "link-li":     "https://linkedin.com/in/ahmad-alanazi-b1040933b/",
  };
  Object.entries(SOCIAL).forEach(([id, url]) => {
    const btn = document.getElementById(id);
    if (btn) btn.addEventListener("click", () => chrome.tabs.create({ url }));
  });

  // Boot
  loadAll();
  startPoll();
});
