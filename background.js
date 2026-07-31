"use strict";

// ── Keep service worker alive (MV3 can kill it after ~30s idle) ───────────────
// We use an alarm that fires every 25s to prevent the SW from being suspended.
chrome.alarms.create("keepAlive", { periodInMinutes: 0.4 });
chrome.alarms.onAlarm.addListener(() => { syncPushBurst(); });

// ── WebSocket sync: fire-and-forget push on each alarm tick ─────────────────
// Panel.js holds the persistent WS for receiving. The SW just pushes history
// in short-lived bursts so containers without DevTools open still share traffic.
let syncLastPushCount = 0;

function syncPushBurst() {
  let allHistory = [...passiveHistory];
  for (const [, t] of tabs) allHistory = allHistory.concat(t.history);
  if (allHistory.length === syncLastPushCount) return; // nothing new
  syncLastPushCount = allHistory.length;

  try {
    const ws = new WebSocket("ws://localhost:17580");
    ws.onopen = () => {
      chrome.storage.local.get("voidContainerName", r => {
        const name = r.voidContainerName || "main";
        ws.send(JSON.stringify({ type: "register", name }));
        ws.send(JSON.stringify({ type: "history", entries: allHistory }));
        // Close after a short delay to let the server process
        setTimeout(() => ws.close(), 500);
      });
    };
    ws.onerror = () => { ws.close(); };
  } catch {}
}

// ── Passive traffic capture (webRequest — no debugger needed) ────────────────
// Captures all HTTP traffic across ALL tabs automatically. The debugger-based
// capture (Network.requestWillBeSent etc.) still provides richer data (bodies,
// timing) when attached, but this ensures Logger always has traffic to show.
const passiveHistory = [];  // { method, url, host, path, status, headers, respHeaders, time, elapsed, tabId }
const passivePending = {};  // requestId → { method, url, headers, body, time, tabId }
const passiveBodies  = {};  // requestId → decoded request body (onBeforeRequest fires first)

const PASSIVE_BODY_CAP = 100000; // chars — avoid holding whole file uploads in memory

// webRequest can read the REQUEST body (onBeforeRequest + "requestBody"), but never
// the response body — that needs the debugger. Entries are tagged with `capture` so
// the panel can say which limitation applies.
function decodeRequestBody(rb) {
  if (!rb || rb.error) return "";
  if (rb.formData) {
    return Object.entries(rb.formData)
      .map(([k, vs]) => (vs || []).map(v => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join("&"))
      .join("&")
      .slice(0, PASSIVE_BODY_CAP);
  }
  if (Array.isArray(rb.raw)) {
    try {
      const dec = new TextDecoder("utf-8", { fatal: false });
      let out = "";
      for (const part of rb.raw) {
        if (part.file) { out += `(file: ${part.file})`; continue; }
        if (part.bytes) out += dec.decode(new Uint8Array(part.bytes));
        if (out.length > PASSIVE_BODY_CAP) break;
      }
      return out.slice(0, PASSIVE_BODY_CAP);
    } catch { return ""; }
  }
  return "";
}

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.tabId < 0) return;
    if (!details.requestBody) return;
    const body = decodeRequestBody(details.requestBody);
    if (body) passiveBodies[details.requestId] = body;
  },
  { urls: ["<all_urls>"] },
  ["requestBody"]
);

chrome.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    if (details.tabId < 0) return; // skip non-tab requests (SW, etc.)
    const hdrs = {};
    (details.requestHeaders || []).forEach(h => { hdrs[h.name] = h.value || ""; });
    const body = passiveBodies[details.requestId] || "";
    delete passiveBodies[details.requestId];
    passivePending[details.requestId] = {
      method: details.method,
      url: details.url,
      headers: hdrs,
      body,
      time: details.timeStamp || Date.now(),
      tabId: details.tabId,
      type: details.type,
    };
  },
  { urls: ["<all_urls>"] },
  ["requestHeaders"]
);

chrome.webRequest.onCompleted.addListener(
  (details) => {
    const pending = passivePending[details.requestId];
    delete passivePending[details.requestId];
    delete passiveBodies[details.requestId]; // cached responses skip onBeforeSendHeaders
    if (!pending) return;

    let host = "", path = "";
    try { const u = new URL(details.url); host = u.host; path = u.pathname + u.search; } catch {}

    const respHdrs = {};
    (details.responseHeaders || []).forEach(h => { respHdrs[h.name.toLowerCase()] = h.value || ""; });

    const entry = {
      method: pending.method,
      url: details.url,
      host, path,
      status: details.statusCode,
      statusText: "",
      headers: pending.headers,
      respHeaders: respHdrs,
      body: pending.body || "",
      respBody: "",           // webRequest cannot read response bodies — debugger only
      length: 0,
      mimeType: respHdrs["content-type"] || "",
      time: pending.time,
      elapsed: Math.round((details.timeStamp || Date.now()) - pending.time),
      resourceType: pending.type || "other",
      tabId: pending.tabId,
      capture: "passive",
    };
    addHostHeader(entry);
    passiveHistory.push(entry);
    // Cap to prevent unbounded growth
    if (passiveHistory.length > 8000) passiveHistory.splice(0, 1000);
    // Trigger sync push
    syncPushBurst();
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

// Clean up stale pending entries (requests that never completed)
chrome.webRequest.onErrorOccurred.addListener(
  (details) => {
    delete passivePending[details.requestId];
    delete passiveBodies[details.requestId];
  },
  { urls: ["<all_urls>"] }
);

// Neither capture path reports Host: Chrome's network stack appends it below the
// webRequest/CDP surface, and over HTTP/2 the wire carries :authority instead.
// Without it a request sent on to Repeater or Intruder loses which vhost it was
// aimed at, so put it back from the URL.
function addHostHeader(entry) {
  const hdrs = entry.headers || (entry.headers = {});
  if (Object.keys(hdrs).some(k => k.toLowerCase() === "host")) return;
  let host = entry.host;
  if (!host) { try { host = new URL(entry.url).host; } catch { return; } }
  if (!host) return;
  entry.headers = { Host: host, ...hdrs }; // first line, as on the wire
}

// ── Proxy traffic (from void-proxy-server.js, relayed by the panel) ─────────
// The external proxy captures clients Chrome never sees — curl, Postman, a
// phone. The panel holds the control WebSocket and forwards completed
// transactions here so they land in History/Logger like anything else.
const proxyHistory = [];

// ── Settings (shared across tabs) ────────────────────────────────────────────
let voidSettings = {
  matchReplace: [],
  autoHeaders: "",
  scopeInclude: "", scopeExclude: "",
  followRedirects: true, timeout: "30000",
};

// Load settings from storage on SW start
chrome.storage.local.get("voidSettings", r => {
  if (r.voidSettings) voidSettings = { ...voidSettings, ...r.voidSettings };
});

function urlInScope(url) {
  const inc = (voidSettings.scopeInclude || "").trim();
  const exc = (voidSettings.scopeExclude || "").trim();
  if (exc) {
    const patterns = exc.split("\n").map(p => p.trim()).filter(Boolean);
    if (patterns.some(p => matchWild(url, p))) return false;
  }
  if (inc) {
    const patterns = inc.split("\n").map(p => p.trim()).filter(Boolean);
    return patterns.some(p => matchWild(url, p));
  }
  return true; // no include = all
}

function matchWild(str, pattern) {
  const re = new RegExp("^" + pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*") + "$", "i");
  return re.test(str);
}

function applyMatchReplace(url, headers, body, direction) {
  // direction: "req" or "resp"
  const rules = (voidSettings.matchReplace || []).filter(r => {
    if (r.enabled === false) return false;
    if (direction === "req" && !r.type.startsWith("req") && r.type !== "url") return false;
    if (direction === "resp" && !r.type.startsWith("resp")) return false;
    if (r.scope && !matchWild(url, r.scope)) return false;
    return true;
  });

  let modUrl = url;
  let modHeaders = { ...headers };
  let modBody = body;

  for (const rule of rules) {
    try {
      if (rule.type === "url") {
        if (!rule.match) continue;
        modUrl = modUrl.replace(new RegExp(rule.match, "g"), rule.replace || "");
      } else if (rule.type === "req-header" || rule.type === "resp-header") {
        if (!rule.match) {
          // Empty match = add header. Replace format: "Name: Value"
          const ci = (rule.replace || "").indexOf(":");
          if (ci > 0) {
            modHeaders[rule.replace.slice(0, ci).trim()] = rule.replace.slice(ci + 1).trim();
          }
        } else {
          // Replace in header values
          const re = new RegExp(rule.match, "g");
          const newHdrs = {};
          for (const [k, v] of Object.entries(modHeaders)) {
            const newK = k.replace(re, rule.replace || "");
            const newV = v.replace(re, rule.replace || "");
            newHdrs[newK] = newV;
          }
          modHeaders = newHdrs;
        }
      } else if (rule.type === "req-body" || rule.type === "resp-body") {
        if (rule.match && modBody) {
          modBody = modBody.replace(new RegExp(rule.match, "g"), rule.replace || "");
        }
      }
    } catch { /* invalid regex — skip */ }
  }

  return { url: modUrl, headers: modHeaders, body: modBody };
}

function parseAutoHeaders() {
  const hdrs = {};
  (voidSettings.autoHeaders || "").split("\n").forEach(line => {
    const i = line.indexOf(":");
    if (i > 0) hdrs[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  });
  return hdrs;
}

function fetchResponseBody(tabId, requestId, tabState, histIdx, retries = 3) {
  if (!tabState.attached) return; // don't try if not attached
  chrome.debugger.sendCommand(
    { tabId }, "Network.getResponseBody",
    { requestId },
    (result) => {
      const err = chrome.runtime.lastError;
      if (err || !result) {
        // Don't retry if debugger is gone
        if (err && /not attached/i.test(err.message || "")) return;
        if (retries > 0) {
          setTimeout(() => fetchResponseBody(tabId, requestId, tabState, histIdx, retries - 1), 200);
        }
        return;
      }
      if (result.base64Encoded) {
        try {
          tabState.history[histIdx].respBody = atob(result.body);
        } catch {
          tabState.history[histIdx].respBody = "(binary data, " + (result.body?.length || 0) + " bytes)";
        }
      } else {
        tabState.history[histIdx].respBody = result.body || "";
      }
    }
  );
}

// ── Per-tab state (in-memory; cleared on SW restart) ─────────────────────────
const tabs = new Map();

function getTab(id) {
  if (!tabs.has(id)) {
    tabs.set(id, {
      attached:     false,
      intercepting: false,
      pending:      {},   // requestId → request object
      endpoints:    [],
      technologies: [],
      headers:      {},   // merged security response headers (all responses in tab)
      headerSrc:    {},   // header name → URL of the response it came from
      docHeaders:   null, // main-document response headers only (authoritative)
      docUrl:       "",   // URL those main-document headers came from
      docStatus:    null,
      history:      [],   // HTTP history entries
      historyMap:   {},   // Network.requestId → history index (for matching responses)
      wsConnections: {},  // requestId → { url, status, time }
      wsFrames:      [],  // { requestId, url, direction, opcode, data, length, time, mask }
    });
  }
  return tabs.get(id);
}


// Clean up tabs when closed
chrome.tabs.onRemoved.addListener(id => {
  tabs.delete(id);
  probeInjectedTabs.delete(id);
});

// ── Debugger events ───────────────────────────────────────────────────────────

chrome.debugger.onEvent.addListener((src, method, params) => {
  const t = getTab(src.tabId);
  if (!t) return;

  // ── HTTP History: capture requests ──────────────────────────────────────
  if (method === "Network.requestWillBeSent") {
    const req = params.request || {};
    const entry = {
      id:           params.requestId,
      method:       req.method || "GET",
      url:          req.url || "",
      host:         "",
      path:         "",
      headers:      req.headers || {},
      body:         req.postData || "",
      status:       null,
      statusText:   "",
      respHeaders:  {},
      length:       0,
      mimeType:     "",
      time:         Date.now(),
      elapsed:      0,
      resourceType: params.type || "other",
      tabId:        src.tabId,
      capture:      "debugger",
    };
    try {
      const u = new URL(entry.url);
      entry.host = u.host;
      entry.path = u.pathname + u.search;
    } catch {}
    addHostHeader(entry);
    t.history.push(entry);
    // Cap history to prevent unbounded memory growth
    if (t.history.length > 10000) {
      t.history.splice(0, 1000);
      t.historyMap = {};
      t.history.forEach((e, i) => { if (e.id) t.historyMap[e.id] = i; });
    }
    t.historyMap[params.requestId] = t.history.length - 1;

    // Auto-populate endpoints from network traffic
    const epUrl = entry.url;
    if (epUrl && !t._epSeen) t._epSeen = new Set(t.endpoints.map(e => e.url));
    if (epUrl && !t._epSeen.has(epUrl)) {
      const epType = netGuessType(epUrl, params.type);
      if (epType) {
        t.endpoints.push({ url: epUrl, method: entry.method, type: epType });
        t._epSeen.add(epUrl);
      }
    }
  }

  // ── HTTP History: capture responses ────────────────────────────────────
  if (method === "Network.responseReceived") {
    const idx = t.historyMap[params.requestId];
    if (idx !== undefined && t.history[idx]) {
      const resp = params.response || {};
      t.history[idx].status      = resp.status;
      t.history[idx].statusText  = resp.statusText || "";
      t.history[idx].mimeType    = resp.mimeType || "";
      t.history[idx].length      = resp.encodedDataLength || 0;
      t.history[idx].elapsed     = Date.now() - t.history[idx].time;

      t.history[idx].respHeaders = resp.headers || {};
    }
  }

  // ── HTTP History: capture response body when loading finishes ────────
  if (method === "Network.loadingFinished") {
    const reqId = params.requestId;
    const idx = t.historyMap[reqId];
    if (idx !== undefined && t.history[idx] && !t.history[idx].respBody) {
      fetchResponseBody(src.tabId, reqId, t, idx);
    }
    // Push to sync server (debounced — only if count changed)
    syncPushBurst();
  }

  // ── Also try on dataReceived for streaming responses ────────────────
  if (method === "Network.dataReceived") {
    const idx = t.historyMap[params.requestId];
    if (idx !== undefined && t.history[idx]) {
      t.history[idx].length = (t.history[idx].length || 0) + (params.dataLength || 0);
    }
  }

  // ── WebSocket: track connections and frames ─────────────────────────
  if (method === "Network.webSocketCreated") {
    t.wsConnections[params.requestId] = { url: params.url || "", status: "connecting", time: Date.now() };
  }
  if (method === "Network.webSocketHandshakeResponseReceived") {
    if (t.wsConnections[params.requestId]) t.wsConnections[params.requestId].status = "open";
  }
  if (method === "Network.webSocketFrameSent") {
    const conn = t.wsConnections[params.requestId];
    const frame = params.response || {};
    t.wsFrames.push({ requestId: params.requestId, url: conn?.url || "", direction: "sent", opcode: frame.opcode ?? 1, data: (frame.payloadData || "").slice(0, 100000), length: frame.payloadData?.length || 0, time: Date.now(), mask: frame.mask ?? true });
    if (t.wsFrames.length > 5000) t.wsFrames.splice(0, 500);
  }
  if (method === "Network.webSocketFrameReceived") {
    const conn = t.wsConnections[params.requestId];
    const frame = params.response || {};
    t.wsFrames.push({ requestId: params.requestId, url: conn?.url || "", direction: "received", opcode: frame.opcode ?? 1, data: (frame.payloadData || "").slice(0, 100000), length: frame.payloadData?.length || 0, time: Date.now(), mask: frame.mask ?? false });
    if (t.wsFrames.length > 5000) t.wsFrames.splice(0, 500);
  }
  if (method === "Network.webSocketClosed") {
    if (t.wsConnections[params.requestId]) t.wsConnections[params.requestId].status = "closed";
  }

  if (method === "Fetch.requestPaused") {
    const reqUrl = params.request.url;
    const reqHeaders = params.request.headers || {};
    const reqBody = params.request.postData || "";

    // Apply Match & Replace + Auto Headers even when not intercepting
    const autoHdrs = parseAutoHeaders();
    const merged = { ...reqHeaders, ...autoHdrs };
    const mr = applyMatchReplace(reqUrl, merged, reqBody, "req");

    if (!t.intercepting) {
      // auto-forward with modifications applied
      const opts = { requestId: params.requestId };
      if (mr.url !== reqUrl) opts.url = mr.url;
      const hdrEntries = Object.entries(mr.headers);
      const origEntries = Object.entries(reqHeaders);
      if (hdrEntries.length !== origEntries.length || JSON.stringify(mr.headers) !== JSON.stringify(reqHeaders)) {
        opts.headers = hdrEntries.map(([name, value]) => ({ name, value: String(value) }));
      }
      if (mr.body !== reqBody && mr.body) {
        try { opts.postData = btoa(unescape(encodeURIComponent(mr.body))); } catch {}
      }
      chrome.debugger.sendCommand(
        { tabId: src.tabId }, "Fetch.continueRequest", opts, () => {
          void chrome.runtime.lastError;
        }
      );
      return;
    }
    t.pending[params.requestId] = {
      requestId:    params.requestId,
      url:          mr.url,
      method:       params.request.method,
      headers:      mr.headers,
      body:         mr.body,
      resourceType: params.resourceType || "other",
    };
  }

  if (method === "Network.responseReceived") {
    const SAFE_HDRS = new Set([
      "content-security-policy","strict-transport-security","x-frame-options",
      "x-content-type-options","referrer-policy","permissions-policy",
      "access-control-allow-origin","x-powered-by","server","set-cookie",
      "x-xss-protection","cross-origin-opener-policy","cross-origin-embedder-policy",
      "x-generator","x-drupal-cache","x-wordpress-theme","x-aspnet-version",
      "x-runtime","x-served-by","via","x-cache","cf-ray","x-amz-cf-id",
      "alt-svc","x-netlify","x-heroku-queue-wait-time","x-render-origin-server",
      "x-vercel-id","x-github-request-id","x-wp-engine","x-pantheon-styx-hostname",
      "x-amz-request-id","x-robots-tag","link",
    ]);
    const raw = params.response?.headers || {};
    const respUrl = params.response?.url || "";

    // For a navigation's main resource CDP reuses the loaderId as the requestId.
    // That distinguishes the top-level document from sub-frames, XHRs and assets
    // — which matters because CSP/HSTS/X-Frame-Options are only meaningful for
    // the top document, and the merged map below happily lets a third-party
    // iframe's headers overwrite the real ones.
    if (params.type === "Document" && params.requestId === params.loaderId) {
      t.docHeaders = {};
      Object.keys(raw).forEach(k => { t.docHeaders[k.toLowerCase()] = raw[k]; });
      t.docUrl    = respUrl;
      t.docStatus = params.response?.status ?? null;
    }

    Object.keys(raw).forEach(k => {
      const lk = k.toLowerCase();
      if (SAFE_HDRS.has(lk)) {
        t.headers[lk] = raw[k];
        t.headerSrc[lk] = respUrl;
      }
    });

    // Header-based tech detection (only for main document)
    if (params.type === "Document") {
      const h = k => (raw[k] || raw[k.toLowerCase()] || "");
      const server    = h("server").toLowerCase();
      const powered   = h("x-powered-by").toLowerCase();
      const generator = h("x-generator").toLowerCase();
      const via       = h("via").toLowerCase();
      const altSvc    = h("alt-svc").toLowerCase();

      const techSeen = new Set(t.technologies.map(x => x.name));
      function hdrAdd(name, cat, version) {
        if (!techSeen.has(name)) {
          t.technologies.push({ name, cat, version: version || null, evidence: "HTTP header" });
          techSeen.add(name);
        }
      }

      // Server header
      if (/nginx/i.test(server))           hdrAdd("Nginx",   "Web Server", server.match(/nginx\/([\d.]+)/i)?.[1]);
      if (/apache/i.test(server))          hdrAdd("Apache",  "Web Server", server.match(/apache\/([\d.]+)/i)?.[1]);
      if (/microsoft-iis/i.test(server))   hdrAdd("IIS",     "Web Server", server.match(/iis\/([\d.]+)/i)?.[1]);
      if (/cloudflare/i.test(server))      hdrAdd("Cloudflare", "CDN / Security");
      if (/openresty/i.test(server))       hdrAdd("OpenResty","Web Server", server.match(/openresty\/([\d.]+)/i)?.[1]);
      if (/litespeed/i.test(server))       hdrAdd("LiteSpeed","Web Server");
      if (/caddy/i.test(server))           hdrAdd("Caddy",   "Web Server");
      if (/gunicorn/i.test(server))        hdrAdd("Gunicorn","App Server");
      if (/unicorn/i.test(server))         hdrAdd("Unicorn", "App Server");
      if (/jetty/i.test(server))           hdrAdd("Jetty",   "App Server");
      if (/tomcat/i.test(server))          hdrAdd("Tomcat",  "App Server");

      // X-Powered-By
      if (/php/i.test(powered))            hdrAdd("PHP",      "Programming Language", powered.match(/php\/([\d.]+)/i)?.[1]);
      if (/asp\.net/i.test(powered))       hdrAdd("ASP.NET",  "Programming Language", powered.match(/asp\.net version\/([\d.]+)/i)?.[1]);
      if (/express/i.test(powered))        hdrAdd("Express",  "Framework");
      if (/next\.js/i.test(powered))       hdrAdd("Next.js",  "Meta-Framework");
      if (/rails/i.test(powered))          hdrAdd("Ruby on Rails","Framework");

      // X-Generator
      if (/wordpress/i.test(generator))    hdrAdd("WordPress","CMS", generator.match(/wordpress\s*([\d.]+)/i)?.[1]);
      if (/drupal/i.test(generator))       hdrAdd("Drupal",   "CMS");
      if (/joomla/i.test(generator))       hdrAdd("Joomla",   "CMS");

      // Via (CDN/Proxy)
      if (/varnish/i.test(via))            hdrAdd("Varnish",  "Cache");
      if (/cloudfront/i.test(via))         hdrAdd("AWS CloudFront","CDN");
      if (/fastly/i.test(via))             hdrAdd("Fastly",   "CDN");

      // CF-Ray header = Cloudflare
      if (h("cf-ray"))                     hdrAdd("Cloudflare","CDN / Security");
      // X-Amz = AWS
      if (h("x-amz-cf-id"))               hdrAdd("AWS CloudFront","CDN");
      if (h("x-amz-request-id"))          hdrAdd("AWS",      "Cloud");

      // Alt-Svc → HTTP/3
      if (/\bh3\b/.test(altSvc))           hdrAdd("HTTP/3",   "Miscellaneous");
      if (/\bh2\b/.test(altSvc) && !/\bh3\b/.test(altSvc)) hdrAdd("HTTP/2","Miscellaneous");

      // Hosting providers (from Server / special headers)
      if (/hostinger/i.test(server))       hdrAdd("Hostinger","Hosting");
      if (/siteground/i.test(server))      hdrAdd("SiteGround","Hosting");
      if (/bluehost/i.test(server))        hdrAdd("Bluehost","Hosting");
      if (/wpengine/i.test(server) || h("x-wp-engine")) hdrAdd("WP Engine","Hosting");
      if (/pantheon/i.test(server) || h("x-pantheon-styx-hostname")) hdrAdd("Pantheon","Hosting");
      if (h("x-vercel-id"))                hdrAdd("Vercel",   "Hosting");
      if (h("x-netlify"))                  hdrAdd("Netlify",  "Hosting");
      if (h("x-heroku-queue-wait-time"))   hdrAdd("Heroku",   "Hosting");
      if (h("x-render-origin-server"))     hdrAdd("Render",   "Hosting");
      if (h("x-github-request-id") && /pages/i.test(server)) hdrAdd("GitHub Pages","Hosting");
      if (/kinsta/i.test(server))          hdrAdd("Kinsta",   "Hosting");
      if (/flywheel/i.test(server))        hdrAdd("Flywheel", "Hosting");
      if (/digitalocean/i.test(server))    hdrAdd("DigitalOcean","Hosting");

      // LS-Cache header = LiteSpeed Cache (WordPress plugin)
      if (h("x-litespeed-cache") || h("x-lsadc"))  hdrAdd("LiteSpeed Cache","Cache");
    }
  }
});

// Tabs pending auto-reattach: tabId → { intercepting: bool }
const pendingReattach = new Map();

chrome.debugger.onDetach.addListener((src, reason) => {
  const tabId = src.tabId;
  const t = tabs.get(tabId);
  if (!t) return;
  const wasIntercepting = t.intercepting;
  const wasAttached = t.attached;
  t.attached     = false;
  t.intercepting = false;
  t.pending      = {};

  if (wasAttached && !t._userDetached) {
    pendingReattach.set(tabId, { intercepting: wasIntercepting });
    setTimeout(() => doReattach(tabId), reason === "canceled_by_user" ? 300 : 0);
  }
  t._userDetached = false;
});

function doReattach(tabId) {
  const info = pendingReattach.get(tabId);
  if (!info) return;
  info._retries = (info._retries || 0) + 1;
  if (info._retries > 20) { pendingReattach.delete(tabId); return; }
  chrome.debugger.attach({ tabId }, "1.3", () => {
    if (chrome.runtime.lastError) return; // retry via onUpdated
    pendingReattach.delete(tabId);
    const t = getTab(tabId);
    t.attached = true;
    chrome.debugger.sendCommand({ tabId }, "Network.enable", {}, () => {
      void chrome.runtime.lastError;
    });
    if (info.intercepting) {
      chrome.debugger.sendCommand({ tabId }, "Fetch.enable", {
        patterns: [{ urlPattern: "*", requestStage: "Request" }],
      }, () => {
        if (!chrome.runtime.lastError && info.intercepting) t.intercepting = true;
      });
    }
  });
}

chrome.tabs.onUpdated.addListener((tabId, info) => {
  // Re-attach as soon as the tab starts loading or completes
  if (pendingReattach.has(tabId)) {
    doReattach(tabId);
  }
  if (info.status === "loading") {
    const t = tabs.get(tabId);
    if (t) {
      t.endpoints = []; t.technologies = []; t.headers = {}; t.headerSrc = {};
      t.docHeaders = null; t.docUrl = ""; t.docStatus = null;
      t.pending = {}; t._epSeen = null;
      t.wsConnections = {}; t.wsFrames = [];
    }
    probeInjectedTabs.delete(tabId);
  }
});


// ── Message handler ───────────────────────────────────────────────────────────

const ALLOWED = new Set([
  "PING",
  "ATTACH","DETACH","INTERCEPT_ON","INTERCEPT_OFF",
  "FORWARD","DROP","SEND_REQUEST",
  "GET_DATA","GET_INTERCEPTED","GET_HISTORY","CLEAR_HISTORY","REPORT","CLEAR",
  "RESTORE_HISTORY","RESTORE_ENDPOINTS",
  "CNT_LAUNCH","CNT_AUTO_EXPORT","GET_EXT_PATH","PROXY_TXN",
  "LOOKUP","CRAWL_START","CRAWL_STOP","UPDATE_SETTINGS","GET_COOKIES","GET_WS_HISTORY",
  "PROBE_INJECT","PROBE_CMD","PROBE_STATUS","PROBE_FINDINGS",
]);

// ── Probe (DOM XSS Hunter) ─────────────────────────────────────────────────
const PROBE_SCRIPTS = [
  'probe/config.js', 'probe/utils.js', 'probe/highlighter.js',
  'probe/scanner.js', 'probe/flows.js', 'probe/hooks.js',
  'probe/probe.js', 'probe/fuzzer-helpers.js', 'probe/fuzzer-core.js',
  'probe/fuzzer-tools.js', 'probe/fuzzer-autofill.js',
  'probe/frameworks.js', 'probe/reporter.js', 'probe/main.js',
];
const probeInjectedTabs = new Set();

// Shared console hook function (runs in MAIN world)
const PROBE_CONSOLE_HOOK = () => {
  if (window.__probeLog) return;
  window.__probeLog = [];
  window.__probeLogIdx = 0;
  const origLog = console.log.bind(console);
  const origInfo = console.info.bind(console);
  const origWarn = console.warn.bind(console);
  const origGroup = console.group.bind(console);
  const origGroupEnd = console.groupEnd.bind(console);
  const origTable = console.table.bind(console);
  const origClear = console.clear.bind(console);

  function stripC(args) {
    if (!args.length) return { text: "", styles: [] };
    const first = args[0];
    if (typeof first !== "string") {
      return { text: args.map(a => typeof a === "object" ? JSON.stringify(a, null, 2) : String(a)).join(" "), styles: [] };
    }
    const styles = [];
    let si = 1;
    const text = first.replace(/%c/g, () => {
      const style = si < args.length ? String(args[si]) : "";
      si++;
      styles.push(style);
      return "\x00STYLE\x00";
    });
    return { text, styles };
  }

  function capture(type, args) {
    const { text, styles } = stripC(args);
    window.__probeLog.push({ id: window.__probeLogIdx++, type, text, styles, ts: Date.now() });
    if (window.__probeLog.length > 2000) window.__probeLog.splice(0, 500);
  }

  console.log = function(...a) { capture("log", a); return origLog(...a); };
  console.info = function(...a) { capture("info", a); return origInfo(...a); };
  console.warn = function(...a) { capture("warn", a); return origWarn(...a); };
  console.group = function(...a) { capture("group", a); return origGroup(...a); };
  console.groupEnd = function(...a) { capture("groupEnd", a); return origGroupEnd(...a); };
  console.table = function(data, ...rest) {
    try {
      const text = typeof data === "object" ? JSON.stringify(data, null, 2) : String(data);
      window.__probeLog.push({ id: window.__probeLogIdx++, type: "table", text, styles: [], ts: Date.now() });
    } catch {}
    return origTable(data, ...rest);
  };
  console.clear = function() {
    window.__probeLog.push({ id: window.__probeLogIdx++, type: "clear", text: "", styles: [], ts: Date.now() });
    return origClear();
  };
};

// Shared script injection function (runs in ISOLATED world, creates <script> tags in MAIN world)
const PROBE_INJECT_SCRIPTS_FN = (urls) => {
  return new Promise((resolve) => {
    let i = 0;
    function next() {
      if (i >= urls.length) { resolve(); return; }
      const s = document.createElement("script");
      s.src = urls[i];
      s.onload = () => { s.remove(); i++; next(); };
      s.onerror = () => { s.remove(); i++; next(); };
      (document.head || document.documentElement).appendChild(s);
    }
    next();
  });
};

// Bootstrap: install console hook + inject scripts
async function probeBootstrap(tabId) {
  await chrome.scripting.executeScript({ target: { tabId }, world: "MAIN", func: PROBE_CONSOLE_HOOK });
  const scriptUrls = PROBE_SCRIPTS.map(f => chrome.runtime.getURL(f));
  await chrome.scripting.executeScript({ target: { tabId }, func: PROBE_INJECT_SCRIPTS_FN, args: [scriptUrls] });
  probeInjectedTabs.add(tabId);
}

// ── Crawler ────────────────────────────────────────────────────────────────
let crawlAbortCtrl = null;

function netGuessType(url, resourceType) {
  const u = url.toLowerCase().split("?")[0];
  // Skip static assets
  if (/\.(css|woff2?|ttf|eot|png|jpe?g|gif|webp|ico|svg|map)$/.test(u)) return null;
  if (resourceType === "Image" || resourceType === "Font" || resourceType === "Stylesheet") return null;
  if (/\/api\/|\/v\d+\/|\/graphql|\/rest\//.test(u) || resourceType === "XHR" || resourceType === "Fetch") return "api";
  if (/\.(js|mjs)$/.test(u) || resourceType === "Script") return "script";
  if (resourceType === "Document") return "link";
  return "link";
}

function crawlGuessType(url) {
  const u = url.toLowerCase().split("?")[0];
  if (/\/api\/|\/v\d+\/|\/graphql|\/rest\//.test(u)) return "api";
  if (/\.(js|mjs)$/.test(u)) return "script";
  if (/\.(css|woff2?|ttf|eot|png|jpe?g|gif|webp|ico|svg)$/.test(u)) return null;
  return "link";
}

function crawlExtractUrls(html, pageUrl, origin) {
  const found = new Set();
  const attrRe = /(?:href|src|action|data-url|data-href)\s*=\s*["']([^"'\s>]+)["']/gi;
  const jsRe   = /(?:fetch|axios\.(?:get|post|put|patch|delete)|\.open)\s*\(\s*["'`]([^"'`\s]+)["'`]/gi;
  for (const re of [attrRe, jsRe]) {
    let m;
    while ((m = re.exec(html)) !== null) {
      try {
        const raw = m[1].trim();
        if (!raw || raw.startsWith("javascript:") || raw.startsWith("mailto:") || raw.startsWith("data:")) continue;
        const u = new URL(raw, pageUrl);
        if (u.origin !== origin) continue;
        u.hash = "";
        found.add(u.href);
      } catch {}
    }
  }
  return [...found];
}

async function startCrawl(tabId, origin, seeds, maxPages) {
  crawlAbortCtrl = new AbortController();
  const signal = crawlAbortCtrl.signal;
  const visited = new Set();
  const epSeen  = new Set(seeds);
  const queue   = [...new Set(seeds)];

  if (tabId) {
    const t = getTab(tabId);
    const tSeen = new Set(t.endpoints.map(e => e.url));
    for (const url of seeds) {
      if (!tSeen.has(url)) {
        t.endpoints.push({ url, method: "GET", type: crawlGuessType(url) || "link" });
        tSeen.add(url);
      }
    }
  }

  while (queue.length > 0 && visited.size < maxPages && !signal.aborted) {
    const url = queue.shift();
    if (visited.has(url)) continue;
    visited.add(url);

    chrome.runtime.sendMessage({
      type: "CRAWL_PROGRESS",
      visited: visited.size,
      total: Math.min(queue.length + visited.size, maxPages),
      currentUrl: url,
      newEndpoints: [],
    }).catch(() => {});

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 7000);
      signal.addEventListener("abort", () => controller.abort(), { once: true });

      const resp = await fetch(url, {
        method: "GET",
        redirect: "follow",
        signal: controller.signal,
        headers: { "Accept": "text/html,application/xhtml+xml,*/*;q=0.9" },
      });
      clearTimeout(timer);

      const ct = resp.headers.get("content-type") || "";
      if (!ct.includes("html")) continue;

      const html = await resp.text();
      const links = crawlExtractUrls(html, url, origin);
      const newEndpoints = [];

      for (const link of links) {
        const type = crawlGuessType(link);
        if (type === null) continue;
        if (!epSeen.has(link)) {
          epSeen.add(link);
          newEndpoints.push({ url: link, method: "GET", type });
        }
        if (!visited.has(link) && type === "link") queue.push(link);
      }

      if (newEndpoints.length) {
        if (tabId) {
          const t = getTab(tabId);
          const tSeen = new Set(t.endpoints.map(e => e.url));
          for (const ep of newEndpoints) {
            if (!tSeen.has(ep.url)) { t.endpoints.push(ep); tSeen.add(ep.url); }
          }
        }
        chrome.runtime.sendMessage({
          type: "CRAWL_PROGRESS",
          visited: visited.size,
          total: Math.min(queue.length + visited.size, maxPages),
          currentUrl: url,
          newEndpoints,
        }).catch(() => {});
      }
    } catch { /* timeout / abort — skip */ }
  }

  chrome.runtime.sendMessage({
    type: "CRAWL_DONE",
    visited: visited.size,
    stopped: signal.aborted,
  }).catch(() => {});
  crawlAbortCtrl = null;
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg?.type || !ALLOWED.has(msg.type)) return;
  if (sender.id !== chrome.runtime.id) return; // only our own extension

  const tabId = msg.tabId ?? sender.tab?.id;

  switch (msg.type) {

    case "PING": { sendResponse({ ok: true }); break; }

    // ── Recon from content script ───────────────────────────────────────────
    case "REPORT": {
      if (!tabId) { sendResponse({ ok: true }); break; }
      const t = getTab(tabId);
      if (Array.isArray(msg.endpoints)) {
        const seen = new Set(t.endpoints.map(e => e.url));
        for (const ep of msg.endpoints) {
          if (ep?.url && typeof ep.url === "string" && !seen.has(ep.url)) {
            t.endpoints.push({ url: ep.url, method: ep.method || "GET", type: ep.type || "link" });
            seen.add(ep.url);
          }
        }
      }
      if (Array.isArray(msg.technologies)) {
        const seen = new Set(t.technologies.map(x => x.name));
        for (const tech of msg.technologies) {
          if (tech?.name && typeof tech.name === "string" && !seen.has(tech.name)) {
            t.technologies.push({
              name:     tech.name,
              cat:      tech.cat || tech.category || "Other",
              version:  tech.version  || null,
              evidence: tech.evidence || null,
            });
            seen.add(tech.name);
          }
        }
      }
      sendResponse({ ok: true });
      break;
    }

    // ── Session restore ────────────────────────────────────────────────────
    case "RESTORE_HISTORY": {
      if (!tabId) { sendResponse({ ok: false }); break; }
      const t = getTab(tabId);
      t.history = msg.history || [];
      t.historyMap = {};
      t.history.forEach((e, i) => { if (e.id) t.historyMap[e.id] = i; });
      sendResponse({ ok: true });
      break;
    }
    case "RESTORE_ENDPOINTS": {
      if (!tabId) { sendResponse({ ok: false }); break; }
      const t = getTab(tabId);
      t.endpoints = msg.endpoints || [];
      t._epSeen = null;
      sendResponse({ ok: true });
      break;
    }

    // ── Containers (launch isolated Chrome instance) ────────────────────
    case "CNT_LAUNCH": {
      sendResponse({ ok: false, reason: "no-native" });
      break;
    }

    case "CNT_AUTO_EXPORT": {
      // Auto-export this instance's history to Downloads for cross-container sync
      const name = msg.name || "void-container";
      let allHistory = [];
      for (const [, t] of tabs) { allHistory = allHistory.concat(t.history); }
      const data = JSON.stringify({ name, timestamp: new Date().toISOString(), history: allHistory });
      const blob = new Blob([data], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      chrome.downloads.download({
        url,
        filename: `void-sync/${name}.json`,
        conflictAction: "overwrite",
        saveAs: false,
      }, (downloadId) => {
        void chrome.runtime.lastError;
        URL.revokeObjectURL(url);
        sendResponse({ ok: !!downloadId, count: allHistory.length });
      });
      return true;
    }

    case "GET_EXT_PATH": {
      chrome.management.getSelf(info => {
        void chrome.runtime.lastError;
        sendResponse({ path: "", id: info?.id || "", installType: info?.installType || "" });
      });
      return true;
    }

    // ── Proxy transaction relayed from the panel ───────────────────────────
    case "PROXY_TXN": {
      if (msg.entry) {
        proxyHistory.push(msg.entry);
        if (proxyHistory.length > 5000) proxyHistory.splice(0, 500);
      }
      sendResponse({ ok: true });
      break;
    }

    // ── Panel reads ─────────────────────────────────────────────────────────
    case "GET_DATA": {
      if (!tabId) { sendResponse(null); break; }
      const t = getTab(tabId);
      sendResponse({
        attached:     t.attached,
        intercepting: t.intercepting,
        endpoints:    t.endpoints,
        technologies: t.technologies,
        headers:      t.headers,
        headerSrc:    t.headerSrc,
        docHeaders:   t.docHeaders,
        docUrl:       t.docUrl,
        docStatus:    t.docStatus,
      });
      break;
    }

    case "GET_INTERCEPTED": {
      if (!tabId) { sendResponse({ requests: [] }); break; }
      const t = getTab(tabId);
      sendResponse({ requests: Object.values(t.pending) });
      break;
    }

    case "GET_HISTORY": {
      if (!tabId) { sendResponse({ history: [] }); break; }
      const t = getTab(tabId);
      // Merge debugger history (rich: has bodies) + passive history (basic: all tabs).
      // The two sources timestamp the same request at different moments — Date.now()
      // on Network.requestWillBeSent vs details.timeStamp on onBeforeSendHeaders — so
      // an exact-time key never matches and every request showed up twice, once with
      // an empty body. Pair them by tab+method+url within a window instead, one-to-one
      // so genuinely repeated requests (polling) aren't collapsed into a single row.
      const DEDUP_WINDOW = 3000; // ms
      const dbgTimes = new Map(); // "tabId|METHOD|url" → [time, ...]
      for (const e of t.history) {
        const key = `${e.tabId ?? tabId}|${e.method}|${e.url}`;
        if (!dbgTimes.has(key)) dbgTimes.set(key, []);
        dbgTimes.get(key).push(e.time);
      }
      const merged = [...t.history, ...proxyHistory];
      for (const pe of passiveHistory) {
        const times = dbgTimes.get(`${pe.tabId}|${pe.method}|${pe.url}`);
        if (times) {
          const i = times.findIndex(ts => Math.abs(ts - pe.time) < DEDUP_WINDOW);
          if (i !== -1) { times.splice(i, 1); continue; } // debugger already has it, richer
        }
        merged.push(pe);
      }
      merged.sort((a, b) => (a.time || 0) - (b.time || 0));
      sendResponse({ history: merged });
      break;
    }

    case "CLEAR_HISTORY": {
      if (!tabId) { sendResponse({ ok: false }); break; }
      const t = getTab(tabId);
      t.history = []; t.historyMap = {};
      proxyHistory.length = 0;
      sendResponse({ ok: true });
      break;
    }

    case "GET_WS_HISTORY": {
      if (!tabId) { sendResponse({ frames: [], connections: {} }); break; }
      const t = getTab(tabId);
      sendResponse({ frames: t.wsFrames, connections: t.wsConnections });
      break;
    }

    case "GET_COOKIES": {
      const url = msg.url;
      if (!url) { sendResponse({ cookies: "" }); break; }
      chrome.cookies.getAll({ url }, cookies => {
        const cookieStr = (cookies || []).map(c => `${c.name}=${c.value}`).join("; ");
        sendResponse({ cookies: cookieStr });
      });
      return true; // async
    }

    case "UPDATE_SETTINGS": {
      if (msg.settings) voidSettings = { ...voidSettings, ...msg.settings };
      sendResponse({ ok: true });
      break;
    }

    case "CLEAR": {
      if (!tabId) { sendResponse({ ok: false }); break; }
      const t = getTab(tabId);
      t.endpoints = []; t.technologies = []; t.headers = {}; t._epSeen = null;
      t.headerSrc = {}; t.docHeaders = null; t.docUrl = ""; t.docStatus = null;
      sendResponse({ ok: true });
      break;
    }

    // ── Debugger: attach ────────────────────────────────────────────────────
    case "ATTACH": {
      if (!tabId) { sendResponse({ ok: false, error: "no tabId" }); break; }
      const t = getTab(tabId);

      chrome.debugger.attach({ tabId }, "1.3", () => {
        const err = chrome.runtime.lastError;
        if (err && !/already attached/i.test(err.message)) {
          sendResponse({ ok: false, error: err.message });
          return;
        }
        // Attached (or was already attached) — enable Network
        t.attached = true;
        chrome.debugger.sendCommand({ tabId }, "Network.enable", {}, () => {
          void chrome.runtime.lastError; // may already be enabled
          sendResponse({ ok: true });
        });
      });
      return true; // async
    }

    // ── Debugger: detach ────────────────────────────────────────────────────
    case "DETACH": {
      if (!tabId) { sendResponse({ ok: false }); break; }
      const t = getTab(tabId);
      t._userDetached = true; // prevent auto-reattach
      t.intercepting = false;
      t.attached = false;
      pendingReattach.delete(tabId);
      // Forward all pending before detaching
      Object.keys(t.pending).forEach(id => {
        chrome.debugger.sendCommand({ tabId }, "Fetch.continueRequest", { requestId: id }, () => {
          void chrome.runtime.lastError; // suppress
        });
      });
      t.pending = {};
      chrome.debugger.detach({ tabId }, () => {
        void chrome.runtime.lastError; // suppress if already detached
        sendResponse({ ok: true });
      });
      return true;
    }

    // ── Intercept ON ─────────────────────────────────────────────────────────
    case "INTERCEPT_ON": {
      if (!tabId) { sendResponse({ ok: false }); break; }
      const t = getTab(tabId);

      function doFetchEnable() {
        chrome.debugger.sendCommand({ tabId }, "Network.enable", {}, () => {
          void chrome.runtime.lastError;
          chrome.debugger.sendCommand({ tabId }, "Fetch.enable", {
            patterns: [{ urlPattern: "*", requestStage: "Request" }],
          }, () => {
            if (chrome.runtime.lastError) {
              sendResponse({ ok: false, error: chrome.runtime.lastError.message });
              return;
            }
            t.intercepting = true;
            sendResponse({ ok: true });
          });
        });
      }

      if (!t.attached) {
        // Try to attach first (might have lost state after SW restart)
        chrome.debugger.attach({ tabId }, "1.3", () => {
          const err = chrome.runtime.lastError;
          if (err && !/already attached/i.test(err.message)) {
            sendResponse({ ok: false, error: "not attached: " + err.message });
            return;
          }
          t.attached = true;
          doFetchEnable();
        });
      } else {
        doFetchEnable();
      }
      return true;
    }

    // ── Intercept OFF ────────────────────────────────────────────────────────
    case "INTERCEPT_OFF": {
      if (!tabId) { sendResponse({ ok: false }); break; }
      const t = getTab(tabId);
      t.intercepting = false;
      if (!t.attached) { sendResponse({ ok: true }); break; }
      Object.keys(t.pending).forEach(id => {
        chrome.debugger.sendCommand({ tabId }, "Fetch.continueRequest", { requestId: id }, () => {
          void chrome.runtime.lastError;
        });
      });
      t.pending = {};
      chrome.debugger.sendCommand({ tabId }, "Fetch.disable", {}, () => {
        void chrome.runtime.lastError;
        sendResponse({ ok: true });
      });
      return true;
    }

    // ── Forward paused request ───────────────────────────────────────────────
    case "FORWARD": {
      if (!tabId) { sendResponse({ ok: false }); break; }
      const t = getTab(tabId);
      const { requestId, overrides } = msg;
      if (!t.pending[requestId]) { sendResponse({ ok: false, error: "not found" }); break; }

      const opts = { requestId };
      if (overrides?.url)    opts.url    = overrides.url;
      if (overrides?.method) opts.method = overrides.method;
      if (overrides?.headers && typeof overrides.headers === "object") {
        opts.headers = Object.entries(overrides.headers)
          .filter(([k]) => typeof k === "string" && k.length > 0)
          .map(([name, value]) => ({ name, value: String(value) }));
      }
      if (overrides?.body) {
        try { opts.postData = btoa(unescape(encodeURIComponent(overrides.body))); } catch {}
      }

      chrome.debugger.sendCommand({ tabId }, "Fetch.continueRequest", opts, () => {
        void chrome.runtime.lastError;
        delete t.pending[requestId];
        sendResponse({ ok: true });
      });
      return true;
    }

    // ── Drop paused request ──────────────────────────────────────────────────
    case "DROP": {
      if (!tabId) { sendResponse({ ok: false }); break; }
      const t = getTab(tabId);
      const { requestId } = msg;
      chrome.debugger.sendCommand({ tabId }, "Fetch.failRequest",
        { requestId, errorReason: "BlockedByClient" }, () => {
          void chrome.runtime.lastError;
          delete t.pending[requestId];
          sendResponse({ ok: true });
        });
      return true;
    }

    // ── Repeater: send HTTP request ──────────────────────────────────────────
    case "SEND_REQUEST": {
      const { url, method, rawHeaders, body, targetOverride } = msg;

      // Validate URL
      let safeUrl;
      let originalHost = "";
      try {
        const u = new URL(url);
        if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error("bad protocol");
        originalHost = u.host;

        // Target override: rewrite URL to connect to different host/IP
        if (targetOverride?.host) {
          const tls = targetOverride.tls !== false;
          const port = targetOverride.port || (tls ? "443" : "80");
          u.protocol = tls ? "https:" : "http:";
          u.hostname = targetOverride.host;
          u.port = port;
        }
        safeUrl = u.href;
      } catch {
        sendResponse({ ok: false, error: "Invalid URL — must start with http:// or https://" });
        break;
      }

      // Parse raw headers (Key: Value per line)
      const headers = {};
      if (rawHeaders && typeof rawHeaders === "string") {
        rawHeaders.split("\n").forEach(line => {
          const i = line.indexOf(":");
          if (i > 0) {
            const k = line.slice(0, i).trim();
            const v = line.slice(i + 1).trim();
            // Allow Host header when target override is active
            if (k && !/^(content-length)$/i.test(k)) {
              if (/^host$/i.test(k) && !targetOverride?.host) return; // skip Host unless target override
              headers[k] = v;
            }
          }
        });
      }

      // When target override is set, inject Host header with original hostname
      if (targetOverride?.host && originalHost && !headers["Host"] && !headers["host"]) {
        headers["Host"] = originalHost;
      }

      // Apply Auto Headers + Match & Replace
      const autoHdrs = parseAutoHeaders();
      const merged = { ...headers, ...autoHdrs };
      const mr = applyMatchReplace(safeUrl, merged, body || "", "req");
      safeUrl = mr.url;

      const fetchOpts = { method: method || "GET", headers: mr.headers };
      if (mr.body && !["GET","HEAD"].includes((method || "GET").toUpperCase())) {
        fetchOpts.body = mr.body;
      }

      const timeout = parseInt(voidSettings.timeout) || 30000;
      const redirect = voidSettings.followRedirects ? "follow" : "manual";

      (async () => {
        try {
          const start = Date.now();
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), timeout);
          const resp  = await fetch(safeUrl, { ...fetchOpts, redirect, signal: controller.signal });
          clearTimeout(timer);
          const elapsed = Date.now() - start;
          const respHdrs = {};
          resp.headers.forEach((v, k) => { respHdrs[k] = v; });
          const text = await resp.text();
          sendResponse({
            ok: true,
            status:     resp.status,
            statusText: resp.statusText,
            headers:    respHdrs,
            body:       text,
            url:        resp.url,
            elapsed,
            size:       new TextEncoder().encode(text).length,
          });
        } catch (err) {
          const msg = String(err?.message || err);
          // Provide actionable error messages
          let hint = msg;
          if (/failed to fetch/i.test(msg)) {
            hint = `Network error — possible causes:\n` +
              `• Target is offline or unreachable\n` +
              `• HTTPS certificate error on target\n` +
              `• Try reloading the extension (chrome://extensions)\n` +
              `Raw: ${msg}`;
          } else if (/ssl|certificate|cert/i.test(msg)) {
            hint = `TLS/SSL error — target has an invalid certificate.\nRaw: ${msg}`;
          } else if (/timeout/i.test(msg)) {
            hint = `Request timed out — target is too slow or offline.\nRaw: ${msg}`;
          }
          sendResponse({ ok: false, error: hint });
        }
      })();
      return true; // async
    }

    // ── WHOIS / DNS / IP lookup ──────────────────────────────────────────────
    case "LOOKUP": {
      const raw = msg.domain;
      if (!raw || typeof raw !== "string") {
        sendResponse({ ok: false, error: "No domain provided" });
        break;
      }

      let domain;
      try {
        const withProto = raw.includes("://") ? raw : `https://${raw}`;
        domain = new URL(withProto).hostname.toLowerCase();
        if (!/^[a-z0-9][a-z0-9.-]{0,252}[a-z0-9]$/.test(domain)) throw new Error("bad hostname");
      } catch {
        sendResponse({ ok: false, error: "Invalid domain" });
        break;
      }

      (async () => {
        const result = { ok: true, domain };

        // ── DNS via Google DoH (accepts optional custom qname for PTR) ────
        async function dnsQ(type, qname) {
          try {
            const name = qname || domain;
            const r = await fetch(
              `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`,
              { headers: { Accept: "application/dns-json" } }
            );
            if (!r.ok) return [];
            const j = await r.json();
            return (j.Answer || []).map(a => ({ ttl: a.TTL, data: String(a.data) }));
          } catch { return []; }
        }

        // Fetch all record types in parallel
        const [aRecs, mxRaw, nsRecs, txtRaw, aaaaRecs, cnameRecs, soaRaw, caaRaw] =
          await Promise.all([
            dnsQ("A"), dnsQ("MX"), dnsQ("NS"), dnsQ("TXT"),
            dnsQ("AAAA"), dnsQ("CNAME"), dnsQ("SOA"), dnsQ("CAA"),
          ]);

        // MX — split priority from data
        const mxRecs = mxRaw.map(r => {
          const m = r.data.match(/^(\d+)\s+(.+)$/);
          return { ttl: r.ttl, priority: m ? parseInt(m[1]) : 0, data: m ? m[2].replace(/\.$/, "") : r.data };
        }).sort((a, b) => a.priority - b.priority);

        // TXT — detect SPF / DMARC / DKIM
        const txtRecs = txtRaw.map(r => {
          const d = r.data.replace(/^"|"$/g, "");
          let txtype = "TXT";
          if (/^v=spf1/i.test(d))   txtype = "SPF";
          else if (/^v=DMARC1/i.test(d)) txtype = "DMARC";
          else if (/v=DKIM1/i.test(d))   txtype = "DKIM";
          return { ttl: r.ttl, data: d, txtype };
        });

        // SOA — parse fields
        let soa = null;
        if (soaRaw[0]) {
          const p = soaRaw[0].data.split(/\s+/);
          soa = {
            ttl:     soaRaw[0].ttl,
            primary: (p[0] || "").replace(/\.$/, ""),
            admin:   (p[1] || "").replace(/\.$/, "").replace(".", "@"),
            serial:  p[2]  || null,
            refresh: p[3]  || null,
            retry:   p[4]  || null,
            expire:  p[5]  || null,
            minimum: p[6]  || null,
          };
        }

        // CAA — parse flags / tag / value
        const caaRecs = caaRaw.map(r => {
          const m = r.data.match(/^(\d+)\s+(\S+)\s+"([^"]*)"$/);
          return { ttl: r.ttl, flags: m?.[1] ?? "0", tag: m?.[2] ?? "?", value: m?.[3] ?? r.data };
        });

        result.dns = {
          a: aRecs, aaaa: aaaaRecs, mx: mxRecs, ns: nsRecs,
          txt: txtRecs, cname: cnameRecs, soa, caa: caaRecs,
        };

        // ── IP geo + PTR (reverse DNS) in parallel ────────────────────────
        const firstIp = aRecs[0]?.data;
        if (firstIp) {
          const revDomain = firstIp.split(".").reverse().join(".") + ".in-addr.arpa";

          const [ptrRecs, ipData] = await Promise.all([
            dnsQ("PTR", revDomain),
            (async () => {
              const ipApis = [
                // ipwho.is — free, HTTPS, no key, richest data
                async ip => {
                  const r = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`);
                  if (!r.ok) return null;
                  const j = await r.json();
                  if (j.success === false) return null;
                  return {
                    ip:           j.ip,
                    type:         j.type         || null,
                    flag:         j.flag?.emoji  || null,
                    country:      j.country      || null,
                    country_code: j.country_code || null,
                    continent:    j.continent    || null,
                    region:       j.region       || null,
                    region_code:  j.region_code  || null,
                    city:         j.city         || null,
                    postal:       j.postal       || null,
                    latitude:     j.latitude  != null ? j.latitude.toFixed(5)  : null,
                    longitude:    j.longitude != null ? j.longitude.toFixed(5) : null,
                    timezone:     j.timezone?.id  || null,
                    tz_utc:       j.timezone?.utc || null,
                    calling_code: j.calling_code  ? `+${j.calling_code}` : null,
                    capital:      j.capital       || null,
                    isp:          j.connection?.isp    || null,
                    org:          j.connection?.org    || null,
                    asn:          j.connection?.asn    ? `AS${j.connection.asn}` : null,
                    domain:       j.connection?.domain || null,
                  };
                },
                // freeipapi.com — fallback
                async ip => {
                  const r = await fetch(`https://freeipapi.com/api/json/${encodeURIComponent(ip)}`);
                  if (!r.ok) return null;
                  const j = await r.json();
                  if (!j.ipAddress) return null;
                  return {
                    ip:           j.ipAddress,
                    type:         j.ipVersion === 6 ? "IPv6" : "IPv4",
                    flag:         j.countryFlag  || null,
                    country:      j.countryName  || null,
                    country_code: j.countryCode  || null,
                    continent:    null,
                    region:       j.regionName   || null,
                    region_code:  null,
                    city:         j.cityName     || null,
                    postal:       j.zipCode      || null,
                    latitude:     j.latitude  != null ? String(j.latitude)  : null,
                    longitude:    j.longitude != null ? String(j.longitude) : null,
                    timezone:     j.timeZone     || null,
                    tz_utc:       null,
                    calling_code: null,
                    capital:      null,
                    isp:          j.isp          || null,
                    org:          null,
                    asn:          null,
                    domain:       null,
                  };
                },
              ];
              for (const api of ipApis) {
                try { const d = await api(ip); if (d) return d; } catch {}
              }
              return null;
            })(),
          ]);

          // PTR appears in both IP section and DNS section
          result.dns.ptr = ptrRecs;
          if (ipData) {
            ipData.ptr = ptrRecs[0]?.data?.replace(/\.$/, "") || null;
            result.ip  = ipData;
          }
        }

        // ── WHOIS via RDAP.org ────────────────────────────────────────────
        function vcardGet(entity, field) {
          const v = entity?.vcardArray?.[1]?.find(a => a[0] === field)?.[3];
          return v != null ? String(v) : null;
        }
        function parseRdap(j, tryDomain) {
          function getEvent(action) {
            return j.events?.find(e => e.eventAction === action)?.eventDate?.slice(0, 10) || null;
          }
          const registrar  = j.entities?.find(e => e.roles?.includes("registrar"));
          const registrant = j.entities?.find(e => e.roles?.includes("registrant"));
          const admin      = j.entities?.find(e => e.roles?.includes("administrative"));
          const tech       = j.entities?.find(e => e.roles?.includes("technical"));
          const abuse      = registrar?.entities?.find(e => e.roles?.includes("abuse"));

          const regUrl   = registrar?.links?.find(l => ["related","self","about"].includes(l.rel))?.href || null;
          const ianaId   = registrar?.publicIds?.find(p => p.type === "IANA Registrar ID")?.identifier || null;
          const whoisSrv = registrar?.port43 || j.port43 || null;

          const sec = j.secureDNS;
          const dnssec = sec
            ? (sec.delegationSigned ? "Signed (DS)" : sec.zoneSigned ? "Zone Signed" : "Unsigned")
            : null;

          return {
            domain:              j.ldhName || tryDomain,
            registryDomainId:    j.handle  || null,
            status:              (j.status || []).join(", "),
            dnssec,
            created:             getEvent("registration"),
            updated:             getEvent("last changed"),
            expires:             getEvent("expiration"),
            lastChecked:         getEvent("last update of RDAP database"),
            nameservers:         (j.nameservers || []).map(n => n.ldhName).filter(Boolean).join(", "),
            registrar:           vcardGet(registrar, "fn"),
            registrarUrl:        regUrl,
            registrarIanaId:     ianaId,
            registrarWhois:      whoisSrv,
            registrarAbuse:      vcardGet(abuse, "email"),
            registrarAbusePhone: vcardGet(abuse, "tel"),
            registrant:          vcardGet(registrant, "fn"),
            registrantOrg:       vcardGet(registrant, "org"),
            registrantEmail:     vcardGet(registrant, "email"),
            adminName:           vcardGet(admin, "fn"),
            adminEmail:          vcardGet(admin, "email"),
            techName:            vcardGet(tech,  "fn"),
            techEmail:           vcardGet(tech,  "email"),
          };
        }

        // Strip subdomains: try full domain first, then each shorter suffix
        const rdapCandidates = [];
        const parts = domain.split(".");
        for (let i = 0; i < parts.length - 1; i++) {
          const candidate = parts.slice(i).join(".");
          if (candidate.split(".").length >= 2) rdapCandidates.push(candidate);
        }
        for (const tryDomain of rdapCandidates) {
          try {
            const r = await fetch(
              `https://rdap.org/domain/${encodeURIComponent(tryDomain)}`,
              { headers: { Accept: "application/rdap+json, application/json" } }
            );
            if (r.ok) {
              const j = await r.json();
              result.rdap = parseRdap(j, tryDomain);
              break;
            }
          } catch {}
        }

        sendResponse(result);
      })();
      return true;
    }

    // ── Crawler ──────────────────────────────────────────────────────────────
    case "CRAWL_START": {
      if (crawlAbortCtrl) crawlAbortCtrl.abort(); // stop any running crawl
      const { origin, seeds = [], maxPages = 60 } = msg;
      if (!origin) { sendResponse({ ok: false, error: "no origin" }); break; }
      startCrawl(tabId, origin, seeds, maxPages);
      sendResponse({ ok: true });
      break;
    }

    case "CRAWL_STOP": {
      if (crawlAbortCtrl) crawlAbortCtrl.abort();
      sendResponse({ ok: true });
      break;
    }

    // ── Probe: inject DOM XSS Hunter scripts ─────────────────────────────────
    case "PROBE_INJECT": {
      if (!tabId) { sendResponse({ ok: false, error: "no tabId" }); break; }
      (async () => {
        try {
          await probeBootstrap(tabId);

          // Apply saved toggle settings
          const { probeAutofill, probeCsti, probeSsti, probeProtoPollution } =
            await chrome.storage.local.get(["probeAutofill", "probeCsti", "probeSsti", "probeProtoPollution"]);
          const toggleCmds = [];
          if (probeAutofill)      toggleCmds.push("autofill.toggle");
          if (probeCsti)          toggleCmds.push("csti.toggle");
          if (probeSsti)          toggleCmds.push("ssti.toggle");
          if (probeProtoPollution) toggleCmds.push("protopollution.toggle");

          for (const cmd of toggleCmds) {
            await chrome.scripting.executeScript({
              target: { tabId }, world: "MAIN",
              func: (c) => { window.postMessage({ __domxss_cmd: true, command: c, args: true }, "*"); },
              args: [cmd],
            });
          }

          sendResponse({ ok: true });
        } catch (error) {
          sendResponse({ ok: false, error: error.message });
        }
      })();
      return true;
    }

    // ── Probe: dispatch command ──────────────────────────────────────────────
    case "PROBE_CMD": {
      if (!tabId) { sendResponse({ ok: false, error: "no tabId" }); break; }
      const { command: probeCommand, args: probeArgs } = msg;
      (async () => {
        try {
          if (!probeInjectedTabs.has(tabId)) await probeBootstrap(tabId);

          await chrome.scripting.executeScript({
            target: { tabId }, world: "MAIN",
            func: (cmd, cmdArgs) => {
              window.postMessage({ __domxss_cmd: true, command: cmd, args: cmdArgs }, "*");
            },
            args: [probeCommand, probeArgs ?? null],
          });
          sendResponse({ ok: true });
        } catch (error) {
          sendResponse({ ok: false, error: error.message });
        }
      })();
      return true;
    }

    // ── Probe: check injection status ────────────────────────────────────────
    case "PROBE_STATUS": {
      if (!tabId) { sendResponse({ injected: false }); break; }
      (async () => {
        try {
          // Read status + log from MAIN world in one call
          const results = await chrome.scripting.executeScript({
            target: { tabId },
            world: "MAIN",
            func: (fromId) => {
              // Get findings stats directly from window.domxss
              let status = { injected: false };
              if (window.domxss && window.domxss.findings) {
                const f = window.domxss.findings;
                status = {
                  injected: true,
                  sources: f.sources.length,
                  sinks: f.sinks.length,
                  flows: f.flows.length,
                  runtimeCalls: f.runtimeCalls.length,
                  likelyFlows: f.flows.filter(fl => fl.exploitability === "likely").length,
                  possibleFlows: f.flows.filter(fl => fl.exploitability === "possible").length,
                };
              }
              // Get console log entries (id-based to survive splice)
              const arr = window.__probeLog || [];
              let log;
              if (fromId <= 0) { log = arr; }
              else {
                let lo = 0;
                for (lo = 0; lo < arr.length; lo++) { if (arr[lo].id >= fromId) break; }
                log = arr.slice(lo);
              }
              status.log = log;
              return status;
            },
            args: [msg.logFrom || 0],
          });
          const status = results[0]?.result || { injected: false, log: [] };
          sendResponse(status);
        } catch (error) {
          sendResponse({ injected: false, error: error.message, log: [] });
        }
      })();
      return true; // async
    }

    // ── Probe: get full structured findings ──────────────────────────────────
    case "PROBE_FINDINGS": {
      if (!tabId) { sendResponse(null); break; }
      (async () => {
        try {
          const results = await chrome.scripting.executeScript({
            target: { tabId },
            world: "MAIN",
            func: () => {
              if (!window.domxss || !window.domxss.findings) return null;
              const f = window.domxss.findings;
              const fw = window.__DOMXSS?.state?.frameworks;
              return {
                sources: f.sources.map(s => ({
                  id: s.id, sev: s.severity, cat: s.category,
                  file: s.file, line: s.line, match: s.match,
                  manipulable: s.manipulable, why: s.why || "",
                  code: (s.code || "").slice(0, 300),
                  context: (s.context || "").slice(0, 300),
                  url: s.url || "",
                })),
                sinks: f.sinks.map(s => ({
                  id: s.id, sev: s.severity, cat: s.category,
                  file: s.file, line: s.line, match: s.match,
                  code: (s.code || "").slice(0, 300),
                })),
                flows: f.flows.map(fl => ({
                  id: fl.id, expl: fl.exploitability,
                  srcId: fl.source?.id, srcMatch: fl.source?.match || "",
                  srcManip: fl.source?.manipulable || "none", srcLine: fl.source?.line,
                  srcWhy: fl.source?.why || "",
                  snkId: fl.sink?.id, snkMatch: fl.sink?.match || "",
                  snkCat: fl.sink?.category || "", snkLine: fl.sink?.line,
                  file: fl.file, dist: fl.distance, score: fl.combinedScore,
                })),
                runtimeCalls: f.runtimeCalls.map(r => ({
                  id: r.id, sev: r.severity, hook: r.hook,
                  value: (r.value || r.args || "").slice(0, 200),
                })),
                frameworks: fw ? {
                  angular: { detected: !!fw.angular?.detected, version: fw.angular?.version || null },
                  jquery: { detected: !!fw.jquery?.detected, version: fw.jquery?.version || null },
                  vue: { detected: !!fw.vue?.detected, version: fw.vue?.version || null },
                  react: { detected: !!fw.react?.detected, version: fw.react?.version || null },
                  alpine: { detected: !!fw.alpine?.detected },
                  htmx: { detected: !!fw.htmx?.detected },
                } : null,
              };
            },
          });
          sendResponse(results[0]?.result || null);
        } catch {
          sendResponse(null);
        }
      })();
      return true;
    }
  }

  return false;
});
