// Runs at document_start — patches network APIs BEFORE page scripts execute
// This is the fix for missing endpoints: fetch/XHR calls are captured from page load
(function () {
  "use strict";

  window.__bhp = { endpoints: [], seen: new Set() };

  function add(rawUrl, method, type) {
    try {
      const u = new URL(rawUrl, location.href);
      if (u.protocol !== "http:" && u.protocol !== "https:") return;
      if (window.__bhp.seen.has(u.href)) return;
      window.__bhp.seen.add(u.href);
      window.__bhp.endpoints.push({ url: u.href, method: String(method).toUpperCase(), type });
    } catch {}
  }

  // ── Patch fetch ────────────────────────────────────────────────────────────
  const _fetch = window.fetch;
  window.fetch = function (input, init) {
    try {
      const url = typeof input === "string" ? input
        : input instanceof URL ? input.href
        : (input && typeof input === "object" && "url" in input) ? input.url
        : "";
      add(url, (init && init.method) || "GET", "api");
    } catch {}
    return _fetch.apply(this, arguments);
  };

  // ── Patch XMLHttpRequest ───────────────────────────────────────────────────
  const _xhrOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (method, url) {
    try { add(String(url), String(method), "api"); } catch {}
    return _xhrOpen.apply(this, arguments);
  };

  // ── Patch WebSocket ────────────────────────────────────────────────────────
  const _WS = window.WebSocket;
  if (typeof _WS === "function") {
    function PatchedWS(url, protocols) {
      try {
        // Convert ws:// → https:// for URL normalization only (for storage)
        add(String(url).replace(/^wss:\/\//, "https://").replace(/^ws:\/\//, "http://"), "WS", "websocket");
      } catch {}
      if (arguments.length >= 2) return new _WS(url, protocols);
      return new _WS(url);
    }
    PatchedWS.prototype = _WS.prototype;
    PatchedWS.CONNECTING = _WS.CONNECTING;
    PatchedWS.OPEN = _WS.OPEN;
    PatchedWS.CLOSING = _WS.CLOSING;
    PatchedWS.CLOSED = _WS.CLOSED;
    window.WebSocket = PatchedWS;
  }
})();
