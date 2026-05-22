"use strict";

// ── Keep service worker alive (MV3 can kill it after ~30s idle) ───────────────
// We use an alarm that fires every 25s to prevent the SW from being suspended.
chrome.alarms.create("keepAlive", { periodInMinutes: 0.4 });
chrome.alarms.onAlarm.addListener(() => {}); // noop — just wakes the SW

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
      headers:      {},   // security response headers
    });
  }
  return tabs.get(id);
}

// ── Debugger events ───────────────────────────────────────────────────────────

chrome.debugger.onEvent.addListener((src, method, params) => {
  const t = tabs.get(src.tabId);
  if (!t) return;

  if (method === "Fetch.requestPaused") {
    if (!t.intercepting) {
      // auto-forward when intercept is off
      chrome.debugger.sendCommand(
        { tabId: src.tabId }, "Fetch.continueRequest",
        { requestId: params.requestId }, () => {}
      );
      return;
    }
    t.pending[params.requestId] = {
      requestId:    params.requestId,
      url:          params.request.url,
      method:       params.request.method,
      headers:      params.request.headers || {},
      body:         params.request.postData || "",
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
    Object.keys(raw).forEach(k => {
      const lk = k.toLowerCase();
      if (SAFE_HDRS.has(lk)) t.headers[lk] = raw[k];
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

chrome.debugger.onDetach.addListener(src => {
  const t = tabs.get(src.tabId);
  if (!t) return;
  t.attached     = false;
  t.intercepting = false;
  t.pending      = {};
});

chrome.tabs.onUpdated.addListener((tabId, info) => {
  if (info.status === "loading") {
    const t = tabs.get(tabId);
    if (t) { t.endpoints = []; t.technologies = []; t.headers = {}; t.pending = {}; }
  }
});

chrome.tabs.onRemoved.addListener(id => tabs.delete(id));

// ── Message handler ───────────────────────────────────────────────────────────

const ALLOWED = new Set([
  "PING",
  "ATTACH","DETACH","INTERCEPT_ON","INTERCEPT_OFF",
  "FORWARD","DROP","SEND_REQUEST",
  "GET_DATA","GET_INTERCEPTED","REPORT","CLEAR",
  "LOOKUP","CRAWL_START","CRAWL_STOP",
]);

// ── Crawler ────────────────────────────────────────────────────────────────
let crawlAbortCtrl = null;

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
      if (!tabId) break;
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
      });
      break;
    }

    case "GET_INTERCEPTED": {
      if (!tabId) { sendResponse({ requests: [] }); break; }
      const t = getTab(tabId);
      sendResponse({ requests: Object.values(t.pending) });
      break;
    }

    case "CLEAR": {
      if (!tabId) break;
      const t = getTab(tabId);
      t.endpoints = []; t.technologies = []; t.headers = {};
      sendResponse({ ok: true });
      break;
    }

    // ── Debugger: attach ────────────────────────────────────────────────────
    case "ATTACH": {
      if (!tabId) { sendResponse({ ok: false, error: "no tabId" }); break; }
      const t = getTab(tabId);
      if (t.attached) { sendResponse({ ok: true }); break; }
      chrome.debugger.attach({ tabId }, "1.3", () => {
        if (chrome.runtime.lastError) {
          sendResponse({ ok: false, error: chrome.runtime.lastError.message });
          return;
        }
        t.attached = true;
        chrome.debugger.sendCommand({ tabId }, "Network.enable", {}, () => {});
        sendResponse({ ok: true });
      });
      return true; // async
    }

    // ── Debugger: detach ────────────────────────────────────────────────────
    case "DETACH": {
      if (!tabId) { sendResponse({ ok: false }); break; }
      const t = getTab(tabId);
      if (!t.attached) { sendResponse({ ok: true }); break; }
      // Forward all pending before detaching
      Object.keys(t.pending).forEach(id => {
        chrome.debugger.sendCommand({ tabId }, "Fetch.continueRequest", { requestId: id }, () => {});
      });
      t.pending = {}; t.intercepting = false;
      chrome.debugger.detach({ tabId }, () => {
        t.attached = false;
        sendResponse({ ok: true });
      });
      return true;
    }

    // ── Intercept ON ─────────────────────────────────────────────────────────
    case "INTERCEPT_ON": {
      if (!tabId) { sendResponse({ ok: false }); break; }
      const t = getTab(tabId);
      if (!t.attached) { sendResponse({ ok: false, error: "not attached" }); break; }
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
      return true;
    }

    // ── Intercept OFF ────────────────────────────────────────────────────────
    case "INTERCEPT_OFF": {
      if (!tabId) { sendResponse({ ok: false }); break; }
      const t = getTab(tabId);
      if (!t.attached) { sendResponse({ ok: true }); break; }
      Object.keys(t.pending).forEach(id => {
        chrome.debugger.sendCommand({ tabId }, "Fetch.continueRequest", { requestId: id }, () => {});
      });
      t.pending = {};
      chrome.debugger.sendCommand({ tabId }, "Fetch.disable", {}, () => {
        t.intercepting = false;
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
          delete t.pending[requestId];
          sendResponse({ ok: true });
        });
      return true;
    }

    // ── Repeater: send HTTP request ──────────────────────────────────────────
    case "SEND_REQUEST": {
      const { url, method, rawHeaders, body } = msg;

      // Validate URL
      let safeUrl;
      try {
        const u = new URL(url);
        if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error("bad protocol");
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
            // Block forbidden headers that would expose the extension
            if (k && !/^(host|content-length)$/i.test(k)) headers[k] = v;
          }
        });
      }

      const fetchOpts = { method: method || "GET", headers };
      if (body && !["GET","HEAD"].includes((method || "GET").toUpperCase())) {
        fetchOpts.body = body;
      }

      (async () => {
        try {
          const start = Date.now();
          const resp  = await fetch(safeUrl, { ...fetchOpts, redirect: "follow" });
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
  }

  return false;
});
