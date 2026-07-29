#!/usr/bin/env node
/**
 * Void Extension — Intercepting Proxy
 *
 * A Chrome MV3 extension cannot open a listening socket (chrome.sockets.tcpServer
 * is Chrome-Apps only), so the proxy lives out here and the DevTools panel drives
 * it over a WebSocket control channel.
 *
 *   Run:  node void-proxy-server.js
 *   Proxy:   http://127.0.0.1:8081   ← point curl/Postman/phone at this
 *   Control: ws://127.0.0.1:8082     ← the Void panel connects here
 *
 * HTTPS is MITM'd with a CA generated on first run into ~/.void/. Clients must
 * trust it:  curl -x http://127.0.0.1:8081 --cacert ~/.void/void-ca.pem https://…
 */
"use strict";

const http = require("http");
const https = require("https");
const net = require("net");
const tls = require("tls");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");
const { WebSocketServer } = require("ws");

const PROXY_PORT = Number(process.env.VOID_PROXY_PORT) || 8081;
const CTRL_PORT = Number(process.env.VOID_CTRL_PORT) || 8082;
const MAX_BODY = 5 * 1024 * 1024; // 5 MB — bodies are buffered so they can be edited
const MAX_HISTORY = 5000;

const CA_DIR = path.join(os.homedir(), ".void");
const CA_KEY = path.join(CA_DIR, "void-ca.key");
const CA_CRT = path.join(CA_DIR, "void-ca.pem");
const LEAF_DIR = path.join(CA_DIR, "certs");

// ── Certificate authority ────────────────────────────────────────────────────

function sh(args) {
  return execFileSync("openssl", args, { stdio: ["ignore", "pipe", "pipe"] });
}

function ensureCA() {
  fs.mkdirSync(CA_DIR, { recursive: true, mode: 0o700 });
  fs.mkdirSync(LEAF_DIR, { recursive: true, mode: 0o700 });
  if (fs.existsSync(CA_KEY) && fs.existsSync(CA_CRT)) return;

  console.log("[Void Proxy] generating CA in " + CA_DIR);
  sh(["req", "-x509", "-newkey", "rsa:2048", "-nodes",
    "-keyout", CA_KEY, "-out", CA_CRT, "-days", "3650",
    "-subj", "/CN=Void Proxy CA/O=Void Extension",
    "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
    "-addext", "keyUsage=critical,keyCertSign,cRLSign"]);
  fs.chmodSync(CA_KEY, 0o600);
  console.log("[Void Proxy] CA ready — trust it with: --cacert " + CA_CRT);
}

const ctxCache = new Map(); // hostname → tls.SecureContext

function leafContext(hostname) {
  if (ctxCache.has(hostname)) return ctxCache.get(hostname);

  const safe = hostname.replace(/[^a-zA-Z0-9.-]/g, "_");
  const keyPath = path.join(LEAF_DIR, safe + ".key");
  const crtPath = path.join(LEAF_DIR, safe + ".crt");

  if (!fs.existsSync(keyPath) || !fs.existsSync(crtPath)) {
    const csrPath = path.join(LEAF_DIR, safe + ".csr");
    const extPath = path.join(LEAF_DIR, safe + ".ext");
    // An IP in SAN must be typed as IP, not DNS, or clients reject the cert.
    const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(hostname);
    fs.writeFileSync(extPath,
      "basicConstraints=CA:FALSE\n" +
      "keyUsage=critical,digitalSignature,keyEncipherment\n" +
      "extendedKeyUsage=serverAuth\n" +
      `subjectAltName=${isIp ? "IP" : "DNS"}:${hostname}\n`);
    sh(["req", "-newkey", "rsa:2048", "-nodes", "-keyout", keyPath,
      "-out", csrPath, "-subj", "/CN=" + hostname]);
    sh(["x509", "-req", "-in", csrPath, "-CA", CA_CRT, "-CAkey", CA_KEY,
      "-CAcreateserial", "-out", crtPath, "-days", "825",
      "-extfile", extPath]);
    fs.unlinkSync(csrPath);
    fs.unlinkSync(extPath);
  }

  const ctx = tls.createSecureContext({
    key: fs.readFileSync(keyPath),
    cert: fs.readFileSync(crtPath),
  });
  ctxCache.set(hostname, ctx);
  return ctx;
}

// ── Control channel ──────────────────────────────────────────────────────────

let intercepting = false;
const pending = new Map();  // id → { txn, resolve }
const history = [];
let nextId = 1;

const wss = new WebSocketServer({ port: CTRL_PORT });
const panels = new Set();

function broadcast(msg) {
  const raw = JSON.stringify(msg);
  for (const ws of panels) {
    if (ws.readyState === 1) { try { ws.send(raw); } catch {} }
  }
}

wss.on("connection", (ws) => {
  panels.add(ws);
  console.log(`[Void Proxy] panel connected (${panels.size})`);
  ws.send(JSON.stringify({
    type: "hello",
    proxyPort: PROXY_PORT,
    caPath: CA_CRT,
    intercepting,
    pending: [...pending.values()].map(p => p.txn),
  }));

  ws.on("message", (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    if (msg.type === "intercept") {
      intercepting = !!msg.on;
      console.log(`[Void Proxy] intercept ${intercepting ? "ON" : "OFF"}`);
      // Turning intercept off must release whatever is already held, or those
      // clients hang until their own timeout.
      if (!intercepting) {
        for (const [id, p] of [...pending]) { pending.delete(id); p.resolve(null); }
      }
      broadcast({ type: "state", intercepting });
      return;
    }

    if (msg.type === "forward" || msg.type === "drop") {
      const p = pending.get(msg.id);
      if (!p) return;
      pending.delete(msg.id);
      p.resolve(msg.type === "drop" ? { drop: true } : {
        method: msg.method, url: msg.url,
        headers: msg.headers, body: msg.body,
      });
      broadcast({ type: "resolved", id: msg.id });
      return;
    }

    if (msg.type === "forwardAll") {
      for (const [id, p] of [...pending]) { pending.delete(id); p.resolve(null); }
      broadcast({ type: "state", intercepting });
    }
  });

  ws.on("close", () => {
    panels.delete(ws);
    // With nobody left to click Forward, holding requests would just hang the
    // clients. Release them and stop intercepting.
    if (panels.size === 0 && pending.size) {
      for (const [id, p] of [...pending]) { pending.delete(id); p.resolve(null); }
      intercepting = false;
      console.log("[Void Proxy] no panels left — released held requests");
    }
  });
});

// ── Request handling ─────────────────────────────────────────────────────────

function parseRawHeaders(raw) {
  const out = {};
  for (const line of String(raw || "").split("\n")) {
    const i = line.indexOf(":");
    if (i > 0) out[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  }
  return out;
}

function headersToRaw(h) {
  return Object.entries(h || {}).map(([k, v]) => `${k}: ${v}`).join("\n");
}

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    let size = 0, truncated = false;
    req.on("data", (c) => {
      size += c.length;
      if (size <= MAX_BODY) chunks.push(c);
      else truncated = true;
    });
    req.on("end", () => resolve({ buf: Buffer.concat(chunks), truncated }));
    req.on("error", () => resolve({ buf: Buffer.concat(chunks), truncated }));
  });
}

async function handle(clientReq, clientRes, isTls) {
  const started = Date.now();
  const hostHeader = clientReq.headers.host || "";
  let target;
  try {
    target = isTls
      ? new URL(`https://${hostHeader}${clientReq.url}`)
      : new URL(clientReq.url.startsWith("http") ? clientReq.url : `http://${hostHeader}${clientReq.url}`);
  } catch {
    clientRes.writeHead(400).end("Void Proxy: bad request target");
    return;
  }

  const { buf: bodyBuf } = await readBody(clientReq);

  let method = clientReq.method;
  let url = target.href;
  let headers = { ...clientReq.headers };
  let body = bodyBuf;

  // ── Intercept: hold the request until the panel decides ──
  if (intercepting) {
    const id = "px" + (nextId++);
    const txn = {
      id, method, url,
      host: target.host,
      path: target.pathname + target.search,
      headers: headersToRaw(headers),
      body: bodyBuf.toString("utf8"),
      resourceType: "proxy",
      time: started,
    };
    const decision = await new Promise((resolve) => {
      pending.set(id, { txn, resolve });
      broadcast({ type: "paused", req: txn });
    });

    if (decision && decision.drop) {
      clientRes.writeHead(403).end("Void Proxy: dropped");
      broadcast({ type: "resolved", id });
      return;
    }
    if (decision) {
      method = decision.method || method;
      if (decision.url) { try { target = new URL(decision.url); url = target.href; } catch {} }
      if (decision.headers != null) headers = parseRawHeaders(decision.headers);
      if (decision.body != null) body = Buffer.from(decision.body, "utf8");
    }
  }

  // Rewrite hop-by-hop / stale framing before going upstream
  delete headers["proxy-connection"];
  delete headers["content-length"];
  headers.host = target.host;
  if (body.length) headers["content-length"] = String(body.length);
  // We buffer and re-emit the body, so ask for something we can hand back as-is
  headers["accept-encoding"] = "identity";

  const mod = target.protocol === "https:" ? https : http;
  const upstream = mod.request({
    protocol: target.protocol,
    hostname: target.hostname,
    port: target.port || (target.protocol === "https:" ? 443 : 80),
    method,
    path: target.pathname + target.search,
    headers,
    rejectUnauthorized: false, // we are the interception point; upstream trust is the operator's call
  }, (upRes) => {
    const chunks = [];
    let size = 0;
    upRes.on("data", (c) => { size += c.length; if (size <= MAX_BODY) chunks.push(c); });
    upRes.on("end", () => {
      const respBuf = Buffer.concat(chunks);
      try {
        clientRes.writeHead(upRes.statusCode, upRes.statusMessage, upRes.headers);
        clientRes.end(respBuf);
      } catch {}

      const respHeaders = {};
      for (const [k, v] of Object.entries(upRes.headers)) {
        respHeaders[k.toLowerCase()] = Array.isArray(v) ? v.join(", ") : String(v);
      }
      const entry = {
        method, url,
        host: target.host,
        path: target.pathname + target.search,
        status: upRes.statusCode,
        statusText: upRes.statusMessage || "",
        headers,
        respHeaders,
        body: body.toString("utf8"),
        respBody: respBuf.toString("utf8"),
        length: respBuf.length,
        mimeType: respHeaders["content-type"] || "",
        time: started,
        elapsed: Date.now() - started,
        resourceType: "proxy",
        capture: "proxy",
      };
      history.push(entry);
      if (history.length > MAX_HISTORY) history.splice(0, 500);
      broadcast({ type: "txn", entry });
    });
  });

  upstream.on("error", (err) => {
    try { clientRes.writeHead(502).end("Void Proxy upstream error: " + err.message); } catch {}
    broadcast({
      type: "txn",
      entry: {
        method, url, host: target.host, path: target.pathname + target.search,
        status: 0, statusText: "upstream error", headers, respHeaders: {},
        body: body.toString("utf8"), respBody: String(err.message),
        length: 0, mimeType: "", time: started, elapsed: Date.now() - started,
        resourceType: "proxy", capture: "proxy",
      },
    });
  });

  if (body.length) upstream.write(body);
  upstream.end();
}

// ── Servers ──────────────────────────────────────────────────────────────────

ensureCA();

// Everything CONNECT-tunnelled is re-terminated here so we can read the plaintext.
const mitm = https.createServer({
  SNICallback: (servername, cb) => {
    try { cb(null, leafContext(servername)); }
    catch (e) { cb(e); }
  },
}, (req, res) => handle(req, res, true));
mitm.on("clientError", (e, sock) => { try { sock.destroy(); } catch {} });
mitm.listen(0, "127.0.0.1");

const proxy = http.createServer((req, res) => handle(req, res, false));

proxy.on("connect", (req, clientSocket, head) => {
  const [host, port] = req.url.split(":");
  if (!host) { clientSocket.destroy(); return; }
  // Pre-generate before the handshake so a slow openssl call doesn't stall TLS
  try { leafContext(host); } catch (e) {
    console.error("[Void Proxy] cert generation failed for " + host + ": " + e.message);
    clientSocket.destroy();
    return;
  }
  clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
  const inner = net.connect(mitm.address().port, "127.0.0.1", () => {
    if (head && head.length) inner.write(head);
    clientSocket.pipe(inner).pipe(clientSocket);
  });
  inner.on("error", () => clientSocket.destroy());
  clientSocket.on("error", () => inner.destroy());
});

proxy.on("clientError", (e, sock) => { try { sock.destroy(); } catch {} });

proxy.listen(PROXY_PORT, () => {
  console.log(`[Void Proxy] proxy   http://127.0.0.1:${PROXY_PORT}`);
  console.log(`[Void Proxy] control ws://127.0.0.1:${CTRL_PORT}`);
  console.log(`[Void Proxy] CA      ${CA_CRT}`);
  console.log(`[Void Proxy] test    curl -x http://127.0.0.1:${PROXY_PORT} --cacert ${CA_CRT} https://example.com`);
});
