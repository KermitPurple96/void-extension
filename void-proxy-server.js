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

// ── Listen errors ────────────────────────────────────────────────────────────
// Without this a busy port surfaces as an unhandled 'error' event and a raw
// stack trace — which is what you get every time you start a second instance.

function onListenError(label, port) {
  return (err) => {
    if (err.code === "EADDRINUSE") {
      console.error(`[Void Proxy] ${label} port ${port} is already in use.`);
      console.error(`[Void Proxy] Another instance is probably running:  ss -ltnp | grep ${port}`);
      console.error(`[Void Proxy] Or choose other ports:  VOID_PROXY_PORT=9081 VOID_CTRL_PORT=9082 node void-proxy-server.js`);
    } else if (err.code === "EACCES") {
      console.error(`[Void Proxy] ${label} port ${port} requires elevated privileges (ports below 1024).`);
    } else {
      console.error(`[Void Proxy] ${label} could not listen on port ${port}: ${err.message}`);
    }
    process.exit(1);
  };
}

// ── Control channel ──────────────────────────────────────────────────────────

let intercepting = false;
const pending = new Map();  // id → { txn, resolve }
const history = [];
let nextId = 1;

const wss = new WebSocketServer({ port: CTRL_PORT });
wss.on("error", onListenError("control", CTRL_PORT));
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
      return;
    }

    // Tool execution results from panel
    if (msg.type === "tool_result") {
      const p = pendingToolCalls.get(msg.callId);
      if (p) { pendingToolCalls.delete(msg.callId); p.resolve(msg.result); }
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

let hasOpenSSL = true;
try { ensureCA(); } catch (e) {
  hasOpenSSL = false;
  console.log("[Void Proxy] openssl not found — HTTPS MITM disabled (HTTP proxy + AI chat still work)");
  console.log("[Void Proxy] Install OpenSSL or add it to PATH to enable HTTPS interception");
}

// Everything CONNECT-tunnelled is re-terminated here so we can read the plaintext.
let mitm = null;
if (hasOpenSSL) {
  mitm = https.createServer({
    SNICallback: (servername, cb) => {
      try { cb(null, leafContext(servername)); }
      catch (e) { cb(e); }
    },
  }, (req, res) => handle(req, res, true));
  mitm.on("clientError", (e, sock) => { try { sock.destroy(); } catch {} });
  mitm.on("error", onListenError("internal TLS", "(ephemeral)"));
  mitm.listen(0, "127.0.0.1");
}

// ── LLM Chat Proxy ──────────────────────────────────────────────────────────
// POST /api/chat — proxies to whichever LLM API the user configured.
// The panel sends tool results back over WebSocket; this endpoint handles
// the agentic loop (LLM → tool_call → panel → result → LLM → repeat).

const { execFile } = require("child_process");

const AI_ENDPOINTS = {
  anthropic: "https://api.anthropic.com/v1/messages",
  openai: "https://api.openai.com/v1/chat/completions",
  openrouter: "https://openrouter.ai/api/v1/chat/completions",
  ollama: "http://localhost:11434/v1/chat/completions",
};

// Active tool calls waiting for panel results
const pendingToolCalls = new Map(); // callId → { resolve }
let toolCallNextId = 1;

// Request a tool execution from the panel, wait for result
function requestToolExec(toolName, toolArgs) {
  return new Promise((resolve) => {
    const callId = "tc_" + (toolCallNextId++);
    pendingToolCalls.set(callId, { resolve });
    broadcast({ type: "tool_exec", callId, tool: toolName, args: toolArgs });
    // Timeout after 30s
    setTimeout(() => {
      if (pendingToolCalls.has(callId)) {
        pendingToolCalls.delete(callId);
        resolve({ error: "Tool execution timed out" });
      }
    }, 30000);
  });
}

async function llmFetch(url, headers, body) {
  const mod = url.startsWith("https") ? https : http;
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const req = mod.request({
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: "POST",
      headers: { ...headers, "content-type": "application/json" },
      rejectUnauthorized: true,
    }, (res) => {
      const chunks = [];
      res.on("data", c => chunks.push(c));
      res.on("end", () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString()) }); }
        catch { resolve({ status: res.statusCode, body: { error: Buffer.concat(chunks).toString().slice(0, 500) } }); }
      });
    });
    req.on("error", e => reject(e));
    req.write(JSON.stringify(body));
    req.end();
  });
}

// Claude CLI — uses the user's existing Claude Code auth, no API key needed
function claudeCliExec(cliPath, prompt, model) {
  return new Promise((resolve, reject) => {
    const args = ["--print", "--output-format", "text"];
    if (model) args.push("--model", model);
    args.push(prompt);
    const proc = execFile(cliPath || "claude", args, {
      timeout: 120000,
      maxBuffer: 10 * 1024 * 1024,
      env: { ...process.env, CLAUDE_CODE_ENTRYPOINT: "void-extension" },
    }, (err, stdout, stderr) => {
      if (err) reject(new Error(err.message + (stderr ? ": " + stderr.slice(0, 200) : "")));
      else resolve(stdout);
    });
  });
}

async function handleAiChat(req, res) {
  const { buf } = await readBody(req);
  let msg;
  try { msg = JSON.parse(buf.toString()); } catch { res.writeHead(400).end('{"error":"Invalid JSON"}'); return; }

  const { provider, apiKey, model, endpoint, messages, tools, systemPrompt, cliPath } = msg;

  // Claude CLI mode — spawn the CLI process
  if (provider === "claude-cli") {
    // Build conversation into a single prompt
    const toolList = (tools || []).map(t => `- ${t.name}(${Object.keys(t.parameters?.properties || {}).join(", ")}): ${t.description}`).join("\n");
    const toolInstr = tools?.length ? `

IMPORTANT: You have access to security testing tools. When you need data or want to perform an action, you MUST respond with EXACTLY this format (no markdown, no code blocks around it):

<tool_call>{"name": "tool_name", "args": {"param": "value"}}</tool_call>

You may include text before the tool call to explain what you're doing. Only ONE tool call per response. After receiving the tool result, you can make another tool call or provide your final analysis.

Available tools:
${toolList}

Example:
Let me check the HTTP history for interesting requests.
<tool_call>{"name": "get_history", "args": {"filter": "POST", "limit": 20}}</tool_call>` : "";

    const sysBlock = (systemPrompt || "") + toolInstr;

    let conversationText = sysBlock ? `System: ${sysBlock}\n\n` : "";
    for (const m of (messages || [])) {
      if (typeof m.content === "string") conversationText += `${m.role === "user" ? "User" : "Assistant"}: ${m.content}\n\n`;
    }

    const MAX_CLI_TURNS = 30;
    for (let turn = 0; turn < MAX_CLI_TURNS; turn++) {
      broadcast({ type: "ai_status", text: turn === 0 ? "Sending to Claude CLI\u2026" : `Claude is thinking (turn ${turn + 1})\u2026` });

      let response;
      try {
        response = await claudeCliExec(cliPath, conversationText.trim(), model);
      } catch (e) {
        res.writeHead(502).end(JSON.stringify({ error: `Claude CLI error: ${e.message}` }));
        return;
      }

      // Check for tool calls in the response
      const toolCallMatch = response.match(/<tool_call>\s*(\{[\s\S]*?\})\s*<\/tool_call>/);
      if (toolCallMatch) {
        let parsed;
        try { parsed = JSON.parse(toolCallMatch[1]); } catch { break; }
        const textBefore = response.slice(0, response.indexOf("<tool_call>")).trim();
        if (textBefore) broadcast({ type: "ai_chunk", role: "assistant", text: textBefore, toolCalls: [] });

        broadcast({ type: "ai_tool_start", name: parsed.name, args: parsed.args || {} });
        const result = await requestToolExec(parsed.name, parsed.args || {});
        broadcast({ type: "ai_tool_done", name: parsed.name, result });

        const resultStr = typeof result === "string" ? result : JSON.stringify(result);
        conversationText += `Assistant: ${response}\n\nUser: Tool result for ${parsed.name}:\n${resultStr.slice(0, 5000)}\n\nPlease continue your analysis based on this result.\n\n`;
        continue;
      }

      // No tool call — final response
      broadcast({ type: "ai_chunk", role: "assistant", text: response, toolCalls: [] });
      res.writeHead(200).end(JSON.stringify({ role: "assistant", content: response, done: true }));
      return;
    }

    res.writeHead(200).end(JSON.stringify({ role: "assistant", content: "Max tool turns reached.", done: true }));
    return;
  }

  const isAnthropic = provider === "anthropic";
  const baseUrl = endpoint || AI_ENDPOINTS[provider] || AI_ENDPOINTS.openai;

  // Build API request
  let apiHeaders, apiBody;

  if (isAnthropic) {
    apiHeaders = {
      "x-api-key": apiKey || "",
      "anthropic-version": "2023-06-01",
    };
    apiBody = {
      model: model || "claude-sonnet-4-20250514",
      max_tokens: 8192,
      system: systemPrompt || "",
      messages: messages || [],
      tools: (tools || []).map(t => ({
        name: t.name,
        description: t.description,
        input_schema: t.parameters,
      })),
    };
  } else {
    apiHeaders = {
      "authorization": `Bearer ${apiKey || "void"}`,
    };
    if (provider === "openrouter") {
      apiHeaders["http-referer"] = "https://void-extension.local";
      apiHeaders["x-title"] = "Void Extension AI";
    }
    const sysMsg = systemPrompt ? [{ role: "system", content: systemPrompt }] : [];
    apiBody = {
      model: model || "gpt-4o",
      messages: [...sysMsg, ...(messages || [])],
      tools: (tools || []).map(t => ({
        type: "function",
        function: { name: t.name, description: t.description, parameters: t.parameters },
      })),
    };
    if (!apiBody.tools.length) delete apiBody.tools;
  }

  // Agentic loop — keep calling LLM until it returns text (no more tool calls)
  const conversationMessages = isAnthropic ? [...(messages || [])] : [...(messages || [])];
  const MAX_TURNS = 30;

  for (let turn = 0; turn < MAX_TURNS; turn++) {
    broadcast({ type: "ai_status", text: turn === 0 ? `Sending to ${provider}\u2026` : `AI is thinking (turn ${turn + 1})\u2026` });
    let llmRes;
    try {
      if (isAnthropic) apiBody.messages = conversationMessages;
      else apiBody.messages = [...(systemPrompt ? [{ role: "system", content: systemPrompt }] : []), ...conversationMessages];

      llmRes = await llmFetch(baseUrl, apiHeaders, apiBody);
    } catch (e) {
      res.writeHead(502).end(JSON.stringify({ error: `LLM API error: ${e.message}` }));
      return;
    }

    if (llmRes.status >= 400) {
      res.writeHead(llmRes.status).end(JSON.stringify({ error: llmRes.body?.error?.message || JSON.stringify(llmRes.body).slice(0, 300) }));
      return;
    }

    if (isAnthropic) {
      const content = llmRes.body.content || [];
      const toolUses = content.filter(c => c.type === "tool_use");

      // Broadcast assistant message to panel for display
      const textParts = content.filter(c => c.type === "text").map(c => c.text).join("\n");
      broadcast({ type: "ai_chunk", role: "assistant", text: textParts, toolCalls: toolUses.map(t => ({ name: t.name, args: t.input })) });

      if (llmRes.body.stop_reason !== "tool_use" || !toolUses.length) {
        // Final response — no more tool calls
        res.writeHead(200).end(JSON.stringify({
          role: "assistant",
          content: textParts,
          done: true,
        }));
        return;
      }

      // Execute tools and feed results back
      conversationMessages.push({ role: "assistant", content });
      const toolResults = [];
      for (const tu of toolUses) {
        broadcast({ type: "ai_tool_start", name: tu.name, args: tu.input });
        const result = await requestToolExec(tu.name, tu.input || {});
        broadcast({ type: "ai_tool_done", name: tu.name, result });
        toolResults.push({
          type: "tool_result",
          tool_use_id: tu.id,
          content: typeof result === "string" ? result : JSON.stringify(result),
        });
      }
      conversationMessages.push({ role: "user", content: toolResults });

    } else {
      // OpenAI-compatible
      const choice = llmRes.body.choices?.[0];
      if (!choice) {
        res.writeHead(502).end(JSON.stringify({ error: "No choices in LLM response" }));
        return;
      }

      const msg = choice.message;
      const toolCalls = msg.tool_calls || [];

      broadcast({ type: "ai_chunk", role: "assistant", text: msg.content || "", toolCalls: toolCalls.map(t => ({ name: t.function?.name, args: t.function?.arguments })) });

      if (choice.finish_reason !== "tool_calls" || !toolCalls.length) {
        res.writeHead(200).end(JSON.stringify({
          role: "assistant",
          content: msg.content || "",
          done: true,
        }));
        return;
      }

      // Execute tools
      conversationMessages.push({ role: "assistant", content: msg.content || null, tool_calls: toolCalls });
      for (const tc of toolCalls) {
        const fnName = tc.function?.name;
        let fnArgs = {};
        try { fnArgs = JSON.parse(tc.function?.arguments || "{}"); } catch {}
        broadcast({ type: "ai_tool_start", name: fnName, args: fnArgs });
        const result = await requestToolExec(fnName, fnArgs);
        broadcast({ type: "ai_tool_done", name: fnName, result });
        conversationMessages.push({
          role: "tool",
          tool_call_id: tc.id,
          content: typeof result === "string" ? result : JSON.stringify(result),
        });
      }
    }
  }

  res.writeHead(200).end(JSON.stringify({ role: "assistant", content: "Max tool turns reached.", done: true }));
}

const proxy = http.createServer((req, res) => {
  // CORS for panel requests
  if (req.method === "OPTIONS") {
    res.writeHead(204, { "access-control-allow-origin": "*", "access-control-allow-methods": "POST, OPTIONS", "access-control-allow-headers": "content-type" });
    res.end();
    return;
  }
  if (req.url === "/api/chat" && req.method === "POST") {
    res.setHeader("access-control-allow-origin", "*");
    handleAiChat(req, res);
    return;
  }
  handle(req, res, false);
});

proxy.on("connect", (req, clientSocket, head) => {
  if (!mitm) {
    clientSocket.write("HTTP/1.1 502 HTTPS MITM unavailable (no openssl)\r\n\r\n");
    clientSocket.destroy();
    return;
  }
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
proxy.on("error", onListenError("proxy", PROXY_PORT));

proxy.listen(PROXY_PORT, () => {
  console.log(`[Void Proxy] proxy   http://127.0.0.1:${PROXY_PORT}`);
  console.log(`[Void Proxy] control ws://127.0.0.1:${CTRL_PORT}`);
  console.log(`[Void Proxy] CA      ${CA_CRT}`);
  console.log(`[Void Proxy] test    curl -x http://127.0.0.1:${PROXY_PORT} --cacert ${CA_CRT} https://example.com`);
});
