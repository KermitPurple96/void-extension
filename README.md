# Void Extension

A Chrome DevTools extension for bug bounty hunters and security researchers — an in-browser testing toolkit in the shape of a DevTools panel. Works standalone; two optional Node helpers add an intercepting proxy, AI chat integration, and cross-container sync.

![Chrome MV3](https://img.shields.io/badge/Chrome-MV3-4285F4?logo=googlechrome&logoColor=white)
![Version](https://img.shields.io/badge/version-1.0.0-green)
![License](https://img.shields.io/badge/license-MIT-blue)

---

## Contents

- [Features](#features)
- [Traffic capture](#traffic-capture)
- [Installation](#installation)
- [The intercepting proxy](#the-intercepting-proxy)
- [AI Chat](#ai-chat)
- [Cross-container sync](#cross-container-sync)
- [Usage guide](#usage-guide)
- [Permissions](#permissions)
- [Project structure](#project-structure)
- [Legal & ethics](#legal--ethics)

---

## Features

| Tab | What it does |
|-----|-------------|
| **Project** | Session save/restore, site map tree, endpoint list, scope rules, WHOIS/DNS recon |
| **Intercept** | Pause requests **and responses**, edit headers/body/status, forward or drop — from Chrome *and* external proxy |
| **History** | Every request with field search, column filters, reflection detection, canary tracking, **remote IP column**, **response timeline** |
| **WebSocket** | Live WebSocket frame capture — direction, type, length, connection status pills, JSON detail |
| **Repeater** | Dual side-by-side with independent tabs, **tab groups** (collapsible, color-coded), **Diff**, split/raw mode, **cookie sync** (smart merge), **response timeline** |
| **Intruder** | 4 fuzzing modes + **10 specialized attacks**: Auth/IDOR, Race Condition, Param Miner, JWT Attacker, CORS Scanner, Request Smuggling, GraphQL Explorer, Upload Scanner, **Flow Builder**, **Sequencer** |
| **Scan** | DOM XSS hunter (Probe) + **Active Scanner** (8 modules) + **Content Discovery** + **Interactsh OOB** |
| **Logger** | Cross-container traffic aggregator |
| **Containers** | Launch isolated Chrome profiles with their own cookie jars |
| **Headers** | Security-header analysis with rescan, custom URL scan, per-domain auto-scan |
| **Dencoder** | Chain-based encoding/decoding with **saved presets** — 20 operations in any order |
| **API Schema** | Auto-generate **OpenAPI 3.0 YAML** from captured traffic |
| **PoC** | CSRF PoC (6 techniques + 4 evasions) + Clickjacking PoC (4 techniques) |
| **Sequencer** | Token entropy analysis — Shannon entropy, 5 statistical tests, character frequency histogram |
| **Notes** | Severity-tagged findings, CRUD, markdown export by host |
| **M&R** | Match & Replace rules, **canary tokens**, **regex tester**, **payload generator**, **response baseline** |
| **Sensitive** | 180+ passive rules — secrets, PII, tech disclosure, cookie flags, CSP, SRI, CRLF |
| **Storage** | **localStorage/sessionStorage/cookies** inspector + **postMessage monitor** — read, delete, export, live capture |
| **Scripts** | **User automation engine** — JavaScript editor with 20-function `void.*` API, save/load library, console output |
| **AI Chat** | **LLM integration** with **48 tools** — multi-session, Claude CLI / Anthropic / OpenAI / OpenRouter / Ollama, full extension control |
| **Settings** | Network (Connections, DNS, TLS, HTTP), Tool configs (Proxy, Intruder, Repeater, Sequencer), **4 themes**, TLS fingerprint, settings profiles, AI config |

### Recon engine

- **WHOIS** via RDAP — registrar, registrant, contacts, DNSSEC, abuse info
- **DNS** — A, AAAA, MX (with priority), NS, TXT (SPF / DMARC / DKIM), CNAME, SOA, CAA, PTR
- **IP geolocation** — ASN, ISP, org, country, region, city, timezone, coordinates
- **Technology fingerprinting** — 40+ categories, from response headers and page content

---

## Traffic capture

Void records from three independent sources, merged into one History:

| Source | Covers | Request body | Response body | Needs |
|---|---|---|---|---|
| **Passive** (`webRequest`) | every tab in this Chrome | yes | **no** — the API cannot read them | nothing |
| **Debugger** (CDP) | the tab you attached to | yes | yes | click **Attach** |
| **Proxy** (Node helper) | anything outside Chrome — curl, Postman, a phone | yes | yes | run the proxy server |

Passive capture is always on, which is why History fills up without attaching anything. Response bodies only exist on debugger- and proxy-captured rows.

---

## Installation

> No build step. No bundler. Load the folder straight into Chrome.

### 1. Get the extension

```bash
git clone https://github.com/KermitPurple96/void-extension.git
```

Or use **Code > Download ZIP** and extract it anywhere.

### 2. Load it into Chrome

1. Go to `chrome://extensions`
2. Toggle **Developer mode** ON (top-right)
3. Click **Load unpacked**
4. Select the folder containing `manifest.json`

### 3. Open the panel

1. Open any site you are authorised to test
2. Press `F12` (or `Ctrl+Shift+I` / `Cmd+Option+I`)
3. Click the **>>** arrow in the DevTools tab bar
4. Choose **Void**

### 4. Optional — the Node helpers

Both need the `ws` module, pinned in `package.json`:

```bash
npm install                  # installs ws
npm run proxy                # intercepting proxy   :8081  + control ws :8082
npm run sync                 # cross-container sync ws :17580
```

Or run them directly with `node void-proxy-server.js` / `node void-sync-server.js`.
The extension itself needs no install step — npm is only for these two helpers.

---

## The intercepting proxy

A Chrome MV3 extension **cannot open a listening socket** — `chrome.sockets.tcpServer` is Chrome-Apps only. So intercepting clients outside the browser needs a helper process, driven by the panel over a WebSocket control channel.

```bash
node void-proxy-server.js
```

```
proxy    http://127.0.0.1:8081     <- point curl / Postman / your phone here
control  ws://127.0.0.1:8082       <- the Void panel connects here
CA       ~/.void/void-ca.pem       <- generated on first run (requires openssl)
```

HTTPS is MITM'd with a CA generated by `openssl` on first run. If `openssl` is not in PATH, HTTPS interception is disabled but HTTP proxy and AI chat still work.

### The three states

In the **Intercept** tab, the `Proxy` button cycles:

| Button | Control channel | Traffic | Recorded in History | Held for editing |
|---|---|---|---|---|
| `Proxy: connect` | disconnected | passes | no | no |
| `Proxy: logging` | connected | passes | **yes** | no |
| `Proxy: intercepting` | connected | passes | yes | **yes** |

---

## AI Chat

The **AI Chat** tab connects to any LLM (local or cloud) and gives it **48 tools** with full read/write access to every tab in the extension.

### Supported providers

| Provider | Auth | How it works |
|----------|------|-------------|
| **Claude CLI** (default) | None — uses your Claude Code login | Spawns `claude --print` subprocess via the proxy |
| **Anthropic API** | API key | Direct API with native tool_use |
| **OpenAI API** | API key | Direct API with function calling |
| **OpenRouter** | API key | Unified API (OpenAI-compatible) |
| **Ollama** | None | Local models at `localhost:11434` |
| **Custom** | Optional | Any OpenAI-compatible endpoint |

### Setup

1. Start the proxy: `node void-proxy-server.js`
2. Open **Settings** > **AI Chat** section > choose provider + enter credentials
3. Open the **AI Chat** tab and start chatting

### What the AI can do (48 tools)

**Read everything:** HTTP history, endpoints, technologies, cookies, storage, WebSocket frames, scan findings, Intruder results, Repeater tabs, site map, security headers, sequencer tokens, Notes, scope, M&R rules, postMessage events

**Execute actions:** send requests, run active scanner, run sensitive scan, run Intruder attacks, run Flow Builder chains, send to Repeater/Intruder, toggle interception, forward/drop requests, add M&R rules, set scope, set canary tokens, set DNS overrides, generate CSRF PoCs

**Browser access:** evaluate JavaScript in the inspected page, extract forms/links/scripts from DOM, read page info (URL, title, cookies, referrer)

**Encoding:** encode/decode (base64, URL, HTML, hex, unicode, JS), hash (MD5, SHA-1, SHA-256), compare/diff responses

### Multi-session

The left sidebar maintains multiple chat sessions. Sessions auto-name from the first message, persist to `chrome.storage`, and survive browser restarts. Arrow Up/Down scrolls through input history.

---

## Cross-container sync

```bash
node void-sync-server.js     # ws://localhost:17580
```

Containers launch separate Chrome profiles with their own `--user-data-dir`, so cookies are genuinely isolated. Each instance pushes its history to the sync server and the **Logger** tab shows the merged view.

---

## Usage guide

### Intercept

1. **Chrome traffic** — click **Attach Debugger**, toggle **Intercept: OFF** > ON
2. **Response interception** — click **Responses: OFF** > ON to also pause responses
3. **External traffic** — start the proxy, click **Proxy: connect** > **logging** > **intercepting**
4. Click a paused request/response to open the editor
5. **Forward** sends, **Drop** kills

### Repeater

- **Dual side-by-side** — click **Compare** to open a second Repeater
- **Tab groups** — click **+** > **New Group**, then use the gear icon to add tabs, pick a color, rename, or collapse
- **Diff** button highlights differences between left and right responses
- **Cookie sync** — smart merge that updates browser cookies while preserving manually-added test cookies; yellow indicator when cookies drift
- **Response Timeline** — click the clock icon in detail view to see how an endpoint's response changed over time

### Intruder

**Fuzzing modes:** Sniper, Battering Ram, Pitchfork, Cluster Bomb — with `payload` markers

**10 specialized attacks:**

| Mode | What it does |
|------|-------------|
| **Auth / IDOR** | Replays with User A, User B, and unauthenticated cookies |
| **Race Condition** | 20+ parallel requests; flags anomalies |
| **Param Miner** | Bruteforces hidden params (200 built-in) |
| **JWT Attacker** | `alg:none`, HS256 brute-force, claim tampering |
| **CORS Scanner** | 7 Origin variations; reports reflection + credentials |
| **Request Smuggling** | CL.TE, TE.CL, TE.TE detection |
| **GraphQL Explorer** | Introspection + schema discovery |
| **Upload Scanner** | 7 polyglot payloads (SVG XSS, PHP shell, XXE) |
| **Flow Builder** | Chained requests with variable extraction between steps |
| **Sequencer** | Token entropy analysis with 5+ statistical tests |

**Payload validation:** Warnings appear when markers don't match the attack mode (e.g., JWT attack without a JWT in the request).

### Scripts

Write JavaScript automation with the `void.*` API:

```javascript
// Fuzz a parameter and report findings
const results = await void.attack({
  url: 'https://target.com/search?q=FUZZ',
  payloads: ["<script>alert(1)</script>", "' OR 1=1--"],
  marker: 'FUZZ', injectIn: 'url', threads: 3
});
for (const r of results) {
  if (r.body.includes(r.payload))
    void.addFinding({ title: 'Reflected: ' + r.payload, severity: 'high' });
}
```

**API:** `request`, `history`, `cookies`, `sendToRepeater`, `sendToIntruder`, `attack`, `scan`, `encode`, `decode`, `hash`, `log`, `addFinding`, `sleep`, `storage`, `setVar`, `getVar`, `isInScope`, `esc`, `parseUrl`

### Storage

- **localStorage / sessionStorage / Cookies** — read, delete, export as JSON
- **postMessage monitor** — captures cross-origin messages with origin, data, timestamp

### Settings

**Network:** Connections (timeouts, upstream proxy, platform auth), DNS (resolution mode, hostname overrides), TLS (verify, min/max version, client certs, CA path), HTTP (redirect types, streaming, keep-alive, HTTP/2)

**Tools:** Proxy (interception rules, WebSocket interception), Intruder (payload placement, processing, threading), Repeater (message modification, redirects, streaming, tab defaults), Sequencer (capture settings, token handling, 9 statistical tests)

**General:** Match & Replace, 4 themes, TLS fingerprint (JA3/JA4), settings profiles, HAR export, AI provider config

---

## Permissions

| Permission | Why it's needed |
|-----------|----------------|
| `debugger` | Attach to tabs to intercept/modify requests, read response bodies |
| `webRequest` | Passive traffic capture across all tabs |
| `tabs` | Open links and read the active tab's URL |
| `activeTab` | Access the currently inspected page |
| `storage` | Persist settings, sessions, AI chat history |
| `unlimitedStorage` | Saved sessions can hold large histories |
| `scripting` | Inject content script and Probe scanner |
| `cookies` | Cookie sync for Repeater and Intruder |
| `downloads` | Export findings, sessions and container sync |
| `alarms` | Keep the service worker alive |
| `host_permissions: <all_urls>` | Required to attach debugger and capture traffic on any domain |

---

## Project structure

```
void-extension/
|-- manifest.json          # Extension manifest (MV3)
|-- package.json           # Pins ws for the Node helpers
|-- devtools.html/.js      # DevTools page entry point
|-- panel.html             # Panel UI markup (21 tabs)
|-- panel.js               # Panel logic — all tabs, AI chat, tool executors
|-- panel.css              # All styles
|-- background.js          # Service worker — debugger bridge, passive capture,
|                          #   DNS/WHOIS/IP APIs, crawler, proxy history
|-- content.js             # Content script — endpoint & tech fingerprinting
|-- early.js               # document_start content script
|-- sensitive-rules.js     # 180+ passive scanner rules
|-- void-proxy-server.js   # Node helper — MITM proxy + LLM chat proxy + DNS overrides
|-- void-sync-server.js    # Node helper — cross-container sync
|-- probe/                 # DOM XSS hunter, injected into the page
|-- tests/
|   +-- e2e-audit.js       # 187 automated integrity tests
+-- icons/
```

Neither Node helper is required to use the extension. The proxy is needed for external client interception and AI chat.

---

## Legal & ethics

This tool is intended **only** for targets you own or have **explicit written permission** to test.

Two things worth stating plainly:

- Attaching the Chrome Debugger is **visible** to whoever is using that tab.
- The proxy's CA is a **real MITM certificate authority**. Trusting it means any process that trusts it can have its TLS intercepted. Install it only where you intend to, and delete `~/.void/` when you are done.

Always operate within the scope of an authorised engagement or bug bounty program.

---

## Author

**Ahmad Alanazi**

[![X](https://img.shields.io/badge/X-0x4161-000000?logo=x&logoColor=white)](https://x.com/0x4161)
[![Instagram](https://img.shields.io/badge/Instagram-fx__py3-E4405F?logo=instagram&logoColor=white)](https://instagram.com/fx_py3)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Ahmad_Alanazi-0A66C2?logo=linkedin&logoColor=white)](https://linkedin.com/in/ahmad-alanazi-b1040933b/)

---

## License

MIT — free to use, modify, and distribute. See [LICENSE](LICENSE) for details.
