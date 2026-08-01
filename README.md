# Void Extension

A Chrome DevTools extension for bug bounty hunters and security researchers — an in-browser testing toolkit in the shape of a DevTools panel. Works standalone; two optional Node helpers add an intercepting proxy and cross-container sync.

![Chrome MV3](https://img.shields.io/badge/Chrome-MV3-4285F4?logo=googlechrome&logoColor=white)
![Version](https://img.shields.io/badge/version-1.0.0-green)
![License](https://img.shields.io/badge/license-MIT-blue)

---

## Contents

- [Features](#features)
- [Traffic capture](#traffic-capture)
- [Installation](#installation)
- [The intercepting proxy](#the-intercepting-proxy)
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
| **History** | Every request with field search, column filters, reflection detection, **remote IP column** |
| **WebSocket** | Live WebSocket frame capture — direction, type, length, connection status pills, JSON detail |
| **Repeater** | Dual side-by-side Repeaters with independent tabs, **Diff** to compare responses, Burp-style path + HTTP version bar, split/raw mode |
| **Intruder** | 4 fuzzing modes + **8 specialized attacks**: Auth/IDOR, Race Condition, Param Miner, JWT Attacker, CORS Scanner, Request Smuggling, GraphQL Explorer, Upload Scanner |
| **Scan** | DOM XSS hunter (Probe) + **Active Scanner** (8 modules: SQLi, XSS, SSRF, path traversal, SSTI, CMDi, open redirect, CRLF) + **Content Discovery** (100+ paths) + **Interactsh OOB** |
| **Logger** | Cross-container traffic aggregator |
| **Containers** | Launch isolated Chrome profiles with their own cookie jars |
| **Headers** | Security-header analysis of the main document, beside every captured header |
| **Dencoder** | Chain-based encoding/decoding with **saved presets** — 20 operations in any order |
| **PoC** | CSRF PoC (6 techniques + 4 evasions) + Clickjacking PoC (4 techniques), based on PortSwigger labs |
| **Sequencer** | Token entropy analysis — Shannon entropy, 5 statistical tests, character frequency histogram |
| **Notes** | Severity-tagged findings, CRUD, markdown export by host |
| **API Schema** | Auto-generate **OpenAPI 3.0 YAML** from captured traffic |
| **Sensitive** | 180+ passive rules — secrets, PII, tech disclosure, **cookie flags, CSP absence, SRI, CRLF** |
| **Settings** | Match & replace, auto headers, scope, **4 themes**, **TLS fingerprint (JA3/JA4)**, session handling, **Collaborator Everywhere**, settings profiles, upstream proxy, HAR export |

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

Passive capture is always on, which is why History fills up without attaching anything. Response bodies only exist on debugger- and proxy-captured rows; passive rows say so plainly instead of implying one is on the way.

---

## Installation

> No build step. No bundler. Load the folder straight into Chrome.

### 1. Get the extension

```bash
git clone https://github.com/KermitPurple96/void-extension.git
```

Or use **Code → Download ZIP** and extract it anywhere.

### 2. Load it into Chrome

1. Go to `chrome://extensions`
2. Toggle **Developer mode** ON (top-right)
3. Click **Load unpacked**
4. Select the folder containing `manifest.json`

### 3. Open the panel

1. Open any site you are authorised to test
2. Press `F12` (or `Ctrl+Shift+I` / `Cmd+Option+I`)
3. Click the **»** arrow in the DevTools tab bar
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
proxy    http://127.0.0.1:8081     ← point curl / Postman / your phone here
control  ws://127.0.0.1:8082       ← the Void panel connects here
CA       ~/.void/void-ca.pem       ← generated on first run
```

HTTPS is MITM'd with a CA generated by `openssl` on first run; per-host leaf certificates are signed on demand and cached. Clients must trust it:

```bash
curl -x http://127.0.0.1:8081 --cacert ~/.void/void-ca.pem https://target/
```

### The three states

In the **Intercept** tab, the `Proxy` button cycles:

| Button | Control channel | Traffic | Recorded in History | Held for editing |
|---|---|---|---|---|
| `Proxy: connect` | disconnected | passes | no | no |
| `Proxy: logging` | connected | passes | **yes** | no |
| `Proxy: intercepting` | connected | passes | yes | **yes** |

`logging` is the everyday mode — the equivalent of Burp with *Intercept is off*. Requests held by the proxy land in the same queue as debugger-held ones, tagged `PROXY`, and reuse the same editor, Forward / Drop and → Repeater / → Intruder buttons.

> **Disconnecting Void does not stop the proxy.** If the Node process is running it keeps passing traffic — it just stops being recorded. Kill the process to actually stop it.

### Limitations

- **No streaming.** Bodies are buffered (5 MB cap) so they can be edited, and `Accept-Encoding: identity` is forced. SSE and large downloads will not work through the proxy.
- **Chrome is not routed through it.** The browser keeps using the debugger path; the proxy is for external clients.
- **Upstream certificates are not verified** (`rejectUnauthorized: false`) — you are the interception point, so validating upstream is your call, not the tool's.

---

## Cross-container sync

```bash
node void-sync-server.js     # ws://localhost:17580
```

Containers launch separate Chrome profiles with their own `--user-data-dir`, so cookies are genuinely isolated. Each instance pushes its history to the sync server and the **Logger** tab shows the merged view across all of them.

History is local to its window; Logger is the aggregator.

---

## Usage guide

### Intercept

1. **Chrome traffic** — click **Attach Debugger**, toggle **Intercept: OFF** → ON
2. **Response interception** — click **Responses: OFF** → ON to also pause responses for editing (status, headers, body)
3. **External traffic** — start the proxy, click **Proxy: connect** → **logging** → **intercepting**
4. Click a paused request/response to open the editor
5. **Forward →** sends, **Drop ✕** kills
6. Full toolbar: → Repeater, → Intruder, → PoC, → Notes, ↗ Open, Reflections, Render, curl/fetch/py

### Repeater

- **Dual side-by-side** — click **Compare** to open a second Repeater; each side has its own tab selection from the shared tab pool
- **Diff** button highlights differences between left and right responses (LCS diff, case-insensitive option)
- Burp-style request bar: `[Method ▼] [/path?query] [HTTP/1.1 ▼]` — Host in headers, not URL
- **Split / Raw** mode toggle in Settings — separate Headers+Body or single raw editor
- **✎ Target** overrides TCP destination (IP/domain to connect to, independent of Host header)
- Full toolbar on both sides: → Intruder, → PoC, → Notes, ↗ Open, Reflections, Render, curl/fetch/py

### Intruder

**Fuzzing modes:** Sniper, Battering Ram, Pitchfork, Cluster Bomb — with `§position§` markers, payload processing (12 transforms), grep match/extract columns

**Specialized attacks:**

| Mode | What it does |
|------|-------------|
| **Auth / IDOR** | Replays request with User A, User B, and unauthenticated cookies; flags same-status responses |
| **Race Condition** | Fires 20+ parallel requests simultaneously; flags status/length anomalies |
| **Param Miner** | Bruteforces hidden params (200 built-in) in query/body/headers/cookies |
| **JWT Attacker** | `alg:none` bypass, HS256 weak secret brute-force (30 secrets), claim tampering |
| **CORS Scanner** | Tests 7 Origin header variations; reports ACAO reflection + credentials |
| **Request Smuggling** | CL.TE, TE.CL, TE.TE detection with timing analysis |
| **GraphQL Explorer** | Introspection query, schema discovery, type/field listing |
| **Upload Scanner** | 7 polyglot payloads (SVG XSS, PHP shell, path traversal, XXE) |

### History

- Fills automatically from passive capture — no attach needed
- `field:value` search (`host:`, `path:`, `status:`, `body:`, `header:`) alongside per-column filters
- **Remote IP column** — shows the server IP:port from CDP (like Burp)
- Reflection dot marks rows where request values appear in the response

### Active Scanner (Scan tab)

- **8 scan modules**: SQL injection (error + time-based), reflected XSS, path traversal, SSRF (with Interactsh OOB), SSTI, command injection, open redirect, CRLF/header injection
- **Content Discovery**: 100+ common paths bruteforced (SecLists-based)
- **Interactsh OOB**: generate callback URLs, poll for DNS/HTTP/SMTP interactions
- Auto-identifies injection points from URL params and body params

### Dencoder

- **Chain-only**: add steps from dropdown (20 operations: base64, URL, hex, HTML, unicode, JS, ASCII hex, JWT decode, MD5, SHA-1, SHA-256, lowercase, uppercase)
- Steps run in order — output of each feeds into the next
- **Save/load named chains** to chrome.storage
- Swap input/output, clear all

### PoC Generator

- **CSRF**: 6 techniques (auto-form, GET img/iframe, XHR text/plain, fetch no-cors, method override, multipart) + 4 evasion toggles (auto-submit, suppress referer, strip tokens, sandbox)
- **Clickjacking**: 4 techniques (basic overlay, prefilled form, frame buster bypass, multistep) with configurable positioning

### API Schema

- **Generate from History** builds OpenAPI 3.0 YAML from captured traffic
- Groups endpoints by path + method, extracts query params, content types, observed status codes
- Copy + download .yaml

### Headers

- **Security Analysis** (left) runs against the **main document response only** — CSP, HSTS and X-Frame-Options are meaningless for sub-resources, and a third-party iframe must not be allowed to overwrite them
- The bar at the top names the exact URL being analysed
- **All Headers** (right) defaults to that same response; tick *include sub-resources* to fold in every other response, each labelled with its origin and flagged when it came from another host

### Sensitive

180+ passive rules across everything in History:

| Category | Examples |
|---|---|
| Tokens & keys | AWS, Google, Stripe, GitHub, Slack, OpenAI |
| General secrets | PEM blocks, generic API keys, private IPv4 |
| Cloud & webhooks | S3, Azure Blob, GCS, Slack/Teams webhooks |
| Sensitive files | `.bak`, `.keychain`, `.cscfg`, `.env` |
| Information disclosure | stack traces, `phpinfo()`, exposed `.git/config` |
| PII | SSN, card numbers, JWTs, bcrypt hashes |
| Security misconfig | **Cookie missing Secure/HttpOnly/SameSite**, missing CSP, mixed content, missing SRI |
| Tech & version disclosure | `Server`, `X-Powered-By`, ASP.NET/PHP versions, internal hostnames |
| Source maps | `.js.map` requests, `sourceMappingURL`, inline maps |

Custom rules can be added from the tab.

### Settings

- **Match & Replace** — auto-modify requests and responses (regex, header add/remove, body)
- **Auto Headers** — injected into every outgoing request
- **Request view** — Split (Headers + Body) or Raw (single editor like Burp)
- **4 Themes** — Dark (GitHub), Light (GitHub), Dracula, Hacker
- **TLS Fingerprint** — fetch your JA3/JA4 hash, TLS version, cipher suites, extensions
- **Collaborator Everywhere** — auto-inject Interactsh OOB URLs into 10 request headers
- **Session handling** — login macro with auto-renewal on session expiry
- **Settings profiles** — save/load/export/import named settings configurations
- **HAR 1.2 export**, scope auto-detect, upstream proxy config
- **Keyboard shortcuts** — Ctrl+Enter (send), Ctrl+I (intercept), Ctrl+1-9 (switch tabs)

### Project

- **Session** — full workspace save/restore (history, repeater tabs, scope, notes, WS frames, sequencer, scan findings, decoder chain)
- **Site Map** — hierarchical tree of everything seen
- **Scope** — include/exclude patterns other tabs can filter by

---

## Permissions

| Permission | Why it's needed |
|-----------|----------------|
| `debugger` | Attach to tabs to intercept and modify requests, and read response bodies |
| `webRequest` | Passive traffic capture across all tabs without attaching the debugger |
| `tabs` | Open links and read the active tab's URL |
| `activeTab` | Access the currently inspected page |
| `storage` | Persist settings, sessions and intercept state |
| `unlimitedStorage` | Saved sessions can hold large histories |
| `scripting` | Inject the content script and the Probe scanner |
| `cookies` | Cookie sync for Repeater and Intruder |
| `downloads` | Export findings, sessions and container sync files |
| `alarms` | Keep the service worker alive |
| `host_permissions: <all_urls>` | Required to attach the debugger and capture traffic on any domain |

The `extension_pages` CSP uses `connect-src *` because the Repeater, the crawler and the DNS/WHOIS lookups issue `fetch()` from the service worker to arbitrary hosts. `default-src 'none'` and `script-src 'self'` — the directives that actually stop injection — stay in place.

---

## Project structure

```
void-extension/
├── manifest.json          # Extension manifest (MV3)
├── package.json           # Pins `ws` for the two Node helpers — not needed by the extension
├── devtools.html/.js      # DevTools page entry point
├── panel.html             # Panel UI markup
├── panel.js               # Panel logic — all tabs, rendering, proxy control channel
├── panel.css              # All styles
├── background.js          # Service worker — debugger bridge, passive capture,
│                          #   DNS/WHOIS/IP APIs, crawler, proxy history
├── content.js             # Content script — endpoint & tech fingerprinting
├── early.js               # document_start content script
├── sensitive-rules.js     # 180+ passive scanner rules
├── void-proxy-server.js   # Node helper — intercepting MITM proxy (:8081 / ws :8082)
├── void-sync-server.js    # Node helper — cross-container sync (ws :17580)
├── probe/                 # DOM XSS hunter, injected into the page
│   ├── scanner.js  flows.js  hooks.js  frameworks.js
│   ├── fuzzer-*.js        # payload generation and autofill
│   └── highlighter.js  reporter.js  main.js
├── tests/
│   └── e2e-audit.js       # 180 automated integrity tests
└── icons/
```

Neither Node helper is required to use the extension.

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
