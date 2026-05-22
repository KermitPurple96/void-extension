# Void Extension

A professional Chrome DevTools extension built for bug bounty hunters and security researchers. Packed into your browser's DevTools panel — no external proxy required.

![Chrome MV3](https://img.shields.io/badge/Chrome-MV3-4285F4?logo=googlechrome&logoColor=white)
![Version](https://img.shields.io/badge/version-1.0.0-green)
![License](https://img.shields.io/badge/license-MIT-blue)

---

## Features

| Tab | What it does |
|-----|-------------|
| **Intercept** | Attach Chrome Debugger, pause live requests, edit headers/body, forward or drop |
| **Repeater** | Craft and replay HTTP requests with full header and body control |
| **Endpoints** | Auto-discover API routes, forms, scripts, and links on any page |
| **Tech** | Detect the full technology stack — server, framework, CMS, CDN, WAF, analytics, and more |
| **Headers** | Capture and inspect every response header for security misconfigurations |

### Recon Engine (Tech tab)
- WHOIS via RDAP — registrar, registrant, contacts, DNSSEC, abuse info
- DNS — A, AAAA, MX (with priority), NS, TXT (SPF / DMARC / DKIM detection), CNAME, SOA, CAA, PTR
- IP Geolocation — ASN, ISP, org, country, region, city, timezone, coordinates
- Technology fingerprinting — 40+ categories with SVG icons and brand colours

---

## Installation

> No build step. No npm. Just load the folder directly into Chrome.

### Step 1 — Download the extension

**Option A — Clone with Git**
```bash
git clone https://github.com/0x4161/void-extension.git
```

**Option B — Download ZIP**
1. Click the green **Code** button at the top of this page
2. Choose **Download ZIP**
3. Extract the ZIP anywhere on your computer (e.g. `Desktop/void-extension`)

---

### Step 2 — Open Chrome Extensions page

Open a new tab and go to:
```
chrome://extensions
```

Or navigate via the Chrome menu:
> ⋮ → Extensions → Manage Extensions

---

### Step 3 — Enable Developer Mode

In the top-right corner of the Extensions page, toggle **Developer mode** ON.

```
┌─────────────────────────────────┐
│  Extensions          [Developer mode ●] │
└─────────────────────────────────┘
```

---

### Step 4 — Load the extension

1. Click **Load unpacked**
2. Browse to the folder you cloned/extracted (the folder that contains `manifest.json`)
3. Click **Select Folder**

The extension will appear in your list with the name **Void Extension**.

---

### Step 5 — Open DevTools on any page

1. Go to any website you have permission to test
2. Press `F12` (or `Ctrl+Shift+I` / `Cmd+Option+I` on Mac) to open DevTools
3. Click the **»** arrow at the right of the DevTools tab bar
4. Select **Void** from the dropdown

The panel will open with all five tabs ready to use.

---

## Usage Guide

### Intercept Tab

1. Click **Attach Debugger** — Chrome will show a banner on the target tab (normal behaviour)
2. Click **Intercept: OFF** to toggle interception ON
3. Interact with the page — any network request will pause and appear in the list
4. Click a paused request to open the editor
5. Edit method, URL, headers, or body freely
6. Click **Forward →** to send the (possibly modified) request, or **Drop ✕** to cancel it
7. Use **→ Repeater** to send the request to the Repeater tab for further testing

### Repeater Tab

- Set the HTTP method, full URL, custom headers, and body
- Click **Send** — the response appears split into Body / Headers / Raw views
- Drag the divider between request and response panes to resize

### Endpoints Tab

- Endpoints are collected automatically while you browse the page
- Use the **filter box** to search by URL and the **type dropdown** to narrow by API / Form / Script / Link
- Click **Copy All** to copy every discovered URL to the clipboard
- Click any endpoint row to send it straight to the Repeater

### Tech Tab

1. Click **⚡ Scan WHOIS + DNS** to run the full recon scan
2. Left sidebar shows IP / Geo, DNS records, and WHOIS details
3. Right side shows the detected technology stack grouped by category

### Headers Tab

- Response headers are captured automatically once the debugger is attached
- Each row shows the header name, value, and the URL it came from

---

## Permissions Explained

| Permission | Why it's needed |
|-----------|----------------|
| `debugger` | Attach to tabs to intercept and modify network requests |
| `tabs` | Open social links and read the active tab's URL |
| `activeTab` | Access the currently inspected page |
| `storage` | Persist intercept state across DevTools open/close |
| `scripting` | Inject the content script for endpoint and tech detection |
| `alarms` | Keep the service worker alive in the background |
| `host_permissions: <all_urls>` | Required to attach the debugger to any domain |

---

## Project Structure

```
void-extension/
├── manifest.json      # Extension manifest (MV3)
├── devtools.html      # DevTools page entry point
├── devtools.js        # Creates the DevTools panel
├── panel.html         # Panel UI markup
├── panel.js           # Panel logic (intercept, repeater, recon rendering)
├── panel.css          # All styles
├── background.js      # Service worker — debugger bridge, DNS/WHOIS/IP APIs
├── content.js         # Content script — endpoint & tech fingerprinting
├── early.js           # document_start content script
└── icons/
    ├── icon16.png
    ├── icon48.png
    └── icon128.png
```

---

## Legal & Ethics

This tool is intended **only** for use on targets you own or have **explicit written permission** to test. Attaching the Chrome Debugger to a tab is visible to the user of that tab. Always operate within the scope of an authorised bug bounty program.

---

## Author

**Ahmad Alanazi**

[![X](https://img.shields.io/badge/X-0x4161-000000?logo=x&logoColor=white)](https://x.com/0x4161)
[![Instagram](https://img.shields.io/badge/Instagram-fx__py3-E4405F?logo=instagram&logoColor=white)](https://instagram.com/fx_py3)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Ahmad_Alanazi-0A66C2?logo=linkedin&logoColor=white)](https://linkedin.com/in/ahmad-alanazi-b1040933b/)

---

## License

MIT — free to use, modify, and distribute. See [LICENSE](LICENSE) for details.
