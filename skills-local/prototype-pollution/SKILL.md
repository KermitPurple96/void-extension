---
name: "prototype-pollution"
description: "JavaScript Prototype Pollution Testing"
version: "1.0.0"
author: "void-extension"
tags: ["pentest", "prototype-pollution", "javascript", "node", "injection", "rce", "xss"]
trigger_patterns:
  - "/prototype-pollution"
  - "test prototype pollution"
  - "test __proto__"
  - "prototype pollution"
  - "server-side prototype pollution"
  - "client-side prototype pollution"
---

# Prototype Pollution Testing Methodology

Test JavaScript applications for prototype pollution — injecting properties into
`Object.prototype` via `__proto__`, `constructor.prototype`, or `constructor`
gadgets. Covers both client-side (DOM-based XSS, privilege escalation in SPAs)
and server-side (RCE via template engine gadgets, property injection).

## Scope and preconditions

Applies to any application that parses attacker-controlled JSON, query strings,
or form data and merges it into objects — especially Node.js backends using
recursive merge/extend utilities and SPAs consuming JSON APIs.

It does **not** cover: general XSS (use `xss`), SQL injection (use `sqli`),
or template injection without a pollution vector (use `ssti`).

## Rules of engagement

- NEVER use a pollution payload that causes denial of service (e.g. polluting
  `toString` to crash all subsequent operations). Use read-only detection first.
- Use status-code and response-body changes as your oracle, not destructive
  side effects.
- Record every request/response pair for confirmed findings with
  `add_pentest_finding`.
- In mode `ask`: confirm the pollution sticks and stop. Do not chain to RCE.

## Workflow

- [ ] 1. Identify merge/parse surfaces (JSON body, query params, PATCH endpoints)
- [ ] 2. Probe for server-side pollution via status-code oracle
- [ ] 3. Probe for client-side pollution via URL fragment/query
- [ ] 4. Confirm pollution persistence
- [ ] 5. Identify exploitable gadgets
- [ ] 6. Verify and record findings

## Step 1: Identify merge surfaces

### Actions

Use `get_endpoints` and `search_responses` to find endpoints that accept JSON
bodies — especially PUT, PATCH, POST endpoints for user profiles, settings,
preferences, or any object update.

Look for query-string parsers that support nested objects:
`?__proto__[polluted]=true` or `?constructor[prototype][polluted]=true`.

## Step 2: Server-side pollution detection

### Status-code oracle technique

The safest detection method: pollute a property that changes the HTTP status
code without breaking the application.

**Probe 1 — Inject via JSON body:**

```json
POST /api/user/update
Content-Type: application/json

{
  "__proto__": {
    "status": 555
  }
}
```

Then send a normal request. If the response status changes to 555, pollution
persists on the server.

**Probe 2 — Common detection properties:**

| Payload | Oracle |
|---------|--------|
| `"__proto__": {"status": 555}` | Response status changes to 555 |
| `"__proto__": {"admin": true}` | Privilege escalation (check via `send_request` to admin endpoint) |
| `"__proto__": {"isAdmin": true}` | Same — try common role property names |
| `"constructor": {"prototype": {"status": 555}}` | Alternative path to prototype |

**Probe 3 — JSON content-type variants:**

Some parsers only trigger on specific content types. Try each:

```
Content-Type: application/json
Content-Type: application/x-www-form-urlencoded (with nested bracket syntax)
Content-Type: application/merge-patch+json
```

**Probe 4 — Nested object paths:**

```json
{"__proto__": {"polluted": "yes"}}
{"constructor": {"prototype": {"polluted": "yes"}}}
{"a": {"__proto__": {"polluted": "yes"}}}
```

### Detecting without side effects

Use `compare_responses` to diff a normal request against one with the pollution
payload. If the response changes (status, headers, body properties), pollution
is confirmed.

After confirming, try to clean up by sending:
```json
{"__proto__": {"status": null}}
```

## Step 3: Client-side pollution detection

### Actions

Use `eval_page` to check if `Object.prototype` is polluted:

```javascript
Object.prototype.testVoidPollution === undefined
```

Then inject via URL:
- `https://target.com/?__proto__[testVoidPollution]=injected`
- `https://target.com/?__proto__.testVoidPollution=injected`
- `https://target.com/#__proto__[testVoidPollution]=injected`

Use `eval_page` again to check:
```javascript
({}).testVoidPollution
```

If it returns `"injected"`, client-side pollution works.

### DOM-based exploitation

Use `get_scripts` to find JavaScript that reads from `Object.prototype` without
`hasOwnProperty` checks. Common sinks:

| Pattern | Impact |
|---------|--------|
| `element.innerHTML = obj[key]` | XSS via polluted property |
| `$.extend(true, {}, userInput)` | jQuery deep merge — classic vector |
| `_.merge({}, userInput)` | Lodash merge — version-dependent |
| `document.createElement(obj.tag)` | DOM manipulation |

## Step 4: Confirm persistence

Server-side pollution that persists across requests for ALL users is Critical.
Pollution that only affects the current request is lower severity but still
exploitable in gadget chains.

Use `send_request` from a clean session (no cookies) to a generic endpoint.
If the polluted property appears, it persists globally.

## Step 5: Gadget chains

Once pollution is confirmed, identify what consumes the polluted properties.

### Server-side gadgets (Node.js)

| Template engine | Gadget property | Impact |
|----------------|-----------------|--------|
| EJS | `outputFunctionName` | RCE — polluted value is injected into compiled template function |
| Pug/Jade | `block.type` / `block.val` | RCE — polluted block definition executes during render |
| Handlebars | `pendingContent` | XSS — injected HTML rendered in template output |
| Express | `layout` | View hijack — loads attacker-controlled template |

For each gadget, the technique is: pollute the gadget property via the
vulnerable merge endpoint, then trigger a template render. The template
engine reads the polluted property from its options object (which inherits
from `Object.prototype`) and uses it unsafely.

### Client-side gadgets

Use `search_responses` and `get_scripts` to find libraries:

| Library | Gadget | Impact |
|---------|--------|--------|
| jQuery < 3.4.0 | `$.extend(true, ...)` | Merge vector |
| Lodash < 4.17.12 | `_.merge`, `_.defaultsDeep` | Merge vector |
| Vue.js | `v-bind:class` via `__proto__` | XSS |
| Google Closure | `goog.object.merge` | Merge vector |

## Step 6: Verification

Do not report until:

1. You can show the polluted property value in a response or `eval_page` output.
2. Reproduction works from a clean session.
3. You have identified the impact: information disclosure, privilege escalation,
   XSS, or RCE.

## Severity reference

| Finding | Severity |
|---------|----------|
| Server-side RCE via gadget chain (EJS/Pug) | Critical |
| Global persistent pollution (affects all users) | Critical |
| Privilege escalation via admin property | High |
| Client-side XSS via DOM gadget | High |
| Request-scoped pollution (no gadget found) | Medium |
| Client-side pollution (no exploitable gadget) | Low |

## Known false positives

- The server returned 500 after your payload — this may be a parsing error, not
  pollution. Confirm by checking if a *subsequent clean request* is affected.
- jQuery `$.extend` is present but only called with `false` (shallow merge) — no
  pollution possible.
- The application uses `Object.freeze(Object.prototype)` — pollution is blocked.
  Check with `eval_page` before reporting.

## Tooling note

This methodology is designed for the Void panel tools (`send_request`,
`compare_responses`, `search_responses`, `get_endpoints`, `eval_page`,
`get_scripts`, `add_pentest_finding`, `decode`, `encode`). These are
browser-extension APIs, not shell commands. Do not attempt to run CLI tools.
