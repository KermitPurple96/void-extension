---
name: "http-parameter-pollution"
description: "HTTP Parameter Pollution — server-side and client-side HPP, parameter precedence by framework, WAF bypass and cache poisoning chains"
version: "1.0.0"
author: "void-extension"
tags: ["pentest", "injection", "hpp", "parameter-pollution", "waf-bypass", "cache", "oauth"]
trigger_patterns:
  - "/http-parameter-pollution"
  - "/hpp"
  - "http parameter pollution"
  - "parameter pollution"
  - "duplicate parameters"
  - "test hpp"
  - "waf bypass parameter"
---

# HTTP Parameter Pollution (HPP)

HTTP Parameter Pollution occurs when an attacker injects additional parameters
into a query string or POST body that already contains that parameter. The
server-side application's behaviour when it receives two values for the same
key depends entirely on the backend framework — and often differs from what the
WAF or proxy sitting in front of it expects.

This creates three distinct classes of attack:

1. **Server-side HPP (SHPP)** — influence application logic by supplying a
   duplicate that overrides or extends the legitimate value.
2. **Client-side HPP (CHPP)** — inject an extra parameter whose value appears
   inside a link or form the page generates, leading to open redirect or XSS.
3. **Bypass layer** — WAF / proxy parses the first value while the app uses the
   last (or a concatenation), letting a malicious value slip through.

Reference: OWASP WSTG-INPV-04.

## Scope and preconditions

Applies to any endpoint that reads parameters from query strings, POST bodies
(`application/x-www-form-urlencoded`, `multipart/form-data`), or HTTP headers.
JSON bodies are NOT susceptible — duplicate keys are a JSON syntax error handled
by the parser, not by the framework.

## Rules of engagement

- Only test against accounts and data you own or that are explicitly in scope.
- HPP that successfully bypasses a WAF might expose SQL injection, XSS, or
  SSRF — follow the relevant skill for the underlying vuln once HPP bypass is
  confirmed.
- Record each bypass with `add_pentest_finding`.

## Parameter precedence reference

This table is the foundation of HPP testing. Knowing what the target stack does
with duplicates tells you which direction to send the attack value:

| Backend / Language       | Behaviour on `?id=1&id=2`                     | Example |
|--------------------------|-----------------------------------------------|---------|
| PHP (`$_GET['id']`)      | **Last wins** — `id = 2`                      | Laravel, Symfony, WordPress |
| ASP.NET (`Request["id"]`)| **Concatenated with comma** — `id = "1,2"`    | .NET MVC, WebForms |
| Java Servlet (`getParameter`) | **First wins** — `id = 1`               | Tomcat, Jetty, Spring |
| Java Servlet (`getParameterValues`) | **Array** — `["1","2"]`           | Correct multi-value API |
| Node.js / Express (`req.query.id`) | **Array** — `["1","2"]` (default qs) | qs parser; scalar with querystring |
| Ruby on Rails            | **Last wins** — `id = 2`                      | Rack |
| Go `net/http` (`r.FormValue`) | **First wins** — `id = 1`               | stdlib |
| Python Flask (`request.args.get`) | **First wins** — `id = 1`           | Werkzeug |
| Python Django (`request.GET.get`) | **Last wins** — `id = 2`            | QueryDict |
| Nginx (proxy_pass)       | **Both forwarded** unchanged to upstream       | Depends on upstream |

When you do not know the stack, test empirically in Step 2.

## Workflow

- [ ] 1. Fingerprint parameter handling behaviour
- [ ] 2. Test server-side HPP (logic influence)
- [ ] 3. Test client-side HPP (generated links / forms)
- [ ] 4. Test WAF/proxy bypass
- [ ] 5. Chain with cache poisoning, OAuth, or other vulns
- [ ] 6. Report findings

## Step 1: Fingerprint parameter handling

Choose a parameter whose effect is observable — a numeric ID, a search term, a
flag. Send the following four requests using `send_request`, varying only the
query string:

```
GET /search?q=hello HTTP/1.1          → baseline
GET /search?q=hello&q=world           → last-wins stack: "world"; first-wins: "hello"; ASP: "hello,world"
GET /search?q=world&q=hello           → if result flips vs above → last-wins confirmed
GET /search?q[]=hello&q[]=world       → PHP array notation — alternative duplicate mechanism
```

Use `compare_responses` between the baseline and the duplicate request to see
which value the server acted on. Check the response body for the reflected value.

**Fingerprint result guide:**

| Observed response | Conclusion |
|-------------------|------------|
| Second value used | Last-wins (PHP / Node / Rails) |
| First value used  | First-wins (Java / Go / Django) |
| Both values in body | Concatenated (ASP.NET) or array |
| Error / 400       | Framework rejects duplicates |

## Step 2: Server-side HPP — logic influence

Once you know the precedence rule, craft the attack parameter position accordingly.

### Example: privilege escalation via role override

If a POST body sets `role=user`, adding a second `role=admin` in last-wins
frameworks overrides it:

```
POST /profile/update HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=alice&role=user&role=admin
```

Use `send_request` to submit this. Compare the response to a legitimate request
using `compare_responses`. Look for:
- Different response body (e.g., admin menu appears)
- Different redirect destination
- Changed session permissions on next request

### Example: bypassing business logic with duplicate amounts

E-commerce price checks sometimes validate only the first parameter:

```
POST /checkout HTTP/1.1

item_id=123&quantity=1&price=0.01&price=99.99
```

If the validation reads `price[0]` (first-wins) but billing reads `price[-1]`
(last-wins), you pay 0.01 and are charged 99.99 — or vice versa.

### Example: token injection in OAuth / SAML flows

Add a duplicate `redirect_uri` or `state` parameter:

```
GET /oauth/authorize?client_id=app&redirect_uri=https://legit.com&redirect_uri=https://evil.com
```

Which URI the auth server uses determines whether the code is delivered to the
attacker. Use `search_responses` to look for the URI reflected in the `Location`
header.

## Step 3: Client-side HPP

CHPP exploits pages that build links or form actions from request parameters.

### Detection

Search the response HTML for reflected parameter values. Use `search_responses`
with the parameter value as the pattern. If the value appears inside an `<a
href>`, `<form action>`, or `<script>` block, CHPP may be possible.

### Attack: injecting an extra parameter into a generated link

```
GET /share?url=https://legit.com&url=https://evil.com
```

If the page generates:
```html
<a href="https://legit.com&url=https://evil.com">Share</a>
```

The user clicking the link sends both parameters to `legit.com`, and if that
site is also vulnerable to HPP, the evil value takes effect there.

### Attack: CHPP → XSS

When a parameter value is reflected into a `href` without encoding:

```
GET /page?next=/dashboard&next=javascript:alert(1)
```

If `next` is written into `href="…"` and the last value wins, the link becomes
`href="javascript:alert(1)"`.

## Step 4: WAF / proxy bypass

This is often the highest-value HPP finding. The WAF inspects the first
(or primary) parameter; the application processes a different one.

### Strategy A: attack value as second parameter

WAF blocks `?id=1 OR 1=1--`. Send:

```
GET /search?id=SAFE&id=1 OR 1=1--
```

If the WAF checks only the first `id` (value `SAFE`), it passes. If the app
uses the last (value `1 OR 1=1--`), the SQL injection executes.

### Strategy B: split across parameter and fragment

Some WAF products do not decode `%26` before matching:

```
GET /search?id=1%26id=2 OR 1=1--
```

The WAF sees one parameter `id=1%26id=2 OR 1=1--`. The app URL-decodes `%26`
to `&` and sees two parameters. Combine with the SQL injection skill for
exploitation steps.

### Strategy C: HPP with header injection

Some frameworks allow headers to be overridden via query parameters
(e.g., `_method=PUT` in Rails):

```
GET /delete?_method=GET&_method=DELETE
```

One value passes authorisation checks; the other executes the action.

Use `get_response_headers` after each probe to check what the upstream received.

## Step 5: Chain with cache poisoning

If the target sits behind a cache:

1. Use `send_request` with a cache-buster to avoid polluting real cache.
2. Inject the HPP payload in a parameter that influences cacheable content.
3. If the cache is keyed on the first parameter value and the app uses the
   last, the response stored under the clean key contains the injected content.
4. Verify by fetching the URL with no HPP payload from a fresh session — the
   poisoned content should appear.

This chain can escalate a reflected HPP to stored/cached XSS or a persistent
redirect. Document with `add_pentest_finding` at Critical if XSS executes from
cache.

## Severity reference

| Finding | Severity |
|---------|----------|
| HPP → WAF bypass → SQL injection / RCE | Critical |
| HPP → stored/cached XSS | Critical |
| HPP → privilege escalation (role override) | High |
| HPP → OAuth redirect_uri hijack | High |
| HPP → open redirect via CHPP | Medium |
| HPP → WAF bypass (no exploitable downstream vuln) | Medium |
| HPP reflected in response but no exploitable context | Low |

## Known false positives

- Parameters that concatenate (ASP.NET) and both values appear in a non-rendered
  context (JSON field, log) are usually not exploitable.
- A framework that returns 400 on duplicate parameters is safe for SHPP; still
  check CHPP in generated links.
- Test the actual backend, not just the WAF response — the WAF may strip
  duplicates before forwarding, eliminating the bypass.

## Tooling note

This methodology uses Void panel tools exclusively: `send_request` for crafting
duplicate-parameter requests, `compare_responses` for baseline diffing,
`search_responses` for finding reflections in HTML, `get_response_headers` for
header analysis, and `add_pentest_finding` to record confirmed results.
These are browser-extension APIs, not shell commands — do not attempt to run CLI
tools.
