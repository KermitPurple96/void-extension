---
name: "cspt"
description: "Client-Side Path Traversal Testing"
version: "1.0.0"
author: "void-extension"
tags: ["pentest", "cspt", "client-side", "path-traversal", "fetch", "spa", "xhr"]
trigger_patterns:
  - "/cspt"
  - "test cspt"
  - "client-side path traversal"
  - "client side path traversal"
  - "test fetch url"
  - "cspt to csrf"
---

# Client-Side Path Traversal (CSPT) Testing Methodology

Test for client-side path traversal where attacker-controlled input is used to
construct fetch/XHR URLs in the browser, allowing the request to be redirected
to unintended API endpoints. This can escalate to CSRF (CSPT-to-CSRF), XSS
(CSPT-to-XSS), or information disclosure.

## Scope and preconditions

Applies to any single-page application (SPA) or JavaScript-heavy application
that constructs API URLs dynamically using values from: URL path segments, query
parameters, hash fragments, postMessage data, or localStorage/sessionStorage.

It does **not** cover: server-side path traversal for file read (use
path-traversal), open redirect (use redirect), or general CSRF (use csrf).

## Rules of engagement

- NEVER use CSPT to perform destructive actions on real accounts. Prove the
  traversal reaches the unintended endpoint, then stop.
- Use benign target endpoints (e.g. user profile fetch) to prove traversal.
- Record every request with add_pentest_finding.
- In mode ask: confirm the path traversal changes the destination endpoint
  and stop.

## Workflow

- [ ] 1. Find dynamic URL construction in JavaScript
- [ ] 2. Identify attacker-controlled path segments
- [ ] 3. Test path traversal payloads
- [ ] 4. Assess CSPT-to-CSRF potential
- [ ] 5. Assess CSPT-to-XSS potential
- [ ] 6. Test postMessage-based CSPT
- [ ] 7. Verify and report

## Step 1: Find dynamic URL construction

### Actions

Use get_scripts to list all JavaScript files. Search for patterns where URLs
are built using user input.

Use search_responses with patterns like fetch() combined with string
concatenation, XMLHttpRequest with dynamic URLs, or axios calls with
variable URL segments.

### Common vulnerable patterns

URL path segment from user input: fetch('/api/users/' + userId + '/profile')

Query parameter used in path: extract id from URLSearchParams, then
fetch('/api/items/' + id)

Hash fragment used in URL: extract tab from location.hash, then
fetch('/api/data/' + tab)

## Step 2: Identify attacker-controlled segments

For each dynamic URL found, trace the input source:

| Source | Attacker control |
|--------|-----------------|
| URL path segment (/page/:id) | Full control via crafted link |
| Query parameter (?id=X) | Full control via crafted link |
| Hash fragment (#section) | Full control via crafted link |
| postMessage data | Control if no origin check |
| localStorage/sessionStorage | Requires prior XSS or CSPT |
| Cookie value | Partial control via cookie injection |

## Step 3: Test path traversal payloads

If the application constructs: fetch('/api/users/' + id + '/profile')

And id comes from ?id=123, test:

| Payload | Resulting URL | Effect |
|---------|---------------|--------|
| ../admin/users | /api/admin/users/profile (after browser normalisation) | Accesses admin endpoint |
| ..%2f..%2fadmin | Depends on browser URL normalisation | Encoding bypass |
| ....//admin | May bypass non-recursive sanitisation | Double-dot bypass |
| %2e%2e%2fadmin | Full URL encoding | Encoding bypass |
| ..%252f..%252fadmin | Double encoding | For apps that double-decode |

Use send_request to verify which URL the browser actually sends by checking
the network request path.

### Important: browser normalisation

Browsers normalise ../ in URL paths before sending the request. So
/api/users/../admin becomes /api/admin in the actual HTTP request. This
means path traversal in client-side URL construction DOES reach the intended
target -- the browser does the work for us.

### Verification

Use eval_page to intercept the fetch call and log the actual URL, then
trigger the action with the traversal payload and check the console.

## Step 4: CSPT-to-CSRF

If the traversed request hits a state-changing endpoint, this becomes CSRF.

### Conditions for CSPT-to-CSRF

1. The original request uses a method that can trigger state changes (POST, PUT,
   DELETE) OR the traversed endpoint accepts GET for state changes.
2. The request includes session cookies (SameSite=None or same-site context).
3. The request body is either absent, attacker-controllable, or a fixed body
   that still causes damage.

### Example

Original code constructs a PUT to /api/users/{userId}/preferences.
If userId is set to ../admin/delete-user?target=victim, the PUT request
hits /api/admin/delete-user?target=victim with the victim session cookies.

### Testing

1. Identify the state-changing endpoint reachable via traversal.
2. Confirm the request carries authentication (cookies).
3. Use send_request to simulate the traversed request and check if the action
   succeeds.

## Step 5: CSPT-to-XSS

If the traversed response is rendered as HTML or used in a dangerous DOM sink:

### Conditions

1. The fetch response is inserted into the DOM via unsafe sinks.
2. The traversed endpoint returns attacker-controllable content.
3. The content is not sanitised before insertion.

If pageId traverses to an endpoint that reflects user input (e.g. an error
page, a search results page), and that content is injected into the DOM,
XSS is achieved.

## Step 6: postMessage-based CSPT

### Actions

Use get_scripts to search for addEventListener('message') patterns.

### Testing

1. Find the postMessage handler and trace how event.data is used.
2. Check for origin validation.
3. If no origin check, craft a page that sends a malicious message with a
   traversal path in the endpoint field.

### Encoding bypass

If the application sanitises ../:
- Try URL encoding: %2e%2e%2f
- Try double encoding: %252e%252e%252f
- Try non-recursive strip bypass: ....//

## Severity reference

| Finding | Severity |
|---------|----------|
| CSPT-to-CSRF on destructive action (delete, payment) | High |
| CSPT-to-XSS via DOM injection | High |
| CSPT to admin/internal endpoints | High |
| CSPT-to-CSRF on settings change | Medium |
| CSPT to information disclosure | Medium |
| CSPT confirmed but no exploitable impact | Low |

## Known false positives

- The application uses a full URL (with scheme and host) rather than a relative
  path -- client-side traversal only works on relative URLs.
- The API endpoint validates the traversed path server-side and returns 404 -- the
  traversal exists in the client code but has no impact.
- The application uses a whitelist of valid path segments before constructing the
  URL -- traversal is blocked.
- The fetch response is parsed as JSON (not HTML) and rendered as text -- no XSS
  possible even with traversal.

## Tooling note

This methodology is designed for the Void panel tools (send_request,
compare_responses, search_responses, get_endpoints, eval_page, get_scripts,
add_pentest_finding). These are browser-extension APIs, not shell commands.
Do not attempt to run CLI tools.
