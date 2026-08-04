---
name: "host-header"
description: "Host Header Attack Testing"
version: "1.0.0"
author: "void-extension"
tags: ["pentest", "host-header", "password-reset", "ssrf", "routing", "config"]
trigger_patterns:
  - "/host-header"
  - "test host header"
  - "host header injection"
  - "password reset poisoning"
  - "host header attack"
---

# Host Header Attack Testing Methodology

Test for host header injection leading to password-reset poisoning, SSRF via
routing, access-control bypass, and web cache poisoning. The Host header is
trusted by many frameworks for URL generation, routing, and access decisions.

## Scope and preconditions

Applies to any web application — especially those behind reverse proxies,
load balancers, or virtual hosting configurations where the Host header
influences routing or URL generation.

You need a valid account to test password-reset poisoning (you will receive
the poisoned email on your own account).

It does **not** cover: SSRF via user-supplied URLs (use `ssrf`), or cache
poisoning via other unkeyed headers (use `cache`).

## Rules of engagement

- ONLY test password-reset poisoning against your own test account. Confirm the
  poisoned link appears in the email you receive, then stop.
- NEVER use Host header manipulation to access internal services in production
  without explicit authorization.
- Record every request/response pair with `add_pentest_finding`.

## Workflow

- [ ] 1. Baseline — check how the Host header is used
- [ ] 2. Test Host header reflection
- [ ] 3. Test password-reset poisoning
- [ ] 4. Test SSRF via Host header
- [ ] 5. Test access-control bypass
- [ ] 6. Verify and report

## Step 1: Baseline

Use `send_request` to fetch a page normally. Note where the Host value appears
in the response:

- `<link>` or `<script>` tags (asset URLs)
- `<form action="...">` values
- Redirect `Location` headers
- `<meta>` tags (canonical URL, Open Graph)
- JSON API responses containing URLs

Use `search_responses` with pattern `https?://[^"'\s]+` to find all generated
URLs and check which include the Host value.

## Step 2: Test Host reflection

Send requests with modified Host headers. Use `compare_responses` between the
normal and modified response:

### Payloads

| Technique | Header |
|-----------|--------|
| Direct replacement | `Host: evil.com` |
| Port injection | `Host: target.com:evil.com` |
| Subdomain prefix | `Host: evil.target.com` |
| Absolute URL | `GET https://target.com/ HTTP/1.1` + `Host: evil.com` |
| X-Forwarded-Host | `Host: target.com` + `X-Forwarded-Host: evil.com` |
| X-Host | `Host: target.com` + `X-Host: evil.com` |
| X-Forwarded-Server | `Host: target.com` + `X-Forwarded-Server: evil.com` |
| Duplicate Host | Two `Host:` headers: `Host: target.com` and `Host: evil.com` |
| Host with port | `Host: target.com:@evil.com` |
| Wrapped Host | `Host: target.com\r\nX-Injected: evil.com` |
| Encoded dot | `Host: target%2ecom` |

For each, check if `evil.com` appears in the response body or headers.

## Step 3: Password-reset poisoning

The highest-impact Host header attack. If the application uses the Host header
to construct password-reset links, an attacker can make the victim click a link
pointing to the attacker's server, leaking the reset token.

### Actions

1. Use `send_request` to submit the password-reset form for YOUR test account:

```
POST /forgot-password HTTP/1.1
Host: evil.com
Content-Type: application/x-www-form-urlencoded

email=your-test@example.com
```

2. Check the email you receive. If the reset link points to `evil.com`:
   `https://evil.com/reset?token=abc123` — the application is vulnerable.

3. Also try the override headers:

```
POST /forgot-password HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com

email=your-test@example.com
```

4. Try double Host:

```
POST /forgot-password HTTP/1.1
Host: target.com
Host: evil.com

email=your-test@example.com
```

### Why this works

Frameworks like Django, Laravel, Express, and Spring use `request.getHost()` or
equivalent to build absolute URLs. Behind a reverse proxy, they may trust
`X-Forwarded-Host` without validation. The password-reset email template uses
this host to build the reset link.

## Step 4: SSRF via Host header

If the application or reverse proxy routes requests based on the Host header,
you can reach internal services.

### Actions

1. Send a request with an internal hostname:

```
GET / HTTP/1.1
Host: localhost
```

```
GET / HTTP/1.1
Host: 127.0.0.1
```

```
GET / HTTP/1.1
Host: internal-admin.target.com
```

2. Use `compare_responses` between the normal host and internal hosts. Different
   content (especially admin panels or internal APIs) confirms routing-based SSRF.

3. Try common internal hostnames:
   `localhost`, `127.0.0.1`, `admin`, `backend`, `api-internal`, `staging`,
   `intranet`, `monitoring`, `grafana`, `kibana`, `jenkins`

## Step 5: Access-control bypass

Some applications restrict access to admin pages by checking the Host header
or using virtual host routing.

### Actions

1. Access `/admin` normally — expect 403 or redirect.

2. Try overriding the URL path via headers:

```
GET / HTTP/1.1
Host: target.com
X-Original-URL: /admin
```

```
GET / HTTP/1.1
Host: target.com
X-Rewrite-URL: /admin
```

3. Try accessing admin on a different virtual host:

```
GET /admin HTTP/1.1
Host: localhost
```

If the admin panel loads, access control is based on the Host header and
bypassable.

## Severity reference

| Finding | Severity |
|---------|----------|
| Password-reset link points to attacker domain | Critical |
| SSRF to internal admin panel via Host | High |
| Access-control bypass via Host/X-Original-URL | High |
| Host reflected in links (cache poisoning possible) | High |
| Host reflected in non-actionable context | Medium |
| X-Forwarded-Host override without exploitable impact | Low |

## Known false positives

- The server returns a generic error or default page for an unknown Host — this
  is correct virtual host behavior, not a finding.
- The Host header is reflected in a `404` error page but not in any actionable
  URL — lower severity, only useful if combined with cache poisoning.
- Password-reset email uses a hardcoded domain regardless of Host — not
  vulnerable, even if the web response reflects Host.
- The reverse proxy strips X-Forwarded-Host before it reaches the application —
  test the actual email/response, not just the header injection.

## Tooling note

This methodology is designed for the Void panel tools (`send_request`,
`compare_responses`, `search_responses`, `get_endpoints`,
`add_pentest_finding`). These are browser-extension APIs, not shell commands.
Do not attempt to run CLI tools.
