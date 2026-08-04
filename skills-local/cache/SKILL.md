---
name: "cache"
description: "Web Cache Poisoning and Cache Deception"
version: "1.0.0"
author: "void-extension"
tags: ["pentest", "cache", "poisoning", "deception", "cdn", "unkeyed", "web-cache"]
trigger_patterns:
  - "/cache"
  - "test cache poisoning"
  - "test cache deception"
  - "web cache"
  - "cache attack"
  - "unkeyed headers"
  - "cache key"
---

# Web Cache Poisoning and Cache Deception

Test for web cache poisoning (injecting malicious content into cached responses
via unkeyed inputs) and web cache deception (tricking the cache into storing
sensitive responses under attacker-accessible URLs).

## Scope and preconditions

Applies to any application behind a caching layer: CDN (Cloudflare, Akamai,
Fastly, CloudFront), reverse proxy (Varnish, nginx), or application-level cache.

Requires the ability to detect caching via response headers.

It does **not** cover: DNS cache poisoning, browser cache attacks, or HTTP
request smuggling (use `request-smuggling`).

## Rules of engagement

- ALWAYS use a unique cache-buster parameter (`?void_cb=<random>`) on every
  probe request to avoid poisoning real cached content.
- NEVER poison a production cache without the cache-buster. Only remove it for
  final confirmation on a path you control.
- Record every poisoned response with `add_pentest_finding`.
- In mode `ask`: confirm the cache stores your injected value and stop.

## Workflow

- [ ] 1. Detect and fingerprint the cache
- [ ] 2. Map the cache key
- [ ] 3. Find unkeyed inputs (headers, cookies, query params)
- [ ] 4. Test cache poisoning
- [ ] 5. Test cache deception
- [ ] 6. Verify and report

## Step 1: Detect the cache

Use `send_request` to fetch a page twice. Check response headers:

| Header | Meaning |
|--------|---------|
| `X-Cache: HIT` / `MISS` | Cache is active |
| `Age: 30` | Response was cached 30 seconds ago |
| `Cache-Control: max-age=300` | Cacheable for 5 minutes |
| `CF-Cache-Status: HIT` | Cloudflare cache |
| `X-Varnish: 123 456` | Varnish (two IDs = cache hit) |
| `Via: 1.1 varnish` | Varnish in chain |
| `X-Served-By` | CDN node identifier |
| `Vary: Accept-Encoding` | Cache varies by this header |

Use `compare_responses` between the first (MISS) and second (HIT) request. If
`Age` increases or `X-Cache` changes from MISS to HIT, caching is confirmed.

## Step 2: Map the cache key

The cache key determines which requests share a cached response. Typically:
`scheme + host + path + sorted query string`.

### Actions

1. Send a request with `?void_cb=1` — cache MISS.
2. Repeat with `?void_cb=1` — should be HIT (query is keyed).
3. Send with `?void_cb=2` — should be MISS (different key).
4. Send the same URL with a different `Accept-Language` header — HIT or MISS?
   If MISS, that header is keyed (check `Vary` header).
5. Send with a different `Cookie` header — HIT or MISS? Cookies are often
   excluded from the cache key even if they influence the response.

### What is NOT in the cache key = attack surface

Any input that changes the response but is NOT part of the cache key is an
unkeyed input. You can inject your value, cache it, and serve it to other users.

## Step 3: Find unkeyed inputs

### Unkeyed headers

Send requests with each header below (one at a time) and a cache-buster. Check
if the header value is reflected in the response:

| Header | Common reflection point |
|--------|----------------------|
| `X-Forwarded-Host: evil.com` | `<link>`, `<script src>`, `<meta>`, redirects |
| `X-Forwarded-Scheme: http` | Forces redirect or changes asset URLs |
| `X-Original-URL: /admin` | Path override (nginx/IIS) |
| `X-Rewrite-URL: /admin` | Path override |
| `X-Forwarded-Port: 1234` | Port reflected in URLs |
| `X-Host: evil.com` | Alternative to X-Forwarded-Host |
| `X-Forwarded-Prefix: /evil` | Prefix reflected in links |
| `Transfer-Encoding: chunked` | May cause differential parsing |

Use `compare_responses` between a request with and without each header. Any
header that changes the response body but does NOT change the cache key is
exploitable.

### Unkeyed query parameters

Some caches exclude specific parameters (UTM, analytics):
`?utm_source=<script>alert(1)</script>`

If the parameter is reflected in the response and not part of the cache key,
it's a poisoning vector.

### Parameter cloaking

When the cache and the application parse query strings differently:

```
GET /page?param=valid%26utm_content=<script>alert(1)</script>
```

The cache sees one parameter (keyed); the application decodes `%26` as `&` and
sees two parameters, reflecting the injected one.

Also try semicolon as separator:
```
GET /page?param=valid;injected=<script>alert(1)</script>
```

Ruby on Rails and some frameworks treat `;` as `&`.

## Step 4: Cache poisoning

### Attack flow

1. Find an unkeyed input that is reflected in the response.
2. Send the request WITH the malicious value and WITHOUT the cache-buster.
3. Repeat until the cache stores it (check `X-Cache: HIT`).
4. Verify by fetching the URL from a clean session — the poisoned value appears.

### Example: X-Forwarded-Host poisoning

```
GET /page HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com

Response:
<script src="https://evil.com/assets/app.js"></script>
```

If this response is cached, every subsequent visitor loads JavaScript from
`evil.com` — stored XSS via cache.

### Fat GET poisoning

Some frameworks process a body on GET requests:

```
GET /page HTTP/1.1
Content-Type: application/x-www-form-urlencoded

param=<script>alert(1)</script>
```

The body is not part of the cache key, but the application uses the body value
in the response.

## Step 5: Cache deception

Trick the cache into storing a response containing sensitive data under a URL
the attacker can access.

### Path confusion technique

If the cache decides cacheability by file extension:

```
GET /account/settings/nonexistent.css HTTP/1.1
```

- The application ignores `nonexistent.css` and serves `/account/settings` with
  the victim's data.
- The cache sees `.css` and caches the response.
- The attacker fetches `/account/settings/nonexistent.css` and gets the victim's
  account page.

### Variations

| Technique | URL |
|-----------|-----|
| Path append | `/account/settings/x.css` |
| Encoded separator | `/account/settings%2fx.css` |
| Semicolon | `/account/settings;x.css` |
| Dot segment | `/account/settings/..%2f..%2faccount/settings/x.css` |
| Null byte | `/account/settings%00.css` |

### Detection

1. Log in as victim, send the deception URL.
2. From a clean session (no cookies), fetch the same URL.
3. If you see the victim's data, cache deception works.

Use `compare_responses` between the authenticated and unauthenticated fetch.

## Severity reference

| Finding | Severity |
|---------|----------|
| Cache poisoning → stored XSS (JavaScript injection) | Critical |
| Cache poisoning → redirect to attacker (phishing) | High |
| Cache deception → sensitive data exposure (PII, tokens) | High |
| Cache poisoning → header injection (non-XSS) | Medium |
| Unkeyed input reflected but no exploitable gadget | Low |

## Known false positives

- `X-Cache: HIT` does not prove the response was poisoned — it only proves
  caching is active. You must show your injected content in the cached response.
- A reflected header value in a non-rendered context (JSON API, non-HTML) may
  not be exploitable for XSS. Assess the actual impact.
- Cache deception returning generic content (not user-specific) is not a finding.

## Tooling note

This methodology is designed for the Void panel tools (`send_request`,
`compare_responses`, `search_responses`, `get_endpoints`,
`add_pentest_finding`). These are browser-extension APIs, not shell commands.
Do not attempt to run CLI tools.
