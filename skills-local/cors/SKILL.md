# CORS Misconfiguration Testing

## Scope and preconditions

Applies to any API or web application that returns `Access-Control-Allow-Origin`
headers. CORS misconfigurations allow malicious websites to read cross-origin
responses, bypassing the Same-Origin Policy. This is especially dangerous for
APIs that return sensitive data (user profiles, tokens, financial data).

It does **not** cover: CSRF (which writes data cross-origin, use `csrf`),
clickjacking (use `clickjacking`), or XSS on the target domain.

## Rules of engagement

- MUST test with your own origin domains only.
- NEVER host a PoC page that targets real users. Use only your test accounts.
- MUST capture both the request with the attacker Origin and the response with
  the reflected ACAO header as evidence.

## Workflow

- [ ] 1. Identify endpoints returning CORS headers
- [ ] 2. Test origin reflection
- [ ] 3. Test regex bypass patterns
- [ ] 4. Test null origin
- [ ] 5. Test subdomain trust
- [ ] 6. Test Vary header and cache interaction
- [ ] 7. Assess impact and record

## Step 1: Identify CORS endpoints

### Goal
Find endpoints that return `Access-Control-Allow-Origin`.

### Actions
Use `search_responses` to find responses containing `Access-Control-Allow-Origin`.
Note which endpoints return it and what value they set.

## Step 2: Test origin reflection

### Goal
Determine if the server reflects arbitrary origins.

### Actions
Send requests with different Origin headers using `send_request`:

```
Origin: https://evil.com
Origin: https://attacker.com
Origin: null
```

Check if `Access-Control-Allow-Origin` reflects your origin AND
`Access-Control-Allow-Credentials: true` is present.

**Why credentials matter**: `ACAO: *` without credentials is low risk — the
browser blocks cookies, so responses contain only public data. `ACAO: evil.com`
WITH `Credentials: true` is the real vulnerability — cookies are sent, response
contains user-specific data, and the attacker can read it.

## Step 3: Test regex bypass patterns

### Goal
Bypass origin validation implemented with flawed regex.

### Regex flaw classification

| Flaw | Regex example | Bypass origin |
|---|---|---|
| Missing end-anchor | `/^https:\/\/trusted\.com/` | `https://trusted.com.evil.com` |
| Missing dot escape | `/trusted.com$/` | `https://trustedXcom.evil.com` (X = any char) |
| Prefix-only check | `startsWith('https://trusted.com')` | `https://trusted.com.evil.com` |
| Contains check | `origin.includes('trusted.com')` | `https://evil-trusted.com` |
| Missing separator | `/trusted\.com$/` | `https://notatrusted.com` |
| Incomplete scheme | `endsWith('.trusted.com')` | `http://evil.trusted.com` (HTTP downgrade) |

Test each pattern with `send_request` using the bypass origin.
Use `run_intruder_attack` to test all variants simultaneously.

## Step 4: Test null origin

### Goal
Test if `Origin: null` is whitelisted.

### Technique
Many developers add `null` to the allowlist for local development and forget
to remove it. Send:
```
Origin: null
```

The browser sends `Origin: null` from:
- Sandboxed iframes: `<iframe sandbox="allow-scripts">`
- `data:` URLs
- `file://` origins
- Redirected cross-origin requests

PoC: host an HTML page that creates a sandboxed iframe pointing to the target.
The iframe's requests have `Origin: null`.

## Step 5: Test subdomain trust

### Goal
Determine if wildcard subdomain trust is exploitable.

### Technique
If the server trusts `*.trusted.com`:
```
Origin: https://any-subdomain.trusted.com
```

This is only exploitable if you can run JavaScript on any subdomain (via XSS,
subdomain takeover, or user-generated content). But the CORS misconfiguration
is still a finding — it means XSS on any subdomain escalates to reading data
from the main API.

## Step 6: Test Vary and cache interaction

### Goal
Determine if CORS responses are cached without `Vary: Origin`.

### Technique
If the response has CORS headers but no `Vary: Origin`:
1. Request the endpoint from `Origin: https://trusted.com` — response cached
   with `ACAO: trusted.com`.
2. Request from `Origin: https://evil.com` — cache serves the previous response.
3. The evil origin now has a valid ACAO header from the cache.

This is **CORS + cache poisoning** — the impact is broader because the cached
response affects all users.

Check for `Vary: Origin` in the response. If absent and the response is cached
(check `Cache-Control`, `Age`, `X-Cache` headers), this is a finding.

## Step 7: Assess impact and record

### Impact matrix

| Configuration | Credentials | Impact |
|---|---|---|
| `ACAO: *` | No credentials | Low — public data only |
| `ACAO: *` | `Credentials: true` | Invalid — browser rejects (but report the config) |
| `ACAO: attacker.com` | `Credentials: true` | **Critical** — full read of user data |
| `ACAO: null` | `Credentials: true` | **High** — exploitable via sandbox iframe |
| `ACAO: *.trusted.com` | `Credentials: true` | **Medium-High** — requires XSS on subdomain |
| No Vary: Origin | Cached | **Medium** — CORS + cache poisoning |

Use `add_pentest_finding` with:
- The Origin header you sent
- The ACAO and ACAC headers in the response
- What sensitive data the endpoint returns with credentials
- PoC: HTML page that reads the response cross-origin

## Known false positives

- `ACAO: *` without credentials on a public API — this is correct behavior
  for public data. Not a vulnerability.
- Origin reflected but `Credentials: false` or absent — attacker can read the
  response but it contains only public data (no cookies sent).
- Preflight (OPTIONS) reflects origin but actual request does not — test the
  actual request method (GET/POST), not just OPTIONS.
- Internal API that reflects origin but is not reachable from the internet — the
  CORS config is wrong but not exploitable externally.

## Reminder

CORS severity depends on one thing: can the attacker read **authenticated,
user-specific data** cross-origin? The answer requires BOTH `ACAO: attacker.com`
AND `Credentials: true`. Without credentials, the response is public data and
the finding is informational. Always test the actual response content with
credentials to prove the impact.
