---
name: "api"
description: "API Security Testing - OWASP API Top 10 (2023)"
version: "1.0.0"
author: "void-extension"
tags: ["pentest", "api", "owasp", "rest", "graphql", "authorization"]
trigger_patterns:
  - "/api"
  - "test api security"
  - "owasp api top 10"
  - "api pentest"
  - "rest api testing"
---

# API Security Testing

Systematic methodology covering the OWASP API Security Top 10 (2023). Applies to
REST, GraphQL, gRPC-web, and any HTTP-based service that exposes structured data.
Each section maps to one API Top 10 category and gives concrete steps you can
execute with Void's tooling.

This skill does **not** cover: browser-rendered XSS in API responses (use `xss`),
file upload through an API endpoint (use `file-upload`), or OAuth/OIDC flow
testing beyond token handling (use `jwt`).

## Rules of engagement

- MUST have written authorization before testing any API.
- MUST use only accounts and tokens provided for the engagement. Do not register
  new accounts unless the scope explicitly allows it.
- NEVER attempt credential stuffing against production authentication endpoints.
  Demonstrate the finding with 3-5 attempts, then stop.
- NEVER exfiltrate real user data. When BOLA or data exposure is confirmed, quote
  the minimum fields needed to prove the issue and redact the rest.
- MUST record every finding with the exact request, the exact response, and the
  authorization context (which user/role sent it). A finding without these three
  pieces is not reproducible.

## Workflow

- [ ] 1. Reconnaissance: map endpoints, methods, and authentication scheme
- [ ] 2. API1 - BOLA: horizontal privilege escalation via object IDs
- [ ] 3. API2 - Broken Authentication: token and credential issues
- [ ] 4. API3 - Broken Object Property Level Authorization: mass assignment and excessive data
- [ ] 5. API4 - Unrestricted Resource Consumption: rate limits and pagination
- [ ] 6. API5 - BFLA: vertical privilege escalation via function-level access
- [ ] 7. API6 - Unrestricted Access to Sensitive Business Flows
- [ ] 8. API7 - SSRF: server-side request forgery through API parameters
- [ ] 9. API8 - Security Misconfiguration: CORS, headers, methods, errors
- [ ] 10. API9 - Improper Inventory Management: old versions and shadow APIs
- [ ] 11. API10 - Unsafe Consumption of APIs
- [ ] 12. GraphQL-specific checks
- [ ] 13. Verification and evidence collection

---

## Step 1: API Reconnaissance

### Goal
Build a complete map of the API surface before testing anything.

### Actions

Use `get_endpoints` to pull every endpoint the proxy has seen. Supplement with
these probes:

**Discover documentation endpoints** by sending each of these with `send_request`:
```
GET /swagger.json
GET /swagger/v1/swagger.json
GET /openapi.json
GET /api-docs
GET /v2/api-docs
GET /docs
GET /redoc
GET /.well-known/openapi
GET /graphql  (body: {"query":"{__schema{types{name}}}"})
```
A 200 with JSON or HTML confirms the doc is live.

**Identify authentication scheme:**

| Header / Pattern | Scheme |
|---|---|
| `Authorization: Bearer <jwt>` | JWT / OAuth 2.0 |
| `Authorization: Basic <b64>` | Basic Auth |
| `X-API-Key: <key>` | API key |
| `Cookie: session=<value>` | Session cookie |
| Custom header (`X-Auth-Token`, `X-Access-Token`) | Proprietary |

**Enumerate HTTP methods on every endpoint.** For each path, send OPTIONS then
GET, POST, PUT, PATCH, DELETE, HEAD, TRACE with `send_request`. Record which
return 200/201/204 vs 405/403/401. A method that returns data when it should
return 405 is a finding on its own.

### Stop condition
You can list every endpoint, its accepted methods, its authentication requirement,
and the ID format it uses (integer, UUID, slug, composite).

---

## Step 2: API1 - Broken Object Level Authorization (BOLA)

### What it is
The API uses an object identifier supplied by the client (path parameter, query
parameter, or request body field) and does not verify the caller owns that object.
This is horizontal privilege escalation.

### ID manipulation patterns

**Sequential integers:**
```
GET /api/v1/users/1001         <- your user
GET /api/v1/users/1002         <- another user
GET /api/v1/orders/7780
GET /api/v1/orders/7781
```

**UUIDs (still testable if leaked):**
```
GET /api/v1/invoices/550e8400-e29b-41d4-a716-446655440000   <- yours
GET /api/v1/invoices/550e8400-e29b-41d4-a716-446655440001   <- guess
```
UUIDs are not authorization. If the API leaks them in list endpoints, pagination
responses, or error messages, they are predictable enough.

**Encoded or composite IDs:**
```
GET /api/v1/documents/dXNlcjoxMDAx          <- base64("user:1001")
GET /api/v1/documents/dXNlcjoxMDAy          <- base64("user:1002")
```
Use `decode` to inspect, `encode` to forge.

**GraphQL BOLA:**
```graphql
query {
  user(id: "OTHER_USER_ID") {
    id email orders { id total }
  }
}
```

### Testing procedure

1. As User A, access your own object. Record the ID.
2. As User B, replay the request with User A's ID but User B's token.
3. `compare_responses` to diff. If User B gets User A's data, BOLA is confirmed.
4. Test PUT/PATCH/DELETE too -- read access is bad, write access is worse.

Use `search_responses` to find all responses containing your user ID, then
systematically replace with another ID and replay. Record both tokens, the
object ID, and the cross-user response. `add_pentest_finding` as HIGH/CRITICAL.

---

## Step 3: API2 - Broken Authentication

### What it is
Weak, missing, or bypassable authentication on API endpoints.

### Checks

**No authentication required:**
```
GET /api/v1/users/me
```
Send without any Authorization header. If it returns data, the endpoint is
unprotected.

**JWT issues:**

Decode the token with `decode` (base64).

| Attack | Payload |
|---|---|
| Algorithm none | Header: `{"alg":"none","typ":"JWT"}`, remove signature |
| Algorithm confusion (RS256 to HS256) | Re-sign with public key as HMAC secret |
| Weak secret | Try: `secret`, `password`, `123456`, `changeme`, the app name |
| Expired token accepted | Set `exp` to a past timestamp, re-encode, send |
| Missing audience/issuer validation | Change `aud` or `iss` claim, re-sign |
| `kid` injection | `"kid": "../../dev/null"` or `"kid": "key' UNION SELECT 'secret'--"` |
| `jku`/`x5u` header injection | Point to attacker-controlled JWKS |

**Token in URL:**
```
GET /api/v1/data?token=eyJhbGci...
```
Tokens in URLs leak via Referer headers, server logs, and browser history. Flag
as a finding.

**Credential stuffing signal:** Send 5 wrong-password login attempts. If no
lockout or CAPTCHA appears, report absent rate limiting.

**Password reset token reuse:** Use a reset token, then replay it. If it works
twice, the token is not invalidated after use.

---

## Step 4: API3 - Broken Object Property Level Authorization

### What it is
Two sub-problems: (a) the API returns properties the caller should not see
(excessive data exposure), and (b) the API accepts properties the caller should
not set (mass assignment).

### Excessive data exposure

GET a resource and inspect every field. Look for fields not shown in the UI:
`password_hash`, `ssn`, `internal_notes`, `is_admin`, `credit_card`, `api_key`.
Use `search_responses` to scan all captured responses for patterns like
`password`, `hash`, `ssn`, `secret`, `token`, `internal`, `admin`.

### Mass assignment

Take a legitimate PUT/PATCH request and add fields the client should not control:
`role`, `is_admin`, `permissions`, `balance`, `credits`, `verified`,
`email_verified`, `discount_rate`, `password`, `org_id`, `tenant_id`.

```
PUT /api/v1/users/me
{"name": "Alice", "role": "admin", "is_admin": true, "balance": 999999}
```

GET the resource afterwards and use `compare_responses` to check whether any
injected field was accepted. For GraphQL, add extra fields to mutation inputs.

---

## Step 5: API4 - Unrestricted Resource Consumption

### What it is
The API does not enforce limits on request rate, response size, pagination depth,
or computational cost.

### Rate limiting

Send 50 rapid login attempts with `send_request`. If all return the same error
with no 429, no CAPTCHA, and no lockout, rate limiting is absent. Check whether
`X-RateLimit-Limit`/`X-RateLimit-Remaining`/`Retry-After` headers exist and
whether they are actually enforced.

### Pagination abuse

```
GET /api/v1/users?page=1&per_page=10       <- normal
GET /api/v1/users?page=1&per_page=100000   <- abuse
GET /api/v1/users?limit=-1                  <- unlimited
GET /api/v1/users?limit=0                   <- sometimes means unlimited
```

If the API returns all records with a large `per_page`, it has no server-side cap.

### Computational cost

Force expensive operations: `GET /api/v1/reports?start=2000-01-01&end=2030-12-31`.
For GraphQL, send deeply nested queries (`{ users { friends { friends { friends
{ name } } } } }`). If processed without error, depth/cost limits are absent.

---

## Step 6: API5 - Broken Function Level Authorization (BFLA)

### What it is
A regular user can call administrative endpoints. This is vertical privilege
escalation.

### Testing procedure

1. Identify admin-only endpoints from documentation, naming conventions, or
   by observing admin traffic.
2. Call them with a regular user's token.

**Endpoint patterns to probe** (replace with actual paths from recon):
```
/api/v1/admin/users          /api/v1/admin/settings
/api/v1/admin/logs           /api/v1/internal/metrics
/api/v1/users/1001/ban       /api/v1/users/1001/promote
```

**Method-based BFLA:** A user who can GET their own profile should not be able to
DELETE it. Try every HTTP method on user-accessible endpoints.

**Parameter-based BFLA:** Add `?role=admin`, `?all=true`, or `?export=true` to
scoped list endpoints and check whether the server returns unscoped data.

**GraphQL BFLA:** Call admin mutations (`deleteUser`, `updateSystemConfig`) and
admin queries (`adminDashboard`) with a regular user's token.

### Evidence
Show: the regular user's token, the admin endpoint called, and the successful
response. Use `add_pentest_finding` with severity CRITICAL.

---

## Step 7: API6 - Unrestricted Access to Sensitive Business Flows

### What it is
The API lets automated tools abuse business-critical flows that were designed
for human interaction: bulk purchasing, mass account creation, review/rating
manipulation, reservation squatting.

### Checks

Look for flows with no CAPTCHA, proof-of-work, or device fingerprinting:
account registration, coupon redemption, ticket booking, review submission,
money transfers. Replay the request 3-5 times with `send_request`. If every
attempt succeeds, the flow is automatable.

Test promo/referral abuse: send the same coupon code 5 times or self-refer.
Severity depends on business impact -- scalping bots are HIGH, duplicate
comments are LOW. State the risk explicitly.

---

## Step 8: API7 - Server-Side Request Forgery (SSRF)

### What it is
The API accepts a URL or hostname from the client and makes a server-side request
to it without proper validation.

### Where to look

Any parameter named: `url`, `uri`, `link`, `href`, `callback`, `redirect`,
`webhook`, `feed`, `source`, `image_url`, `avatar_url`, `import_url`, `proxy`.

### Key payloads

```
http://169.254.169.254/latest/meta-data/iam/security-credentials/   <- AWS
http://metadata.google.internal/computeMetadata/v1/                 <- GCP
http://169.254.169.254/metadata/instance?api-version=2021-02-01     <- Azure
http://127.0.0.1:8080                                               <- loopback
http://[::1]:8080                                                   <- IPv6 loopback
http://0x7f000001/                                                  <- hex bypass
http://2130706433/                                                  <- decimal bypass
file:///etc/passwd                                                  <- file read
```

For a complete list of IP obfuscation, protocol smuggling, and blind detection
techniques, use the dedicated `ssrf` skill. The API-specific concern is that URL
parameters in REST/GraphQL inputs are high-value SSRF vectors because they bypass
WAF rules that only inspect browser-initiated traffic.

---

## Step 9: API8 - Security Misconfiguration

### CORS

Send a request with an `Origin` header from an attacker domain:

```
GET /api/v1/users/me
Origin: https://evil.com
```

Check response headers:

| Response Header | Vulnerable If |
|---|---|
| `Access-Control-Allow-Origin: https://evil.com` | Reflects arbitrary origin |
| `Access-Control-Allow-Origin: *` | Wildcard with credentials |
| `Access-Control-Allow-Credentials: true` | Combined with reflected origin |
| `Access-Control-Allow-Origin: null` | Allows sandboxed iframe attacks |

**Origin variations to test:**
```
Origin: https://evil.com
Origin: https://api.target.com.evil.com
Origin: https://target.com.evil.com
Origin: null
Origin: https://subdomain.target.com
```

### Verbose error messages

Send malformed input (`GET /api/v1/users/notanumber`, POST with wrong types like
`{"password": []}`). If errors include stack traces, SQL queries, file paths, or
internal hostnames, it is information disclosure.

### Unnecessary HTTP methods

TRACE is the classic:
```
TRACE /api/v1/users
```
If the server echoes the full request including cookies and auth headers, that is
Cross-Site Tracing (XST).

### Missing security headers

Check for:
- `Strict-Transport-Security` (HSTS)
- `X-Content-Type-Options: nosniff`
- `Cache-Control: no-store` on sensitive responses
- `X-Frame-Options` or CSP `frame-ancestors`

### Debug endpoints

Probe `/debug`, `/health`, `/metrics`, `/env`, `/config`, `/actuator`,
`/actuator/env`, `/_debug`, `/elmah.axd`. If any return internal config,
dependency versions, or environment variables, report as MEDIUM-HIGH.

---

## Step 10: API9 - Improper Inventory Management

### What it is
Old API versions remain accessible and lack the security fixes applied to newer
versions. Shadow or undocumented APIs exist without monitoring.

### Version enumeration

Try path-based (`/api/v1/`, `/api/v2/`, `/v1/`, `/v2/`) and header-based
versioning (`Accept: application/vnd.api+json;version=1` or
`X-API-Version: 1`) with `send_request`.

### Checks on old versions

For each old version that responds:
1. Does it enforce the same authentication?
2. Does it enforce the same authorization (BOLA/BFLA)?
3. Does it have the same rate limiting?
4. Does it return the same fields (or does it over-expose)?

Use `compare_responses` between `/api/v1/users/me` and `/api/v2/users/me` to
diff the response bodies.

### Shadow API discovery

Check for undocumented paths using `get_endpoints` and comparing against
the official documentation. Endpoints present in traffic but absent from
docs are shadow APIs.

Common shadow prefixes: `/api/internal/`, `/api/private/`, `/api/legacy/`,
`/api/beta/`, `/api/test/`, `/api/staging/`, and `/graphql` when only REST is
documented.

### Host-based variants

Try the same API path with `Host: api-staging.target.com` or
`Host: api-internal.target.com`. Staging and internal hosts often have weaker
controls.

---

## Step 11: API10 - Unsafe Consumption of APIs

### What it is
The API trusts data received from third-party APIs or integrations without
validation, enabling injection or SSRF through the upstream data.

### Where to look
Webhook receivers, import features (CSV/API sync), OAuth/SSO callbacks,
payment gateway IPNs.

### Testing approach

Send a webhook payload with injection in every field:
```json
{"event":"payment.completed","customer_name":"<script>alert(1)</script>",
 "amount":"1; DROP TABLE orders;--",
 "callback_url":"http://169.254.169.254/latest/meta-data/"}
```

Check whether values appear unescaped in the UI, trigger SQL errors, or cause
SSRF. This is typically HIGH because it bypasses validation on direct user input.

---

## Step 12: GraphQL-Specific Checks

These supplement the REST checks above. If the target exposes GraphQL, run
all of these.

### Introspection

Send `{__schema{queryType{name} mutationType{name} types{name fields{name
type{name kind ofType{name}}}}}}`. If it returns the full schema, extract every
type, field, and mutation. MEDIUM on its own but enables all subsequent attacks.

### Batching for brute force

**Alias batching** (single query, multiple operations):
```graphql
{ a: login(u:"admin",p:"pass1"){token} b: login(u:"admin",p:"pass2"){token} }
```

**Array batching** (multiple queries in one HTTP request):
```json
[{"query":"mutation{login(u:\"admin\",p:\"pass1\"){token}}"},
 {"query":"mutation{login(u:\"admin\",p:\"pass2\"){token}}"}]
```

Both bypass per-request rate limits. If the server processes all operations,
batching abuse is confirmed.

### Depth attacks

```graphql
{ users { friends { friends { friends { friends { friends { name } } } } } } }
```

If processed without error, there is no query depth limit.

### Field suggestion leak

Send `{"query": "{ usr { name } }"}`. If the error says `Did you mean 'user'?`,
field names leak even when introspection is disabled.

### CSRF via GET

`GET /graphql?query=mutation{deleteAccount{success}}` -- if mutations are
accepted via GET, a simple `<img>` tag achieves CSRF.

---

## Step 13: Verification and Evidence Collection

### Before reporting any finding

1. **Reproduce it twice** from a clean state (new session, no cached tokens).
2. **Confirm the authorization context**: state exactly which user/role was
   used and which user/role should have been required.
3. **Capture the full request and response** with `send_request`. Include
   headers, especially Authorization.
4. **Diff against the legitimate case** with `compare_responses` so the
   reader can see exactly what changed.

### Severity guide

| Finding | Severity |
|---|---|
| BOLA on PII / BFLA admin access / mass assignment to roles / SSRF to metadata | CRITICAL |
| BOLA non-sensitive / excessive PII / no rate limit on auth / CORS with creds / old API weaker auth / batching bypass / blind SSRF | HIGH |
| Mass assignment non-security / excessive metadata / GraphQL introspection / verbose errors | MEDIUM |
| Missing headers / no rate limit on non-auth | LOW |

### Recording

Use `add_pentest_finding` for every confirmed vulnerability. Include:
- The OWASP API category (API1 through API10)
- The CWE number
- The exact request (method, path, headers, body)
- The exact response (status, relevant body excerpt)
- The authorization context
- Remediation guidance

## CWE mapping

| API Category | Primary CWE |
|---|---|
| API1 - BOLA | CWE-284, CWE-639 |
| API2 - Broken Authentication | CWE-287, CWE-798 |
| API3 - Broken Object Property Authorization | CWE-213, CWE-915 |
| API4 - Unrestricted Resource Consumption | CWE-770, CWE-799 |
| API5 - BFLA | CWE-285 |
| API6 - Sensitive Business Flows | CWE-840 |
| API7 - SSRF | CWE-918 |
| API8 - Security Misconfiguration | CWE-16, CWE-942 |
| API9 - Improper Inventory Management | CWE-1059 |
| API10 - Unsafe Consumption | CWE-20 |

## Known false positives

- A 403 on an admin endpoint is not BFLA -- the server correctly denied access.
- CORS `Access-Control-Allow-Origin: *` without `Allow-Credentials: true` is
  low severity; browsers block credentialed requests with wildcard origin.
- Old API versions returning identical data are not findings unless security
  controls differ.
- Rate limit headers existing does not mean they are enforced. Always exceed them.
- A GraphQL error for a field does not confirm it exists; compare error format
  against a field you do have access to.

## Reminder

API security testing is about authorization and business logic, not just
injection. The most impactful findings are usually BOLA and BFLA -- they give
one user access to another user's data or to admin functions. Start there,
use `get_endpoints` to map the full surface, and test every endpoint with
every role. Record findings with `add_pentest_finding` as you go.

## Tooling note

This methodology is designed for the Void panel tools. Use `send_request` for
HTTP probes, `compare_responses` for baseline diffing, `search_responses` to
find patterns across captured traffic, `get_endpoints` to map the API surface,
`decode`/`encode` for token analysis, and `add_pentest_finding` to record
confirmed results. There is no shell and no filesystem — do not attempt to
run scripts.
