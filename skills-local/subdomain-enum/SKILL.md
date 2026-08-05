# Subdomain Enumeration (Void-Native)

## Scope and preconditions

Applies to any engagement where the target scope includes wildcard domains
(`*.target.com`) or where discovering additional subdomains expands the attack
surface. This skill uses Void-native techniques — extracting subdomains from
captured HTTP traffic, JavaScript analysis, and targeted probing via the proxy.

It does **not** cover: active DNS brute force requiring CLI tools (subfinder,
amass), network scanning, or infrastructure reconnaissance beyond DNS/HTTP.

## Rules of engagement

- MUST stay within the authorized scope. If only `app.target.com` is in scope,
  discovering `admin.target.com` does not automatically mean it is in scope.
- MUST NOT perform active DNS brute force unless authorized.
- MUST document all discovered subdomains and their live status.
- Use passive techniques first, active probing second.

## Workflow

- [ ] 1. Extract subdomains from captured traffic
- [ ] 2. Analyze JavaScript for internal references
- [ ] 3. Check certificate transparency
- [ ] 4. Probe discovered subdomains
- [ ] 5. Test for subdomain takeover
- [ ] 6. Assess scope expansion impact
- [ ] 7. Record findings

## Step 1: Extract from captured traffic

### Goal
Find subdomains mentioned in HTTP responses you already have.

### Actions
Use `search_responses` with regex patterns:

**Absolute URLs in response bodies**:
```
https?://[a-zA-Z0-9.-]+\.target\.com
```

**Location headers (redirects)**:
Search for `Location:` headers containing `target.com` subdomains.

**Set-Cookie domain attributes**:
```
Set-Cookie: ....; domain=.target.com
```
Reveals the cookie's domain scope and implies expected subdomains.

**CSP headers** (rich source of subdomains):
```
Content-Security-Policy: connect-src https://api.target.com https://ws.target.com;
                         script-src https://cdn.target.com;
                         img-src https://images.target.com
```
Each CSP directive lists trusted origins — these are real subdomains.

**CORS headers**:
```
Access-Control-Allow-Origin: https://admin.target.com
```

**Link headers**:
```
Link: <https://preload.target.com/resource>; rel="preload"
```

**Email addresses**:
```
support@mail.target.com → mail.target.com
noreply@notifications.target.com → notifications.target.com
```

**API response data**:
JSON fields containing URLs, webhook configurations, integration endpoints.

## Step 2: Analyze JavaScript

### Goal
Extract subdomains from JavaScript bundles and configuration.

### Actions
Use `search_responses` filtered to JavaScript files:

**API endpoint references**:
```
fetch("https://api.target.com/v2/users")
axios.get("https://internal.target.com/graphql")
new WebSocket("wss://ws.target.com/events")
```

**Configuration objects**:
```javascript
const config = {
  apiUrl: "https://api.target.com",
  cdnUrl: "https://cdn.target.com",
  wsUrl: "wss://realtime.target.com",
  authUrl: "https://auth.target.com"
};
```

**Environment-specific URLs**:
```javascript
const envs = {
  production: "https://api.target.com",
  staging: "https://api-staging.target.com",
  dev: "https://api-dev.target.com"
};
```
Staging and dev subdomains are often less protected.

**Source map references**:
```
//# sourceMappingURL=https://maps.target.com/app.js.map
```

## Step 3: Certificate transparency

### Goal
Find historical subdomains from CT logs.

### Actions
Use `send_request` to query the crt.sh API through the proxy:
```
GET https://crt.sh/?q=%.target.com&output=json
```

This returns all certificates ever issued for `*.target.com`, revealing:
- Current subdomains with active certificates
- Historical subdomains (may still resolve)
- Wildcard certificates (indicates more subdomains exist)
- Internal subdomains that were accidentally included in public certs

### Deduplication
CT results contain duplicates. Filter unique subdomains from the response.

## Step 4: Probe discovered subdomains

### Goal
Determine which discovered subdomains are live and what they serve.

### Actions
For each discovered subdomain, use `send_request`:
```
GET https://subdomain.target.com/
```

Record:
- HTTP status code (200, 301, 403, 404, 500, connection refused)
- Server header
- Response size and title
- Interesting headers (`X-Powered-By`, `X-Backend-Server`)
- Whether it requires authentication

### Categorize results

| Category | Implication |
|---|---|
| Web application | Full testing target |
| API endpoint | Test with `api` skill |
| Admin panel | High-value target |
| Staging/dev | Often less hardened |
| Internal tool | May lack authentication |
| CDN/static assets | Lower priority |
| Non-responsive | May be takeover candidate |

## Step 5: Test for subdomain takeover

### Goal
Identify subdomains pointing to unclaimed cloud services.

### Technique
A subdomain has a CNAME pointing to a cloud service (S3, Azure, Heroku, etc.)
but the service is not claimed. An attacker can claim the service and control
the subdomain's content.

### Detection fingerprints

| Service | Error message / Pattern |
|---|---|
| AWS S3 | "NoSuchBucket", "The specified bucket does not exist" |
| Azure | "404 Web Site not found" |
| GitHub Pages | "There isn't a GitHub Pages site here" |
| Heroku | "No such app", "herokucdn.com/error-pages/no-such-app.html" |
| Shopify | "Sorry, this shop is currently unavailable" |
| Tumblr | "There's nothing here" |
| WordPress.com | "Do you want to register" |
| Ghost | "The thing you were looking for is no longer here" |
| Fastly | "Fastly error: unknown domain" |
| Pantheon | "404 error unknown site" |
| Cargo Collective | "404 Not Found" |
| Fly.io | "404 Not Found" (with Fly.io header) |

Use `send_request` to each non-responsive subdomain. If the response matches
a takeover fingerprint, the subdomain is vulnerable.

### Impact of subdomain takeover

| Combined with | Result |
|---|---|
| Cookie domain scope (`.target.com`) | Session hijacking |
| OAuth redirect_uri wildcard | Token theft |
| CSP trusted source | XSS via trusted subdomain |
| CORS trusted origin (regex) | Cross-origin data theft |
| Email MX record | Email spoofing |

## Step 6: Scope expansion assessment

### Goal
Determine which discovered subdomains expand the attack surface meaningfully.

### High-value patterns
- `admin.`, `internal.`, `vpn.`, `staging.`, `dev.`, `test.` — often less hardened
- `api.`, `api-v1.`, `api-staging.` — API endpoints may lack web app protections
- `jenkins.`, `ci.`, `build.`, `deploy.` — CI/CD infrastructure
- `grafana.`, `kibana.`, `prometheus.` — monitoring (may expose internal data)
- `mail.`, `smtp.`, `mx.` — email infrastructure
- Numbered hosts (`web01.`, `app02.`) — indicate infrastructure scale

## Step 7: Record findings

Use `add_pentest_finding` with:
- The list of discovered subdomains and their status
- Any subdomain takeover vulnerabilities with proof
- Scope expansion recommendations
- Screenshots or response captures from interesting subdomains

## Known false positives

- CNAME pointing to a service that returns a generic error but is actually
  claimed — verify by attempting to register/claim the service.
- Subdomains that resolve but return connection refused — may be internal only,
  not a takeover candidate.
- CT log entries for expired certificates — the subdomain may no longer resolve.
- CDN subdomains that show default pages — these are often shared infrastructure,
  not target-specific.

## Reminder

Subdomain enumeration in Void is passive-first: extract from traffic you already
have, analyze JavaScript, check CT logs. The highest-value discovery is a
**subdomain takeover** — it provides content control on a trusted subdomain,
which chains into session hijacking, XSS via CSP trust, and OAuth token theft.
Always combine subdomain discovery with scope validation — finding it does not
mean testing it is authorized.
