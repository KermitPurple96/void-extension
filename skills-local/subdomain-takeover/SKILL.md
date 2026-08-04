---
name: "subdomain-takeover"
description: "Subdomain Takeover — dangling CNAME detection, service fingerprints (S3, Azure, Heroku, GitHub Pages), verification and PoC methodology"
version: "1.0.0"
author: "void-extension"
tags: ["pentest", "recon", "subdomain-takeover", "cname", "dns", "s3", "azure", "heroku", "github-pages", "wstg-conf-10"]
trigger_patterns:
  - "/subdomain-takeover"
  - "subdomain takeover"
  - "dangling cname"
  - "cname takeover"
  - "unclaimed subdomain"
  - "s3 bucket takeover"
  - "github pages takeover"
---

# Subdomain Takeover

Subdomain takeover occurs when a DNS CNAME record for `sub.example.com` points
to an external service (S3 bucket, Azure App Service, Heroku, GitHub Pages,
etc.) that is no longer provisioned. An attacker who registers the unclaimed
resource on that service can then serve arbitrary content — including malicious
JavaScript, phishing pages, or cookie-stealing payloads — under the
`sub.example.com` domain, which inherits the trust of the parent.

Reference: WSTG-CONF-10. Commonly reported as High on HackerOne.

## Scope and preconditions

Requires DNS enumeration results from `subdomain-enum`. This skill begins where
that skill ends: you have a list of subdomains and need to identify which ones
have dangling CNAMEs. Requires internet access to verify NXDOMAIN or service
fingerprints.

## Rules of engagement

- **Do not actually claim the resource** without explicit written authorisation
  to do so. The finding is demonstrated by confirming NXDOMAIN resolution and
  matching the service fingerprint — that is sufficient for a valid bug report.
- If the client explicitly authorises a full PoC (claiming the resource), stop
  immediately after the screenshot and release the resource.
- Record all findings with `add_pentest_finding`.

## Workflow

- [ ] 1. Enumerate subdomains (input from subdomain-enum)
- [ ] 2. Identify dangling CNAMEs
- [ ] 3. Fingerprint the service
- [ ] 4. Verify the resource is claimable
- [ ] 5. Build PoC (authorised scope only)
- [ ] 6. Report

## Step 1: Identify dangling CNAMEs

For every subdomain in scope, use `send_request` to probe it. A dangling CNAME
has one of these response signatures:

| HTTP Status | Body pattern | Likely service |
|-------------|-------------|----------------|
| 404 | `NoSuchBucket` | AWS S3 |
| 404 | `The specified bucket does not exist` | AWS S3 |
| 404 | `404 Web Site not found` | Azure App Service / Azure CDN |
| 404 | `There isn't a GitHub Pages site here.` | GitHub Pages |
| 404 | `No such app` | Heroku |
| 404 | `Fastly error: unknown domain` | Fastly CDN |
| 404 | `404 Not Found` + `Pantheon` header | Pantheon |
| 404 | `Sorry, we couldn't find that page` | Zendesk |
| 404 | `Help Center Closed` | Zendesk |
| 404 | `This UserVoice subdomain is currently available` | UserVoice |
| 404 | `project not found` | GitLab Pages |
| 530 | `error code: 1001` | Cloudflare (unrouted) |
| NXDOMAIN | DNS resolution fails entirely | Unclaimed base service |

Use `search_responses` to scan all subdomains in captured traffic for these
body patterns. Also check `get_response_headers` for service-identifying headers
(`X-GitHub-Request-Id`, `X-Served-By: Heroku`, `X-MS-ServerSideWarning`).

## Step 2: Service-specific fingerprints

### AWS S3

**CNAME pattern**: `sub.example.com` → `sub.example.com.s3.amazonaws.com`

S3 bucket names match the subdomain. If the bucket does not exist:
```
HTTP/1.1 404 Not Found
<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message>
<BucketName>sub.example.com</BucketName></Error>
```

**PoC path**: Create an S3 bucket named `sub.example.com` in any AWS account,
enable static website hosting, and upload a proof file. The subdomain will
serve it.

### Azure App Service / Blob Storage

**CNAME patterns**: `→ *.azurewebsites.net`, `→ *.blob.core.windows.net`,
`→ *.trafficmanager.net`, `→ *.cloudapp.azure.com`

Fingerprint:
```
HTTP/1.1 404 Not Found
404 Web Site not found
```

Or for Traffic Manager:
```
HTTP/1.1 404 Not Found
```
With header: `X-MS-ServerSideWarning: ...`

**PoC path**: Create an Azure App Service or Storage Account with the matching
hostname and deploy a static page.

### GitHub Pages

**CNAME pattern**: `sub.example.com` → `<org>.github.io`

Fingerprint:
```
HTTP/1.1 404 Not Found
There isn't a GitHub Pages site here.
```

**PoC path**: Create a GitHub repository `<org>/<repo>`, add a CNAME file
containing `sub.example.com`, enable Pages. The repo must be public.

**Impact**: GitHub Pages serves the `sub.example.com` cookies (set by parent
JavaScript) — this can be an XSS escalation point if the parent sets cookies
without `HttpOnly`.

### Heroku

**CNAME pattern**: `sub.example.com` → `<random>.herokudns.com`

Fingerprint:
```
HTTP/1.1 404 Not Found
No such app
```

With header: `Via: 1.1 vegur`

**PoC path**: Create a Heroku app, add a custom domain `sub.example.com` via
`heroku domains:add sub.example.com`.

### Shopify

**CNAME pattern**: `→ shops.myshopify.com`

Fingerprint:
```
Sorry, this shop is currently unavailable.
```

**PoC path**: Create a Shopify store, add the custom domain in the Shopify admin.

### Fastly

**CNAME pattern**: `→ nonssl.global.fastly.net` or `→ ssl.global.fastly.net`

Fingerprint:
```
Fastly error: unknown domain: sub.example.com.
```

**PoC path**: Create a Fastly service, add `sub.example.com` as the domain.

### Zendesk

**CNAME pattern**: `→ <account>.zendesk.com`

Fingerprint:
```
Help Center Closed
```
or
```
Oops, this page doesn't exist.
```

**PoC path**: Create a Zendesk account with the matching subdomain.

### Pantheon

**CNAME pattern**: `→ *.pantheonsite.io`

Fingerprint:
```
404 Not Found
```
With header: `Served-By: Pantheon` or `X-Pantheon-Endpoint`

### Tumblr

**CNAME pattern**: `→ domains.tumblr.com`

Fingerprint:
```
There's nothing here.
```
Custom domain must be claimed via a Tumblr blog settings.

## Step 3: Verify the resource is claimable

Before declaring a finding, confirm the resource is genuinely unclaimed (not
just temporarily returning an error):

1. **Check DNS CNAME chain**: Use `send_request` to verify the CNAME still
   exists. If DNS already returns NXDOMAIN, the subdomain itself may be
   droppable without a CNAME chain.

2. **Check the service directly**: Visit the service's console (S3 bucket
   console, Heroku dashboard) to confirm the resource name is available. Do not
   create it — just verify availability.

3. **Check if body is consistent**: Request the subdomain 3 times. If the "not
   found" fingerprint is consistent, it is genuine. A flapping response suggests
   a deployment in progress.

4. **Record the evidence**: Use `add_pentest_finding` with the CNAME chain, the
   HTTP response body excerpt, and service fingerprint as evidence.

## Step 4: PoC (authorised only)

If the client authorises a full PoC demonstration:

1. **Claim the resource** on the relevant service (S3 bucket, GitHub repo, etc.).
2. **Deploy a minimal proof page**:
   ```html
   <!DOCTYPE html>
   <html>
   <head><title>Subdomain Takeover PoC</title></head>
   <body>
   <h1>Subdomain Takeover Confirmed</h1>
   <p>This page is served from sub.example.com via an unclaimed external service.</p>
   <p>Tester: [your name] | Date: [date] | Authorised engagement</p>
   </body>
   </html>
   ```
3. **Screenshot the page** loading at `https://sub.example.com` showing the domain
   in the browser address bar.
4. **Demonstrate cookie access** (if parent-domain cookies lack HttpOnly):
   Use `eval_page` from the Void panel to read `document.cookie` on the claimed
   subdomain and confirm that parent-domain cookies are accessible.
5. **Immediately release the resource** after screenshotting.

## Severity reference

| Scenario | Severity |
|----------|----------|
| Subdomain serves user-facing content + cookie access to parent | Critical |
| Subdomain is login/auth flow (`login.example.com`) | Critical |
| Subdomain can serve arbitrary JS (cookie-less) | High |
| Subdomain used in OAuth redirect_uri or CORS allow-list | High |
| Subdomain serves static content only (no cookie access) | High |
| Subdomain is internal / not user-facing | Medium |
| CNAME pointing to dead service, resource not claimable without payment | Low |

## Known false positives

- A 404 from Cloudflare (`1001 DNS resolution error`) means the origin is
  misconfigured — it is not directly claimable via the Cloudflare service.
- Some services return consistent "not found" pages for all unrouted domains
  without allowing takeover (e.g., load balancers with catch-all 404).
- Wildcard DNS entries (`*.example.com CNAME proxy.example.com`) do not
  necessarily mean every subdomain is individually vulnerable.
- A domain returning NXDOMAIN does NOT have a dangling CNAME — it may simply
  be unused with no DNS record at all.

## Tooling note

This methodology uses Void panel tools: `send_request` for probing subdomains
and checking service fingerprints, `search_responses` for pattern matching across
captured traffic, `get_response_headers` for service header identification,
`eval_page` for demonstrating cookie access in authorised PoCs, and
`add_pentest_finding` to record confirmed takeovers. These are browser-extension
APIs, not shell commands — do not attempt to run CLI tools.
