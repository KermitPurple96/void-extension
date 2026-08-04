---
name: "supply-chain"
description: "Client-Side Supply Chain Risk Assessment"
version: "1.0.0"
author: "void-extension"
tags: ["pentest", "supply-chain", "sri", "cdn", "dependency", "third-party", "cve"]
trigger_patterns:
  - "/supply-chain"
  - "test supply chain"
  - "check sri"
  - "check third-party scripts"
  - "library vulnerabilities"
  - "outdated libraries"
  - "dependency audit"
---

# Client-Side Supply Chain Risk Assessment

Assess client-side supply chain risks: missing Subresource Integrity (SRI),
outdated libraries with known CVEs, typosquatting risks, CDN compromise
exposure, and CSP containment gaps.

## Scope and preconditions

Applies to any web application that loads third-party JavaScript, CSS, fonts,
or other resources from external CDNs or package registries. Also applies to
self-hosted dependencies that may be outdated.

It does **not** cover: server-side dependency analysis (npm audit, pip audit),
CI/CD pipeline attacks, or package registry account compromise.

## Rules of engagement

- This is a passive/reconnaissance skill. Do not modify any resources.
- Do not attempt to exploit CVEs -- identify and report them.
- Record every finding with add_pentest_finding.

## Workflow

- [ ] 1. Inventory all external resources
- [ ] 2. Check SRI on external scripts/styles
- [ ] 3. Fingerprint library versions
- [ ] 4. Check for known CVEs
- [ ] 5. Assess typosquatting risk
- [ ] 6. Evaluate CDN risk
- [ ] 7. Check CSP containment

## Step 1: Inventory external resources

### Actions

Use eval_page to enumerate all external resources -- query all script[src]
and link[rel=stylesheet] elements and collect their URLs.

Use get_scripts to get a list of all loaded scripts.

Categorize each resource:
- **Same-origin**: hosted on the application domain
- **CDN**: loaded from a public CDN (cdnjs, jsdelivr, unpkg, googleapis)
- **Third-party service**: analytics, ads, chat widgets, A/B testing
- **Unknown external**: unrecognised external domain

## Step 2: Check Subresource Integrity (SRI)

### Actions

Use eval_page to check SRI attributes on all script and link elements.
For each, record the tag, src/href, integrity attribute (or MISSING), and
crossorigin attribute (or MISSING).

### Assessment

| Condition | Finding |
|-----------|---------|
| External script without integrity attribute | Missing SRI (Medium) |
| External script with integrity but no crossorigin | SRI may not be enforced |
| CDN script with SRI | Good -- protected against CDN compromise |
| Same-origin script | SRI not required (but recommended) |

### Why SRI matters

If a CDN is compromised, every site loading scripts from it without SRI
runs attacker-controlled code. SRI pins the expected hash -- any modification
causes the browser to reject the resource.

## Step 3: Fingerprint library versions

### Actions

Use eval_page to detect common library versions by checking global objects:
jQuery (jQuery.fn.jquery), Angular (angular.version.full), React (React.version),
Vue (Vue.version), Lodash (_.VERSION), Moment (moment.version), DOMPurify
(DOMPurify.version), Axios (axios.VERSION).

For scripts without global variables, check:
- Comment headers in script files (use search_responses with version patterns)
- Known file paths: /jquery-3.6.0.min.js, /angular.min.js
- Script content hashes against known version databases

### Additional detection

Use search_responses to find version strings in script file contents.

## Step 4: Check for known CVEs

For each identified library and version, check for known vulnerabilities:

| Library | Version | CVE example | Impact |
|---------|---------|------------|--------|
| jQuery < 3.5.0 | Prototype pollution, XSS | CVE-2020-11022/23 | High |
| Lodash < 4.17.21 | Prototype pollution | CVE-2021-23337 | High |
| Angular.js < 1.8.0 | Sandbox bypass XSS | Multiple | Critical |
| Moment.js < 2.29.4 | ReDoS path traversal | CVE-2022-31129 | Medium |
| Bootstrap < 4.3.1 | XSS in tooltip/popover | CVE-2019-8331 | Medium |
| DOMPurify < 2.3.0 | Bypass (mXSS) | Multiple | Critical |
| React < 16.0 | XSS in SSR | CVE-2018-6341 | High |

### Reporting

For each vulnerable library, record:
- Library name and version
- CVE number(s)
- Whether the vulnerable function is actually used by the application
- Upgrade path (latest safe version)

## Step 5: Assess typosquatting risk

### Actions

Check loaded resources for suspicious domain names that look similar to
legitimate CDNs:

| Legitimate | Typosquat example |
|-----------|-------------------|
| cdnjs.cloudflare.com | cdnjs.cloudfIare.com (capital I) |
| cdn.jsdelivr.net | cdn.jsdeliver.net |
| unpkg.com | unpackage.com |
| ajax.googleapis.com | ajax.googleapi.com |
| code.jquery.com | code.jquerry.com |

Check loaded npm package names (if visible in paths) for typosquatting:
- Extra characters: lodaash vs lodash
- Swapped characters: axois vs axios
- Scope confusion: @mycompany/utils vs mycompany-utils

## Step 6: Evaluate CDN risk

### Assessment criteria

| Risk factor | Impact |
|-------------|--------|
| All scripts from one CDN, no SRI | Single point of compromise (High) |
| Scripts loaded over HTTP | MITM injection possible (Critical) |
| CDN with no HTTPS enforcement | Downgrade attack possible |
| Deprecated CDN (e.g. RawGit) | May stop serving or be acquired |
| Self-hosted but outdated copies | No automatic security updates |

### Actions

For each external script, verify:
1. HTTPS is used (not HTTP)
2. The CDN is a reputable, actively maintained service
3. SRI is present (Step 2)
4. The specific version is still supported

## Step 7: Check CSP containment

### Actions

Use send_request to fetch the page and check the Content-Security-Policy header.

| CSP directive | Secure value | Risk if missing |
|---------------|-------------|-----------------|
| script-src | Specific domains, nonces, or hashes | Any script can load |
| script-src with unsafe-inline | Present | XSS not mitigated by CSP |
| script-src * or missing | Wildcard | No script source restriction |
| default-src | Fallback for missing directives | Depends on value |

### Key questions

1. Does the CSP allow loading scripts from arbitrary CDNs? Overly broad
   wildcards let attackers host malicious scripts on those CDNs.

2. Does the CSP allow unsafe-inline? If yes, XSS from a supply chain attack
   is not the primary concern -- inline XSS is already possible.

3. Are there CSP bypass gadgets? Libraries like Angular.js with permissive
   settings or JSONP endpoints on whitelisted domains can bypass CSP.

## Severity reference

| Finding | Severity |
|---------|----------|
| Library with known RCE/XSS CVE actively exploitable | Critical |
| External scripts loaded over HTTP (MITM) | Critical |
| AngularJS (end-of-life) with CSP bypass | High |
| jQuery < 3.5.0 with XSS CVE | High |
| Multiple external scripts without SRI | Medium |
| Outdated library with no known exploitable CVE | Medium |
| Missing CSP or overly permissive CSP | Medium |
| Self-hosted library one minor version behind | Low |
| SRI present but crossorigin attribute missing | Low |

## Known false positives

- A library has a CVE but the vulnerable function is never called by the
  application -- report as informational, not a confirmed vulnerability.
- SRI is missing on a same-origin script -- SRI is primarily for external
  resources; same-origin scripts are protected by server security.
- An old jQuery version is loaded but only used for non-security-critical UI
  animations -- the CVE may still be exploitable if user input reaches jQuery
  DOM manipulation functions.

## Tooling note

This methodology is designed for the Void panel tools (send_request,
compare_responses, search_responses, get_endpoints, eval_page, get_scripts,
add_pentest_finding). These are browser-extension APIs, not shell commands.
Do not attempt to run CLI tools.
