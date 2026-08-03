window.VOID_PROMPTS = [
  // ═══ Reconnaissance ═══════════════════════════════════════════════════════
  {
    id: 'recon-target',
    name: 'Full Recon',
    category: 'recon',
    template: `Perform comprehensive reconnaissance on {{target}}.

## Phase 1 — Passive Discovery
- Map the full attack surface: use get_site_map, get_endpoints, get_links, get_scripts
- Identify technologies with get_technologies
- Check all security headers with get_headers_analysis
- Enumerate cookies and storage with get_cookies, get_storage
- Look for forms and input points with get_forms

## Phase 2 — Analysis
- Identify API endpoints vs web pages (REST patterns, JSON responses)
- Map authentication flows (login pages, OAuth redirects, JWT issuance)
- Catalog input vectors: URL params, POST bodies, headers, cookies
- Note any version disclosure, debug endpoints, or admin panels

## Output
Produce a structured summary with sections:
1. Target overview (domain, IP, server, tech stack)
2. Attack surface map (endpoints by category)
3. Authentication mechanisms found
4. Input vectors (sorted by potential impact)
5. Security posture assessment (headers, CORS, CSP)
6. Recommended testing priorities`,
    tags: ['target']
  },
  {
    id: 'recon-subdomain',
    name: 'Subdomain & Asset Discovery',
    category: 'recon',
    template: `Perform subdomain and asset discovery for {{domain}}.

1. Query DNS records: A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, PTR
2. Check for common subdomains: www, api, dev, staging, admin, mail, ftp, test, beta, internal, vpn, cdn
3. Enumerate from certificate transparency logs if available
4. Check for DMARC, SPF, and DKIM configuration
5. Look for WHOIS information and registrar details
6. Check for IP ranges and ASN information

Report all discovered assets with their purpose and security implications.`,
    tags: ['domain']
  },

  // ═══ Detection ════════════════════════════════════════════════════════════
  {
    id: 'test-vuln-class',
    name: 'Test Vulnerability Class',
    category: 'detection',
    template: `Test {{target}} for {{vuln_class}} vulnerabilities using a systematic methodology.

## Approach
1. **Discovery**: Identify all input points that could be vulnerable to {{vuln_class}}
   - URL parameters, POST bodies, headers, cookies
   - File upload fields, JSON/XML request bodies
   - WebSocket messages, postMessage handlers

2. **Detection**: Start with safe, non-destructive payloads
   - Use the /{{vuln_class}} skill methodology if available
   - Send detection payloads via send_request
   - Check for reflections with check_reflections
   - Monitor for error messages, timing differences, behavioral changes

3. **Confirmation**: Verify each potential finding
   - Use multiple payload variants to confirm (not just one)
   - Check if filtering/encoding is applied and try bypasses
   - Distinguish between reflected but safe vs. actually exploitable

4. **Evidence**: For each confirmed finding, document:
   - Exact URL and parameter
   - Payload that triggered the vulnerability
   - Server response proving exploitation
   - Potential impact and severity assessment

Record all confirmed findings with add_finding. Never add speculative findings.`,
    tags: ['target', 'vuln_class']
  },
  {
    id: 'test-injection-suite',
    name: 'Full Injection Suite',
    category: 'detection',
    template: `Run a comprehensive injection test suite against {{target}}.

Test ALL injection classes in order of severity:

### SQL Injection
- Error-based: ' OR 1=1--, ' UNION SELECT NULL--
- Blind boolean: ' AND 1=1-- vs ' AND 1=2--
- Time-based: ' OR SLEEP(5)--
- Test both GET and POST parameters

### Cross-Site Scripting (XSS)
- Reflected: <script>alert(1)</script>, <img/src=x onerror=alert(1)>
- DOM-based: Check sources/sinks via probe
- Test in different contexts: HTML, attribute, JS string, URL

### Command Injection
- ; id, | whoami, \`id\`, $(id)
- Test both Unix and Windows patterns

### Server-Side Template Injection (SSTI)
- {{7*7}}, ${7*7}, <%=7*7%>, #{7*7}
- Identify template engine from error messages

### XML External Entity (XXE)
- Test XML endpoints with DTD injection
- Check for file read, SSRF via XXE

### SSRF
- Test URL parameters with internal addresses
- 127.0.0.1, 169.254.169.254, internal hostnames

For each finding, provide the exact payload and evidence.`,
    tags: ['target']
  },

  // ═══ Analysis ═════════════════════════════════════════════════════════════
  {
    id: 'analyze-response',
    name: 'Analyze HTTP Response',
    category: 'analysis',
    template: `Analyze this HTTP response for security issues:

URL: {{url}}
Status: {{status}}
Headers: {{headers}}
Body (first 2000 chars): {{body}}

## Check for:
1. **Error Disclosure**: Stack traces, SQL errors, debug info, internal paths
2. **Version Disclosure**: Server versions, framework versions, library versions
3. **Security Header Gaps**: Missing HSTS, CSP, X-Frame-Options, X-Content-Type-Options
4. **Reflected Input**: Any user-controlled data reflected without encoding
5. **Sensitive Data**: API keys, tokens, credentials, PII in response
6. **CORS Issues**: Overly permissive Access-Control-Allow-Origin
7. **Cookie Security**: Missing Secure, HttpOnly, SameSite flags
8. **Caching Issues**: Sensitive data with permissive Cache-Control
9. **Authentication Clues**: Session tokens, JWT structures, auth flow indicators
10. **Business Logic**: Unusual parameters, hidden fields, debug flags

Rate each finding by severity and provide remediation advice.`,
    tags: ['url', 'status', 'headers', 'body']
  },
  {
    id: 'analyze-auth-flow',
    name: 'Analyze Auth Flow',
    category: 'analysis',
    template: `Analyze the authentication flow for {{target}}.

1. Identify the login mechanism:
   - Form-based login (username/password)
   - OAuth/OIDC redirects
   - API key / Bearer token
   - SSO / SAML

2. Analyze session management:
   - Session token format and entropy (use Sequencer if available)
   - Cookie flags (Secure, HttpOnly, SameSite)
   - Token storage mechanism (cookie, localStorage, sessionStorage)
   - Session timeout behavior

3. Check for common flaws:
   - Username enumeration (different error messages)
   - Brute force protection (rate limiting, CAPTCHA)
   - Password reset flow weaknesses
   - Remember me / persistent session issues
   - Session fixation
   - Concurrent session handling

4. If JWT is used:
   - Decode header and payload
   - Check algorithm (none, HS256 vs RS256)
   - Verify signature validation
   - Check for sensitive data in claims

Report all findings with severity ratings.`,
    tags: ['target']
  },

  // ═══ Exploitation ═════════════════════════════════════════════════════════
  {
    id: 'exploit-finding',
    name: 'Exploit Finding',
    category: 'exploitation',
    template: `A {{vuln_type}} vulnerability was detected at {{url}} in the {{parameter}} parameter.

**Detection payload:** {{payload}}

## Exploitation Plan
1. **Confirm exploitability**: Verify the vulnerability is real, not a false positive
2. **Assess impact**: Determine what an attacker could achieve
3. **Escalate carefully**: Demonstrate maximum impact within engagement rules

### If XSS:
- Try to steal cookies (if not HttpOnly): document.cookie
- Try DOM manipulation to demonstrate impact
- Check if it can be used for session hijacking

### If SQLi:
- Enumerate database type and version
- Extract table names and column names
- Demonstrate data extraction (use safe test data)

### If Command Injection:
- Identify OS with safe commands (id, whoami, hostname)
- Demonstrate file read capability
- Check for reverse shell possibility (note in report, don't execute)

### If SSRF:
- Probe internal network (127.0.0.1 ports, metadata endpoints)
- Check cloud metadata (169.254.169.254)
- Attempt file:// protocol

Follow the engagement config safety rules strictly.`,
    tags: ['vuln_type', 'url', 'parameter', 'payload']
  },
  {
    id: 'bypass-waf',
    name: 'Bypass WAF / Filter',
    category: 'exploitation',
    template: `The {{vuln_type}} payload "{{payload}}" is being blocked at {{url}} (parameter: {{parameter}}).
WAF/filter indicator: {{waf_indicator}}

## Bypass Strategy

### Encoding Bypasses
- URL encoding: %3Cscript%3E, double URL encoding: %253Cscript%253E
- HTML entities: &#x3C;script&#x3E;, &#60;script&#62;
- Unicode: \\u003Cscript\\u003E
- Mixed case: <ScRiPt>, <SCRIPT>

### Syntax Alternatives
- For XSS: <img>, <svg>, <details>, <body>, event handlers
- For SQLi: UNION vs UNION ALL, /**/ comments, /*!MySQL*/, char()
- For CMDi: $IFS, {cat,/etc/passwd}, indirect variable expansion

### Evasion Techniques
- Content-Type manipulation (multipart, JSON, XML)
- HTTP method switching (GET↔POST)
- Parameter pollution (HPP)
- Chunked transfer encoding
- Line feeds and null bytes in payloads

### Advanced
- Time-based blind techniques (avoid pattern matching)
- Out-of-band channels (DNS, HTTP callback)
- Recursive decoding exploitation

Document each attempt and result. If all bypasses fail, note the WAF type and version for the report.`,
    tags: ['vuln_type', 'payload', 'url', 'parameter', 'waf_indicator']
  },

  // ═══ Reporting ════════════════════════════════════════════════════════════
  {
    id: 'generate-report',
    name: 'Generate Security Report',
    category: 'reporting',
    template: `Generate a comprehensive security assessment report for {{target}}.

## Report Structure

### Executive Summary
- Assessment scope and dates
- Overall risk rating (Critical/High/Medium/Low)
- Key findings summary (1-2 sentences per critical/high)
- Immediate action items

### Findings Detail
For each finding, include:
- **Title**: Clear, descriptive vulnerability name
- **Severity**: Critical/High/Medium/Low with CVSS score
- **Location**: Exact URL, parameter, endpoint
- **Description**: What the vulnerability is and why it matters
- **Evidence**: HTTP request/response proving the vulnerability
- **Impact**: What an attacker could do if exploiting this
- **Remediation**: Specific fix recommendations with code examples

### Methodology
- Tools and techniques used
- Testing coverage summary
- Limitations and caveats

### Appendices
- Full list of endpoints tested
- Security header analysis
- Technology stack detected

Read all findings with get_findings before generating. Group by severity, then by vulnerability class.`,
    tags: ['target']
  },

  // ═══ Hybrid Judge/Refute ══════════════════════════════════════════════════
  {
    id: 'judge-response',
    name: 'Judge Response',
    category: 'hybrid',
    template: `You are a vulnerability judge. Given the HTTP exchange below, determine if {{vuln_type}} is present.

Payload: {{payload}}
URL: {{url}}
HTTP Status: {{status}}
Response (first 2000 chars): {{response}}
Pattern matched: {{pattern}}

## Evaluation criteria:
1. Is the payload actually reflected/executed, or just present in a safe context?
2. Could the pattern match be coincidental (e.g., natural HTML, error template)?
3. Is the response behavior consistent with the vulnerability type?
4. Are there mitigating factors (CSP, encoding, sandboxing)?

Respond ONLY with JSON:
{"vulnerable": true/false, "evidence": "exact text from response proving it", "confidence": 0.0-1.0, "reasoning": "brief explanation"}`,
    tags: ['vuln_type', 'payload', 'url', 'status', 'response', 'pattern']
  },
  {
    id: 'refute-finding',
    name: 'Refute Finding',
    category: 'hybrid',
    template: `A {{vuln_type}} finding was reported at {{url}}.
Evidence: {{evidence}}
Payload: {{payload}}

## Actively look for reasons this could be a FALSE POSITIVE:
1. Is the reflection in a safe context (inside a comment, attribute, quoted string)?
2. Is the response a generic error page that would match any input?
3. Could server-side encoding/escaping prevent exploitation?
4. Is there a CSP or other security header that mitigates this?
5. Does the "evidence" actually demonstrate the vulnerability, or just show the input?
6. Would this behavior occur with any random input, not just the payload?

Respond ONLY with JSON:
{"false_positive": true/false, "reason": "detailed explanation", "confidence": 0.0-1.0}`,
    tags: ['vuln_type', 'url', 'evidence', 'payload']
  },

  // ═══ Specialized ══════════════════════════════════════════════════════════
  {
    id: 'api-audit',
    name: 'API Security Audit',
    category: 'detection',
    template: `Audit the API at {{target}} for security vulnerabilities.

## API-Specific Tests
1. **Authentication**: Test API key/token validation, check for auth bypass
2. **Authorization**: Test IDOR/BOLA by changing object IDs, test horizontal privilege escalation
3. **Rate Limiting**: Check if rate limiting is enforced per endpoint
4. **Input Validation**: Test with unexpected types, oversized payloads, special characters
5. **Mass Assignment**: Send extra fields in POST/PUT requests
6. **SSRF via API**: Test URL parameters for internal resource access
7. **Information Disclosure**: Check verbose error messages, stack traces
8. **Broken Function Level Auth**: Try admin endpoints with regular user tokens
9. **GraphQL-specific** (if applicable): Introspection, nested query DoS, batch attacks

Use get_endpoints to find all API routes, then systematically test each one.
Generate an OpenAPI schema with the API Schema generator if not already done.`,
    tags: ['target']
  },
  {
    id: 'content-discovery',
    name: 'Content Discovery',
    category: 'recon',
    template: `Run content discovery against {{target}} to find hidden endpoints and files.

## Wordlists to try:
- Common admin paths: /admin, /dashboard, /panel, /manage, /wp-admin
- Backup files: .bak, .old, .swp, .save, ~, .orig
- Config files: .env, .config, web.config, application.yml, .htaccess
- Source code: .git, .svn, .hg, .DS_Store, .idea
- API docs: /swagger, /api-docs, /openapi.json, /graphql
- Debug: /debug, /trace, /health, /metrics, /status, /info

## Method:
1. Use the Content Discovery scanner module
2. Cross-reference with technologies detected (WordPress paths for WP, etc.)
3. Check robots.txt and sitemap.xml for disclosed paths
4. Try common file extensions for each discovered directory

Report all discovered paths with their HTTP status and content type.`,
    tags: ['target']
  },
  {
    id: 'privilege-escalation',
    name: 'Privilege Escalation Check',
    category: 'detection',
    template: `Test for privilege escalation at {{target}} using these credentials:
Low-privilege: {{low_user}}
High-privilege: {{high_user}} (for reference only — do not use for testing)

## Horizontal Privilege Escalation
1. Access resources belonging to other users at the same privilege level
2. Change user IDs, account numbers, or object references in requests
3. Check if session tokens are predictable or can be forged

## Vertical Privilege Escalation
1. Access admin endpoints with regular user session
2. Modify role/permission fields in profile update requests
3. Check for parameter tampering (isAdmin=true, role=admin)
4. Test function-level access control for each admin action

## Methodology
- Capture requests from both privilege levels
- Replay high-privilege requests with low-privilege session
- Document which endpoints have proper access control and which don't`,
    tags: ['target', 'low_user', 'high_user']
  },
];
