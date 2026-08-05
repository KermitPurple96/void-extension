# WAF Bypass

## Scope and preconditions

Applies when a Web Application Firewall blocks your test payloads. This skill
is a companion to other attack skills (XSS, SQLi, command injection, etc.) —
use it when you confirm a vulnerability exists but the WAF prevents exploitation.
The goal is not to bypass the WAF for its own sake, but to prove that the
underlying vulnerability is exploitable despite the WAF.

It does **not** cover: identifying the vulnerability itself (use the specific
vuln skill), network-layer firewall bypass, or DDoS protection bypass.

## Rules of engagement

- MUST NOT use bypass techniques to attack applications you are not authorized
  to test. WAF bypass without authorization is unauthorized access.
- MUST document which WAF is in use and which specific rule was bypassed.
- MUST report both the underlying vulnerability AND the WAF bypass as separate
  findings — the WAF bypass is a defense-in-depth failure.
- NEVER use bypass techniques that could cause denial of service (e.g.,
  excessive chunked encoding that exhausts WAF resources).

## Workflow

- [ ] 1. Identify the WAF
- [ ] 2. Determine what is being blocked (rule identification)
- [ ] 3. Test encoding-based bypasses
- [ ] 4. Test structural bypasses
- [ ] 5. Test protocol-level bypasses
- [ ] 6. Test WAF-specific known bypasses
- [ ] 7. Find the origin IP (bypass WAF entirely)
- [ ] 8. Record the finding

## Step 1: Identify the WAF

### Goal
Determine which WAF product is in use.

### Actions
Use `send_request` with a known-bad payload and examine the block response:

| WAF | Block page indicators |
|---|---|
| Cloudflare | `cf-ray` header, "Attention Required" page, ray ID |
| AWS WAF | `x-amzn-requestid`, 403 with JSON error body |
| Akamai | `AkamaiGHost` header, reference ID in error page |
| ModSecurity | `Mod_Security`, `NOYB` in error page |
| Imperva/Incapsula | `X-CDN: Imperva`, `incap_ses_*` cookies |
| F5 BIG-IP ASM | `TS` cookies, `X-WA-Info` header |
| Sucuri | `X-Sucuri-ID` header, `sucuri.net` in block page |
| Barracuda | `barra_counter_session` cookie |

Also check: `Server` header, error page HTML, specific cookies.

Use `search_responses` to find these indicators in captured traffic.

## Step 2: Determine what is being blocked

### Goal
Understand the specific rule that triggers the block.

### Actions
Start with a full payload and systematically reduce it:
1. Send the full payload — blocked.
2. Remove parts one at a time. When the block stops, the removed part was the
   trigger.
3. Common trigger keywords: `SELECT`, `UNION`, `<script>`, `alert`, `onerror`,
   `../`, `cmd`, `eval`, `/etc/passwd`

Use `compare_responses` to diff blocked vs. allowed responses. Look for the
exact boundary between blocked and allowed.

## Step 3: Encoding-based bypasses

### Goal
Transform the payload so the WAF does not recognize it but the application
still processes it.

### Techniques

**Double URL encoding**: `<script>` → `%253Cscript%253E`
The WAF decodes once (sees `%3Cscript%3E`), does not match. The app decodes
again (sees `<script>`).

**Unicode encoding**: `<` → `\u003c`, `'` → `\u0027`
Works when the application processes Unicode escapes (JavaScript contexts).

**HTML entity encoding**: `<` → `&lt;` → `&#60;` → `&#x3c;`
WAF may not decode HTML entities. Browser will.

**Hex encoding (SQL)**: `SELECT` → `0x53454c454354`
MySQL interprets hex strings. WAF sees only hex digits.

**Overlong UTF-8**: `<` (U+003C) encoded as 2 or 3 byte overlong sequence.
Some WAFs fail to canonicalize UTF-8 before matching.

**Mixed case**: `SeLeCt`, `<ScRiPt>`, `OnErRoR`
Only bypasses case-sensitive rules, but surprisingly common.

**Null bytes**: `%00` before keyword — `%00SELECT`, `<scr%00ipt>`
Some WAFs stop processing at null byte. Application ignores it.

**Concatenation (SQL)**: `SEL/**/ECT`, `S'+'ELECT` (MSSQL), `CONCAT(0x73,0x65,0x6c,0x65,0x63,0x74)`

Use `run_intruder_attack` to test multiple encoding variants of the same
payload simultaneously.

## Step 4: Structural bypasses

### Goal
Change the request structure so the WAF inspects the wrong part.

### Techniques

**Content-Type switching**: 
WAFs often inspect only one Content-Type. Try:
- `application/json` → `application/x-www-form-urlencoded`
- `application/x-www-form-urlencoded` → `multipart/form-data`
- `application/json` → `text/plain` (CORS simple request)
- `multipart/form-data` with unusual boundary

**Parameter pollution**: 
`?id=1&id=2` — WAF checks first `id`, app uses second (or last, or concatenates).
- Apache: uses last
- IIS/ASP: concatenates with comma
- PHP: uses last
- Python/Flask: uses first

**Duplicate Content-Type**: Send two Content-Type headers — WAF parses one,
app parses the other.

**Chunked transfer encoding**:
```
Transfer-Encoding: chunked

4
SEL
3
ECT
0
```
WAF may not reassemble chunks before inspection.

**HTTP/2 pseudo-headers**: `:method`, `:path` in HTTP/2 bypass WAFs that only
inspect HTTP/1.1 headers.

**Large body padding**: Add large innocent content before the payload — WAF
may stop inspecting after N bytes.

## Step 5: Protocol-level bypasses

### Goal
Exploit differences in how the WAF and application handle HTTP.

### Techniques

**HTTP method override**: Some frameworks accept `X-HTTP-Method-Override: PUT`
on a POST request. WAF may only inspect POST parameters, but the app processes
it as PUT with different validation.

**Path normalization differences**: 
- `/api/./users/../admin` — WAF sees the raw path, app normalizes
- `/API/ADMIN` — WAF is case-sensitive, app is not
- `/api/admin;jsessionid=x` — WAF does not strip path parameters

**Request line oddities**:
- Absolute URL in request line: `GET https://target.com/path`
- Tab or vertical tab instead of space
- HTTP/0.9 request (no headers)

## Step 6: WAF-specific bypasses

### Cloudflare
- `<svg/onload=alert(1)>` often passes when `<script>` is blocked
- Use `<img src=x onerror=confirm(1)>` — `confirm` not always in ruleset
- HTML comments inside tags: `<scr<!---->ipt>`

### AWS WAF
- Check regex rules — they often have size limits. Payloads > 8KB may bypass.
- Test with `Transfer-Encoding: chunked` — older rulesets don't reassemble.
- Unicode normalization: fullwidth characters `＜script＞`

### ModSecurity CRS
- Paranoia Level affects rules. Many sites run PL1 (basic). PL1 bypasses:
  - `<details/open/ontoggle=alert(1)>` (less common event handlers)
  - `<svg><animate onbegin=alert(1)>`
- SQL: `/*!50000SELECT*/` (MySQL version-specific comments)

### Akamai
- JSON-based payloads often bypass when form-encoded payloads are blocked
- `Transfer-Encoding: chunked` with odd chunk sizes

## Step 7: Find origin IP

### Goal
Bypass the WAF entirely by connecting directly to the origin server.

### Actions
Use `send_request` to probe for origin indicators:
- Historical DNS records (check if older A records point to origin)
- Certificate transparency logs — look for origin IP in certificate SANs
- Mail server: MX record may point to same host, revealing origin IP
- `X-Forwarded-For`, `X-Real-IP` in responses that leak internal IPs
- Subdomains that bypass the WAF (API endpoints, staging, dev)
- Error pages that reveal the origin hostname

If you find the origin IP, send requests directly to it with the original
`Host` header. If the origin accepts direct connections, the entire WAF is
bypassed.

## Step 8: Record the finding

Use `add_pentest_finding` with:
- The WAF identification evidence
- The original blocked payload and the blocked response
- The bypass payload and the successful response
- Which specific technique succeeded
- The underlying vulnerability that the WAF was masking

## Known false positives

- A different response code (e.g., 403 → 200) that does not actually indicate
  the payload was processed — the application may return 200 for a generic
  error page.
- Encoding bypass where the WAF allows the encoded form through but the
  application does not decode it — the payload lands encoded and harmless.
- Origin IP that accepts connections but runs a different application or
  version than what is behind the WAF.

## Reminder

WAF bypass is always secondary to the underlying vulnerability. Report two
findings: (1) the vulnerability itself, and (2) the WAF bypass as a
defense-in-depth failure. The three highest-value bypass categories:
**Content-Type switching** (WAF inspects wrong format), **encoding chains**
(WAF decodes once, app decodes twice), and **origin IP discovery** (WAF is
bypassed entirely). Always try Content-Type switching first — it is the most
commonly successful technique.
