---
name: "auth"
description: "Authentication Testing Methodology"
version: "1.0.0"
author: "void-extension"
tags: ["pentest", "auth", "authentication", "credentials", "brute-force", "mfa", "session", "lockout"]
trigger_patterns:
  - "/auth"
  - "test authentication"
  - "test login"
  - "authentication testing"
  - "brute force login"
  - "test password reset"
  - "test mfa bypass"
  - "test account lockout"
  - "credential testing"
---

# Authentication Testing Methodology

Test the entire authentication surface of a web application: credential handling,
login mechanisms, lockout policies, password reset flows, MFA, session fixation,
persistent login, credential transport, and brute-force protections. Covers
OWASP WSTG-ATHN-01 through WSTG-ATHN-11 and the corresponding PortSwigger
Authentication labs.

## Scope and preconditions

Applies to any application that authenticates users: traditional login forms, API
key/token endpoints, OAuth/OIDC flows, SSO providers, and headless APIs with
Basic/Bearer auth.

It does **not** cover: authorization/access-control after login (use `idor`),
JWT-specific cryptographic attacks (use `jwt`), or session management beyond
fixation (use a dedicated session skill if one exists).

You need **at least two test accounts** (one low-privilege, one higher) plus the
ability to create throwaway accounts or observe the registration flow. If only one
account is available, note which phases are blocked and proceed with the rest.

## Rules of engagement

- NEVER lock out real user accounts. If you discover the lockout threshold, stop
  one attempt below it and record the threshold as a finding.
- NEVER change another user's password through a reset flow. Prove the flaw by
  reaching the "enter new password" page with another user's token, screenshot it,
  and stop.
- Use only test email addresses you control when testing password-reset and
  registration flows.
- Record every request and response pair for every confirmed finding using
  `add_pentest_finding`.
- In mode `ask`: confirm the vulnerability exists and stop. Do not exploit further.

## Workflow overview

Copy this checklist into your response and tick items off as you go.

- [ ] Phase 1: Credential transport — HTTPS enforcement, secure headers
- [ ] Phase 2: Default and weak credentials
- [ ] Phase 3: Account enumeration — error messages, timing, response diff
- [ ] Phase 4: Login bypass — SQLi, logic flaws, parameter manipulation
- [ ] Phase 5: Password policy assessment
- [ ] Phase 6: Brute-force protection assessment
- [ ] Phase 7: Account lockout mechanism
- [ ] Phase 8: Remember-me / persistent login
- [ ] Phase 9: Password reset and forgot-password flaws
- [ ] Phase 10: Multi-factor authentication bypass
- [ ] Phase 11: Session fixation

---

## PHASE 1 — Credential transport (WSTG-ATHN-01)

### Goal

Verify that credentials never travel in cleartext and that the server enforces
encrypted transport.

### Actions

1. Use `send_request` to fetch the login page over plain HTTP (change the scheme
   to `http://`). Check whether the server redirects to HTTPS or serves the page
   over HTTP.

2. Inspect the login form's `action` attribute. If the page is HTTPS but the form
   posts to HTTP, credentials leak in transit.

3. Check response headers with `send_request`:

   | Header | Secure value | Risk if missing |
   |--------|-------------|-----------------|
   | `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Downgrade attacks via sslstrip |
   | `Set-Cookie` | `Secure` flag on session cookie | Cookie sent over HTTP |
   | `Content-Security-Policy` | `upgrade-insecure-requests` | Mixed content allows sniffing |

4. Use `get_cookies` to list all cookies. Any session or auth cookie without the
   `Secure` flag is a finding.

5. Use `search_responses` to look for `password` or `passwd` appearing in any URL
   query string — GET-based login forms leak credentials in server logs, browser
   history, and Referer headers.

### Decision tree

```
Login page served over HTTP?
  YES ──► FINDING: credentials transmitted in cleartext (High)
  NO  ──► Form action posts to HTTP?
             YES ──► FINDING: mixed-content credential leak (High)
             NO  ──► HSTS header present?
                       NO  ──► FINDING: missing HSTS (Medium)
                       YES ──► Check Secure flag on session cookies
                                 Missing ──► FINDING (Medium)
                                 Present ──► PASS
```

### Stop condition

You can state whether credentials are protected in transit across all observed
login and registration endpoints.

---

## PHASE 2 — Default and weak credentials (WSTG-ATHN-02)

### Goal

Determine whether the application ships with or permits default, well-known, or
trivially weak credentials.

### Actions

1. Identify the application/framework from recon data (technology fingerprint,
   `Server` header, login page branding).

2. Test common default credential pairs with `send_request`:

   | Application | Username | Password |
   |-------------|----------|----------|
   | Apache Tomcat | `tomcat` | `tomcat`, `s3cret`, `admin` |
   | WordPress | `admin` | `admin`, `password` |
   | Joomla | `admin` | `admin` |
   | phpMyAdmin | `root` | (empty), `root`, `toor` |
   | Jenkins | `admin` | `admin`, `password` |
   | Grafana | `admin` | `admin` |
   | Spring Actuator | (none) | (none — check `/actuator` unauthenticated) |
   | MongoDB | (none) | (none — no auth by default) |
   | Elasticsearch | `elastic` | `changeme` |
   | RabbitMQ | `guest` | `guest` |
   | Redis | (none) | (none — check `AUTH` command) |
   | Cisco devices | `admin` / `cisco` | `admin` / `cisco` |
   | Ubiquiti | `ubnt` | `ubnt` |
   | Default DBMS | `sa` / `root` / `postgres` | (empty), `password` |

3. Also try: `admin/admin`, `admin/password`, `admin/Password1`, `test/test`,
   `user/user`, `demo/demo`, `guest/guest`.

4. Check for self-registration. If you can register, try creating an account with
   a trivially weak password (`a`, `123456`, `password`) to assess enforcement
   (overlaps with Phase 5).

5. Look for administrative paths (`/admin`, `/manager`, `/console`,
   `/administrator`) and test default credentials on each.

### Decision tree

```
Default credentials work?
  YES ──► FINDING: default credentials active (Critical)
  NO  ──► Admin panels accessible with common creds?
             YES ──► FINDING (Critical)
             NO  ──► Application allows trivially weak passwords on registration?
                       YES ──► Continue to Phase 5 for full policy assessment
                       NO  ──► PASS for this phase
```

---

## PHASE 3 — Account enumeration (WSTG-ATHN-03)

### Goal

Determine whether an attacker can enumerate valid usernames through differences
in responses, timing, or behaviour.

### Technique 1 — Error message differential

1. Use `send_request` to submit a login with a **known-valid** username and wrong
   password. Save the response.

2. Submit a login with a **definitely-invalid** username (e.g.
   `void_nonexistent_user_8472`) and wrong password. Save the response.

3. Use `compare_responses` to diff the two responses. Look for:

   | Signal | Example | Enumerable? |
   |--------|---------|-------------|
   | Different error text | "Invalid password" vs "User not found" | YES |
   | Different HTTP status | 401 vs 404 | YES |
   | Different response length | 3012 vs 3089 bytes | YES |
   | Different hidden fields or tokens | CSRF token differs in structure | MAYBE |
   | Identical in every respect | Same error, same status, same length | NO |

4. Also test the **registration** endpoint — submit a username that already exists
   and one that does not. Different responses reveal existing accounts.

5. Test the **forgot-password** endpoint — enter a valid email vs an invalid one.
   "We've sent a reset link" only for valid emails is enumerable.

### Technique 2 — Timing side-channel

1. Use `send_request` to submit 10 login attempts with a valid username (wrong
   password) and record response times.

2. Repeat with an invalid username and record response times.

3. If valid-username requests consistently take longer (because the server hashes
   the password before comparing), the timing delta is an enumeration vector.
   A difference of >50ms across 10 samples is significant.

### Technique 3 — Forgot-password and registration oracles

Use `send_request` against the registration endpoint:

```
POST /register
{"username": "admin", "email": "test@example.com", "password": "Test1234!"}
```

If the response says "Username already taken" or "Email already registered", the
endpoint is an enumeration oracle.

### Payloads for username guessing

Use `get_payloads` with category `usernames` or manually test:

```
admin, administrator, root, user, test, demo, guest, info, support
user1, user01, admin1, manager, operator, service
firstname.lastname patterns derived from the target's public staff pages
```

### Decision tree

```
Error messages differ for valid vs invalid usernames?
  YES ──► FINDING: username enumeration via error messages (Low-Medium)
  NO  ──► Timing differs by >50ms consistently?
             YES ──► FINDING: username enumeration via timing (Low)
             NO  ──► Registration or reset reveals existing accounts?
                       YES ──► FINDING: enumeration via registration/reset (Low-Medium)
                       NO  ──► PASS
```

---

## PHASE 4 — Login bypass (WSTG-ATHN-04)

### Goal

Bypass the authentication mechanism entirely without valid credentials.

### Technique 1 — SQL injection in login

Test the username and password fields for SQL injection:

```
Username payloads:
  admin' --
  admin' #
  ' OR 1=1 --
  ' OR '1'='1
  admin'/*
  ' OR 1=1 LIMIT 1 --
  ' UNION SELECT 1,'admin','password' --
  ') OR ('1'='1
  admin' OR '1'='1' --

Password payloads:
  ' OR 1=1 --
  ' OR '1'='1
  anything' OR 'x'='x
  ') OR ('1'='1
```

Use `send_request` to submit each payload. If the application returns a
successful login response (redirect to dashboard, session cookie set), confirm
with `get_cookies` — the presence of a new session cookie proves bypass.

### Technique 2 — Authentication logic flaws

1. **Parameter removal**: Submit the login request but remove the `password`
   parameter entirely. Some frameworks treat missing parameters as null/empty
   and skip validation.

2. **Type juggling** (PHP): Submit `password` as `true` (boolean) or as an array
   `password[]=`:

   ```
   POST /login
   Content-Type: application/json
   {"username": "admin", "password": true}

   POST /login
   username=admin&password[]=
   ```

3. **Response manipulation**: If the login returns a JSON response like
   `{"success": false}`, intercept and change it to `{"success": true}` to test
   whether the client relies on the response body rather than a server-side
   session.

4. **HTTP verb tampering**: If POST /login is the normal flow, try:
   - `GET /login?username=admin&password=admin`
   - `PUT /login` with the same body
   - `OPTIONS /login` to enumerate allowed methods

5. **Direct navigation**: After a failed login, try navigating directly to
   authenticated pages (`/dashboard`, `/profile`, `/admin`). Some applications
   only check authentication on certain routes.

6. **Blank password**: Submit with the password field present but empty. Some
   LDAP-backed systems treat empty bind as anonymous bind success.

### Technique 3 — OAuth/SSO bypass

If the application uses OAuth or SSO:

1. Check for open redirect in the `redirect_uri` parameter.
2. Try removing or modifying the `state` parameter (CSRF protection).
3. Test whether the `code` parameter can be reused or is long-lived.
4. Check if the application validates the `iss` (issuer) claim.

### Decision tree

```
SQLi in login fields?
  YES ──► FINDING: SQL injection authentication bypass (Critical)
  NO  ──► Parameter removal or type juggling works?
             YES ──► FINDING: authentication logic flaw (Critical)
             NO  ──► Can access authenticated pages without login?
                       YES ──► FINDING: missing authentication check (Critical)
                       NO  ──► PASS
```

---

## PHASE 5 — Password policy assessment (WSTG-ATHN-05)

### Goal

Determine whether the application enforces a password policy strong enough to
resist offline attacks.

### Actions

1. Attempt to register (or use "change password") with each of the following
   passwords, using `send_request`:

   | Test password | What it checks |
   |---------------|----------------|
   | `a` | Minimum length enforcement |
   | `abcdef` | Short password (6 chars) |
   | `abcdefgh` | 8-char lower-only |
   | `12345678` | Digits only |
   | `ABCDEFGH` | Upper only |
   | `Password` | No digit, no special |
   | `Password1` | No special character |
   | `P@ssw0rd` | Common dictionary password with substitutions |
   | `aaaaaaaaaaaa` | Repeated characters |
   | `username` (same as the account) | Username-as-password |
   | Previous password | Password reuse allowed? |
   | `Aa1!Aa1!Aa1!Aa1!Aa1!Aa1!Aa1!Aa1!Aa1!Aa1!Aa1!Aa1!Aa1!Aa1!` | Maximum length (check for truncation) |

2. Record which passwords the application accepts and which it rejects. The
   rejection message itself is useful evidence — quote it.

3. Use `compare_responses` between accepted and rejected attempts to confirm the
   server is making the decision (not just client-side JavaScript).

4. Check if the application uses a breached-password check (e.g. HaveIBeenPwned
   API). Try `Password1!` — it appears in every breach list.

### Assessment criteria

| Requirement | Good | Weak |
|-------------|------|------|
| Minimum length | >= 10 | < 8 |
| Complexity | 3+ character classes | 1-2 classes |
| Dictionary check | Rejects `P@ssw0rd` | Accepts common passwords |
| Breach list check | Rejects known-breached | No check |
| Maximum length | >= 64 | Truncates at 20 or less |
| Password reuse | Prevents last N | Allows immediate reuse |

### Decision tree

```
Accepts passwords shorter than 8 characters?
  YES ──► FINDING: weak password policy — no minimum length (Medium)
  NO  ──► Accepts single-class passwords (e.g. all lowercase)?
             YES ──► FINDING: weak password policy — no complexity (Medium)
             NO  ──► Accepts known-breached passwords?
                       YES ──► FINDING: no breached-password check (Low)
                       NO  ──► PASS
```

---

## PHASE 6 — Brute-force protection assessment (WSTG-ATHN-06)

### Goal

Determine whether the login endpoint has rate-limiting, CAPTCHA, or other
controls to prevent credential stuffing.

### Actions

1. Submit 5 consecutive failed logins rapidly with `send_request` for the same
   username. Observe:

   - Does the response change after N failures? (CAPTCHA appears, account locked,
     IP blocked, response delayed)
   - Are response times increasing? (progressive delay / tar-pit)
   - Does a `Retry-After` or `X-RateLimit-Remaining` header appear?

2. If no protection appears after 5 attempts, submit 5 more (total 10). Still
   nothing? The endpoint likely has no brute-force protection.

3. Test bypass techniques if protection exists:

   | Protection | Bypass technique |
   |------------|-----------------|
   | IP-based rate limit | Add `X-Forwarded-For: 127.0.0.1` or rotate values |
   | Account lockout | Spray across many usernames instead (1 attempt each) |
   | CAPTCHA after N fails | Reset counter by logging in successfully, then resume |
   | Client-side CAPTCHA | Omit CAPTCHA field entirely from the request |
   | Rate limit on POST only | Try GET with query-string credentials |

4. Test `X-Forwarded-For` header bypass specifically:

   ```
   X-Forwarded-For: 1.2.3.4
   X-Forwarded-For: 10.0.0.1
   X-Real-IP: 192.168.1.1
   X-Originating-IP: 127.0.0.1
   X-Client-IP: 172.16.0.1
   ```

   If adding one of these headers resets the rate limit counter, the protection
   is bypassable.

5. Check for credential stuffing resistance: try `username:password` pairs from a
   list (not the same username each time). Per-IP rate limiting without per-account
   rate limiting is insufficient.

### Decision tree

```
No rate limiting or lockout after 10 rapid failures?
  YES ──► FINDING: no brute-force protection (High)
  NO  ──► Protection bypassable via X-Forwarded-For?
             YES ──► FINDING: rate limit bypass via header injection (High)
             NO  ──► Only per-account lockout (no per-IP rate limit)?
                       YES ──► Credential stuffing still possible (Medium)
                       NO  ──► PASS
```

---

## PHASE 7 — Account lockout mechanism (WSTG-ATHN-07)

### Goal

Assess whether the account lockout mechanism is present, effective, and not
itself exploitable as a denial-of-service vector.

### Actions

1. Using a test account, submit failed logins one at a time with `send_request`.
   Count until the account locks. Record the exact threshold. **Stop one attempt
   before you expect lockout on any account you do not control.**

2. Once locked, determine the unlock mechanism:

   | Mechanism | How to test |
   |-----------|------------|
   | Time-based (e.g. 15 min) | Wait, then try again |
   | Admin intervention | Check for admin-unlock endpoint |
   | CAPTCHA unlock | Complete the CAPTCHA |
   | Email/SMS unlock | Check for notification |
   | No lockout at all | 50+ failures, still works |

3. After unlock, check whether the failure counter resets. If it does not, the
   user is one failed attempt away from permanent lockout — a DoS vector.

4. Test lockout as a DoS: can you lock **another** user's account by sending
   failed logins for their username? If yes, this is an abuse vector for targeted
   denial-of-service.

5. Test whether a successful login between failures resets the counter.

6. Check if the lockout message reveals the lockout duration ("Your account is
   locked for 15 minutes") — this helps attackers time their attacks.

### Decision tree

```
No lockout after 20+ attempts?
  YES ──► FINDING: no account lockout (High — enables brute force)
  NO  ──► Lockout threshold < 5?
             YES ──► FINDING: lockout threshold too low — DoS risk (Medium)
             NO  ──► Can you lock other users' accounts?
                       YES ──► FINDING: lockout as denial-of-service (Medium)
                       NO  ──► Counter resets after successful login?
                                 NO  ──► FINDING: persistent failure counter (Low)
                                 YES ──► PASS
```

---

## PHASE 8 — Remember-me / persistent login (WSTG-ATHN-08)

### Goal

Assess whether the "remember me" or persistent login mechanism is
cryptographically sound and resistant to forgery.

### Actions

1. Log in with "remember me" checked. Use `get_cookies` to capture all cookies.
   Identify the persistent cookie (usually has a long `Max-Age` or `Expires`).

2. Analyze the cookie value. Use `decode` to try Base64, hex, and URL decoding:

   | Pattern | Risk |
   |---------|------|
   | `username=admin` | Trivially forgeable (Critical) |
   | `admin:md5hash` | Forgeable if hash is unsalted (High) |
   | `base64(username:timestamp)` | Forgeable, predictable (High) |
   | Long opaque random token (>= 128 bits) | Acceptable if server-validated |

3. If the cookie looks structured, try forging one for a different user:
   - Change the username portion
   - Recompute the hash if the scheme is guessable
   - Submit the forged cookie with `send_request` and see if you get that user's session

4. Use `get_sequencer_tokens` on the remember-me cookie if it looks random.
   Collect at least 100 samples. If the entropy analysis shows < 100 bits of
   effective entropy, the token is guessable.

5. Check cookie attributes:

   | Attribute | Required | Risk if missing |
   |-----------|----------|-----------------|
   | `HttpOnly` | Yes | XSS steals persistent session |
   | `Secure` | Yes | Cookie sent over HTTP |
   | `SameSite` | Lax or Strict | CSRF uses persistent auth |
   | Long expiry (> 30 days) | — | Extended attack window |

6. Test whether logging out invalidates the persistent cookie server-side. Log
   out, then replay the old cookie with `send_request`. If it still works, the
   server does not revoke remember-me tokens on logout.

### Decision tree

```
Cookie contains username/ID in cleartext or reversible encoding?
  YES ──► FINDING: forgeable remember-me cookie (Critical)
  NO  ──► Cookie is hashed but unsalted / uses weak hash?
             YES ──► FINDING: weak remember-me token (High)
             NO  ──► Entropy < 100 bits?
                       YES ──► FINDING: predictable remember-me token (High)
                       NO  ──► Cookie survives logout?
                                 YES ──► FINDING: remember-me not invalidated on logout (Medium)
                                 NO  ──► PASS
```

---

## PHASE 9 — Password reset / forgot password flaws (WSTG-ATHN-09)

### Goal

Identify flaws in the password-reset flow that could allow an attacker to reset
another user's password.

### Actions

1. **Trigger a reset** for your own test account. Use `send_request` to submit
   the forgot-password form. Capture the full flow.

2. **Inspect the reset link/token**:

   - Use `search_responses` to find the reset URL or token in the response.
   - Use `decode` to analyse the token — is it a timestamp, a sequential ID,
     a short numeric code, or a properly random token?
   - Use `get_sequencer_tokens` if you can trigger multiple resets: collect 20+
     tokens and check for predictable patterns or low entropy.

3. **Test token reuse**: After using the reset token once, try using it again.
   If it works, the token is not invalidated after use.

4. **Test token expiry**: Wait 10+ minutes and try the token. Long-lived tokens
   widen the attack window.

5. **Test for Host header poisoning**: Submit the forgot-password request with a
   modified `Host` header:

   ```
   POST /forgot-password HTTP/1.1
   Host: attacker.com
   Content-Type: application/x-www-form-urlencoded

   email=victim@example.com
   ```

   If the reset email contains a link to `attacker.com`, you can intercept reset
   tokens for any account. Also try:

   ```
   Host: legitimate.com
   X-Forwarded-Host: attacker.com
   ```

6. **Test parameter pollution**: Submit two `email` parameters:

   ```
   email=victim@example.com&email=attacker@example.com
   ```

   Some frameworks send the reset link to the second email while associating it
   with the first account.

7. **Test for information disclosure**: Does the reset response reveal whether
   the account exists? (overlaps with Phase 3 enumeration)

8. **Test the security question flow** (if present):

   - Are the questions guessable? ("What is your favourite colour?" has ~10
     realistic answers)
   - Can you brute-force the answer? Is there rate limiting?
   - Does a wrong answer lock the account or just retry?

9. **Test password reset via API**: If there is an API endpoint like
   `POST /api/reset-password`, try submitting it with another user's ID or
   email and your own new password.

### Payloads for Host header poisoning

```
Host: attacker.com
Host: legitimate.com\r\nHost: attacker.com
Host: legitimate.com:@attacker.com
Host: legitimate.com%00.attacker.com
X-Forwarded-Host: attacker.com
X-Host: attacker.com
X-Original-URL: /forgot-password
Forwarded: host=attacker.com
```

### Decision tree

```
Reset token predictable or low-entropy?
  YES ──► FINDING: predictable password reset token (Critical)
  NO  ──► Host header poisoning injects attacker domain into reset link?
             YES ──► FINDING: password reset poisoning (Critical)
             NO  ──► Token reusable after consumption?
                       YES ──► FINDING: reset token not invalidated (Medium)
                       NO  ──► Token valid for > 1 hour?
                                 YES ──► FINDING: long-lived reset token (Low)
                                 NO  ──► PASS
```

---

## PHASE 10 — Multi-factor authentication bypass (WSTG-ATHN-10)

### Goal

Determine whether MFA can be bypassed, skipped, or brute-forced.

### Actions

1. **Direct navigation past MFA**: After submitting valid credentials (Phase 1 of
   login), the server may redirect to `/mfa-verify`. Instead of submitting the
   MFA code, navigate directly to an authenticated page (`/dashboard`,
   `/account`, `/api/me`) using `send_request`. If the application serves the
   page, MFA is not enforced server-side.

2. **Manipulate the MFA response**: If the MFA step returns JSON like
   `{"mfa_required": true}`, try modifying it to `false` or removing the field.
   If the flow uses a `step=2` parameter, try changing it to `step=3`.

3. **Brute-force the MFA code**: Most TOTP codes are 6-digit. Submit multiple
   codes with `send_request`:

   ```
   000000, 000001, 000002, ... (up to 999999)
   ```

   But first check rate limiting: submit 5 wrong codes rapidly. If no lockout or
   rate limit is applied, a brute-force is feasible (999,999 attempts for a
   6-digit code at 10 requests/second = ~28 hours — practical for a 4-digit code
   at ~17 minutes).

   **Stop after 5-10 attempts** if rate limiting exists. Record the rate limit as
   a positive control.

4. **Test code reuse**: Submit a valid MFA code, complete login. Then replay the
   same code. If it works again, TOTP replay is possible.

5. **Test backup codes**: If the application provides backup codes, test:
   - Are they single-use?
   - Are they rate-limited?
   - Can they be brute-forced (often 8-digit alphanumeric)?

6. **Test MFA enrollment bypass**: Can a user disable MFA via the API without
   re-authenticating? Use `send_request`:

   ```
   POST /api/mfa/disable
   Cookie: session=authenticated_session
   ```

   Or change MFA settings:

   ```
   PUT /api/settings
   {"mfa_enabled": false}
   ```

7. **Test fallback mechanisms**: "Send code via SMS" or "Use email instead" may
   have weaker protections than TOTP. Test each channel independently.

8. **Test for leaked MFA secret**: Check if the TOTP seed/secret appears in any
   API response, HTML source, or JavaScript file using `search_responses` with
   pattern `otpauth://` or `secret=`.

### Decision tree

```
Can access authenticated pages without completing MFA?
  YES ──► FINDING: MFA bypass via direct navigation (Critical)
  NO  ──► No rate limit on MFA code submission?
             YES ──► FINDING: MFA code brute-forceable (High)
             NO  ──► MFA code reusable?
                       YES ──► FINDING: TOTP replay attack (Medium)
                       NO  ──► MFA can be disabled without re-authentication?
                                 YES ──► FINDING: MFA disable without re-auth (High)
                                 NO  ──► PASS
```

---

## PHASE 11 — Session fixation (WSTG-ATHN-11)

### Goal

Determine whether the application issues a new session identifier upon
successful authentication, or whether an attacker can fixate a known session ID
and hijack the user's authenticated session.

### Actions

1. **Capture pre-authentication session**: Use `get_cookies` before logging in.
   Record the session cookie value.

2. **Log in**: Submit valid credentials with `send_request`.

3. **Compare session IDs**: Use `get_cookies` again after login. Compare the
   session cookie value with the pre-login value.

   | Behaviour | Verdict |
   |-----------|---------|
   | Session ID changed | Correct — not fixatable |
   | Session ID unchanged | VULNERABLE to fixation |

4. **Test fixation via URL** (if session ID accepted in query string):

   ```
   https://target.com/login?PHPSESSID=attacker_controlled_value
   ```

   Log in through this URL, then check if the session cookie matches the
   attacker-controlled value.

5. **Test fixation via cookie injection**: Use `send_request` with a
   manually-set session cookie before authentication:

   ```
   Cookie: session=ATTACKER_FIXED_VALUE
   ```

   Then submit login credentials in the same session. If the post-login cookie
   is still `ATTACKER_FIXED_VALUE`, the application is vulnerable.

6. **Cross-subdomain fixation**: If the cookie's `Domain` attribute is set to
   `.example.com`, a compromised subdomain can set a session cookie for the
   main application.

7. Use `get_cookies` to check the cookie's `Domain` and `Path` attributes. A
   domain-scoped cookie (`.example.com`) is higher risk than a host-specific one.

### Decision tree

```
Session ID unchanged after login?
  YES ──► FINDING: session fixation (High)
  NO  ──► Session ID accepted from URL parameter?
             YES ──► FINDING: session fixation via URL (High)
             NO  ──► Cookie scoped to parent domain?
                       YES ──► FINDING: cross-subdomain session risk (Medium)
                       NO  ──► PASS
```

---

## Evidence and reporting

For every confirmed finding, call `add_pentest_finding` with:

1. **Title**: e.g. "Authentication Bypass via SQL Injection in Login"
2. **Severity**: Critical / High / Medium / Low
3. **The exact request** that triggers the vulnerability (method, URL, headers, body)
4. **The exact response** proving exploitation (status code, body excerpt, set cookies)
5. **Reproduction steps**: numbered steps a reviewer can follow
6. **Impact statement**: what an attacker gains (account takeover, credential
   stuffing, DoS, etc.)
7. **Remediation**: specific fix (parameterised queries, bcrypt, rate limiting, etc.)

Use `compare_responses` between the normal flow and the attack flow to generate
a clean diff for the report.

## Severity reference

| Finding | Severity |
|---------|----------|
| SQL injection auth bypass | Critical |
| Default credentials on production | Critical |
| Forgeable remember-me cookie | Critical |
| Password reset token poisoning | Critical |
| MFA bypass via direct navigation | Critical |
| No brute-force protection | High |
| MFA brute-forceable (no rate limit) | High |
| Session fixation | High |
| Predictable reset tokens | High |
| Credentials over HTTP | High |
| Weak password policy | Medium |
| Account lockout DoS | Medium |
| Username enumeration (error messages) | Low-Medium |
| Username enumeration (timing) | Low |
| Missing HSTS | Medium |
| Long-lived reset token (> 1 hour) | Low |

## Known false positives

- **Login fails with SQLi payload**: A syntax error or WAF block is not a bypass.
  Only a successful authentication (session cookie issued, dashboard loads)
  counts.
- **Different response length but same message**: Compression, dynamic tokens, or
  timestamps can alter length. Read the actual body before calling it enumeration.
- **Account locked after your testing**: This is your test account, not a finding
  about the lockout mechanism. The finding is whether you can lock *other* users.
- **CAPTCHA appears after 3 failures**: This is a positive control, not a finding.
  Only report if the CAPTCHA is bypassable (client-side only, no server
  validation, audio fallback with speech-to-text).
- **MFA code rejected**: A rejected code proves MFA is enforced. The finding is
  when it is *not* rejected, or when there is no rate limit on attempts.

## Tooling note

This methodology is designed for the Void panel tools (`send_request`,
`compare_responses`, `get_cookies`, `get_storage`, `search_responses`,
`get_payloads`, `add_pentest_finding`, `run_hybrid_scan`,
`get_sequencer_tokens`, `decode`, `hash`, `encode`). These are browser-extension
APIs, not shell commands. Do not attempt to run `curl`, `hashcat`, `hydra`,
`ffuf`, or other CLI tools. All HTTP requests go through `send_request`, all
findings go through `add_pentest_finding`, and all analysis uses the decode/encode
utilities and `compare_responses`.
