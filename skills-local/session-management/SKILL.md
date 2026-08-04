---
name: "session-management"
description: "Session Management Testing — WSTG-SESS-01 through SESS-09: fixation, puzzling, logout, timeout, cookie attributes, session ID entropy"
version: "1.0.0"
author: "void-extension"
tags: ["pentest", "session", "fixation", "cookies", "logout", "timeout", "entropy", "httponly", "samesite", "wstg-sess"]
trigger_patterns:
  - "/session-management"
  - "/session"
  - "session management"
  - "session fixation"
  - "session puzzling"
  - "test session"
  - "cookie attributes"
  - "session timeout"
  - "session entropy"
  - "logout testing"
---

# Session Management Testing

Session management is the mechanism by which a web application recognises a
returning authenticated user across multiple HTTP requests. Flaws in this
mechanism are among the most impactful vulnerabilities: session fixation allows
an attacker to pre-set a victim's session ID; weak session IDs allow
brute-force or prediction; improper logout leaves tokens valid after the user
believes they have signed out.

This skill covers WSTG-SESS-01 through WSTG-SESS-09 in order.

## Scope and preconditions

Requires at least one test account. Some tests (fixation, puzzling) benefit from
two accounts in different roles. Session entropy testing requires the ability to
collect many session tokens — use `get_sequencer_tokens` to automate this.

## Rules of engagement

- Collect the minimum number of real user sessions needed to demonstrate entropy
  weaknesses. Never collect or store session tokens belonging to real users.
- Fixation and puzzling tests target your own test accounts only.
- Record every confirmed flaw with `add_pentest_finding`.

## Workflow

- [ ] SESS-01: Analyse session token format and transmission
- [ ] SESS-02: Test cookie attributes
- [ ] SESS-03: Test session fixation
- [ ] SESS-04: Test session puzzling / namespace collision
- [ ] SESS-05: Test CSRF (see `csrf` skill for full methodology)
- [ ] SESS-06: Test logout functionality
- [ ] SESS-07: Test session timeout
- [ ] SESS-08: Test session variable overflow
- [ ] SESS-09: Test for session token in URL
- [ ] Entropy analysis with sequencer

## SESS-01: Session token analysis

### Locate session tokens

Use `get_cookies` to list all cookies set after login. Identify the session
cookie — it is typically named `PHPSESSID`, `JSESSIONID`, `ASP.NET_SessionId`,
`sessionid`, `session`, `sid`, `auth`, `token`, or similar.

Also check `get_storage` for tokens stored in `localStorage` or `sessionStorage`
(SPAs and mobile-style frontends often use `Authorization: Bearer <token>` from
storage rather than cookies).

### Examine token structure

Use `search_responses` to find the `Set-Cookie` header or the storage assignment.
Note the token value and check:

| Property | What to look for |
|----------|-----------------|
| **Length** | Short tokens (< 128 bits / 16 bytes hex / 22 base64 chars) are weak |
| **Charset** | Very small charset (digits only, hex only) reduces entropy |
| **Pattern** | Sequential numbers, timestamps, or usernames embedded |
| **Format** | JWT (`eyJ...`) — test with `jwt` skill instead |
| **Encoding** | Base64 decoded may reveal internal structure |

A token like `12345678`, a username hash, or `user_id + timestamp` in base64 is
a **Critical** finding (predictable session ID — WSTG-SESS-01).

### Check token transmission

Use `send_request` to make an authenticated request and verify:
- Session token is sent in `Cookie:` header, not in the URL query string (see
  SESS-09 below).
- Token is not logged by the application (check error pages and logs if
  accessible).

## SESS-02: Cookie attributes

For each session cookie identified in SESS-01, verify all five security
attributes. Use `get_cookies` to read them, then cross-reference
`get_response_headers` on the `Set-Cookie` response.

### Attribute checklist

| Attribute | Required? | Attack if missing |
|-----------|-----------|-------------------|
| `HttpOnly` | Yes | JavaScript `document.cookie` steals token; XSS → ATO |
| `Secure` | Yes (HTTPS) | Token sent over plaintext HTTP; network intercept |
| `SameSite=Strict` or `Lax` | Yes | CSRF attacks (see `csrf` skill) |
| `Domain=` | Minimal scope | Subdomains can read parent cookies if set too broadly |
| `Path=/` | Scope as narrow as auth requires | Over-broad path scope |
| `__Secure-` prefix | Recommended | Enforces `Secure` at browser level |
| `__Host-` prefix | Recommended | Enforces `Secure` + no `Domain` + `Path=/` |

**Test: is `HttpOnly` missing?**

Use `eval_page`:
```javascript
document.cookie
```

If the session cookie appears in the result, `HttpOnly` is absent — **High**.

**Test: is `Secure` missing?**

Use `send_request` to make the same request over `http://` (not `https://`). If
the session cookie is transmitted, `Secure` is missing — **High**.

**Test: SameSite**

Missing `SameSite` on a session cookie that performs state-changing actions is a
CSRF risk. Test cross-origin form submission as described in the `csrf` skill.

**Test: Broad Domain attribute**

If `Domain=.example.com`, any subdomain (including user-controlled ones) can
read the cookie. Combine with subdomain takeover for Critical impact.

## SESS-03: Session fixation (WSTG-SESS-03)

Session fixation occurs when the application does not issue a new session token
after authentication, allowing an attacker to pre-set the token.

### Test procedure

1. **Get a pre-auth session**: Use `send_request` to fetch the login page
   without credentials. Note the `Set-Cookie` session token value — call it
   `TOKEN_A`.

2. **Authenticate using that token**: Use `send_request` with `Cookie: session=TOKEN_A`
   and valid credentials in the POST body.

3. **Check the post-auth session**: Look at the `Set-Cookie` header in the login
   response. If it is absent (no new token issued) or the value is still
   `TOKEN_A`, session fixation exists.

4. **Exploit scenario**: An attacker who knows `TOKEN_A` (e.g., sets it via XSS
   on an `http://` subdomain, or via a `session` query parameter if the app
   accepts it) can hijack the session the moment the victim logs in.

**Severity**: High (attacker must induce victim to use the known token, often
via XSS or subdomain).

### Test: token accepted from URL

Some applications accept session tokens in the query string for "remember me"
or password-reset links:
```
GET /login?PHPSESSID=ATTACKERTOKEN
```

Use `send_request` with the token in the URL instead of a cookie. If the app
sets a cookie matching the URL token, the fixation vector exists.

## SESS-04: Session puzzling / namespace collision (WSTG-SESS-04)

Session puzzling occurs when the application uses the same session variable name
for different purposes in different states, allowing one state to satisfy the
authentication check of another.

### Test procedure

**Multi-step flow attack:**

1. Identify a multi-step process (checkout, password reset, admin action) that
   stores a state variable in the session (e.g., `step=2_confirmed`).

2. Complete step 1 of the privileged flow (e.g., confirm email for password
   reset).

3. In a separate tab, start the multi-step checkout or another flow that sets
   the same session variable.

4. Return to the privileged flow and skip to a later step via direct URL.

If the application uses `$_SESSION['verified'] = true` for both "email verified"
and "payment authorised", completing one verification may unlock the other.

**Cross-application collision:**

If the same session storage (Redis key namespace, PHP session directory) is
shared across multiple applications on the same domain:
- Log in to a low-privilege app.
- Reuse the session token on the high-privilege app.
- Check if the session is accepted (missing application identifier in session).

## SESS-06: Logout testing (WSTG-SESS-06)

A complete logout must:
1. Invalidate the session server-side.
2. Clear the session cookie in the browser.
3. Prevent the old token from being reused.

### Test procedure

1. Log in and note the session token (`get_cookies`).
2. Click logout.
3. Immediately use `send_request` with the old session token to access an
   authenticated endpoint (e.g., `/profile`, `/api/user`).

**Expected**: 401, 403, or redirect to login.

**Failure modes**:

| Response | Finding |
|----------|---------|
| 200 with user data | Session not invalidated server-side — **High** |
| 200 but cookie cleared | Client-side only logout — **High** |
| 302 to login but token still valid on API | Frontend logout without backend invalidation — **High** |

### Test: concurrent sessions

Log in from two different sessions (two browser profiles). Log out from one.
Check if the other session is still valid. If the application does not provide
"log out all sessions", test whether a single logout invalidates all.

### Test: password change invalidates sessions

1. Log in → get `SESSION_A`.
2. Change the password (use `send_request` or the UI).
3. Use `send_request` with `SESSION_A` to access `/profile`.

If the session remains valid after a password change, an attacker who stole a
token retains access indefinitely — **High**.

## SESS-07: Session timeout (WSTG-SESS-07)

### Absolute timeout

The session must expire after a fixed wall-clock time regardless of activity.

**Test**: Log in. Use `get_sequencer_tokens` to keep a session active by sending
a heartbeat request every minute. After 30–60 minutes, check whether the
session is still valid even though it has been in continuous use.

If there is no absolute timeout, the session is valid indefinitely — **Medium**.

### Idle timeout

The session must expire after a period of inactivity.

**Test**: Log in. Wait (do not send requests) for the application's stated idle
timeout + 2 minutes. Then use `send_request` with the old token. If the session
is still valid, the idle timeout is not enforced — **Medium**.

### Test: Secure and HttpOnly on session timeout response

When the session expires and the server clears the cookie, verify the
`Set-Cookie: session=; Max-Age=0` response also carries `HttpOnly` and `Secure`.

## SESS-08: Session variable overflow (WSTG-SESS-08)

Test whether extremely large or malformed values stored in the session cause
server-side errors or allow session memory exhaustion.

Use `send_request` to submit an extremely long value for every field that the
application stores in session state (e.g., language preference, cart contents,
search filters):

```
GET /search?q=AAAAAAAAAA...(8000 chars)...AAAA
```

Look for:
- 500 errors (session storage overflow).
- Truncation that breaks the session ID itself.
- Different session behaviour after the large value (session cleared = DoS vector).

## SESS-09: Session token in URL (WSTG-SESS-09)

Session tokens in URLs appear in:
- Browser history.
- Server access logs.
- `Referer` headers sent to third-party resources.
- Reverse-proxy logs.

**Detection**: Use `search_responses` to scan all request URLs in captured
traffic for the session token value. Also check:

```
Referer: https://target.com/page?PHPSESSID=SECRETTOKEN
```

If the session token appears in any URL, record it as **High**.

**Test: token passed as GET parameter**

```
GET /app?session=TOKEN&redirect=https://target.com/dashboard
```

Some apps accept the session token in query string for "deep link" functionality.

## Entropy analysis with get_sequencer_tokens

Use `get_sequencer_tokens` to collect 100+ session tokens. The tool sends the
login request repeatedly and extracts the Set-Cookie value each time.

Analyse the collected tokens for:

**1. Sequential patterns**
Sort the tokens. If numeric part increments by 1 or a small value, the ID is
guessable — **Critical**.

**2. Time-based encoding**
Convert hex tokens to decimal and check if the values align with Unix timestamps.
If so, entropy is only in the timestamp — **Critical**.

**3. Username / user-ID embedding**
Base64-decode the tokens. If the decoded value contains the username, email, or
user ID, the ID is predictable and also leaks PII — **High**.

**4. Statistical analysis**
Count unique characters, bit patterns, and length variance. A session ID with
less than 128 bits of effective entropy fails the OWASP minimum — **High**.

**5. Bias detection**
Check if certain character positions are always the same value or from a very
small set. Fixed positions reduce effective entropy.

## Cookie security summary

Quick reference for reporting:

| Attribute missing | CVSS Base | Report title |
|-------------------|-----------|--------------|
| `HttpOnly` + XSS exists | 8.8 (High) | Session Hijacking via XSS — Cookie lacks HttpOnly |
| `Secure` | 6.5 (Medium) | Session Cookie Transmitted Over HTTP |
| `SameSite` | 6.5 (Medium) | CSRF via Missing SameSite Cookie Attribute |
| Session fixation | 8.1 (High) | Session Fixation — No Token Rotation at Login |
| No server-side logout | 8.1 (High) | Session Token Not Invalidated After Logout |
| Short / predictable tokens | 9.8 (Critical) | Predictable Session ID — Brute-forceable |

## Tooling note

This methodology uses Void panel tools: `get_cookies` to inspect cookie
attributes, `get_storage` to check localStorage/sessionStorage, `send_request`
to replay requests with specific tokens, `compare_responses` to diff
authenticated vs unauthenticated responses, `get_sequencer_tokens` to collect
tokens for entropy analysis, `get_response_headers` to inspect Set-Cookie
headers, `eval_page` to test HttpOnly via JavaScript, and `add_pentest_finding`
to record confirmed session flaws. These are browser-extension APIs, not shell
commands — do not attempt to run CLI tools.
