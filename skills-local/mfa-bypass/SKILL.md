# MFA Bypass

## Scope and preconditions

Applies to any application with multi-factor authentication: TOTP (Google
Authenticator, Authy), SMS OTP, email OTP, push notifications, hardware tokens,
or backup codes. The target must have an MFA-enabled account you can test with.

It does **not** cover: password-only brute force (use `auth`), OAuth token
attacks (use `oauth`), or session hijacking after MFA (use `session-management`).

## Rules of engagement

- MUST use only test accounts you control. NEVER attempt MFA bypass on accounts
  belonging to other users.
- MUST NOT trigger account lockout for other users. If testing rate limits, use
  only your own account.
- MUST stop brute force attempts after confirming the absence of rate limiting —
  demonstrate the issue with a small sample, do not exhaust the code space.
- NEVER intercept or redirect real users' MFA codes.

## Workflow

- [ ] 1. Map the MFA flow and identify all endpoints
- [ ] 2. Test response manipulation
- [ ] 3. Test step skipping
- [ ] 4. Test rate limiting and brute force
- [ ] 5. Test OTP reuse and replay
- [ ] 6. Test backup code weaknesses
- [ ] 7. Test channel and scope gaps
- [ ] 8. Test race conditions
- [ ] 9. Record findings

## Step 1: Map the MFA flow

### Goal
Understand every endpoint and parameter in the MFA verification flow.

### Actions
Complete a legitimate MFA login, capturing all requests with Void. Identify:
- The endpoint that sends the OTP (e.g., `/api/mfa/send`)
- The endpoint that verifies the OTP (e.g., `/api/mfa/verify`)
- The response on success vs. failure (status codes, JSON fields, cookies set)
- Any tokens or session identifiers passed between steps
- The post-MFA redirect or state change

Use `search_responses` to find all MFA-related endpoints. Look for parameters
like `otp`, `code`, `token`, `mfa_token`, `verification_code`.

## Step 2: Test response manipulation

### Goal
Determine if the client relies on the response to decide MFA success.

### Actions
1. Submit an invalid OTP. Capture the failure response.
2. Using Void's response interception, modify the response:
   - Change `"success": false` to `"success": true`
   - Change `"verified": false` to `"verified": true`
   - Change HTTP status from 403/401 to 200
   - Change `"error": "Invalid code"` to remove the error field
3. Check if the application grants access after the modified response.

Use `send_request` with the invalid OTP, then intercept and modify the response.

### Decision
- **Access granted after response modification** — the client trusts the
  response without server-side session validation. High finding.
- **Access denied despite modified response** — server-side state is authoritative.
  Continue to step 3.

## Step 3: Test step skipping

### Goal
Determine if MFA can be bypassed by skipping the verification step entirely.

### Actions
1. Complete step 1 of login (username/password). Note any tokens or cookies set.
2. Instead of submitting the OTP to the verification endpoint, navigate directly
   to the post-MFA page (dashboard, account settings, etc.).
3. Also try: directly call authenticated API endpoints using the session from
   step 1, without completing step 2.
4. Try accessing `/api/user/profile` or similar with just the initial auth token.

### What to look for
- Access to authenticated content without OTP verification
- A session or JWT that is fully valid before MFA completion
- Different endpoints having different MFA enforcement

## Step 4: Test rate limiting and brute force

### Goal
Determine if OTP codes can be brute-forced.

### Actions
**4-digit OTP**: 10,000 combinations. Send 20 requests rapidly with
`run_intruder_attack` using sequential codes (0000-0019). If none are rate-limited,
the full space is brute-forceable.

**6-digit OTP**: 1,000,000 combinations. Direct brute force is impractical, but
test for rate limiting. Send 10 rapid requests — if no lockout or delay after 10
failures, note it.

**Prefix oracle technique**: Some implementations return subtly different
responses for partial matches. Test:
- First digit correct vs. wrong: `1XXXXX` vs. `2XXXXX` — compare response
  times with `compare_responses`. A timing difference reduces 1M combinations
  to ~60 guesses (10 per digit position).

**Rate limit bypass techniques**:
- Add `X-Forwarded-For: 1.2.3.4` with varying IPs per request
- Change case of endpoint URL (`/API/MFA/Verify` vs. `/api/mfa/verify`)
- Add trailing slash, query parameters, URL fragments
- Use different HTTP methods (GET vs. POST)
- Add null bytes or whitespace in parameter names

## Step 5: Test OTP reuse and replay

### Goal
Determine if a valid OTP can be used more than once or after expiry.

### Actions
1. Request a valid OTP. Use it to log in successfully. Then try the same OTP
   again in a new login flow. If it works — no one-time enforcement.
2. Request an OTP. Wait for the stated expiry period (usually 30-60 seconds for
   TOTP, 5-15 minutes for email/SMS). Then submit it. If it works — no expiry.
3. Request an OTP. Request a NEW OTP. Try the FIRST OTP. If it works — old codes
   are not invalidated when new ones are issued.

## Step 6: Test backup code weaknesses

### Goal
Backup codes are often weaker than the primary MFA method.

### Actions
1. Check backup code format: typically 8-10 alphanumeric characters. If purely
   numeric and short (6-8 digits), brute force may be feasible.
2. Test rate limiting on backup code entry separately — it often has different
   (weaker) limits than OTP entry.
3. Test if backup codes are returned in API responses, visible in page source,
   or stored in client-accessible storage.
4. Test if backup codes regenerate without requiring current MFA — this would
   allow an attacker with just the password to disable MFA.

## Step 7: Test channel and scope gaps

### Goal
Find MFA enforcement gaps across different channels and operations.

### Actions
**Channel gaps**:
- Request OTP via SMS, then via email — are both valid simultaneously?
- If the app supports both TOTP and SMS, does completing one invalidate the other?
- Is MFA enforced on API endpoints the same as web endpoints?
- Is MFA enforced on mobile app login the same as web login?

**Scope gaps** — MFA on login but not on:
- Password change
- Email/phone change (leads to MFA lockout bypass)
- API key generation
- Session management (delete other sessions)
- Account deletion
- Admin actions
- OAuth authorization grants

Test each sensitive operation after MFA login — remove the MFA session marker
from the request and see if the operation still proceeds.

## Step 8: Test race conditions

### Goal
Submit the same valid OTP simultaneously to create multiple authenticated sessions.

### Actions
1. Obtain a valid OTP.
2. Prepare 10-20 identical verification requests with the same OTP.
3. Use `run_intruder_attack` in concurrent mode to send them simultaneously.
4. Check how many succeed — if more than one, the OTP is consumed non-atomically.

This matters for limit-1-per-user features: "only one active session" bypassed
by racing MFA verification.

## Step 9: Record the finding

Use `add_pentest_finding` with:
- The specific bypass technique that worked
- The original failed MFA response and the successful bypass
- Steps to reproduce including any timing requirements
- Impact: what an attacker gains by bypassing MFA

## Known false positives

- Response modification that changes the UI but does not grant API access — the
  client may show a dashboard but API calls still fail. Test API access, not UI.
- Step skip that lands on a login page or error page, not authenticated content.
- Rate limiting that kicks in after your test window — always verify with enough
  attempts (at least 10-20) before claiming no rate limit.
- Backup code entry that uses different rate limits by design — this may be
  intentional, not a bypass.

## Reminder

MFA bypass is about finding the gap between "MFA exists" and "MFA is enforced on
every path." The three highest-value findings are: **step skip** (MFA never
required for certain paths), **no rate limit on OTP** (brute force feasible),
and **scope gaps** (MFA on login but not on password/email change). Always test
the scope gaps — they are the most commonly missed.
