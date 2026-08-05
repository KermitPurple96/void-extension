# Account Takeover (ATO)

## Scope and preconditions

Applies to any application with user accounts. ATO is not a single vulnerability
but a taxonomy of paths — each path exploits a different weakness in the
authentication, recovery, or account management flow. This skill provides a
systematic checklist of all 9 known ATO paths.

It does **not** cover: MFA bypass specifically (use `mfa-bypass`), OAuth token
attacks (use `oauth`), SAML assertion manipulation (use `saml`), or session
management flaws (use `session-management`).

## Rules of engagement

- MUST use only test accounts you control.
- MUST NOT attempt password reset for accounts you do not own.
- MUST NOT send phishing emails to real users.
- NEVER exfiltrate real user credentials. Demonstrate with test accounts only.
- MUST stop testing a path as soon as it is confirmed — do not escalate to
  accessing other users' data.

## Workflow

- [ ] 1. Map all account management endpoints
- [ ] 2. Test password reset poisoning (Host header)
- [ ] 3. Test reset token leakage (Referer)
- [ ] 4. Test reset token predictability
- [ ] 5. Test token expiry and invalidation
- [ ] 6. Test email/phone change without re-auth
- [ ] 7. Test OAuth account linking
- [ ] 8. Test session fixation
- [ ] 9. Test credential stuffing protections
- [ ] 10. Record findings

## Step 1: Map account management endpoints

### Goal
Identify all endpoints involved in authentication and account management.

### Actions
Use `get_endpoints` and `search_responses` to find:
- Login: `/login`, `/api/auth/login`, `/api/v1/session`
- Password reset: `/forgot-password`, `/reset-password`, `/api/auth/reset`
- Email change: `/settings/email`, `/api/user/email`
- Phone change: `/settings/phone`, `/api/user/phone`
- OAuth linking: `/auth/google/callback`, `/auth/github/link`
- Session management: `/settings/sessions`, `/api/auth/sessions`
- Account deletion: `/settings/delete`, `/api/user/delete`

Map the flow for each: what parameters are sent, what tokens are generated,
what validations occur.

## Step 2: Password reset poisoning

### Goal
Hijack the password reset link by manipulating the Host header.

### Technique
1. Request a password reset for your test account.
2. Intercept the request. Change the `Host` header to `evil.com`:
   ```
   POST /forgot-password HTTP/1.1
   Host: evil.com
   
   email=victim@target.com
   ```
3. If the application generates reset links using the Host header, the email
   will contain `https://evil.com/reset?token=XXXXX`.
4. Verify by checking if the reset email contains the attacker's domain.

Also test: `X-Forwarded-Host: evil.com`, `X-Host: evil.com`,
`Forwarded: host=evil.com`, `X-Original-URL`.

Use `send_request` with the modified Host header. Check if the reset link
in the email uses the injected domain.

### Decision
- **Reset link uses injected host** — Critical ATO. An attacker sends a reset
  for the victim's email, the victim clicks the link (which goes to evil.com),
  and the attacker captures the token.
- **Host header ignored** — Continue to path 3.

## Step 3: Token leakage via Referer

### Goal
Determine if password reset tokens leak through the Referer header.

### Actions
1. Generate a password reset link for your test account.
2. Visit the reset page. Check if the page loads any external resources
   (analytics scripts, CDN assets, social media widgets, images).
3. If external resources are loaded, the Referer header sent to those domains
   will contain the reset URL including the token.

Use `search_responses` on the reset page to find external resource references.
Look for third-party domains in `<script src>`, `<img src>`, `<link href>`.

### What to look for
- External JavaScript loaded on the reset page
- Tracking pixels or analytics
- CDN resources on different domains
- `Referrer-Policy` header missing or set to `unsafe-url` or `no-referrer-when-downgrade`

## Step 4: Token predictability

### Goal
Determine if reset tokens are guessable.

### Actions
1. Generate 5 reset tokens for the same account. Collect them all.
2. Analyze patterns:
   - Sequential or incrementing? (e.g., `token1001`, `token1002`)
   - Timestamp-based? (decode base64, check for epoch values)
   - Short or low-entropy? (< 20 characters, numeric only)
   - UUIDv1? (decode — contains timestamp and MAC address)
3. Use `compare_responses` to diff the tokens and find the changing parts.

### Decision
- **Tokens are sequential or timestamp-derived** — brute-forceable. Critical.
- **Tokens are UUIDv1** — predictable with enough samples. High.
- **Tokens are UUIDv4 or long random** — not practically guessable. Continue.

## Step 5: Token expiry and invalidation

### Goal
Determine if tokens have proper lifecycle management.

### Actions
1. Generate a reset token. Use it to reset the password. Try using it again.
   If it works — no single-use enforcement.
2. Generate a reset token. Wait 24+ hours. Try using it.
   If it works — no expiry.
3. Generate a reset token. Change the password through normal settings.
   Try the old reset token. If it works — password change does not
   invalidate outstanding reset tokens.
4. Generate two reset tokens in sequence. Try the first one.
   If it works — new token does not invalidate the previous one.

## Step 6: Email/phone change without re-auth

### Goal
Determine if an attacker with session access can take over an account
by changing the recovery email/phone.

### Actions
1. Log in to a test account. Navigate to email change.
2. Change the email WITHOUT re-entering the current password.
   If allowed — attacker with any session access (XSS, CSRF, shared computer)
   can silently change the email.
3. After changing email, request a password reset. The reset link goes to the
   attacker's email — full ATO.

This is the most common ATO chain: **XSS → email change (no re-auth) →
password reset → full ATO**.

Also test phone number change — same principle.

## Step 7: OAuth account linking

### Goal
Link an attacker's OAuth account to a victim's application account.

### Actions
1. Log in as your test user (victim). Note the OAuth linking endpoint.
2. Start the OAuth linking flow. Intercept the callback URL with the
   authorization code.
3. Do NOT complete the flow. Instead, craft a URL/page that makes the VICTIM
   visit the callback URL with YOUR authorization code.
4. If CSRF protection is absent on the OAuth linking endpoint, the victim's
   account gets linked to the attacker's OAuth account.
5. The attacker can now log in via OAuth as the victim.

### What to look for
- Missing `state` parameter in OAuth linking flow (CSRF)
- Linking endpoint accessible without re-authentication
- No confirmation step before linking

## Step 8: Session fixation

### Goal
Determine if the session ID rotates on login.

### Actions
1. Visit the application and note your session cookie (before login).
2. Log in. Check if the session cookie value changed.
   If the same cookie value persists — session fixation.
3. An attacker who can set a cookie (via XSS, subdomain, or HTTP injection)
   can set a known session ID, wait for the victim to log in, and hijack
   the now-authenticated session.

## Step 9: Record findings

Use `add_pentest_finding` with:
- The specific ATO path that succeeded
- Full request/response chain showing the attack
- Impact statement: what the attacker gains (full account control, partial access)
- Chain documentation if multiple steps are required

## Known false positives

- Password reset Host header reflected in the response but NOT in the email —
  the response reflection is informational, the email is what matters.
- Email change that requires verification on the NEW email — this is a valid
  control. ATO requires the change to take effect immediately.
- OAuth linking that requires re-authentication — this is the correct behavior.
- Session cookie that changes value due to rotation but the old value is also
  still valid — this is a session invalidation issue, not fixation.

## Reminder

ATO has 9 paths but two dominate real-world bounty reports: **password reset
poisoning via Host header** and **email change without re-auth**. Test those
first. The chain that matters most: any session access (XSS, CSRF, shared
computer) → email change → password reset → full ATO. Always verify the
complete chain, not just individual links.
