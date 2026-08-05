# OAuth / OpenID Connect Testing

## Scope and preconditions

Applies to any application implementing OAuth 2.0 or OpenID Connect for
authentication or authorization: social login (Google, Facebook, GitHub),
SSO integrations, API authorization, or any endpoint exchanging authorization
codes or tokens. Covers Authorization Code, Implicit, Device, and Client
Credentials flows.

It does **not** cover: SAML SSO (use `saml`), JWT token format attacks outside
OAuth (use `jwt`), or session management after OAuth login (use `session-management`).

## Rules of engagement

- MUST use only test accounts you control on both the application and the OAuth
  provider.
- NEVER intercept or redirect authorization flows for accounts you do not own.
- MUST NOT register rogue OAuth applications on the provider unless authorized.
- MUST handle tokens carefully — revoke test tokens after testing.

## Workflow

- [ ] 1. Map the OAuth flow and identify grant type
- [ ] 2. Test redirect_uri validation
- [ ] 3. Test state parameter (CSRF protection)
- [ ] 4. Test PKCE enforcement
- [ ] 5. Test token handling and leakage
- [ ] 6. Test scope escalation
- [ ] 7. Test account linking attacks
- [ ] 8. Test implicit flow token theft
- [ ] 9. Test device flow abuse
- [ ] 10. Record findings

## Step 1: Map the OAuth flow

### Goal
Identify the OAuth implementation details.

### Actions
Use `search_responses` to find OAuth-related endpoints:
- Authorization: `/authorize`, `/oauth/authorize`, `/auth`
- Token exchange: `/token`, `/oauth/token`, `/api/oauth/callback`
- JWKS: `/.well-known/jwks.json`, `/.well-known/openid-configuration`
- Callback: `/callback`, `/auth/callback`, `/login/callback`

Capture a full login flow and identify:
- Grant type: Authorization Code, Implicit, Device, Client Credentials
- `response_type`: `code` (auth code), `token` (implicit), `id_token`
- `redirect_uri`: the registered callback URL
- `state`: CSRF token (if present)
- `code_challenge` / `code_challenge_method`: PKCE (if present)
- `scope`: requested permissions
- `nonce`: replay protection for OpenID Connect

## Step 2: Test redirect_uri validation

### Goal
Bypass redirect_uri restrictions to steal authorization codes or tokens.

### 11 bypass techniques

| # | Technique | Payload |
|---|---|---|
| 1 | Path traversal | `/callback/../evil` |
| 2 | Double URL encode | `/callback%252f..%252fevil` |
| 3 | @ bypass | `https://legit.com@evil.com/callback` |
| 4 | Fragment injection | `https://legit.com/callback#@evil.com` |
| 5 | Backslash | `https://legit.com\@evil.com/callback` |
| 6 | Whitespace | `https://legit.com%20.evil.com/callback` |
| 7 | Subdomain match bypass | `https://evil-legit.com/callback` if check is `contains('legit.com')` |
| 8 | URL-encoded dots | `https://legit%2Ecom.evil.com/callback` |
| 9 | Regex bypass | `https://legitimate.com/callback` if regex is `/legit.com/` (unescaped dot) |
| 10 | Parameter pollution | `?redirect_uri=legit&redirect_uri=evil` |
| 11 | Open redirect chain | `redirect_uri=https://legit.com/redirect?url=https://evil.com` |

Test each with `send_request`. Use `compare_responses` to see how the redirect_uri
is reflected. The authorization server may validate differently than the application.

### Impact
A bypassed redirect_uri allows stealing the authorization code (in auth code flow)
or the token directly (in implicit flow). Combined with a legitimate-looking phishing
page, this is a Critical ATO.

## Step 3: Test state parameter

### Goal
Determine if CSRF protection exists on the OAuth callback.

### Actions
1. Start an OAuth login flow. Note the `state` parameter value.
2. Complete the flow. Remove the `state` parameter from the callback URL.
   If login succeeds — state is not validated. CSRF attack possible.
3. Use a different `state` value. If accepted — state is not bound to session.
4. Reuse the same `state` in a different browser session. If accepted — state
   is not session-bound.

### Impact
Without state validation, an attacker can initiate an OAuth flow, get the callback
URL with their authorization code, and trick the victim into visiting it. The
victim's account gets linked to the attacker's OAuth account.

## Step 4: Test PKCE enforcement

### Goal
Determine if Proof Key for Code Exchange prevents code interception.

### Actions
1. Normal flow: send `code_challenge` in authorization request, `code_verifier`
   in token exchange.
2. Remove PKCE entirely: no `code_challenge`, no `code_verifier`. If the flow
   succeeds — PKCE not enforced.
3. Wrong verifier: correct `code_challenge` but different `code_verifier`.
   If it succeeds — PKCE not validated.
4. Downgrade to plain: change `code_challenge_method` from `S256` to `plain`.
   If accepted — weaker protection.

### Impact
Without PKCE, an intercepted authorization code (via redirect_uri bypass, Referer
leak, or network interception) can be exchanged for tokens.

## Step 5: Test token handling and leakage

### Goal
Find places where OAuth tokens leak.

### Actions
**Referer header leakage**: After callback, check if subsequent requests to
third-party domains include the callback URL (with code/token) in Referer.

**Token in URL**: Implicit flow puts tokens in fragments. Check if the page
loads external resources that receive the fragment.

**Token in server logs**: Error pages or debug endpoints may reflect the token.

**Token lifetime**: Request a token and note `expires_in`. Is it too long?
(Days or weeks for an access token is excessive.)

**Refresh token rotation**: Use refresh token, get new access token. Can you
reuse the old refresh token? (It should be invalidated.)

## Step 6: Test scope escalation

### Goal
Obtain higher permissions than the application requests.

### Actions
1. Note the original `scope` parameter.
2. Add higher scopes: `scope=email profile admin openid`.
3. If additional scopes are granted — scope not restricted by app registration.
4. Test scope modification during token refresh with broader scope.
5. Test if the token works for APIs beyond its intended scope.

## Step 7: Test account linking attacks

### Goal
Link an attacker's OAuth identity to a victim's application account.

### Actions
1. Start OAuth linking flow as attacker.
2. Intercept the callback URL with authorization code. Don't complete.
3. Craft a page that forces victim's browser to visit your callback URL.
4. If state/CSRF is missing, victim's account links to attacker's OAuth.
5. Attacker logs in via OAuth as victim.

### Pre-authentication linking
1. Register with victim's email (unverified).
2. Link attacker's OAuth account.
3. Log in via OAuth — bypasses email verification.

## Step 8: Test implicit flow token theft

### Goal
Steal tokens from URL fragment in implicit flow.

### Technique
If `response_type=token` is supported:
1. Find an open redirect on the registered domain.
2. Set `redirect_uri` to the open redirect.
3. Token arrives in fragment: `https://evil.com/#access_token=...`
4. Attacker's JavaScript reads `location.hash`.

Even if the app uses auth code flow, test if implicit flow is also accepted
(`response_type=token`). Many servers support both.

## Step 9: Test device flow abuse

### Goal
Exploit device authorization flow for phishing.

### Technique
1. Attacker: `POST /device/code` → gets `user_code` and `device_code`.
2. Attacker sends `user_code` + verification URL to victim.
3. Victim enters code, authorizes the "device".
4. Attacker polls `POST /token` with `device_code` → victim's token.

Check: is there clear disclosure of what permissions are granted?
Is the `user_code` short enough to brute force (< 8 chars)?
Is the polling interval enforced?

## Step 10: Record the finding

Use `add_pentest_finding` with:
- The specific OAuth vulnerability
- The authorization request showing the attack
- The callback showing the stolen code/token
- Impact: ATO, unauthorized API access, scope escalation

## Known false positives

- redirect_uri validated at token exchange even if not at authorization — the
  code is useless without matching redirect_uri. Still test both steps.
- State missing but callback uses SameSite cookies or other CSRF protection.
- Scope granted in response but token actually has restricted permissions.
- Device code that works once — correct behavior, not a vulnerability.

## Reminder

OAuth's top three bugs: **redirect_uri bypass** (#1 OAuth finding), **missing
state** (CSRF), and **token leakage** (Referer, logs, URL). Test redirect_uri
first. Always check if implicit flow is enabled even when the app uses auth code.
The chain that matters: redirect_uri bypass + phishing = ATO.
