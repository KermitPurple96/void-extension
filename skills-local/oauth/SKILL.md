---
name: "oauth"
description: "OAuth 2.0 / OpenID Connect Security Testing"
version: "1.0.0"
author: "void-extension"
tags: ["pentest", "oauth", "oidc", "authorization", "token", "pkce", "redirect-uri", "jwk"]
trigger_patterns:
  - "/oauth"
  - "test oauth"
  - "test oidc"
  - "oauth security"
  - "test redirect_uri"
  - "test authorization flow"
  - "pkce bypass"
  - "token theft"
---

# OAuth 2.0 / OIDC Security Testing Methodology

Test OAuth 2.0 and OpenID Connect implementations for redirect URI manipulation,
state parameter CSRF, PKCE bypass, authorization code replay, token theft via
referrer, scope escalation, and JWK/JWKS abuse.

## Scope and preconditions

Applies to any application that uses OAuth 2.0 (authorization code, implicit,
client credentials) or OpenID Connect for authentication/authorization — both as
a client (relying party) and as a provider (authorization server).

You need at least one valid OAuth client registration and the ability to observe
the authorization flow (redirects, tokens, codes).

It does **not** cover: JWT cryptographic attacks in isolation (use `jwt`), or
general session management (use `auth`).

## Rules of engagement

- NEVER use stolen tokens to access real user data. Prove token theft by
  demonstrating the redirect to an attacker-controlled URI, then stop.
- Record every authorization URL, redirect, and token exchange with
  `add_pentest_finding`.
- In mode `ask`: confirm the flaw and stop before accessing protected resources.

## Workflow

- [ ] 1. Map the OAuth flow (grant type, endpoints, parameters)
- [ ] 2. Test redirect_uri manipulation
- [ ] 3. Test state parameter (CSRF)
- [ ] 4. Test PKCE enforcement
- [ ] 5. Test authorization code handling
- [ ] 6. Test token security
- [ ] 7. Test scope escalation
- [ ] 8. Test JWK/JWKS abuse

## Step 1: Map the OAuth flow

Use `search_responses` and `get_endpoints` to find OAuth-related endpoints:

- `/authorize`, `/oauth/authorize`, `/auth`
- `/token`, `/oauth/token`
- `/callback`, `/oauth/callback`
- `/.well-known/openid-configuration`
- `/.well-known/jwks.json`

Use `send_request` to fetch `/.well-known/openid-configuration` — it reveals
all endpoints, supported grant types, and token signing algorithms.

Identify: grant type (code, implicit, hybrid), client_id, redirect_uri,
response_type, scope, and whether PKCE is used.

## Step 2: redirect_uri manipulation

The most impactful OAuth attack. If the authorization server does not strictly
validate redirect_uri, an attacker can steal authorization codes or tokens.

### Payloads

Use `send_request` to submit authorization requests with modified redirect_uri:

| Technique | Payload |
|-----------|---------|
| Open redirect on client | `redirect_uri=https://client.com/callback/../redirect?url=https://evil.com` |
| Subdomain | `redirect_uri=https://evil.client.com/callback` |
| Path traversal | `redirect_uri=https://client.com/callback/../../attacker-page` |
| Parameter injection | `redirect_uri=https://client.com/callback?next=https://evil.com` |
| Port manipulation | `redirect_uri=https://client.com:8443/callback` |
| URL encoding | `redirect_uri=https://client.com%40evil.com/callback` |
| Fragment | `redirect_uri=https://client.com/callback#@evil.com` |
| Localhost | `redirect_uri=http://localhost/callback` |
| Exact match bypass | `redirect_uri=https://client.com/callbackevil` |
| Removed entirely | Omit redirect_uri — does the server use a default? |

### Detection

If the authorization server redirects to your modified URI with a `code=` or
`access_token=` parameter, the redirect_uri validation is broken.

Use `compare_responses` between a valid and invalid redirect_uri to see if error
handling differs (some servers silently accept bad URIs).

## Step 3: State parameter CSRF

### Actions

1. Initiate an OAuth flow and capture the authorization URL. Note the `state`
   parameter.

2. Test without state: remove the `state` parameter entirely from the
   authorization URL. If the flow completes, the application is vulnerable to
   OAuth CSRF — an attacker can force a victim to link the attacker's account.

3. Test state reuse: complete a flow, capture the state value, then replay it
   in a new flow. If accepted, state is not single-use.

4. Test state predictability: collect 10+ state values and look for patterns
   (sequential, timestamp-based, short values).

## Step 4: PKCE enforcement

PKCE (Proof Key for Code Exchange) prevents code interception.

1. Initiate a flow with `code_challenge` and `code_challenge_method=S256`.
2. At the token exchange, omit `code_verifier`. If the token is issued, PKCE
   is not enforced.
3. Send a wrong `code_verifier`. If the token is still issued, PKCE validation
   is broken.
4. Try `code_challenge_method=plain` — if accepted, an attacker who intercepts
   the challenge can derive the verifier.

## Step 5: Authorization code handling

### Code replay

1. Complete an OAuth flow and capture the authorization code.
2. Exchange it for a token via `send_request`.
3. Replay the same code in another token request. If a second token is issued,
   codes are not single-use.

### Code lifetime

Wait 60+ seconds before exchanging. Long-lived codes widen the attack window.

### Code-to-token binding

Exchange a code obtained for client_A using client_B's credentials. If it works,
codes are not bound to clients.

## Step 6: Token security

### Access token leakage

Use `search_responses` to check if tokens appear in:
- URL query strings (Referer header leakage)
- Browser history
- Server logs (if observable)
- Error messages

### Token in implicit flow

If `response_type=token`, the access token is in the URL fragment. Check if the
application has open redirects that could leak it via Referer.

### Refresh token rotation

Exchange a refresh token, then try reusing the old one. If it still works,
refresh tokens are not rotated — a leaked token gives indefinite access.

### Token scope

Request a token with `scope=openid profile email`. Then use the token to access
resources outside that scope. If it works, scope enforcement is broken.

## Step 7: Scope escalation

1. Request authorization with elevated scope:
   `scope=openid profile email admin` — does the server grant it?

2. Modify the scope in the token request (after receiving the code):
   `grant_type=authorization_code&code=X&scope=admin`

3. Check if downscoped tokens can be upgraded by requesting a new token with
   broader scope using a refresh token.

## Step 8: JWK/JWKS abuse

If tokens are JWTs signed with RS256/ES256:

1. Fetch `/.well-known/jwks.json` with `send_request`.
2. Check if the server accepts `alg: none` (remove signature, set alg to none).
3. Check if the server accepts `alg: HS256` with the RSA public key as the
   HMAC secret (algorithm confusion).
4. Check if `jku` or `x5u` headers in the JWT can be pointed to an
   attacker-controlled URL.
5. Try injecting a crafted JWK in the JWT header (`jwk` parameter) — if the
   server trusts embedded keys, you can forge tokens.

Use `decode` to inspect JWT structure, then craft modified tokens with `encode`.

## Severity reference

| Finding | Severity |
|---------|----------|
| redirect_uri bypass → token/code theft | Critical |
| Algorithm confusion (RS256→HS256/none) | Critical |
| PKCE not enforced (code interception possible) | High |
| Missing state parameter (OAuth CSRF) | High |
| Authorization code replay | High |
| JWK injection in JWT header | High |
| Scope escalation to admin | High |
| Refresh token not rotated | Medium |
| Token in URL query string (Referer leak) | Medium |
| Long-lived authorization codes (> 60s) | Medium |
| State parameter predictable but present | Low |

## Known false positives

- The authorization server returns an error page for an invalid redirect_uri —
  this is correct behavior, not a bypass. Only report if it redirects WITH a
  code/token.
- `state` parameter is missing but the application uses a separate CSRF token
  in the callback — this may be an alternative mitigation. Verify the CSRF token
  is validated before downgrading.
- PKCE is optional because the client is a confidential client with a
  client_secret — this is acceptable per RFC 7636 but worth noting.

## Tooling note

This methodology is designed for the Void panel tools (`send_request`,
`compare_responses`, `search_responses`, `get_endpoints`, `decode`, `encode`,
`add_pentest_finding`). These are browser-extension APIs, not shell commands.
Do not attempt to run CLI tools.
