# JWT Security Testing

## Scope and preconditions

Applies to any application using JSON Web Tokens for authentication or
authorization: session tokens, API keys, OAuth access/refresh tokens, or any
`Authorization: Bearer eyJ...` header. Covers JWS (signed), JWE (encrypted),
header injection, and algorithm attacks.

It does **not** cover: OAuth flow-level attacks (use `oauth`), SAML assertions
(use `saml`), or session cookie management (use `session-management`).

## Rules of engagement

- MUST use only tokens issued to your test accounts.
- NEVER attempt to forge tokens for accounts you do not control.
- MUST NOT use forged tokens against production systems without authorization.
- MUST record the original token, your modification, and the server's response.

## Workflow

- [ ] 1. Identify and decode the JWT
- [ ] 2. Test alg:none attack
- [ ] 3. Test algorithm confusion (RS256→HS256)
- [ ] 4. Test kid header injection
- [ ] 5. Test JKU/X5U injection
- [ ] 6. Test claim manipulation
- [ ] 7. Test token lifecycle
- [ ] 8. Test JWE attacks
- [ ] 9. Record findings

## Step 1: Identify and decode

### Goal
Find JWTs and understand their structure.

### Actions
Use `search_responses` for:
- `Authorization: Bearer eyJ` headers
- Cookies containing `eyJ` (base64-encoded `{"`)
- JSON response fields containing JWTs
- `Set-Cookie` with JWT-like values

Decode the JWT (base64url decode header and payload):
- **Header**: `alg` (algorithm), `typ`, `kid` (key ID), `jku` (JWK Set URL),
  `x5u` (X.509 URL), `x5c` (certificate chain)
- **Payload**: `sub` (subject), `iss` (issuer), `aud` (audience), `exp` (expiry),
  `iat` (issued at), `nbf` (not before), `roles`, `admin`, custom claims

Note: the signature is the third part — you can read the header and payload
without the key.

## Step 2: Test alg:none

### Goal
Bypass signature verification by setting the algorithm to none.

### Technique
Change the header to `{"alg": "none", "typ": "JWT"}`, remove the signature
(keep the trailing dot):
```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.
```

Test variations: `"none"`, `"None"`, `"NONE"`, `"nOnE"`, `"NonE"`.

Send with `send_request` and check if the server accepts the unsigned token.

### Decision
- **Token accepted** — Critical. Signatures are not verified.
- **Token rejected** — Continue to algorithm confusion.

## Step 3: Algorithm confusion (RS256→HS256)

### Goal
Sign the token with the server's public key used as an HMAC secret.

### Technique
This attack works when:
1. The server uses RSA (RS256) for signing — asymmetric: private key signs,
   public key verifies.
2. The server uses `jwt.verify(token, key)` without restricting the algorithm.
3. The attacker changes `alg` to `HS256` — symmetric: the same key signs and
   verifies.
4. The attacker signs the token with the **public key** as the HMAC secret.
5. The server uses the public key to verify the HMAC — it matches.

### Steps
1. Obtain the public key: `/.well-known/jwks.json`, `/oauth/certs`, or extract
   from the TLS certificate.
2. Convert JWK to PEM format if needed.
3. Modify the JWT: change `alg` to `HS256`, modify claims as desired.
4. Sign with HMAC-SHA256 using the public key bytes as the secret.
5. Send the forged token.

### Libraries vulnerable to this
Old versions of `jsonwebtoken` (Node.js), `PyJWT` (Python), `php-jwt` (PHP)
that do not enforce algorithm restrictions.

## Step 4: kid header injection

### Goal
Exploit the `kid` (key ID) header to control which key the server uses.

### Techniques

**Path traversal to known file**:
```json
{"alg": "HS256", "kid": "../../../dev/null"}
```
`/dev/null` is empty → sign with empty string as HMAC secret.

```json
{"alg": "HS256", "kid": "../../public/css/style.css"}
```
Sign with the content of a known public file as the secret.

**SQL injection in kid lookup**:
```json
{"alg": "HS256", "kid": "key' UNION SELECT 'attacker-secret' -- "}
```
If the server looks up the key from a database using `kid`, SQL injection
returns your chosen secret.

**Directory traversal to /proc**:
```json
{"alg": "HS256", "kid": "../../../proc/self/environ"}
```
Sign with the environment variables content (if predictable).

## Step 5: JKU/X5U injection

### Goal
Point the server to your own key set URL.

### JKU (JWK Set URL)
```json
{"alg": "RS256", "jku": "https://evil.com/.well-known/jwks.json"}
```
Host a JWKS at the attacker URL with your key pair. Sign the token with your
private key. If the server fetches the JKU URL without validation, it uses
your public key to verify — and it passes.

**With open redirect**: If the server validates JKU against an allowlist:
```json
{"jku": "https://trusted.com/redirect?url=https://evil.com/jwks.json"}
```

### X5U (X.509 URL)
Same technique with X.509 certificates:
```json
{"alg": "RS256", "x5u": "https://evil.com/cert.pem"}
```

### X5C (certificate chain)
Embed your certificate directly in the header:
```json
{"alg": "RS256", "x5c": ["MIIBkTCB+...your-cert..."]}
```
If the server trusts the embedded certificate without checking it against a
known CA or pinned certificate, you can sign with your own key.

## Step 6: Test claim manipulation

### Goal
Modify payload claims to escalate privileges.

### Actions
Decode the JWT payload and try modifying:
- `"sub": "admin"` — change to admin user
- `"role": "admin"` or `"roles": ["admin"]`
- `"admin": true`
- `"email": "admin@target.com"`
- `"user_id": 1` — first user is often admin
- `"iss": "different-issuer"` — test issuer validation
- `"aud": "different-audience"` — test audience validation

For each modification, re-sign (if you found a signing bypass above) and send.

## Step 7: Test token lifecycle

### Goal
Determine if tokens have proper expiry and invalidation.

### Actions
1. **Expired token**: Set `exp` to a past timestamp. Send it.
   If accepted — no expiry validation.

2. **Missing exp**: Remove `exp` claim entirely. Sign and send.
   If accepted — tokens never expire.

3. **Far-future exp**: Set `exp` to year 2099. If accepted, check if the server
   has its own max lifetime that overrides.

4. **Not-before (nbf)**: Set `nbf` to a future timestamp. Send now.
   If accepted — `nbf` is not validated.

5. **Token after logout**: Log out. Reuse the old token.
   If it still works — no token revocation.

6. **Token after password change**: Change password. Reuse the old token.
   If it works — password change does not invalidate tokens.

7. **Cross-service replay**: Use a token from service A on service B.
   If accepted — audience (`aud`) is not validated.

## Step 8: Test JWE attacks

### Goal
Attack encrypted JWTs (JWE).

### Techniques

**Algorithm downgrade**: Change `alg` to `dir` (direct encryption) to skip
key wrapping. This may allow using a known key.

**Encryption downgrade**: Change `enc` to a weaker algorithm (e.g., `A128CBC-HS256`
instead of `A256GCM`).

**Missing integrity check**: Some JWE implementations encrypt but do not
authenticate (no AEAD or missing integrity check). Modify the ciphertext and
check if it is accepted.

### CVE-2022-21449 (Psychic Signatures)
Java 15-17 ECDSA signature verification accepted blank signatures where both
`r` and `s` components are set to 0. If the target uses Java 15-17 with ECDSA:
```
Set signature to all zeros
```
This bypasses signature verification entirely.

## Step 9: Record the finding

Use `add_pentest_finding` with:
- The original JWT and your modified version
- The specific attack technique
- The server's response accepting the forged token
- What access was gained (admin, other user, elevated permissions)

## Known false positives

- `alg:none` token rejected with a different error than "invalid signature" —
  may be a parsing error, not signature validation. Check the error message.
- Algorithm confusion where the server rejects HS256 tokens entirely — the
  algorithm restriction is properly configured.
- Kid path traversal where the file does not exist or is not readable — the
  path traversal exists but is not exploitable with available files.
- Expired token accepted within a grace period (clock skew tolerance, usually
  30-60 seconds) — this is normal, not a vulnerability.

## Reminder

JWT security comes down to: **is the signature actually verified** and **against
the right key**? The three highest-impact attacks: `alg:none` (no signature),
algorithm confusion RS256→HS256 (sign with public key), and `kid` injection
(control which key is used). Always decode the JWT first — the claims reveal
the application's authorization model and the header reveals the attack surface.
