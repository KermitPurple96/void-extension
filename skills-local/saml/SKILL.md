# SAML / SSO Testing

## Scope and preconditions

Applies to any application that uses SAML 2.0 for Single Sign-On, either as a
Service Provider (SP) or Identity Provider (IdP). The target must have a SAML
login flow you can intercept — look for `SAMLRequest` and `SAMLResponse`
parameters in POST or redirect bindings.

It does **not** cover: OAuth/OIDC flows (use `oauth`), JWT token attacks outside
SAML context (use `jwt`), or general authentication bypass without SAML (use
`auth`).

## Rules of engagement

- MUST have authorization to test the SSO flow. Testing SAML often involves the
  IdP — confirm scope includes both SP and IdP.
- MUST use only test accounts provided for the engagement. NEVER attempt to
  access real user assertions.
- NEVER replay captured SAML assertions from production traffic.
- MUST record the original assertion, your modification, and the result.

## Workflow

- [ ] 1. Intercept a valid SAML Response
- [ ] 2. Decode and understand the assertion structure
- [ ] 3. Test signature validation
- [ ] 4. Test XML Signature Wrapping (XSW)
- [ ] 5. Test comment injection in NameID
- [ ] 6. Test assertion replay and expiry
- [ ] 7. Test assertion consumer URL manipulation
- [ ] 8. Record findings

## Step 1: Intercept a valid SAML Response

### Goal
Capture a complete SAML authentication flow.

### Actions
1. Use `search_responses` to find requests containing `SAMLResponse` parameter.
2. If not captured yet, initiate a login and watch for the POST to the ACS
   (Assertion Consumer Service) endpoint.
3. Extract the `SAMLResponse` value — it is base64-encoded XML.

### What to look for
- POST binding: `SAMLResponse` as a form parameter
- Redirect binding: `SAMLResponse` as a URL parameter (deflate + base64)
- The `RelayState` parameter — sometimes sensitive, sometimes a redirect target

### Stop condition
You have a valid, decodable SAMLResponse and know the ACS endpoint URL.

## Step 2: Decode and understand the assertion

### Goal
Map the assertion structure before modifying it.

### Actions
Base64-decode the SAMLResponse. Identify:
- `<saml:Assertion>` — the core identity claim
- `<saml:NameID>` — the authenticated identity (email, username)
- `<saml:Conditions>` — `NotBefore`, `NotOnOrAfter`, `AudienceRestriction`
- `<ds:Signature>` — XML digital signature over the assertion or response
- `<saml:AttributeStatement>` — role, group membership, other claims

Note the `InResponseTo` attribute — it should bind this response to a specific
AuthnRequest. Note the `Destination` — it should match the ACS URL.

## Step 3: Test signature validation

### Goal
Determine if the SP actually validates the XML signature.

### Actions

**Signature stripping**: Remove the entire `<ds:Signature>` element from the
response. Re-encode and replay. If the SP accepts it, signature validation is
completely absent — Critical finding.

**Unsigned assertion in signed response**: If the response is signed but the
assertion inside it is not, modify the assertion (change NameID) and replay.
Some SPs only validate the outer response signature.

**Algorithm downgrade**: Change `SignatureMethod` from SHA-256 to SHA-1 or from
RSA to HMAC. Some implementations accept any algorithm without restriction.

### Decision
- **Signature stripped and accepted** — Critical. Report immediately.
- **Unsigned assertion accepted** — High. Continue testing with modified assertions.
- **Signature properly validated** — Continue to XSW attacks.

## Step 4: XML Signature Wrapping (XSW)

### Goal
Bypass signature validation by moving the signed assertion and inserting a
malicious one that the SP reads instead.

### Technique
The XML signature covers a specific element identified by reference URI. XSW
attacks exploit the gap between which element was signed and which element the
SP's code reads:

**XSW variant 1** — Wrap the signed assertion inside a new element, add an
unsigned assertion at the original location:
```xml
<samlp:Response>
  <saml:Assertion ID="evil">  <!-- SP reads this one -->
    <saml:NameID>admin@target.com</saml:NameID>
  </saml:Assertion>
  <Wrapper>
    <saml:Assertion ID="legit">  <!-- Signature covers this one -->
      <saml:NameID>user@target.com</saml:NameID>
    </saml:Assertion>
  </Wrapper>
</samlp:Response>
```

**XSW variant 2** — Place the malicious assertion before the signed one.
**XSW variant 3** — Nest the signed assertion as a child of the malicious one.
**XSW variant 4-8** — Variations using `<Extensions>`, `<Object>`, detached
signatures, and different tree positions.

Test each variant with `send_request` — modify the NameID to your admin test
account in the unsigned assertion. The signed assertion stays untouched.

### What to look for
- Login as a different user than the one in the signed assertion
- Different role/group assignment
- Access to admin functionality

## Step 5: Comment injection in NameID

### Goal
Exploit XML comment handling differences between the IdP's signature library
and the SP's identity extraction.

### Technique
```xml
<saml:NameID>admin@target.com<!---->.evil.com</saml:NameID>
```

The signature library may compute the digest over the text content including the
comment (or canonicalize it away). The SP's application code may:
- Strip comments → reads `admin@target.com.evil.com`
- Truncate at the comment → reads `admin@target.com`

Real CVEs: CVE-2017-11428 (Ruby SAML), CVE-2016-5697 (various libs).

Other comment patterns to test:
```xml
admin<!-- comment -->@target.com
admin@target.com<!-- -->.evil.com
```

## Step 6: Test assertion replay and expiry

### Goal
Determine if assertions can be reused after their intended lifetime.

### Actions
1. Capture a valid assertion, note the `NotOnOrAfter` timestamp.
2. Wait until after that timestamp, then replay. If accepted — no expiry check.
3. Replay the same assertion immediately a second time. If accepted —
   no `InResponseTo` binding or replay protection.
4. Test with a missing or empty `InResponseTo`. If accepted — the assertion is
   not bound to a specific authentication request.

### What to look for
- `NotOnOrAfter` not validated → replay window is unlimited
- `InResponseTo` not validated → assertion from one session works in another
- No assertion store / replay cache → same assertion accepted repeatedly

## Step 7: Assertion Consumer URL manipulation

### Goal
Test if the SP validates the `Destination` attribute and the ACS endpoint.

### Actions
1. Change the `Destination` in the SAMLResponse to `https://evil.com/acs`.
2. POST the SAMLResponse to the legitimate ACS endpoint but with modified
   `Destination`. If accepted — the SP does not validate the destination.
3. Test if the `Recipient` in `SubjectConfirmationData` is validated similarly.

## Step 8: Record the finding

Use `add_pentest_finding` with:
- The original SAMLResponse (base64)
- Your modified SAMLResponse
- The specific variant that succeeded
- Evidence of the identity you obtained (different user, admin role)

## Known false positives

- The SP rejected your modified assertion with a generic error — that does not
  mean signature validation is present. It might be a schema validation error.
  Check the error message carefully.
- A 200 response to a replayed assertion does not mean success — check if a
  session was actually created (look for Set-Cookie, redirect to dashboard).
- Comment injection that changes the NameID but the SP maps it to the same
  account anyway (case-insensitive matching, email normalization).

## Reminder

SAML attacks target the gap between what the cryptographic signature covers and
what the application code reads. The three things that make a SAML finding:
**you modified the assertion**, **the signature check did not catch it**, and
**you obtained a different identity or elevated privileges**. Always test
signature stripping first — if that works, you have a Critical and everything
else is academic.
