# IDOR / Broken Object-Level Authorization

## Scope and preconditions

Applies to any endpoint that references objects by ID: user profiles, documents,
orders, files, settings, messages, or any resource accessed via a numeric ID,
UUID, or encoded identifier. IDOR is about accessing objects belonging to other
users by manipulating the identifier.

It does **not** cover: broken function-level authorization where the issue is
access to the endpoint itself (use `api`), or vertical privilege escalation
without object reference (use `auth`).

## Rules of engagement

- MUST use at least two test accounts you control (Account A and Account B).
- NEVER attempt to access real user data. Demonstrate cross-account access
  only between your test accounts.
- MUST stop after confirming the vulnerability — do not enumerate all objects.
- MUST record both the request (with Account B's ID) and the response (showing
  Account A's data or unauthorized action).

## Workflow

- [ ] 1. Collect object IDs from both test accounts
- [ ] 2. Test read access (horizontal IDOR)
- [ ] 3. Test write/modify access
- [ ] 4. Test delete access
- [ ] 5. Test ID predictability and enumeration
- [ ] 6. Test GraphQL-specific IDOR
- [ ] 7. Test advanced patterns
- [ ] 8. Record findings

## Step 1: Collect object IDs

### Goal
Build a matrix of object IDs from two test accounts.

### Actions
1. Log in as Account A. Navigate through the application capturing all requests.
2. Use `search_responses` to find all IDs referenced in:
   - URL paths: `/api/users/123`, `/orders/456`
   - URL parameters: `?id=123`, `?user_id=456`
   - JSON request bodies: `{"orderId": 789}`
   - JSON response bodies (leaking IDs of related objects)
   - Headers: `X-Request-Id`, `X-Correlation-Id`
3. Log in as Account B. Collect the same types of IDs.
4. Build a crossover matrix: try Account A's IDs with Account B's session.

### Two-session methodology
Open two browser sessions (or two sets of cookies). Systematically replay
each request from Session A using Session B's authentication:
- Same endpoint, same method, same body — only swap the auth header/cookie
- Use Account A's object IDs in requests authenticated as Account B

## Step 2: Test read access

### Goal
Determine if Account B can read Account A's data.

### Actions
For each object ID from Account A, send the request with Account B's session:

```
GET /api/users/ACCOUNT_A_ID
Authorization: Bearer ACCOUNT_B_TOKEN
```

Use `send_request` with Account B's credentials and Account A's object ID.
Use `compare_responses` to diff the response against Account A's legitimate
response.

### What to look for
- 200 OK returning Account A's data to Account B — confirmed IDOR read
- 200 OK but empty body — may be filtered on the backend, not a finding
- 403/404 — authorization is enforced for this endpoint
- Different response for valid vs. invalid IDs — information oracle

## Step 3: Test write/modify access

### Goal
Determine if Account B can modify Account A's objects.

### Actions
```
PUT /api/users/ACCOUNT_A_ID
Authorization: Bearer ACCOUNT_B_TOKEN
Content-Type: application/json

{"name": "IDOR_TEST"}
```

After the request, verify from Account A's session whether the modification
took effect.

### HTTP method matrix
Test ALL methods on each endpoint:
| Method | Effect |
|---|---|
| GET | Read data |
| PUT/PATCH | Modify data |
| DELETE | Delete data |
| POST | Create child resources |

The endpoint may enforce auth on GET but not on PUT — test each method.

**HTTP method override**: If PUT is blocked, try:
```
POST /api/users/ACCOUNT_A_ID
X-HTTP-Method-Override: PUT
```

## Step 4: Test delete access

### Goal
Determine if Account B can delete Account A's objects.

### Actions
Use a non-critical test object (create a temporary item as Account A):
```
DELETE /api/items/TEMP_ITEM_ID
Authorization: Bearer ACCOUNT_B_TOKEN
```

Verify from Account A's session that the item is gone.

NEVER test delete on critical objects without a way to restore them.

## Step 5: Test ID predictability

### Goal
Determine if object IDs can be guessed or enumerated.

### Sequential IDs
If your objects have IDs like 1001, 1002, 1003 — other users' objects are at
nearby numbers. Use `run_intruder_attack` with a range payload.

### UUID analysis
Decode the UUID to check its version:
- **UUIDv1**: Contains timestamp and MAC address — predictable with enough
  samples. Decode: bytes 0-3 = time_low, bytes 4-5 = time_mid, bytes 6-7 =
  time_hi. The timestamp reveals when the object was created.
- **UUIDv4**: Random — not practically enumerable.
- **UUIDv7**: Timestamp-sortable — predictable creation time but random suffix.

Even with random UUIDs, IDs may leak in:
- API responses listing related objects
- WebSocket messages
- JavaScript bundles containing hardcoded IDs
- Email notifications (order IDs, ticket IDs)
- Referer headers
- Browser history and autocomplete

### Encoded IDs
Base64-encoded IDs may decode to `Type:NumericID`:
```
VXNlcjoxMjM=  →  User:123
```
Increment the number: `VXNlcjoxMjQ=` → `User:124`

### Parameter name variations
Try different parameter names for the same concept:
- `user_id`, `userId`, `uid`, `account_id`, `accountId`, `id`, `user`
- Some names may bypass authorization checks that only protect one variant

## Step 6: GraphQL-specific IDOR

### Goal
Exploit GraphQL's Relay node interface and alias enumeration.

### Relay node() interface
Many GraphQL APIs implement Relay's global ID system:
```json
{"query": "{node(id: \"VXNlcjox\") {...on User {email phone address}}}"}
```
Decode `VXNlcjox` → `User:1`. Change to `User:2` → `VXNlcjoy`.

The `node()` interface bypasses per-type authorization because it is a single
resolver that dispatches to any type.

### Alias enumeration
Query multiple objects in one request:
```json
{"query": "{
  u1: user(id: 1) { email }
  u2: user(id: 2) { email }
  u3: user(id: 3) { email }
}"}
```
50 IDs per request, bypassing per-request rate limits.

### WebSocket IDOR
WebSocket frames often include object IDs without server-side ownership checks:
```json
{"action": "subscribe", "channelId": "OTHER_USER_CHANNEL"}
```
The server may not validate that the authenticated user owns the channel.

## Step 7: Advanced patterns

### Old API version bypass
```
/api/v2/users/123  →  403 (auth enforced)
/api/v1/users/123  →  200 (old version has no auth check)
```
Always test discovered API versions — older versions may lack authorization.

### BFLA (Broken Function Level Authorization)
Access admin-only endpoints with a regular user's token:
```
GET /api/admin/users
Authorization: Bearer REGULAR_USER_TOKEN
```
Use `get_endpoints` to find admin paths, then test with regular user auth.

### Mass assignment
Send additional fields in update requests:
```json
PATCH /api/users/me
{"name": "test", "role": "admin", "isAdmin": true}
```
The API may accept and apply fields that should not be user-modifiable.

### Soft delete bypass
Objects marked as "deleted" may still be accessible via direct ID:
```
GET /api/items/DELETED_ITEM_ID
```
If the item returns — soft delete does not enforce access control.

## Step 8: Record the finding

Use `add_pentest_finding` with:
- The object ID and whose object it belongs to
- The request authenticated as the wrong user
- The response showing unauthorized access
- The HTTP method and action (read/modify/delete)
- Impact: data exposure, unauthorized modification, unauthorized deletion

## Known false positives

- Accessing a shared or public object — some objects are intentionally public.
  Verify that the object should be private.
- 200 response with empty or redacted data — the endpoint responds but does not
  leak private fields. Check the actual response content.
- Different response size but same content — may be formatting differences, not
  data differences.
- Access to your own objects via a different code path — make sure you are testing
  cross-account access, not same-account access.

## Reminder

IDOR testing is systematic: build a matrix of IDs from two accounts, then cross
them. The three highest-value patterns: **read other users' data** (horizontal
IDOR), **modify other users' objects** (write IDOR, higher severity), and
**GraphQL node() bypass** (often misses per-type auth). Always test ALL HTTP
methods on each endpoint — authorization is often enforced on GET but not on
PUT or DELETE.
