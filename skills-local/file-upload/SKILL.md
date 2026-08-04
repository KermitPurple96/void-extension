# Testing file upload

## Scope and preconditions

Applies to any endpoint that accepts a file: avatars, attachments, imports, document
converters, "upload your CV", presigned S3 puts. It covers reaching code execution,
stored XSS, file read and denial of service through an upload.

It does **not** cover: SSRF via a URL-fetch "import from link" field (use `ssrf`),
XXE inside an uploaded XML/DOCX/SVG (use `xxe`), or plain path traversal on a
download parameter (use `path-traversal`).

## Rules of engagement

- MUST upload only files you generated for this test. NEVER upload anything
  containing real data.
- MUST name every artefact with a unique marker (`void-<random>.ext`) so you can
  find and reference it later, and so the client can clean up.
- NEVER upload a zip bomb, a decompression bomb, or anything designed to exhaust
  disk or CPU unless destructive testing is explicitly enabled. Instead, report the
  missing size/ratio limit as a finding based on what you observed.
- MUST prove execution with a benign sentinel. Use `START`/`END` markers around a
  trivial value, NEVER `phpinfo()` (noisy, and its output is unreadable when the
  file is served as an image) and NEVER a reverse shell.
- MUST record the exact upload request and the exact retrieval request. An upload
  finding without the retrieval URL is not reproducible and does not count.
- In mode `ask`: confirm that the file lands and is interpreted, then stop. Do not
  read files, do not run commands beyond echoing your sentinel.

## Workflow

Copy this into your response and tick items off as you go.

- [ ] 1. Baseline: upload a legitimate file, capture the full request and response
- [ ] 2. Find the retrieval path — can you read back what you uploaded?
- [ ] 3. Probe what the validator checks (extension / content-type / magic bytes / size)
- [ ] 4. Bypass the weakest check
- [ ] 5. Determine what interprets the file, and aim at that
- [ ] 6. Verify with a sentinel, twice, from a clean session
- [ ] 7. Record the finding with both requests

## Step 1: Baseline

### Goal
Know exactly what a successful upload looks like before you change anything.

### Actions
Send a valid file of the type the form advertises. Capture with `send_request` and
keep the whole multipart body. Note every field, not just the file part — CSRF
tokens, a `type` selector, or a destination folder are all injection surface.

### What to look for
- Does the response contain the stored path, filename, or an id?
- Was your filename kept, sanitised, or replaced with a UUID?
- Is there a second request (thumbnailing, virus scan, conversion) visible in
  history afterwards?

### Stop condition
You can state the stored URL of your baseline file, or you have established that
the response reveals nothing about where it went.

## Step 2: Retrieval path

### Goal
An upload you cannot fetch back is usually only a parser bug, not an execution bug.

### Actions
Try, in order: the URL echoed in the response · a predictable pattern derived from
your filename · directory listing on the parent · an id-based endpoint
(`/files/1234`) walked with `run_intruder_attack`.

### Decision
- **Predictable path** — continue to step 3, execution is in play.
- **Random UUID and no echo** — execution is likely out of reach. Pivot to what
  *parses* the file (step 5) and to stored-XSS-on-retrieval.
- **Not retrievable at all** — the surface is the parser and the storage layer only.

## Step 3: What does the validator check?

Change one thing at a time and record the response for each. The point is to learn
which layer rejects you, not to get lucky.

| Probe | Tells you |
|---|---|
| Valid image, extension `.php` | Extension is checked (or not) |
| `.jpg` name, part `Content-Type: text/php` | Content-Type is checked |
| `.jpg` name, correct type, body `<?php ...` | Magic bytes / real parse is checked |
| Correct everything, 10 MB | Size limit exists |
| Same filename twice | Overwrite is possible |

The part-level `Content-Type` inside the multipart body is fully attacker
controlled and is frequently the only thing checked.

## Step 4: Bypasses, by what the validator does

### Extension blocklist
Case (`.pHp`) · double extension (`shell.jpg.php`, `shell.php.jpg`) · trailing dot
or space (`shell.php.`, `shell.php%20`) · non-recursive strip (`shell.p.phphp`
becomes `shell.php` after one pass) · alternate handlers:

- PHP: `.php3 .php4 .php5 .php7 .phtml .phar .inc .module .ctp`
- ASP/.NET: `.aspx .ashx .asmx .cshtml .config .asa .cer`
- JSP: `.jsp .jspx .jsw .jsv .jspf`
- Perl `.pl .cgi` · ColdFusion `.cfm` · Node `.js`

### Extension allowlist
You are not getting a new extension in. Install a handler instead:

- `.htaccess` with `AddType application/x-httpd-php .png` — then your `.png`
  executes. Handler names are distro specific, which is why this silently fails
  more often than it works; try `SetHandler application/x-httpd-php` too.
- IIS `web.config` with a `<mimeMap>`, or `customErrors mode="Off"` to leak the
  physical path.
- PHP-FPM `.user.ini` with `auto_prepend_file=` — the uploaded file is never
  requested directly, which defeats "we only serve images from that folder".

### Content-Type checked
Set the part header to `image/jpeg` and keep the dangerous filename.

### Magic bytes checked
Prepend a valid header, keep the payload after it. Minimal headers:

| Type | Bytes |
|---|---|
| GIF | `GIF89a` |
| PNG | `\x89PNG\r\n\x1a\n` |
| JPEG | `\xFF\xD8\xFF\xE0` |
| PDF | `%PDF-` |
| ZIP | `PK\x03\x04` |

`GIF89a<?php echo 'START'.`whoami`.'END'; ?>` passes both a magic-byte check and
`getimagesize()` on many stacks.

### The image is re-encoded
EXIF comments do not survive re-encoding. What does:

- **PLTE** chunk survives PHP-GD compression (payload length must be a multiple of 3)
- **IDAT** survives `imagecopyresized` / `imagecopyresampled`
- **`tEXt` with a keyword other than "Comment"** survives Imagick resize

### Path is sanitised
`filename="../../shell.php"` · URL-encoded `..%2fshell.php` (the check runs before
decoding, the write runs after) · the RFC 5987 differential:
`filename="ok.png"; filename*=UTF-8''%2e%2e%2fshell.php` — the validator reads one
parameter and the writer reads the other.

The response message is the oracle. `The file avatars/../shell.php has been
uploaded` proves the traversal survived the check.

## Step 5: What interprets the file?

This is the step most testers skip, and it is where the findings are when
execution is not reachable. Every one of these is an independent path that needs
neither webroot nor an executable extension:

- **Thumbnailer / resizer** — ImageMagick, GD, libvips. Ask for a format that
  invokes a delegate.
- **EXIF stripper** — ExifTool. A crafted DjVu comment has reached RCE.
- **Transcoder** — FFmpeg. An `.avi` referencing an HLS playlist reads server files.
- **Document converter** — LibreOffice, wkhtmltopdf. HTML to PDF converters fetch
  URLs, which is SSRF, and read `file://`, which is file read.
- **Archive extractor** — Zip Slip (`../` inside the archive) and, more quietly,
  **symlink entries**: a tar containing a symlink to `/etc/passwd` needs no `../`
  at all.
- **The antivirus itself** — has been the sink more than once.

Fingerprint before firing: upload a file that makes the processor reveal itself,
then download the processed derivative and inspect its metadata. Processors
frequently leak absolute server-side paths there.

## Step 6: Serving and stored XSS

If the file is served back to other users, the question is what the browser does
with it:

| Condition | Result |
|---|---|
| Same origin + attacker-controlled `Content-Type` + no `nosniff` | Stored XSS |
| SVG accepted and served as `image/svg+xml` | Stored XSS, script runs |
| HTML served inline rather than `Content-Disposition: attachment` | Stored XSS |
| Upload lands at `/sw.js` or the response sets `Service-Worker-Allowed: /` | Whole-origin compromise — Critical |

An upload directory on a separate sandbox domain kills most of this. Its absence is
worth noting even when you cannot demonstrate impact.

## Step 7: Verification

Do not report until:

1. The sentinel appears in the retrieved response — quote the exact bytes.
2. It reproduces from a clean session (no cookies from your test flow).
3. You can state which layer failed: the extension check, the type check, the
   magic-byte check, the path handling, or the serving headers.

If the output is swallowed, use a timing sentinel instead and compare against a
baseline request with `compare_responses`.

## Known false positives

- The file uploaded and you got a 200 — a 200 means "accepted", not "stored", and
  certainly not "executed".
- Your payload appears in the response of the *upload* endpoint. That is a
  reflection of your own request, not stored content. Fetch it back in a new
  request.
- The `.htaccess` uploaded successfully. Apache may not be reading it (`AllowOverride
  None`), and it does nothing at all on nginx or IIS. Prove the effect, not the write.
- A source-code disclosure served as `text/plain` is a real finding, but it is
  disclosure, not execution — do not rate it as RCE.
- Traversal appearing to work because the app echoed your filename back verbatim.
  The echo is not the filesystem.

## Reminder

Three things decide whether this is a finding: **you retrieved it**, **something
interpreted it**, and **you can quote the evidence**. A payload that uploads but is
never fetched, never parsed and never served is not a vulnerability yet — say so
plainly and record what you tested.
