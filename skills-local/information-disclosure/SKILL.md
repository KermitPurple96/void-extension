---
name: "information-disclosure"
description: "Information Disclosure — error messages, source leakage (.git, .svn, backup files), debug endpoints, sensitive data in HTML/JS comments"
version: "1.0.0"
author: "void-extension"
tags: ["pentest", "recon", "information-disclosure", "error-messages", "source-leakage", "backup-files", "debug-endpoints", "wstg-info", "wstg-errh"]
trigger_patterns:
  - "/information-disclosure"
  - "/info-disclosure"
  - "information disclosure"
  - "info disclosure"
  - "test error messages"
  - "stack trace"
  - "source code leak"
  - "backup file"
  - "debug endpoint"
  - ".git exposure"
  - "sensitive data html"
---

# Information Disclosure

Information Disclosure is the #3 most reported vulnerability class on HackerOne.
It encompasses any unintended exposure of sensitive data that aids an attacker:
stack traces revealing internal paths or library versions, source control
directories left on the web root, backup files with cleartext credentials,
debug endpoints that expose runtime state, and developer comments embedded in
HTML or JavaScript.

References: WSTG-INFO-01 through WSTG-INFO-10 (recon), WSTG-ERRH-01 and
WSTG-ERRH-02 (error handling).

## Scope and preconditions

Applies to every web application. There is no "not applicable" — even a static
site may expose `.git/` or backup files. The checks are passive or semi-passive:
they probe standard paths and observe responses, not exploit live injections.

This skill does **not** cover:
- Credential stuffing with leaked credentials (use `auth`).
- IDOR giving access to another user's data (use `idor`).
- Sensitive data in API responses beyond what is described here (use `api`).

## Workflow

- [ ] 1. Analyse error messages and exception output
- [ ] 2. Probe for source control and IDE artefacts
- [ ] 3. Discover backup and temporary files
- [ ] 4. Enumerate debug and diagnostic endpoints
- [ ] 5. Audit HTML comments and embedded JavaScript
- [ ] 6. Check HTTP response headers for version disclosure
- [ ] 7. Report findings

## Step 1: Error message analysis

Triggering verbose errors is the fastest way to learn about the technology stack,
internal file paths, database schema, and framework version.

### Techniques to trigger errors

Use `send_request` for each of the following and record any stack trace, SQL
error, or path disclosure with `add_pentest_finding`:

**1. Type confusion**
```
GET /user?id=abc         (expects integer)
GET /product?price=xyz   (expects float)
GET /date?from=notadate  (expects ISO date)
```

**2. Out-of-range values**
```
GET /user?id=9999999999999999
GET /page?limit=-1
GET /page?offset=9999999
```

**3. Missing required parameters**
```
GET /api/items           (delete required body param)
POST /api/order          (send empty JSON body: {})
```

**4. Malformed content types**
```
POST /api/data HTTP/1.1
Content-Type: application/json

{malformed json here
```

**5. HTTP method confusion**
```
DELETE /api/user/1
PUT /static/image.png
PATCH /login
```

**6. Path edge cases**
```
GET /..%2f..%2fetc%2fpasswd
GET /api/v1/../../../../etc/passwd
GET /page.php%00.html
```

### What to look for in error responses

| Indicator | Information disclosed |
|-----------|----------------------|
| `at com.example.UserService.getUser(UserService.java:42)` | Java stack trace with package names and line numbers |
| `PHP Fatal error: ... in /var/www/html/app/controllers/` | PHP error with absolute server path |
| `ORA-00942: table or view does not exist` | Oracle database, table names |
| `syntax error at or near "'"` | PostgreSQL, SQL syntax |
| `Microsoft OLE DB Provider for SQL Server` | MSSQL server |
| `Django Version: 3.2.1` / `DEBUG = True` | Django debug page with full config |
| `Rails.root: /app` | Rails stack trace with root path |
| `ErrorException in Model.php line 88` | Laravel path |
| `Traceback (most recent call last)` | Python exception with module paths |
| `node_modules/express/lib/router` | Node.js + Express stack |
| `ASP.NET is configured to show verbose error messages` | Classic ASP.NET |

Use `search_responses` to scan all captured traffic for these patterns.

### Verbose error via `Accept` header

Some frameworks return detailed errors only to browsers that accept HTML:
```
Accept: text/html,application/xhtml+xml
```

Others return verbose JSON errors when `Accept: application/json`. Try both.

## Step 2: Source control and IDE artefacts

Developers often deploy code from a working directory, leaving version control
metadata accessible on the web root.

### Source control probes

Use `send_request` for each path. A 200 response (not a redirect to the homepage
or a custom 404) is a finding:

```
GET /.git/HEAD
GET /.git/config
GET /.git/COMMIT_EDITMSG
GET /.git/logs/HEAD
GET /.git/refs/heads/main
GET /.git/objects/info/packs
GET /.svn/entries
GET /.svn/wc.db
GET /.svn/pristine/
GET /.hg/dirstate
GET /.hg/hgrc
GET /CVS/Entries
GET /CVS/Repository
GET /CVS/Root
GET /.bzr/branch/format
```

**Exploiting `.git` exposure**

If `/.git/HEAD` returns `ref: refs/heads/main`, the full repository may be
downloadable. The attack sequence is:

1. `GET /.git/config` — confirms origin URL, may reveal remote credentials.
2. `GET /.git/COMMIT_EDITMSG` — reveals recent commit message (internal names).
3. `GET /.git/logs/HEAD` — reveals commit hashes.
4. Use each hash to fetch object blobs:
   `GET /.git/objects/<first2>/<remaining38>`
5. Reconstruct source tree → credentials, API keys, internal endpoints.

Record the severity as **Critical** if credentials or API keys are found in
reconstructed source.

### IDE and framework artefacts

```
GET /.idea/workspace.xml        (JetBrains IDE)
GET /.idea/.gitignore
GET /.vscode/settings.json      (VS Code — may contain remote debug config)
GET /WEB-INF/web.xml            (Java EE deployment descriptor)
GET /WEB-INF/classes/
GET /META-INF/context.xml       (Tomcat — may contain DB credentials)
GET /config/database.yml        (Rails)
GET /.env                       (dotenv — credentials)
GET /.env.local
GET /.env.backup
GET /.env.production
GET /config.php
GET /configuration.php          (Joomla)
GET /wp-config.php.bak          (WordPress backup)
GET /settings.py                (Django)
GET /local_settings.py
GET /application.properties     (Spring Boot)
GET /application.yml
GET /appsettings.json           (.NET Core)
GET /appsettings.Development.json
```

Use `get_endpoints` to check which of these paths the scanner has already
crawled, then `send_request` for any that haven't been probed.

## Step 3: Backup and temporary files

Web servers sometimes serve backup files created by text editors or scripting
conventions.

### Common backup file patterns

For every `.php`, `.asp`, `.aspx`, `.jsp`, `.py`, `.rb` file you find via
`get_endpoints`, probe these variants:

| Pattern | Example |
|---------|---------|
| `<file>.bak` | `index.php.bak` |
| `<file>~` | `index.php~` (Vim/Emacs backup) |
| `<file>.swp` | `.index.php.swp` (Vim swap) |
| `<file>.swo` | `.index.php.swo` |
| `<file>.old` | `config.php.old` |
| `<file>.orig` | `login.php.orig` |
| `<file>.save` | `admin.php.save` |
| `<file>.1`, `<file>.2` | `database.php.1` |
| `<file>_backup` | `config_backup.php` |
| `<file>.copy` | `process.asp.copy` |
| `Copy of <file>` | `Copy of login.jsp` |

Also probe for archive backups at the root:

```
GET /backup.zip
GET /backup.tar.gz
GET /backup.tar.bz2
GET /www.zip
GET /htdocs.zip
GET /site.zip
GET /db.sql
GET /dump.sql
GET /database.sql
GET /data.sql
```

A backup `.zip` of the webroot is a Critical — it typically contains all source
code, credentials, and configuration files.

### Editor swap file detection

Vim creates `.swp` files in the same directory as the edited file:
```
GET /.login.php.swp
GET /.wp-config.php.swp
```

These contain recoverable file contents even if the original was deleted.

## Step 4: Debug and diagnostic endpoints

Many frameworks ship debug panels that developers forget to disable in
production.

### Framework-specific debug endpoints

```
# Java Spring Boot Actuator
GET /actuator
GET /actuator/health
GET /actuator/env           → full environment including credentials
GET /actuator/configprops   → all configuration properties
GET /actuator/beans         → Spring bean graph
GET /actuator/mappings      → all URL mappings
GET /actuator/heapdump      → JVM heap dump
GET /actuator/threaddump    → thread state
GET /actuator/loggers       → log levels
GET /actuator/metrics

# Django (only active when DEBUG=True)
GET /admin/
GET /__debug__/             (Django Debug Toolbar)

# Laravel Telescope / Debugbar
GET /telescope
GET /_debugbar/open
GET /_debugbar/clockwork

# PHP
GET /info.php               → phpinfo() — full PHP config
GET /phpinfo.php
GET /test.php

# ASP.NET
GET /elmah.axd              → Error Log Modules And Handlers
GET /trace.axd              → ASP.NET request trace
GET /ScriptResource.axd

# Symfony
GET /_profiler
GET /_wdt
GET /app_dev.php

# Express / Node.js
GET /status
GET /health
GET /metrics
GET /debug

# Ruby on Rails
GET /rails/info/properties  → Rails & Ruby version, routes
GET /rails/info/routes
GET /rails/mailers

# Generic admin / monitoring
GET /admin
GET /admin/
GET /manager/html           → Tomcat Manager
GET /phpmyadmin
GET /adminer.php
GET /server-status          → Apache mod_status
GET /server-info            → Apache mod_info
GET /nginx_status           → Nginx stub_status
```

Use `get_endpoints` to check which are already in scope, then `send_request`
for each. An actuator `/env` endpoint that returns Spring datasource passwords
is a Critical finding.

### Swagger / OpenAPI exposure

```
GET /swagger-ui.html
GET /swagger-ui/
GET /api-docs
GET /api-docs.json
GET /v2/api-docs
GET /v3/api-docs
GET /openapi.json
GET /openapi.yaml
```

A live Swagger UI with authentication not required is a High finding — it
exposes the full API surface and may allow direct testing without a client.

## Step 5: HTML comments and embedded JavaScript

Developers often leave credentials, internal URLs, and debugging information in
HTML comments and JavaScript files.

### HTML comment patterns

Use `search_responses` to scan all captured responses for:

```
<!--
<!-- TODO
<!-- DEBUG
<!-- FIXME
<!-- password
<!-- pass
<!-- pwd
<!-- key
<!-- secret
<!-- token
<!-- api
<!-- internal
<!-- admin
<!-- test
<!-- staging
<!-- dev
```

Common high-value finds:
- `<!-- admin:password123 -->`
- `<!-- TODO: remove debug key: sk_live_... -->`
- `<!-- DB_HOST=internal.db.company.com -->`
- `<!-- staging API: https://api-staging.internal/ -->`

### JavaScript source analysis

Use `get_scripts` to enumerate all JavaScript files loaded by the page. For each
file, use `search_responses` to look for:

```
apiKey
api_key
API_KEY
secret
password
passwd
credentials
AWS_ACCESS_KEY
AWS_SECRET
auth_token
access_token
clientSecret
client_secret
Bearer
Basic
-----BEGIN
private_key
```

Also look for hardcoded internal URLs:
```
localhost
127.0.0.1
10\.
192\.168\.
172\.(1[6-9]|2[0-9]|3[01])\.
internal
staging
dev\.
test\.
```

Source maps (`.js.map`) loaded in production expose the original, unminified
source including variable names, comments, and sometimes credentials.

```
GET /app.js.map
GET /main.chunk.js.map
GET /bundle.js.map
```

### robots.txt and sitemap disclosure

```
GET /robots.txt
GET /sitemap.xml
GET /sitemap_index.xml
GET /.well-known/security.txt
GET /.well-known/change-password
```

`robots.txt` disallowed paths often reveal admin panels and internal sections.
Record any sensitive path in the Disallow list with `add_pentest_finding`.

## Step 6: HTTP response header version disclosure

Use `get_response_headers` on the main page and API responses:

| Header | Example disclosure |
|--------|-------------------|
| `Server: Apache/2.4.29 (Ubuntu)` | Web server + OS + version |
| `X-Powered-By: PHP/7.2.1` | Language + version |
| `X-Powered-By: ASP.NET` | Framework |
| `X-AspNet-Version: 4.0.30319` | .NET runtime |
| `X-Generator: Drupal 9` | CMS |
| `X-Runtime: Ruby` | Language |
| `Via: 1.1 vegur (Heroku)` | Hosting platform |
| `X-Served-By: cache-xxx` | CDN node |

Version numbers allow precise CVE lookup. Cross-reference with `tech-fingerprint`
if detailed version-based exploit matching is needed.

## Severity reference

| Finding | Severity |
|---------|----------|
| Credentials / API keys in source / comments / backup | Critical |
| `.git/` directory exposed with full source reconstruction | Critical |
| Spring Actuator `/env` leaking datasource passwords | Critical |
| Database dump (`.sql`) accessible | Critical |
| Backup archive (`.zip`, `.tar.gz`) with source code | Critical |
| Django debug page / `phpinfo()` in production | High |
| Stack trace with internal paths and library versions | High |
| Swagger / OpenAPI UI unauthenticated in production | High |
| `.env` file accessible (no credentials, just config) | High |
| `robots.txt` exposing admin / internal paths | Medium |
| Version disclosure in headers | Low |
| HTML comments with non-sensitive developer notes | Informational |

## Known false positives

- Custom 200 pages that return 200 for every 404 path will match all backup
  probes. Verify the response body, not just the status code.
- Some actuator endpoints are public by design (`/actuator/health`). Only report
  endpoints that expose sensitive data.
- Stack traces in non-production environments (dev, staging) are expected; only
  report against production scope.

## Tooling note

This methodology uses Void panel tools: `send_request` for probing individual
paths, `search_responses` for pattern scanning across captured traffic,
`get_endpoints` for checking what the crawler found, `get_scripts` for
enumerating JavaScript files, `get_response_headers` for header inspection,
and `add_pentest_finding` to record confirmed disclosures. These are
browser-extension APIs, not shell commands — do not attempt to run CLI tools.
