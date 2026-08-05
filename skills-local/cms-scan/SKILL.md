# CMS Security Testing

## Scope and preconditions

Applies to applications built on content management systems: WordPress, Joomla,
Drupal, Magento, or any recognizable CMS platform. CMS-specific testing finds
vulnerabilities in the platform itself, its plugins/themes, and common
misconfigurations. This skill provides Void-native techniques that work entirely
through the proxy without requiring CLI tools.

It does **not** cover: general web application testing not specific to CMS
platforms (use the appropriate vuln-specific skill), or custom application
testing on non-CMS frameworks.

## Rules of engagement

- MUST have written authorization before testing CMS installations.
- NEVER run brute force attacks against admin panels without explicit permission.
- MUST NOT modify CMS content or settings on production installations.
- MUST record the exact paths and responses as evidence.

## Workflow

- [ ] 1. Identify the CMS platform and version
- [ ] 2. Enumerate users
- [ ] 3. Test for exposed sensitive files
- [ ] 4. Enumerate plugins/themes
- [ ] 5. Test plugin-specific vulnerabilities
- [ ] 6. Test authentication and admin panel
- [ ] 7. Test CMS-specific attack vectors
- [ ] 8. Record findings

## Step 1: Identify the CMS and version

### Goal
Determine the exact CMS platform and version.

### Actions
Use `send_request` and `search_responses` to check:

**WordPress indicators**:
- Meta generator: `<meta name="generator" content="WordPress 6.x">`
- `/wp-admin/` redirect, `/wp-login.php` login page
- `/wp-content/` and `/wp-includes/` directories
- `/feed/` containing `<generator>https://wordpress.org/?v=X.X</generator>`
- `wp-emoji-release.min.js` version in HTML source
- `/wp-json/` REST API endpoint

**Joomla indicators**:
- `/administrator/` admin panel
- `/language/en-GB/en-GB.xml` contains version
- `<meta name="generator" content="Joomla!">`
- `/media/system/` directory

**Drupal indicators**:
- `/user/login` login page
- `CHANGELOG.txt` or `CHANGELOG.md` in root (version disclosure)
- `X-Generator: Drupal` header
- `/core/CHANGELOG.txt` (Drupal 8+)
- `Drupal.settings` in JavaScript

**General detection**:
- Favicon hash comparison (each CMS has a default favicon)
- CSS/JS paths unique to each platform
- Cookie names: `wp-settings-*`, `joomla_*`, `SSESS*` (Drupal)
- Response headers: `X-Powered-By`, `X-Drupal-Cache`

## Step 2: Enumerate users

### Goal
Discover valid usernames for brute force or targeted attacks.

### WordPress user enumeration
```
GET /?author=1     → 301 redirect to /author/admin/ (reveals username "admin")
GET /?author=2     → 301 redirect to /author/editor/
GET /?author=3     → 404 (no user with ID 3)
```
Use `run_intruder_attack` with IDs 1-20.

REST API (no auth required by default):
```
GET /wp-json/wp/v2/users
```
Returns JSON array with usernames, names, and avatar URLs.

### Joomla user enumeration
```
POST /index.php?option=com_users&task=user.register
```
Registration form may reveal if email/username is taken.

### Drupal user enumeration
```
GET /user/1    → profile page (if accessible)
GET /user/register → registration form may reveal taken usernames
```
Password reset form: different error for "user exists" vs. "user not found."

## Step 3: Test for exposed sensitive files

### Goal
Find configuration files, backups, and debug information.

### WordPress
| Path | Content |
|---|---|
| `/wp-config.php.bak` | Database credentials, secret keys |
| `/wp-config.php.old` | Same as above |
| `/wp-config.php~` | Vim backup |
| `/.wp-config.php.swp` | Vim swap file |
| `/wp-content/debug.log` | PHP errors, stack traces, paths |
| `/wp-admin/install.php` | Installation script (should be blocked) |
| `/.git/config` | Git repository exposure |
| `/wp-content/uploads/` | Directory listing of uploads |
| `/xmlrpc.php` | XML-RPC interface (brute force vector) |
| `/readme.html` | WordPress version |

### Joomla
| Path | Content |
|---|---|
| `/configuration.php.bak` | Database credentials |
| `/configuration.php~` | Same |
| `/administrator/manifests/files/joomla.xml` | Exact version |
| `/.htaccess` | Configuration (may reveal internal paths) |

### Drupal
| Path | Content |
|---|---|
| `/sites/default/settings.php` | Database credentials (if exposed) |
| `/sites/default/files/` | Uploaded files (may have directory listing) |
| `/CHANGELOG.txt` | Exact version |
| `/core/CHANGELOG.txt` | Version (Drupal 8+) |

Use `run_intruder_attack` with a list of common backup/config paths.

## Step 4: Enumerate plugins/themes

### Goal
Identify installed plugins and themes — they are the #1 source of CMS vulnerabilities.

### WordPress plugin enumeration
Probe for `readme.txt` files in plugin directories:
```
GET /wp-content/plugins/PLUGIN_NAME/readme.txt
```
The `readme.txt` contains the version number and often the changelog.

Use `run_intruder_attack` with a list of top 100 WordPress plugins:
`akismet`, `contact-form-7`, `woocommerce`, `yoast-seo`, `elementor`,
`wordfence`, `jetpack`, `wp-mail-smtp`, `all-in-one-seo-pack`,
`really-simple-ssl`, `updraftplus`, `wp-super-cache`, `sucuri-scanner`,
`classic-editor`, `tinymce-advanced`, etc.

200 response with version info = plugin installed. 404 = not installed.

### Theme enumeration
```
GET /wp-content/themes/THEME_NAME/style.css
```
The `style.css` header contains theme name and version.

### Joomla component enumeration
```
GET /index.php?option=com_COMPONENT_NAME
```
Or check for component-specific directories under `/components/`.

## Step 5: Test plugin-specific vulnerabilities

### Goal
Check identified plugins against known vulnerabilities.

### Actions
For each plugin and version found:
1. Search `search_responses` for the plugin version.
2. Cross-reference with known CVEs for that version.
3. Test the most critical known vulnerabilities.

### Common vulnerable patterns
- File upload in plugins without proper validation
- SQL injection in custom database queries
- XSS in admin settings pages (stored XSS → admin compromise)
- Path traversal in file include parameters
- Unauthenticated API endpoints in plugins

## Step 6: Test authentication and admin panel

### Goal
Test the admin panel for weak authentication.

### Actions
**Default credentials**: Test `admin:admin`, `admin:password`, `admin:wordpress`,
`administrator:admin` on the login page.

**WordPress xmlrpc.php brute force**:
```xml
POST /xmlrpc.php
<methodCall>
  <methodName>system.multicall</methodName>
  <params><param><value><array><data>
    <value><struct>
      <member><name>methodName</name><value>wp.getUsersBlogs</value></member>
      <member><name>params</name><value><array><data>
        <value>admin</value><value>password1</value>
      </data></array></value></member>
    </struct></value>
    <value><struct>
      <member><name>methodName</name><value>wp.getUsersBlogs</value></member>
      <member><name>params</name><value><array><data>
        <value>admin</value><value>password2</value>
      </data></array></value></member>
    </struct></value>
  </data></array></value></param></params>
</methodCall>
```
`system.multicall` tests multiple passwords in a single HTTP request,
bypassing per-request rate limits.

**Drupal Drupalgeddon**:
- CVE-2018-7600 (Drupalgeddon 2): RCE via Form API rendering
- CVE-2019-6340: REST API deserialization RCE

## Step 7: CMS-specific attack vectors

### WordPress REST API
```
GET /wp-json/wp/v2/posts?per_page=100&status=draft
```
May return draft posts if authorization is misconfigured.

```
POST /wp-json/wp/v2/users
```
May allow user registration even when the setting is disabled.

### WordPress file editing
If you gain admin access, WordPress allows editing theme/plugin files directly:
```
/wp-admin/theme-editor.php
/wp-admin/plugin-editor.php
```
This means admin access = RCE (write PHP to a theme file).

### Joomla template injection
Admin panel allows editing templates directly — same as WordPress file editing.

### Drupal PHP filter
Older Drupal versions have a PHP filter module that allows PHP execution in
content fields if enabled.

## Step 8: Record the finding

Use `add_pentest_finding` with:
- The CMS platform and version
- The specific vulnerability (plugin CVE, exposed config, user enum)
- Steps to reproduce
- Impact assessment

## Known false positives

- `/wp-admin/` returning 302 redirect to login — this is normal, not an exposure.
- User enumeration returning only `admin` — if only one user exists and the
  site is obviously a personal blog, this is low impact.
- `xmlrpc.php` accessible but `system.multicall` disabled — the endpoint exists
  but the brute force vector is blocked.
- Backup files returning 403 — the file may exist but is not readable.

## Reminder

CMS security follows one pattern: **identify the platform → enumerate
plugins/themes → check versions against known CVEs**. Plugins are the #1 source
of CMS vulnerabilities — the CMS core is usually well-maintained, but plugins
are often abandoned or poorly coded. Always enumerate plugins before testing
anything else.
