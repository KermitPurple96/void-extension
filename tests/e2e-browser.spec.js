// @ts-check
// Void Extension AI Pentest — Playwright E2E
// Tests extension loading, data integrity, DOM structure, and interactions
// Run: npx playwright test tests/e2e-browser.spec.js --config=tests/playwright.config.js
const { test, expect, chromium } = require('@playwright/test');
const path = require('path');
const { chromeExecutable } = require('./chrome-path');

const EXT_PATH = path.resolve(__dirname, '..');
const EXE = chromeExecutable();

// panel.html is opened as a plain extension page, where `chrome.devtools` does not
// exist. Without this stub, panel.js throws on its very first statement
// (`chrome.devtools.inspectedWindow.tabId`), the whole script aborts, and every
// top-level `let` stays in TDZ — so only hoisted functions and static DOM are
// testable. Stubbing it lets the script evaluate fully and DOMContentLoaded run,
// which is what makes the runtime tests below meaningful.
const DEVTOOLS_STUB = () => {
  if (typeof chrome === 'undefined' || chrome.devtools) return;
  chrome.devtools = {
    inspectedWindow: {
      tabId: 1,
      // Callback form: (result, exceptionInfo)
      eval: (_expr, cb) => { if (typeof cb === 'function') cb(undefined, { isError: true, value: 'no inspected window in tests' }); },
    },
  };
};

async function launchExt() {
  const ctx = await chromium.launchPersistentContext('', {
    headless: false,
    ...(EXE ? { executablePath: EXE } : {}),
    args: [`--disable-extensions-except=${EXT_PATH}`, `--load-extension=${EXT_PATH}`, '--no-first-run', '--disable-gpu'],
  });
  const sw = ctx.serviceWorkers()[0] || await ctx.waitForEvent('serviceworker');
  const page = await ctx.newPage();

  // Listeners must be attached BEFORE goto. Attaching them afterwards makes
  // load-time failures invisible — which is exactly the class of bug DEVTOOLS_STUB
  // exists to prevent (a top-level throw in panel.js aborting the whole script).
  // Only environment-only noise is filtered. "No tab with id" is unavoidable here:
  // DEVTOOLS_STUB reports a synthetic tabId because the harness has no inspected
  // page, so panel.js's chrome.tabs.get(TAB_ID) cannot resolve. Everything else —
  // including anything thrown while panel.js evaluates — must fail the suite.
  const ENV_ONLY = [/No tab with id/, /Extension context/, /Permissions policy/, /favicon/];
  page.on('console', m => {
    if (m.type() !== 'error') return;
    const t = m.text();
    if (ENV_ONLY.some(re => re.test(t))) return;
    // Resource failures against the panel's own proxy are environment, not code:
    // the harness has no model configured, so a judge call fails at the socket
    // (proxy down) or with a 502 (proxy up, provider unreachable). Matching on the
    // resource URL rather than the message keeps every other failure visible. The
    // engine's fail-closed handling of exactly this is asserted separately.
    if (/^Failed to load resource/.test(t) && /127\.0\.0\.1:808[12]|localhost:808[12]/.test(m.location()?.url || '')) return;
    errors.push(t.substring(0, 200));
  });
  page.on('pageerror', e => errors.push('UNCAUGHT:' + e.message.substring(0, 200)));

  await page.addInitScript(DEVTOOLS_STUB);
  await page.goto(`chrome-extension://${sw.url().split('/')[2]}/panel.html`);
  await page.waitForTimeout(3000);
  return { ctx, page };
}

const errors = [];

test.describe('Void Extension AI Pentest', () => {
  let ctx, page;
  test.beforeAll(async () => {
    ({ ctx, page } = await launchExt());
  });
  test.afterAll(async () => { await ctx?.close(); });

  // ═══ Load + Data ═══
  test('Panel loads', async () => { expect(await page.textContent('body')).toBeTruthy(); });
  test('21+ tabs', async () => { expect(await page.locator('[data-tab]').count()).toBeGreaterThanOrEqual(20); });
  test('VOID_AGENTS=12', async () => { expect(await page.evaluate(() => window.VOID_AGENTS?.length)).toBe(12); });
  test('VOID_SKILLS=32', async () => { expect(await page.evaluate(() => Object.keys(window.VOID_SKILLS||{}).length)).toBe(32); });
  test('VOID_WORKFLOWS=23', async () => { expect(await page.evaluate(() => window.VOID_WORKFLOWS?.length)).toBe(23); });
  test('VOID_PROMPTS=15', async () => { expect(await page.evaluate(() => window.VOID_PROMPTS?.length)).toBe(15); });
  test('VOID_PAYLOADS=10', async () => { expect(await page.evaluate(() => Object.keys(window.VOID_PAYLOADS||{}).length)).toBe(10); });
  test('VOID_VULN_CLASSES=25', async () => { expect(await page.evaluate(() => window.VOID_VULN_CLASSES?.length)).toBe(25); });
  test('VOID_HYBRID_CHECKS=16', async () => { expect(await page.evaluate(() => Object.keys(window.VOID_HYBRID_CHECKS||{}).length)).toBe(16); });

  // ═══ Settings DOM structure ═══
  test('Settings: split layout exists', async () => {
    expect(await page.locator('.settings-left').count()).toBe(1);
    expect(await page.locator('.settings-right').count()).toBe(1);
  });
  test('Settings: 7 AI subtabs', async () => { expect(await page.locator('.ai-settings-tab').count()).toBe(7); });
  test('Models: triple config IDs', async () => {
    expect(await page.locator('#ai-primary-provider').count()).toBe(1);
    expect(await page.locator('#ai-judge-provider').count()).toBe(1);
    expect(await page.locator('#ai-utility-provider').count()).toBe(1);
  });
  test('Models: 3 exec mode buttons', async () => { expect(await page.locator('.ai-exec-mode-btn').count()).toBe(3); });
  test('Agents: every persona plus Custom is selectable', async () => {
    // Populated from VOID_AGENTS at load, so a new persona needs no markup change.
    expect(await page.locator('#ai-persona option').count()).toBe(13);
    expect(await page.locator('#ai-persona option[value="verifier"]').count()).toBe(1);
  });
  test('Engagement: env + mode + toggles exist', async () => {
    expect(await page.locator('#ai-engagement-env').count()).toBe(1);
    expect(await page.locator('#ai-engagement-mode').count()).toBe(1);
    expect(await page.locator('#ai-safety-brute').count()).toBe(1);
    expect(await page.locator('#ai-safety-destructive').count()).toBe(1);
  });
  test('Engagement: 3 presets exist', async () => {
    expect(await page.locator('#ai-preset-prod').count()).toBe(1);
    expect(await page.locator('#ai-preset-preprod').count()).toBe(1);
    expect(await page.locator('#ai-preset-lab').count()).toBe(1);
  });
  test('Vuln table tbody exists', async () => { expect(await page.locator('#ai-vuln-tbody').count()).toBe(1); });
  test('Skills browser elements', async () => {
    expect(await page.locator('#ai-skills-search').count()).toBe(1);
    expect(await page.locator('#ai-skills-list').count()).toBe(1);
    expect(await page.locator('#ai-skills-preview').count()).toBe(1);
  });
  test('Workflows list element', async () => { expect(await page.locator('#ai-wf-list').count()).toBe(1); });
  test('Prompts list element', async () => { expect(await page.locator('#ai-prompts-list').count()).toBe(1); });

  // ═══ AI Chat DOM structure ═══
  test('Chat: projects section', async () => {
    expect(await page.locator('.ai-projects-section').count()).toBe(1);
    expect(await page.locator('#ai-new-project').count()).toBe(1);
  });
  test('Chat: agent quick-switch', async () => {
    expect(await page.locator('.ai-agent-btn[data-agent="pentester"]').count()).toBe(1);
    expect(await page.locator('.ai-agent-btn[data-agent="analyst"]').count()).toBe(1);
    expect(await page.locator('.ai-agent-btn[data-agent="orchestrator"]').count()).toBe(1);
  });
  test('Chat: mode toggle', async () => {
    expect(await page.locator('.ai-mode-btn[data-aimode="interactive"]').count()).toBe(1);
    expect(await page.locator('.ai-mode-btn[data-aimode="autonomous"]').count()).toBe(1);
  });
  test('Chat: slash panel element', async () => { expect(await page.locator('#ai-slash-panel').count()).toBe(1); });
  test('Chat: context bar element', async () => { expect(await page.locator('#ai-context-bar').count()).toBe(1); });
  test('Chat: auto progress bar', async () => { expect(await page.locator('#ai-auto-bar').count()).toBe(1); });

  // ═══ Wizard DOM ═══
  test('Wizard: overlay exists', async () => { expect(await page.locator('#ai-wizard-overlay').count()).toBe(1); });
  test('Wizard: 4 step dots', async () => { expect(await page.locator('.ai-wizard-dot').count()).toBe(4); });
  test('Wizard: no workflow step', async () => {
    // Creating a project must not ask the user to commit to a scan workflow.
    expect(await page.locator('#wiz-workflow').count()).toBe(0);
    const created = await page.evaluate(() => { wizOpen(); wizClose(); return 'ok'; });
    expect(created).toBe('ok');
  });
  test('Wizard: all step inputs', async () => {
    expect(await page.locator('#wiz-name').count()).toBe(1);
    expect(await page.locator('#wiz-scope-input').count()).toBe(1);
    expect(await page.locator('#wiz-username').count()).toBe(1);
    expect(await page.locator('#wiz-env').count()).toBe(1);
  });

  // ═══ Slide panels ═══
  test('Findings panel exists', async () => { expect(await page.locator('#ai-findings-panel').count()).toBe(1); });
  test('Scope panel exists', async () => { expect(await page.locator('#ai-scope-panel').count()).toBe(1); });
  test('Findings: export buttons', async () => {
    expect(await page.locator('#ai-findings-export-md').count()).toBe(1);
    expect(await page.locator('#ai-findings-export-json').count()).toBe(1);
  });

  // ═══ Functional: evaluate-based interactions ═══
  // Functional tests use evaluate — panel.js vars use `let` which creates TDZ when
  // called from evaluate before DOMContentLoaded. These functions ARE global but need
  // the init to have run. We verify the functions exist and are callable.
  test('getActiveSystemPrompt function exists', async () => {
    const exists = await page.evaluate(() => typeof getActiveSystemPrompt === 'function');
    expect(exists).toBe(true);
  });
  test('pentestCreateProject function exists', async () => {
    const exists = await page.evaluate(() => typeof pentestCreateProject === 'function');
    expect(exists).toBe(true);
  });
  test('pentestGetActive function exists', async () => {
    const exists = await page.evaluate(() => typeof pentestGetActive === 'function');
    expect(exists).toBe(true);
  });
  test('slashBuildItems returns 40+ items', async () => {
    const count = await page.evaluate(() => {
      try { return slashBuildItems().length; } catch { return -1; }
    });
    expect(count).toBeGreaterThan(40);
  });

  // ═══ Secret vault — real crypto against real chrome.storage ═══
  // Runs as an ordered sequence: set passphrase -> save -> lock -> unlock.
  const PASSPHRASE = 'correct horse battery staple';
  const SECRET = 'sk-e2e-primary-key-should-never-hit-disk';
  const PROXY_PASS = 'e2e-proxy-password';

  // Read everything chrome.storage.local holds, from inside the extension page.
  const readStorage = () => page.evaluate(() => new Promise(r => chrome.storage.local.get(null, r)));

  test('Vault: bar and modal exist', async () => {
    expect(await page.locator('#ai-vault-bar').count()).toBe(1);
    expect(await page.locator('#vault-overlay').count()).toBe(1);
    expect(await page.locator('#vault-pass').count()).toBe(1);
    expect(await page.locator('#vault-pass2').count()).toBe(1);
  });

  test('Vault: starts locked with no vault configured', async () => {
    const state = await page.evaluate(() => ({ unlocked: vaultUnlocked(), exists: vaultExists() }));
    expect(state).toEqual({ unlocked: false, exists: false });
    await expect(page.locator('#ai-vault-status')).toHaveText(/No passphrase set/);
  });

  test('Vault: modal survives the wizard having been opened', async () => {
    // Regression: the modal body reused .ai-wizard-step, and wizUpdateUI toggles
    // `hidden` on every element with that class document-wide. Opening the project
    // wizard once permanently hid the vault modal's inputs for the rest of the
    // session — the modal appeared as a header and footer with nothing between.
    await page.evaluate(() => { wizOpen(); wizClose(); });
    await page.evaluate(() => vaultOpenModal('create'));
    await expect(page.locator('#vault-pass')).toBeVisible();
    await expect(page.locator('#vault-modal-desc')).toBeVisible();
    await page.evaluate(() => vaultCloseModal());
  });

  test('Vault: setup button opens the modal with a confirm field', async () => {
    await page.evaluate(() => showTab('settings'));
    await page.locator('.ai-settings-tab[data-aitab="models"]').click();
    await page.locator('#ai-vault-setup').click(); // real click — proves wireVaultUI ran
    await expect(page.locator('#vault-overlay')).toBeVisible();
    await expect(page.locator('#vault-confirm-row')).toBeVisible();
    await expect(page.locator('#vault-modal-title')).toHaveText('Set vault passphrase');
  });

  test('Vault: mismatched passphrases are rejected', async () => {
    await page.locator('#vault-pass').fill(PASSPHRASE);
    await page.locator('#vault-pass2').fill('something else');
    await page.locator('#vault-ok').click();
    await expect(page.locator('#vault-error')).toHaveText(/do not match/);
    expect(await page.evaluate(() => vaultExists())).toBe(false);
  });

  test('Vault: short passphrases are rejected', async () => {
    await page.locator('#vault-pass').fill('short');
    await page.locator('#vault-pass2').fill('short');
    await page.locator('#vault-ok').click();
    await expect(page.locator('#vault-error')).toHaveText(/at least 8/);
    expect(await page.evaluate(() => vaultExists())).toBe(false);
  });

  test('Vault: matching passphrase creates and unlocks the vault', async () => {
    await page.locator('#vault-pass').fill(PASSPHRASE);
    await page.locator('#vault-pass2').fill(PASSPHRASE);
    await page.locator('#vault-ok').click();
    await expect(page.locator('#vault-overlay')).toBeHidden();
    expect(await page.evaluate(() => ({ unlocked: vaultUnlocked(), exists: vaultExists() })))
      .toEqual({ unlocked: true, exists: true });
    await expect(page.locator('#ai-vault-bar')).toHaveClass(/unlocked/);
    await expect(page.locator('#ai-vault-lock')).toBeVisible();
    await expect(page.locator('#ai-vault-setup')).toBeHidden();
  });

  test('Vault: passphrase is not left in the DOM', async () => {
    expect(await page.locator('#vault-pass').inputValue()).toBe('');
    expect(await page.locator('#vault-pass2').inputValue()).toBe('');
  });

  test('Vault: saved secrets never reach storage in plaintext', async () => {
    await page.locator('#ai-primary-key').fill(SECRET);
    await page.locator('#cfg-auth-pass').fill(PROXY_PASS);
    await page.evaluate(() => saveSettings());
    await page.waitForTimeout(500); // sealing is async

    const stored = await readStorage();
    const dump = JSON.stringify(stored);
    expect(dump).not.toContain(SECRET);
    expect(dump).not.toContain(PROXY_PASS);
    expect(dump).not.toContain(PASSPHRASE);
    expect(stored.voidSettings.aiPrimaryKey).toBe('');
    expect(stored.voidSettings.authPass).toBe('');
    expect(stored.voidSettings.__secrets.aiPrimaryKey).toHaveProperty('ct');
    expect(stored.voidSettings.__secrets.aiPrimaryKey).toHaveProperty('iv');
    // Vault metadata is a salt + verifier, never the derived key
    expect(stored.voidVault).toHaveProperty('salt');
    expect(stored.voidVault).toHaveProperty('verifier');
    expect(stored.voidVault).not.toHaveProperty('key');
  });

  test('Vault: project credentials are encrypted too', async () => {
    await page.evaluate(s => pentestCreateProject({
      name: 'E2E Vault Project', username: 'admin', password: s.pw, apiToken: s.tok,
    }), { pw: 'e2e-project-password', tok: 'e2e-project-token' });
    await page.waitForTimeout(500);

    const stored = await readStorage();
    const dump = JSON.stringify(stored.voidPentestProjects);
    expect(dump).not.toContain('e2e-project-password');
    expect(dump).not.toContain('e2e-project-token');
    const proj = stored.voidPentestProjects.find(p => p.name === 'E2E Vault Project');
    expect(proj.credentials.password).toBe('');
    expect(proj.credentials.username).toBe('admin'); // non-secret field untouched
    expect(proj.credentials.__secrets.password).toHaveProperty('ct');
  });

  test('Vault: export and profiles are redacted', async () => {
    const red = await page.evaluate(() => vaultRedact(settings));
    expect(JSON.stringify(red)).not.toContain(SECRET);
    expect(red.aiPrimaryKey).toBeUndefined();
    expect(red.authPass).toBeUndefined();
    expect(red.__secrets).toBeUndefined();
  });

  test('Vault: saving a session does not smuggle secrets into storage', async () => {
    // buildSessionData() embeds the whole settings object, and a session is both
    // written to storage and offered as a downloadable file — it bypassed the vault
    // completely until settings were redacted at the source.
    const sessionJson = await page.evaluate(() => JSON.stringify(buildSessionData()));
    expect(sessionJson).not.toContain(SECRET);
    expect(sessionJson).not.toContain(PROXY_PASS);

    await page.evaluate(() => {
      document.getElementById('session-name').value = 'E2E Vault Session';
      return saveSessionToBrowser();
    });
    await page.waitForTimeout(500);
    const stored = await readStorage();
    expect(Object.keys(stored.voidSessions || {}).length).toBeGreaterThan(0); // it really saved

    // Sweep EVERY key in storage, not just the ones we expect to be involved.
    const dump = JSON.stringify(await readStorage());
    expect(dump).not.toContain(SECRET);
    expect(dump).not.toContain(PROXY_PASS);
    expect(dump).not.toContain('e2e-project-password');
    expect(dump).not.toContain('e2e-project-token');
  });

  test('Vault: lock wipes plaintext from memory and the UI', async () => {
    await page.locator('#ai-vault-lock').click();
    expect(await page.evaluate(() => vaultUnlocked())).toBe(false);
    expect(await page.evaluate(() => settings.aiPrimaryKey)).toBe('');
    expect(await page.evaluate(() => pentestProjects.find(p => p.name === 'E2E Vault Project').credentials.password)).toBe('');
    expect(await page.locator('#ai-primary-key').inputValue()).toBe('');
    await expect(page.locator('#ai-primary-key')).toHaveAttribute('placeholder', /locked/);
    await expect(page.locator('#ai-vault-unlock')).toBeVisible();
  });

  test('Vault: wrong passphrase is rejected on unlock', async () => {
    await page.locator('#ai-vault-unlock').click();
    await page.locator('#vault-pass').fill('definitely not the passphrase');
    await page.locator('#vault-ok').click();
    await expect(page.locator('#vault-error')).toHaveText(/Wrong passphrase/);
    expect(await page.evaluate(() => vaultUnlocked())).toBe(false);
    expect(await page.evaluate(() => settings.aiPrimaryKey)).toBe('');
  });

  test('Vault: correct passphrase restores every secret', async () => {
    await page.locator('#vault-pass').fill(PASSPHRASE);
    await page.locator('#vault-ok').click();
    await expect(page.locator('#vault-overlay')).toBeHidden();
    expect(await page.evaluate(() => vaultUnlocked())).toBe(true);
    expect(await page.evaluate(() => settings.aiPrimaryKey)).toBe(SECRET);
    expect(await page.evaluate(() => settings.authPass)).toBe(PROXY_PASS);
    expect(await page.evaluate(() => pentestProjects.find(p => p.name === 'E2E Vault Project').credentials.password))
      .toBe('e2e-project-password');
    // UI repopulated from the decrypted settings
    expect(await page.locator('#ai-primary-key').inputValue()).toBe(SECRET);
  });

  test('Vault: re-key invalidates the old passphrase', async () => {
    await page.locator('#ai-vault-change').click();
    await expect(page.locator('#vault-modal-title')).toHaveText('Change vault passphrase');
    await page.locator('#vault-pass').fill('a completely new passphrase');
    await page.locator('#vault-pass2').fill('a completely new passphrase');
    await page.locator('#vault-ok').click();
    await expect(page.locator('#vault-overlay')).toBeHidden();
    await page.waitForTimeout(500);

    await page.locator('#ai-vault-lock').click();
    await page.locator('#ai-vault-unlock').click();
    await page.locator('#vault-pass').fill(PASSPHRASE); // the old one
    await page.locator('#vault-ok').click();
    await expect(page.locator('#vault-error')).toHaveText(/Wrong passphrase/);

    await page.locator('#vault-pass').fill('a completely new passphrase');
    await page.locator('#vault-ok').click();
    await expect(page.locator('#vault-overlay')).toBeHidden();
    // Both halves must survive — re-encrypting settings but not projects passed
    // every test while silently destroying every stored credential.
    expect(await page.evaluate(() => settings.aiPrimaryKey)).toBe(SECRET);
    expect(await page.evaluate(() => settings.authPass)).toBe(PROXY_PASS);
    expect(await page.evaluate(() => pentestProjects.find(p => p.name === 'E2E Vault Project').credentials.password))
      .toBe('e2e-project-password');
    // ...and the new ciphertext is on disk, not just in memory
    const dump = JSON.stringify(await readStorage());
    expect(dump).not.toContain(SECRET);
    expect(dump).not.toContain('e2e-project-password');
  });

  // ═══ Credential scan before export ═══
  // M&R rules and auto-headers are deliberately NOT vault-encrypted (background.js
  // applies them on every request), so the protection is a warning before a file
  // carrying them leaves the machine.
  test('Export scan: flags Authorization and Cookie values', async () => {
    const hits = await page.evaluate(() => scanForCredentials({
      autoHeaders: 'Authorization: Bearer abcdefghijklmnop\nX-Trace: 1',
      matchReplace: [{ match: 'a', replace: 'Cookie: PHPSESSID=8f3a9c2b7d1e' }],
    }));
    const names = hits.map(h => h.name);
    expect(names).toContain('Authorization header');
    expect(names).toContain('Bearer token');
    expect(names).toContain('Cookie header');
    expect(hits.some(h => h.field === 'autoHeaders')).toBe(true);
    expect(hits.some(h => h.field === 'matchReplace')).toBe(true);
  });

  test('Export scan: flags a JWT anywhere in a rule', async () => {
    const hits = await page.evaluate(() => scanForCredentials({
      matchReplace: [{ match: 'x', replace: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NX0.dBjftJeZ4CVP' }],
    }));
    expect(hits.map(h => h.name)).toContain('JWT');
  });

  test('Export scan: stays quiet on ordinary rules', async () => {
    const hits = await page.evaluate(() => scanForCredentials({
      autoHeaders: 'X-Requested-With: XMLHttpRequest\nAccept: application/json',
      matchReplace: [{ match: 'foo', replace: 'bar' }],
    }));
    expect(hits).toHaveLength(0);
  });

  test('Export scan: redaction empties only the scanned fields', async () => {
    const out = await page.evaluate(() => redactCredentialFields({
      autoHeaders: 'Authorization: Bearer secret-value-here',
      matchReplace: [{ match: 'a', replace: 'b' }],
      timeout: '30000',
      scopeInclude: 'example.com',
    }));
    expect(out.autoHeaders).toBe('');
    expect(out.matchReplace).toEqual([]);
    expect(out.timeout).toBe('30000');       // untouched
    expect(out.scopeInclude).toBe('example.com');
  });

  test('Export scan: dialog lists the findings and Cancel resolves cancel', async () => {
    const choice = page.evaluate(() => confirmCredentialExport([
      { field: 'autoHeaders', name: 'Authorization header' },
      { field: 'matchReplace', name: 'Session cookie' },
    ]));
    await expect(page.locator('#export-scan-overlay')).toBeVisible();
    await expect(page.locator('#export-scan-list li')).toHaveCount(2);
    await expect(page.locator('#export-scan-list')).toContainText('Authorization header');
    await expect(page.locator('#export-scan-list')).toContainText('in matchReplace');
    await page.locator('#export-scan-cancel').click();
    expect(await choice).toBe('cancel');
    await expect(page.locator('#export-scan-overlay')).toBeHidden();
  });

  test('Export scan: Redact button resolves redact', async () => {
    const choice = page.evaluate(() => confirmCredentialExport([{ field: 'autoHeaders', name: 'JWT' }]));
    await expect(page.locator('#export-scan-overlay')).toBeVisible();
    await page.locator('#export-scan-redact').click();
    expect(await choice).toBe('redact');
  });

  // ═══ Intruder grep + payload processing ═══
  test('Intruder: row builder emits all 8 columns', async () => {
    const tdCount = await page.evaluate(() => {
      const html = intrRowCells({ id: 1, payload: 'p', status: 200, elapsed: 5, grepMatch: true, grepExtract: 'hit' }, 'x', '10', 'body');
      const d = document.createElement('tbody');
      d.innerHTML = '<tr>' + html + '</tr>';
      return d.querySelectorAll('td').length;
    });
    const thCount = await page.locator('#intr-table thead th').count();
    expect(tdCount).toBe(thCount); // was 6 vs 8 — preview rendered under "Grep"
    expect(tdCount).toBe(8);
  });

  test('Intruder: grep match and extract reach the row', async () => {
    const html = await page.evaluate(() =>
      intrRowCells({ id: 3, payload: 'admin', status: 200, elapsed: 12, grepMatch: true, grepExtract: 'token=abc' }, 'ok', '1k', 'preview'));
    expect(html).toContain('intr-grep-hit');
    expect(html).toContain('token=abc');
  });

  test('Intruder: grep regex drives match and extract', async () => {
    const out = await page.evaluate(() => {
      document.getElementById('intr-grep-match').value = 'admin panel';
      document.getElementById('intr-grep-extract').value = 'csrf_token=([a-f0-9]+)';
      const hit = intrGrepResult('welcome to the admin panel, csrf_token=deadbeef99');
      const miss = intrGrepResult('403 forbidden');
      document.getElementById('intr-grep-match').value = '';
      document.getElementById('intr-grep-extract').value = '';
      return { hit, miss };
    });
    expect(out.hit.grepMatch).toBe(true);
    expect(out.hit.grepExtract).toBe('deadbeef99'); // capture group, not whole match
    expect(out.miss.grepMatch).toBe(false);
  });

  test('Intruder: an invalid grep regex does not throw', async () => {
    const out = await page.evaluate(() => {
      document.getElementById('intr-grep-match').value = '([unclosed';
      const r = intrGrepResult('anything');
      document.getElementById('intr-grep-match').value = '';
      return r;
    });
    expect(out.grepMatch).toBe(false);
  });

  test('Intruder: payload processing actually transforms payloads', async () => {
    const out = await page.evaluate(async () => ({
      urlenc: await intrProcessPayload('a b&c', 'url-encode', ''),
      b64: await intrProcessPayload('admin', 'base64-encode', ''),
      upper: await intrProcessPayload('admin', 'uppercase', ''),
      prefix: await intrProcessPayload('admin', 'prefix', 'x-'),
      suffix: await intrProcessPayload('admin', 'suffix', '!'),
      none: await intrProcessPayload('admin', '', ''),
    }));
    expect(out.urlenc).toBe('a%20b%26c');
    expect(out.b64).toBe('YWRtaW4=');
    expect(out.upper).toBe('ADMIN');
    expect(out.prefix).toBe('x-admin');
    expect(out.suffix).toBe('admin!');
    expect(out.none).toBe('admin');
  });

  test('Intruder: SHA-1 and SHA-256 really hash', async () => {
    // These used to return the payload untouched, silently running a completely
    // different attack from the one selected.
    const out = await page.evaluate(async () => ({
      sha1: await intrProcessPayload('abc', 'sha1', ''),
      sha256: await intrProcessPayload('abc', 'sha256', ''),
      md5: await intrProcessPayload('abc', 'md5', ''),
    }));
    expect(out.sha1).toBe('a9993e364706816aba3e25717850c26c9cd0d89d');
    expect(out.sha256).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    expect(out.md5).toBe('900150983cd24fb0d6963f7d28e17f72');
  });

  test('Intruder: processing is applied when building requests', async () => {
    const raw = await page.evaluate(async () => {
      document.getElementById('intr-proc').value = 'base64-encode';
      const reqs = await intrBuildRequests('GET /?u=§x§ HTTP/1.1', 'battering-ram', ['admin']);
      document.getElementById('intr-proc').value = '';
      return reqs.map(r => r.raw);
    });
    expect(raw[0]).toContain('YWRtaW4=');  // processed
    expect(raw[0]).not.toContain('=admin'); // not the raw payload
  });

  // ═══ User content: editable + creatable personas/skills/workflows/prompts ═══
  // The data/*.js files are build artifacts, so edits live in a chrome.storage
  // overlay merged over the shipped data at load.
  test('UC: toolbars exist for all four kinds', async () => {
    for (const kind of ['agents', 'skills', 'workflows', 'prompts']) {
      for (const act of ['new', 'edit', 'dup', 'del', 'restore']) {
        expect(await page.locator(`#uc-${act}-${kind}`).count(), `uc-${act}-${kind}`).toBe(1);
      }
    }
  });

  test('UC: builtins are snapshotted before any overlay', async () => {
    const snap = await page.evaluate(() => ({
      agents: ucBuiltin.agents.length,
      skills: Object.keys(ucBuiltin.skills).length,
      workflows: ucBuiltin.workflows.length,
      prompts: ucBuiltin.prompts.length,
    }));
    expect(snap).toEqual({ agents: 12, skills: 32, workflows: 23, prompts: 15 });
  });

  test('UC: creating a prompt adds it to the live registry', async () => {
    await page.evaluate(() => ucUpsert('prompts', 'e2e-custom', {
      id: 'e2e-custom', name: 'E2E Custom', category: 'test',
      template: 'Probe {{target}} now', tags: ['target'],
    }));
    const found = await page.evaluate(() => window.VOID_PROMPTS.find(p => p.id === 'e2e-custom'));
    expect(found.name).toBe('E2E Custom');
    expect(await page.evaluate(() => ucIsCustom('prompts', 'e2e-custom'))).toBe(true);
    // It must survive a reload of the overlay, i.e. actually be persisted.
    const persisted = await page.evaluate(async () => {
      const s = await new Promise(r => chrome.storage.local.get('voidUserContent', r));
      return s.voidUserContent.overrides.prompts['e2e-custom'].template;
    });
    expect(persisted).toBe('Probe {{target}} now');
  });

  test('UC: editing a built-in overrides it without touching the snapshot', async () => {
    await page.evaluate(() => ucUpsert('agents', 'pentester', { title: 'Edited Pentester' }));
    expect(await page.evaluate(() => window.VOID_AGENTS.find(a => a.id === 'pentester').title))
      .toBe('Edited Pentester');
    // The merge is a shallow overlay, so untouched fields still come from the builtin.
    expect(await page.evaluate(() => !!window.VOID_AGENTS.find(a => a.id === 'pentester').systemPrompt))
      .toBe(true);
    expect(await page.evaluate(() => ucBuiltin.agents.find(a => a.id === 'pentester').title))
      .not.toBe('Edited Pentester');
    expect(await page.evaluate(() => ucIsModified('agents', 'pentester'))).toBe(true);
  });

  test('UC: restore brings the shipped version back', async () => {
    await page.evaluate(() => ucRestore('agents', 'pentester'));
    const title = await page.evaluate(() => window.VOID_AGENTS.find(a => a.id === 'pentester').title);
    expect(title).toBe('Pentester');
    expect(await page.evaluate(() => ucIsModified('agents', 'pentester'))).toBe(false);
  });

  test('UC: deleting a built-in hides it and restore undoes that', async () => {
    await page.evaluate(() => ucRemove('workflows', 'full-pentest'));
    expect(await page.evaluate(() => window.VOID_WORKFLOWS.some(w => w.id === 'full-pentest'))).toBe(false);
    await page.evaluate(() => ucRestore('workflows', 'full-pentest'));
    expect(await page.evaluate(() => window.VOID_WORKFLOWS.some(w => w.id === 'full-pentest'))).toBe(true);
  });

  test('UC: skills merge by key, not by array position', async () => {
    await page.evaluate(() => ucUpsert('skills', 'e2e-skill', {
      name: 'E2E Skill', category: 'test', description: 'd', tags: ['t'], body: 'method',
    }));
    expect(await page.evaluate(() => window.VOID_SKILLS['e2e-skill'].name)).toBe('E2E Skill');
    // Editing a shipped skill keeps the fields the override does not mention.
    await page.evaluate(() => ucUpsert('skills', 'xss', { name: 'XSS (edited)' }));
    const xss = await page.evaluate(() => window.VOID_SKILLS.xss);
    expect(xss.name).toBe('XSS (edited)');
    expect(xss.category).toBeTruthy();
    await page.evaluate(() => ucRestore('skills', 'xss'));
    await page.evaluate(() => ucRemove('skills', 'e2e-skill'));
    expect(await page.evaluate(() => 'e2e-skill' in window.VOID_SKILLS)).toBe(false);
  });

  test('UC: custom prompt is reachable from the slash menu', async () => {
    const cmds = await page.evaluate(() => slashBuildItems().map(i => i.cmd));
    expect(cmds.length).toBeGreaterThan(40);
    // Custom skills must show up as slash commands like shipped ones do.
    await page.evaluate(() => ucUpsert('skills', 'e2e-slash', {
      name: 'E2E Slash', category: 'test', description: 'd', tags: [], body: 'x',
    }));
    const after = await page.evaluate(() => slashBuildItems().map(i => i.cmd));
    expect(after).toContain('/e2e-slash');
    await page.evaluate(() => ucRemove('skills', 'e2e-slash'));
  });

  test('UC: editor validates required fields and rejects duplicate ids', async () => {
    await page.evaluate(() => ucOpenEditor('prompts', null));
    await expect(page.locator('#uc-editor-overlay')).toBeVisible();
    await page.locator('#uc-editor-save').click();
    await expect(page.locator('#uc-editor-error')).toContainText('required');

    // An id that already exists must not silently overwrite it.
    await page.evaluate(() => {
      const set = (k, v) => { const i = document.querySelector(`#uc-editor-fields [data-key="${k}"]`); i.value = v; };
      set('id', 'e2e-custom'); set('name', 'Clash'); set('category', 'test'); set('template', 'x');
    });
    await page.locator('#uc-editor-save').click();
    await expect(page.locator('#uc-editor-error')).toContainText('already exists');

    // A bad slug is rejected too.
    await page.evaluate(() => { document.querySelector('#uc-editor-fields [data-key="id"]').value = 'has spaces'; });
    await page.locator('#uc-editor-save').click();
    await expect(page.locator('#uc-editor-error')).toContainText('slug');
    await page.evaluate(() => ucCloseEditor());
    await expect(page.locator('#uc-editor-overlay')).toBeHidden();
  });

  test('UC: workflow editor builds Agent-zero shaped steps', async () => {
    await page.evaluate(() => ucOpenEditor('workflows', null));
    await expect(page.locator('#uc-editor-overlay')).toBeVisible();
    // The container starts empty, so it has no height — assert it exists, then
    // add a step through the real button and assert the card renders.
    expect(await page.locator('#uc-steps-list').count()).toBe(1);
    expect(await page.locator('.uc-step').count()).toBe(0);
    await page.getByRole('button', { name: '+ AGENT', exact: true }).click();
    await expect(page.locator('.uc-step').first()).toBeVisible();
    await expect(page.locator('#uc-steps-list')).toBeVisible();
    const step = await page.evaluate(() => ucEditSteps[ucEditSteps.length - 1]);
    // The shape must carry the Agent-zero fields, not just a skill reference.
    expect(step).toHaveProperty('goal');
    expect(step).toHaveProperty('intrusive');
    expect(step).toHaveProperty('decisionTree');
    expect(step).toHaveProperty('toolGuidance.aiShould');
    expect(step).toHaveProperty('validation.mustReproduce');
    expect(step).toHaveProperty('validation.contextCheck');
    expect(step).toHaveProperty('validation.impactAssessment');

    // The decision tree is the substance of an Agent-zero step, so it must be
    // editable from the UI, not just present in the data shape.
    await page.getByRole('button', { name: '+ Add decision' }).click();
    await expect(page.locator('.uc-dtree-node').first()).toBeVisible();
    await page.locator('.uc-dtree-node input').first().fill('Send a single quote to each field');
    expect(await page.evaluate(() => ucEditSteps[ucEditSteps.length - 1].decisionTree[0].action))
      .toBe('Send a single quote to each field');
    await page.evaluate(() => ucCloseEditor());
  });

  test('UC: cleanup leaves no test entries behind', async () => {
    await page.evaluate(() => ucRemove('prompts', 'e2e-custom'));
    expect(await page.evaluate(() => window.VOID_PROMPTS.some(p => p.id === 'e2e-custom'))).toBe(false);
    expect(await page.evaluate(() => window.VOID_PROMPTS.length)).toBe(15);
    expect(await page.evaluate(() => window.VOID_AGENTS.length)).toBe(12);
    expect(await page.evaluate(() => window.VOID_WORKFLOWS.length)).toBe(23);
    expect(await page.evaluate(() => Object.keys(window.VOID_SKILLS).length)).toBe(32);
  });

  test('Workflows: detail renders goals and decision trees', async () => {
    // The detail pane lives inside the Workflows subtab, so activate it first —
    // otherwise the pane is hidden by its ancestor and nothing is visible.
    await page.evaluate(() => showTab('settings'));
    await page.locator('.ai-settings-tab[data-aitab="workflows"]').click();
    await page.evaluate(() => {
      const wf = window.VOID_WORKFLOWS.find(w => w.id === 'sqli-form');
      aiWfSelectedId = wf.id;
      renderWorkflowDetail(wf);
    });
    await expect(page.locator('#ai-wf-detail')).toBeVisible();
    // The point of the port is that a step shows its decision tree, not just a name.
    expect(await page.locator('.ai-wf-dnode').count()).toBeGreaterThan(3);
    await expect(page.locator('.ai-wf-step-goal').first()).toBeVisible();
    await expect(page.locator('#ai-wf-steps')).toContainText('single quote');
    await expect(page.locator('.ai-wf-step-intrusive').first()).toBeVisible();
    await expect(page.locator('#ai-wf-steps')).toContainText('must reproduce');
  });

  test('Workflows: an engagement renders phases with the workflows they cover', async () => {
    await page.evaluate(() => {
      const wf = window.VOID_WORKFLOWS.find(w => w.id === 'full-pentest');
      renderWorkflowDetail(wf);
    });
    expect(await page.locator('.ai-wf-step').count()).toBe(6);
    await expect(page.locator('#ai-wf-steps')).toContainText('Reconnaissance');
    // Phases inline the goals of the workflows they pull in.
    expect(await page.locator('.ai-wf-include').count()).toBeGreaterThan(3);
    await expect(page.locator('.ai-wf-step-checks').first()).toContainText('csrf');
  });

  // ═══ Workflow engine: steps, branching, triggers, finish, run log ═══
  const FLOW = {
    id: 'e2e-flow', name: 'E2E Flow', description: 'branching test', level: 'engagement',
    category: 'test', initialInstructions: 'Stay in scope. Report everything.',
    triggers: [{ id: 'trig-1', name: 'out of scope', condition: 'the target is out of scope', action: 'stop', target: '' }],
    steps: [
      { id: 'recon', name: 'Recon', type: 'AGENT', agent: 'recon', skills: ['basic-recon'],
        prompt: 'recon-target', goal: 'Map the surface', skillOverrides: {}, next: '' },
      { id: 'gate', name: 'Injectable?', type: 'CONDITION', check: 'Did recon find any input parameters?',
        branches: [{ condition: 'parameters were found', goto: 'inject' }], elseGoto: 'done' },
      { id: 'inject', name: 'Injection', type: 'AGENT', agent: 'injector', skills: ['xss', 'sqli'],
        prompt: '', promptOverride: 'Attack {{target}} now', goal: 'Find injection', next: 'done' },
      { id: 'done', name: 'Done', type: 'FINISH', summary: 'Flow finished' },
    ],
  };

  // Each engine test ensures its own fixture. Depending on a sibling test having
  // created it means one unrelated failure cascades into all of them.
  const ensureFlow = () => page.evaluate(async f => {
    if (!window.VOID_WORKFLOWS.find(w => w.id === f.id)) await ucUpsert('workflows', f.id, f);
  }, FLOW);

  test('Engine: workflow with all three step types round-trips', async () => {
    await ensureFlow();
    const wf = await page.evaluate(() => window.VOID_WORKFLOWS.find(w => w.id === 'e2e-flow'));
    expect(wf.steps.map(s => s.type)).toEqual(['AGENT', 'CONDITION', 'AGENT', 'FINISH']);
    expect(wf.initialInstructions).toContain('Stay in scope');
    expect(wf.triggers).toHaveLength(1);
  });

  test('Engine: a step assembles its own agent and skills into the system prompt', async () => {
    await ensureFlow();
    const sp = await page.evaluate(() => {
      const wf = window.VOID_WORKFLOWS.find(w => w.id === 'e2e-flow');
      return wfStepSystemPrompt(wf.steps.find(s => s.id === 'inject'));
    });
    // The injector agent's prompt plus both selected skill bodies.
    expect(sp).toContain('SKILL:');
    expect(sp.match(/# SKILL:/g).length).toBe(2);

    // An inline override replaces the shared agent prompt without editing it.
    const overridden = await page.evaluate(() =>
      wfStepSystemPrompt({ agent: 'injector', agentOverride: 'ONLY DO WHAT I SAY', skills: [] }));
    expect(overridden).toBe('ONLY DO WHAT I SAY');
    const shared = await page.evaluate(() => window.VOID_AGENTS.find(a => a.id === 'injector').systemPrompt);
    expect(shared).not.toBe('ONLY DO WHAT I SAY');
  });

  test('Engine: a step message carries instructions, log and prompt override', async () => {
    await ensureFlow();
    const msg = await page.evaluate(() => {
      const wf = window.VOID_WORKFLOWS.find(w => w.id === 'e2e-flow');
      wfRun = wfRunNew(wf);
      wfLog('result', 'Recon found 12 endpoints');
      return wfStepMessage(wf, wf.steps.find(s => s.id === 'inject'));
    });
    expect(msg).toContain('INITIAL INSTRUCTIONS');
    expect(msg).toContain('Stay in scope');
    // Later steps see the log, which is what gives each agent context.
    expect(msg).toContain('Recon found 12 endpoints');
    expect(msg).toContain('Attack ');   // the prompt override, with {{target}} rendered
    expect(msg).not.toContain('{{target}}');
    expect(msg).toContain('GOAL: Find injection');
  });

  test('Engine: the run log records every kind of event', async () => {
    await ensureFlow();
    const kinds = await page.evaluate(() => {
      const wf = window.VOID_WORKFLOWS.find(w => w.id === 'e2e-flow');
      wfRun = wfRunNew(wf);
      wfLog('start', 'x'); wfLog('step', 'y'); wfLog('result', 'z');
      wfLog('condition', 'c'); wfLog('trigger', 't'); wfLog('finish', 'f');
      return wfRun.log.map(e => e.kind);
    });
    expect(kinds).toEqual(['start', 'step', 'result', 'condition', 'trigger', 'finish']);
    const stamped = await page.evaluate(() => wfRun.log.every(e => typeof e.t === 'string' && e.t.length > 10));
    expect(stamped).toBe(true);
  });

  test('Engine: default next follows the list, explicit next wins', async () => {
    await ensureFlow();
    const out = await page.evaluate(() => {
      const wf = window.VOID_WORKFLOWS.find(w => w.id === 'e2e-flow');
      return {
        implicit: wfDefaultNext(wf, wf.steps.find(s => s.id === 'recon')),
        explicit: wfDefaultNext(wf, wf.steps.find(s => s.id === 'inject')),
        end: wfDefaultNext(wf, wf.steps.find(s => s.id === 'done')),
      };
    });
    expect(out.implicit).toBe('gate');   // next in the list
    expect(out.explicit).toBe('done');   // step.next
    expect(out.end).toBe(null);          // ran off the end
  });

  test('Engine: a judge that cannot answer fails closed instead of guessing', async () => {
    // No model is configured here, so the call cannot produce a verdict — whether
    // it fails at the socket, at the provider, or on an unparseable body. In every
    // one of those the answer must be false rather than sending the flow down an
    // arbitrary branch, and the reason must say what went wrong.
    const verdict = await page.evaluate(() => wfEvaluate('anything at all', 'no context'));
    expect(verdict.answer).toBe(false);
    expect(verdict.reason).toMatch(/unavailable|unparseable|judge error/);
    expect(verdict.reason.length).toBeGreaterThan(0);
  });

  test('Engine: a condition with no matching branch takes else', async () => {
    await ensureFlow();
    const target = await page.evaluate(async () => {
      const wf = window.VOID_WORKFLOWS.find(w => w.id === 'e2e-flow');
      wfRun = wfRunNew(wf);
      return wfResolveCondition(wf, wf.steps.find(s => s.id === 'gate'));
    });
    expect(target).toBe('done');
    const logged = await page.evaluate(() => wfRun.log.some(e => e.kind === 'condition'));
    expect(logged).toBe(true);
  });

  test('Engine: FINISH ends the run and records why', async () => {
    await ensureFlow();
    await page.evaluate(() => {
      const wf = window.VOID_WORKFLOWS.find(w => w.id === 'e2e-flow');
      wfRun = wfRunNew(wf);
      wfRun.cursor = 'done';
      autoRunning = true; autoPaused = false; autoStepIndex = 0; autoMaxSteps = 10;
      return autoNext();
    });
    expect(await page.evaluate(() => wfRun.status)).toBe('finished');
    expect(await page.evaluate(() => autoRunning)).toBe(false);
    expect(await page.evaluate(() => wfRun.log.some(e => e.kind === 'finish' && e.text.includes('Flow finished')))).toBe(true);
  });

  test('Engine: the step budget stops a flow that loops forever', async () => {
    await page.evaluate(async () => {
      // A step that points at itself would otherwise never terminate.
      await ucUpsert('workflows', 'e2e-loop', {
        id: 'e2e-loop', name: 'Loop', description: '', level: 'atomic', category: 'test',
        steps: [{ id: 'a', name: 'A', type: 'CONDITION', check: '', branches: [], elseGoto: 'a' }],
      });
      const wf = window.VOID_WORKFLOWS.find(w => w.id === 'e2e-loop');
      wfRun = wfRunNew(wf);
      autoRunning = true; autoPaused = false; autoStepIndex = 0; autoMaxSteps = 5;
      return autoNext();
    });
    expect(await page.evaluate(() => autoRunning)).toBe(false);
    expect(await page.evaluate(() => wfRun.visited.length)).toBeLessThanOrEqual(6);
    await page.evaluate(() => ucRemove('workflows', 'e2e-loop'));
  });

  test('Engine: the run log renders into the panel', async () => {
    await ensureFlow();
    await page.evaluate(() => {
      const wf = window.VOID_WORKFLOWS.find(w => w.id === 'e2e-flow');
      wfRun = wfRunNew(wf);
      wfLog('start', 'Workflow started');
      wfLog('trigger', 'out of scope fired');
      document.getElementById('ai-wf-log').classList.remove('hidden');
      wfRenderLog();
    });
    expect(await page.locator('#ai-wf-log .ai-wf-log-row').count()).toBe(2);
    await expect(page.locator('#ai-wf-log')).toContainText('out of scope fired');
    expect(await page.locator('.ai-wf-log-trigger').count()).toBe(1);
    await page.evaluate(() => document.getElementById('ai-wf-log').classList.add('hidden'));
  });

  test('Editor: condition and trigger rows are authorable', async () => {
    await ensureFlow();
    await page.evaluate(() => showTab('settings'));
    await page.locator('.ai-settings-tab[data-aitab="workflows"]').click();
    await page.evaluate(() => ucOpenEditor('workflows', 'e2e-flow'));
    await expect(page.locator('#uc-editor-overlay')).toBeVisible();

    // Four steps, one of each kind styled distinctly.
    expect(await page.locator('.uc-step').count()).toBe(4);
    expect(await page.locator('.uc-step-condition').count()).toBe(1);
    expect(await page.locator('.uc-step-finish').count()).toBe(1);

    // The goto dropdowns offer every step in the flow.
    const opts = await page.locator('.uc-branch select').first().locator('option').allTextContents();
    expect(opts.join(' ')).toContain('Recon');
    expect(opts.join(' ')).toContain('Done');

    // A trigger row exists with its condition and action.
    expect(await page.locator('.uc-trigger').count()).toBe(1);
    await expect(page.locator('.uc-trigger input').nth(1)).toHaveValue('the target is out of scope');

    // Skills are multi-select and reflect what the step already had.
    const checked = await page.locator('.uc-step').nth(2).locator('.uc-skill-tag.on').count();
    expect(checked).toBe(2);
    await page.evaluate(() => ucCloseEditor());
  });

  test('Editor: adding a step of each type works from the buttons', async () => {
    await page.evaluate(() => ucOpenEditor('workflows', null));
    for (const type of ['AGENT', 'CONDITION', 'FINISH']) {
      await page.getByRole('button', { name: '+ ' + type, exact: true }).click();
    }
    expect(await page.locator('.uc-step').count()).toBe(3);
    const types = await page.evaluate(() => ucEditSteps.map(s => s.type));
    expect(types).toEqual(['AGENT', 'CONDITION', 'FINISH']);
    await page.getByRole('button', { name: '+ Add trigger' }).click();
    expect(await page.evaluate(() => ucEditTriggers.length)).toBe(1);
    await page.evaluate(() => ucCloseEditor());
  });

  test('Engine: cleanup', async () => {
    await page.evaluate(() => { wfRun = null; autoRunning = false; return ucRemove('workflows', 'e2e-flow'); });
    expect(await page.evaluate(() => window.VOID_WORKFLOWS.length)).toBe(23);
  });

  // ═══ Console health ═══
  test('No JS console errors', async () => {
    expect(errors, 'Errors: ' + errors.join('; ')).toHaveLength(0);
  });
});
