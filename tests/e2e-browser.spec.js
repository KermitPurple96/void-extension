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
    const t = m.text();
    if (m.type() === 'error' && !ENV_ONLY.some(re => re.test(t))) errors.push(t.substring(0, 200));
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
  test('VOID_AGENTS=11', async () => { expect(await page.evaluate(() => window.VOID_AGENTS?.length)).toBe(11); });
  test('VOID_SKILLS=32', async () => { expect(await page.evaluate(() => Object.keys(window.VOID_SKILLS||{}).length)).toBe(32); });
  test('VOID_WORKFLOWS=6', async () => { expect(await page.evaluate(() => window.VOID_WORKFLOWS?.length)).toBe(6); });
  test('VOID_PROMPTS=8', async () => { expect(await page.evaluate(() => window.VOID_PROMPTS?.length)).toBe(8); });
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
  test('Persona: 12 options', async () => { expect(await page.locator('#ai-persona option').count()).toBe(12); });
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
  test('Wizard: 5 step dots', async () => { expect(await page.locator('.ai-wizard-dot').count()).toBe(5); });
  test('Wizard: all step inputs', async () => {
    expect(await page.locator('#wiz-name').count()).toBe(1);
    expect(await page.locator('#wiz-scope-input').count()).toBe(1);
    expect(await page.locator('#wiz-username').count()).toBe(1);
    expect(await page.locator('#wiz-workflow').count()).toBe(1);
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

  // ═══ Console health ═══
  test('No JS console errors', async () => {
    expect(errors, 'Errors: ' + errors.join('; ')).toHaveLength(0);
  });
});
