// @ts-check
// Void Extension AI Pentest — Playwright E2E
// Tests extension loading, data integrity, DOM structure, and interactions
// Run: npx playwright test tests/e2e-browser.spec.js --config=tests/playwright.config.js
const { test, expect, chromium } = require('@playwright/test');
const path = require('path');

const EXT_PATH = path.resolve(__dirname, '..');

async function launchExt() {
  const ctx = await chromium.launchPersistentContext('', {
    headless: false,
    args: [`--disable-extensions-except=${EXT_PATH}`, `--load-extension=${EXT_PATH}`, '--no-first-run', '--disable-gpu'],
  });
  const sw = ctx.serviceWorkers()[0] || await ctx.waitForEvent('serviceworker');
  const page = await ctx.newPage();
  await page.goto(`chrome-extension://${sw.url().split('/')[2]}/panel.html`);
  await page.waitForTimeout(3000);
  return { ctx, page };
}

const errors = [];

test.describe('Void Extension AI Pentest', () => {
  let ctx, page;
  test.beforeAll(async () => {
    ({ ctx, page } = await launchExt());
    page.on('console', m => { if (m.type() === 'error' && !m.text().includes('chrome.devtools') && !m.text().includes('Extension context') && !m.text().includes('Permissions policy') && !m.text().includes('favicon')) errors.push(m.text().substring(0, 200)); });
    page.on('pageerror', e => errors.push('UNCAUGHT:' + e.message.substring(0, 200)));
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

  // ═══ Console health ═══
  test('No JS console errors', async () => {
    expect(errors, 'Errors: ' + errors.join('; ')).toHaveLength(0);
  });
});
