// Playwright config for void-extension Chrome extension E2E tests.
//
// There is deliberately no `projects[].use.launchOptions` block here: the spec
// never takes Playwright's `page`/`context` fixtures — loading an unpacked
// extension needs launchPersistentContext, which e2e-browser.spec.js calls itself.
// Anything configured here would be silently ignored, so browser launch settings
// live in launchExt() in the spec instead.
const { defineConfig } = require('@playwright/test');

module.exports = defineConfig({
  testDir: __dirname,
  testMatch: '*.spec.js',
  timeout: 60000,
  // The vault tests run as an ordered sequence sharing one browser context, so a
  // retry would resume against a half-configured vault rather than a clean one.
  retries: 0,
  workers: 1,
  reporter: 'list',
});
