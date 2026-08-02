// Playwright config for void-extension Chrome extension E2E tests
const { defineConfig } = require('@playwright/test');
const path = require('path');

module.exports = defineConfig({
  testDir: __dirname,
  testMatch: '*.spec.js',
  timeout: 60000,
  use: {
    headless: false, // Extensions require headed mode
    viewport: { width: 1400, height: 900 },
  },
  projects: [{
    name: 'chromium-extension',
    use: {
      launchOptions: {
        args: [
          `--disable-extensions-except=${path.resolve(__dirname, '..')}`,
          `--load-extension=${path.resolve(__dirname, '..')}`,
          '--no-first-run',
          '--disable-gpu',
        ],
      },
    },
  }],
  reporter: 'list',
});
