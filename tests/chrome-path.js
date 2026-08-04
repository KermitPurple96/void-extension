// Resolve a Chromium/Chrome binary for the browser E2E tests.
// Prefers an explicit CHROME_PATH, then the system install, and finally falls back
// to Playwright's bundled download — so the suite runs without a 150MB fetch on
// machines that already have Chrome.
"use strict";
const fs = require("fs");

const CANDIDATES = [
  process.env.CHROME_PATH,
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser",
  "/usr/bin/google-chrome",
  "/usr/bin/google-chrome-stable",
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
];

function chromeExecutable() {
  for (const p of CANDIDATES) {
    if (p && fs.existsSync(p)) return p;
  }
  return null; // let Playwright use its own bundled build
}

module.exports = { chromeExecutable };
