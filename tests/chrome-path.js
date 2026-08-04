// Resolve a Chromium/Chrome binary for the browser E2E tests.
//
// Do NOT replace this with Playwright's `channel` option — both alternatives were
// measured and neither works for this repo:
//   channel: 'chrome'    launches Google Chrome, but the extension's service
//                        worker never appears (30s timeout). Chrome stable has
//                        tightened unpacked-extension loading, so --load-extension
//                        does not reliably register an MV3 extension there.
//   channel: 'chromium'  wants Playwright's own downloaded build (~150MB) and
//                        fails outright when it is absent.
// Plain /usr/bin/chromium does load the unpacked extension, which is why the
// ordering below puts chromium ahead of google-chrome. That order is load-bearing.
"use strict";
const fs = require("fs");

// Checked in order; first hit wins.
const CANDIDATES = [
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser",
  "/usr/bin/google-chrome",
  "/usr/bin/google-chrome-stable",
  "/Applications/Chromium.app/Contents/MacOS/Chromium",
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
];

function chromeExecutable() {
  // An explicit CHROME_PATH is an instruction, not a suggestion: falling through
  // to a different browser would mean silently testing something other than what
  // was asked for.
  if (process.env.CHROME_PATH) {
    if (!fs.existsSync(process.env.CHROME_PATH)) {
      throw new Error(`CHROME_PATH is set to "${process.env.CHROME_PATH}" but no such file exists`);
    }
    return process.env.CHROME_PATH;
  }
  for (const p of CANDIDATES) {
    if (fs.existsSync(p)) return p;
  }
  return null; // let Playwright fall back to its own bundled build
}

module.exports = { chromeExecutable, CANDIDATES };
