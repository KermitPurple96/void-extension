# Handoff

## State
I migrated all AI pentesting capabilities from Agent-zero-pentest into void-extension as a pure browser extension. 28 commits on main, ~5,700 lines added across 18 files. 408 tests (187 original + 184 AI pentest + 37 Playwright browser), all passing. Full code review done — 6 CRITICAL/HIGH issues fixed. Pushed to GitHub.

Phases 1-6 COMPLETE: 8 data files (651KB skills, 519 payloads, 11 agents, 6 workflows, 8 prompts, 25 vuln classes, 16 hybrid checks), Settings split with 7 subtabs (Models/Persona/Engagement/Vulns/Skills/Workflows/Prompts), AI Chat enhanced (projects, wizard, slash commands, agent switch, autonomous mode, slide-in panels), hybrid engine, judge/refute endpoint, 62 AI tools, model probe.

All three open code-review items are fixed (secret vault, dead code, wizard null-safety),
then a 4-agent code review over that work found and fixed 2 CRITICAL + 4 HIGH on top.
Tests: 509 Node (`npm test`) + 53 Playwright (`npm run test:browser`), all passing.

## Next
1. **Test in real browser** — load extension, set a vault passphrase, create a pentest project, run AI chat against DVWA with deepseek-v4-pro via Ollama Cloud
2. **WindowsDevEnv repo** — earlier session added Microsoft/WindowsDeveloperConfig features (WSL comfort shell, Windows settings, extra tools). Committed but verify it works on a fresh machine.
3. **Phase 5 hybrid engine live test** — run `run_hybrid_scan` tool against DVWA to verify the 16 deterministic checks + judge/refute pipeline works E2E

## Context
- Proxy server runs from `C:\tmp\void-extension\` not `C:\tmp\`: `cd C:\tmp\void-extension && node void-proxy-server.js`
- Ollama Cloud key is in Agent-zero `.env` (`OLLAMA_API_KEY`), NOT in void-extension — user must set env var or configure in Settings UI
- `data/skills.js` is 651KB — `file-upload` skill has empty body (no SKILL.md source exists in Agent-zero)
- `npm test` runs the three Node suites; `npm run test:browser` runs Playwright
- Playwright uses the **system** Chrome/Chromium via `tests/chrome-path.js` (override with `CHROME_PATH`) — no 150MB browser download. Installed with `PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1`.
- **The browser suite used to be much weaker than it looked.** `panel.html` opened as a plain
  extension page has no `chrome.devtools`, so panel.js threw on line 11
  (`chrome.devtools.inspectedWindow.tabId`), aborting the entire script: every top-level `let`
  stayed in TDZ and DOMContentLoaded never registered. Only hoisted functions and static DOM were
  testable. `DEVTOOLS_STUB` in `e2e-browser.spec.js` (via `page.addInitScript`) now stubs it so the
  script evaluates fully — that is what makes runtime tests possible. Keep the stub.

## Secret vault
API keys (`aiPrimaryKey`, `aiJudgeKey`, `aiUtilityKey`, `engagementOobToken`, `authPass`) and project
credentials (`password`, `apiToken`) are AES-GCM encrypted before reaching `chrome.storage.local`.
- Key = PBKDF2-SHA256, 250k iterations, 16-byte random salt; **memory only**, so the vault re-locks when the panel closes.
- Vault bar lives in Settings → AI Pentest Config → Models. Set passphrase / Unlock / Lock / Change.
- Secret inputs read empty while locked — that means encrypted, not unset.
- Settings exports and saved profiles are redacted: they never carry secrets, plaintext or ciphertext.
- **Unlock before using AI features** — a locked panel has no API key, and `authPass` (proxy auth) is empty too.
- Passphrase loss is unrecoverable by design. Re-keying ("Change") requires an unlocked vault.
- Legacy plaintext from earlier builds stays usable for the session and is left on disk untouched until
  the user sets a passphrase — an unrelated save must never destroy it (`vaultLegacySettingKeys`).
- Re-key is ONE atomic `chrome.storage.local.set` of {voidVault, voidSettings, voidPentestProjects}.
  Never split it: a new salt paired with old-key ciphertext unlocks cleanly and then decrypts to nothing.
- All vault writes go through `vaultEnqueueWrite` so overlapping saves can't land out of order.
- Ciphertext that fails to decrypt is recorded in `vaultUndecryptable` and preserved on the next save,
  never overwritten with "" — that turns a recoverable problem into permanent loss.
- Anything that serializes `settings` must redact: session save/export (`buildSessionData`), settings
  profiles, and settings export. Session/profile RESTORE must carry `__secrets` forward.
