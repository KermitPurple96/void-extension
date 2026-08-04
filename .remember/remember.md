# Handoff

## State
I migrated all AI pentesting capabilities from Agent-zero-pentest into void-extension as a pure browser extension. 28 commits on main, ~5,700 lines added across 18 files. 408 tests (187 original + 184 AI pentest + 37 Playwright browser), all passing. Full code review done — 6 CRITICAL/HIGH issues fixed. Pushed to GitHub.

Phases 1-6 COMPLETE: 8 data files (651KB skills, 519 payloads, 11 agents, 6 workflows, 8 prompts, 25 vuln classes, 16 hybrid checks), Settings split with 7 subtabs (Models/Persona/Engagement/Vulns/Skills/Workflows/Prompts), AI Chat enhanced (projects, wizard, slash commands, agent switch, autonomous mode, slide-in panels), hybrid engine, judge/refute endpoint, 62 AI tools, model probe.

Since then, on 2026-08-04: secret vault, the wizard's workflow step removed, all four
content types made user-editable, workflows rebuilt as a real flow engine, an E2E pass
that caught a dead judge URL, and a deep-research pass over agents/skills/prompts.
Tests: **654 Node** (`npm test`) + **116 Playwright** (`npm run test:browser`), all passing.

## Next
1. **Live run against a target** — needs the proxy up (`npm run proxy`) and a model
   configured. Nothing in the AI path has ever executed against a real model here: the
   judge, the workflow conditions and the triggers are all verified only structurally
   and on their failure paths. This is the biggest untested surface.
2. **Bind workflow steps to agents.** All 23 shipped workflows leave `step.agent` unset,
   so every step runs as whatever persona the user happened to pick. `panel.js` already
   supports per-step agents — wiring `full-pentest` as recon → injector → authhunter →
   verifier → auditor is what turns the persona set into an actual pipeline.
3. **Skill coverage gaps** (researched, not yet written). Ranked: `auth` (whole
   PortSwigger Authentication topic missing), `api` (REST/BOLA/mass-assignment — only
   GraphQL exists), `oauth`, `cache` (poisoning + deception, zero coverage),
   `host-header`, `prototype-pollution`, `clickjacking`, `web-llm`, `cspt`,
   `cloud-storage`, `supply-chain`. Stale bodies: `http-smuggling` (no CL.0/0.CL/TE.0 or
   browser-powered desync), `race-condition` (no single-packet attack), `ssti` (no
   error-based blind), `ssrf` (IMDSv2 named but no attack path), `jwt` (no JWE).
4. **WindowsDevEnv repo** — verify on a fresh machine.

## Context
- Proxy server runs from `C:\tmp\void-extension\` not `C:\tmp\`: `cd C:\tmp\void-extension && node void-proxy-server.js`
- Ollama Cloud key is in Agent-zero `.env` (`OLLAMA_API_KEY`), NOT in void-extension — user must set env var or configure in Settings UI
- `npm test` runs four Node suites; `npm run test:browser` runs two Playwright specs
- The proxy must be running for the E2E authoring spec (it checks and fails with the command)
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
- Key = PBKDF2-SHA256, 600k iterations (OWASP, ~220ms), 16-byte random salt; **memory only**, so the
  vault re-locks when the panel closes. Unlock derives at the count stored WITH the vault, so vaults
  made by older builds (250k) still open; the bar tells them to use Change to upgrade.
  `vaultClampIterations` bounds anything read from storage to [100k, 5M].
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
- `matchReplace` and `autoHeaders` are deliberately NOT in the vault: background.js applies them on
  every request, so encrypting them would make the proxy silently stop rewriting while locked. Instead
  `scanForCredentials` warns before either file-producing export (settings export, session export),
  offering Redact / Export anyway / Cancel. Storage-only writes intentionally do not scan.

## Picking this up on another machine

```bash
git clone https://github.com/KermitPurple96/void-extension && cd void-extension
npm install                                   # ws + @playwright/test
PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 npm install   # if the browser download is unwanted
npm test                                      # 654, no services needed
npm run proxy                                 # 8081 http + 8082 ws, needed for AI and for the
                                              # authoring E2E spec (it fails loudly if absent)
npm run test:browser                          # 116, needs a display and the proxy
```

- Playwright uses the **system** browser via `tests/chrome-path.js`. It prefers
  `/usr/bin/chromium` on purpose: `channel: 'chrome'` was measured here and the
  extension's service worker never registers under Chrome stable, and
  `channel: 'chromium'` demands Playwright's own 150MB download. Override with
  `CHROME_PATH` (it throws if that path does not exist rather than silently using
  another browser). On Windows the candidate list already covers the default install.
- Load the extension unpacked from the repo root at `chrome://extensions`.
- Regenerating bundles needs a checkout of `Agent-zero-pentest` beside this one; pass
  its path to the generators. Without it the shipped `data/*.js` are already complete —
  you only need it to re-derive from upstream.
- **No secrets are in the repo.** Set a vault passphrase in Settings → AI Pentest
  Config → Models first, then enter API keys; they are AES-GCM encrypted per machine,
  so keys entered on one PC do not travel with the repo and must be re-entered here.
- On Kali, `--load-extension` has historically been unreliable for container windows;
  that is a known issue, unrelated to the test harness.

## Content: agents, skills, prompts, workflows

All four are **user-editable in the panel** (New / Edit / Duplicate / Delete / Restore).
`data/*.js` are build artifacts — never edit them by hand. User changes live as an
overlay in `chrome.storage` under `voidUserContent`, merged over the shipped data at
load, so regenerating a bundle does not lose them and Restore is just dropping the
overlay entry.

Generators: `scripts/bundle-skills.js <path-to-Agent-zero-pentest>`,
`scripts/bundle-workflows.py <path>`, `scripts/bundle-payloads.js`.
`skills-local/<slug>/SKILL.md` overrides upstream and is where Void-authored
methodologies live (currently `file-upload`, which upstream ships empty).

**Agents (12).** Rewritten 2026-08-04 from research. Each carries only what must hold
every turn — execution contract, scope and mode, its own tool subset, evidence
contract, quantified stop rules, output shape. Detailed methodology deliberately stays
in skills via `get_skill`; inlining it crowds out the instructions that matter.
- The harness ends the turn on the first text-only reply, so every acting persona now
  states that explicitly. Without it an "autonomous pentest" stops after three calls.
- Personas point at `add_pentest_finding` (rejects without evidence), never
  `add_finding` (a note with no checks). They used to point at the wrong one.
- New `verifier` persona: adversarial, assumes the finding is wrong, uses the
  `judge_candidate` tool that previously no persona used.
- `ask | manual | tool` is now defined in the injected project context; it used to be
  injected as a bare word with no meaning anywhere.

**Skills (32).** 15 of them instructed the model to call `code_execution_tool` with
`/a0/...` paths — Agent Zero's container tooling, which Void does not have. Those were
guaranteed hallucinated tool calls; the generator now sanitises them and appends a
Void tooling note. Zero empty bodies (was 1).

**Prompts (15, was 8).** `data/prompts.js` is now the single source of truth for the
judge and refute wording — `void-proxy-server.js` loads and renders it rather than
keeping its own drifting copy, which meant editing the library changed nothing about
what the judge saw. Added: verify-finding, authz-differential, triage-and-score,
executive-summary, remediation-advice, retest-finding, chain-findings.

## Judge / verification pipeline — the sharp edges

- **Booleans arrive as strings.** `asBool` in the proxy coerces `"false"`/`"no"`/`"0"`.
  The old `if (!result.vulnerable)` read the string `"false"` as truthy and **inverted
  the verdict**. `asBool` returns `null` for anything unusable so "did not answer" stays
  distinguishable from "answered no" — an unusable judge reply now surfaces as
  `verdict: "unknown"` instead of being read as clean.
- **JSON extraction is brace-matched**, not regex. The old non-greedy `/\{[\s\S]*?\}/`
  stopped at the first `}`, so any nested object or a `}` inside a string threw and was
  swallowed. `extractJsonObject` also strips ```` ``` ```` fences and `<think>` blocks.
- Prompts put **reasoning before the verdict** and require a **quote from the response**
  for every claim. The judge is deliberately NOT told what regex a scanner matched — a
  pattern hint is the surface cue a judge overfits to. `max_tokens` is 1024 because
  reason-first output truncated at 512.
- The judge gets a **baseline response and the Content-Type**; without them "reflected
  `<script>`" in a JSON body reads as XSS.
- The refuter is given the raw data and **withheld the reporter's reasoning**, and a
  refutation only counts if it quotes supporting text — otherwise refuting is free and
  it always finds something.

## Workflow engine

`autoNext` walks a **cursor**, not an index, so branches and loops work.
- Step types: `AGENT` (agent + skills[] + prompt, each overridable inline for that
  workflow only), `CONDITION` (AI decides from the log; if/else-if/else rows each with a
  goto dropdown), `FINISH`.
- Workflow-level `initialInstructions` and `triggers` (checked after every step, can
  stop or divert).
- **Context comes from the run log, not the chat.** Every start/step/result/condition/
  trigger/finish is recorded with a timestamp, and that log plus the initial
  instructions plus the project findings is what each subsequent agent receives.
- Conditions and triggers share one judge call and **fail closed** — an unreachable or
  unparseable judge answers false rather than taking an arbitrary branch.
- A step budget scaled to workflow size stops a flow that cycles.
- `VOID_PROXY_CHAT_URL` is a named constant because a hand-copied duplicate of it had
  drifted to a port and path that did not exist, and the fail-closed handling made that
  look like "the judge is offline" for every condition and trigger.

## Testing notes

- `tests/e2e-workflow-authoring.spec.js` only clicks, types and selects — it authors an
  agent, skill, prompt and branching workflow through the UI, then reopens the panel to
  prove it persisted. That is the spec that catches what `page.evaluate` cannot.
- Console-error filtering matches the **failing resource's URL**, not the message text,
  so proxy noise is ignored without hiding anything else. Verified by running the whole
  suite with the proxy both up and down.
- Engine tests each ensure their own fixture; they used to depend on a sibling test and
  one unrelated failure cascaded into four more.
- `tests/judge-parsing.js` pins the two parsing bugs above with the old implementations
  alongside the new ones, so a regression is visible rather than silent.
