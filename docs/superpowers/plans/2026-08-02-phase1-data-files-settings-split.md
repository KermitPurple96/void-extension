# Phase 1: Data Files + Settings Split — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create the 6 bundled data files (skills, agents, workflows, prompts, payloads, vuln-classes), split the Settings tab into two columns, move AI config to the right column with triple-model support, add agent persona selector, and add engagement config with per-vuln-class modes.

**Architecture:** Pure client-side Chrome extension. Data files are static JS modules loaded by panel.html. Settings stored in chrome.storage.local under existing `voidSettings` key. No backend changes in this phase.

**Tech Stack:** Vanilla JS, HTML, CSS. No frameworks. chrome.storage.local API. Data exported as window globals via script tags.

**Existing codebase notes:**
- `panel.html` is 2,628 lines. Settings tab starts at line 2017, AI Chat section at line 2444.
- `panel.js` is 10,730 lines. AI tools defined at line 8272, AI_SYSTEM_PROMPT at line 8324.
- `panel.css` is 2,820 lines. Settings styles use `.settings-*` classes.
- All state saved/loaded via `chrome.storage.local` under `voidSettings`.
- No test framework — verification is manual (load extension, inspect UI).

---

### Task 1: Create `data/vuln-classes.js`

**Files:**
- Create: `data/vuln-classes.js`

- [ ] **Step 1: Create the vuln-classes data file**

25 vulnerability class definitions sourced from Agent-zero-pentest engagement_config_api.py. Each entry has: id, name, risk level, safe default mode, and a note explaining the risk.

See spec section 2.10 and the empirical vuln class data in the design doc for the full list. Structure:
```js
window.VOID_VULN_CLASSES = [
  { id: 'xss', name: 'XSS (Reflected/Stored/DOM)', risk: 'low', safeDefault: 'manual', note: 'alert() is harmless' },
  // ... 24 more entries
];
```

- [ ] **Step 2: Verify syntax**

Run: `node --check data/vuln-classes.js`
Expected: no output (success)

- [ ] **Step 3: Commit**

```bash
git add data/vuln-classes.js
git commit -m "feat: add vuln-classes data file (25 vulnerability class definitions)"
```

---

### Task 2: Create `data/agents.js`

**Files:**
- Create: `data/agents.js`

- [ ] **Step 1: Create the agents data file**

11 agent personas ported from Agent-zero-pentest agents_seed/. Each has: id, title, description, context, icon (Material Symbols name), and systemPrompt (functional system prompt text for void-extension's tool set).

Agents: pentester, analyst, orchestrator, injector, recon, apihunter, auditor, authhunter, bughunter, cryptoanalyst, redteam.

Each systemPrompt must reference void-extension's tool names (send_request, check_reflections, get_endpoints, etc.) — not Agent-zero's Python tools.

Structure:
```js
window.VOID_AGENTS = [
  { id: 'pentester', title: 'AI Pentester', description: '...', context: '...', icon: 'security', systemPrompt: '...' },
  // ... 10 more
];
```

- [ ] **Step 2: Verify syntax**

Run: `node --check data/agents.js`
Expected: no output

- [ ] **Step 3: Commit**

```bash
git add data/agents.js
git commit -m "feat: add 11 AI agent personas with system prompts"
```

---

### Task 3: Create `data/payloads.js`

**Files:**
- Create: `data/payloads.js`

- [ ] **Step 1: Read all payload .txt files from Agent-zero-pentest and bundle**

Read every file from `C:\Users\jaime\Agent-zero-pentest\patches\plugins\_pentest_kit\data\payloads\`. Strip comment lines (starting with `#`) and empty lines. Bundle as a JS object keyed by category.

10 categories: xss_tags (243 lines), sqli_auth_bypass (42), ssti_detect (27), cmdi_detect (30), ssrf_bypass (98), cors_origins (43), idor_patterns (71), jwt_attacks (66), cache_deception (46), oauth_redirect (49).

Structure:
```js
window.VOID_PAYLOADS = {
  xss_tags: ['<script>alert(1)</script>', ...],
  sqli_auth_bypass: ["' OR 1=1--", ...],
  // ... 8 more categories
};
```

- [ ] **Step 2: Verify syntax and counts**

Run: `node --check data/payloads.js`
Expected: no output

Run: `node -e "const fs=require('fs'); const src=fs.readFileSync('data/payloads.js','utf8').replace('window.VOID_PAYLOADS','module.exports'); fs.writeFileSync('/tmp/_p.js',src); const p=require('/tmp/_p.js'); console.log(Object.entries(p).map(([k,v])=>k+': '+v.length).join(', '))"`
Expected: counts for each category

- [ ] **Step 3: Commit**

```bash
git add data/payloads.js
git commit -m "feat: add curated payload libraries (10 categories, ~715 payloads)"
```

---

### Task 4: Create `data/workflows.js`

**Files:**
- Create: `data/workflows.js`

- [ ] **Step 1: Create workflow DAG definitions**

6 workflows adapted from Agent-zero-pentest: full-pentest, quick-vuln-scan, injection-testing, auth-session-testing, api-security-audit, bug-bounty-quickwins.

Each workflow has: id, name, description, category, and steps array. Each step has: id, name, type (SKILL/AGENT), skill or agent reference, and dependsOn array.

Structure:
```js
window.VOID_WORKFLOWS = [
  { id: 'full-pentest', name: 'Full Pentest', description: '...', category: 'engagement',
    steps: [
      { id: 'recon', name: 'Reconnaissance', type: 'SKILL', skill: 'basic-recon', dependsOn: [] },
      { id: 'sqli', name: 'SQL Injection', type: 'SKILL', skill: 'sqli', dependsOn: ['recon'] },
      // ...
    ]
  },
  // ... 5 more workflows
];
```

- [ ] **Step 2: Verify syntax**

Run: `node --check data/workflows.js`

- [ ] **Step 3: Commit**

```bash
git add data/workflows.js
git commit -m "feat: add 6 workflow DAG definitions"
```

---

### Task 5: Create `data/prompts.js`

**Files:**
- Create: `data/prompts.js`

- [ ] **Step 1: Create prompt templates**

8 prompt templates: recon-target, test-vuln-class, analyze-response, exploit-finding, generate-report, bypass-waf, judge-response (hybrid), refute-finding (hybrid).

Each has: id, name, category, template (with {{tag}} placeholders), tags array.

The judge-response and refute-finding templates are critical for the hybrid engine — they produce the structured JSON prompts for binary vulnerability judgment.

- [ ] **Step 2: Verify syntax**

Run: `node --check data/prompts.js`

- [ ] **Step 3: Commit**

```bash
git add data/prompts.js
git commit -m "feat: add 8 prompt templates (recon, detection, hybrid judge/refute)"
```

---

### Task 6: Create skeleton `data/skills.js`

**Files:**
- Create: `data/skills.js`

- [ ] **Step 1: Create skills metadata file**

32 skill entries with metadata only (name, category, tags, description). The `body` field is empty string — full methodology texts will be populated in Phase 3 when wired into system prompt injection.

Structure:
```js
window.VOID_SKILLS = {
  'basic-recon': { name: 'Basic Reconnaissance', category: 'recon', tags: [...], description: '...', body: '' },
  'xss': { name: 'Cross-Site Scripting', category: 'injection', tags: [...], description: '...', body: '' },
  // ... 30 more
};
```

- [ ] **Step 2: Verify syntax**

Run: `node --check data/skills.js`

- [ ] **Step 3: Commit**

```bash
git add data/skills.js
git commit -m "feat: add 32 skill definitions (metadata only, full bodies in Phase 3)"
```

---

### Task 7: Load data files in `panel.html`

**Files:**
- Modify: `panel.html` (add script tags before panel.js)

- [ ] **Step 1: Find the panel.js script tag and add data file scripts before it**

```html
<!-- AI Pentest data files -->
<script src="data/vuln-classes.js"></script>
<script src="data/agents.js"></script>
<script src="data/payloads.js"></script>
<script src="data/workflows.js"></script>
<script src="data/prompts.js"></script>
<script src="data/skills.js"></script>
```

- [ ] **Step 2: Commit**

```bash
git add panel.html
git commit -m "feat: load AI pentest data files in panel.html"
```

---

### Task 8: Split Settings tab into two columns (CSS + HTML)

**Files:**
- Modify: `panel.css` (add split layout styles)
- Modify: `panel.html:2017-2498` (Settings tab restructure)

- [ ] **Step 1: Add CSS for split layout and all new AI config components**

Append styles for: `.settings-split`, `.settings-left`, `.settings-right`, `.ai-model-slot`, `.ai-exec-mode-bar`, `.ai-exec-mode-btn`, `.ai-persona-preview`, `.ai-preset-bar`, `.ai-preset-btn`, `.ai-safety-toggle`, `.ai-vuln-table`, `.ai-risk-*` severity colors, `.ai-mode-dot`.

- [ ] **Step 2: Restructure Settings HTML**

Wrap existing settings content (lines 2017-2443, everything BEFORE the "AI Chat" section) in a `<div class="settings-left settings-scroll">`.

Remove the old "AI Chat" settings section (lines 2444-2488).

Add a `<div class="settings-right settings-scroll">` containing:

**Section: Execution Mode** — three buttons: Full AI / Hybrid / Scanner Only

**Section: AI Models** — three model slots, each with: provider dropdown (same 6 options as current), API key input, model name input, endpoint URL input (shown for ollama/custom), and a recommendation note.

**Section: Model Presets** — four buttons: Default / Budget / Max / Local Only

**Section: Agent Persona** — dropdown listing all 11 agents + "Custom" option. Below it: collapsible system prompt preview textarea. Below that: a "Probe Model" button with status output.

**Section: Engagement Config** — environment dropdown, default mode dropdown, three preset buttons (Production/Pre-prod/Lab), two safety toggles (bruteforce, destructive), vuln class table (tbody id="ai-vuln-tbody"), OOB server input + token input.

**Section: Save** — single "Save AI Config" button + status span.

Wrap both columns in `<div class="settings-split">`.

- [ ] **Step 3: Commit**

```bash
git add panel.html panel.css
git commit -m "feat: split Settings tab — left: existing, right: AI Pentest Config"
```

---

### Task 9: Wire Settings save/load for new AI config fields

**Files:**
- Modify: `panel.js` (settings save/load + event listeners)

- [ ] **Step 1: Find settings save/load in panel.js**

Search for `voidSettings` and `cfg-save` to find the serialization functions. Add all new fields to the save object and load them on startup.

New fields on `voidSettings`:
- `aiExecMode` ('full_ai'|'hybrid'|'scanner_only')
- `aiPrimaryProvider`, `aiPrimaryKey`, `aiPrimaryModel`, `aiPrimaryEndpoint`
- `aiJudgeProvider`, `aiJudgeKey`, `aiJudgeModel`, `aiJudgeEndpoint`
- `aiUtilityProvider`, `aiUtilityKey`, `aiUtilityModel`, `aiUtilityEndpoint`
- `aiPersona` (agent id string)
- `aiCustomSystemPrompt` (string)
- `engagementEnv`, `engagementMode`, `engagementBruteforce`, `engagementDestructive`
- `engagementOobServer`, `engagementOobToken`
- `engagementVulnModes` (object: { vulnId: mode })

- [ ] **Step 2: Add event listeners for all new UI elements**

Wire: execution mode buttons, provider dropdowns (show/hide key/endpoint based on provider), model preset buttons, persona dropdown (update preview), engagement preset buttons, safety toggles, vuln class mode dropdowns, OOB inputs, Save button.

- [ ] **Step 3: Implement `getActiveSystemPrompt()` function**

```js
function getActiveSystemPrompt() {
  const personaId = (currentSettings || {}).aiPersona || 'pentester';
  if (personaId === 'custom') return (currentSettings || {}).aiCustomSystemPrompt || AI_SYSTEM_PROMPT;
  const agent = window.VOID_AGENTS?.find(a => a.id === personaId);
  return agent ? agent.systemPrompt : AI_SYSTEM_PROMPT;
}
```

Replace hardcoded `AI_SYSTEM_PROMPT` usage in `aiSendMessage` with `getActiveSystemPrompt()`.

- [ ] **Step 4: Update `aiSendMessage` to use primary model config**

Read provider/model/key/endpoint from the new `aiPrimary*` settings fields. Fall back to old `ai-provider`/`ai-model`/`ai-apikey` fields for backward compatibility.

- [ ] **Step 5: Implement `renderVulnClassTable()` function**

Dynamically render the 25-row vuln class table from `window.VOID_VULN_CLASSES` data. Each row shows: name, risk badge, mode dropdown, effective mode indicator, and note. Dropdown changes update `engagementVulnModes` on `currentSettings`.

- [ ] **Step 6: Implement `applyEngagementPreset()` function**

Three presets: production (ask everything, no brute/destructive), preproduction (manual, no brute/destructive), lab (tool mode, brute allowed). Updates all UI elements and clears per-vuln overrides.

- [ ] **Step 7: Commit**

```bash
git add panel.js
git commit -m "feat: wire Settings save/load for triple model + engagement config"
```

---

### Task 10: Manual verification

**Files:** (no changes)

- [ ] **Step 1: Load extension in Chrome**

Open `chrome://extensions`, enable Developer mode, Load unpacked → void-extension directory. Open any page → F12 → Void tab.

- [ ] **Step 2: Verify Settings layout**

Confirm: two-column layout, left has existing settings, right has AI Pentest Config with all sections.

- [ ] **Step 3: Verify data loaded**

In Void panel's DevTools console:
```js
console.log('Agents:', window.VOID_AGENTS?.length);           // 11
console.log('Skills:', Object.keys(window.VOID_SKILLS||{}).length); // 32
console.log('Workflows:', window.VOID_WORKFLOWS?.length);      // 6
console.log('Prompts:', window.VOID_PROMPTS?.length);          // 8
console.log('Payloads:', Object.keys(window.VOID_PAYLOADS||{}).length); // 10
console.log('Vuln Classes:', window.VOID_VULN_CLASSES?.length); // 25
```

- [ ] **Step 4: Verify settings persistence**

Change execution mode to Hybrid, select "Analyst" persona, apply Lab preset, save. Reload extension. Confirm all settings restored.

- [ ] **Step 5: Verify AI chat uses selected persona**

Switch to AI Chat, start new chat, send a message. Confirm the AI responds according to the selected agent persona's system prompt.
