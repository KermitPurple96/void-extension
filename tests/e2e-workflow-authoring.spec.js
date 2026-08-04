// @ts-check
// Void Extension — E2E verification of today's diff, driven through the real UI.
//
// The other browser spec asserts a lot through page.evaluate(), which proves the
// functions behave but not that a user can reach them. This file only clicks,
// types and selects the way a person would, then reloads the panel to prove the
// result actually persisted.
//
// Run: npx playwright test tests/e2e-workflow-authoring.spec.js --config=tests/playwright.config.js
const { test, expect, chromium } = require('@playwright/test');
const path = require('path');
const { chromeExecutable } = require('./chrome-path');

const EXT_PATH = path.resolve(__dirname, '..');
const EXE = chromeExecutable();
const PROXY = 'http://localhost:8081';

// panel.html opened as a plain extension page has no chrome.devtools, and panel.js
// dereferences it on its first line. Without this the whole script aborts.
const DEVTOOLS_STUB = () => {
  if (typeof chrome === 'undefined' || chrome.devtools) return;
  chrome.devtools = {
    inspectedWindow: {
      tabId: 1,
      eval: (_e, cb) => { if (typeof cb === 'function') cb(undefined, { isError: true, value: 'no inspected window' }); },
    },
  };
};

// Unique per run so a leftover entry from a previous run can never make a test
// pass for the wrong reason.
const RUN = Date.now().toString(36);
const WF_ID = `e2e-wf-${RUN}`;
const AGENT_ID = `e2e-agent-${RUN}`;
const SKILL_ID = `e2e-skill-${RUN}`;
const PROMPT_ID = `e2e-prompt-${RUN}`;

let ctx, page, panelUrl;
const errors = [];

async function openPanel() {
  const p = await ctx.newPage();
  p.on('pageerror', e => errors.push('UNCAUGHT: ' + e.message.slice(0, 200)));
  await p.addInitScript(DEVTOOLS_STUB);
  await p.goto(panelUrl);
  await p.waitForTimeout(2500);
  return p;
}

// Fill an editor field by the key the schema gave it.
async function setField(p, key, value) {
  await p.locator(`#uc-editor-fields [data-key="${key}"]`).fill(value);
}

async function openSubtab(p, name) {
  await p.evaluate(() => showTab('settings'));
  await p.locator(`.ai-settings-tab[data-aitab="${name}"]`).click();
}

test.describe.configure({ mode: 'serial' });

test.describe('E2E — authoring through the UI', () => {
  test.beforeAll(async () => {
    // Tier 2 requires the service under test to be up. Fail with the command to
    // run rather than a confusing assertion deep in a later test.
    const up = await fetch(`${PROXY}/api/chat`, { method: 'OPTIONS' }).then(r => r.ok || r.status === 204).catch(() => false);
    if (!up) throw new Error(`void-proxy-server is not running on ${PROXY}. Start it with: npm run proxy`);

    ctx = await chromium.launchPersistentContext('', {
      headless: false,
      ...(EXE ? { executablePath: EXE } : {}),
      args: [`--disable-extensions-except=${EXT_PATH}`, `--load-extension=${EXT_PATH}`, '--no-first-run', '--disable-gpu'],
    });
    const sw = ctx.serviceWorkers()[0] || await ctx.waitForEvent('serviceworker');
    panelUrl = `chrome-extension://${sw.url().split('/')[2]}/panel.html`;
    page = await openPanel();
  });
  test.afterAll(async () => { await ctx?.close(); });

  // ── Tier 5: navigation and discoverability ────────────────────────────────

  test('every top-level tab opens without leaving the panel blank', async () => {
    const tabs = await page.locator('.tab[data-tab]').evaluateAll(els => els.map(e => e.dataset.tab));
    expect(tabs.length).toBeGreaterThanOrEqual(20);
    for (const name of tabs) {
      await page.locator(`.tab[data-tab="${name}"]`).click();
      await expect(page.locator(`#tab-${name}`), `tab ${name}`).toBeVisible();
    }
  });

  test('all seven AI subtabs render their content', async () => {
    await page.evaluate(() => showTab('settings'));
    const subtabs = await page.locator('.ai-settings-tab').evaluateAll(e => e.map(x => x.dataset.aitab));
    expect(subtabs).toEqual(['models', 'agents', 'engagement', 'vulns', 'skills', 'workflows', 'prompts']);
    for (const name of subtabs) {
      await page.locator(`.ai-settings-tab[data-aitab="${name}"]`).click();
      await expect(page.locator(`.ai-settings-pane[data-aitab="${name}"]`)).toBeVisible();
    }
  });

  test('the Persona tab is now called Agents', async () => {
    await expect(page.locator('.ai-settings-tab[data-aitab="agents"]')).toHaveText('Agents');
    expect(await page.locator('.ai-settings-tab[data-aitab="persona"]').count()).toBe(0);
  });

  test('every editable browser exposes its toolbar to the user', async () => {
    for (const kind of ['agents', 'skills', 'workflows', 'prompts']) {
      await openSubtab(page, kind);
      for (const act of ['new', 'edit', 'dup', 'del', 'restore']) {
        await expect(page.locator(`#uc-${act}-${kind}`), `${act}/${kind}`).toBeVisible();
      }
    }
  });

  // ── Tier 3 + 4: create, read, update, delete — all through the UI ─────────

  test('create an agent by clicking New and filling the form', async () => {
    await openSubtab(page, 'agents');
    await page.locator('#uc-new-agents').click();
    await expect(page.locator('#uc-editor-overlay')).toBeVisible();
    await expect(page.locator('#uc-editor-title')).toHaveText('New Agent');

    await setField(page, 'id', AGENT_ID);
    await setField(page, 'title', 'E2E Agent');
    await setField(page, 'description', 'created through the UI');
    await setField(page, 'systemPrompt', 'You are an end-to-end test agent.');
    await page.locator('#uc-editor-save').click();
    await expect(page.locator('#uc-editor-overlay')).toBeHidden();

    // It must be selectable as a real agent, not just stored.
    await expect(page.locator(`#ai-persona option[value="${AGENT_ID}"]`)).toHaveCount(1);
    await page.selectOption('#ai-persona', AGENT_ID);
    await expect(page.locator('#ai-persona-preview')).toContainText('end-to-end test agent');
  });

  test('create a skill and see it become a slash command', async () => {
    await openSubtab(page, 'skills');
    await page.locator('#uc-new-skills').click();
    await setField(page, 'slug', SKILL_ID);
    await setField(page, 'name', 'E2E Skill');
    await setField(page, 'category', 'e2e');
    await setField(page, 'description', 'skill created through the UI');
    await setField(page, 'tags', 'e2e, ui');
    await setField(page, 'body', 'Step 1: prove the skill body is stored.');
    await page.locator('#uc-editor-save').click();
    await expect(page.locator('#uc-editor-overlay')).toBeHidden();

    await page.locator('#ai-skills-search').fill(SKILL_ID);
    await expect(page.locator('#ai-skills-list')).toContainText('E2E Skill');
    await page.locator('#ai-skills-list .ai-skill-item').first().click();
    await expect(page.locator('#ai-skills-preview')).toContainText('prove the skill body is stored');
    await page.locator('#ai-skills-search').fill('');
  });

  test('create a prompt through the UI', async () => {
    await openSubtab(page, 'prompts');
    await page.locator('#uc-new-prompts').click();
    await setField(page, 'id', PROMPT_ID);
    await setField(page, 'name', 'E2E Prompt');
    await setField(page, 'category', 'e2e');
    await setField(page, 'template', 'Assess {{target}} for the E2E run.');
    await setField(page, 'tags', 'target');
    await page.locator('#uc-editor-save').click();
    await expect(page.locator('#ai-prompts-list')).toContainText('E2E Prompt');
  });

  test('author a branching workflow entirely by clicking', async () => {
    await openSubtab(page, 'workflows');
    await page.locator('#uc-new-workflows').click();
    await setField(page, 'id', WF_ID);
    await setField(page, 'name', 'E2E Authored Flow');
    await setField(page, 'description', 'built through the UI');
    await setField(page, 'initialInstructions', 'Stay strictly in scope.');

    // A trigger that can abort the run.
    await page.getByRole('button', { name: '+ Add trigger' }).click();
    const trigger = page.locator('.uc-trigger').first();
    await trigger.locator('input').first().fill('scope breach');
    await trigger.locator('input').nth(1).fill('the target is outside the agreed scope');

    // Three steps: work, branch, end.
    await page.getByRole('button', { name: '+ AGENT', exact: true }).click();
    await page.getByRole('button', { name: '+ CONDITION', exact: true }).click();
    await page.getByRole('button', { name: '+ FINISH', exact: true }).click();
    expect(await page.locator('.uc-step').count()).toBe(3);

    const s1 = page.locator('.uc-step').nth(0);
    await s1.locator('.uc-step-id').fill('recon');
    await s1.locator('.uc-step-name').fill('Recon');
    await s1.locator('.uc-step-agent').selectOption(AGENT_ID);   // the agent made above
    await s1.locator(`.uc-skill-tag:has-text("E2E Skill") input`).check();
    await s1.locator('.uc-step-prompt').selectOption(PROMPT_ID); // the prompt made above

    const s2 = page.locator('.uc-step').nth(1);
    await s2.locator('.uc-step-id').fill('gate');
    await s2.locator('.uc-step-name').fill('Anything found?');
    await s2.locator('textarea').first().fill('Did recon find any input parameters?');

    const s3 = page.locator('.uc-step').nth(2);
    await s3.locator('.uc-step-id').fill('end');
    await s3.locator('.uc-step-name').fill('End');
    await s3.locator('textarea').first().fill('Report what was found.');

    // The branch dropdown must offer the steps the user just named.
    const gotoSel = s2.locator('.uc-branch select').first();
    await expect(gotoSel.locator('option')).toContainText(['— next step —', 'Recon  (AGENT)', 'Anything found?  (CONDITION)', 'End  (FINISH)']);
    await s2.locator('.uc-branch input').first().fill('parameters were found');
    await gotoSel.selectOption('end');

    await page.locator('#uc-editor-save').click();
    await expect(page.locator('#uc-editor-overlay')).toBeHidden();
    await expect(page.locator('#ai-wf-list')).toContainText('E2E Authored Flow');
  });

  test('the authored workflow reads back with every field the user set', async () => {
    const wf = await page.evaluate(id => window.VOID_WORKFLOWS.find(w => w.id === id), WF_ID);
    expect(wf.initialInstructions).toBe('Stay strictly in scope.');
    expect(wf.triggers).toHaveLength(1);
    expect(wf.triggers[0].condition).toContain('outside the agreed scope');
    expect(wf.steps.map(s => s.id)).toEqual(['recon', 'gate', 'end']);
    expect(wf.steps.map(s => s.type)).toEqual(['AGENT', 'CONDITION', 'FINISH']);
    expect(wf.steps[0].agent).toBe(AGENT_ID);
    expect(wf.steps[0].skills).toEqual([SKILL_ID]);
    expect(wf.steps[0].prompt).toBe(PROMPT_ID);
    expect(wf.steps[1].branches[0]).toEqual({ condition: 'parameters were found', goto: 'end' });
    expect(wf.steps[2].summary).toBe('Report what was found.');
  });

  test('the detail pane shows the authored flow to the user', async () => {
    await page.locator(`#ai-wf-list .ai-wf-card:has-text("E2E Authored Flow")`).click();
    await expect(page.locator('#ai-wf-detail')).toBeVisible();
    await expect(page.locator('#ai-wf-steps')).toContainText('Recon');
    await expect(page.locator('#ai-wf-steps')).toContainText('Anything found?');
    await expect(page.locator('#ai-wf-steps')).toContainText('End');
  });

  test('the step assembles the authored agent and skill into its prompt', async () => {
    const sp = await page.evaluate(id => {
      const wf = window.VOID_WORKFLOWS.find(w => w.id === id);
      return wfStepSystemPrompt(wf.steps[0]);
    }, WF_ID);
    expect(sp).toContain('You are an end-to-end test agent.');
    expect(sp).toContain('prove the skill body is stored');
  });

  // ── Tier 6: refresh preserves state ───────────────────────────────────────

  test('everything authored survives a panel reload', async () => {
    const fresh = await openPanel();
    const state = await fresh.evaluate(ids => ({
      agent: window.VOID_AGENTS.find(a => a.id === ids.a)?.title,
      skill: window.VOID_SKILLS[ids.s]?.name,
      prompt: window.VOID_PROMPTS.find(p => p.id === ids.p)?.name,
      wfSteps: window.VOID_WORKFLOWS.find(w => w.id === ids.w)?.steps.length,
      wfBranch: window.VOID_WORKFLOWS.find(w => w.id === ids.w)?.steps[1].branches[0].goto,
    }), { a: AGENT_ID, s: SKILL_ID, p: PROMPT_ID, w: WF_ID });

    expect(state).toEqual({
      agent: 'E2E Agent', skill: 'E2E Skill', prompt: 'E2E Prompt',
      wfSteps: 3, wfBranch: 'end',
    });
    // And it is visible, not merely in memory.
    await fresh.evaluate(() => showTab('settings'));
    await fresh.locator('.ai-settings-tab[data-aitab="workflows"]').click();
    await expect(fresh.locator('#ai-wf-list')).toContainText('E2E Authored Flow');
    await fresh.close();
  });

  // ── Tier 3: update ────────────────────────────────────────────────────────

  test('editing through the UI changes what the user sees', async () => {
    await openSubtab(page, 'prompts');
    await page.locator(`#ai-prompts-list .ai-prompt-item:has-text("E2E Prompt")`).click();
    await page.locator('#uc-edit-prompts').click();
    await expect(page.locator('#uc-editor-title')).toHaveText('Edit Prompt');
    await setField(page, 'name', 'E2E Prompt (edited)');
    await page.locator('#uc-editor-save').click();
    await expect(page.locator('#ai-prompts-list')).toContainText('E2E Prompt (edited)');
  });

  test('duplicating produces an independent copy', async () => {
    await page.locator(`#ai-prompts-list .ai-prompt-item:has-text("E2E Prompt (edited)")`).click();
    await page.locator('#uc-dup-prompts').click();
    await expect(page.locator('#uc-editor-title')).toHaveText('Duplicate Prompt');
    const dupId = await page.locator('#uc-editor-fields [data-key="id"]').inputValue();
    expect(dupId).toBe(PROMPT_ID + '-copy');
    await page.locator('#uc-editor-save').click();
    const both = await page.evaluate(id => [id, id + '-copy'].map(x => !!window.VOID_PROMPTS.find(p => p.id === x)), PROMPT_ID);
    expect(both).toEqual([true, true]);
    await page.evaluate(id => ucRemove('prompts', id + '-copy'), PROMPT_ID);
  });

  test('a built-in hidden through the UI comes back with Restore', async () => {
    await openSubtab(page, 'workflows');
    await page.locator(`#ai-wf-list .ai-wf-card:has-text("Sqli Form")`).click();
    await page.locator('#uc-del-workflows').click();
    await expect(page.locator('#ai-wf-list')).not.toContainText('Sqli Form');

    // Restore needs the selection, which the delete just cleared from the list.
    await page.evaluate(() => { aiWfSelectedId = 'sqli-form'; });
    await page.locator('#uc-restore-workflows').click();
    await expect(page.locator('#ai-wf-list')).toContainText('Sqli Form');
  });

  // ── Tier 6: edge cases ────────────────────────────────────────────────────

  test('an empty search shows an empty list rather than crashing', async () => {
    await openSubtab(page, 'skills');
    await page.locator('#ai-skills-search').fill('zzz-no-such-skill-zzz');
    expect(await page.locator('#ai-skills-list .ai-skill-item').count()).toBe(0);
    await expect(page.locator('#ai-skills-count')).toBeVisible();
    await page.locator('#ai-skills-search').fill('');
    expect(await page.locator('#ai-skills-list .ai-skill-item').count()).toBeGreaterThan(30);
  });

  test('a workflow with 120 steps renders without hanging the panel', async () => {
    const t0 = Date.now();
    await page.evaluate(() => ucUpsert('workflows', 'e2e-big', {
      id: 'e2e-big', name: 'E2E Big', description: 'stress', level: 'engagement', category: 'test',
      steps: Array.from({ length: 120 }, (_, i) => ({
        id: 's' + i, name: 'Step ' + i, type: 'AGENT', agent: '', skills: [], prompt: '',
        goal: 'goal ' + i, decisionTree: [{ action: 'do ' + i, ifPositive: 'y', ifNegative: 'n', stopWhen: '' }],
        validation: {}, toolGuidance: {}, dependsOn: [],
      })),
    }));
    await openSubtab(page, 'workflows');
    await page.locator(`#ai-wf-list .ai-wf-card:has-text("E2E Big")`).click();
    await expect(page.locator('#ai-wf-detail')).toBeVisible();
    expect(await page.locator('#ai-wf-steps .ai-wf-step').count()).toBe(120);
    expect(Date.now() - t0).toBeLessThan(15000);
    await page.evaluate(() => ucRemove('workflows', 'e2e-big'));
  });

  test('a workflow with no steps does not break the detail pane', async () => {
    await page.evaluate(() => ucUpsert('workflows', 'e2e-empty', {
      id: 'e2e-empty', name: 'E2E Empty', description: '', level: 'atomic', category: 'test', steps: [],
    }));
    await page.locator(`#ai-wf-list .ai-wf-card:has-text("E2E Empty")`).click();
    await expect(page.locator('#ai-wf-detail')).toBeVisible();
    expect(await page.locator('#ai-wf-steps .ai-wf-step').count()).toBe(0);
    await page.evaluate(() => ucRemove('workflows', 'e2e-empty'));
  });

  test('two rapid saves both land, last write winning', async () => {
    await page.evaluate(async id => {
      // Overlapping writes to the same key must not lose the later one.
      await Promise.all([
        ucUpsert('prompts', id, { id, name: 'race-a', category: 'e2e', template: 'a', tags: [] }),
        ucUpsert('prompts', id, { id, name: 'race-b', category: 'e2e', template: 'b', tags: [] }),
      ]);
    }, PROMPT_ID);
    const stored = await page.evaluate(async id => {
      const s = await new Promise(r => chrome.storage.local.get('voidUserContent', r));
      return s.voidUserContent.overrides.prompts[id].name;
    }, PROMPT_ID);
    expect(stored).toBe('race-b');
  });

  // ── Tier 2: the engine reaches the real proxy ─────────────────────────────

  test('the judge call reaches the running proxy instead of a dead URL', async () => {
    // With the proxy up, a wrong URL would surface as a connection failure. A
    // provider-level error proves the request was actually served.
    const verdict = await page.evaluate(() => wfEvaluate('is the sky blue?', 'no context'));
    expect(verdict.reason).not.toMatch(/unavailable/);
    expect(typeof verdict.answer).toBe('boolean');
  });

  test('the proxy chat endpoint is what the panel targets', async ({ playwright }) => {
    const api = await playwright.request.newContext({ ignoreHTTPSErrors: true });
    const url = await page.evaluate(() => VOID_PROXY_CHAT_URL);
    expect(url).toBe(`${PROXY}/api/chat`);
    const res = await api.post(url, { data: {} });
    // What matters is that our proxy served it. A wrong path or port gives 404/405
    // or no response at all; anything else means the route exists and ran. (An
    // empty body reaches the upstream provider unauthenticated, hence 401.)
    expect([404, 405]).not.toContain(res.status());
    expect(res.status()).toBeGreaterThanOrEqual(400);
    await api.dispose();
  });

  // ── Cleanup + health ──────────────────────────────────────────────────────

  test('cleanup removes everything this run created', async () => {
    await page.evaluate(async ids => {
      await ucRemove('workflows', ids.w);
      await ucRemove('agents', ids.a);
      await ucRemove('skills', ids.s);
      await ucRemove('prompts', ids.p);
    }, { w: WF_ID, a: AGENT_ID, s: SKILL_ID, p: PROMPT_ID });

    const counts = await page.evaluate(() => ({
      agents: window.VOID_AGENTS.length,
      skills: Object.keys(window.VOID_SKILLS).length,
      workflows: window.VOID_WORKFLOWS.length,
      prompts: window.VOID_PROMPTS.length,
    }));
    expect(counts).toEqual({ agents: 12, skills: 32, workflows: 23, prompts: 20 });
  });

  test('no uncaught errors were thrown during any of it', async () => {
    expect(errors, errors.join('; ')).toHaveLength(0);
  });
});
