#!/usr/bin/env node
/**
 * Model Capability Probe for void-extension AI Pentest
 *
 * Tests LLM models for:
 * 1. Tool calling support (can it invoke a function?)
 * 2. Structured JSON output (can it reply with valid JSON only?)
 * 3. Instruction following (does it follow a multi-step pentest methodology?)
 * 4. Hybrid judge capability (can it make binary vuln judgments?)
 *
 * Usage: node model-capability-probe.js [model-name]
 *   If no model specified, tests all known Ollama Cloud models.
 */

const OLLAMA_KEY = process.env.OLLAMA_API_KEY || '';
const OLLAMA_BASE = 'https://ollama.com/v1';

// Models known to be live on Ollama Cloud as of 2026-07
const MODELS_TO_TEST = [
  'deepseek-v4-pro',
  'deepseek-v4-flash',
  'gemma4:31b',
  'nemotron-3-nano:30b',
  'glm-5.2',
];

// ─── Test tools (mimicking void-extension's AI_TOOLS) ───────────────────────

const TEST_TOOLS = [
  {
    type: 'function',
    function: {
      name: 'send_request',
      description: 'Send an HTTP request and return the response',
      parameters: {
        type: 'object',
        properties: {
          url: { type: 'string', description: 'The URL to request' },
          method: { type: 'string', enum: ['GET', 'POST', 'PUT', 'DELETE'], description: 'HTTP method' },
          body: { type: 'string', description: 'Request body (for POST/PUT)' },
          headers: { type: 'object', description: 'Custom headers' }
        },
        required: ['url', 'method']
      }
    }
  },
  {
    type: 'function',
    function: {
      name: 'check_reflections',
      description: 'Check if a string is reflected in an HTTP response',
      parameters: {
        type: 'object',
        properties: {
          url: { type: 'string', description: 'URL to check' },
          payload: { type: 'string', description: 'String to look for in the response' }
        },
        required: ['url', 'payload']
      }
    }
  },
  {
    type: 'function',
    function: {
      name: 'add_finding',
      description: 'Record a confirmed vulnerability finding',
      parameters: {
        type: 'object',
        properties: {
          title: { type: 'string' },
          severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
          url: { type: 'string' },
          evidence: { type: 'string' },
          request: { type: 'string' },
          response_snippet: { type: 'string' }
        },
        required: ['title', 'severity', 'url', 'evidence']
      }
    }
  }
];

// ─── API call helper ────────────────────────────────────────────────────────

async function chatCompletion(model, messages, tools = null, jsonMode = false) {
  const body = {
    model,
    messages,
    temperature: 0,
    max_tokens: 1024,
  };
  if (tools && tools.length > 0) {
    body.tools = tools;
  }
  if (jsonMode) {
    body.response_format = { type: 'json_object' };
  }

  const startTime = Date.now();
  try {
    const resp = await fetch(`${OLLAMA_BASE}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${OLLAMA_KEY}`,
      },
      body: JSON.stringify(body),
    });

    const elapsed = Date.now() - startTime;

    if (!resp.ok) {
      const errText = await resp.text().catch(() => '');
      return { error: `HTTP ${resp.status}: ${errText.slice(0, 200)}`, elapsed };
    }

    const data = await resp.json();
    return { data, elapsed };
  } catch (err) {
    return { error: err.message, elapsed: Date.now() - startTime };
  }
}

// ─── Test 1: Tool Calling ───────────────────────────────────────────────────

async function testToolCalling(model) {
  const messages = [
    {
      role: 'system',
      content: 'You are a web security tester. Use the available tools to test for vulnerabilities.'
    },
    {
      role: 'user',
      content: 'Check if http://dvwa.local/vulnerabilities/sqli/?id=1&Submit=Submit is vulnerable to SQL injection. Send a request with a single quote appended to the id parameter.'
    }
  ];

  const result = await chatCompletion(model, messages, TEST_TOOLS);

  if (result.error) {
    return { pass: false, reason: `API error: ${result.error}`, elapsed: result.elapsed };
  }

  const choice = result.data.choices?.[0];
  if (!choice) {
    return { pass: false, reason: 'No choices in response', elapsed: result.elapsed };
  }

  const toolCalls = choice.message?.tool_calls;
  if (!toolCalls || toolCalls.length === 0) {
    // Check if it tried to do a text-based tool call
    const content = choice.message?.content || '';
    const hasTextToolCall = content.includes('send_request') || content.includes('tool_call');
    return {
      pass: false,
      reason: hasTextToolCall
        ? 'Model attempted text-based tool call (no native support)'
        : `No tool calls. Response: ${content.slice(0, 200)}`,
      textFallback: hasTextToolCall,
      elapsed: result.elapsed
    };
  }

  // Validate the tool call
  const tc = toolCalls[0];
  const fnName = tc.function?.name;
  let fnArgs;
  try {
    fnArgs = typeof tc.function?.arguments === 'string'
      ? JSON.parse(tc.function.arguments)
      : tc.function?.arguments;
  } catch {
    return { pass: false, reason: `Invalid JSON in tool args: ${tc.function?.arguments}`, elapsed: result.elapsed };
  }

  const correctTool = fnName === 'send_request' || fnName === 'check_reflections';
  const hasUrl = fnArgs?.url && typeof fnArgs.url === 'string';
  const hasSqliPayload = JSON.stringify(fnArgs).includes("'") || JSON.stringify(fnArgs).includes('%27');

  return {
    pass: correctTool && hasUrl,
    reason: `Called ${fnName}(${JSON.stringify(fnArgs).slice(0, 150)})`,
    correctTool,
    hasUrl,
    hasSqliPayload,
    elapsed: result.elapsed
  };
}

// ─── Test 2: Structured JSON Output ─────────────────────────────────────────

async function testJsonOutput(model) {
  const messages = [
    {
      role: 'system',
      content: 'You are a vulnerability judge. You MUST respond with ONLY a JSON object. No other text before or after the JSON.'
    },
    {
      role: 'user',
      content: `Given this HTTP exchange, is there a SQL injection vulnerability?

Request: GET /vuln/sqli/?id=1'+OR+'1'='1&Submit=Submit HTTP/1.1
Response (200 OK): <pre>ID: 1' OR '1'='1<br>First name: admin<br>Surname: admin</pre><pre>ID: 1' OR '1'='1<br>First name: Gordon<br>Surname: Brown</pre>

Respond ONLY with: {"vulnerable": true/false, "evidence": "exact text from response proving it", "confidence": 0.0-1.0}`
    }
  ];

  const result = await chatCompletion(model, messages, null, false);

  if (result.error) {
    return { pass: false, reason: `API error: ${result.error}`, elapsed: result.elapsed };
  }

  const content = result.data.choices?.[0]?.message?.content || '';

  // Try to extract JSON from the response
  let json = null;
  try {
    // Try direct parse first
    json = JSON.parse(content.trim());
  } catch {
    // Try to find JSON in the response
    const jsonMatch = content.match(/\{[\s\S]*?\}/);
    if (jsonMatch) {
      try {
        json = JSON.parse(jsonMatch[0]);
      } catch { /* ignore */ }
    }
  }

  if (!json) {
    return {
      pass: false,
      reason: `No valid JSON found. Response: ${content.slice(0, 300)}`,
      elapsed: result.elapsed
    };
  }

  const hasVulnerable = typeof json.vulnerable === 'boolean';
  const hasEvidence = typeof json.evidence === 'string' && json.evidence.length > 0;
  const hasConfidence = typeof json.confidence === 'number';
  const correctAnswer = json.vulnerable === true;

  return {
    pass: hasVulnerable && hasEvidence && correctAnswer,
    reason: `JSON: ${JSON.stringify(json).slice(0, 200)}`,
    hasVulnerable,
    hasEvidence,
    hasConfidence,
    correctAnswer,
    cleanJson: content.trim().startsWith('{'),
    elapsed: result.elapsed
  };
}

// ─── Test 3: Multi-step Instruction Following ───────────────────────────────

async function testInstructionFollowing(model) {
  const messages = [
    {
      role: 'system',
      content: `You are a web pentester. Follow the methodology EXACTLY as written. Do not skip steps.

METHODOLOGY:
Step 1: Send a GET request to the target URL to see the normal response.
Step 2: Send the same request but append a single quote (') to the id parameter.
Step 3: Compare the two responses. If step 2 shows a database error, report a finding.

You MUST start with Step 1. Do not skip to step 2 or 3.`
    },
    {
      role: 'user',
      content: 'Test http://dvwa.local/vuln/sqli/?id=1&Submit=Submit for SQL injection. Follow the methodology step by step. Start with step 1.'
    }
  ];

  const result = await chatCompletion(model, messages, TEST_TOOLS);

  if (result.error) {
    return { pass: false, reason: `API error: ${result.error}`, elapsed: result.elapsed };
  }

  const choice = result.data.choices?.[0];
  const toolCalls = choice?.message?.tool_calls;
  const content = choice?.message?.content || '';

  // Check if it started with step 1 (normal request, no payload)
  if (toolCalls && toolCalls.length > 0) {
    const firstCall = toolCalls[0];
    let args;
    try {
      args = typeof firstCall.function?.arguments === 'string'
        ? JSON.parse(firstCall.function.arguments)
        : firstCall.function?.arguments;
    } catch {
      args = {};
    }

    const url = args?.url || '';
    // Step 1 should be the NORMAL request (id=1, no quote)
    const isStep1 = url.includes('id=1') && !url.includes("'") && !url.includes('%27');
    // Or did it skip to step 2? (id=1')
    const skippedToStep2 = url.includes("'") || url.includes('%27');

    return {
      pass: isStep1,
      reason: isStep1
        ? `Correctly started with Step 1: ${firstCall.function?.name}(${url.slice(0, 100)})`
        : `Skipped to step 2 (injected payload immediately): ${url.slice(0, 100)}`,
      followedOrder: isStep1,
      skippedSteps: skippedToStep2,
      elapsed: result.elapsed
    };
  }

  // No tool calls — just talked about it
  const mentionsStep1 = content.toLowerCase().includes('step 1');
  return {
    pass: false,
    reason: `No tool calls. ${mentionsStep1 ? 'Mentioned step 1 in text but didn\'t execute.' : 'Ignored methodology entirely.'}`,
    elapsed: result.elapsed
  };
}

// ─── Test 4: Hybrid Judge (binary judgment) ─────────────────────────────────

async function testHybridJudge(model) {
  // This is the simplest possible task — exactly what the hybrid engine needs
  const messages = [
    {
      role: 'user',
      content: `You are a vulnerability classifier. Analyze this HTTP response and determine if SQL injection is present.

PAYLOAD SENT: 1' OR '1'='1
URL: http://dvwa.local/vuln/sqli/?id=1'+OR+'1'='1&Submit=Submit
HTTP STATUS: 200
RESPONSE BODY (first 500 chars):
<pre>ID: 1' OR '1'='1<br>First name: admin<br>Surname: admin</pre>
<pre>ID: 1' OR '1'='1<br>First name: Gordon<br>Surname: Brown</pre>
<pre>ID: 1' OR '1'='1<br>First name: Hack<br>Surname: Me</pre>

PATTERN MATCHED: Multiple rows returned (3 rows vs expected 1)

Reply with ONLY this JSON, nothing else:
{"vulnerable": true or false, "evidence": "brief reason"}`
    }
  ];

  const result = await chatCompletion(model, messages);

  if (result.error) {
    return { pass: false, reason: `API error: ${result.error}`, elapsed: result.elapsed };
  }

  const content = result.data.choices?.[0]?.message?.content || '';

  let json = null;
  try {
    json = JSON.parse(content.trim());
  } catch {
    const jsonMatch = content.match(/\{[\s\S]*?\}/);
    if (jsonMatch) {
      try { json = JSON.parse(jsonMatch[0]); } catch { /* ignore */ }
    }
  }

  if (!json) {
    return {
      pass: false,
      reason: `No JSON. Response: ${content.slice(0, 200)}`,
      elapsed: result.elapsed
    };
  }

  return {
    pass: json.vulnerable === true && typeof json.evidence === 'string',
    reason: `${JSON.stringify(json).slice(0, 200)}`,
    correctAnswer: json.vulnerable === true,
    hasEvidence: typeof json.evidence === 'string',
    elapsed: result.elapsed
  };
}

// ─── Main ───────────────────────────────────────────────────────────────────

async function testModel(model) {
  console.log(`\n${'═'.repeat(70)}`);
  console.log(`  MODEL: ${model}`);
  console.log(`${'═'.repeat(70)}`);

  const tests = [
    { name: 'Tool Calling', fn: testToolCalling },
    { name: 'JSON Output (Judge)', fn: testJsonOutput },
    { name: 'Instruction Following', fn: testInstructionFollowing },
    { name: 'Hybrid Judge (Binary)', fn: testHybridJudge },
  ];

  const results = {};
  for (const test of tests) {
    process.stdout.write(`  ${test.name.padEnd(30)}`);
    try {
      const r = await test.fn(model);
      const icon = r.pass ? '✓ PASS' : '✗ FAIL';
      const time = r.elapsed ? ` (${(r.elapsed / 1000).toFixed(1)}s)` : '';
      console.log(`${icon}${time}`);
      console.log(`    ${r.reason}`);
      if (r.textFallback) console.log(`    → Could use regex fallback for tool extraction`);
      results[test.name] = r;
    } catch (err) {
      console.log(`✗ ERROR: ${err.message}`);
      results[test.name] = { pass: false, reason: err.message };
    }
  }

  // Summary
  const passed = Object.values(results).filter(r => r.pass).length;
  const total = tests.length;
  const toolOk = results['Tool Calling']?.pass;
  const judgeOk = results['Hybrid Judge (Binary)']?.pass;

  let recommendation;
  if (passed === total) recommendation = 'Full AI ★★★';
  else if (toolOk && passed >= 3) recommendation = 'Full AI ★★ (with guardrails)';
  else if (judgeOk) recommendation = 'Hybrid ★★ (judge role)';
  else if (results['JSON Output (Judge)']?.pass) recommendation = 'Hybrid ★ (judge with retries)';
  else recommendation = 'Scanner Only (no AI)';

  console.log(`\n  SCORE: ${passed}/${total} | RECOMMENDED MODE: ${recommendation}`);
  return { model, passed, total, recommendation, results };
}

async function main() {
  const specificModel = process.argv[2];
  const models = specificModel ? [specificModel] : MODELS_TO_TEST;

  console.log('╔══════════════════════════════════════════════════════════════════════╗');
  console.log('║          void-extension — Model Capability Probe                    ║');
  console.log('║          Testing tool calling, JSON, instructions, hybrid judge     ║');
  console.log(`║          Endpoint: ${OLLAMA_BASE.padEnd(48)}║`);
  console.log(`║          Models: ${models.length.toString().padEnd(50)}║`);
  console.log('╚══════════════════════════════════════════════════════════════════════╝');

  const allResults = [];
  for (const model of models) {
    const r = await testModel(model);
    allResults.push(r);
  }

  // Final comparison table
  console.log(`\n\n${'═'.repeat(70)}`);
  console.log('  COMPARISON TABLE');
  console.log(`${'═'.repeat(70)}`);
  console.log('  Model'.padEnd(28) + 'Tools  JSON   Instr  Judge  Mode');
  console.log('  ' + '─'.repeat(66));
  for (const r of allResults) {
    const t = r.results;
    const row = [
      r.model.padEnd(26),
      (t['Tool Calling']?.pass ? '✓' : '✗').padEnd(7),
      (t['JSON Output (Judge)']?.pass ? '✓' : '✗').padEnd(7),
      (t['Instruction Following']?.pass ? '✓' : '✗').padEnd(7),
      (t['Hybrid Judge (Binary)']?.pass ? '✓' : '✗').padEnd(7),
      r.recommendation,
    ];
    console.log('  ' + row.join(''));
  }
  console.log('');
}

main().catch(err => {
  console.error('Fatal:', err);
  process.exit(1);
});
