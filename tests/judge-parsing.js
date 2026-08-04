#!/usr/bin/env node
// Void Extension — judge/refute output parsing
//
// The two-pass verification endpoint reads JSON out of a model's reply. Small local
// models (gemma3, phi4, qwen3) fence it, wrap it in prose, emit <think> blocks, and
// return booleans as the strings "false"/"no"/"0". Two bugs came from that:
//
//   1. A non-greedy /\{[\s\S]*?\}/ stopped at the first "}", so any nested object
//      or brace inside a string threw and was swallowed into "not vulnerable" —
//      real findings vanished silently.
//   2. `if (!judgeResult.vulnerable)` treated the STRING "false" as true, so a
//      "not vulnerable" verdict was reported as vulnerable. The verdict inverted.
//
// These tests pin both. Run: node tests/judge-parsing.js
"use strict";
const fs = require("fs"), path = require("path"), vm = require("vm");

const src = fs.readFileSync(path.join(__dirname, "..", "void-proxy-server.js"), "utf8");
const start = src.indexOf("function extractJsonObject");
const end = src.indexOf("// Active tool calls");
if (start < 0 || end < 0 || end < start) {
  console.error("could not slice the parsing helpers out of void-proxy-server.js");
  process.exit(1);
}
const sandbox = { JSON, String, Number, console };
vm.createContext(sandbox);
vm.runInContext(src.slice(start, end), sandbox);
for (const fn of ["extractJsonObject", "asBool"]) {
  if (typeof sandbox[fn] !== "function") { console.error("missing helper: " + fn); process.exit(1); }
}
const { extractJsonObject, asBool } = sandbox;

let P = 0, F = 0;
const t = (n, ok) => { ok ? P++ : (F++, console.log("  FAIL: " + n)); };
const S = n => console.log("\n-- " + n + " --");

S("1. extractJsonObject — shapes a small model actually emits");
t("plain object", extractJsonObject('{"vulnerable":true}').vulnerable === true);
t("nested object is not truncated at the first brace",
  JSON.stringify(extractJsonObject('{"a":{"b":1},"vulnerable":false}')) === '{"a":{"b":1},"vulnerable":false}');
t("a brace inside a string does not end the object",
  extractJsonObject('{"evidence":"got } here","vulnerable":true}').evidence === "got } here");
t("an escaped quote does not end the string",
  extractJsonObject('{"evidence":"say \\"hi\\" }","vulnerable":true}').vulnerable === true);
t("array of check objects survives",
  extractJsonObject('{"checks":[{"id":1,"result":"pass"}],"verdict":"confirmed"}').checks.length === 1);
t("```json fence", extractJsonObject('```json\n{"verdict":"refuted"}\n```').verdict === "refuted");
t("bare fence", extractJsonObject('```\n{"verdict":"refuted"}\n```').verdict === "refuted");
t("<think> block is stripped, not parsed",
  extractJsonObject('<think>{"verdict":"confirmed"}</think>{"verdict":"refuted"}').verdict === "refuted");
t("leading prose", extractJsonObject('Here is my verdict:\n{"verdict":"confirmed"}').verdict === "confirmed");
t("trailing prose with a stray brace", extractJsonObject('{"verdict":"confirmed"} — done }').verdict === "confirmed");
t("no JSON at all returns null", extractJsonObject("I could not determine this.") === null);
t("malformed JSON returns null rather than throwing", extractJsonObject('{"verdict": }') === null);
t("empty input returns null", extractJsonObject("") === null);
t("undefined input returns null", extractJsonObject(undefined) === null);

S("2. asBool — models say booleans in words");
t('"false" is false, not truthy', asBool("false") === false);
t('"FALSE" is false', asBool("FALSE") === false);
t('" false " is false', asBool(" false ") === false);
t('"no" is false', asBool("no") === false);
t('"0" is false', asBool("0") === false);
t('"not_vulnerable" is false', asBool("not_vulnerable") === false);
t('"refuted" is false', asBool("refuted") === false);
t('"true" is true', asBool("true") === true);
t('"yes" is true', asBool("yes") === true);
t('"confirmed" is true', asBool("confirmed") === true);
t("real booleans pass through", asBool(true) === true && asBool(false) === false);
t("numbers coerce", asBool(1) === true && asBool(0) === false);
t("unusable text is null, not false", asBool("maybe") === null);
t("missing is null, not false", asBool(undefined) === null && asBool(null) === null);
t("null is distinguishable from false", asBool("maybe") !== false);

S("3. The regressions these replaced");
// The old code was `if (!judgeResult.vulnerable)`. With the string "false" that
// test is false, so it did NOT take the not-vulnerable branch — it reported the
// candidate as vulnerable. The verdict inverted.
const naive = v => !v;                    // old
const fixed = v => asBool(v) === false;   // new
t("old truthiness inverted a string 'false'", naive("false") === false);
t("new coercion reads it correctly", fixed("false") === true);
t("both agree on a real false", naive(false) === true && fixed(false) === true);

// The old regex was non-greedy and stopped at the first closing brace.
const oldRe = s => { const m = String(s).match(/\{[\s\S]*?\}/); try { return m ? JSON.parse(m[0]) : null; } catch { return null; } };
const nested = '{"checks":[{"id":1}],"verdict":"confirmed"}';
t("old regex could not parse a nested object", oldRe(nested) === null);
t("new extractor parses it", extractJsonObject(nested).verdict === "confirmed");

S("4. Server wiring — no second copy of the prompts, no silent defaults");
t("templates come from data/prompts.js", src.includes('path.join(__dirname, "data", "prompts.js")'));
t("judge prompt is rendered from the shared template", src.includes('renderPrompt("judge-response"'));
t("refute prompt is rendered from the shared template", src.includes('renderPrompt("refute-finding"'));
t("no hardcoded judge wording left", !src.includes("You are a vulnerability judge"));
t("the scanner's matched pattern is not fed to the judge", !/matchedPattern[\s\S]{0,200}judgePrompt/.test(src));
t("an unusable verdict is surfaced, not read as clean", src.includes('verdict: "unknown"'));
t("only an explicit refutation overturns the judge", src.includes('asBool(refuteResult.false_positive) === true'));
t("reason-before-verdict needs room in max_tokens", src.includes("max_tokens: 1024") && !src.includes("max_tokens: 512"));

// The templates must actually render — a missing tag would ship a broken prompt.
const psb = { window: {} };
vm.createContext(psb);
vm.runInContext(fs.readFileSync(path.join(__dirname, "..", "data", "prompts.js"), "utf8"), psb);
const prompts = psb.window.VOID_PROMPTS;
for (const id of ["judge-response", "refute-finding"]) {
  const tpl = prompts.find(p => p.id === id);
  t(id + " exists", !!tpl);
  const used = [...new Set([...tpl.template.matchAll(/\{\{(\w+)\}\}/g)].map(m => m[1]))];
  t(id + " declares every tag it uses", used.every(u => tpl.tags.includes(u)));
  // Under constrained decoding, field order is generation order: a verdict emitted
  // first turns the reasoning into a post-hoc justification.
  // The example is the last line beginning with "{" — not the last "{" in the
  // template, which lands inside the nested object.
  const example = tpl.template.split("\n").filter(l => l.trim().startsWith("{")).pop() || "";
  const reasonField = id === "judge-response" ? '"checks"' : '"causes"';
  const verdictField = id === "judge-response" ? '"verdict"' : '"false_positive"';
  t(id + " example JSON puts reasoning before the verdict",
    example.indexOf(reasonField) >= 0 && example.indexOf(reasonField) < example.indexOf(verdictField));
  t(id + " requires a quote", /quote/i.test(tpl.template));
}
t("judge is given a baseline to diff against", prompts.find(p => p.id === "judge-response").tags.includes("baseline"));
t("judge is given the content type", prompts.find(p => p.id === "judge-response").tags.includes("content_type"));
t("judge has a three-valued verdict", /insufficient/.test(prompts.find(p => p.id === "judge-response").template));
t("refuter is withheld the reporter's reasoning",
  /not shown the reporter's reasoning/i.test(prompts.find(p => p.id === "refute-finding").template));

console.log("\n" + "=".repeat(60));
console.log("JUDGE PARSING: " + P + " PASS, " + F + " FAIL");
console.log("=".repeat(60));
process.exit(F > 0 ? 1 : 0);
