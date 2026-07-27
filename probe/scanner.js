/**
 * DOM XSS Hunter v4.0 — Static Analysis Engine
 */
(function () {
  'use strict';

  const ns = window.__DOMXSS;
  const CONFIG = ns.CONFIG;
  const { isLibraryFile, isLibraryCode, truncate, getContext } = ns.utils;

  function addFinding(type, entry) {
    const { findings, seen } = ns.state;
    const key = `${type}:${entry.file}:${entry.line}:${entry.match}`;
    if (seen.has(key)) return;
    seen.add(key);
    entry.id = ns.state.idCounter++;
    entry.type = type;
    findings[type === 'source' ? 'sources' : 'sinks'].push(entry);
  }

  function scanText(text, meta) {
    const lines = text.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (isLibraryCode(line)) continue;

      for (const src of ns.SOURCES) {
        src.pattern.lastIndex = 0;
        const m = line.match(src.pattern);
        if (!m) continue;
        addFinding('source', {
          file: meta.file, origin: meta.origin, line: i + 1,
          match: m[0].trim(), category: src.category, severity: src.severity,
          manipulable: src.manipulable, why: src.why,
          code: truncate(line.trim(), CONFIG.maxCodePreview),
          context: getContext(lines, i, 2), url: meta.url,
        });
      }

      for (const snk of ns.SINKS) {
        snk.pattern.lastIndex = 0;
        const m = line.match(snk.pattern);
        if (!m) continue;
        addFinding('sink', {
          file: meta.file, origin: meta.origin, line: i + 1,
          match: m[0].trim(), category: snk.category, severity: snk.severity,
          code: truncate(line.trim(), CONFIG.maxCodePreview),
          context: getContext(lines, i, 2), url: meta.url,
        });
      }
    }

    // Composite sink detection — scan full text for multi-signal patterns
    for (const comp of (ns.COMPOSITE_SINKS || [])) {
      if (comp.tests.every(re => re.test(text))) {
        addFinding('sink', {
          file: meta.file, origin: meta.origin, line: 0,
          match: comp.name, category: comp.category, severity: comp.severity,
          code: comp.desc,
          context: '', url: meta.url,
        });
      }
    }
  }

  async function scanScript(url) {
    const { seenScripts } = ns.state;
    if (seenScripts.has(url)) return;
    seenScripts.add(url);
    const filename = url.split('/').pop().split('?')[0];
    if (isLibraryFile(filename)) return;
    try {
      const res = await fetch(url, { credentials: 'same-origin' });
      if (!res.ok) return;
      const text = await res.text();
      if (/\*!?\s*(jQuery|React|Angular|Vue|Lodash|Underscore|Backbone)\b/i.test(text.substring(0, 500))) return;
      scanText(text, { origin: 'JS', file: filename, url });
    } catch (e) {}
  }

  function scanInlineScripts() {
    document.querySelectorAll('script:not([src])').forEach((script, idx) => {
      if (!script.textContent?.trim()) return;
      scanText(script.textContent, { origin: 'HTML-inline', file: `(inline-${idx})`, url: null });
    });
  }

  function scanEventHandlerAttributes() {
    const events = ns.ALL_EVENTS;
    document.querySelectorAll('*').forEach(el => {
      for (const attr of events) {
        const val = el.getAttribute(attr);
        if (!val) continue;
        addFinding('sink', {
          file: '(DOM-attribute)', origin: 'HTML-attr', line: 0,
          match: attr, category: 'Inline Event Handler', severity: 'high',
          code: truncate(`<${el.tagName.toLowerCase()} ${attr}="${val}">`, CONFIG.maxCodePreview), url: null,
        });
      }
    });
  }

  function scanDangerousLinks() {
    document.querySelectorAll('a[href^="javascript:"], iframe[srcdoc], object[data], embed[src], base[href], link[rel="canonical"][href]').forEach(el => {
      const tag = el.tagName.toLowerCase();
      let attr, val;
      if (tag === 'a') { attr = 'href'; val = el.getAttribute('href'); }
      else if (tag === 'iframe') { attr = 'srcdoc'; val = el.getAttribute('srcdoc'); }
      else if (tag === 'base') { attr = 'href'; val = el.getAttribute('href'); }
      else if (tag === 'link') { attr = 'href'; val = el.getAttribute('href'); }
      else { attr = el.hasAttribute('data') ? 'data' : 'src'; val = el.getAttribute(attr); }
      addFinding('sink', {
        file: '(DOM-element)', origin: 'HTML-element', line: 0,
        match: `${tag}[${attr}]`, category: 'Dangerous Element', severity: 'critical',
        code: truncate(`<${tag} ${attr}="${val?.substring(0, 80)}">`, CONFIG.maxCodePreview), url: null,
      });
    });
  }

  function scanFrameworkPatterns() {
    // AngularJS: ng-app attribute (source — indicates AngularJS is active)
    document.querySelectorAll('[ng-app]').forEach(el => {
      addFinding('source', {
        file: '(DOM-framework)', origin: 'HTML-attr', line: 0,
        match: 'ng-app', category: 'AngularJS', severity: 'high',
        manipulable: 'full', why: 'AngularJS application detected — template injection possible',
        code: truncate(`<${el.tagName.toLowerCase()} ng-app="${el.getAttribute('ng-app') || ''}">`, CONFIG.maxCodePreview),
        url: null,
      });
    });

    // AngularJS: ng-bind-html / ng-bind-html-unsafe (sink)
    document.querySelectorAll('[ng-bind-html], [ng-bind-html-unsafe]').forEach(el => {
      const attr = el.hasAttribute('ng-bind-html-unsafe') ? 'ng-bind-html-unsafe' : 'ng-bind-html';
      addFinding('sink', {
        file: '(DOM-framework)', origin: 'HTML-attr', line: 0,
        match: attr, category: 'Angular HTML Binding', severity: 'high',
        code: truncate(`<${el.tagName.toLowerCase()} ${attr}="${el.getAttribute(attr) || ''}">`, CONFIG.maxCodePreview),
        url: null,
      });
    });

    // Vue: v-html (sink)
    document.querySelectorAll('[v-html]').forEach(el => {
      addFinding('sink', {
        file: '(DOM-framework)', origin: 'HTML-attr', line: 0,
        match: 'v-html', category: 'Vue HTML', severity: 'high',
        code: truncate(`<${el.tagName.toLowerCase()} v-html="${el.getAttribute('v-html') || ''}">`, CONFIG.maxCodePreview),
        url: null,
      });
    });

    // React: dangerouslySetInnerHTML (sink)
    document.querySelectorAll('*').forEach(el => {
      if (el.outerHTML && el.outerHTML.includes('dangerouslySetInnerHTML')) {
        addFinding('sink', {
          file: '(DOM-framework)', origin: 'HTML-element', line: 0,
          match: 'dangerouslySetInnerHTML', category: 'React Unsafe HTML', severity: 'critical',
          code: truncate(el.outerHTML.substring(0, 200), CONFIG.maxCodePreview),
          url: null,
        });
      }
    });

    // jQuery $() with location-based input (sink)
    if (typeof window.jQuery === 'function' || typeof window.$ === 'function') {
      const scripts = document.querySelectorAll('script:not([src])');
      scripts.forEach((script, idx) => {
        const text = script.textContent || '';
        if (/\$\s*\(\s*(location\.|document\.URL|document\.location|window\.location)/.test(text)) {
          addFinding('sink', {
            file: `(inline-${idx})`, origin: 'HTML-inline', line: 0,
            match: '$() with location input', category: 'jQuery Selector', severity: 'critical',
            code: truncate(text.substring(0, 200), CONFIG.maxCodePreview),
            url: null,
          });
        }
      });
    }
  }

  async function detectCSP() {
    // Check HTTP response headers first (most CSP is set via headers)
    let headerCSP = null;
    try {
      const resp = await fetch(location.href, { method: 'HEAD', credentials: 'same-origin' });
      headerCSP = resp.headers.get('Content-Security-Policy');
    } catch (e) { ns.log.debug(e.message); }

    // Check meta tag as fallback
    const meta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    const metaCSP = meta ? (meta.getAttribute('content') || null) : null;

    // Prefer HTTP header CSP over meta tag
    const csp = headerCSP || metaCSP || null;
    ns.state.csp = csp;
    return csp;
  }

  function scanDomClobberingPatterns() {
    const KNOWN_GLOBALS = /^(jQuery|\$|angular|React|ReactDOM|Vue|ga|gtag|dataLayer|google|gapi|FB|twttr|Modernizr|require|define|exports|module|__webpack_require__|process|Buffer)$/;
    const scripts = document.querySelectorAll('script:not([src])');
    scripts.forEach((script, idx) => {
      const text = script.textContent || '';
      if (!text.trim()) return;
      const lines = text.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        // window.X || default (global fallback)
        const fallbackRe = /window\s*\.\s*(\w+)\s*\|\|/g;
        let m;
        while ((m = fallbackRe.exec(line))) {
          if (KNOWN_GLOBALS.test(m[1])) continue;
          addFinding('sink', {
            file: `(inline-${idx})`, origin: 'HTML-inline', line: i + 1,
            match: `window.${m[1]}`, category: 'DOM Clobbering: global fallback',
            severity: 'medium',
            code: truncate(line.trim(), CONFIG.maxCodePreview), url: null,
          });
        }

        // window.X.Y (property chain — clobberable via dual-anchor)
        const chainRe = /window\s*\.\s*(\w+)\s*\.\s*(\w+)/g;
        while ((m = chainRe.exec(line))) {
          if (KNOWN_GLOBALS.test(m[1])) continue;
          addFinding('sink', {
            file: `(inline-${idx})`, origin: 'HTML-inline', line: i + 1,
            match: `window.${m[1]}.${m[2]}`, category: 'DOM Clobbering: property chain',
            severity: 'medium',
            code: truncate(line.trim(), CONFIG.maxCodePreview), url: null,
          });
        }

        // typeof X !== 'undefined' (existence checks)
        const typeofRe = /typeof\s+(\w+)\s*!==?\s*['"]undefined['"]/g;
        while ((m = typeofRe.exec(line))) {
          if (KNOWN_GLOBALS.test(m[1])) continue;
          addFinding('sink', {
            file: `(inline-${idx})`, origin: 'HTML-inline', line: i + 1,
            match: `typeof ${m[1]}`, category: 'DOM Clobbering: existence check',
            severity: 'low',
            code: truncate(line.trim(), CONFIG.maxCodePreview), url: null,
          });
        }
      }
    });
  }

  function scanProtoPollutionPatterns() {
    // Patterns for URL-based parameter parsers that enable prototype pollution
    const URL_PARSER_PATTERNS = [
      { pattern: /deparam|deparameterize|parseParams|queryStringToObject|urlToObject/gi, desc: 'Custom URL parameter parser — potential __proto__ injection via query string' },
      { pattern: /function\s+\w*[Pp]arse\w*\s*\([^)]*\)\s*\{[^}]*split\s*\(\s*['"][&=]/gi, desc: 'Custom query string parser splitting on & and = — check for recursive merge' },
      { pattern: /\[\s*key\s*\]\s*=\s*\w*val/gi, desc: 'Dynamic property assignment obj[key]=val — exploitable if key is __proto__' },
      { pattern: /\[\s*parts?\s*\[\s*\d\s*\]\s*\]\s*=/gi, desc: 'Array-indexed property assignment obj[parts[0]] — __proto__ injectable' },
    ];

    function scanTextForProto(text, meta) {
      const lines = text.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        for (const src of ns.PROTO_POLLUTION_SOURCES) {
          src.pattern.lastIndex = 0;
          const m = line.match(src.pattern);
          if (m) {
            addFinding('source', {
              file: meta.file, origin: meta.origin, line: i + 1,
              match: m[0].trim(), category: 'Prototype Pollution Source',
              severity: 'high', manipulable: 'conditional',
              why: src.desc,
              code: truncate(line.trim(), CONFIG.maxCodePreview), url: meta.url,
            });
          }
        }

        for (const snk of ns.PROTO_POLLUTION_SINKS) {
          snk.pattern.lastIndex = 0;
          const m = line.match(snk.pattern);
          if (m) {
            addFinding('sink', {
              file: meta.file, origin: meta.origin, line: i + 1,
              match: m[0].trim(), category: 'Prototype Pollution Sink',
              severity: 'high',
              code: truncate(line.trim(), CONFIG.maxCodePreview), url: meta.url,
            });
          }
        }

        for (const pat of URL_PARSER_PATTERNS) {
          pat.pattern.lastIndex = 0;
          const m = line.match(pat.pattern);
          if (m) {
            addFinding('sink', {
              file: meta.file, origin: meta.origin, line: i + 1,
              match: m[0].trim(), category: 'Prototype Pollution: URL Parser',
              severity: 'high',
              code: truncate(line.trim(), CONFIG.maxCodePreview), url: meta.url,
            });
          }
        }
      }
    }

    // Scan inline scripts
    const scripts = document.querySelectorAll('script:not([src])');
    scripts.forEach((script, idx) => {
      const text = script.textContent || '';
      if (!text.trim()) return;
      scanTextForProto(text, { file: `(inline-${idx})`, origin: 'HTML-inline', url: null });
    });

    // Also scan external scripts that aren't libraries
    const extScripts = document.querySelectorAll('script[src]');
    extScripts.forEach(script => {
      const src = script.src;
      if (!src || isLibraryFile(src.split('/').pop().split('?')[0])) return;
      if (ns.state.seenScripts.has(src)) {
        // Already fetched — we can't re-fetch, but the text was scanned via scanScript
        // The proto patterns will be caught there if we add them to SOURCES/SINKS
      }
    });
  }

  function scanCookieDomFlows() {
    const scripts = document.querySelectorAll('script:not([src])');
    scripts.forEach((script, idx) => {
      const text = script.textContent || '';
      if (!text.trim()) return;
      // Only scan scripts that use document.cookie
      if (!/document\s*\.\s*cookie/i.test(text)) return;

      const hasSink = /\.innerHTML\s*=|\.outerHTML\s*=|document\s*\.\s*write\s*\(|location\s*(?:\.\s*href\s*=|=)|eval\s*\(|\.src\s*=/i.test(text);
      if (!hasSink) return;

      // Look for cookie read + DOM sink in same script
      const lines = text.split('\n');
      let cookieReadLine = -1;
      for (let i = 0; i < lines.length; i++) {
        if (/document\s*\.\s*cookie/i.test(lines[i]) && !/document\s*\.\s*cookie\s*=/i.test(lines[i])) {
          cookieReadLine = i;
        }
        if (cookieReadLine >= 0) {
          const sinkPatterns = [
            { re: /\.innerHTML\s*=/i, name: 'innerHTML' },
            { re: /\.outerHTML\s*=/i, name: 'outerHTML' },
            { re: /document\s*\.\s*write\s*\(/i, name: 'document.write' },
            { re: /location\s*\.\s*href\s*=/i, name: 'location.href' },
            { re: /eval\s*\(/i, name: 'eval' },
            { re: /\.src\s*=/i, name: '.src' },
          ];
          for (const sp of sinkPatterns) {
            if (sp.re.test(lines[i]) && i >= cookieReadLine && (i - cookieReadLine) <= 30) {
              addFinding('sink', {
                file: `(inline-${idx})`, origin: 'HTML-inline', line: i + 1,
                match: `cookie → ${sp.name}`, category: 'Cookie to DOM Flow',
                severity: 'high',
                code: truncate(lines[i].trim(), CONFIG.maxCodePreview), url: null,
              });
            }
          }
        }
      }
    });
  }

  function scanPostMessagePatterns() {
    const PATTERNS = ns.POSTMESSAGE_VULN_PATTERNS;
    if (!PATTERNS) return;

    const scripts = document.querySelectorAll('script:not([src])');
    scripts.forEach((script, idx) => {
      const text = script.textContent || '';
      if (!text.trim()) return;

      // Only scan scripts that have message-related code
      if (!/message|postMessage|onmessage/i.test(text)) return;

      const lines = text.split('\n');
      const hasListener = /addEventListener\s*\(\s*['"`]message['"`]|onmessage\s*=/i.test(text);
      if (!hasListener) return;

      // Check for missing origin validation
      const hasOriginCheck = /(?:event|e|evt|msg)\s*\.\s*origin\s*[!=]==?\s*['"`]/i.test(text);

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        // Detect flawed origin checks
        for (const pat of PATTERNS.flawedOriginChecks) {
          pat.pattern.lastIndex = 0;
          const m = line.match(pat.pattern);
          if (m) {
            addFinding('sink', {
              file: `(inline-${idx})`, origin: 'HTML-inline', line: i + 1,
              match: m[0].trim(), category: 'PostMessage: Flawed Origin Check',
              severity: 'high',
              code: truncate(line.trim(), CONFIG.maxCodePreview), url: null,
            });
          }
        }

        // Detect dangerous sinks from message data
        for (const pat of PATTERNS.dangerousSinks) {
          pat.pattern.lastIndex = 0;
          const m = line.match(pat.pattern);
          if (m) {
            addFinding('sink', {
              file: `(inline-${idx})`, origin: 'HTML-inline', line: i + 1,
              match: m[0].trim(), category: 'PostMessage: ' + pat.desc.split('(')[0].trim(),
              severity: 'critical',
              code: truncate(line.trim(), CONFIG.maxCodePreview), url: null,
            });
          }
        }
      }

      // If message listener with no origin check at all
      if (!hasOriginCheck) {
        addFinding('sink', {
          file: `(inline-${idx})`, origin: 'HTML-inline', line: 0,
          match: 'addEventListener("message")', category: 'PostMessage: No Origin Validation',
          severity: 'critical',
          code: truncate(text.substring(0, CONFIG.maxCodePreview), CONFIG.maxCodePreview), url: null,
        });
      }
    });
  }

  // =====================================================
  // OPEN REDIRECT via URL params — detect ?url= / ?redirect= flowing to location
  // =====================================================
  function scanOpenRedirectParams() {
    const REDIRECT_PARAMS = /\b(url|redirect|next|return|goto|dest|rurl|return_url|continue|target|redir|redirect_uri|redirect_url|callback|forward|out|view|link|to)\b/i;
    const scripts = document.querySelectorAll('script:not([src])');
    scripts.forEach((script, idx) => {
      const text = script.textContent || '';
      if (!text.trim()) return;

      // Check if script reads common redirect params AND assigns to location
      const hasLocationAssign = /location\s*(?:\.\s*href\s*=|\.\s*assign\s*\(|\.\s*replace\s*\(|=\s*)/i.test(text);
      if (!hasLocationAssign) return;

      const lines = text.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        // Detect .get('url'), .get('redirect'), params['next'], etc.
        const paramReadRe = /(?:\.get\s*\(\s*['"]|params\s*\[\s*['"]|searchParams\s*\.\s*get\s*\(\s*['"])([\w_-]+)['"]\s*\)/gi;
        let m;
        while ((m = paramReadRe.exec(line))) {
          if (REDIRECT_PARAMS.test(m[1])) {
            addFinding('sink', {
              file: `(inline-${idx})`, origin: 'HTML-inline', line: i + 1,
              match: `param "${m[1]}" → location`, category: 'Open Redirect: URL Param to Location',
              severity: 'high',
              code: truncate(line.trim(), CONFIG.maxCodePreview), url: null,
            });
          }
        }
      }
    });

    // Also check current URL params for redirect-like names
    try {
      const url = new URL(location.href);
      for (const [key, val] of url.searchParams.entries()) {
        if (REDIRECT_PARAMS.test(key) && val) {
          // Check if value looks like a URL
          if (/^https?:\/\/|^\/\/|^javascript:/i.test(val)) {
            addFinding('source', {
              file: '(URL-param)', origin: 'URL', line: 0,
              match: `?${key}=${truncate(val, 60)}`, category: 'Open Redirect: Suspicious URL Param',
              severity: 'high', manipulable: 'full',
              why: `URL param "${key}" contains a URL value — likely redirect target`,
              code: `?${key}=${truncate(val, 80)}`, url: null,
            });
          }
        }
      }
    } catch (e) { ns.log.debug(e.message); }
  }

  // =====================================================
  // DOM COOKIE MANIPULATION — URL param → document.cookie → DOM
  // =====================================================
  function scanCookieManipulation() {
    const scripts = document.querySelectorAll('script:not([src])');
    scripts.forEach((script, idx) => {
      const text = script.textContent || '';
      if (!text.trim()) return;

      // Detect when document.cookie is SET from URL params (attacker-controlled cookie injection)
      const hasCookieWrite = /document\s*\.\s*cookie\s*=/i.test(text);
      const hasUrlRead = /location\s*\.\s*(search|hash|href)|URLSearchParams|searchParams\s*\.\s*get/i.test(text);

      if (hasCookieWrite && hasUrlRead) {
        const lines = text.split('\n');
        let urlReadLine = -1;
        let cookieWriteLine = -1;
        for (let i = 0; i < lines.length; i++) {
          if (/location\s*\.\s*(search|hash|href)|URLSearchParams|searchParams\s*\.\s*get/i.test(lines[i])) {
            if (urlReadLine === -1) urlReadLine = i;
          }
          if (/document\s*\.\s*cookie\s*=/i.test(lines[i])) {
            cookieWriteLine = i;
          }
        }
        if (urlReadLine >= 0 && cookieWriteLine >= 0 && Math.abs(cookieWriteLine - urlReadLine) <= 40) {
          addFinding('sink', {
            file: `(inline-${idx})`, origin: 'HTML-inline', line: cookieWriteLine + 1,
            match: 'URL param → document.cookie', category: 'Cookie Manipulation: URL to Cookie',
            severity: 'high',
            code: truncate(lines[cookieWriteLine].trim(), CONFIG.maxCodePreview), url: null,
          });
        }
      }

      // Detect cookie value reflected in DOM without sanitization (cookie → stored XSS)
      if (/document\s*\.\s*cookie/i.test(text)) {
        const lines = text.split('\n');
        for (let i = 0; i < lines.length; i++) {
          // Look for patterns like: element.innerHTML = cookieValue or document.write(cookie)
          if (/\.\s*innerHTML\s*=.*cookie|document\s*\.\s*write\s*\(.*cookie|\.html\s*\(.*cookie/i.test(lines[i])) {
            addFinding('sink', {
              file: `(inline-${idx})`, origin: 'HTML-inline', line: i + 1,
              match: 'cookie → innerHTML/write', category: 'Cookie to DOM: Stored XSS Loop',
              severity: 'critical',
              code: truncate(lines[i].trim(), CONFIG.maxCodePreview), url: null,
            });
          }
        }
      }
    });
  }

  // =====================================================
  // JS RESOURCE MAP — enumerate, classify, risk-assess all JS
  // =====================================================
  async function buildResourceMap() {
    const resources = [];
    const origin = location.origin;
    const fw = ns.state.frameworks || {};

    // Dangerous sink patterns to search for in file content
    const DANGEROUS_PATTERNS = [
      { re: /\beval\s*\(/g, name: 'eval()' },
      { re: /\bFunction\s*\(/g, name: 'Function()' },
      { re: /\bsetTimeout\s*\(\s*['"`]/g, name: 'setTimeout(string)' },
      { re: /\bsetInterval\s*\(\s*['"`]/g, name: 'setInterval(string)' },
      { re: /document\s*\.\s*write\s*\(/g, name: 'document.write' },
      { re: /\.innerHTML\s*=/g, name: 'innerHTML=' },
      { re: /\.outerHTML\s*=/g, name: 'outerHTML=' },
      { re: /\$\s*\(\s*\)\s*\.html\s*\(|\.\s*html\s*\(/g, name: '$.html()' },
      { re: /v-html/g, name: 'v-html' },
      { re: /dangerouslySetInnerHTML/g, name: 'dangerouslySetInnerHTML' },
      { re: /\.insertAdjacentHTML\s*\(/g, name: 'insertAdjacentHTML' },
      { re: /\.src\s*=/g, name: '.src=' },
      { re: /location\s*\.\s*href\s*=/g, name: 'location.href=' },
      { re: /location\s*\.\s*assign\s*\(/g, name: 'location.assign()' },
      { re: /location\s*\.\s*replace\s*\(/g, name: 'location.replace()' },
    ];

    // User-controllable source patterns
    const SOURCE_PATTERNS = [
      { re: /location\s*\.\s*search/g, name: 'location.search', manipulable: 'full' },
      { re: /location\s*\.\s*hash/g, name: 'location.hash', manipulable: 'full' },
      { re: /location\s*\.\s*href(?!\s*=)/g, name: 'location.href', manipulable: 'partial' },
      { re: /location\s*\.\s*pathname/g, name: 'location.pathname', manipulable: 'partial' },
      { re: /document\s*\.\s*URL/g, name: 'document.URL', manipulable: 'partial' },
      { re: /document\s*\.\s*documentURI/g, name: 'document.documentURI', manipulable: 'partial' },
      { re: /document\s*\.\s*referrer/g, name: 'document.referrer', manipulable: 'full' },
      { re: /document\s*\.\s*cookie/g, name: 'document.cookie', manipulable: 'conditional' },
      { re: /window\s*\.\s*name/g, name: 'window.name', manipulable: 'full' },
      { re: /postMessage|addEventListener\s*\(\s*['"]message/g, name: 'postMessage', manipulable: 'full' },
      { re: /URLSearchParams|searchParams\s*\.\s*get/g, name: 'URLSearchParams', manipulable: 'full' },
      { re: /localStorage\s*\.\s*getItem|localStorage\s*\[/g, name: 'localStorage', manipulable: 'conditional' },
      { re: /sessionStorage\s*\.\s*getItem|sessionStorage\s*\[/g, name: 'sessionStorage', manipulable: 'conditional' },
    ];

    // Known framework header patterns
    const FRAMEWORK_HEADER_RE = /\/\*!?\s*(jQuery|React|Angular|Vue|Lodash|Underscore|Backbone|Ember|D3|GSAP|Three|Moment)/i;

    function classifyType(url, scriptEl, content) {
      if (!url) return 'inline';
      if (scriptEl && scriptEl.type === 'module') return 'module';

      const filename = url.split('/').pop().split('?')[0].toLowerCase();

      // Check framework detection results
      if (fw.angular?.detected && /angular/i.test(filename)) return 'framework';
      if (fw.jquery?.detected && /jquery/i.test(filename)) return 'framework';
      if (fw.vue?.detected && /vue/i.test(filename)) return 'framework';
      if (fw.react?.detected && /react/i.test(filename)) return 'framework';

      // Check header comment for framework identification
      if (content && FRAMEWORK_HEADER_RE.test(content.substring(0, 500))) return 'framework';

      // Library check
      if (isLibraryFile(filename)) return 'library';

      // Origin check
      try {
        const u = new URL(url);
        return u.origin === origin ? 'first-party' : 'third-party';
      } catch {
        return 'first-party';
      }
    }

    function analyzeContent(content) {
      const sinks = [];
      const sources = [];
      for (const pat of DANGEROUS_PATTERNS) {
        pat.re.lastIndex = 0;
        const matches = content.match(pat.re);
        if (matches) {
          sinks.push({ name: pat.name, count: matches.length });
        }
      }
      for (const pat of SOURCE_PATTERNS) {
        pat.re.lastIndex = 0;
        const matches = content.match(pat.re);
        if (matches) {
          sources.push({ name: pat.name, count: matches.length, manipulable: pat.manipulable });
        }
      }
      const composites = [];
      for (const comp of (ns.COMPOSITE_SINKS || [])) {
        if (comp.tests.every(re => re.test(content))) {
          composites.push({ name: comp.name, category: comp.category, severity: comp.severity, desc: comp.desc });
        }
      }

      // Detect flawed sanitizer patterns (first-occurrence-only string .replace())
      const flawedSanitizers = [];
      for (const pat of (ns.FLAWED_SANITIZER_PATTERNS || [])) {
        pat.pattern.lastIndex = 0;
        const matches = content.match(pat.pattern);
        if (matches) {
          flawedSanitizers.push({ desc: pat.desc, char: pat.char, count: matches.length });
        }
      }

      return { sinks, sources, composites, flawedSanitizers };
    }

    function assessRisk(type, sinks, sources, composites, flawedSanitizers) {
      if (composites && composites.some(c => c.severity === 'critical')) return 'CRITICAL';
      if (!sinks.length && !(flawedSanitizers && flawedSanitizers.length)) return 'NONE';
      // Flawed sanitizers (first-occurrence-only replace) are always exploitable if reflected
      if (flawedSanitizers && flawedSanitizers.length > 0) {
        const hasManipulable = sources.some(s => s.manipulable === 'full' || s.manipulable === 'partial');
        if (hasManipulable) return 'HIGH';
        if (sources.length > 0) return 'HIGH';
      }
      const hasManipulable = sources.some(s => s.manipulable === 'full' || s.manipulable === 'partial');
      if (hasManipulable && sinks.length > 0) return 'HIGH';
      if (sources.length > 0 && sinks.length > 0) return 'MEDIUM';
      if ((type === 'library' || type === 'framework') && sinks.length > 0) return 'LOW';
      return 'MEDIUM';
    }

    function manipulableStatus(sources) {
      if (!sources.length) return 'NO';
      const hasFull = sources.some(s => s.manipulable === 'full');
      const hasPartial = sources.some(s => s.manipulable === 'partial' || s.manipulable === 'conditional');
      if (hasFull) return 'YES';
      if (hasPartial) return 'PARTIAL';
      return 'NO';
    }

    // 1. Enumerate external scripts from Performance API
    const perfEntries = performance.getEntriesByType('resource')
      .filter(e => e.initiatorType === 'script');

    for (const entry of perfEntries) {
      const url = entry.name;
      const filename = url.split('/').pop().split('?')[0] || url;
      let content = null;
      let sinks = [];
      let sources = [];
      let type = 'third-party';

      // Try to fetch content for same-origin scripts
      try {
        const u = new URL(url);
        if (u.origin === origin) {
          const res = await fetch(url, { credentials: 'same-origin' });
          if (res.ok) content = await res.text();
        }
      } catch (e) { ns.log.debug(e.message); }

      // Find corresponding script element for module detection
      const scriptEl = document.querySelector(`script[src="${url}"], script[src="${url.replace(origin, '')}"]`);
      type = classifyType(url, scriptEl, content);

      let composites = [];
      let flawedSanitizers = [];
      if (content) {
        const analysis = analyzeContent(content);
        sinks = analysis.sinks;
        sources = analysis.sources;
        composites = analysis.composites || [];
        flawedSanitizers = analysis.flawedSanitizers || [];
      }

      // Count flows from ns.state.findings that match this file
      const flowCount = ns.state.findings.flows.filter(f => f.file === filename || f.source?.file === filename || f.sink?.file === filename).length;

      resources.push({
        url,
        file: truncate(filename, 60),
        type,
        size: entry.transferSize || 0,
        sinks,
        sources,
        composites,
        flawedSanitizers,
        sinkCount: sinks.reduce((sum, s) => sum + s.count, 0),
        sourceCount: sources.reduce((sum, s) => sum + s.count, 0),
        flowCount,
        risk: assessRisk(type, sinks, sources, composites, flawedSanitizers),
        manipulable: manipulableStatus(sources),
        hasContent: !!content,
      });
    }

    // 2. Add inline <script> tags
    document.querySelectorAll('script:not([src])').forEach((script, idx) => {
      const content = script.textContent || '';
      if (!content.trim()) return;

      const type = script.type === 'module' ? 'module' : 'inline';
      const analysis = analyzeContent(content);
      const filename = `(inline-${idx})`;

      const flowCount = ns.state.findings.flows.filter(f => f.file === filename).length;

      resources.push({
        url: null,
        file: filename,
        type,
        size: new Blob([content]).size,
        sinks: analysis.sinks,
        sources: analysis.sources,
        composites: analysis.composites || [],
        flawedSanitizers: analysis.flawedSanitizers || [],
        sinkCount: analysis.sinks.reduce((sum, s) => sum + s.count, 0),
        sourceCount: analysis.sources.reduce((sum, s) => sum + s.count, 0),
        flowCount,
        risk: assessRisk(type, analysis.sinks, analysis.sources, analysis.composites, analysis.flawedSanitizers),
        manipulable: manipulableStatus(analysis.sources),
        hasContent: true,
      });
    });

    ns.state.resources = resources;
    return resources;
  }

  ns.scanner = { addFinding, scanText, scanScript, scanInlineScripts, scanEventHandlerAttributes, scanDangerousLinks, scanFrameworkPatterns, detectCSP, scanDomClobberingPatterns, scanProtoPollutionPatterns, scanPostMessagePatterns, scanCookieDomFlows, scanOpenRedirectParams, scanCookieManipulation, buildResourceMap };
})();
