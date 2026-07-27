/**
 * DOM XSS Hunter v4.0 — Runtime Hooks & MutationObserver
 */
(function () {
  'use strict';

  const ns = window.__DOMXSS;
  const CONFIG = ns.CONFIG;
  const { truncate, getCallStack } = ns.utils;

  function installRuntimeHooks() {
    if (!CONFIG.enableRuntimeHooks) return;
    const { findings, originalFunctions } = ns.state;

    const hooks = [
      { obj: Element.prototype, name: 'innerHTML', type: 'setter', category: 'HTML Injection', severity: 'critical' },
      { obj: Element.prototype, name: 'outerHTML', type: 'setter', category: 'HTML Injection', severity: 'critical' },
      { obj: Element.prototype, name: 'insertAdjacentHTML', type: 'function', category: 'HTML Injection', severity: 'critical' },
      { obj: document, name: 'write', type: 'function', category: 'HTML Injection', severity: 'critical' },
      { obj: document, name: 'writeln', type: 'function', category: 'HTML Injection', severity: 'critical' },
      { obj: window, name: 'eval', type: 'function', category: 'JS Execution', severity: 'critical' },
      { obj: window, name: 'open', type: 'function', category: 'Navigation', severity: 'high' },
    ];

    for (const hook of hooks) {
      try {
        const key = `${hook.obj === window ? 'window' : hook.obj === document ? 'document' : 'Element'}.${hook.name}`;
        if (hook.type === 'setter') {
          const desc = Object.getOwnPropertyDescriptor(hook.obj, hook.name);
          if (!desc) continue;
          originalFunctions[key] = desc.set;
          Object.defineProperty(hook.obj, hook.name, {
            set(value) {
              if (typeof value === 'string' && (/<[a-z]/i.test(value) || /on\w+\s*=/i.test(value))) {
                findings.runtimeCalls.push({
                  id: ns.state.idCounter++, timestamp: Date.now(), hook: key,
                  category: hook.category, severity: hook.severity,
                  value: truncate(String(value), CONFIG.maxCodePreview),
                  stack: getCallStack(),
                  element: this.tagName ? `<${this.tagName.toLowerCase()}>` : '?',
                });
              }
              // Stored/Async DOM XSS: detect canary flowing through sinks
              const canaryBase = window.__domxss_lastCanary && window.__domxss_lastCanary.base;
              if (canaryBase && typeof value === 'string' && value.includes(canaryBase)) {
                findings.runtimeCalls.push({
                  id: ns.state.idCounter++, timestamp: Date.now(), hook: key,
                  category: 'Stored/Async Canary Flow', severity: 'critical',
                  value: truncate(String(value), CONFIG.maxCodePreview),
                  stack: getCallStack(),
                  element: this.tagName ? `<${this.tagName.toLowerCase()}>` : '?',
                  canary: canaryBase,
                });
              }
              return desc.set.call(this, value);
            },
            get: desc.get, configurable: true,
          });
        } else {
          originalFunctions[key] = hook.obj[hook.name];
          hook.obj[hook.name] = function (...args) {
            if (typeof args[0] === 'string' && args[0].length > 0) {
              findings.runtimeCalls.push({
                id: ns.state.idCounter++, timestamp: Date.now(), hook: key,
                category: hook.category, severity: hook.severity,
                args: truncate(args.map(String).join(', '), CONFIG.maxCodePreview),
                stack: getCallStack(),
              });
            }
            // Stored/Async DOM XSS: detect canary flowing through function sinks
            const canaryBase = window.__domxss_lastCanary && window.__domxss_lastCanary.base;
            if (canaryBase && typeof args[0] === 'string' && args[0].includes(canaryBase)) {
              findings.runtimeCalls.push({
                id: ns.state.idCounter++, timestamp: Date.now(), hook: key,
                category: 'Stored/Async Canary Flow', severity: 'critical',
                args: truncate(args.map(String).join(', '), CONFIG.maxCodePreview),
                stack: getCallStack(),
                canary: canaryBase,
              });
            }
            return originalFunctions[key].apply(this, args);
          };
        }
      } catch (e) { ns.log.debug(e.message); }
    }

    // Hook Element.prototype.setAttribute — only log when setting dangerous attributes
    try {
      const setAttrKey = 'Element.setAttribute';
      const dangerousAttrs = /^(href|src|action|formaction|srcdoc|on\w+)$/i;
      originalFunctions[setAttrKey] = Element.prototype.setAttribute;
      Element.prototype.setAttribute = function (...args) {
        if (typeof args[0] === 'string' && dangerousAttrs.test(args[0])) {
          findings.runtimeCalls.push({
            id: ns.state.idCounter++, timestamp: Date.now(), hook: setAttrKey,
            category: 'Attr Setting', severity: 'high',
            args: truncate(args.map(String).join(', '), CONFIG.maxCodePreview),
            stack: getCallStack(),
            element: this.tagName ? `<${this.tagName.toLowerCase()}>` : '?',
          });
        }
        return originalFunctions[setAttrKey].apply(this, args);
      };
    } catch (e) { ns.log.debug(e.message); }

    // Hook document.createElement — only log when creating dangerous elements
    try {
      const createElKey = 'document.createElement';
      const dangerousElements = /^(script|iframe|embed|object|svg)$/i;
      originalFunctions[createElKey] = document.createElement;
      document.createElement = function (...args) {
        if (typeof args[0] === 'string' && dangerousElements.test(args[0])) {
          findings.runtimeCalls.push({
            id: ns.state.idCounter++, timestamp: Date.now(), hook: createElKey,
            category: 'Element Creation', severity: 'high',
            args: truncate(args.map(String).join(', '), CONFIG.maxCodePreview),
            stack: getCallStack(),
          });
        }
        return originalFunctions[createElKey].apply(this, args);
      };
    } catch (e) { ns.log.debug(e.message); }

    // Hook window.fetch — intercept responses to detect canary in fetch response bodies
    try {
      const fetchKey = 'window.fetch';
      originalFunctions[fetchKey] = window.fetch;
      window.fetch = function (...args) {
        return originalFunctions[fetchKey].apply(this, args).then(response => {
          const canaryBase = window.__domxss_lastCanary && window.__domxss_lastCanary.base;
          if (!canaryBase) return response;
          // Clone so the original response body is still consumable
          const cloned = response.clone();
          cloned.text().then(body => {
            if (body.includes(canaryBase)) {
              const reqUrl = (args[0] && typeof args[0] === 'object' && args[0].url) ? args[0].url
                : (typeof args[0] === 'string' ? args[0] : String(args[0]));
              findings.runtimeCalls.push({
                id: ns.state.idCounter++, timestamp: Date.now(), hook: fetchKey,
                category: 'Fetch Response Flow', severity: 'critical',
                value: truncate(body, CONFIG.maxCodePreview),
                stack: getCallStack(),
                canary: canaryBase,
                url: truncate(reqUrl, 200),
              });
            }
          }).catch(() => {});
          return response;
        });
      };
    } catch (e) { ns.log.debug(e.message); }

    // Hook XMLHttpRequest — intercept responses to detect canary in XHR response bodies
    try {
      const xhrOpenKey = 'XMLHttpRequest.open';
      const origOpen = XMLHttpRequest.prototype.open;
      originalFunctions[xhrOpenKey] = origOpen;
      XMLHttpRequest.prototype.open = function (...args) {
        // Store request URL for later reference
        this.__domxss_url = args[1] || '';
        // Attach load listener to check response for canary (once: true to prevent memory leak)
        this.addEventListener('load', function () {
          try {
            const canaryBase = window.__domxss_lastCanary && window.__domxss_lastCanary.base;
            if (!canaryBase) return;
            const body = this.responseText || '';
            if (body.includes(canaryBase)) {
              findings.runtimeCalls.push({
                id: ns.state.idCounter++, timestamp: Date.now(), hook: 'XMLHttpRequest',
                category: 'XHR Response Flow', severity: 'critical',
                value: truncate(body, CONFIG.maxCodePreview),
                stack: '(async XHR load)',
                canary: canaryBase,
                url: truncate(String(this.__domxss_url), 200),
              });
            }
          } catch (e) { ns.log.debug(e.message); }
        }, { once: true });
        return origOpen.apply(this, args);
      };
    } catch (e) { ns.log.debug(e.message); }

    // Hook setTimeout/setInterval — detect string-argument code execution
    for (const fnName of ['setTimeout', 'setInterval']) {
      try {
        const key = `window.${fnName}`;
        originalFunctions[key] = window[fnName];
        window[fnName] = function (...args) {
          if (typeof args[0] === 'string' && args[0].length > 0) {
            findings.runtimeCalls.push({
              id: ns.state.idCounter++, timestamp: Date.now(), hook: key,
              category: 'JS Execution', severity: 'critical',
              args: truncate(String(args[0]), CONFIG.maxCodePreview),
              stack: getCallStack(),
            });
          }
          const canaryBase = window.__domxss_lastCanary && window.__domxss_lastCanary.base;
          if (canaryBase && typeof args[0] === 'string' && args[0].includes(canaryBase)) {
            findings.runtimeCalls.push({
              id: ns.state.idCounter++, timestamp: Date.now(), hook: key,
              category: 'Stored/Async Canary Flow', severity: 'critical',
              args: truncate(String(args[0]), CONFIG.maxCodePreview),
              stack: getCallStack(), canary: canaryBase,
            });
          }
          return originalFunctions[key].apply(this, args);
        };
      } catch (e) { ns.log.debug(e.message); }
    }

    // Hook Function() constructor — detect dynamic code generation
    try {
      const fnKey = 'Function.constructor';
      const OrigFunction = Function;
      originalFunctions[fnKey] = OrigFunction;
      // Wrap via prototype to catch new Function('code') and Function('code')
      window.Function = function (...args) {
        if (args.length > 0 && typeof args[args.length - 1] === 'string') {
          const body = args[args.length - 1];
          if (body.length > 0) {
            findings.runtimeCalls.push({
              id: ns.state.idCounter++, timestamp: Date.now(), hook: fnKey,
              category: 'JS Execution', severity: 'critical',
              args: truncate(body, CONFIG.maxCodePreview),
              stack: getCallStack(),
            });
          }
          const canaryBase = window.__domxss_lastCanary && window.__domxss_lastCanary.base;
          if (canaryBase && body.includes(canaryBase)) {
            findings.runtimeCalls.push({
              id: ns.state.idCounter++, timestamp: Date.now(), hook: fnKey,
              category: 'Stored/Async Canary Flow', severity: 'critical',
              args: truncate(body, CONFIG.maxCodePreview),
              stack: getCallStack(), canary: canaryBase,
            });
          }
        }
        return OrigFunction.apply(this, args);
      };
      window.Function.prototype = OrigFunction.prototype;
      Object.defineProperty(window.Function, 'name', { value: 'Function' });
    } catch (e) { ns.log.debug(e.message); }

    // Hook location.assign / location.replace — detect navigation sinks
    for (const fnName of ['assign', 'replace']) {
      try {
        const key = `location.${fnName}`;
        const origFn = location[fnName].bind(location);
        originalFunctions[key] = origFn;
        location[fnName] = function (url) {
          if (typeof url === 'string' && url.length > 0) {
            const isJs = /^\s*javascript:/i.test(url);
            findings.runtimeCalls.push({
              id: ns.state.idCounter++, timestamp: Date.now(), hook: key,
              category: isJs ? 'JS Execution' : 'Navigation', severity: isJs ? 'critical' : 'high',
              args: truncate(url, CONFIG.maxCodePreview),
              stack: getCallStack(),
            });
            const canaryBase = window.__domxss_lastCanary && window.__domxss_lastCanary.base;
            if (canaryBase && url.includes(canaryBase)) {
              findings.runtimeCalls.push({
                id: ns.state.idCounter++, timestamp: Date.now(), hook: key,
                category: 'Stored/Async Canary Flow', severity: 'critical',
                args: truncate(url, CONFIG.maxCodePreview),
                stack: getCallStack(), canary: canaryBase,
              });
            }
          }
          return origFn(url);
        };
      } catch (e) { ns.log.debug(e.message); }
    }

    // Hook location.href setter — detect javascript: navigation
    try {
      const key = 'location.href';
      const locDesc = Object.getOwnPropertyDescriptor(window, 'location');
      // Some browsers don't allow overriding location — use a fallback approach
      // We wrap the Location prototype's href setter instead
      const hrefDesc = Object.getOwnPropertyDescriptor(Location.prototype, 'href');
      if (hrefDesc && hrefDesc.set) {
        originalFunctions[key] = hrefDesc.set;
        Object.defineProperty(Location.prototype, 'href', {
          set(url) {
            if (typeof url === 'string' && url.length > 0) {
              const isJs = /^\s*javascript:/i.test(url);
              if (isJs) {
                findings.runtimeCalls.push({
                  id: ns.state.idCounter++, timestamp: Date.now(), hook: key,
                  category: 'JS Execution', severity: 'critical',
                  args: truncate(url, CONFIG.maxCodePreview),
                  stack: getCallStack(),
                });
              }
              const canaryBase = window.__domxss_lastCanary && window.__domxss_lastCanary.base;
              if (canaryBase && url.includes(canaryBase)) {
                findings.runtimeCalls.push({
                  id: ns.state.idCounter++, timestamp: Date.now(), hook: key,
                  category: 'Stored/Async Canary Flow', severity: 'critical',
                  args: truncate(url, CONFIG.maxCodePreview),
                  stack: getCallStack(), canary: canaryBase,
                });
              }
            }
            return hrefDesc.set.call(this, url);
          },
          get: hrefDesc.get, configurable: true, enumerable: true,
        });
      }
    } catch (e) { ns.log.debug(e.message); }
  }

  function removeRuntimeHooks() {
    const { originalFunctions } = ns.state;
    for (const [key, original] of Object.entries(originalFunctions)) {
      try {
        const [objName, fnName] = key.split('.');
        let obj;
        if (objName === 'window') obj = window;
        else if (objName === 'document') obj = document;
        else if (objName === 'XMLHttpRequest') obj = XMLHttpRequest.prototype;
        else if (objName === 'location') obj = location;
        else if (objName === 'Location') obj = Location.prototype;
        else if (objName === 'Function') { window.Function = original; continue; }
        else obj = Element.prototype;

        const desc = Object.getOwnPropertyDescriptor(obj, fnName);
        if (desc && desc.set && typeof original === 'function') {
          Object.defineProperty(obj, fnName, { set: original, get: desc.get, configurable: true });
        } else {
          obj[fnName] = original;
        }
      } catch (e) { ns.log.debug(e.message); }
    }
  }

  function startObserver() {
    if (!CONFIG.enableMutationObserver) return;
    const { scanText, scanScript } = ns.scanner;

    ns.state.observer = new MutationObserver(muts => {
      for (const m of muts) for (const n of m.addedNodes) {
        if (n.tagName === 'SCRIPT') {
          if (n.src) scanScript(n.src);
          else if (n.textContent) scanText(n.textContent, { origin: 'HTML-dynamic', file: '(dynamic-script)', url: null });
        }
      }
    });
    ns.state.observer.observe(document.documentElement, { childList: true, subtree: true });
  }

  ns.hooks = { installRuntimeHooks, removeRuntimeHooks, startObserver };
})();
