/**
 * DOM XSS Hunter v4.0 — DOM Highlighting
 */
(function () {
  'use strict';

  const ns = window.__DOMXSS;
  const { truncate, hexToRgb } = ns.utils;
  const HL_STYLES = ns.HL_STYLES;

  // Persistent store of all marked elements — survives unhighlight/highlight cycles
  if (!ns.state.markedEls) ns.state.markedEls = [];

  function highlightEl(el, labelText, styleOrBool) {
    if (!el || !el.style) return;

    let styleName;
    if (styleOrBool === true) styleName = 'input';
    else if (typeof styleOrBool === 'string') styleName = styleOrBool;
    else styleName = 'sink';

    // Store in persistent marked list (dedup by element + label)
    const alreadyMarked = ns.state.markedEls.some(m => m.el === el && m.labelText === labelText);
    if (!alreadyMarked) {
      ns.state.markedEls.push({ el, labelText, styleName });
    }

    applyHighlight(el, labelText, styleName);
  }

  function applyHighlight(el, labelText, styleName) {
    if (!el || !el.style) return;

    const hs = HL_STYLES[styleName] || HL_STYLES.sink;

    const original = {
      el,
      outline: el.style.outline,
      outlineOffset: el.style.outlineOffset,
      position: el.style.position,
      boxShadow: el.style.boxShadow,
      animation: el.style.animation,
    };
    ns.state.highlightedEls.push(original);

    el.style.outline = `${hs.width} solid ${hs.color}`;
    el.style.outlineOffset = '2px';

    if (hs.glow) {
      const rgb = hexToRgb(hs.color);
      el.style.boxShadow = `0 0 12px 4px rgba(${rgb},0.5)`;
      if (hs.anim) el.style.animation = `${hs.anim} 1.5s ease-in-out infinite`;
    }

    const label = document.createElement('div');
    label.className = '__domxss-label';
    label.textContent = labelText || '\u26A0\uFE0F XSS SINK';
    label.style.cssText = `
      position:absolute; top:-24px; left:0; z-index:999999;
      background:${hs.bg}; color:#fff; font-size:10px; font-weight:bold;
      padding:3px 8px; border-radius:3px; font-family:monospace;
      pointer-events:none; white-space:nowrap;
      border:1px solid ${hs.color}; box-shadow:0 2px 8px rgba(0,0,0,0.3);
    `;

    const pos = getComputedStyle(el).position;
    if (pos === 'static') el.style.position = 'relative';
    el.appendChild(label);
    original.label = label;
  }

  function reapplyHighlights() {
    for (const m of ns.state.markedEls) {
      if (!m.el || !m.el.isConnected) continue;
      applyHighlight(m.el, m.labelText, m.styleName);
    }
  }

  function injectPulseAnimation() {
    if (document.getElementById('__domxss-pulse-style')) return;
    const style = document.createElement('style');
    style.id = '__domxss-pulse-style';
    style.textContent = `
      @keyframes __domxss-pulse {
        0%   { box-shadow: 0 0 8px 2px rgba(255,0,0,0.4); outline-color: #ff0000; }
        50%  { box-shadow: 0 0 20px 8px rgba(255,0,0,0.7); outline-color: #ff4444; }
        100% { box-shadow: 0 0 8px 2px rgba(255,0,0,0.4); outline-color: #ff0000; }
      }
      @keyframes __domxss-pulse-cyan {
        0%   { box-shadow: 0 0 8px 2px rgba(0,221,255,0.4); outline-color: #00ddff; }
        50%  { box-shadow: 0 0 22px 8px rgba(0,221,255,0.7); outline-color: #44eeff; }
        100% { box-shadow: 0 0 8px 2px rgba(0,221,255,0.4); outline-color: #00ddff; }
      }
      @keyframes __domxss-pulse-magenta {
        0%   { box-shadow: 0 0 8px 2px rgba(255,0,255,0.4); outline-color: #ff00ff; }
        50%  { box-shadow: 0 0 22px 8px rgba(255,0,255,0.7); outline-color: #ff44ff; }
        100% { box-shadow: 0 0 8px 2px rgba(255,0,255,0.4); outline-color: #ff00ff; }
      }
      @keyframes __domxss-pulse-green {
        0%   { box-shadow: 0 0 8px 2px rgba(0,255,0,0.3); outline-color: #00ff00; }
        50%  { box-shadow: 0 0 25px 10px rgba(0,255,0,0.7); outline-color: #44ff44; }
        100% { box-shadow: 0 0 8px 2px rgba(0,255,0,0.3); outline-color: #00ff00; }
      }
    `;
    document.head.appendChild(style);
  }

  function clearHighlights() {
    for (const item of ns.state.highlightedEls) {
      if (item.el) {
        item.el.style.outline = item.outline;
        item.el.style.outlineOffset = item.outlineOffset;
        item.el.style.position = item.position;
        item.el.style.boxShadow = item.boxShadow || '';
        item.el.style.animation = item.animation || '';
        if (item.label && item.label.parentNode) {
          item.label.parentNode.removeChild(item.label);
        }
      }
    }
    ns.state.highlightedEls.length = 0;
    document.querySelectorAll('.__domxss-label, .__domxss-input-banner').forEach(l => l.remove());
  }

  function extractAndHighlight(codeLine) {
    const selectorPatterns = [
      /\$\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/,
      /jQuery\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/,
      /getElementById\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/,
      /querySelector(?:All)?\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/,
      /getElementsByClassName\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/,
      /getElementsByName\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/,
    ];

    for (const pat of selectorPatterns) {
      const m = codeLine.match(pat);
      if (!m) continue;

      let selector = m[1];
      if (codeLine.includes('getElementById')) selector = '#' + selector;
      if (codeLine.includes('getElementsByClassName')) selector = '.' + selector;
      if (codeLine.includes('getElementsByName')) selector = `[name="${selector}"]`;

      try {
        const els = document.querySelectorAll(selector);
        els.forEach(el => highlightEl(el));
        return els.length;
      } catch (e) {}
    }
    return 0;
  }

  function isInputElement(el) {
    if (!el || !el.tagName) return false;
    const tag = el.tagName.toLowerCase();
    if (tag === 'textarea' || tag === 'select') return true;
    if (tag === 'input') {
      const type = (el.type || 'text').toLowerCase();
      return ['text', 'search', 'url', 'email', 'tel', 'password', 'hidden', 'number'].includes(type);
    }
    if (el.hasAttribute?.('contenteditable')) return true;
    return false;
  }

  function extractInputsFromCode(codeLine) {
    if (!codeLine) return [];
    const results = [];
    const selectorPatterns = [
      /\$\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/,
      /jQuery\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/,
      /getElementById\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/,
      /querySelector(?:All)?\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/,
      /getElementsByClassName\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/,
      /getElementsByName\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/,
    ];

    for (const pat of selectorPatterns) {
      const m = codeLine.match(pat);
      if (!m) continue;
      let selector = m[1];
      if (codeLine.includes('getElementById')) selector = '#' + selector;
      else if (codeLine.includes('getElementsByClassName')) selector = '.' + selector;
      else if (codeLine.includes('getElementsByName')) selector = `[name="${selector}"]`;

      try {
        const els = document.querySelectorAll(selector);
        for (const el of els) {
          if (isInputElement(el)) results.push(el);
          el.querySelectorAll?.('input, textarea, select, [contenteditable]').forEach(child => results.push(child));
        }
      } catch (e) { ns.log.debug(e.message); }
    }
    return results;
  }

  function extractElementsFromCode(codeLine) {
    if (!codeLine) return [];
    const results = [];
    const pats = [
      /\$\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/,
      /jQuery\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/,
      /getElementById\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/,
      /querySelector(?:All)?\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/,
      /getElementsByClassName\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/,
      /getElementsByName\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/,
    ];
    for (const pat of pats) {
      const m = codeLine.match(pat);
      if (!m) continue;
      let sel = m[1];
      if (codeLine.includes('getElementById')) sel = '#' + sel;
      else if (codeLine.includes('getElementsByClassName')) sel = '.' + sel;
      else if (codeLine.includes('getElementsByName')) sel = `[name="${sel}"]`;
      try { document.querySelectorAll(sel).forEach(el => results.push(el)); } catch (e) { ns.log.debug(e.message); }
    }
    return results;
  }

  function highlightVulnerableInputs() {
    injectPulseAnimation();
    let count = 0;
    const alreadyMarked = new Set();
    const { findings } = ns.state;
    const { manipulableIcon } = ns.utils;

    const hotFlows = findings.flows.filter(f => f.exploitability === 'likely' || f.exploitability === 'possible');
    const actionableSources = findings.sources.filter(s => s.manipulable === 'full' || s.manipulable === 'partial');

    // 1. Inputs referenciados en el código de sources/sinks
    const allCodeLines = [
      ...actionableSources.map(s => s.code),
      ...findings.sinks.filter(s => hotFlows.some(f => f.sink.id === s.id)).map(s => s.code),
    ];

    for (const code of allCodeLines) {
      const inputs = extractInputsFromCode(code);
      for (const el of inputs) {
        if (alreadyMarked.has(el)) continue;
        alreadyMarked.add(el);
        const name = el.name || el.id || el.tagName.toLowerCase();
        highlightEl(el, `\uD83C\uDFAF INPUT VULNERABLE: ${name}`, true);
        count++;
      }
    }

    // 2. Para URL sources -> inputs cuyo name coincide con URL params
    const urlSources = actionableSources.filter(s =>
      s.match.includes('location.search') || s.match.includes('location.hash') ||
      s.match.includes('URLSearchParams') || s.match.includes('.searchParams')
    );

    if (urlSources.length > 0) {
      let params;
      try { params = new URLSearchParams(location.search); } catch { params = new URLSearchParams(); }

      const allInputs = document.querySelectorAll('input, textarea, select, [contenteditable]');
      for (const el of allInputs) {
        if (alreadyMarked.has(el)) continue;
        const inputName = el.name || el.id || '';
        if (!inputName) continue;

        if (params.has(inputName)) {
          alreadyMarked.add(el);
          highlightEl(el, `\uD83C\uDFAF INPUT \u2190 URL param: ?${inputName}=...`, true);
          count++;
          continue;
        }

        const inputVal = el.value || el.textContent || '';
        if (inputVal.length > 2) {
          for (const [key, val] of params.entries()) {
            if (val && inputVal.includes(val)) {
              alreadyMarked.add(el);
              highlightEl(el, `\uD83C\uDFAF INPUT refleja param: ?${key}=`, true);
              count++;
              break;
            }
          }
        }
      }
    }

    // 3. Para .value sources -> localizar inputs en contexto
    const valueSources = actionableSources.filter(s => s.match.includes('.value'));
    for (const src of valueSources) {
      const inputs = extractInputsFromCode(src.code);
      for (const el of inputs) {
        if (alreadyMarked.has(el)) continue;
        alreadyMarked.add(el);
        highlightEl(el, `\uD83C\uDFAF INPUT .value \u2192 sink`, true);
        count++;
      }
    }

    // 4. Para sinks que apuntan a elementos visibles: buscar inputs hijos
    for (const flow of hotFlows) {
      const sink = findings.sinks.find(s => s.id === flow.sink.id);
      if (!sink) continue;
      const sinkEls = extractElementsFromCode(sink.code);
      for (const sinkEl of sinkEls) {
        if (isInputElement(sinkEl) && !alreadyMarked.has(sinkEl)) {
          alreadyMarked.add(sinkEl);
          highlightEl(sinkEl, `\uD83C\uDFAF INPUT es SINK: ${sink.match}`, true);
          count++;
        }
        const childInputs = sinkEl.querySelectorAll?.('input, textarea, select') || [];
        for (const child of childInputs) {
          if (alreadyMarked.has(child)) continue;
          alreadyMarked.add(child);
          highlightEl(child, `\uD83C\uDFAF INPUT dentro de SINK: ${sink.match}`, true);
          count++;
        }
      }
    }

    return count;
  }

  // Export to namespace
  ns.highlight = {
    highlightEl,
    injectPulseAnimation,
    clearHighlights,
    reapplyHighlights,
    extractAndHighlight,
    highlightVulnerableInputs,
    extractInputsFromCode,
    extractElementsFromCode,
    isInputElement,
  };
})();
