/**
 * DOM XSS Hunter v4.0 — Utility Functions
 */
(function () {
  'use strict';

  const ns = window.__DOMXSS;
  const CONFIG = ns.CONFIG;

  // Logging system — ns.log.debug() only outputs when CONFIG.debug is true
  ns.log = {
    debug: (...args) => { if (CONFIG.debug) console.log('[dbg]', ...args); },
    info:  console.log.bind(console),
    warn:  console.warn.bind(console),
    error: console.error.bind(console),
  };

  ns.utils = {
    isLibraryFile(filename) {
      if (!CONFIG.filterLibraries) return false;
      return CONFIG.libraryPatterns.some(p => p.test(filename));
    },

    isLibraryCode(codeLine) {
      if (!CONFIG.filterLibraries) return false;
      return [
        codeLine.length > 500 && !codeLine.includes('\n'),
        /^[a-z]\.[a-z]\.[a-z]/i.test(codeLine.trim()),
        /\}\)\(jQuery\)/i.test(codeLine),
        /\}\)\(window,document\)/i.test(codeLine),
        /\/\*!?\s*(jQuery|React|Angular|Vue|Lodash|Backbone)/i.test(codeLine),
      ].some(Boolean);
    },

    truncate(str, max) {
      if (!str) return '';
      return str.length <= max ? str : str.substring(0, max) + '\u2026';
    },

    getCallStack() {
      try { throw new Error(); } catch (e) {
        return e.stack.split('\n').slice(3)
          .filter(l => !l.includes('dom-xss-scanner'))
          .join('\n');
      }
    },

    severityColor(sev) {
      return { critical: 'color:#ff0000;font-weight:bold', high: 'color:#ff6600;font-weight:bold', medium: 'color:#ffaa00', low: 'color:#888' }[sev] || 'color:#888';
    },

    severityScore(sev) {
      return { critical: 4, high: 3, medium: 2, low: 1 }[sev] || 0;
    },

    manipulableIcon(level) {
      return { full: '\uD83D\uDFE2 FULL', partial: '\uD83D\uDFE1 PARTIAL', conditional: '\uD83D\uDFE0 COND', none: '\u26AB NONE' }[level] || '\u2753';
    },

    manipulableScore(level) {
      return { full: 3, partial: 2, conditional: 1, none: 0 }[level] || 0;
    },

    getContext(lines, index, range) {
      const start = Math.max(0, index - range);
      const end = Math.min(lines.length - 1, index + range);
      const out = [];
      for (let j = start; j <= end; j++) {
        out.push(`${j === index ? '>>>' : '   '} ${j + 1}| ${ns.utils.truncate(lines[j].trim(), 120)}`);
      }
      return out.join('\n');
    },

    hexToRgb(hex) {
      const h = hex.replace('#', '');
      return [parseInt(h.substring(0, 2), 16), parseInt(h.substring(2, 4), 16), parseInt(h.substring(4, 6), 16)].join(',');
    },

    generateCanary() {
      const id = Math.random().toString(36).substring(2, 8);
      const charString = Object.keys(ns.PROBE_CHARS).join('');
      return {
        id,
        base: `xSs${id}`,
        full: `xSs${id}${charString}xSs${id}`,
        chars: charString,
        ts: Date.now(),
      };
    },
  };
})();
