/**
 * DOM XSS Hunter v4.6 — Main Entry Point & Public API
 */
(function () {
  'use strict';

  const ns = window.__DOMXSS;

  // Reset shared state (already initialized in config.js, reset here for rescan)
  ns.state.idCounter = 1;
  ns.state.findings = { sources: [], sinks: [], runtimeCalls: [], flows: [] };
  ns.state.seen = new Set();
  ns.state.seenScripts = new Set();
  ns.state.highlightedEls = [];
  ns.state.observer = null;
  ns.state.originalFunctions = {};
  ns.state.csp = null;
  ns.state.frameworks = null;
  ns.state.resources = [];

  if (window.__domxss_running) {
    console.warn('[DOM XSS Hunter] Already running. Use domxss.clear() to reset.');
    return;
  }
  window.__domxss_running = true;

  const { findings } = ns.state;
  const { truncate, generateCanary } = ns.utils;
  const { highlightEl, injectPulseAnimation, clearHighlights, reapplyHighlights, extractAndHighlight } = ns.highlight;
  const { scanScript, scanText, scanInlineScripts, scanEventHandlerAttributes, scanDangerousLinks, scanFrameworkPatterns, detectCSP: scanDetectCSP, scanDomClobberingPatterns, scanProtoPollutionPatterns, scanPostMessagePatterns, scanCookieDomFlows, scanOpenRedirectParams, scanCookieManipulation, buildResourceMap } = ns.scanner;
  const { analyzeFlows } = ns.flows;
  const { installRuntimeHooks, removeRuntimeHooks, startObserver } = ns.hooks;
  const { printReport, printTriage, inspectSource, printFlows, exportJSON, printHelp, printInputs, printResources } = ns.reporter;
  const { runProbe, probeGo, probeCheck, probePostMessage, findReflections, detectReflectionContext, printReflections } = ns.probe;
  const { autoFuzz, fuzzCheck, fuzzNav, fuzzResultsExport, wafEnumerate, detectCSP: fuzzDetectCSP, fuzzJSProtocol, fuzzDanglingMarkup, fuzzPostForms, fuzzBlind, fuzzClobbering, fuzzMXSS, fuzzPrototype, fuzzTemplateInjection, checkCstiConfirmation, toggleAutofill, toggleCstiAutofill, toggleSstiAutofill } = ns.fuzzer;
  const { detectFrameworks, fuzzAngular, detectJQuerySinks, fuzzJQueryHashchange, detectVueSinks, detectReactSinks, printFrameworkReport } = ns.frameworks;
  const CONTEXT_PAYLOADS = ns.CONTEXT_PAYLOADS;

  function clearAll() {
    ns.state.findings.sources = [];
    ns.state.findings.sinks = [];
    ns.state.findings.runtimeCalls = [];
    ns.state.findings.flows = [];
    ns.state.seen.clear();
    ns.state.seenScripts.clear();
    ns.state.idCounter = 1;
    ns.state.csp = null;
    ns.state.frameworks = null;
    ns.state.resources = [];
    clearHighlights();
    ns.state.markedEls = [];
    removeRuntimeHooks();
    if (ns.state.observer) ns.state.observer.disconnect();
    try {
      sessionStorage.removeItem('__domxss_canary');
      sessionStorage.removeItem('__domxss_injected_url');
    } catch (e) {}
    delete window.__domxss_lastCanary;
    delete window.__domxss_lastInjection;
    delete window.__domxss_fuzzResults;
    try { sessionStorage.removeItem('__domxss_fuzz_results'); } catch (e) { ns.log.debug(e.message); }
    try { sessionStorage.removeItem('__domxss_fuzz_vectors'); } catch (e) { ns.log.debug(e.message); }
    try { sessionStorage.removeItem('__domxss_fuzz_nav'); } catch (e) { ns.log.debug(e.message); }
    try { sessionStorage.removeItem('__domxss_fuzz_nav_queue'); } catch (e) { ns.log.debug(e.message); }
    try { sessionStorage.removeItem('__domxss_fuzz_nav_results'); } catch (e) { ns.log.debug(e.message); }
    try { sessionStorage.removeItem('__domxss_fuzz_nav_param'); } catch (e) { ns.log.debug(e.message); }
    try { sessionStorage.removeItem('__domxss_csti_pending'); } catch (e) { ns.log.debug(e.message); }
    window.__domxss_running = false;
    delete window.domxss;
    ns.log.info('%c[DOM XSS Hunter] Cleared and disconnected', 'color:green');
  }

  async function run() {
    ns.log.info('%c[DOM XSS Hunter v4.6] Starting scan...', 'color:#00ff00;font-weight:bold');
    const t0 = performance.now();

    installRuntimeHooks();
    startObserver();

    // Detect frameworks early so CSTI suggestions work during fuzz
    try {
      ns.state.frameworks = detectFrameworks();
    } catch (e) { ns.log.debug(e.message); }

    const scripts = performance.getEntriesByType('resource')
      .filter(e => e.initiatorType === 'script').map(e => e.name);

    for (const url of scripts) await scanScript(url);
    scanInlineScripts();
    scanEventHandlerAttributes();
    scanDangerousLinks();
    scanFrameworkPatterns();
    scanDomClobberingPatterns();
    if (ns.CONFIG.protoPollutionEnabled) {
      scanProtoPollutionPatterns();
    }
    scanPostMessagePatterns();
    scanCookieDomFlows();
    scanOpenRedirectParams();
    scanCookieManipulation();
    await scanDetectCSP();
    analyzeFlows();
    await buildResourceMap();

    // Log detected frameworks
    try {
      const fw = ns.state.frameworks || detectFrameworks();
      ns.state.frameworks = fw;
      if (fw.angular.detected) {
        ns.log.info(`%c[Framework] AngularJS ${fw.angular.version || '?'} detected${fw.angular.hasNgApp ? ' (ng-app found)' : ''}`, 'color:#ff6600;font-weight:bold');
      }
      if (fw.jquery.detected) {
        ns.log.info(`%c[Framework] jQuery ${fw.jquery.version || '?'} detected`, 'color:#ff6600;font-weight:bold');
      }
      if (fw.vue.detected) {
        ns.log.info(`%c[Framework] Vue.js ${fw.vue.version || '?'} detected`, 'color:#ff6600;font-weight:bold');
      }
    } catch (e) {}

    const elapsed = ((performance.now() - t0) / 1000).toFixed(2);
    ns.log.info(`%c[Scan completed in ${elapsed}s]`, 'color:#00ff00;font-weight:bold');

    // Check for pending CSTI confirmation (from previous form submission)
    await checkCstiConfirmation();

    // Auto-check for pending canary
    try {
      const storedCanary = sessionStorage.getItem('__domxss_canary');
      const isFuzzNav = sessionStorage.getItem('__domxss_fuzz_nav');

      if (storedCanary) {
        const canary = JSON.parse(storedCanary);
        if (Date.now() - canary.ts < 300000) {
          window.__domxss_lastCanary = canary;
          const refs = findReflections(canary);

          if (isFuzzNav) {
            sessionStorage.removeItem('__domxss_fuzz_nav');
            const testedParam = sessionStorage.getItem('__domxss_fuzz_nav_param') || '?';
            const paramLabel = testedParam === '__hash__' ? '#hash' : `?${testedParam}`;

            // Store results for this param
            try {
              const RESULTS_KEY = '__domxss_fuzz_nav_results';
              const prevResults = JSON.parse(sessionStorage.getItem(RESULTS_KEY) || '[]');
              prevResults.push({ param: paramLabel, reflectionCount: refs.length });
              sessionStorage.setItem(RESULTS_KEY, JSON.stringify(prevResults));
            } catch (e) { ns.log.debug(e.message); }

            // Check if more params remain in queue
            let hasMore = false;
            try {
              const queue = JSON.parse(sessionStorage.getItem('__domxss_fuzz_nav_queue'));
              hasMore = queue && queue.params && queue.params.length > 0;
            } catch (e) { ns.log.debug(e.message); }

            if (refs.length > 0) {
              injectPulseAnimation();
              ns.log.info(`\n%c\uD83E\uDD16 FUZZ NAV \u2014 Canary detected in ${paramLabel}! ${refs.length} reflection(s)`, 'color:#ff00ff;font-weight:bold;font-size:14px;background:#1a001a;padding:4px 8px');

              for (let i = 0; i < refs.length; i++) {
                const r = refs[i];
                const ctxDesc = CONTEXT_PAYLOADS[r.context]?.desc || r.context;
                ns.log.info(`\n   %c#${i + 1} %c${r.context}%c \u2014 ${ctxDesc}`, 'color:#888', 'color:#ff00ff;font-weight:bold', 'color:#aaa');
                ns.log.info(`      Type: ${r.type}${r.attrName ? ` [${r.attrName}]` : ''} | Elem: ${r.element}`);
                ns.log.info(`      %c\uD83D\uDFE2 Raw: ${r.analysis.survived.join(' ') || '(none)'}`, 'color:#00ff00');
                if (r.analysis.encoded.length) ns.log.info(`      %c\uD83D\uDFE1 Encoded: ${r.analysis.encoded.map(c => `${c}\u2192${r.analysis.encodings[c]}`).join(', ')}`, 'color:#ffaa00');
                if (r.analysis.stripped.length) ns.log.info(`      %c\u26AB Stripped: ${r.analysis.stripped.join(' ')}`, 'color:#ff4444');

                if (r.domElement) highlightEl(r.domElement, `\uD83D\uDFE3 REFLECTION #${i + 1}: ${r.context}`, 'fuzz-refl');

                if (r.suggestions?.length) {
                  ns.log.info('      %c\uD83D\uDCA3 Viable payloads:', 'font-weight:bold;color:#ff0000');
                  for (const s of r.suggestions.filter(s => s.viable)) {
                    ns.log.info(`      %c\u2705 ${s.payload}%c \u2014 ${s.note}`, 'color:#00ff00;font-weight:bold', 'color:#888');
                  }
                }
              }

              for (const flow of findings.flows.filter(f => f.exploitability === 'likely' || f.exploitability === 'possible')) {
                const sink = findings.sinks.find(s => s.id === flow.sink.id);
                if (sink?.code) extractAndHighlight(sink.code);
              }

              ns.log.info('\n%c\uD83C\uDFA8 HIGHLIGHTED ON PAGE:', 'font-weight:bold;color:#ccc');
              ns.log.info('   %c \u25A0 MAGENTA%c = Canary reflection', 'color:#ff00ff;font-weight:bold;font-size:12px', 'color:#ccc');
              ns.log.info('   %c \u25A0 RED    %c = Detected sink', 'color:#ff0000;font-weight:bold;font-size:12px', 'color:#ccc');
            } else {
              ns.log.info(`\n%c\uD83E\uDD16 FUZZ NAV \u2014 No reflections for ${paramLabel}`, 'color:#888;font-weight:bold');
            }

            if (hasMore) {
              ns.log.info('');
              ns.log.info('%c   More params to test. Run %cdomxss.fuzz.nav()%c or %cdomxss.fuzz.nav.next()%c to continue.', 'color:#ffaa00', 'color:#ff00ff;font-weight:bold', 'color:#ffaa00', 'color:#ff00ff;font-weight:bold', 'color:#ffaa00');
            } else {
              ns.log.info('');
              ns.log.info('%c   All params tested!', 'color:#00ff00;font-weight:bold');
              ns.log.info('%c   Run %cdomxss.fuzz.check()%c for full analysis or %cdomxss.fuzz()%c to test payloads', 'color:#ccc', 'color:#ff00ff;font-weight:bold', 'color:#ccc', 'color:#ff00ff;font-weight:bold', 'color:#ccc');
            }

          } else if (refs.length > 0) {
            ns.log.info(`\n%c\uD83E\uDDEA Canary from previous probe detected! ${refs.length} reflection(s) found`, 'color:#ff6600;font-weight:bold');
            injectPulseAnimation();
            for (let i = 0; i < refs.length; i++) {
              if (refs[i].domElement) highlightEl(refs[i].domElement, `\uD83D\uDFE3 REFLECTION #${i + 1}: ${refs[i].context}`, 'fuzz-refl');
            }
            ns.log.info('%c   Run domxss.probe.check() or domxss.fuzz.check() for full analysis', 'color:#ccc');
          }
        }
      }

    } catch (e) {}

    printReport();
    printHelp();

    // If autofill is enabled, fill forms after scan
    if (ns.CONFIG.autofillEnabled) {
      ns.fuzzer.startAutofill();
    }

    // If CSTI autofill is enabled, start it after scan
    if (ns.CONFIG.cstiEnabled) {
      ns.fuzzer.startCstiAutofill();
    }

    // If SSTI autofill is enabled, start it after scan
    if (ns.CONFIG.sstiEnabled) {
      ns.fuzzer.startSstiAutofill();
    }
  }

  // Build probe sub-methods
  runProbe.go = probeGo;
  runProbe.check = probeCheck;
  runProbe.postmessage = probePostMessage;

  // Build fuzz sub-methods
  autoFuzz.check = fuzzCheck;
  autoFuzz.nav = fuzzNav;
  autoFuzz.nav.next = fuzzNav.next;
  autoFuzz.nav.reset = fuzzNav.reset;
  autoFuzz.results = fuzzResultsExport;
  autoFuzz.waf = wafEnumerate;
  autoFuzz.csp = fuzzDetectCSP;
  autoFuzz.protocol = fuzzJSProtocol;
  autoFuzz.dangling = fuzzDanglingMarkup;
  autoFuzz.post = fuzzPostForms;
  autoFuzz.blind = fuzzBlind;
  autoFuzz.clobbering = fuzzClobbering;
  autoFuzz.mxss = fuzzMXSS;
  autoFuzz.prototype = fuzzPrototype;
  autoFuzz.ssti = fuzzTemplateInjection;

  // Build frameworks sub-methods
  const frameworksObj = function() { return printFrameworkReport(); };
  frameworksObj.detect = detectFrameworks;
  frameworksObj.angular = fuzzAngular;
  frameworksObj.jquery = detectJQuerySinks;
  frameworksObj.jqueryHash = fuzzJQueryHashchange;
  frameworksObj.vue = detectVueSinks;
  frameworksObj.react = detectReactSinks;
  frameworksObj.report = printFrameworkReport;

  // Public API
  window.domxss = {
    triage: printTriage,
    report: printReport,
    flows: printFlows,
    inspect: inspectSource,
    inputs: printInputs,
    fuzz: autoFuzz,
    probe: runProbe,
    frameworks: frameworksObj,
    resources: printResources,
    export: exportJSON,
    highlight: () => { clearHighlights(); reapplyHighlights(); },
    unhighlight: clearHighlights,
    rescan: run,
    clear: clearAll,
    help: printHelp,
    autofill: toggleAutofill,
    cstiAutofill: toggleCstiAutofill,
    sstiAutofill: toggleSstiAutofill,
    findings,
    config: ns.CONFIG,
  };

  // Listen for commands from the extension popup via postMessage (cross-browser: Chrome + Firefox)
  // Background script sends postMessage from ISOLATED world → picked up here in MAIN world
  window.addEventListener('message', (event) => {
    if (event.source !== window || !event.data?.__domxss_cmd) return;
    const cmd = event.data.command;
    const args = event.data.args;

    // Special: status request — write to data attribute for ISOLATED world to read
    if (cmd === '__status_request') {
      const el = document.documentElement;
      if (window.domxss && window.domxss.findings) {
        const f = window.domxss.findings;
        const fw = window.__DOMXSS && window.__DOMXSS.state && window.__DOMXSS.state.frameworks;
        el.setAttribute('data-domxss-status', JSON.stringify({
          injected: true,
          sources: f.sources.length,
          sinks: f.sinks.length,
          flows: f.flows.length,
          runtimeCalls: f.runtimeCalls.length,
          likelyFlows: f.flows.filter(fl => fl.exploitability === 'likely').length,
          possibleFlows: f.flows.filter(fl => fl.exploitability === 'possible').length,
          frameworks: {
            angular: !!(fw && fw.angular && fw.angular.detected),
            jquery: !!(fw && fw.jquery && fw.jquery.detected),
            vue: !!(fw && fw.vue && fw.vue.detected),
            react: !!(fw && fw.react && fw.react.detected),
          },
        }));
      } else {
        el.setAttribute('data-domxss-status', JSON.stringify({
          injected: false,
          frameworks: {
            angular: !!(window.angular || document.querySelector('[ng-app],[data-ng-app]')),
            jquery: !!(window.jQuery || window.$),
            vue: !!(window.Vue || window.__VUE__),
            react: !!(window.React || document.querySelector('[data-reactroot],[data-reactid]')),
          },
        }));
      }
      return;
    }

    // Regular command — re-dispatch as CustomEvent for the existing handler
    window.dispatchEvent(new CustomEvent('__domxss_command', {
      detail: { command: cmd, args: args },
    }));
  });

  // Listen for commands from the extension popup via CustomEvent (legacy/direct)
  window.addEventListener('__domxss_command', (e) => {
    const cmd = e.detail?.command;
    if (!cmd || !window.domxss) return;

    switch (cmd) {
      case 'scan': run(); break;
      case 'triage': printTriage(); break;
      case 'report': printReport(); break;
      case 'fuzz': autoFuzz(); break;
      case 'fuzz.nav': fuzzNav(); break;
      case 'fuzz.nav.next': fuzzNav.next(); break;
      case 'fuzz.nav.reset': fuzzNav.reset(); break;
      case 'fuzz.check': fuzzCheck(); break;
      case 'fuzz.results': fuzzResultsExport(); break;
      case 'fuzz.waf': wafEnumerate(); break;
      case 'fuzz.csp': fuzzDetectCSP(); break;
      case 'fuzz.post': fuzzPostForms(); break;
      case 'fuzz.protocol': fuzzJSProtocol(); break;
      case 'fuzz.dangling': fuzzDanglingMarkup(); break;
      case 'fuzz.blind': fuzzBlind(e.detail?.args); break;
      case 'fuzz.clobbering': fuzzClobbering(); break;
      case 'fuzz.mxss': fuzzMXSS(); break;
      case 'fuzz.prototype': fuzzPrototype(); break;
      case 'fuzz.ssti': fuzzTemplateInjection(); break;
      case 'csti.toggle': toggleCstiAutofill(!!e.detail?.args); break;
      case 'ssti.toggle': toggleSstiAutofill(!!e.detail?.args); break;
      case 'probe': runProbe(); break;
      case 'probe.go': probeGo(); break;
      case 'probe.check': probeCheck(); break;
      case 'probe.postmessage': probePostMessage(); break;
      case 'inspect': inspectSource(e.detail?.args); break;
      case 'frameworks': printFrameworkReport(); break;
      case 'frameworks.detect': detectFrameworks(); break;
      case 'frameworks.angular': fuzzAngular(); break;
      case 'frameworks.jqueryHash': fuzzJQueryHashchange(); break;
      case 'frameworks.jquery': detectJQuerySinks(); break;
      case 'frameworks.vue': detectVueSinks(); break;
      case 'frameworks.react': detectReactSinks(); break;
      case 'resources': printResources(); break;
      case 'flows': printFlows(); break;
      case 'inputs': printInputs(); break;
      case 'export': exportJSON(); break;
      case 'highlight': clearHighlights(); reapplyHighlights(); break;
      case 'unhighlight': clearHighlights(); break;
      case 'help': printHelp(); break;
      case 'autofill.toggle': toggleAutofill(!!e.detail?.args); break;
      case 'protopollution.toggle':
        ns.CONFIG.protoPollutionEnabled = !!e.detail?.args;
        ns.log.info(`%c[Proto Pollution] Scan ${ns.CONFIG.protoPollutionEnabled ? 'ENABLED' : 'DISABLED'} — will apply on next scan`, ns.CONFIG.protoPollutionEnabled ? 'color:#00ff88;font-weight:bold' : 'color:#ff4444;font-weight:bold');
        break;
      case 'clear': clearAll(); break;
      default:
        console.warn(`[DOM XSS Hunter] Unknown command: ${cmd}`);
    }

    // Send status back to extension
    window.dispatchEvent(new CustomEvent('__domxss_status', {
      detail: {
        command: cmd,
        stats: {
          sources: findings.sources.length,
          sinks: findings.sinks.length,
          flows: findings.flows.length,
          runtimeCalls: findings.runtimeCalls.length,
          likelyFlows: findings.flows.filter(f => f.exploitability === 'likely').length,
        },
      },
    }));
  });

  run();
})();
