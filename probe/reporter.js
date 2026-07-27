/**
 * DOM XSS Hunter v4.6 — Console Reporting
 */
(function () {
  'use strict';

  const ns = window.__DOMXSS;
  const { truncate, severityScore, manipulableScore, manipulableIcon } = ns.utils;
  const { clearHighlights, extractAndHighlight, highlightVulnerableInputs, injectPulseAnimation, isInputElement } = ns.highlight;
  const { analyzeFlows } = ns.flows;

  function printReport() {
    analyzeFlows();
    const { findings } = ns.state;
    console.clear();
    ns.log.info('%c\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557', 'color:#00ff00;font-weight:bold');
    ns.log.info('%c\u2551     DOM XSS Hunter v4.6 \u2014 Resultados     \u2551', 'color:#00ff00;font-weight:bold');
    ns.log.info('%c\u255A\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255D', 'color:#00ff00;font-weight:bold');
    ns.log.info(`\uD83D\uDCCD ${location.href}`);
    ns.log.info(`\uD83D\uDCC5 ${new Date().toISOString()}\n`);

    ns.log.info('%c\uD83D\uDCCA RESUMEN', 'font-size:14px;font-weight:bold;color:#00aaff');
    console.table({
      sources: findings.sources.length,
      'sources manipulables': findings.sources.filter(s => s.manipulable !== 'none').length,
      sinks: findings.sinks.length,
      runtimeCalls: findings.runtimeCalls.length,
      flows: findings.flows.length,
      '\uD83D\uDD25 likely flows': findings.flows.filter(f => f.exploitability === 'likely').length,
    });

    if (findings.sources.length) {
      ns.log.info('\n%c\uD83D\uDD35 SOURCES', 'font-size:13px;font-weight:bold;color:#4488ff');
      console.table(findings.sources
        .sort((a, b) => manipulableScore(b.manipulable) - manipulableScore(a.manipulable) || severityScore(b.severity) - severityScore(a.severity))
        .map(s => ({ id: s.id, '\uD83C\uDFAF': manipulableIcon(s.manipulable), sev: s.severity.toUpperCase(), cat: s.category, file: s.file, line: s.line, match: s.match, why: truncate(s.why, 55) }))
      );
    }

    if (findings.sinks.length) {
      ns.log.info('\n%c\uD83D\uDD34 SINKS', 'font-size:13px;font-weight:bold;color:#ff4444');
      console.table(findings.sinks
        .sort((a, b) => severityScore(b.severity) - severityScore(a.severity))
        .map(s => ({ id: s.id, sev: s.severity.toUpperCase(), cat: s.category, file: s.file, line: s.line, match: s.match, code: truncate(s.code, 70) }))
      );
    }

    if (findings.flows.length) {
      ns.log.info('\n%c\u26A1 FLUJOS SOURCE \u2192 SINK', 'font-size:13px;font-weight:bold;color:#ff00ff');
      console.table(findings.flows.slice(0, 50).map(f => ({
        '\u26A1': f.exploitability === 'likely' ? '\uD83D\uDD25' : f.exploitability === 'possible' ? '\u26A0\uFE0F' : '\u2753',
        source: `[${f.source.id}] ${f.source.match}`, '\uD83C\uDFAF': manipulableIcon(f.source.manipulable),
        sink: `[${f.sink.id}] ${f.sink.match} (${f.sink.category})`,
        file: f.file, dist: f.distance === 0 ? '\u26A1SAME' : `${f.distance}L`, score: f.combinedScore,
      })));
    }

    if (findings.runtimeCalls.length) {
      ns.log.info('\n%c\uD83D\uDD25 RUNTIME CALLS', 'font-size:13px;font-weight:bold;color:#ff6600');
      console.table(findings.runtimeCalls.map(r => ({ id: r.id, sev: r.severity.toUpperCase(), hook: r.hook, value: truncate(r.value || r.args || '', 70) })));
    }
  }

  function printTriage() {
    analyzeFlows();
    clearHighlights();
    const { findings } = ns.state;
    console.clear();

    ns.log.info('%c\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557', 'color:#ff0000;font-weight:bold');
    ns.log.info('%c\u2551        \uD83C\uDFAF TRIAGE R\u00C1PIDO \u2014 Qu\u00E9 investigar        \u2551', 'color:#ff0000;font-weight:bold');
    ns.log.info('%c\u255A\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255D', 'color:#ff0000;font-weight:bold');
    ns.log.info(`\uD83D\uDCCD ${location.href}\n`);

    const actionable = findings.sources.filter(s => s.manipulable !== 'none');
    const ignored = findings.sources.filter(s => s.manipulable === 'none');

    if (!actionable.length) {
      ns.log.info('%c\u2705 No se encontraron sources manipulables', 'color:green;font-size:13px');
      ns.log.info(`   (${ignored.length} sources detectados pero NINGUNO controlable)\n`);
      return;
    }

    ns.log.info(`%c\uD83D\uDFE2 ${actionable.length} SOURCES MANIPULABLES (de ${findings.sources.length} total)  |  \u26AB ${ignored.length} ignorados`, 'font-weight:bold;color:#00ff00');
    ns.log.info('');

    let totalHighlighted = 0;
    const byFile = {};
    for (const src of actionable) {
      if (!byFile[src.file]) byFile[src.file] = [];
      byFile[src.file].push(src);
    }

    for (const [file, sources] of Object.entries(byFile)) {
      console.group(`%c\uD83D\uDCC2 ${file}`, 'font-weight:bold;color:#00aaff;font-size:12px');
      for (const src of sources) {
        const icon = src.manipulable === 'full' ? '\uD83D\uDFE2' : src.manipulable === 'partial' ? '\uD83D\uDFE1' : '\uD83D\uDFE0';
        ns.log.info(`${icon} %c[ID:${src.id}] L${src.line} %c${src.match}%c \u2014 ${src.why}`, 'color:#888', 'color:#4488ff;font-weight:bold', 'color:#aaa');
        if (src.context) ns.log.info(`%c${src.context}`, 'color:#888;font-family:monospace;font-size:11px');

        const hlCount = extractAndHighlight(src.code);
        if (hlCount) {
          totalHighlighted += hlCount;
          ns.log.info(`   %c\uD83D\uDD34 ${hlCount} elemento(s) resaltados en el DOM con borde rojo`, 'color:#ff4444');
        }

        const near = findings.sinks.filter(s => s.file === src.file && Math.abs(s.line - src.line) <= 5);
        for (const snk of near) {
          const d = Math.abs(snk.line - src.line);
          ns.log.info(`   %c\u2514\u2192 \uD83D\uDD34 SINK [ID:${snk.id}] L${snk.line} %c${snk.match}%c (${snk.category}) %c${d === 0 ? '\u26A1MISMA L\u00CDNEA' : d + 'L'}`,
            'color:#ff4444', 'color:#ff6600;font-weight:bold', 'color:#ff8888', d === 0 ? 'color:#ff0000;font-weight:bold' : 'color:#888');
          extractAndHighlight(snk.code);
        }
        ns.log.info('');
      }
      console.groupEnd();
    }

    if (totalHighlighted) {
      ns.log.info(`%c\uD83D\uDD34 ${totalHighlighted} elemento(s) SINK resaltados con borde rojo`, 'color:#ff0000;font-weight:bold;font-size:13px');
    }

    const inputCount = highlightVulnerableInputs();
    if (inputCount) {
      ns.log.info(`%c\uD83C\uDFAF ${inputCount} INPUT(S) VULNERABLE(S) resaltados con borde rojo pulsante en la p\u00E1gina`, 'color:#ff0000;font-weight:bold;font-size:13px;background:#330000;padding:2px 6px');
      ns.log.info('%c   Los inputs marcados est\u00E1n conectados a flujos explotables \u2014 escribe un payload para testear', 'color:#ffaa00');
      ns.log.info('%c   (usa domxss.unhighlight() para quitar)', 'color:#888');
    }

    if (totalHighlighted || inputCount) ns.log.info('');

    const hot = findings.flows.filter(f => f.exploitability === 'likely');
    const warm = findings.flows.filter(f => f.exploitability === 'possible');

    if (hot.length) {
      ns.log.info(`\n%c\uD83D\uDD25 ${hot.length} FLUJO(S) PROBABLEMENTE EXPLOTABLE(S)`, 'font-size:14px;font-weight:bold;color:#ff0000;background:#330000;padding:4px 8px');
      for (const flow of hot) {
        ns.log.info(`\n%c\uD83D\uDD25 Flow #${flow.id} \u2014 ${flow.file}`, 'font-weight:bold;color:#ff0000;font-size:12px');
        ns.log.info(`   \uD83D\uDD35 Source L${flow.source.line}: %c${flow.source.match}%c \u2192 ${manipulableIcon(flow.source.manipulable)}`, 'color:#4488ff;font-weight:bold', 'color:#ccc');
        ns.log.info(`   \uD83D\uDD34 Sink   L${flow.sink.line}: %c${flow.sink.match}%c (${flow.sink.category})`, 'color:#ff4444;font-weight:bold', 'color:#ccc');
        ns.log.info(`   \uD83D\uDCCF ${flow.distance === 0 ? '\u26A1 MISMA L\u00CDNEA' : flow.distance + ' l\u00EDneas'} | \uD83D\uDCA1 ${flow.source.why}`);
      }
    }

    if (warm.length) {
      ns.log.info(`\n%c\u26A0\uFE0F ${warm.length} flujo(s) posibles \u2014 investigaci\u00F3n manual`, 'font-size:12px;font-weight:bold;color:#ffaa00');
      console.table(warm.map(f => ({
        flow: `#${f.id}`, source: `${f.source.match} (${manipulableIcon(f.source.manipulable)})`,
        sink: `${f.sink.match} (${f.sink.category})`, file: f.file, dist: f.distance === 0 ? 'SAME' : `${f.distance}L`,
      })));
    }

    ns.log.info('\n%c\uD83D\uDCCB SIGUIENTE PASO:', 'font-size:13px;font-weight:bold;color:#00aaff');
    if (hot.length) {
      ns.log.info('  1. Verificar los flujos \uD83D\uDD25 (source controlable \u2192 sink peligroso)');
      ns.log.info('  2. Ejecuta %cdomxss.fuzz()%c para fuzzing autom\u00E1tico end-to-end', 'color:#ff00ff;font-weight:bold', 'color:#ccc');
    } else {
      ns.log.info('  Ejecuta %cdomxss.fuzz()%c para fuzzing autom\u00E1tico o %cdomxss.help()%c para ver comandos', 'color:#ff00ff;font-weight:bold', 'color:#ccc', 'color:#00ccff;font-weight:bold', 'color:#ccc');
    }
  }

  function inspectSource(id) {
    const { findings } = ns.state;
    const src = findings.sources.find(s => s.id === id);
    if (!src) { ns.log.info(`%cSource ID:${id} no encontrado`, 'color:red'); return; }
    ns.log.info('%c\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550', 'color:#4488ff');
    ns.log.info(`%c\uD83D\uDD35 SOURCE #${src.id} \u2014 ${src.match}`, 'font-size:14px;font-weight:bold;color:#4488ff');
    ns.log.info(`\uD83D\uDCC2 ${src.file} | L${src.line}`);
    ns.log.info(`\uD83C\uDFAF ${manipulableIcon(src.manipulable)} \u2014 ${src.why}`);
    ns.log.info(`%c${src.context || src.code}`, 'font-family:monospace;color:#ccc;background:#1a1a1a;padding:8px;font-size:11px');
    const near = findings.sinks.filter(s => s.file === src.file && Math.abs(s.line - src.line) <= 30);
    if (near.length) {
      ns.log.info(`\n%c\uD83D\uDD34 ${near.length} sink(s) cercano(s):`, 'font-weight:bold;color:#ff4444');
      for (const s of near) ns.log.info(`   [${s.id}] L${s.line} ${s.match} (${s.category}) \u2014 ${Math.abs(s.line - src.line) === 0 ? '\u26A1MISMA L\u00CDNEA' : Math.abs(s.line - src.line) + 'L'}`);
    }
    if (src.url) ns.log.info(`\n\uD83D\uDD17 ${src.url}:${src.line}`);
  }

  function printFlows() {
    analyzeFlows();
    const { findings } = ns.state;
    if (!findings.flows.length) { ns.log.info('%cNo hay flujos', 'color:#888'); return; }
    ns.log.info('%c\u26A1 FLUJOS DETALLADOS', 'font-size:14px;font-weight:bold;color:#ff00ff\n');
    for (const f of findings.flows.filter(f => f.exploitability !== 'unlikely')) {
      const e = f.exploitability === 'likely' ? '\uD83D\uDD25' : '\u26A0\uFE0F';
      ns.log.info(`${e} %cFlow #${f.id}%c \u2014 Score:${f.combinedScore} \u2014 ${f.exploitability.toUpperCase()}`, 'font-weight:bold;color:#ff00ff', 'color:#ccc');
      ns.log.info(`   \uD83D\uDCC2 ${f.file}`);
      ns.log.info(`   %c\uD83D\uDD35 L${f.source.line}: ${f.source.match}%c \u2192 ${manipulableIcon(f.source.manipulable)} \u2014 ${f.source.why}`, 'color:#4488ff', 'color:#aaa');
      ns.log.info(`   %c\uD83D\uDD34 L${f.sink.line}: ${f.sink.match} (${f.sink.category})`, 'color:#ff4444');
      ns.log.info(`   \uD83D\uDCCF ${f.distance === 0 ? '\u26A1MISMA L\u00CDNEA' : f.distance + 'L'}\n`);
    }
  }

  function exportJSON() {
    analyzeFlows();
    const { findings } = ns.state;
    const data = { url: location.href, timestamp: new Date().toISOString(),
      stats: { sources: findings.sources.length, sinks: findings.sinks.length, runtimeCalls: findings.runtimeCalls.length, flows: findings.flows.length },
      findings,
      resources: ns.state.resources || [],
    };
    const json = JSON.stringify(data, null, 2);
    function fallbackCopy(text) {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.cssText = 'position:fixed;left:-9999px;top:-9999px;opacity:0';
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand('copy');
        ns.log.info('%c\u2705 JSON copiado al clipboard', 'color:green;font-weight:bold');
      } catch {
        ns.log.info('%c\u26A0 Could not copy — JSON printed below:', 'color:#ffaa00;font-weight:bold');
        ns.log.info(json);
      }
      ta.remove();
    }
    try {
      navigator.clipboard.writeText(json).then(
        () => ns.log.info('%c\u2705 JSON copiado al clipboard', 'color:green;font-weight:bold'),
        () => fallbackCopy(json)
      );
    } catch {
      fallbackCopy(json);
    }
    return data;
  }

  function printInputs() {
    analyzeFlows();
    clearHighlights();
    injectPulseAnimation();

    ns.log.info('%c\uD83C\uDFAF INPUTS VULNERABLES \u2014 Scan', 'font-size:14px;font-weight:bold;color:#ff0000');
    ns.log.info(`\uD83D\uDCCD ${location.href}\n`);

    const count = highlightVulnerableInputs();

    if (count === 0) {
      ns.log.info('%c\u2705 No se encontraron inputs conectados a flujos vulnerables', 'color:green');
      ns.log.info('%cPosibles razones:', 'color:#888');
      ns.log.info('  - Los sources son URL-based (location.search/hash) sin inputs en la p\u00E1gina');
      ns.log.info('  - Los sinks no apuntan a elementos con entradas de texto');
      ns.log.info('  - Usa domxss.triage() para ver los flujos completos');
    } else {
      ns.log.info(`%c\uD83C\uDFAF ${count} INPUT(S) resaltados con borde rojo pulsante`, 'font-weight:bold;color:#ff0000;font-size:13px');
      ns.log.info('');

      const marked = ns.state.highlightedEls.filter(h => h.el && isInputElement(h.el));
      if (marked.length) {
        console.table(marked.map((h, i) => {
          const el = h.el;
          return {
            '#': i + 1,
            tag: el.tagName.toLowerCase(),
            type: el.type || '-',
            name: el.name || '-',
            id: el.id || '-',
            value: truncate(el.value || el.textContent || '', 50),
            label: h.label?.textContent || '',
          };
        }));
      }

      ns.log.info('\n%c\uD83D\uDCA1 Prueba escribir un payload XSS en los inputs marcados y observa si se refleja sin sanitizar', 'color:#ffaa00');
      ns.log.info('%c   usa domxss.unhighlight() para quitar el resaltado', 'color:#888');
    }
  }

  function printHelp() {
    const h = 'font-weight:bold;font-size:13px;color:#00ff88';
    const cmd = 'font-weight:bold;color:#00ccff';
    const desc = 'color:#ccc';
    const sep = 'color:#555';
    const tip = 'color:#ffcc00;font-style:italic';

    ns.log.info('');
    ns.log.info('%c\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550', sep);
    ns.log.info('%c  DOM XSS Hunter v4.6 \u2014 Available Commands', h);
    ns.log.info('%c\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550', sep);

    ns.log.info('');
    ns.log.info('%c\u2500\u2500 ANALYSIS \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500', sep);
    ns.log.info('%c  domxss.triage()           %cQuick view \u2014 manipulable sources + exploitable flows', cmd, desc);
    ns.log.info('%c  domxss.report()           %cFull report \u2014 sources, sinks, flows, runtime calls', cmd, desc);
    ns.log.info('%c  domxss.flows()            %cDetailed source\u2192sink flows with scoring', cmd, desc);
    ns.log.info('%c  domxss.inspect(id)        %cInspect source by ID \u2014 code context + nearby sinks', cmd, desc);
    ns.log.info('%c  domxss.resources()        %cJS resource map \u2014 files, types, sinks, risk', cmd, desc);

    ns.log.info('');
    ns.log.info('%c\u2500\u2500 ACTIVE TESTING \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500', sep);
    ns.log.info('%c  domxss.fuzz()             %cAUTO-FUZZ: inject canary into inputs, URL, hash, postMessage', cmd, desc);
    ns.log.info('%c                            %c   \u2192 detect reflections \u2192 try payloads \u2192 verify execution', cmd, desc);
    ns.log.info('%c  domxss.fuzz.nav()         %cNavigate with canary in URL params (for DOM XSS via URL)', cmd, desc);
    ns.log.info('%c  domxss.fuzz.check()       %cSearch for fuzz canary on current page (cross-page)', cmd, desc);
    ns.log.info('%c  domxss.fuzz.results()     %cExport fuzz results to clipboard (JSON)', cmd, desc);
    ns.log.info('%c  domxss.fuzz.waf()         %cWAF bypass: enumerate allowed tags & events via fetch', cmd, desc);
    ns.log.info('%c  domxss.fuzz.csp()         %cAnalyze CSP policy (HTTP headers + meta tags) and suggest bypasses', cmd, desc);
    ns.log.info('%c  domxss.fuzz.protocol()    %cTest javascript: protocol encoding variants', cmd, desc);
    ns.log.info('%c  domxss.fuzz.dangling()    %cTest dangling markup injection for content exfiltration', cmd, desc);
    ns.log.info('%c  domxss.fuzz.post()        %cTest POST form reflection via fetch (also auto-tested in fuzz())', cmd, desc);
    ns.log.info('%c  domxss.fuzz.blind(url)    %cBlind XSS: inject callback payloads into stored inputs', cmd, desc);
    ns.log.info('%c  domxss.fuzz.clobbering()  %cDOM clobbering: find + test clobberable globals', cmd, desc);
    ns.log.info('%c  domxss.fuzz.mxss()        %cmXSS: test browser HTML mutation through innerHTML/DOMParser', cmd, desc);
    ns.log.info('%c  domxss.fuzz.prototype()   %cPrototype pollution: detect pollutable gadgets + XSS chains', cmd, desc);

    ns.log.info('');
    ns.log.info('%c\u2500\u2500 PROBE \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500', sep);
    ns.log.info('%c  domxss.probe()            %cManual probe: inject canary and show analysis', cmd, desc);
    ns.log.info('%c  domxss.probe.go()         %cNavigate to URL with injected canary', cmd, desc);
    ns.log.info('%c  domxss.probe.check()      %cVerify canary reflections manually', cmd, desc);
    ns.log.info('%c  domxss.probe.postmessage()%cSend canary via postMessage to iframe/window', cmd, desc);

    ns.log.info('');
    ns.log.info('%c\u2500\u2500 FRAMEWORKS \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500', sep);
    ns.log.info('%c  domxss.frameworks()       %cFull framework XSS report', cmd, desc);
    ns.log.info('%c  domxss.frameworks.detect() %cDetect all frameworks (returns object)', cmd, desc);
    ns.log.info('%c  domxss.frameworks.angular()%cAngularJS template injection + sandbox escape test', cmd, desc);
    ns.log.info('%c  domxss.frameworks.jquery() %cFind jQuery-specific sinks', cmd, desc);
    ns.log.info('%c  domxss.frameworks.jqueryHash()%cjQuery hashchange XSS fuzzer', cmd, desc);
    ns.log.info('%c  domxss.frameworks.vue()   %cFind Vue.js v-html and template sinks', cmd, desc);
    ns.log.info('%c  domxss.frameworks.react() %cFind React dangerouslySetInnerHTML sinks', cmd, desc);

    ns.log.info('');
    ns.log.info('%c\u2500\u2500 VISUAL \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500', sep);
    ns.log.info('%c  domxss.inputs()           %cHighlight vulnerable inputs with pulsing red border', cmd, desc);
    ns.log.info('%c  domxss.highlight()        %cHighlight all elements with sinks + vulnerable inputs', cmd, desc);
    ns.log.info('%c  domxss.unhighlight()      %cRemove all visual highlights', cmd, desc);

    ns.log.info('');
    ns.log.info('%c\u2500\u2500 UTILITIES \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500', sep);
    ns.log.info('%c  domxss.export()           %cCopy results as JSON to clipboard (for reports)', cmd, desc);
    ns.log.info('%c  domxss.rescan()           %cRe-run the full scan', cmd, desc);
    ns.log.info('%c  domxss.clear()            %cReset all \u2014 clear results and uninstall hooks', cmd, desc);
    ns.log.info('%c  domxss.help()             %cShow this help again', cmd, desc);

    ns.log.info('');
    ns.log.info('%c\u2500\u2500 RECOMMENDED WORKFLOW \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500', sep);
    ns.log.info('%c  Auto:   triage() \u2192 fuzz() or fuzz.nav() \u2192 done!', tip);
    ns.log.info('%c  Manual: triage() \u2192 inputs() \u2192 inspect(N) \u2192 probe() \u2192 export()', tip);
    ns.log.info('%c  WAF:    fuzz.waf() \u2192 fuzz.protocol() \u2192 fuzz.dangling()', tip);
    ns.log.info('%c  FW:     frameworks() \u2192 frameworks.angular() or frameworks.jqueryHash()', tip);
    ns.log.info('%c  Advanced: fuzz.blind("url") | fuzz.clobbering() | fuzz.mxss() | fuzz.prototype()', tip);
    ns.log.info('%c\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550', sep);
    ns.log.info('');
  }

  function printResources() {
    const resources = ns.state.resources || [];
    if (!resources.length) {
      ns.log.info('%c[Resources] No JS resources mapped yet. Run a scan first.', 'color:#888');
      return;
    }

    const riskColor = { CRITICAL: '#ff0000', HIGH: '#ff0000', MEDIUM: '#ffaa00', LOW: '#888888', NONE: '#00ff00' };
    const riskIcon = { CRITICAL: '\uD83D\uDD34', HIGH: '\uD83D\uDD34', MEDIUM: '\uD83D\uDFE1', LOW: '\u26AA', NONE: '\uD83D\uDFE2' };

    ns.log.info('%c\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557', 'color:#00aaff;font-weight:bold');
    ns.log.info('%c\u2551     JS Resource Map \u2014 Files, Types, Risk     \u2551', 'color:#00aaff;font-weight:bold');
    ns.log.info('%c\u255A\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255D', 'color:#00aaff;font-weight:bold');
    ns.log.info(`\uD83D\uDCCD ${location.href}`);
    ns.log.info(`\uD83D\uDCC5 ${new Date().toISOString()}\n`);

    // Summary stats
    const typeCount = {};
    const riskCount = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, NONE: 0 };
    for (const r of resources) {
      typeCount[r.type] = (typeCount[r.type] || 0) + 1;
      riskCount[r.risk] = (riskCount[r.risk] || 0) + 1;
    }

    ns.log.info('%c\uD83D\uDCCA SUMMARY', 'font-size:14px;font-weight:bold;color:#00aaff');
    const summaryObj = {
      'Total JS files': resources.length,
      ...typeCount,
    };
    if (riskCount.CRITICAL > 0) summaryObj['\uD83D\uDD34 CRITICAL risk'] = riskCount.CRITICAL;
    summaryObj['\uD83D\uDD34 HIGH risk'] = riskCount.HIGH;
    summaryObj['\uD83D\uDFE1 MEDIUM risk'] = riskCount.MEDIUM;
    summaryObj['\u26AA LOW risk'] = riskCount.LOW;
    summaryObj['\uD83D\uDFE2 NONE risk'] = riskCount.NONE;
    console.table(summaryObj);

    // Main resource table
    ns.log.info('\n%c\uD83D\uDCC1 ALL RESOURCES', 'font-size:13px;font-weight:bold;color:#00aaff');
    console.table(
      resources
        .sort((a, b) => {
          const riskOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, NONE: 4 };
          return (riskOrder[a.risk] ?? 4) - (riskOrder[b.risk] ?? 4);
        })
        .map(r => ({
          File: r.file,
          Type: r.type,
          Size: r.size > 1024 ? `${(r.size / 1024).toFixed(1)}KB` : `${r.size}B`,
          Sources: r.sourceCount,
          Sinks: r.sinkCount,
          Flows: r.flowCount,
          Risk: `${riskIcon[r.risk] || ''} ${r.risk}`,
          Manipulable: r.manipulable,
        }))
    );

    // Detailed findings for CRITICAL-risk files
    const criticalRisk = resources.filter(r => r.risk === 'CRITICAL');
    if (criticalRisk.length) {
      ns.log.info('\n%c\uD83D\uDD34 CRITICAL-RISK FILES \u2014 Reflected DOM XSS', 'font-size:13px;font-weight:bold;color:#ff0000;background:#330000;padding:2px 6px');
      for (const r of criticalRisk) {
        ns.log.info(`\n  %c\uD83D\uDD34 ${r.file}%c (${r.type})`, 'color:#ff0000;font-weight:bold', 'color:#888');
        if (r.url) ns.log.info(`     URL: ${r.url}`);

        if (r.composites && r.composites.length) {
          for (const c of r.composites) {
            ns.log.info(`     %c\u26A0\uFE0F CRITICAL: ${c.name} \u2014 ${c.desc}`, 'color:#ff0000;font-weight:bold;font-size:12px');
          }
        }

        if (r.sinks.length) {
          ns.log.info('     %cSinks:', 'color:#ff4444;font-weight:bold');
          for (const s of r.sinks) {
            ns.log.info(`       \u2022 ${s.name} (\u00D7${s.count})`);
          }
        }

        if (r.sources.length) {
          ns.log.info('     %cSources (user-controllable):', 'color:#4488ff;font-weight:bold');
          for (const s of r.sources) {
            const icon = s.manipulable === 'full' ? '\uD83C\uDFAF' : s.manipulable === 'partial' ? '\u26A0\uFE0F' : '\u2753';
            ns.log.info(`       ${icon} ${s.name} (\u00D7${s.count}) \u2014 ${s.manipulable}`);
          }
        }

        ns.log.info('     %c\uD83D\uDCA1 Run domxss.fuzz() \u2014 XHR response scanning will detect the reflection', 'color:#ffaa00;font-weight:bold');
      }
    }

    // Detailed findings for HIGH-risk files
    const highRisk = resources.filter(r => r.risk === 'HIGH');
    if (highRisk.length) {
      ns.log.info('\n%c\uD83D\uDD34 HIGH-RISK FILES \u2014 Detail', 'font-size:13px;font-weight:bold;color:#ff0000');
      for (const r of highRisk) {
        ns.log.info(`\n  %c\uD83D\uDD34 ${r.file}%c (${r.type})`, 'color:#ff0000;font-weight:bold', 'color:#888');
        if (r.url) ns.log.info(`     URL: ${r.url}`);

        if (r.composites && r.composites.length) {
          for (const c of r.composites) {
            ns.log.info(`     %c\u26A0\uFE0F ${c.name} \u2014 ${c.desc}`, 'color:#ff6600;font-weight:bold');
          }
        }

        if (r.sinks.length) {
          ns.log.info('     %cSinks:', 'color:#ff4444;font-weight:bold');
          for (const s of r.sinks) {
            ns.log.info(`       \u2022 ${s.name} (\u00D7${s.count})`);
          }
        }

        if (r.sources.length) {
          ns.log.info('     %cSources (user-controllable):', 'color:#4488ff;font-weight:bold');
          for (const s of r.sources) {
            const icon = s.manipulable === 'full' ? '\uD83C\uDFAF' : s.manipulable === 'partial' ? '\u26A0\uFE0F' : '\u2753';
            ns.log.info(`       ${icon} ${s.name} (\u00D7${s.count}) \u2014 ${s.manipulable}`);
          }
        }

        ns.log.info('     %c\uD83D\uDCA1 Next: Run domxss.fuzz() to test or inspect manually', 'color:#ffaa00');
      }
    }

    // Show MEDIUM-risk details too
    const medRisk = resources.filter(r => r.risk === 'MEDIUM');
    if (medRisk.length) {
      ns.log.info('\n%c\uD83D\uDFE1 MEDIUM-RISK FILES', 'font-size:13px;font-weight:bold;color:#ffaa00');
      for (const r of medRisk) {
        const sinkNames = r.sinks.map(s => s.name).join(', ') || 'none';
        const sourceNames = r.sources.map(s => s.name).join(', ') || 'none';
        ns.log.info(`  \u26A0\uFE0F %c${r.file}%c \u2014 sinks: ${sinkNames} | sources: ${sourceNames}`, 'color:#ffaa00;font-weight:bold', 'color:#ccc');
      }
    }

    ns.log.info('');
  }

  ns.reporter = { printReport, printTriage, inspectSource, printFlows, exportJSON, printHelp, printInputs, printResources };
})();
