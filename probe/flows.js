/**
 * DOM XSS Hunter v4.0 — Flow Analysis (Source -> Sink)
 */
(function () {
  'use strict';

  const ns = window.__DOMXSS;
  const { severityScore, manipulableScore, manipulableIcon } = ns.utils;

  function analyzeFlows() {
    const { findings } = ns.state;
    findings.flows = [];

    for (const source of findings.sources) {
      if (source.manipulable === 'none') continue;
      for (const sink of findings.sinks) {
        if (source.file !== sink.file) continue;
        const distance = Math.abs(source.line - sink.line);
        let confidence;
        if (distance === 0) confidence = 'critical';
        else if (distance <= 5) confidence = 'high';
        else if (distance <= 30) confidence = 'medium';
        else if (distance <= 100) confidence = 'low';
        else continue;

        if (source.line < sink.line && confidence !== 'critical') {
          const levels = ['low', 'medium', 'high', 'critical'];
          confidence = levels[Math.min(levels.indexOf(confidence) + 1, 3)];
        }

        const combinedScore = severityScore(source.severity) + severityScore(sink.severity) + manipulableScore(source.manipulable);
        let exploitability;
        if (distance === 0 && source.manipulable === 'full') exploitability = 'likely';
        else if (source.manipulable === 'full' && combinedScore >= 7) exploitability = 'likely';
        else if (source.manipulable === 'full' && combinedScore >= 5) exploitability = 'possible';
        else if (combinedScore >= 6) exploitability = 'possible';
        else exploitability = 'unlikely';

        findings.flows.push({
          id: findings.flows.length + 1,
          source: { id: source.id, match: source.match, category: source.category, line: source.line, manipulable: source.manipulable, why: source.why },
          sink: { id: sink.id, match: sink.match, category: sink.category, line: sink.line },
          file: source.file, distance, confidence, combinedScore, exploitability,
        });
      }
    }

    findings.flows.sort((a, b) => {
      const ord = { likely: 0, possible: 1, unlikely: 2 };
      return (ord[a.exploitability] ?? 3) - (ord[b.exploitability] ?? 3)
        || b.combinedScore - a.combinedScore
        || a.distance - b.distance;
    });
  }

  ns.flows = { analyzeFlows };
})();
