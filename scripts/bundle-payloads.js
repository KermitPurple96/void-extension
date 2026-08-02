#!/usr/bin/env node
// Bundles payload .txt files from Agent-zero-pentest into data/payloads.js
const fs = require('fs');
const path = require('path');

const srcDir = 'C:/Users/jaime/Agent-zero-pentest/patches/plugins/_pentest_kit/data/payloads';
const outFile = path.join(__dirname, '..', 'data', 'payloads.js');

const files = fs.readdirSync(srcDir).filter(f => f.endsWith('.txt')).sort();
const payloads = {};

for (const f of files) {
  const key = f.replace('.txt', '');
  const lines = fs.readFileSync(path.join(srcDir, f), 'utf8')
    .split(/\r?\n/)
    .filter(l => l.trim() !== '' && !l.trim().startsWith('#'));
  payloads[key] = lines;
}

let out = '// data/payloads.js \u2014 Curated payload libraries for AI pentesting\n';
out += '// Sourced from Agent-zero-pentest data/payloads/\n\n';
out += 'window.VOID_PAYLOADS = ' + JSON.stringify(payloads, null, 2) + ';\n';

fs.writeFileSync(outFile, out, 'utf8');

console.log('Written to', outFile);
for (const k of Object.keys(payloads)) {
  console.log('  ' + k + ': ' + payloads[k].length + ' payloads');
}
