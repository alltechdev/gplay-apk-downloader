// Unit tests for the pure formatting helpers inside src/ui/info-card.js.
// Loaded by vm because info-card.js imports browser-only modules (dom.js,
// rpc.js, etc.) that can't be evaluated under Node. We only exercise the
// helpers that don't touch globals.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const srcPath = resolve(__dirname, '..', '..', 'src', 'ui', 'info-card.js');

function loadHelpers() {
  // Pluck just the helper function bodies. Avoid full ESM evaluation
  // (which would require stubbing dom/rpc/runtime/log).
  const src = readFileSync(srcPath, 'utf8');
  const grab = (name) => {
    const re = new RegExp(`function ${name}\\(([^)]*)\\)[^{]*\\{`, 'g');
    const m = re.exec(src);
    if (!m) throw new Error(`could not find ${name}`);
    // Walk braces to find the matching close.
    let depth = 1; let i = re.lastIndex;
    while (depth > 0 && i < src.length) {
      const c = src[i++];
      if (c === '{') depth++;
      else if (c === '}') depth--;
    }
    return src.slice(m.index, i);
  };
  const fmtSizeStub = `function fmtSize(b) {
    if (b === undefined || b === null || b === 0) return '?';
    if (b < 1024) return (b < 100 ? b.toFixed(2) + ' B' : b + ' B');
    if (b < 1024*1024) return (b/1024).toFixed(2) + ' KB';
    if (b < 1024*1024*1024) return (b/1024/1024).toFixed(2) + ' MB';
    return (b/1024/1024/1024).toFixed(2) + ' GB';
  }`;
  const code = `${fmtSizeStub}\n${grab('describeSplits')}\nglobalThis.describeSplits = describeSplits;`;
  const ctx = vm.createContext({});
  vm.runInContext(code, ctx);
  return ctx;
}

test('describeSplits: tags non-config splits with [asset pack]', () => {
  const ctx = loadHelpers();
  const labels = ctx.describeSplits([
    { name: 'config.arm64_v8a', size: 1024 * 1024 },
    { name: 'config.en',        size: 0          },
    { name: 'obbassets',        size: 5 * 1024 * 1024 },
  ]);
  assert.equal(labels[0], 'config.arm64_v8a (1.00 MB)');
  assert.equal(labels[1], 'config.en');
  assert.equal(labels[2], 'obbassets (5.00 MB) [asset pack]');
});

test('describeSplits: accepts plain-string splits (no size info)', () => {
  const ctx = loadHelpers();
  const labels = ctx.describeSplits(['config.arm64_v8a', 'something_else']);
  assert.equal(labels[0], 'config.arm64_v8a');
  assert.equal(labels[1], 'something_else [asset pack]');
});

test('describeSplits: empty input → empty output', () => {
  const ctx = loadHelpers();
  assert.deepEqual(ctx.describeSplits([]), []);
});
