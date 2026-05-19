// Unit tests for the memory-budget gate in download-handler.js.
// We pluck the pure helper by reading the source and exporting via vm —
// download-handler.js imports browser-only modules that can't load
// under Node, but `checkMergeMemoryBudget` itself only references
// `fmtSize`, which we stub.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const srcPath = resolve(__dirname, '..', '..', 'src', 'ui', 'download-handler.js');

function loadHelper() {
  const src = readFileSync(srcPath, 'utf8');
  // Pull out the constant + function bodies.
  const limitMatch = /const MERGE_MAX_BYTES = ([\d_]+) \* 1024 \* 1024/.exec(src);
  if (!limitMatch) throw new Error('cannot find MERGE_MAX_BYTES');
  const fnMatch = /export function checkMergeMemoryBudget\(installSize\) \{[\s\S]*?\n\}/.exec(src);
  if (!fnMatch) throw new Error('cannot find checkMergeMemoryBudget');

  const code = `
    const fmtSize = (b) => (b / (1024*1024)).toFixed(2) + ' MB';
    const MERGE_MAX_BYTES = ${limitMatch[1]} * 1024 * 1024;
    ${fnMatch[0].replace('export ', '')}
    globalThis.MERGE_MAX_BYTES = MERGE_MAX_BYTES;
    globalThis.checkMergeMemoryBudget = checkMergeMemoryBudget;
  `;
  const ctx = vm.createContext({});
  vm.runInContext(code, ctx);
  return { check: ctx.checkMergeMemoryBudget, limit: ctx.MERGE_MAX_BYTES };
}

const { check, limit } = loadHelper();

test('checkMergeMemoryBudget: returns null for sane sizes', () => {
  assert.equal(check(50 * 1024 * 1024),  null); // 50 MB
  assert.equal(check(500 * 1024 * 1024), null); // 500 MB
  assert.equal(check(limit - 1),         null);
});

test('checkMergeMemoryBudget: returns an error string at the limit', () => {
  const msg = check(limit + 1);
  assert.ok(typeof msg === 'string' && msg.length > 0);
  assert.match(msg, /too large/i);
  assert.match(msg, /Uncheck "Merge splits"/);
});

test('checkMergeMemoryBudget: tolerates missing / zero / negative size', () => {
  assert.equal(check(0), null);
  assert.equal(check(null), null);
  assert.equal(check(undefined), null);
  assert.equal(check(-1), null);
});

test('checkMergeMemoryBudget: includes the actual size in the error', () => {
  const msg = check(2_000 * 1024 * 1024);
  assert.match(msg, /\d.*MB/, 'error must include the formatted size');
});
