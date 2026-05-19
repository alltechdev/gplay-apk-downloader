// Unit tests for shouldEmitProgress in src/ui/log.js. The function is
// called dozens of times per second during a download; getting the
// throttle wrong either floods the log or makes progress look frozen.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const srcPath = resolve(__dirname, '..', '..', 'src', 'ui', 'log.js');

function loadThrottle(initialNow = 1_000_000) {
  let now = initialNow;
  const src = readFileSync(srcPath, 'utf8');
  const throttleMatch = /const PROGRESS_THROTTLE_MS = (\d+);/.exec(src);
  const fnMatch = /export function shouldEmitProgress\(id\) \{[\s\S]*?\n\}/.exec(src);
  if (!throttleMatch || !fnMatch) throw new Error('cannot locate shouldEmitProgress');
  const code = `
    const PROGRESS_THROTTLE_MS = ${throttleMatch[1]};
    const progressLastAt = new Map();
    ${fnMatch[0].replace('export ', '')}
    globalThis.shouldEmitProgress = shouldEmitProgress;
    globalThis.progressLastAt = progressLastAt;
    globalThis.PROGRESS_THROTTLE_MS = PROGRESS_THROTTLE_MS;
  `;
  const ctx = vm.createContext({
    Date: { now: () => now },
    Map,
  });
  vm.runInContext(code, ctx);
  return { ctx, advance: (ms) => { now += ms; } };
}

test('shouldEmitProgress: first call for a given id always returns true', () => {
  const { ctx } = loadThrottle();
  assert.equal(ctx.shouldEmitProgress(1), true);
  assert.equal(ctx.shouldEmitProgress(2), true);
});

test('shouldEmitProgress: rapid second call returns false (throttled)', () => {
  const { ctx, advance } = loadThrottle();
  assert.equal(ctx.shouldEmitProgress(1), true);
  advance(100); // still inside the 750ms window
  assert.equal(ctx.shouldEmitProgress(1), false);
});

test('shouldEmitProgress: call after the throttle window returns true', () => {
  const { ctx, advance } = loadThrottle();
  ctx.shouldEmitProgress(1);
  advance(ctx.PROGRESS_THROTTLE_MS + 1);
  assert.equal(ctx.shouldEmitProgress(1), true);
});

test('shouldEmitProgress: throttles per-id (independent buckets)', () => {
  const { ctx, advance } = loadThrottle();
  ctx.shouldEmitProgress(1);
  ctx.shouldEmitProgress(2);
  advance(100);
  // Both within their own windows → both throttled.
  assert.equal(ctx.shouldEmitProgress(1), false);
  assert.equal(ctx.shouldEmitProgress(2), false);
  advance(ctx.PROGRESS_THROTTLE_MS);
  assert.equal(ctx.shouldEmitProgress(1), true);
  assert.equal(ctx.shouldEmitProgress(2), true);
});

test('shouldEmitProgress: exactly at the boundary is throttled (strict less-than check)', () => {
  const { ctx, advance } = loadThrottle();
  ctx.shouldEmitProgress(1);
  advance(ctx.PROGRESS_THROTTLE_MS - 1);
  assert.equal(ctx.shouldEmitProgress(1), false);
  advance(1); // exactly at PROGRESS_THROTTLE_MS now
  assert.equal(ctx.shouldEmitProgress(1), true, 'at the boundary should emit');
});

test('shouldEmitProgress: stores the latest emit timestamp in progressLastAt', () => {
  const { ctx } = loadThrottle(5000);
  ctx.shouldEmitProgress(42);
  assert.equal(ctx.progressLastAt.get(42), 5000);
});
