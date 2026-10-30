// Unit tests for src/ui/p-map-limit.js — concurrency-limited parallel map.
// Critical correctness for the parallel split-fetch path; legacy uses
// `download_splits_parallel(splits, max_workers=4)`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pMapLimit } from '../../src/ui/p-map-limit.js';

test('pMapLimit: preserves order of input', async () => {
  const out = await pMapLimit([1, 2, 3, 4, 5], 2, async (n) => {
    await new Promise((r) => setTimeout(r, (5 - n) * 10));
    return n * 10;
  });
  assert.deepEqual(out, [10, 20, 30, 40, 50]);
});

test('pMapLimit: never exceeds the concurrency limit', async () => {
  let inFlight = 0; let peak = 0;
  await pMapLimit(Array.from({ length: 12 }, (_, i) => i), 3, async () => {
    inFlight++;
    peak = Math.max(peak, inFlight);
    await new Promise((r) => setTimeout(r, 5));
    inFlight--;
  });
  assert.ok(peak <= 3, `peak concurrency was ${peak}, expected <= 3`);
  assert.ok(peak >= 2, `expected actual parallelism, peak was ${peak}`);
});

test('pMapLimit: rejects on first worker error', async () => {
  await assert.rejects(
    pMapLimit([1, 2, 3], 2, async (n) => { if (n === 2) throw new Error('boom'); return n; }),
    /boom/,
  );
});

test('pMapLimit: handles empty input', async () => {
  const out = await pMapLimit([], 4, async () => { throw new Error('should not run'); });
  assert.deepEqual(out, []);
});

test('pMapLimit: limit larger than items still works', async () => {
  const out = await pMapLimit([1, 2], 10, async (n) => n * 2);
  assert.deepEqual(out, [2, 4]);
});

test('pMapLimit: retains resources until active workers settle and stops scheduling after failure', async () => {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const started = [];
  let cleaned = false;
  let settled = false;
  const job = pMapLimit([0, 1, 2, 3], 2, async (n) => {
    started.push(n);
    if (n === 0) throw new Error('first failure');
    await gate;
    assert.equal(cleaned, false, 'cookie rules must remain until this worker finishes');
    throw new Error('later failure');
  }).finally(() => { cleaned = true; settled = true; });
  const rejection = assert.rejects(job, /first failure/);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(settled, false);
  assert.deepEqual(started, [0, 1]);
  release();
  await rejection;
  assert.equal(cleaned, true);
});
