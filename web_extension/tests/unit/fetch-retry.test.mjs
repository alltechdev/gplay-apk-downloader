// Unit tests for src/ui/fetch-retry.js — retry with exponential backoff.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { backoffMs, fetchWithRetry } from '../../src/ui/fetch-retry.js';

const noSleep = async () => {};

test('backoffMs: grows exponentially within the cap', () => {
  // With jitter:0 the result is deterministic.
  assert.equal(backoffMs(1, { base: 100, max: 10_000, jitter: 0 }), 100);
  assert.equal(backoffMs(2, { base: 100, max: 10_000, jitter: 0 }), 200);
  assert.equal(backoffMs(3, { base: 100, max: 10_000, jitter: 0 }), 400);
  assert.equal(backoffMs(8, { base: 100, max: 10_000, jitter: 0 }), 10_000); // capped
});

test('backoffMs: jitter stays within ±jitter band', () => {
  for (let i = 0; i < 50; i++) {
    const v = backoffMs(3, { base: 1000, max: 30_000, jitter: 0.25 });
    // base=1000, attempt=3 → 4000ms. ±25% = [3000, 5000].
    assert.ok(v >= 3000 && v <= 5000, 'value ' + v + ' outside [3000, 5000]');
  }
});

test('fetchWithRetry: returns immediately on first success', async () => {
  let calls = 0;
  const res = await fetchWithRetry(async () => {
    calls++;
    return new Response('ok', { status: 200 });
  }, { sleep: noSleep });
  assert.equal(calls, 1);
  assert.equal(res.status, 200);
});

test('fetchWithRetry: retries on 5xx, succeeds on 2nd attempt', async () => {
  let calls = 0;
  const res = await fetchWithRetry(async () => {
    calls++;
    return calls < 2
      ? new Response('boom', { status: 503 })
      : new Response('ok',   { status: 200 });
  }, { attempts: 3, sleep: noSleep });
  assert.equal(calls, 2);
  assert.equal(res.status, 200);
});

test('fetchWithRetry: retries on 429', async () => {
  let calls = 0;
  await fetchWithRetry(async () => {
    calls++;
    return calls < 2
      ? new Response('', { status: 429 })
      : new Response('', { status: 200 });
  }, { attempts: 3, sleep: noSleep });
  assert.equal(calls, 2);
});

test('fetchWithRetry: does NOT retry on 404 (client error)', async () => {
  let calls = 0;
  await assert.rejects(
    fetchWithRetry(async () => {
      calls++;
      return new Response('', { status: 404 });
    }, { attempts: 3, sleep: noSleep }),
    /HTTP 404/,
  );
  assert.equal(calls, 1, 'must not retry 4xx');
});

test('fetchWithRetry: retries on thrown network errors', async () => {
  let calls = 0;
  const res = await fetchWithRetry(async () => {
    calls++;
    if (calls < 3) throw new TypeError('NetworkError when attempting to fetch');
    return new Response('', { status: 200 });
  }, { attempts: 5, sleep: noSleep });
  assert.equal(calls, 3);
  assert.equal(res.status, 200);
});

test('fetchWithRetry: gives up after attempts and rethrows last error', async () => {
  let calls = 0;
  await assert.rejects(
    fetchWithRetry(async () => {
      calls++;
      throw new Error('still down');
    }, { attempts: 3, sleep: noSleep }),
    /still down/,
  );
  assert.equal(calls, 3);
});

test('fetchWithRetry: calls onRetry for each retry attempt', async () => {
  const events = [];
  let calls = 0;
  await fetchWithRetry(async () => {
    calls++;
    return calls < 3
      ? new Response('', { status: 503 })
      : new Response('', { status: 200 });
  }, {
    attempts: 3,
    sleep: noSleep,
    onRetry: (attempt, err, status) => events.push({ attempt, status, msg: err?.message }),
  });
  assert.equal(events.length, 2);
  assert.equal(events[0].attempt, 1);
  assert.equal(events[0].status, 503);
  assert.equal(events[1].attempt, 2);
});
