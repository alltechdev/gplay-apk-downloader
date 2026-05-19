// Unit tests for src/sw/05-logger.js — level-filtered tagged logger.
// SW_LOG_LEVEL is 'info' in production. We verify the gate by examining
// the console calls made for each method.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadSw } from '../helpers/sw-load.mjs';

function loadLogger() {
  const calls = [];
  const consoleStub = {
    debug: (...a) => calls.push(['debug', ...a]),
    info:  (...a) => calls.push(['info',  ...a]),
    warn:  (...a) => calls.push(['warn',  ...a]),
    error: (...a) => calls.push(['error', ...a]),
  };
  return {
    calls,
    ...loadSw(['00-config.js', '05-logger.js'], ['swLog'], { console: consoleStub }),
  };
}

test('swLog.debug is filtered out at the default level', () => {
  const { swLog, calls } = loadLogger();
  swLog.debug('hidden');
  assert.equal(calls.length, 0);
});

test('swLog.info / warn / error all reach console', () => {
  const { swLog, calls } = loadLogger();
  swLog.info('a');
  swLog.warn('b');
  swLog.error('c');
  assert.equal(calls.length, 3);
  assert.deepEqual(calls.map((c) => c[0]), ['info', 'warn', 'error']);
});

test('swLog prefixes every call with [gplaydl]', () => {
  const { swLog, calls } = loadLogger();
  swLog.info('hello', 'world');
  assert.equal(calls[0][1], '[gplaydl]');
  assert.equal(calls[0][2], 'hello');
  assert.equal(calls[0][3], 'world');
});

test('swLog handles arbitrary arg counts and types', () => {
  const { swLog, calls } = loadLogger();
  swLog.error('e:', new Error('boom'), { meta: 1 }, [1, 2, 3]);
  assert.equal(calls[0][0], 'error');
  assert.equal(calls[0].length, 6); // method, tag, 'e:', Error, obj, array
});
