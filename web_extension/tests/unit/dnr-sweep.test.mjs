// Unit tests for sweepStaleDownloadRules in src/sw/40-dnr.js.
//
// On SW boot, any per-download DNR rule (id ≥ DNR_DOWNLOAD_ID_MIN) that
// isn't tied to a live `downloadRuleByDl` entry is orphaned from a
// previous SW lifetime and must be cleared. This test exercises that
// classification across the realistic scenarios.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const swDir = resolve(__dirname, '..', '..', 'src', 'sw');

function loadSweep({ existingRules, downloadRuleByDl = new Map() }) {
  const removed = [];
  const chromeStub = {
    runtime: {
      sendMessage: () => Promise.resolve(),
      getURL: (p) => 'chrome-extension://test/' + p,
    },
    storage: {
      session: {
        get: async () => ({}),
        set: async () => {},
      },
    },
    declarativeNetRequest: {
      getDynamicRules: async () => existingRules,
      updateDynamicRules: async ({ removeRuleIds = [] }) => {
        removed.push(...removeRuleIds);
        // Mutate existing rules to mirror Chrome's behavior.
        for (const id of removeRuleIds) {
          const i = existingRules.findIndex((r) => r.id === id);
          if (i >= 0) existingRules.splice(i, 1);
        }
      },
    },
  };

  const ctx = vm.createContext({
    chrome: chromeStub,
    console,
    Set, Map, Array, Object, Promise, Number,
  });

  const files = ['00-config.js', '05-logger.js', '15-errors.js', '30-storage.js', '40-dnr.js'];
  let combined = '';
  for (const f of files) combined += readFileSync(resolve(swDir, f), 'utf8') + '\n';
  // Expose `downloadRuleByDl` and the sweep function on globalThis.
  // Seed the live downloadRuleByDl map (it's a `const` so mutate in place).
  combined += `
    downloadRuleByDl.clear();
    ${[...downloadRuleByDl].map(([k, v]) => `downloadRuleByDl.set(${k}, ${v});`).join('\n')}
    Object.assign(globalThis, { sweepStaleDownloadRules, downloadRuleByDl });
  `;
  vm.runInContext(combined, ctx);
  return { sweep: ctx.sweepStaleDownloadRules, removed, chromeStub };
}

test('sweep: removes orphan rules in the download range', async () => {
  const existing = [
    { id: 1,    condition: {} },     // core rule, skip
    { id: 100,  condition: {} },     // orphan
    { id: 250,  condition: {} },     // orphan
    { id: 9999, condition: {} },     // orphan (max boundary)
  ];
  const { sweep, removed } = loadSweep({ existingRules: existing });
  const n = await sweep();
  assert.equal(n, 3);
  assert.deepEqual(removed.sort((a, b) => a - b), [100, 250, 9999]);
});

test('sweep: keeps rules tied to a live chrome.downloads job', async () => {
  const existing = [
    { id: 100, condition: {} },  // tied to download #42 → keep
    { id: 200, condition: {} },  // orphan
    { id: 300, condition: {} },  // tied to download #43 → keep
  ];
  const liveMap = new Map([[42, 100], [43, 300]]);
  const { sweep, removed } = loadSweep({ existingRules: existing, downloadRuleByDl: liveMap });
  const n = await sweep();
  assert.equal(n, 1);
  assert.deepEqual(removed, [200]);
});

test('sweep: does not touch core rules outside the download range', async () => {
  const existing = [
    { id: 1, condition: {} },  // core dispenser
    { id: 2, condition: {} },  // core fdfe
    { id: 3, condition: {} },  // core cdn
    { id: 4, condition: {} },  // core search
  ];
  const { sweep, removed } = loadSweep({ existingRules: existing });
  const n = await sweep();
  assert.equal(n, 0);
  assert.deepEqual(removed, []);
});

test('sweep: returns 0 when there are no rules', async () => {
  const { sweep, removed } = loadSweep({ existingRules: [] });
  const n = await sweep();
  assert.equal(n, 0);
  assert.deepEqual(removed, []);
});

test('sweep: swallows getDynamicRules errors and returns 0', async () => {
  const removed = [];
  const ctx = vm.createContext({
    chrome: {
      runtime: {
        sendMessage: () => Promise.resolve(),
        getURL: (p) => 'chrome-extension://test/' + p,
      },
      storage: { session: { get: async () => ({}), set: async () => {} } },
      declarativeNetRequest: {
        getDynamicRules: async () => { throw new Error('API unavailable'); },
        updateDynamicRules: async ({ removeRuleIds = [] }) => { removed.push(...removeRuleIds); },
      },
    },
    console, Set, Map, Array, Object, Promise, Number,
  });
  const files = ['00-config.js', '05-logger.js', '15-errors.js', '30-storage.js', '40-dnr.js'];
  let combined = '';
  for (const f of files) combined += readFileSync(resolve(swDir, f), 'utf8') + '\n';
  combined += `;Object.assign(globalThis, { sweepStaleDownloadRules });`;
  vm.runInContext(combined, ctx);
  const n = await ctx.sweepStaleDownloadRules();
  assert.equal(n, 0);
  assert.deepEqual(removed, []);
});
