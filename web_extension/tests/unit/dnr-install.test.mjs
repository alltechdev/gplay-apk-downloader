import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadSw } from '../helpers/sw-load.mjs';

test('overlapping core installations atomically replace IDs and preserve download rules', async () => {
  const rules = new Map([[100, { id: 100, condition: { urlFilter: 'download' } }]]);
  const chrome = {
    runtime: { getURL: (p) => 'chrome-extension://test/' + p },
    declarativeNetRequest: {
      getDynamicRules: async () => [...rules.values()],
      updateDynamicRules: async ({ removeRuleIds, addRules }) => {
        // Delay commits so simultaneous callers all read the same old snapshot.
        await new Promise((resolve) => setImmediate(resolve));
        const next = new Map(rules);
        for (const id of removeRuleIds) next.delete(id);
        for (const rule of addRules) {
          if (next.has(rule.id)) throw new Error(`Rule with id ${rule.id} does not have a unique ID.`);
          next.set(rule.id, rule);
        }
        rules.clear();
        for (const [id, rule] of next) rules.set(id, rule);
      },
    },
  };
  const sw = loadSw(['00-config.js', '40-dnr.js'], ['installCoreDnrRules'], { chrome });
  await Promise.all([sw.installCoreDnrRules(), sw.installCoreDnrRules(), sw.installCoreDnrRules('signed-in-UA')]);
  assert.deepEqual([...rules.keys()].sort((a, b) => a - b), [1, 2, 3, 4, 5, 100]);
  assert.equal(rules.get(100).condition.urlFilter, 'download');
  assert.equal(rules.get(2).action.requestHeaders.find((h) => h.header === 'User-Agent').value, 'signed-in-UA');
  await sw.installCoreDnrRules('refreshed-UA');
  assert.equal(rules.size, 6);
});
