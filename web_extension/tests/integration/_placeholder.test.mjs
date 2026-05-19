// Placeholder integration test. Real network tests land here.
// Skipped if NO_NETWORK=1 is set.
import { test } from 'node:test';
import assert from 'node:assert/strict';

test('placeholder: network stage wired', { skip: process.env.NO_NETWORK === '1' }, () => {
  assert.ok(typeof fetch === 'function', 'global fetch should exist in node 24');
});
