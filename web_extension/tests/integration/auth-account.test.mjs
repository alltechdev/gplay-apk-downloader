import { test } from 'node:test';
import assert from 'node:assert/strict';
import { accountTestSkip, personalAccountSession } from '../helpers/personal-account.mjs';

test('Google personal account registers a device and creates a Play session', { skip: accountTestSkip, timeout: 180000 }, async () => {
  const auth = await personalAccountSession();
  assert.equal(auth.accountType, 'personal');
  assert.ok(auth.authToken);
  assert.match(auth.gsfId, /^[a-f0-9]+$/);
});
