import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redact } from '../../scripts/browser-support.mjs';

test('diagnostics redact credentials, account emails and signed URL paths/queries', () => {
  const raw = 'oauth2_4/secret1 aas_et/secret2 Bearer secret3 authToken="secret4" Cookie: secret5 user@example.com https://cdn.gvt1.com/secret6.apk?token=secret7';
  const safe = redact(raw);
  for (let i = 1; i <= 7; i++) assert.ok(!safe.includes('secret' + i));
  assert.ok(!safe.includes('user@example.com'));
  assert.ok(safe.includes('https://cdn.gvt1.com/'));
});

test('diagnostics preserve errors and extension source locations', () => {
  const raw = 'Failed to fetch net::ERR_CONNECTION_RESET at chrome-extension://test/ui/download-handler.js:40';
  assert.equal(redact(raw), raw);
  assert.equal(redact('x'.repeat(10000)).length, 8000);
});
