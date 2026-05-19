// Integration test: hits the real AuroraOSS dispenser from Node and verifies
// we get back an authToken + gsfId for the Pv (Pixel 9a) profile.
// Skipped if NO_NETWORK=1.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SKIP = process.env.NO_NETWORK === '1';

async function loadProfile(key) {
  const path = resolve(__dirname, '..', '..', 'src', 'profiles.json');
  const data = JSON.parse(await readFile(path, 'utf8'));
  const found = data.profiles.find((p) => p.key === key);
  if (!found) throw new Error(`profile ${key} not bundled`);
  return found.profile;
}

test('AuroraOSS dispenser returns a token for Pv profile', { skip: SKIP, timeout: 30000 }, async () => {
  const profile = await loadProfile('Pv');
  const res = await fetch('https://auroraoss.com/api/auth', {
    method: 'POST',
    headers: {
      'User-Agent': 'com.aurora.store-4.6.1-70',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(profile),
  });

  assert.equal(res.status, 200, `dispenser returned ${res.status}`);
  const data = await res.json();
  assert.ok(data.authToken, `no authToken in response: ${JSON.stringify(data).slice(0, 200)}`);
  assert.ok(data.gsfId, `no gsfId in response: ${JSON.stringify(data).slice(0, 200)}`);
  console.log('  authToken length:', data.authToken.length);
  console.log('  gsfId           :', data.gsfId);
  console.log('  email           :', data.email);
});
