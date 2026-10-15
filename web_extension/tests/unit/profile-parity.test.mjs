import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

test('bundled profiles and selection policy match device_profiles.py on main', () => {
  const server = JSON.parse(execFileSync('python3', [fileURLToPath(new URL('../../scripts/export-profiles.py', import.meta.url)), '--stdout'], { encoding: 'utf8' }));
  const bundled = JSON.parse(readFileSync(new URL('../../src/profiles.json', import.meta.url)));
  assert.deepEqual(bundled, server);
  assert.equal(bundled.personalDefaults['arm64-v8a'], 'Pv');
  assert.equal(bundled.personalDefaults['armeabi-v7a'], 'Gj');
});
