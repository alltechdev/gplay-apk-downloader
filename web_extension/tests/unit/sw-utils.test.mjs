// Unit tests for the pure helpers in src/sw/10-utils.js +
// validation-driven throws that come from src/sw/15-errors.js.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadSw } from '../helpers/sw-load.mjs';

const { validatePackageName, sanitizeFilenameSegment, ValidationError, ProtoError } = loadSw(
  ['00-config.js', '05-logger.js', '10-utils.js', '15-errors.js'],
  ['validatePackageName', 'sanitizeFilenameSegment', 'ValidationError', 'ProtoError'],
);

test('validatePackageName: accepts well-formed package names', () => {
  for (const n of ['com.example.app', 'a.b', 'org.mozilla.firefox', 'com.example.foo_bar.baz1']) {
    assert.equal(validatePackageName(n), n, n);
  }
});

test('validatePackageName: rejects malformed inputs', () => {
  const bads = ['', 'com', '.com.example', 'com..example', '1com.example', 'com.1example',
                'com.example/etc', 'com.example app', null, undefined, 123, {}];
  for (const n of bads) {
    assert.throws(() => validatePackageName(n), /\b(invalid package name|must be a string)\b/i, `${JSON.stringify(n)} should be rejected`);
  }
});

test('validatePackageName: throws ValidationError', () => {
  try { validatePackageName('bad'); }
  catch (e) { assert.equal(e.code, 'VALIDATION'); assert.equal(e.name, 'ValidationError'); return; }
  assert.fail('did not throw');
});

test('sanitizeFilenameSegment: keeps safe chars', () => {
  assert.equal(sanitizeFilenameSegment('com.example.app-1.2_beta'), 'com.example.app-1.2_beta');
});

test('sanitizeFilenameSegment: replaces unsafe chars with _', () => {
  assert.equal(sanitizeFilenameSegment('a/b\\c:d*e?'), 'a_b_c_d_e_');
  assert.equal(sanitizeFilenameSegment('  hello world  '), '__hello_world__');
});

test('sanitizeFilenameSegment: truncates to 200 chars', () => {
  const long = 'a'.repeat(500);
  const out = sanitizeFilenameSegment(long);
  assert.equal(out.length, 200);
});

test('sanitizeFilenameSegment: coerces non-strings', () => {
  assert.equal(sanitizeFilenameSegment(42), '42');
});

test('ProtoError is a proper subclass with code', () => {
  const e = new ProtoError('test');
  assert.equal(e.name, 'ProtoError');
  assert.equal(e.code, 'PROTO');
  assert.equal(typeof e.message, 'string');
  assert.equal(typeof e.stack, 'string');
});
