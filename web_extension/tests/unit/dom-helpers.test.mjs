// Unit tests for the pure helpers in src/ui/dom.js — those that don't
// touch the DOM. (`h()` and `replace()` are exercised by every e2e
// scenario.)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { esc, fmtSize } from '../../src/ui/dom.js';

test('esc: escapes the five HTML-significant characters', () => {
  assert.equal(esc('<script>'), '&lt;script&gt;');
  assert.equal(esc('a & b'), 'a &amp; b');
  assert.equal(esc('he said "hi"'), 'he said &quot;hi&quot;');
  assert.equal(esc("it's"), 'it&#39;s');
});

test('esc: leaves alphanumerics + punctuation alone', () => {
  assert.equal(esc('com.example.app v1.2.3'), 'com.example.app v1.2.3');
});

test('esc: coerces non-strings', () => {
  assert.equal(esc(42), '42');
  assert.equal(esc(null), 'null');
});

test('fmtSize: zero / nullish renders as ?', () => {
  assert.equal(fmtSize(0), '?');
  assert.equal(fmtSize(null), '?');
  assert.equal(fmtSize(undefined), '?');
});

test('fmtSize: bytes', () => {
  assert.equal(fmtSize(1), '1.00 B');
  assert.equal(fmtSize(512), '512 B');
  assert.equal(fmtSize(1023), '1023 B');
});

test('fmtSize: kilobytes', () => {
  assert.equal(fmtSize(1024), '1.00 KB');
  assert.equal(fmtSize(1536), '1.50 KB');
});

test('fmtSize: megabytes / gigabytes', () => {
  assert.equal(fmtSize(1024 * 1024), '1.00 MB');
  assert.equal(fmtSize(1024 * 1024 * 1024), '1.00 GB');
});
