// Unit tests for src/ui/analytics.js — Umami beacon payload shape.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const srcPath = resolve(__dirname, '..', '..', 'src', 'ui', 'analytics.js');

function loadAnalytics({ fetchImpl }) {
  const raw = readFileSync(srcPath, 'utf8')
    .replace(/^export\s+(async\s+)?function\s+/gm, (m, a) => (a ? 'async function ' : 'function '))
    + `\nObject.assign(globalThis, { trackPageview, trackEvent });`;
  const ctx = vm.createContext({
    fetch: fetchImpl,
    navigator: { language: 'en-US' },
    screen: { width: 1920, height: 1080 },
    document: { title: 'GPlay APK Downloader' },
    JSON, Object,
  });
  vm.runInContext(raw, ctx);
  return { trackPageview: ctx.trackPageview, trackEvent: ctx.trackEvent };
}

test('trackPageview: POSTs to stats.dietdroid.com with extension website-id', async () => {
  let captured;
  const fetchImpl = async (url, opts) => { captured = { url, opts }; return { ok: true }; };
  const { trackPageview } = loadAnalytics({ fetchImpl });
  await trackPageview();
  assert.equal(captured.url, 'https://stats.dietdroid.com/api/send');
  assert.equal(captured.opts.method, 'POST');
  const body = JSON.parse(captured.opts.body);
  assert.equal(body.type, 'event');
  assert.equal(body.payload.hostname, 'extension.gplaydl');
  assert.equal(body.payload.url, 'https://extension.gplaydl/');
  assert.equal(body.payload.website, '9875f721-0411-4cbd-9702-87e6bb8be189');
  assert.equal(body.payload.language, 'en-US');
  assert.equal(body.payload.screen, '1920x1080');
  assert.equal(body.payload.name, undefined, 'plain pageview, no event name');
});

test('trackEvent: includes event name and data', async () => {
  let captured;
  const fetchImpl = async (url, opts) => { captured = JSON.parse(opts.body); return { ok: true }; };
  const { trackEvent } = loadAnalytics({ fetchImpl });
  await trackEvent('download-clicked', { pkg: 'com.example.app' });
  assert.equal(captured.payload.name, 'download-clicked');
  assert.deepEqual(captured.payload.data, { pkg: 'com.example.app' });
  assert.equal(captured.payload.hostname, 'extension.gplaydl');
});

test('analytics swallows fetch errors silently', async () => {
  const fetchImpl = async () => { throw new Error('network down'); };
  const { trackPageview } = loadAnalytics({ fetchImpl });
  await assert.doesNotReject(() => trackPageview());
});
