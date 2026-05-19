// Unit tests for src/sw/80-search.js — Play Store HTML scrape.
// Critical: a Play layout change silently empties results. Locks each
// of the three extraction paths (featured / related / JSON-embedded)
// plus input validation.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadSw } from '../helpers/sw-load.mjs';

function makeResponse(html, { ok = true, status = 200, redirectedTo = null } = {}) {
  return {
    ok,
    status,
    url: redirectedTo || 'https://play.google.com/store/search',
    text: async () => html,
  };
}

function loadSearch({ html, ok = true, status = 200, redirectedTo = null } = {}) {
  const fetchImpl = async () => makeResponse(html ?? '', { ok, status, redirectedTo });
  return loadSw(
    ['00-config.js', '05-logger.js', '10-utils.js', '15-errors.js', '80-search.js'],
    ['appSearch', 'ValidationError', 'NetworkError', 'PlayApiError'],
    { fetch: fetchImpl },
  );
}

test('appSearch: rejects empty / non-string / oversized queries', async () => {
  const { appSearch } = loadSearch();
  await assert.rejects(appSearch({ query: '' }),         /query required/);
  await assert.rejects(appSearch({ query: '   ' }),      /query required/);
  await assert.rejects(appSearch({ query: null }),       /query required/);
  await assert.rejects(appSearch({ query: 42 }),         /query required/);
  await assert.rejects(appSearch({ query: 'x'.repeat(201) }), /query too long/);
});

test('appSearch: raises NetworkError on non-2xx', async () => {
  const { appSearch } = loadSearch({ ok: false, status: 503 });
  await assert.rejects(appSearch({ query: 'firefox' }), /Play search HTTP 503/);
});

test('appSearch: raises PlayApiError when redirected to sign-in', async () => {
  const { appSearch } = loadSearch({
    redirectedTo: 'https://accounts.google.com/ServiceLogin?continue=…',
  });
  await assert.rejects(appSearch({ query: 'firefox' }), /redirected to sign-in/);
});

test('appSearch: extracts the featured-app result (vWM94c class)', async () => {
  const html = `
    <a href="/store/apps/details?id=org.mozilla.firefox" class="something">
      <img alt="Firefox" src="https://play-lh.googleusercontent.com/abc=s64-rw">
      <div class="vWM94c">Firefox: Private &amp; Safe Browser</div>
    </a>
  `;
  const { appSearch } = loadSearch({ html });
  const { results } = await appSearch({ query: 'firefox' });
  assert.equal(results.length, 1);
  assert.equal(results[0].package, 'org.mozilla.firefox');
  assert.equal(results[0].title, 'Firefox: Private & Safe Browser');
  assert.match(results[0].icon, /=s128/, 'icon size should be upgraded to s128');
});

test('appSearch: caps results at 5 even when more matches exist', async () => {
  let html = '';
  for (let i = 0; i < 8; i++) {
    html += `
      <a href="/store/apps/details?id=com.example.app${i}">
        <img src="https://play-lh.googleusercontent.com/icon${i}=s48-rw">
        <div class="Epkrse ">App ${i}</div>
      </a>
    `;
  }
  const { appSearch } = loadSearch({ html });
  const { results } = await appSearch({ query: 'apps' });
  assert.equal(results.length, 5);
});

test('appSearch: deduplicates packages that appear in both featured + related', async () => {
  const html = `
    <a href="/store/apps/details?id=org.mozilla.firefox" class="x">
      <img src="https://play-lh.googleusercontent.com/dup=s64-rw">
      <div class="vWM94c">Firefox</div>
    </a>
    <a href="/store/apps/details?id=org.mozilla.firefox">
      <img src="https://play-lh.googleusercontent.com/dup=s48-rw">
      <div class="Epkrse ">Firefox (related)</div>
    </a>
  `;
  const { appSearch } = loadSearch({ html });
  const { results } = await appSearch({ query: 'firefox' });
  assert.equal(results.length, 1, 'duplicate package should be filtered');
  assert.equal(results[0].title, 'Firefox');
});

test('appSearch: falls back to JSON-embedded packages when HTML extraction is empty', async () => {
  // Synthesise the minimal JSON shape the third extractor matches.
  const html = `
    foo
    [["com.duckduckgo.mobile.android",7],[null,2,null,[null,null,"https://play-lh.googleusercontent.com/dgicon=s48-rw"]],bar
    [["com.duckduckgo.mobile.android",7],"DuckDuckGo Browser",["1.0", 100
  `;
  const { appSearch } = loadSearch({ html });
  const { results } = await appSearch({ query: 'duckduckgo' });
  assert.equal(results.length, 1);
  assert.equal(results[0].package, 'com.duckduckgo.mobile.android');
  assert.equal(results[0].title, 'DuckDuckGo Browser');
  assert.match(results[0].icon, /=s128/);
});

test('appSearch: returns an empty array when no scraper matches', async () => {
  const { appSearch } = loadSearch({ html: '<html>no apps here</html>' });
  const { results } = await appSearch({ query: 'nothing' });
  assert.equal(results.length, 0);
});

test('appSearch: HTML-entity decode covers &amp; / &#39; / &quot;', async () => {
  const html = `
    <a href="/store/apps/details?id=com.example.amp">
      <img src="https://play-lh.googleusercontent.com/a=s64-rw">
      <div class="vWM94c">A &amp; B &#39;C&#39; &quot;D&quot;</div>
    </a>
  `;
  const { appSearch } = loadSearch({ html });
  const { results } = await appSearch({ query: 'q' });
  assert.equal(results[0].title, "A & B 'C' \"D\"");
});
