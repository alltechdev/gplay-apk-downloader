import assert from 'node:assert/strict';

export default async function searchDetails({ browser, extensionId }) {
  const page = await browser.newPage();
  try {
    await page.goto(`chrome-extension://${extensionId}/index.html`);
    await page.evaluate(() => {
      const original = chrome.runtime.sendMessage.bind(chrome.runtime);
      window.__requests = [];
      chrome.runtime.sendMessage = async (m) => {
        window.__requests.push(m);
        if (m.type === 'app.search') {
          if (m.payload.query === 'error') return { error: 'Search test failure' };
          return { result: { results: m.payload.query === 'empty' ? [] : [{ package: 'com.test.search', title: '<b>Test app</b>' }] } };
        }
        if (m.type === 'app.details') return { result: { ...m.payload, title: 'Test app', versionCode: 123, versionString: '1.2.3', installationSize: 100, splitId: ['config.arm64_v8a'] } };
        if (m.type === 'app.prepareInstall') return { error: 'Test delivery failure' };
        return original(m);
      };
    });
    async function search(query) {
      await page.$eval('#search-q', (el, q) => { el.value = q; }, query);
      await page.click('#search-btn');
    }
    await search('empty');
    await page.waitForFunction(() => document.querySelector('#search-results').textContent.includes('No results found'));
    await search('error');
    await page.waitForFunction(() => document.querySelector('#search-results').textContent.includes('Search test failure'));
    await search('test');
    await page.waitForSelector('#search-results .app-item');
    assert.equal(await page.$$eval('#search-results h3 b', (els) => els.length), 0);
    await page.click('#search-results .app-item button');
    await page.waitForFunction(() => document.querySelector('#log-scroll').textContent.includes('Test delivery failure'));
    assert.equal(await page.$eval('#pkg-input', (el) => el.value), 'com.test.search');
    await page.click('#info-btn');
    await page.waitForSelector('#info-result .msg.ok');
    assert.match(await page.$eval('#info-result', (el) => el.textContent), /Test app.*v1.2.3/);
    const cache = await page.evaluate(async () => {
      const { getDetailsCached } = await import('./ui/info-card.js');
      window.__requests = [];
      await getDetailsCached('com.test.search');
      await getDetailsCached('com.test.search');
      const cached = window.__requests.filter((r) => r.type === 'app.details').length;
      document.querySelector('#arch-select').value = 'armeabi-v7a';
      const changed = await getDetailsCached('com.test.search');
      await getDetailsCached('com.test.search');
      return { cached, changed: changed.arch, fetched: window.__requests.filter((r) => r.type === 'app.details').length };
    });
    assert.deepEqual(cache, { cached: 0, changed: 'armeabi-v7a', fetched: 1 });
    return { emptySearch: true, failedSearch: true, resultEscaping: true, searchDownloadHandoff: true, architectureCache: true };
  } finally { await page.close(); }
}
