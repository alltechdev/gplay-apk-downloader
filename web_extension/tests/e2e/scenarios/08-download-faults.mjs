// Real Chromium fetch/body handling with deterministic CDN responses. No account needed.
import assert from 'node:assert/strict';

export default async function downloadFaults({ browser, extensionId }) {
  const page = await browser.newPage();
  const counts = new Map();
  let mode = 'success';
  await page.setRequestInterception(true);
  page.on('request', async (req) => {
    if (!req.url().startsWith('https://test.gvt1.com/')) return req.continue();
    const name = new URL(req.url()).pathname;
    const attempt = (counts.get(name) || 0) + 1;
    counts.set(name, attempt);
    const headers = { 'access-control-allow-origin': '*' };
    if (mode === 'network' || (mode === 'recover-network' && attempt === 1)) return req.abort('connectionreset');
    if (mode === 'forbidden') return req.respond({ status: 403, headers, body: 'denied' });
    if ((mode === 'recover-503' || mode === 'recover-429') && attempt === 1) return req.respond({ status: mode === 'recover-503' ? 503 : 429, headers, body: 'retry' });
    if (mode === 'short' || (mode === 'recover-short' && attempt === 1)) return req.respond({ status: 200, headers, body: 'x' });
    if (mode === 'parallel' && name === '/base.apk') return req.respond({ status: 403, headers, body: 'denied' });
    if (mode === 'parallel') await new Promise((r) => setTimeout(r, 300));
    await req.respond({ status: 200, headers, body: 'APK!' });
  });
  const checks = [];
  try {
    await page.goto(`chrome-extension://${extensionId}/index.html`);
    await page.evaluate(() => {
      const original = chrome.runtime.sendMessage.bind(chrome.runtime);
      chrome.runtime.sendMessage = async (message) => {
        if (message.type === 'app.prepareInstall') return { result: {
          versionCode: 42, ruleIds: [999], files: ['base.apk', 'config.test.apk'].map((name) => ({ name, size: 4, url: 'https://test.gvt1.com/' + name })),
        } };
        if (message.type === 'app.releaseRules') { window.__released++; return { result: true }; }
        return original(message);
      };
    });
    for (const scenario of ['success', 'recover-network', 'recover-503', 'recover-429', 'recover-short', 'forbidden', 'network', 'short', 'parallel']) {
      mode = scenario;
      counts.clear();
      const result = await page.evaluate(async () => {
        window.__released = 0;
        const { fetchSplits } = await import('./ui/download-handler.js');
        const details = { versionCode: 1, arch: 'arm64' };
        try {
          const files = await fetchSplits('com.test.app', details);
          return { sizes: files.map((f) => f.blob.size), released: window.__released, versionCode: details.versionCode };
        } catch (err) { return { error: err.message, released: window.__released }; }
      });
      assert.equal(result.released, 1, scenario + ' must release temporary rules');
      if (scenario === 'success' || scenario.startsWith('recover-')) {
        assert.deepEqual(result.sizes, [4, 4]);
        assert.equal(result.versionCode, 42);
        assert.equal(counts.get('/base.apk'), scenario === 'success' ? 1 : 2);
      } else {
        assert.match(result.error, /CDN download .* failed:/);
        assert.equal(counts.get('/base.apk'), scenario === 'network' || scenario === 'short' ? 3 : 1);
      }
      if (scenario === 'parallel') {
        assert.ok(await page.evaluate(() => document.querySelector('#log-scroll').textContent.includes('Fetched config.test.apk')), 'Other active transfer must finish before returning failure');
      }
      checks.push(scenario);
    }
    mode = 'success';
    const install = await page.evaluate(async () => {
      const { installToDevice } = await import('./ui/install-handler.js');
      let sizes;
      window.gplaydlAdb = { connected: true, installSplit: async (files) => { sizes = files.map((f) => f.blob.size); } };
      await installToDevice('com.test.app', { versionCode: 42, title: 'Fixture', versionString: '1', arch: 'arm64' });
      window.gplaydlAdb.installSplit = async () => { throw new Error('INSTALL_FAILED_TEST'); };
      let error;
      try { await installToDevice('com.test.app', { versionCode: 42 }); } catch (e) { error = e.message; }
      return { sizes, error };
    });
    assert.deepEqual(install.sizes, [4, 4]);
    assert.equal(install.error, 'INSTALL_FAILED_TEST');
    return { checks, simulatedAdb: ['split forwarding', 'install failure propagation'], liveGooglePlay: false };
  } finally { await page.close(); }
}
