// Account-independent browser checks: only the server's two account controls.
import assert from 'node:assert/strict';
export default async function accountUi({ browser, extensionId }) {
  const page = await browser.newPage();
  try {
    await page.goto(`chrome-extension://${extensionId}/index.html`);
    await page.waitForFunction(() => document.querySelector('#auth-status').textContent.includes('Google account'));
    assert.equal(await page.$$eval('#auth-card input', (els) => els.length), 0);
    assert.deepEqual(await page.$$eval('#auth-card button', (els) => els.map((el) => el.textContent.trim())),
      ['Sign in with Google', 'Sign out']);
    await page.evaluate(() => chrome.storage.local.set({ 'gplaydl.auth': { authToken: 'legacy-anonymous', gsfId: '123' } }));
    const status = await page.evaluate(() => chrome.runtime.sendMessage({ type: 'auth.status' }));
    assert.equal(status.result.signedIn, false);
    const legacy = await page.evaluate(() => chrome.storage.local.get('gplaydl.auth'));
    assert.equal(legacy['gplaydl.auth'], undefined);
    await page.click('#auth-signin-btn');
    await page.waitForFunction(async () => !!(await chrome.storage.session.get('gplaydl.pendingLogin'))['gplaydl.pendingLogin'], { polling: 100 });
    // Closing Google's window cancels login automatically; no Finish/Cancel UI.
    await page.evaluate(async () => {
      const pending = (await chrome.storage.session.get('gplaydl.pendingLogin'))['gplaydl.pendingLogin'];
      await chrome.tabs.remove(pending.tabId);
    });
    await page.bringToFront();
    await page.waitForFunction(() => document.querySelector('#auth-status').textContent.includes('closed before sign-in'));
    assert.equal(await page.$eval('#auth-signin-btn', (el) => el.disabled), false);
    const pending = await page.evaluate(() => chrome.storage.session.get('gplaydl.pendingLogin'));
    assert.equal(pending['gplaydl.pendingLogin'], undefined);
    const rules = await page.evaluate(() => chrome.declarativeNetRequest.getDynamicRules());
    assert.ok(!JSON.stringify(rules).includes('aurora'));
    return { serverUiParity: true, migration: true, automaticCancellation: true, googleOnlyRules: true };
  } finally { await page.close(); }
}
