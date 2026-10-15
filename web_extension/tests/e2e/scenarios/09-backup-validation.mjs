import assert from 'node:assert/strict';

export default async function backupValidation({ browser, extensionId }) {
  const page = await browser.newPage();
  try {
    await page.goto(`chrome-extension://${extensionId}/index.html`);
    async function upload(text) {
      await page.evaluate((text) => {
        const input = document.querySelector('#backup-import');
        const transfer = new DataTransfer();
        transfer.items.add(new File([text], 'backup.json', { type: 'application/json' }));
        input.files = transfer.files;
        input.dispatchEvent(new Event('change', { bubbles: true }));
      }, text);
    }
    for (const text of ['not json', '{}', '{"packages":[]}', '{"packages":[{"package":"com.test.app","available":false}]}']) {
      await upload(text);
      await page.waitForFunction(() => document.querySelector('#backup-result .msg.err')?.textContent.includes('Invalid backup file'));
    }
    await upload(JSON.stringify({ packages: [
      { package: 'com.test.one', title: '<img src=x onerror=alert(1)>' },
      { package: 'com.test.two', available: true },
      { package: 'com.test.three', available: false },
    ] }));
    await page.waitForSelector('.backup-check');
    assert.equal(await page.$$eval('.backup-check:checked', (els) => els.length), 2);
    assert.equal(await page.$$eval('.backup-check:disabled', (els) => els.length), 1);
    assert.equal(await page.$$eval('#backup-result img', (els) => els.length), 0);
    await page.evaluate(() => [...document.querySelectorAll('.backup-summary a')].find((el) => el.textContent === 'None').click());
    assert.equal(await page.$$eval('.backup-check:checked', (els) => els.length), 0);
    await page.click('#backup-restore-btn');
    await page.waitForFunction(() => document.querySelector('#log-scroll').textContent.includes('No packages selected'));
    await page.evaluate(() => [...document.querySelectorAll('.backup-summary a')].find((el) => el.textContent === 'Select all').click());
    assert.equal(await page.$$eval('.backup-check:checked', (els) => els.length), 2);
    // Deterministic service failure: verify sequential restore handles each failure and recovers controls.
    await page.evaluate(() => {
      const original = chrome.runtime.sendMessage.bind(chrome.runtime);
      window.__detailRequests = [];
      chrome.runtime.sendMessage = async (m) => {
        if (m.type === 'app.details') { window.__detailRequests.push(m.payload.packageName); return { error: 'Test unavailable' }; }
        return original(m);
      };
    });
    await page.click('#backup-restore-btn');
    await page.waitForFunction(() => document.querySelector('#log-scroll').textContent.includes('Bulk download done: 0 ok, 2 failed'));
    assert.deepEqual(await page.evaluate(() => window.__detailRequests), ['com.test.one', 'com.test.two']);
    assert.equal(await page.$eval('#backup-restore-btn', (el) => el.disabled), false);
    assert.equal(await page.$('#backup-cancel-btn'), null);
    await page.evaluate(() => {
      const original = chrome.runtime.sendMessage.bind(chrome.runtime);
      window.__detailRequests = [];
      chrome.runtime.sendMessage = async (m) => {
        if (m.type === 'app.details') {
          window.__detailRequests.push(m.payload.packageName);
          return new Promise((resolve) => { window.__finishDetail = () => resolve({ error: 'Test canceled transfer' }); });
        }
        return original(m);
      };
    });
    await page.click('#backup-restore-btn');
    await page.waitForFunction(() => !!window.__finishDetail);
    await page.click('#backup-cancel-btn');
    await page.evaluate(() => window.__finishDetail());
    await page.waitForFunction(() => document.querySelector('#log-scroll').textContent.includes('Bulk download aborted'));
    assert.deepEqual(await page.evaluate(() => window.__detailRequests), ['com.test.one']);
    assert.equal(await page.$eval('#backup-restore-btn', (el) => el.disabled), false);
    return { malformedImports: 4, selection: true, htmlEscaping: true, sequentialFailureRecovery: true, cancellation: true };
  } finally { await page.close(); }
}
