// e2e: write a small backup JSON, import it via the page's file input,
// click "Download all selected", confirm sequential downloads kick off.
// Uses small free packages; cancels chrome.downloads after queuing so the
// test stays bounded.
import { resolve } from 'node:path';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';

export default async function backupRestore({ browser, extensionId, shotDir, latestDir }) {
  if (!extensionId) throw new Error('no extensionId');
  const tmp = await mkdtemp(resolve(tmpdir(), 'gplaydl-bk-'));
  const downloadDir = resolve(tmp, 'downloads');
  await writeFile(resolve(tmp, 'list.json'), JSON.stringify({
    device: 'test-device',
    android: '15',
    date: new Date().toISOString(),
    packages: [
      { package: 'com.duckduckgo.mobile.android', available: true },
    ],
  }));

  const cdp = await browser.target().createCDPSession();
  await cdp.send('Browser.setDownloadBehavior', { behavior: 'allow', downloadPath: downloadDir });

  const page = await browser.newPage();
  await page.setViewport({ width: 800, height: 1100, deviceScaleFactor: 1 });
  await page.goto(`chrome-extension://${extensionId}/index.html`, { waitUntil: 'networkidle0' });
  await page.waitForSelector('#auth-card');

  // Sign in if not already.
  const alreadySignedIn = await page.$eval('#auth-signout-btn', (el) => el.offsetParent !== null).catch(() => false);
  if (!alreadySignedIn) {
    await page.click('#auth-signin-btn');
    await page.waitForFunction(() => {
      const out = document.getElementById('auth-signout-btn');
      const errored = !!document.querySelector('#log-scroll .log-icon.err');
      return (out && out.offsetParent !== null) || errored;
    }, { timeout: 30000 });
  }

  // Upload the backup list.
  const fileInput = await page.$('#backup-import');
  await fileInput.uploadFile(resolve(tmp, 'list.json'));

  await page.waitForSelector('#backup-restore-btn', { timeout: 5000 });
  await page.screenshot({ path: resolve(shotDir, 'backup-1-imported.png') });
  await page.screenshot({ path: resolve(latestDir, 'backup-1-imported.png') });

  // Track download events from the SW so we can assert the bulk run kicked off.
  await page.evaluate(() => {
    window.__bulkEvents = [];
    chrome.runtime.onMessage.addListener((msg) => {
      if (msg?.type === 'download.event') window.__bulkEvents.push(msg.payload);
    });
  });

  await page.click('#backup-restore-btn');

  // Wait for at least one list.start + one queued event.
  await page.waitForFunction(
    () => (window.__bulkEvents || []).some((p) => p.phase === 'list.start') &&
          (window.__bulkEvents || []).some((p) => p.phase === 'queued'),
    { timeout: 60000 },
  );

  // Give the SW a couple seconds to queue everything for the single package.
  await new Promise((r) => setTimeout(r, 3000));
  const events = await page.evaluate(() => window.__bulkEvents || []);
  await page.screenshot({ path: resolve(shotDir, 'backup-2-running.png') });
  await page.screenshot({ path: resolve(latestDir, 'backup-2-running.png') });
  await page.click('#log-header');
  await new Promise((r) => setTimeout(r, 400));
  await page.screenshot({ path: resolve(shotDir, 'backup-3-log.png') });
  await page.screenshot({ path: resolve(latestDir, 'backup-3-log.png') });

  await page.close();

  const queued = events.filter((e) => e.phase === 'queued').length;
  const listStart = events.filter((e) => e.phase === 'list.start').length;
  if (listStart < 1) throw new Error('expected ≥1 list.start, got 0');
  if (queued < 1) throw new Error('expected ≥1 queued file, got 0');
  return { listStart, queued, downloadDir };
}
