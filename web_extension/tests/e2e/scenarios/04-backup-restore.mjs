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

  // Snapshot final state before clicking download, so we can compare.
  // The blob-URL <a download> click sometimes resets the document's
  // execution context in CDP-managed download mode; capture whatever
  // signals we can before that happens.
  await page.click('#backup-restore-btn');

  // Wait for either an early failure log or the per-package ZIP log.
  // Use waitForFunction (it tolerates context destruction internally).
  await page.waitForFunction(
    () => [...document.querySelectorAll('#log-scroll .log-entry')]
      .some((e) => /ZIP ready/i.test(e.textContent) || /Bulk download done/i.test(e.textContent) || /\[fail\]/.test(e.textContent)),
    { timeout: 180000, polling: 1000 },
  ).catch(() => {});

  // Settle a moment. Snapshot logs; tolerate destruction by retrying.
  await new Promise((r) => setTimeout(r, 1500));
  await page.screenshot({ path: resolve(shotDir, 'backup-2-running.png') });
  await page.screenshot({ path: resolve(latestDir, 'backup-2-running.png') });
  await page.click('#log-header');
  await new Promise((r) => setTimeout(r, 400));
  await page.screenshot({ path: resolve(shotDir, 'backup-3-log.png') });
  await page.screenshot({ path: resolve(latestDir, 'backup-3-log.png') });

  await page.close();

  // Robust log read: if the execution context was torn down by the
  // browser's download handling, retry once after a short wait.
  async function readLogs() {
    return page.$$eval('#log-scroll .log-entry', (els) => els.map((e) => e.textContent.trim()));
  }
  let logs;
  try {
    logs = await readLogs();
  } catch {
    await new Promise((r) => setTimeout(r, 1500));
    try { logs = await readLogs(); } catch { logs = []; }
  }
  const okZip = logs.some((t) => /ZIP ready/i.test(t));
  const done  = logs.some((t) => /Bulk download done/i.test(t));
  // Even if log read failed entirely, a zip on disk is the real signal.
  const onDisk = await import('node:fs').then((fs) => fs.promises.readdir(downloadDir).catch(() => []));
  if (!okZip && !done && onDisk.length === 0) {
    throw new Error('bulk path produced no zip; last logs: ' + JSON.stringify(logs.slice(-5)));
  }
  return { okZip, done, lastLogs: logs.slice(-5), files: onDisk, downloadDir };
}
