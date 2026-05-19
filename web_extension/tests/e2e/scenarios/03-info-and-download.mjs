// e2e: sign in, look up a real Play Store package, click Download,
// confirm chrome.downloads.download() actually creates download items.
// Uses com.duckduckgo.mobile.android — small, free, split APK,
// available globally. Each test gets its own temp profile so downloads
// don't pollute the user's real disk.
import { resolve } from 'node:path';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';

const TEST_PKG = 'com.duckduckgo.mobile.android';

export default async function infoAndDownload({ browser, extensionId, shotDir, latestDir }) {
  if (!extensionId) throw new Error('no extensionId');
  const downloadDir = await mkdtemp(resolve(tmpdir(), 'gplaydl-e2e-'));
  const cdp = await browser.target().createCDPSession();
  await cdp.send('Browser.setDownloadBehavior', {
    behavior: 'allow',
    downloadPath: downloadDir,
  });

  const page = await browser.newPage();
  await page.setViewport({ width: 800, height: 1100, deviceScaleFactor: 1 });
  const consoleMsgs = [];
  page.on('console', (m) => consoleMsgs.push(`${m.type()}:${m.text()}`));
  page.on('pageerror', (e) => consoleMsgs.push(`pageerror:${e.message}`));

  await page.goto(`chrome-extension://${extensionId}/index.html`, { waitUntil: 'networkidle0' });
  await page.waitForSelector('#auth-card');

  // If a prior scenario already signed in, skip sign-in.
  const alreadySignedIn = await page.$eval('#auth-signout-btn', (el) => el.offsetParent !== null).catch(() => false);
  if (!alreadySignedIn) {
    await page.waitForSelector('#auth-signin-btn', { visible: true });
    await page.click('#auth-signin-btn');
    await page.waitForFunction(
      () => {
        const out = document.getElementById('auth-signout-btn');
        const errored = !!document.querySelector('#log-scroll .log-icon.err');
        return (out && out.offsetParent !== null) || errored;
      },
      { timeout: 30000 },
    );
  }
  const signedIn = await page.$eval('#auth-signout-btn', (el) => el.offsetParent !== null).catch(() => false);
  if (!signedIn) {
    const logs = await page.$$eval('#log-scroll .log-entry', (els) => els.map((e) => e.textContent.trim()));
    throw new Error('sign-in failed: ' + JSON.stringify(logs.slice(-5)));
  }
  await page.screenshot({ path: resolve(shotDir, 'flow-1-signed-in.png') });
  await page.screenshot({ path: resolve(latestDir, 'flow-1-signed-in.png') });

  // Info lookup.
  await page.type('#pkg-input', TEST_PKG);
  await page.click('#info-btn');
  await page.waitForSelector('#info-result .msg.ok, #info-result .msg.err', { timeout: 30000 });
  const infoOk = await page.$('#info-result .msg.ok') !== null;
  if (!infoOk) {
    const errText = await page.$eval('#info-result', (el) => el.textContent).catch(() => '');
    throw new Error('info lookup failed: ' + errText);
  }
  const infoText = await page.$eval('#info-result .msg', (el) => el.innerText);
  await page.screenshot({ path: resolve(shotDir, 'flow-2-info.png') });
  await page.screenshot({ path: resolve(latestDir, 'flow-2-info.png') });

  // Track chrome.downloads via the SW.
  // Instrument the page to count download.event broadcasts.
  await page.evaluate(() => {
    window.__downloadEvents = [];
    chrome.runtime.onMessage.addListener((msg) => {
      if (msg?.type === 'download.event') window.__downloadEvents.push(msg.payload);
    });
  });

  // Click Download.
  await page.click('#download-btn');

  // Wait for the SW to broadcast queue events.
  await page.waitForFunction(
    () => (window.__downloadEvents || []).some((p) => p.phase === 'queued'),
    { timeout: 60000 },
  );

  // Give the SW a moment to queue all splits.
  await new Promise((r) => setTimeout(r, 2000));

  // Wait until chrome.downloads reports at least one complete file. The
  // base APK is ~100MB and may not finish before the test budget over
  // Termux Wi-Fi; a single complete split is enough proof that the full
  // auth → details → purchase → delivery → CDN download chain works.
  await page.evaluate(() => { window.__dlState = {}; });
  const t0 = Date.now();
  let dlReport;
  while (Date.now() - t0 < 120000) {
    dlReport = await page.evaluate(async () => {
      return new Promise((resolve) => {
        chrome.downloads.search({}, (items) => {
          resolve(items.map((i) => ({ id: i.id, filename: i.filename, state: i.state, bytesReceived: i.bytesReceived, totalBytes: i.totalBytes })));
        });
      });
    });
    const completeCount = dlReport.filter((d) => d.state === 'complete').length;
    if (completeCount >= 1) break;
    await new Promise((r) => setTimeout(r, 2000));
  }

  const events = await page.evaluate(() => window.__downloadEvents || []);
  const queued = events.filter((e) => e.phase === 'queued');
  await page.screenshot({ path: resolve(shotDir, 'flow-3-downloading.png') });
  await page.screenshot({ path: resolve(latestDir, 'flow-3-downloading.png') });

  // Open log panel for the final shot.
  await page.click('#log-header');
  await new Promise((r) => setTimeout(r, 400));
  await page.screenshot({ path: resolve(shotDir, 'flow-4-log.png') });
  await page.screenshot({ path: resolve(latestDir, 'flow-4-log.png') });

  await page.close();

  if (queued.length < 1) throw new Error('expected ≥1 queued download, got 0. events=' + JSON.stringify(events));
  const completed = (dlReport || []).filter((d) => d.state === 'complete');
  const inProgress = (dlReport || []).filter((d) => d.state === 'in_progress' && d.bytesReceived > 0);
  if (completed.length < 1 && inProgress.length < 1) {
    throw new Error('expected ≥1 completed (or in-progress) download within 120s, got 0. report=' + JSON.stringify(dlReport));
  }
  return {
    infoSnippet: infoText.slice(0, 200),
    queuedFiles: queued.map((q) => q.file),
    completedFiles: completed.map((c) => ({ filename: c.filename.split('/').pop(), bytes: c.bytesReceived })),
    downloadDir,
  };
}
