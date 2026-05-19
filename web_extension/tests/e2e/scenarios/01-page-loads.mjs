// Loads chrome-extension://<id>/index.html and asserts that the page
// renders with the legacy site's visual identity (header, log panel,
// footer) and that the Activity Log records the page-load event.
import { resolve } from 'node:path';

export default async function pageLoads({ browser, extensionId, shotDir, latestDir }) {
  if (!extensionId) throw new Error('no extensionId');
  const page = await browser.newPage();
  await page.setViewport({ width: 760, height: 720, deviceScaleFactor: 1 });
  const consoleMsgs = [];
  page.on('console', (m) => consoleMsgs.push(`${m.type()}:${m.text()}`));
  page.on('pageerror', (e) => consoleMsgs.push(`pageerror:${e.message}`));

  await page.goto(`chrome-extension://${extensionId}/index.html`, { waitUntil: 'networkidle0' });
  await page.waitForSelector('header h1');
  await page.waitForFunction(
    () => document.querySelector('#log-badge')?.textContent === '1',
    { timeout: 3000 },
  );

  const h1 = await page.$eval('header h1', (el) => el.textContent.trim());
  const hasFooter = await page.$('footer.footer') !== null;
  const hasLog = await page.$('#log-panel') !== null;
  const hasSearchInput = await page.$('#search-q') !== null;
  const hasAuthCard = await page.$('#auth-card') !== null;
  const hasDownloadCard = await page.$('#download-card') !== null;
  const hasAdbCard = await page.$('#adb-card') !== null;
  const hasBackupCard = await page.$('#backup-card') !== null;
  const logBadge = await page.$eval('#log-badge', (el) => el.textContent);
  const adbBundleLoaded = await page.evaluate(() => typeof window.gplaydlAdb === 'object' && window.gplaydlAdb !== null);

  await page.screenshot({ path: resolve(shotDir, 'page-1-collapsed.png'), fullPage: false });
  await page.screenshot({ path: resolve(latestDir, 'page-1-collapsed.png'), fullPage: false });
  await page.screenshot({ path: resolve(shotDir, 'page-2-full.png'), fullPage: true });
  await page.screenshot({ path: resolve(latestDir, 'page-2-full.png'), fullPage: true });

  await page.click('#log-header');
  await new Promise((r) => setTimeout(r, 400)); // wait for CSS max-height transition
  await page.screenshot({ path: resolve(shotDir, 'page-3-log-open.png'), fullPage: false });
  await page.screenshot({ path: resolve(latestDir, 'page-3-log-open.png'), fullPage: false });

  await page.close();

  if (h1 !== 'GPlay APK Downloader') throw new Error(`h1 mismatch: "${h1}"`);
  if (!hasFooter) throw new Error('footer missing');
  if (!hasLog) throw new Error('log panel missing');
  if (hasSearchInput) throw new Error('search input present — must be removed (no catalog policy)');
  if (!hasAuthCard) throw new Error('auth card missing');
  if (!hasDownloadCard) throw new Error('download card missing');
  if (!hasAdbCard) throw new Error('adb card missing');
  if (!hasBackupCard) throw new Error('backup card missing');
  if (!adbBundleLoaded) throw new Error('window.gplaydlAdb missing — adb bundle did not load');
  if (logBadge !== '1') throw new Error(`expected log badge "1", got "${logBadge}"`);

  return { h1, logBadge, console: consoleMsgs, adbBundleLoaded };
}
