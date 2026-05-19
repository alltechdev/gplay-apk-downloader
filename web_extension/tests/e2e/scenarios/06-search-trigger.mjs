// e2e: search the Play Store, click Download on the first result, and
// assert that the Direct Download card's Info block populates AND
// `#pkg-input` is filled with the chosen package. Confirms the
// search→download path goes through `triggerDownloadFor`.
import { resolve } from 'node:path';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';

export default async function searchTrigger({ browser, extensionId, shotDir, latestDir }) {
  if (!extensionId) throw new Error('no extensionId');
  const downloadDir = await mkdtemp(resolve(tmpdir(), 'gplaydl-search-'));
  const cdp = await browser.target().createCDPSession();
  await cdp.send('Browser.setDownloadBehavior', { behavior: 'allow', downloadPath: downloadDir });

  const page = await browser.newPage();
  await page.setViewport({ width: 1280, height: 900, deviceScaleFactor: 1 });
  await page.goto(`chrome-extension://${extensionId}/index.html`, { waitUntil: 'networkidle0' });
  await page.waitForSelector('#auth-card');

  // Sign in (only if not already signed in from an earlier scenario).
  const already = await page.$eval('#auth-signout-btn', (el) => el.offsetParent !== null).catch(() => false);
  if (!already) {
    await page.click('#auth-signin-btn');
    await page.waitForFunction(() => {
      const out = document.getElementById('auth-signout-btn');
      const err = !!document.querySelector('#log-scroll .log-icon.err');
      return (out && out.offsetParent !== null) || err;
    }, { timeout: 30000 });
  }

  // Type a query and submit.
  await page.type('#search-q', 'duckduckgo');
  await page.click('#search-btn');

  // Wait until #search-results contains either at least one result row
  // OR a status message. The 'Searching…' loading state has no `.msg`
  // nor `.app-item`, so this fires only when search resolves.
  await page.waitForFunction(
    () => {
      const r = document.getElementById('search-results');
      return !!r && (r.querySelector('.app-item') || r.querySelector('.msg.err') || r.querySelector('.msg.info'));
    },
    { timeout: 30000 },
  );
  const errMsg = await page.$('#search-results .msg.err');
  if (errMsg) {
    const txt = await page.$eval('#search-results .msg.err', (el) => el.textContent);
    throw new Error('search returned error: ' + txt);
  }
  const noResults = await page.$('#search-results .msg.info');
  if (noResults) {
    const txt = await page.$eval('#search-results .msg.info', (el) => el.textContent);
    throw new Error('search returned no results: ' + txt);
  }

  const firstPkg = await page.$eval('#search-results .app-item .pkg', (el) => el.textContent.trim()).catch(() => '');
  await page.screenshot({ path: resolve(shotDir, 'search-1-results.png') });
  await page.screenshot({ path: resolve(latestDir, 'search-1-results.png') });

  // Click the first Download button.
  await page.click('#search-results .app-item button');

  // Assert #pkg-input gets filled and #info-result shows the title in <ok>.
  await page.waitForFunction(
    () => {
      const ok = document.querySelector('#info-result .msg.ok');
      const pkg = document.getElementById('pkg-input')?.value;
      return ok && pkg && pkg.length > 0;
    },
    { timeout: 30000 },
  );

  const pkgInput = await page.$eval('#pkg-input', (el) => el.value);
  const infoText = await page.$eval('#info-result .msg.ok', (el) => el.innerText);
  await page.screenshot({ path: resolve(shotDir, 'search-2-info-populated.png') });
  await page.screenshot({ path: resolve(latestDir, 'search-2-info-populated.png') });

  // Verify the Activity Log auto-opened.
  const logOpen = await page.$eval('#log-panel', (el) => el.classList.contains('open'));

  await page.close();

  if (!pkgInput) throw new Error('expected #pkg-input to be filled after Download click');
  if (!infoText.includes('Play:')) throw new Error('#info-result did not render the details block; got: ' + infoText.slice(0, 200));
  if (!logOpen) throw new Error('Activity Log did not auto-open');

  return { pkgInput, firstPkg, infoSnippet: infoText.slice(0, 160), logOpen };
}
