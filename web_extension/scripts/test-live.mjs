// Attach to npm run dev without logging in/out or reading credential storage.
import assert from 'node:assert/strict';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import * as fflate from 'fflate';
import { LOCAL_DIR, LOG_PATH, connectTestBrowser, redact } from './browser-support.mjs';

const smoke = process.argv.includes('--smoke');
const packageIndex = process.argv.indexOf('--package');
const packageName = packageIndex >= 0 ? process.argv[packageIndex + 1] : 'com.whatsapp';
if (!/^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$/.test(packageName || '')) throw new Error('Invalid --package value.');
const { browser, extensionId } = await connectTestBrowser();
const dir = resolve(LOCAL_DIR, 'runs', new Date().toISOString().replace(/[:.]/g, '-'));
await mkdir(dir, { recursive: true, mode: 0o700 });
const report = { startedAt: new Date().toISOString(), packageName: smoke ? null : packageName, checks: [] };
let page;
const downloads = new Map();
const byGuid = new Map();
async function check(name, action) {
  try {
    const details = await action();
    report.checks.push({ name, status: 'passed', details });
    console.log('PASS ' + name);
    return details;
  } catch (error) {
    report.checks.push({ name, status: 'failed', error: redact(error.message) });
    throw error;
  }
}
function expectDownload(name) {
  let timer;
  let done;
  const promise = new Promise((resolveDone, reject) => {
    done = { resolve: resolveDone, reject };
    timer = setTimeout(() => reject(new Error('Download did not finish: ' + name)), 600000);
  });
  downloads.set(name, done);
  return { promise, cleanup: () => { clearTimeout(timer); downloads.delete(name); } };
}
async function saveFromBrowser(name, action) {
  const expected = expectDownload(name);
  try {
    await Promise.all([action(), expected.promise]);
    return resolve(dir, name);
  } finally { expected.cleanup(); }
}
function verifySignatures(path) {
  const out = execFileSync('apksigner', ['verify', '--min-sdk-version', '21', '--verbose', path], { encoding: 'utf8', timeout: 120000, stdio: ['ignore', 'pipe', 'pipe'] });
  for (const scheme of ['v1', 'v2', 'v3']) assert.match(out, new RegExp(`Verified using ${scheme} scheme.*true`, 'i'));
  execFileSync('zipalign', ['-c', '-p', '4', path], { timeout: 120000, stdio: ['ignore', 'pipe', 'pipe'] });
  return { v1: true, v2: true, v3: true, zipAligned: true };
}
try {
  const cdp = await browser.target().createCDPSession();
  await cdp.send('Browser.setDownloadBehavior', { behavior: 'allow', downloadPath: dir, eventsEnabled: true });
  cdp.on('Browser.downloadWillBegin', ({ guid, suggestedFilename }) => {
    if (downloads.has(suggestedFilename)) byGuid.set(guid, downloads.get(suggestedFilename));
  });
  cdp.on('Browser.downloadProgress', ({ guid, state }) => {
    const item = byGuid.get(guid);
    if (!item) return;
    if (state === 'completed') { item.resolve(); byGuid.delete(guid); }
    if (state === 'canceled') { item.reject(new Error('Browser canceled the download')); byGuid.delete(guid); }
  });
  page = await browser.newPage();
  page.setDefaultTimeout(30000);
  await page.goto(`chrome-extension://${extensionId}/index.html`, { waitUntil: 'domcontentloaded' });
  await check('extension UI and bundles', async () => {
    await page.waitForFunction(() => document.querySelector('#auth-status')?.textContent !== 'checking…');
    return page.evaluate(() => {
      if (!window.gplaydlApkTools?.mergeAndSign || !window.gplaydlAdb) throw new Error('Extension bundles did not load');
      if (document.querySelector('#auth-card input')) throw new Error('Unexpected account input fields');
      return { bundlesLoaded: true };
    });
  });
  await check('local Activity Log and error capture', async () => {
    const marker = 'diagnostic-probe-' + Date.now();
    await page.evaluate(async (probe) => {
      const { log } = await import('./ui/log.js');
      log(probe + ' authToken="synthetic-secret"', 'info');
      console.error(probe + ' console error');
      await fetch('http://127.0.0.1:1/' + probe).catch(() => {});
    }, marker);
    let lines = [];
    let networkCaptured = false;
    for (let attempt = 0; attempt < 30; attempt++) {
      const allLines = (await readFile(LOG_PATH, 'utf8')).split('\n');
      networkCaptured = allLines.some((line) => line.includes('network') && line.includes('ERR_UNSAFE_PORT'));
      lines = allLines.filter((line) => line.includes(marker));
      if (lines.some((line) => line.includes('activity')) && lines.some((line) => line.includes('console error')) && networkCaptured) break;
      await new Promise((r) => setTimeout(r, 100));
    }
    assert.ok(lines.some((line) => line.includes('activity')), 'Activity Log was not captured');
    assert.ok(lines.some((line) => line.includes('console error')), 'Console error was not captured');
    assert.ok(!lines.join('').includes('synthetic-secret'), 'Log redaction failed');
    assert.ok(networkCaptured, 'Chrome network failure reason was not captured');
    return { activity: true, errors: true, networkErrors: true, secretsRedacted: true };
  });
  await check('unique DNR rules' , async () => {
    const ids = await page.evaluate(async () => (await chrome.declarativeNetRequest.getDynamicRules()).map((r) => r.id));
    assert.equal(new Set(ids).size, ids.length);
    for (const id of [1, 2, 3, 4, 5]) assert.ok(ids.includes(id));
    return { coreRules: 5 };
  });
  // Runs the shipped browser bundle, not only the unbundled signing source.
  const base = fflate.zipSync({ 'AndroidManifest.xml': new Uint8Array([3, 0, 8, 0, 8, 0, 0, 0]), 'classes.dex': new Uint8Array(4097), 'lib/arm64-v8a/libtest.so': new Uint8Array(1001) }, { level: 0 });
  const split = fflate.zipSync({ 'assets/probe.txt': new TextEncoder().encode('merge probe') }, { level: 0 });
  const signed = await check('browser merge and sign', () => saveFromBrowser('smoke-signed.apk', () => page.evaluate(async (baseBytes, splitBytes) => {
    await window.gplaydlApkTools.mergeAndSign([
      { name: 'base.apk', blob: new Blob([new Uint8Array(baseBytes)]) },
      { name: 'config.test.apk', blob: new Blob([new Uint8Array(splitBytes)]) },
    ], 'smoke-signed.apk');
  }, [...base], [...split])));
  await check('merged content, alignment and v1/v2/v3 signatures', async () => {
    const entries = fflate.unzipSync(new Uint8Array(await readFile(signed)));
    assert.equal(new TextDecoder().decode(entries['assets/probe.txt']), 'merge probe');
    return verifySignatures(signed);
  });
  if (!smoke) {
    const signedIn = await page.evaluate(async () => {
      const res = await chrome.runtime.sendMessage({ type: 'auth.status' });
      if (res.error) throw new Error(res.error);
      return !!res.result?.signedIn; // Never return account email, IDs or credentials.
    });
    if (!signedIn) {
      report.checks.push({ name: 'live Google Play flow', status: 'blocked', reason: 'Sign in with Google in the test browser, then rerun.' });
      process.exitCode = 2;
      console.log('BLOCKED: sign in with Google in the test browser, then rerun.');
    } else {
      await check('Play search', async () => {
        const result = await page.evaluate(async () => {
          const r = await chrome.runtime.sendMessage({ type: 'app.search', payload: { query: 'WhatsApp' } });
          if (r.error) throw new Error(r.error);
          return r.result;
        });
        assert.ok(Array.isArray(result?.results) && result.results.length > 0, 'Search returned no apps');
        return { responded: true };
      });
      await check('app details UI', async () => {
        await page.type('#pkg-input', packageName);
        await page.click('#info-btn');
        await page.waitForSelector('#info-result .msg.ok, #info-result .msg.err', { timeout: 180000 });
        const error = await page.$eval('#info-result', (el) => el.querySelector('.msg.err')?.textContent || '');
        if (error) throw new Error(error);
        return { packageName };
      });
      await check('purchase, delivery and complete CDN bodies', async () => {
        return page.evaluate(async (pkg) => {
          const { getDetailsCached } = await import('./ui/info-card.js');
          const { fetchSplits } = await import('./ui/download-handler.js');
          const details = await getDetailsCached(pkg);
          window.__gplayTestFiles = await fetchSplits(pkg, details);
          return { files: window.__gplayTestFiles.map((f) => ({ name: f.name, bytes: f.blob.size })) };
        }, packageName);
      });
      const zipPath = await check('ZIP download', () => saveFromBrowser('live-splits.zip', () => page.evaluate(() =>
        window.gplaydlApkTools.bundleZip(window.__gplayTestFiles, 'live-splits.zip'))));
      await check('ZIP contains base APK', async () => {
        const files = fflate.unzipSync(new Uint8Array(await readFile(zipPath)));
        assert.ok(files['base.apk']?.length);
        return { fileCount: Object.keys(files).length };
      });
      const apkPath = await check('live merge and APK download', () => saveFromBrowser('live-merged.apk', () => page.evaluate(() =>
        window.gplaydlApkTools.mergeAndSign(window.__gplayTestFiles, 'live-merged.apk'))));
      await check('live APK alignment and signatures', () => verifySignatures(apkPath));
    }
  }
  report.checks.push({ name: 'USB install', status: 'not run', reason: 'Requires a connected Android device and the browser USB permission prompt.' });
} catch (err) {
  if (!report.checks.some((c) => c.status === 'failed')) report.checks.push({ name: 'runner', status: 'failed', error: redact(err.message) });
  console.error('FAIL ' + redact(err.message));
  process.exitCode = 1;
} finally {
  if (page) await page.close().catch(() => {});
  report.finishedAt = new Date().toISOString();
  await writeFile(resolve(dir, 'report.json'), JSON.stringify(report, null, 2), { mode: 0o600 });
  console.log('Report: ' + resolve(dir, 'report.json'));
  browser.disconnect(); // Keep the user's test session and its login alive.
}
