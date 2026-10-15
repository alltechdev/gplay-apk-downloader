// Real sockets + real Chromium host permissions/DNR. No Google account or CDN mocks.
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { once } from 'node:events';
import puppeteer from 'puppeteer-core';

const temp = await mkdtemp(resolve(tmpdir(), 'gplay-cdn-'));
const attempts = new Map();
const sizes = new Map([['/small.apk', 8 * 1024 * 1024], ['/base.apk', 231 * 1024 * 1024], ['/config.apk', 32 * 1024 * 1024], ['/interrupted.apk', 8 * 1024 * 1024]]);
let browser, plain, tls;
const handler = async (req, res) => {
  const key = req.headers.host + req.url;
  attempts.set(key, (attempts.get(key) || 0) + 1);
  if (req.headers.cookie !== 'DownloadAuth=fixture') { res.writeHead(403); res.end('missing cookie'); return; }
  const size = sizes.get(req.url);
  if (!size) { res.writeHead(404); res.end(); return; }
  // No Access-Control-Allow-Origin: only correct extension permissions allow reading.
  res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': size });
  const chunk = Buffer.alloc(256 * 1024, 0x5a);
  try {
    for (let sent = 0; sent < size; sent += chunk.length) {
      if (req.url === '/interrupted.apk' && attempts.get(key) === 1 && sent >= size / 2) { res.destroy(); return; }
      if (!res.write(chunk.subarray(0, Math.min(chunk.length, size - sent)))) await once(res, 'drain');
    }
    res.end();
  } catch { res.destroy(); }
};
try {
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', resolve(temp, 'key.pem'), '-out', resolve(temp, 'cert.pem'), '-subj', '/CN=probe.gvt1.com', '-days', '1'], { stdio: 'ignore' });
  plain = http.createServer(handler);
  tls = https.createServer({ key: await readFile(resolve(temp, 'key.pem')), cert: await readFile(resolve(temp, 'cert.pem')) }, handler);
  await Promise.all([new Promise((r) => plain.listen(0, '127.0.0.1', r)), new Promise((r) => tls.listen(0, '127.0.0.1', r))]);
  const executablePath = process.env.CHROMIUM_BIN || ['/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser', '/data/data/com.termux/files/usr/bin/chromium-browser'].find(existsSync);
  browser = await puppeteer.launch({ executablePath, headless: true, pipe: true, ignoreDefaultArgs: ['--disable-extensions'], args: [
    '--no-sandbox', '--enable-unsafe-extension-debugging', '--ignore-certificate-errors', '--no-proxy-server',
    '--host-resolver-rules=MAP probe.gvt1.com 127.0.0.1, MAP probe.googleusercontent.com 127.0.0.1',
  ] });
  const cdp = await browser.target().createCDPSession();
  const { id } = await cdp.send('Extensions.loadUnpacked', { path: resolve(import.meta.dirname, '../../src') });
  const page = await browser.newPage();
  await page.goto(`chrome-extension://${id}/index.html`);
  const workerTarget = await browser.waitForTarget((t) => t.type() === 'service_worker' && t.url().startsWith(`chrome-extension://${id}/`));
  const worker = await workerTarget.createCDPSession();
  // Let startup finish before installing rules; fixture calls the actual production helper.
  await worker.send('Runtime.evaluate', { expression: 'installCoreDnrRules()', awaitPromise: true });
  let ruleId = 5000;
  for (const host of ['probe.gvt1.com', 'probe.googleusercontent.com']) {
    for (const scheme of ['https', 'http']) {
      const port = scheme === 'https' ? tls.address().port : plain.address().port;
      const url = `${scheme}://${host}:${port}/small.apk`;
      const current = ++ruleId;
      const installed = await worker.send('Runtime.evaluate', { expression: `applyCookieRule(${current}, ${JSON.stringify(url)}, [{name:'DownloadAuth',value:'fixture'}])`, awaitPromise: true });
      assert.ok(!installed.exceptionDetails, 'Cookie rule installation failed');
      const bytes = await page.evaluate(async (url) => { const r = await fetch(url); if (!r.ok) throw new Error('HTTP ' + r.status); return (await r.blob()).size; }, url);
      assert.equal(bytes, sizes.get('/small.apk'));
      console.log(`PASS ${scheme} ${host}: authenticated complete body without CORS headers`);
    }
  }
  // Exercise production parallel fetch + body retries at the reported game's sizes.
  const files = [];
  for (const [name, path] of [['base.apk', '/base.apk'], ['config.arm64_v8a.apk', '/config.apk'], ['retry.apk', '/interrupted.apk']]) {
    const url = `http://probe.gvt1.com:${plain.address().port}${path}`;
    const current = ++ruleId;
    const result = await worker.send('Runtime.evaluate', { expression: `applyCookieRule(${current}, ${JSON.stringify(url)}, [{name:'DownloadAuth',value:'fixture'}])`, awaitPromise: true });
    assert.ok(!result.exceptionDetails);
    files.push({ name, url, size: sizes.get(path), ruleId: current });
  }
  const result = await page.evaluate(async (files) => {
    const original = chrome.runtime.sendMessage.bind(chrome.runtime);
    chrome.runtime.sendMessage = (m) => m.type === 'app.prepareInstall'
      ? Promise.resolve({ result: { versionCode: 1, files, ruleIds: files.map((f) => f.ruleId) } }) : original(m);
    try {
      const { fetchSplits } = await import('./ui/download-handler.js');
      return (await fetchSplits('com.test.transport', { versionCode: 1 })).map((f) => f.blob.size);
    } finally { chrome.runtime.sendMessage = original; }
  }, files);
  assert.deepEqual(result, files.map((f) => f.size));
  assert.equal(attempts.get(`probe.gvt1.com:${plain.address().port}/interrupted.apk`), 2);
  const remaining = await page.evaluate(() => chrome.declarativeNetRequest.getDynamicRules());
  assert.ok(files.every((f) => !remaining.some((r) => r.id === f.ruleId)));
  console.log('PASS 231 MB base + 32 MB split + interrupted-body recovery, with rule cleanup');
} finally {
  await browser?.close();
  plain?.closeAllConnections(); tls?.closeAllConnections();
  plain?.close(); tls?.close();
  await rm(temp, { recursive: true, force: true });
}
