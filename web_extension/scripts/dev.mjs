// Persistent, local-only test browser. No changes to the user's normal profile.
import { mkdir, writeFile, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import puppeteer from 'puppeteer-core';
import { EXT_DIR, LOCAL_DIR, SESSION_PATH, LOG_PATH, captureDiagnostics } from './browser-support.mjs';

const executablePath = process.env.CHROMIUM_BIN || [
  '/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser',
  '/data/data/com.termux/files/usr/bin/chromium-browser',
].find(existsSync);
if (!executablePath) throw new Error('Set CHROMIUM_BIN to an installed Chrome/Chromium executable.');
await mkdir(LOCAL_DIR, { recursive: true, mode: 0o700 });
const headless = process.env.HEADLESS === '1' || (!process.env.DISPLAY && !process.env.WAYLAND_DISPLAY);
const browser = await puppeteer.launch({
  executablePath, headless, defaultViewport: null,
  userDataDir: resolve(LOCAL_DIR, 'chrome-profile'),
  ignoreDefaultArgs: ['--disable-extensions'],
  args: ['--no-sandbox', '--disable-dev-shm-usage', '--enable-unsafe-extension-debugging', '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0'],
});
let diagnostics;
let stopping = false;
async function stop() {
  if (stopping) return;
  stopping = true;
  await browser.close().catch(() => {});
}
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
try {
  const cdp = await browser.target().createCDPSession();
  const { id } = await cdp.send('Extensions.loadUnpacked', { path: resolve(EXT_DIR, 'src') });
  diagnostics = await captureDiagnostics(browser, id);
  await writeFile(SESSION_PATH, JSON.stringify({ browserWSEndpoint: browser.wsEndpoint(), extensionId: id }, null, 2), { mode: 0o600 });
  let page = (await browser.pages()).find((p) => p.url().startsWith(`chrome-extension://${id}/`));
  if (!page) page = await browser.newPage();
  await page.goto(`chrome-extension://${id}/index.html`);
  await page.bringToFront();
  console.log(`[dev] Test browser ready (${headless ? 'headless' : 'visible'}). Sign in in this window once; the profile is retained.`);
  console.log(`[dev] Logs: ${LOG_PATH}`);
  console.log('[dev] Tests: npm run test:live -- --smoke, or npm run test:live -- --package com.whatsapp');
  await new Promise((resolveDone) => browser.once('disconnected', resolveDone));
} finally {
  await stop();
  await diagnostics?.flush();
  await rm(SESSION_PATH, { force: true });
}
