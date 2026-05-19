// e2e runner: launches system chromium via puppeteer-core with the unpacked
// extension loaded from src/, then exercises scenarios.
//
// Scenarios live in tests/e2e/scenarios/*.mjs and export a default async
// function (ctx) where:
//   ctx = { browser, extensionId, logDir, shotDir, latestDir, srcDir }
//
// All screenshots are written to TWO places:
//   - web_extension/screenshots/<timestamp>/<scenario>-<step>.png  (history)
//   - web_extension/screenshots/latest/<scenario>-<step>.png       (one-glance latest)
// Plus a copy under tests/logs/<timestamp>/ for per-run forensics.

import { mkdir, readdir, rm, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import puppeteer from 'puppeteer-core';

const __dirname = dirname(fileURLToPath(import.meta.url));
const EXT_DIR = resolve(__dirname, '..', '..');
const SRC_DIR = resolve(EXT_DIR, 'src');
const LOG_ROOT = resolve(EXT_DIR, 'tests', 'logs');
const SHOT_ROOT = resolve(EXT_DIR, 'screenshots');
const SCENARIO_DIR = resolve(__dirname, 'scenarios');

const ts = new Date().toISOString().replace(/[:.]/g, '-');
const logDir = resolve(LOG_ROOT, `e2e-${ts}`);
const shotDir = resolve(SHOT_ROOT, ts);
const latestDir = resolve(SHOT_ROOT, 'latest');
await mkdir(logDir, { recursive: true });
await mkdir(shotDir, { recursive: true });
// Wipe latestDir so stale screenshots from removed scenarios don't linger.
if (existsSync(latestDir)) await rm(latestDir, { recursive: true, force: true });
await mkdir(latestDir, { recursive: true });

const EXECUTABLE = process.env.CHROMIUM_BIN ||
  '/data/data/com.termux/files/usr/bin/chromium-browser';

console.log('[e2e] chromium      :', EXECUTABLE);
console.log('[e2e] extension src :', SRC_DIR);
console.log('[e2e] log dir       :', logDir);
console.log('[e2e] shot dir      :', shotDir);

const browser = await puppeteer.launch({
  executablePath: EXECUTABLE,
  headless: 'new',
  args: [
    '--no-sandbox',
    '--disable-gpu',
    '--disable-dev-shm-usage',
    `--disable-extensions-except=${SRC_DIR}`,
    `--load-extension=${SRC_DIR}`,
  ],
});

const results = [];
let extensionId = null;

try {
  // Discover extension ID by waiting for the service-worker target to appear.
  // puppeteer's browser.targets() is event-cached and may not include the SW
  // until a targetcreated event fires; ask CDP directly to avoid that lag.
  const cdp = await browser.target().createCDPSession();
  for (let i = 0; i < 100 && !extensionId; i++) {
    const { targetInfos } = await cdp.send('Target.getTargets');
    const sw = targetInfos.find((t) => t.type === 'service_worker' && t.url.startsWith('chrome-extension://'));
    if (sw) extensionId = new URL(sw.url).host;
    else await new Promise((r) => setTimeout(r, 100));
  }
  if (!extensionId) {
    const { targetInfos } = await cdp.send('Target.getTargets');
    const t = targetInfos.find((ti) => ti.url.startsWith('chrome-extension://'));
    if (t) extensionId = new URL(t.url).host;
  }
  console.log('[e2e] extensionId   :', extensionId || '(unknown)');

  const ctx = { browser, extensionId, logDir, shotDir, latestDir, srcDir: SRC_DIR };

  // Built-in smoke: load the extension page, snapshot it.
  if (extensionId) {
    const page = await browser.newPage();
    await page.setViewport({ width: 760, height: 720, deviceScaleFactor: 1 });
    page.on('console', (m) => console.log('[page console]', m.type(), m.text()));
    page.on('pageerror', (e) => console.error('[page error]', e.message));
    await page.goto(`chrome-extension://${extensionId}/index.html`, { waitUntil: 'networkidle0' });
    await page.waitForSelector('header h1');
    const h1 = await page.$eval('header h1', (el) => el.textContent.trim());
    await page.screenshot({ path: resolve(shotDir, 'smoke-page.png') });
    await page.screenshot({ path: resolve(latestDir, 'smoke-page.png') });
    await page.screenshot({ path: resolve(logDir, 'smoke-page.png') });
    results.push({ scenario: 'smoke.page', ok: true, h1 });
    await page.close();
  } else {
    results.push({ scenario: 'smoke.page', ok: false, error: 'extension did not register' });
  }

  // Discover and run additional scenarios.
  if (existsSync(SCENARIO_DIR)) {
    const files = (await readdir(SCENARIO_DIR)).filter((f) => f.endsWith('.mjs')).sort();
    for (const f of files) {
      const name = `scenarios/${f}`;
      console.log('[e2e] run scenario:', name);
      try {
        const mod = await import(resolve(SCENARIO_DIR, f));
        const out = await mod.default(ctx);
        results.push({ scenario: name, ok: true, ...out });
      } catch (err) {
        console.error('[e2e] scenario failed:', name, err);
        results.push({ scenario: name, ok: false, error: String(err?.message || err) });
      }
    }
  }
} finally {
  await browser.close();
}

const summary = {
  chromium: '144.x',
  extensionId,
  timestamp: new Date().toISOString(),
  shotDir,
  latestDir,
  results,
  ok: results.every((r) => r.ok),
};
await writeFile(resolve(logDir, 'result.json'), JSON.stringify(summary, null, 2));
await writeFile(resolve(latestDir, 'result.json'), JSON.stringify(summary, null, 2));
console.log('[e2e]', summary.ok ? 'PASS' : 'FAIL', '— result:', resolve(logDir, 'result.json'));
if (!summary.ok) process.exit(1);
