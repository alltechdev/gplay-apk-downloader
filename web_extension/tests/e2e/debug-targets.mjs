// Debug: list every target type that puppeteer sees, watch for 20s.
import puppeteer from 'puppeteer-core';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SRC = resolve(__dirname, '..', '..', 'src');
const browser = await puppeteer.launch({
  executablePath: '/data/data/com.termux/files/usr/bin/chromium-browser',
  headless: 'new',
  args: [
    '--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage',
    `--disable-extensions-except=${SRC}`,
    `--load-extension=${SRC}`,
  ],
});

browser.on('targetcreated', (t) => console.log('  + ' + t.type() + ' :: ' + t.url()));

// Also dump CDP target list directly.
const ctx = await browser.target().createCDPSession();
async function dumpCDP(tag) {
  const { targetInfos } = await ctx.send('Target.getTargets');
  console.log('\n--- CDP at ' + tag + ' ---');
  for (const ti of targetInfos) console.log('  CDP ' + ti.type + ' :: ' + ti.url);
}

console.log('initial puppeteer targets:');
for (const t of browser.targets()) console.log(' ', t.type(), '::', t.url());
await dumpCDP('t=0');

for (let i = 1; i <= 10; i++) {
  await new Promise((r) => setTimeout(r, 1000));
  const sw = browser.targets().find((t) => t.type() === 'service_worker');
  if (sw) { console.log('SW found via puppeteer at t=' + i); break; }
}
await dumpCDP('final');

await browser.close();
