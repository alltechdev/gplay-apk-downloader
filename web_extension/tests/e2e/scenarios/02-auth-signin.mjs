// e2e: signs in via the extension UI, asserts the auth card flips from
// "Not signed in" to the signed-in state. Verifies the extension can hit
// AuroraOSS from the chrome-extension:// origin (CORS reality check).
import { resolve } from 'node:path';

export default async function authSignIn({ browser, extensionId, shotDir, latestDir }) {
  if (!extensionId) throw new Error('no extensionId');
  const page = await browser.newPage();
  await page.setViewport({ width: 760, height: 720, deviceScaleFactor: 1 });
  const consoleMsgs = [];
  page.on('console', (m) => consoleMsgs.push(`${m.type()}:${m.text()}`));
  page.on('pageerror', (e) => consoleMsgs.push(`pageerror:${e.message}`));

  await page.goto(`chrome-extension://${extensionId}/index.html`, { waitUntil: 'networkidle0' });
  await page.waitForSelector('#auth-signin-btn');

  // Pre-click screenshot.
  await page.screenshot({ path: resolve(shotDir, 'auth-1-before.png') });
  await page.screenshot({ path: resolve(latestDir, 'auth-1-before.png') });

  const beforeText = await page.$eval('#auth-status', (el) => el.textContent.trim());

  // Trigger sign-in.
  await page.click('#auth-signin-btn');

  // Wait for either the sign-out button to show (success) or an "err" log.
  await page.waitForFunction(
    () => {
      const out = document.getElementById('auth-signout-btn');
      const stat = document.getElementById('auth-status');
      const errored = !!document.querySelector('#log-scroll .log-icon.err');
      return (out && out.offsetParent !== null) || errored || stat?.textContent?.includes('Got token') ;
    },
    { timeout: 30000 },
  );

  // Capture state.
  const signedIn = await page.$eval('#auth-signout-btn', (el) => el.offsetParent !== null).catch(() => false);
  const statusText = await page.$eval('#auth-status', (el) => el.textContent.trim());
  const logEntries = await page.$$eval('#log-scroll .log-entry', (els) => els.map((e) => e.textContent.trim()));

  await page.screenshot({ path: resolve(shotDir, 'auth-2-after.png') });
  await page.screenshot({ path: resolve(latestDir, 'auth-2-after.png') });

  // Open log panel for the screenshot.
  await page.click('#log-header');
  await new Promise((r) => setTimeout(r, 400));
  await page.screenshot({ path: resolve(shotDir, 'auth-3-log.png') });
  await page.screenshot({ path: resolve(latestDir, 'auth-3-log.png') });

  await page.close();

  if (!signedIn) {
    throw new Error(`sign-in did not complete. status="${statusText}" log=${JSON.stringify(logEntries.slice(-5))}`);
  }
  return { beforeText, statusText, logEntries: logEntries.slice(-10) };
}
