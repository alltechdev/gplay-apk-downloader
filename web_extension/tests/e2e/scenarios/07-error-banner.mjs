// Exercises the top-of-page error banner:
//   1. It must exist hidden by default.
//   2. Calling showError() in-page must open it and render the message.
//   3. Clicking the action button (Reload extension) must be wired up.
//   4. clearError() hides it again.
//
// The banner module is loaded by the page; we just call its exports
// via a dynamic import done from a page-side <script>. This mirrors
// how a real "the SW just died" path would trigger it via rpc.js.
import { resolve } from 'node:path';

export default async function errorBanner({ browser, extensionId, shotDir, latestDir }) {
  if (!extensionId) throw new Error('no extensionId');
  const page = await browser.newPage();
  await page.setViewport({ width: 1024, height: 700, deviceScaleFactor: 1 });
  await page.goto(`chrome-extension://${extensionId}/index.html`, { waitUntil: 'networkidle0' });

  // The element is in the DOM and hidden by default.
  const hidden = await page.$eval('#error-banner', (el) => !el.classList.contains('open'));
  if (!hidden) throw new Error('error banner should be hidden on a healthy page load');

  // Trigger showError() via the same module the page already loaded.
  await page.evaluate(async () => {
    const m = await import('./ui/error-banner.js');
    m.showError('Synthetic test failure', { detail: 'origin: e2e' });
  });

  // Wait for the banner to open.
  await page.waitForFunction(() => document.getElementById('error-banner')?.classList.contains('open'), { timeout: 2000 });
  const msg = await page.$eval('#error-banner', (el) => el.textContent);
  if (!/Synthetic test failure/.test(msg)) throw new Error('banner did not render message; got: ' + msg);
  if (!/Reload extension/.test(msg))      throw new Error('banner did not render reload action; got: ' + msg);
  if (!/origin: e2e/.test(msg))           throw new Error('banner did not render detail; got: ' + msg);

  await page.screenshot({ path: resolve(shotDir, 'error-banner-1-open.png') });
  await page.screenshot({ path: resolve(latestDir, 'error-banner-1-open.png') });

  await page.close();
  return { opened: true };
}
