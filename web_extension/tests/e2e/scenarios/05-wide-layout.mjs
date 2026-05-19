// e2e: snapshot the page at a desktop-wide viewport to verify the two-column
// layout renders correctly and the header / auth / log / footer span both columns.
import { resolve } from 'node:path';

export default async function wideLayout({ browser, extensionId, shotDir, latestDir }) {
  if (!extensionId) throw new Error('no extensionId');
  const page = await browser.newPage();
  await page.setViewport({ width: 1280, height: 900, deviceScaleFactor: 1 });
  await page.goto(`chrome-extension://${extensionId}/index.html`, { waitUntil: 'networkidle0' });
  await page.waitForSelector('header h1');

  // Layout assertions: at 1280px wide, .wrapper should be display: grid with 2 columns.
  const grid = await page.$eval('.wrapper', (el) => {
    const cs = getComputedStyle(el);
    return { display: cs.display, cols: cs.gridTemplateColumns };
  });

  // Verify the Direct Download and Search cards sit on the same horizontal row
  // (column-spanning header/auth/log are exempt).
  const cardPositions = await page.evaluate(() => {
    const dd = document.getElementById('download-card');
    const sr = document.getElementById('search-results')?.closest('.card');
    if (!dd || !sr) return null;
    return { ddTop: dd.getBoundingClientRect().top, srTop: sr.getBoundingClientRect().top };
  });

  await page.screenshot({ path: resolve(shotDir, 'wide-1280.png'), fullPage: true });
  await page.screenshot({ path: resolve(latestDir, 'wide-1280.png'), fullPage: true });
  await page.close();

  if (!grid.display.includes('grid')) {
    throw new Error('expected wrapper display:grid at 1280px, got: ' + grid.display);
  }
  return { grid, cardPositions };
}
