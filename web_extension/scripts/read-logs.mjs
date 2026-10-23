import { readFile } from 'node:fs/promises';
import { LOG_PATH } from './browser-support.mjs';
const lines = (await readFile(LOG_PATH, 'utf8').catch(() => '')).trim().split('\n').filter(Boolean);
if (!lines.length) console.log('No test-browser logs yet. Run npm run dev, then reproduce the failure in that window.');
for (const line of lines.slice(-100)) {
  const entry = JSON.parse(line);
  console.log(`${entry.time} [${entry.source}/${entry.level}] ${entry.message}` +
    (entry.url ? ` ${entry.url}` : '') + (entry.corsError ? ` CORS=${entry.corsError}` : '') +
    (entry.blockedReason ? ` blocked=${entry.blockedReason}` : ''));
}
