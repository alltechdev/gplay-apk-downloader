// Tiny static dev server for the extension's src/ directory.
// Lets you preview the page rendering in any browser at http://localhost:PORT/index.html
//
// IMPORTANT: this serves the page as a plain web page; chrome.* extension
// APIs are NOT available here. For real extension behaviour, use:
//   npm run dev    # launches Chromium with the extension loaded
//
// Usage:
//   npm run serve              # default port 8765
//   PORT=9000 npm run serve

import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import http from 'node:http';
import { dirname, extname, resolve, normalize, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..', 'src');
const PORT = Number(process.env.PORT || 8765);

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'application/javascript; charset=utf-8',
  '.mjs':  'application/javascript; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png':  'image/png',
  '.jpg':  'image/jpeg',
  '.svg':  'image/svg+xml',
  '.ico':  'image/x-icon',
  '.woff2': 'font/woff2',
  '.woff': 'font/woff',
};

function safeJoin(root, urlPath) {
  // Strip query/hash, decode, normalize, prevent traversal.
  const clean = decodeURIComponent(urlPath.split('?')[0].split('#')[0]);
  const joined = normalize(join(root, clean === '/' ? '/index.html' : clean));
  if (!joined.startsWith(root)) return null;
  return joined;
}

const server = http.createServer(async (req, res) => {
  const path = safeJoin(ROOT, req.url || '/');
  if (!path) {
    res.writeHead(400).end('bad path');
    return;
  }
  try {
    const s = await stat(path);
    if (s.isDirectory()) {
      res.writeHead(302, { Location: req.url.replace(/\/?$/, '/index.html') }).end();
      return;
    }
    res.writeHead(200, {
      'Content-Type': MIME[extname(path).toLowerCase()] || 'application/octet-stream',
      'Cache-Control': 'no-store',
      'Content-Length': s.size,
    });
    createReadStream(path).pipe(res);
  } catch (err) {
    if (err.code === 'ENOENT') {
      res.writeHead(404, { 'Content-Type': 'text/plain' }).end(`not found: ${req.url}`);
    } else {
      res.writeHead(500, { 'Content-Type': 'text/plain' }).end(String(err));
    }
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[serve] root: ${ROOT}`);
  console.log(`[serve] http://localhost:${PORT}/index.html`);
  console.log(`[serve] (chrome.* APIs are not available on this URL — use \`npm run dev\` for the real extension)`);
});
