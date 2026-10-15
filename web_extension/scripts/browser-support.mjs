// Development-only browser connection and redacted diagnostic capture.
import { appendFile, mkdir, readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import puppeteer from 'puppeteer-core';

export const EXT_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const LOCAL_DIR = resolve(EXT_DIR, '.local');
export const SESSION_PATH = resolve(LOCAL_DIR, 'browser.json');
export const LOG_PATH = resolve(LOCAL_DIR, 'extension.jsonl');

export function redact(value) {
  return String(value ?? '')
    .replace(/(?:oauth2_4|aas_et)(?:\/|%2f)[^\s"'<>]+/gi, '[credential redacted]')
    .replace(/\bBearer\s+[^\s"'<>]+/gi, 'Bearer [redacted]')
    .replace(/(["']?(?:authToken|aasToken|ac2dmToken|oauth_token|Token|Auth|Authorization|Cookie|password|securityToken)["']?\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;}]+)/gi, '$1[redacted]')
    .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, '[email redacted]')
    .replace(/https?:\/\/[^\s"'<>]+/gi, (url) => {
      try { return new URL(url).origin + '/[path redacted]'; } catch { return '[URL redacted]'; }
    })
    .slice(0, 8000);
}

export async function connectTestBrowser() {
  const session = JSON.parse(await readFile(SESSION_PATH, 'utf8').catch(() => {
    throw new Error('Test browser is not running. Start it with npm run dev.');
  }));
  const endpoint = new URL(session.browserWSEndpoint);
  if (endpoint.protocol !== 'ws:' || !['127.0.0.1', 'localhost', '[::1]'].includes(endpoint.hostname)) {
    throw new Error('Refusing a non-local browser endpoint.');
  }
  const browser = await puppeteer.connect({ browserWSEndpoint: endpoint.href, defaultViewport: null, protocolTimeout: 900000 });
  return { browser, extensionId: session.extensionId };
}

export async function captureDiagnostics(browser, extensionId, path = LOG_PATH) {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  let writes = Promise.resolve();
  let failure = null;
  const record = (source, level, message, extra = {}) => {
    const entry = { time: new Date().toISOString(), source, level, message: redact(message) };
    // Never record request/response bodies, headers, cookies or storage.
    for (const key of ['url', 'method', 'status', 'blockedReason', 'corsError']) {
      if (extra[key] != null) entry[key] = redact(extra[key]);
    }
    writes = writes.then(() => appendFile(path, JSON.stringify(entry) + '\n', { mode: 0o600 }))
      .catch((err) => { failure = err; });
  };
  const origin = `chrome-extension://${extensionId}/`;
  const attached = new Set();
  async function attach(target) {
    if (!target.url().startsWith(origin) || attached.has(target)) return;
    attached.add(target);
    try {
      const cdp = await target.createCDPSession();
      cdp.on('Runtime.consoleAPICalled', (event) => {
        record(target.type(), event.type, event.args.map((arg) => arg.value ?? arg.description ?? arg.type).join(' '));
      });
      cdp.on('Runtime.exceptionThrown', ({ exceptionDetails: e }) => {
        record(target.type(), 'error', e.exception?.description || e.text, { url: e.url });
      });
      await cdp.send('Runtime.enable');
      const requests = new Map();
      cdp.on('Network.requestWillBeSent', ({ requestId, request }) => {
        requests.set(requestId, { url: request.url, method: request.method });
      });
      cdp.on('Network.responseReceived', ({ requestId, response }) => {
        if (response.status >= 400) record('network', 'error', 'HTTP request failed', { ...requests.get(requestId), status: response.status });
      });
      cdp.on('Network.loadingFailed', (event) => {
        record('network', 'error', event.errorText, { ...requests.get(event.requestId),
          blockedReason: event.blockedReason, corsError: event.corsErrorStatus?.corsError });
        requests.delete(event.requestId);
      });
      cdp.on('Network.loadingFinished', ({ requestId }) => requests.delete(requestId));
      await cdp.send('Network.enable');
      if (target.type() === 'page') {
        const page = await target.page();
        await page.exposeFunction('__gplayDiagnosticEntry', (level, message) => record('activity', String(level), message));
        const observe = () => {
          if (window.__gplayDiagnosticObserver) return;
          const seen = new WeakMap();
          const scan = () => {
            for (const entry of document.querySelectorAll('#log-scroll .log-entry')) {
              const text = entry.querySelector('.log-msg')?.textContent || '';
              if (seen.get(entry) === text) continue;
              seen.set(entry, text);
              const level = entry.querySelector('.log-icon')?.className || 'info';
              window.__gplayDiagnosticEntry(level, text).catch(() => {});
            }
          };
          window.__gplayDiagnosticObserver = new MutationObserver(scan);
          window.__gplayDiagnosticObserver.observe(document, { subtree: true, childList: true, characterData: true });
          scan();
        };
        await page.evaluateOnNewDocument(observe);
        await page.evaluate(observe);
      }
      record('diagnostics', 'info', 'Attached to extension ' + target.type());
    } catch (err) {
      attached.delete(target);
      record('diagnostics', 'warn', 'Could not attach: ' + err.message);
    }
  }
  const onTarget = (target) => { void attach(target); };
  browser.on('targetcreated', onTarget);
  browser.on('targetchanged', onTarget);
  browser.on('targetdestroyed', (target) => attached.delete(target));
  await Promise.all(browser.targets().map(attach));
  return {
    record,
    flush: async () => { await writes; if (failure) throw failure; },
  };
}
