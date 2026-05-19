// Launches the system chromium with the extension loaded unpacked from src/.
// Headed (non-headless) so the user can interact with it.
//
// Requires a display: either an attached X server (Termux:X11, VNC, or a
// real desktop). If $DISPLAY is unset and HEADLESS!=0 we run with the new
// headless mode and start the remote-debugging endpoint so the user can
// attach DevTools from another machine.
//
// Usage:
//   npm run dev                        # default: headed if DISPLAY is set
//   HEADLESS=1 npm run dev             # force headless (remote-debug only)
//   DEBUG_PORT=9222 npm run dev        # change the CDP port

import { spawn } from 'node:child_process';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SRC_DIR = resolve(__dirname, '..', 'src');
const CHROMIUM = process.env.CHROMIUM_BIN ||
  '/data/data/com.termux/files/usr/bin/chromium-browser';
const DEBUG_PORT = Number(process.env.DEBUG_PORT || 9222);
const FORCE_HEADLESS = process.env.HEADLESS === '1';
const HAS_DISPLAY = !!process.env.DISPLAY;

const profile = await mkdtemp(resolve(tmpdir(), 'gplaydl-dev-'));

const args = [
  '--no-sandbox',
  '--disable-dev-shm-usage',
  `--user-data-dir=${profile}`,
  `--disable-extensions-except=${SRC_DIR}`,
  `--load-extension=${SRC_DIR}`,
  `--remote-debugging-port=${DEBUG_PORT}`,
  `chrome-extension://placeholder/index.html`, // replaced after Chrome assigns the ID
];

if (FORCE_HEADLESS || !HAS_DISPLAY) {
  args.unshift('--headless=new');
  args.unshift('--disable-gpu');
  console.log('[dev] no DISPLAY and/or HEADLESS=1 — running headless');
  console.log(`[dev] attach DevTools from another machine: http://localhost:${DEBUG_PORT}`);
} else {
  console.log(`[dev] using DISPLAY=${process.env.DISPLAY}, running headed`);
}

console.log('[dev] chromium :', CHROMIUM);
console.log('[dev] extension:', SRC_DIR);
console.log('[dev] profile  :', profile);
console.log('[dev] cdp port :', DEBUG_PORT);
console.log('[dev] open chrome://extensions to find the loaded extension');
console.log('[dev] press Ctrl-C to stop');

const proc = spawn(CHROMIUM, args, { stdio: 'inherit' });
process.on('SIGINT', () => proc.kill('SIGINT'));
process.on('SIGTERM', () => proc.kill('SIGTERM'));
proc.on('exit', (code) => process.exit(code ?? 0));
