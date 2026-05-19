// Test helper: vm-load a chain of SW files in the same context (mirroring
// `importScripts` order in src/background.js) and return the resulting
// global namespace. Use this to unit-test SW-only top-level declarations
// (which aren't ESM exports).

import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const swDir = resolve(__dirname, '..', '..', 'src', 'sw');

const DEFAULT_GLOBALS = {
  TextDecoder, TextEncoder, Uint8Array, BigInt, Number, Date, Object, Array, Set, Map,
  // minimal `chrome` stub so files that reference chrome.* at top level don't
  // crash on load (files that *call* chrome.* at top level should NOT be in
  // the chain — only ones that declare functions).
  chrome: {
    runtime: { sendMessage: () => Promise.resolve(), getURL: (p) => 'chrome-extension://test/' + p },
  },
};

/**
 * Load `files` (in order) in a fresh vm context. Each file's top-level
 * declarations become bindings in the script-record (not always reachable
 * via the global object); a trailing `Object.assign(globalThis, …)` line
 * publishes the requested names.
 *
 * @param {string[]} files       Filenames inside `src/sw/`, in order.
 * @param {string[]} captureNames Names to make available on the returned object.
 * @returns {object} An object with every captured name (and ctx for direct access).
 */
export function loadSw(files, captureNames) {
  const ctx = vm.createContext({ ...DEFAULT_GLOBALS });
  let combined = '';
  for (const f of files) combined += readFileSync(resolve(swDir, f), 'utf8') + '\n';
  combined += `;Object.assign(globalThis, { ${captureNames.join(', ')} });`;
  vm.runInContext(combined, ctx);
  const out = { ctx };
  for (const n of captureNames) out[n] = ctx[n];
  return out;
}
