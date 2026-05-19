// rpc.js — page → service-worker request helper.
// Every SW handler returns `{ result } | { error, code, status }`;
// this normalises that shape into a Promise that resolves with `result`
// or rejects with an Error carrying `.code` (and optional `.status`).
//
// If the SW itself isn't reachable (terminated, not yet booted,
// extension context invalidated), the page's error banner surfaces
// it — those failures aren't tied to a single user action and would
// otherwise be invisible.

import { showError, isConnectivityError } from './error-banner.js';

/**
 * @param {string} type     RPC name (e.g. "app.details").
 * @param {object} payload  Optional payload object.
 * @returns {Promise<any>}  Whatever the SW handler returned.
 */
export async function rpc(type, payload = {}) {
  let res;
  try {
    res = await chrome.runtime.sendMessage({ type, payload });
  } catch (transportErr) {
    if (isConnectivityError(transportErr)) {
      showError('The extension background service worker is unreachable.', {
        detail: transportErr.message,
      });
    }
    throw transportErr;
  }
  if (res?.error) {
    const e = new Error(res.error);
    if (res.code)   e.code   = res.code;
    if (res.status) e.status = res.status;
    throw e;
  }
  return res?.result;
}
