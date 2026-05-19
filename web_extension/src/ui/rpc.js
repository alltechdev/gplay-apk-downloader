// rpc.js — page → service-worker request helper.
// Every SW handler returns `{ result } | { error, code, status }`;
// this normalises that shape into a Promise that resolves with `result`
// or rejects with an Error carrying `.code` (and optional `.status`).

/**
 * @param {string} type     RPC name (e.g. "app.details").
 * @param {object} payload  Optional payload object.
 * @returns {Promise<any>}  Whatever the SW handler returned.
 */
export async function rpc(type, payload = {}) {
  const res = await chrome.runtime.sendMessage({ type, payload });
  if (res?.error) {
    const e = new Error(res.error);
    if (res.code)   e.code   = res.code;
    if (res.status) e.status = res.status;
    throw e;
  }
  return res?.result;
}
