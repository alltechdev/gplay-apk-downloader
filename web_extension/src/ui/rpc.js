// rpc.js — page → service-worker request helper.
// Every SW handler returns `{ result } | { error }`; this normalises that
// shape into a Promise that resolves with `result` or rejects with Error.

export async function rpc(type, payload = {}) {
  const res = await chrome.runtime.sendMessage({ type, payload });
  if (res?.error) throw new Error(res.error);
  return res?.result;
}
