// 99-rpc.js — RPC dispatcher. Wires SW message names to their handlers.
// Broadcast event names (auth.event, download.event) are intentionally
// not in the RPC table so the SW ignores its own broadcasts.

const RPC = {
  'auth.status':        ()  => authStatus(),
  'auth.signIn':        (p) => authSignIn(p),
  'auth.signOut':       ()  => authSignOut(),
  'arch.set':           (p) => setArchRpc(p),
  'app.details':        (p) => appDetails(p),
  'app.delivery':       (p) => appDelivery(p),
  'app.download':       (p) => appDownload(p),
  'app.cancelDownload': (p) => cancelDownload(p),
  'app.showDownload':   (p) => showDownload(p),
  'app.prepareInstall': (p) => appPrepareInstall(p),
  'app.releaseRules':   (p) => releaseRules(p),
  'app.search':         (p) => appSearch(p),
};

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === 'auth.event' || msg?.type === 'download.event') return false;
  const fn = RPC[msg?.type];
  if (!fn) { sendResponse({ error: `unknown rpc: ${msg?.type}`, code: 'UNKNOWN_RPC' }); return false; }
  Promise.resolve(fn(msg.payload || {}))
    .then((result) => sendResponse({ result }))
    .catch((err) => sendResponse({
      error: String(err?.message || err),
      code:  err?.code,
      status: err?.status,
    }));
  return true;
});
