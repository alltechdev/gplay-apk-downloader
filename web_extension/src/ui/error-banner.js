// error-banner.js — top-of-page banner for failures the Activity Log
// would otherwise hide: an SW that died, an uncaught page error, an
// unhandled promise rejection.
//
// Three things wire into it:
//   1. window.onerror               (uncaught synchronous exceptions)
//   2. window.onunhandledrejection  (async / Promise.reject without catch)
//   3. rpc.js                       (re-thrown for any "could not connect"
//                                    style RPC failure)
//
// The Activity Log still records per-action errors. The banner is for
// errors that aren't tied to a single user click — when the extension
// itself is in a bad state, the user sees it without having to expand
// the log.

import { $, h, replace } from './dom.js';

let banner = null;
let inner  = null;

function ensure() {
  if (banner) return;
  banner = $('#error-banner');
  if (!banner) return;
  inner = banner.querySelector('.error-banner-msg');
}

/** Render a persistent error banner at the top of the page. */
export function showError(message, { detail = null, reloadable = true } = {}) {
  ensure();
  if (!banner || !inner) return;
  const parts = [
    h('strong', null, 'Something broke. '),
    String(message || 'Unknown error'),
  ];
  if (detail) {
    parts.push(h('br'), h('small', { class: 'error-banner-detail' }, detail));
  }
  if (reloadable) {
    parts.push(' ');
    const btn = h('button', { class: 'error-banner-action' }, 'Reload extension');
    btn.addEventListener('click', () => location.reload());
    parts.push(btn);
  }
  replace(inner, ...parts);
  banner.classList.add('open');
}

/**
 * Heuristic: does this RPC error look like the SW is unreachable
 * (terminated, not yet booted, or otherwise not answering)?
 */
export function isConnectivityError(err) {
  if (!err) return false;
  const m = String(err.message || err);
  return /could not establish connection|message port closed|receiving end does not exist|extension context invalidated/i.test(m);
}

/** Wire window-level handlers. Call once on DOMContentLoaded. */
export function initErrorBanner() {
  ensure();
  window.addEventListener('error', (ev) => {
    showError(ev?.message || 'page error', { detail: ev?.filename ? ev.filename + ':' + ev.lineno : null });
  });
  window.addEventListener('unhandledrejection', (ev) => {
    const r = ev?.reason;
    showError(r?.message || String(r) || 'unhandled rejection');
  });
}
