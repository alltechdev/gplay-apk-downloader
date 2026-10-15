// Matches the server UI: sign in with Google, automatic capture, and sign out.
import { $, h, replace } from './dom.js';
import { rpc } from './rpc.js';
import { log, setLogActive } from './log.js';
import { clearDetailsCache } from './info-card.js';

let pollTimer = null;
let polling = false;

function setAuthCard(status) {
  $('#arch-select').value = status.arch || 'arm64-v8a';
  $('#auth-signin-btn').style.display = status.signedIn ? 'none' : '';
  $('#auth-signin-btn').disabled = !!status.pendingLogin;
  $('#auth-signout-btn').style.display = status.signedIn ? '' : 'none';
  if (status.signedIn) {
    const detail = `${status.profileLabel || status.profileKey || ''} · ${status.profileArch || ''}` +
      (status.stale ? ' (will refresh on next request)' : '');
    replace($('#auth-status'), h('div', { class: 'adb-dot' }),
      h('div', { class: 'adb-device-name' }, status.email || 'Authenticated', h('small', null, detail)));
  } else {
    $('#auth-status').textContent = status.pendingLogin
      ? 'Sign in with Google in the opened window…'
      : 'Not signed in. Sign in with your Google account.';
  }
}

function showAuthError(err) {
  $('#auth-status').textContent = err.message;
  $('#auth-signin-btn').disabled = false;
  log('Google sign-in failed: ' + err.message, 'err');
  setLogActive(false);
}

function pollLogin() {
  if (pollTimer || polling) return;
  pollTimer = setTimeout(async () => {
    pollTimer = null;
    polling = true;
    let pending = false;
    try {
      const result = await rpc('auth.completeLogin');
      pending = !!result.pending;
      if (!pending) { setAuthCard(result); setLogActive(false); }
    } catch (err) { showAuthError(err); }
    finally { polling = false; }
    if (pending) pollLogin();
  }, 1000);
}

async function refreshAuth() {
  try {
    const status = await rpc('auth.status');
    setAuthCard(status);
    if (status.pendingLogin) pollLogin();
  } catch (err) { log('Auth status failed: ' + err.message, 'err'); }
}

export function initAuthCard() {
  $('#auth-signin-btn').addEventListener('click', async () => {
    clearDetailsCache();
    $('#auth-signin-btn').disabled = true;
    $('#auth-status').textContent = 'A browser window is opening — sign in there…';
    setLogActive(true);
    try {
      const result = await rpc('auth.beginLogin', { arch: $('#arch-select').value });
      if (result.pending) pollLogin();
      else { setAuthCard(result); setLogActive(false); }
    } catch (err) { showAuthError(err); }
  });
  $('#auth-signout-btn').addEventListener('click', async () => {
    clearDetailsCache();
    try { setAuthCard(await rpc('auth.signOut')); log('Signed out of Google account', 'info'); }
    catch (err) { showAuthError(err); }
  });
  $('#arch-select').addEventListener('change', async (e) => {
    clearDetailsCache();
    try {
      const arch = e.target.value;
      const status = await rpc('arch.set', { arch });
      if (status.canRetry || (status.signedIn && status.profileArch !== arch)) setAuthCard(await rpc('auth.signIn', { arch }));
      else setAuthCard(status);
    } catch (err) { showAuthError(err); }
  });
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg?.type !== 'auth.event') return;
    const p = msg.payload || {};
    if (p.phase === 'start') { log('Signing in with Google…', 'info'); setLogActive(true); }
    else if (p.phase === 'progress') { $('#auth-status').textContent = p.message; log(p.message, 'info'); }
    else if (p.phase === 'done') { log('Google Play session ready', 'ok'); setLogActive(false); refreshAuth(); }
    else if (p.phase === 'fail') setLogActive(false);
    else if (p.phase === 'refresh') log('Refreshing Google Play session', 'info');
  });
  refreshAuth();
}
