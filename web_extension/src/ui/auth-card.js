// auth-card.js — Authentication card.
//
// Renders sign-in state, listens for SW `auth.event` broadcasts, and
// handles the arch selector (which auto re-signs-in if the current
// profile's arch doesn't match).
//
// Legacy parity: dispenser-account email is *not* surfaced.

import { $, h, replace } from './dom.js';
import { rpc } from './rpc.js';
import { log, setLogActive } from './log.js';

function setAuthCard(status) {
  const statusEl = $('#auth-status');
  const signInBtn  = $('#auth-signin-btn');
  const signOutBtn = $('#auth-signout-btn');
  $('#arch-select').value = status.arch || 'arm64-v8a';
  if (status.signedIn) {
    const stale = status.stale ? ' (stale, will refresh on next call)' : '';
    const detail = (status.profileLabel || status.profileKey || '') +
                   ' · ' + (status.profileArch || '') + stale;
    replace(statusEl,
      h('div', { class: 'adb-dot' }),
      h('div', { class: 'adb-device-name' },
        'Authenticated',
        h('small', null, detail),
      ),
    );
    signInBtn.style.display  = 'none';
    signOutBtn.style.display = '';
  } else {
    statusEl.textContent = 'Not signed in. Click "Sign in" for an anonymous AuroraOSS token.';
    signInBtn.style.display  = '';
    signOutBtn.style.display = 'none';
  }
}

async function refreshAuth() {
  try { setAuthCard(await rpc('auth.status')); }
  catch (err) { log('auth status failed: ' + err.message, 'err'); }
}

function onAuthEvent(p) {
  if      (p.phase === 'start')   { log('Sign-in started (arch=' + p.arch + ')', 'info'); setLogActive(true); }
  else if (p.phase === 'try')      log('Trying profile ' + p.key + ' (' + p.label + ', ' + p.arch + ')', 'info');
  else if (p.phase === 'reject')   log('Dispenser rejected ' + p.key + ' (HTTP ' + p.status + ')', 'warn');
  else if (p.phase === 'error')    log('Network error on ' + p.key + ': ' + p.error, 'err');
  else if (p.phase === 'ok')       log('Got token from ' + p.key, 'ok');
  else if (p.phase === 'done')   { log('Sign-in complete (' + p.profileKey + ')', 'ok'); setLogActive(false); refreshAuth(); }
  else if (p.phase === 'fail')   { log('Sign-in failed — all profiles rejected', 'err'); setLogActive(false); }
  else if (p.phase === 'refresh')  log('Re-authenticating (' + p.reason + ')', 'info');
}

export function initAuthCard() {
  $('#auth-signin-btn').addEventListener('click', async () => {
    $('#auth-signin-btn').disabled = true;
    try { setAuthCard(await rpc('auth.signIn', { arch: $('#arch-select').value })); }
    catch (err) { log('Sign-in failed: ' + err.message, 'err'); setLogActive(false); }
    finally { $('#auth-signin-btn').disabled = false; }
  });
  $('#auth-signout-btn').addEventListener('click', async () => {
    try { setAuthCard(await rpc('auth.signOut')); log('Signed out', 'info'); }
    catch (err) { log('Sign-out failed: ' + err.message, 'err'); }
  });
  $('#arch-select').addEventListener('change', async (e) => {
    const arch = e.target.value;
    try {
      const status = await rpc('arch.set', { arch });
      log('Architecture set to ' + arch, 'info');
      if (status.signedIn && status.profileArch && status.profileArch !== arch) {
        log('Profile arch (' + status.profileArch + ') differs — re-authenticating', 'info');
        setAuthCard(await rpc('auth.signIn', { arch }));
      }
    } catch (err) { log('arch.set failed: ' + err.message, 'err'); }
  });
  chrome.runtime.onMessage.addListener((msg) => { if (msg?.type === 'auth.event') onAuthEvent(msg.payload || {}); });
  refreshAuth();
}
