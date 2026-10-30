// Personal Google account lifecycle. No anonymous/dispenser fallback.
let authInFlight = null;
let authGeneration = 0;

function profileArch(entry) {
  return entry.arch === 'armv7' ? 'armeabi-v7a' : 'arm64-v8a';
}

function validateAccountEmail(email) {
  if (typeof email !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
    throw new AuthError('Could not detect the Google account email. Please sign in again.');
  }
  return email.trim();
}

async function authSignIn(args = {}) {
  if (authInFlight) {
    if (args.token || args.email) throw new AuthError('Sign-in is already in progress.');
    return authInFlight;
  }
  const generation = authGeneration;
  const checkCancelled = () => {
    if (generation !== authGeneration) throw new AuthError('Sign-in was cancelled.');
  };
  authInFlight = (async () => {
    const saved = await getAuthStored();
    const arch = args.arch || await getArchPref();
    if (!['arm64-v8a', 'armeabi-v7a'].includes(arch)) throw new ValidationError('Unknown architecture.');
    const email = validateAccountEmail(args.email || saved?.email);
    let aasToken = saved?.email === email ? saved?.aasToken : null;
    const token = typeof args.token === 'string' ? args.token.trim() : '';
    await installCoreDnrRules();
    broadcast('auth.event', { phase: 'start', arch });
    if (token.startsWith('oauth2_4/')) aasToken = await exchangeOauthToken(email, token);
    else if (token.startsWith('aas_et/')) aasToken = token;
    else if (token || !aasToken) throw new AuthError('Sign in with Google first.');
    checkCancelled();
    // Persist the long-lived credential before checkin: oauth_token is single-use.
    // A failed checkin can then be retried without consuming the cookie twice.
    await setAuthStored({ accountType: 'personal', email, aasToken });
    const { profiles, personalDefaults } = await loadProfilesJson();
    const entry = profiles.find((p) => p.key === personalDefaults?.[arch] && profileArch(p) === arch);
    if (!entry) throw new AuthError('No device profile is available for this architecture.');
    const auth = await buildAccountSession(email, aasToken, entry);
    checkCancelled();
    await setAuthStored({ ...auth, _profileKey: entry.key, _profileLabel: entry.profile.UserReadableName || entry.key,
      _profileArch: arch, _obtainedAt: Date.now() });
    if (args.registerBoth) {
      const otherArch = arch === 'arm64-v8a' ? 'armeabi-v7a' : 'arm64-v8a';
      const other = profiles.find((p) => p.key === personalDefaults?.[otherArch] && profileArch(p) === otherArch);
      try {
        if (!other) throw new AuthError('No device profile for ' + otherArch);
        broadcast('auth.event', { phase: 'progress', message: 'Registering a second virtual device for ' + otherArch + ' downloads…' });
        const secondary = await buildAccountSession(email, aasToken, other);
        checkCancelled();
        await setAuthStored({ ...secondary, _profileKey: other.key, _profileLabel: other.profile.UserReadableName || other.key,
          _profileArch: otherArch, _obtainedAt: Date.now() });
      } catch (err) {
        checkCancelled();
        broadcast('auth.event', { phase: 'progress', message: 'Second device registration failed; ' + arch + ' downloads still work.' });
      }
      await installCoreDnrRules(auth.deviceInfoProvider?.userAgentString);
    }
    if (!args.preservePreference) await setArchPref(arch);
    broadcast('auth.event', { phase: 'done', profileKey: entry.key });
    return authStatus();
  })();
  try { return await authInFlight; }
  catch (err) { broadcast('auth.event', { phase: 'fail' }); throw err; }
  finally { authInFlight = null; }
}

async function authStatus() {
  const arch = await getArchPref();
  const auth = await getAuthStored(arch);
  const pending = (await chrome.storage.session.get(LOGIN_STORAGE_KEY))[LOGIN_STORAGE_KEY];
  const pendingLogin = !!pending && Date.now() - pending.startedAt < 15 * 60 * 1000;
  if (!auth?.authToken) return { signedIn: false, arch, pendingLogin, canRetry: !!auth?.aasToken, email: auth?.email || pending?.email };
  const ageMs = Date.now() - (auth._obtainedAt || 0);
  return { signedIn: true, arch, profileKey: auth._profileKey, profileLabel: auth._profileLabel,
    profileArch: auth._profileArch || 'arm64-v8a', gsfId: auth.gsfId, email: auth.email,
    ageMs, stale: ageMs > AUTH_TTL_MS };
}

async function authSignOut() {
  authGeneration++;
  if (authInFlight) await authInFlight.catch(() => {});
  await clearAuthStored();
  await authCancelLogin();
  return { signedIn: false, arch: await getArchPref() };
}

async function setArchRpc({ arch }) {
  await setArchPref(arch);
  return authStatus();
}

// The server captures the oauth cookie and account email automatically after login.
// Polls are short RPCs so the worker can suspend while the user completes 2FA.
async function authBeginLogin({ arch } = {}) {
  arch = arch || await getArchPref();
  if (!['arm64-v8a', 'armeabi-v7a'].includes(arch)) throw new ValidationError('Unknown architecture.');
  await authCancelLogin();
  const saved = await getAuthStored();
  if (saved?.aasToken) {
    try { return await authSignIn({ arch, registerBoth: true }); }
    catch { /* Match the server: open browser sign-in if stored credentials fail. */ }
  }
  const oldCookie = await chrome.cookies.get({ url: GOOGLE_LOGIN_URL, name: 'oauth_token' });
  const loginWindow = await chrome.windows.create({ url: GOOGLE_LOGIN_URL, type: 'popup', width: 480, height: 720 });
  const tab = loginWindow.tabs[0];
  await chrome.storage.session.set({ [LOGIN_STORAGE_KEY]: { arch, tabId: tab.id,
    previousToken: oldCookie?.value || '', startedAt: Date.now() } });
  return { pending: true };
}

let loginPollInFlight = null;
async function authCompleteLogin() {
  if (loginPollInFlight) return loginPollInFlight;
  loginPollInFlight = pollGoogleLogin();
  try { return await loginPollInFlight; }
  finally { loginPollInFlight = null; }
}

async function pollGoogleLogin() {
  const pending = (await chrome.storage.session.get(LOGIN_STORAGE_KEY))[LOGIN_STORAGE_KEY];
  if (!pending) return authStatus();
  if (Date.now() - pending.startedAt > 15 * 60 * 1000) {
    await authCancelLogin();
    throw new AuthError('Google sign-in expired. Start again.');
  }
  try { await chrome.tabs.get(pending.tabId); }
  catch {
    await chrome.storage.session.remove(LOGIN_STORAGE_KEY);
    throw new AuthError('Google sign-in window was closed before sign-in completed.');
  }
  const cookie = await chrome.cookies.get({ url: GOOGLE_LOGIN_URL, name: 'oauth_token' });
  if (!cookie?.value || cookie.value === pending.previousToken) return { pending: true };
  let email;
  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId: pending.tabId },
      func: () => document.querySelector('[data-profile-identifier][data-email]')?.getAttribute('data-email') || null,
    });
    email = results[0]?.result;
  } catch { return { pending: true }; } // Google may be navigating between login steps.
  if (!email) return { pending: true };
  validateAccountEmail(email);
  // Recheck after browser calls in case login was cancelled or replaced meanwhile.
  const current = (await chrome.storage.session.get(LOGIN_STORAGE_KEY))[LOGIN_STORAGE_KEY];
  if (current?.tabId !== pending.tabId || current?.startedAt !== pending.startedAt) return authStatus();
  await chrome.storage.session.remove(LOGIN_STORAGE_KEY);
  try { await chrome.tabs.remove(pending.tabId); } catch { /* already closed */ }
  return authSignIn({ email, arch: pending.arch, token: cookie.value, registerBoth: true });
}

async function authCancelLogin() {
  if (authInFlight) {
    authGeneration++;
    await authInFlight.catch(() => {});
    await clearAuthStored();
  }
  const pending = (await chrome.storage.session.get(LOGIN_STORAGE_KEY))[LOGIN_STORAGE_KEY];
  await chrome.storage.session.remove(LOGIN_STORAGE_KEY);
  if (pending?.tabId != null) {
    try { await chrome.tabs.remove(pending.tabId); } catch { /* already closed */ }
  }
  return { pending: false };
}
