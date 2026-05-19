// 50-auth.js — AuroraOSS dispenser sign-in + status + sign-out.

function profileArch(entry) {
  return entry.arch === 'armv7' ? 'armeabi-v7a' : 'arm64-v8a';
}

async function postProfile(profile) {
  const res = await fetch(DISPENSER_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(profile),
  });
  if (!res.ok) return { ok: false, status: res.status };
  const data = await res.json().catch(() => null);
  if (!data?.authToken) return { ok: false, status: res.status, data };
  return { ok: true, data };
}

async function authSignIn({ arch } = {}) {
  const { profiles } = await loadProfilesJson();
  const wantedArch = arch || (await getArchPref());
  const matchingByArch = profiles.filter((p) => profileArch(p) === wantedArch);
  const queue = matchingByArch.length > 0 ? matchingByArch : profiles;
  broadcast('auth.event', { phase: 'start', arch: wantedArch });
  let lastErr = null;
  for (const entry of queue) {
    const label = entry.profile?.UserReadableName || entry.key;
    broadcast('auth.event', { phase: 'try', key: entry.key, label, arch: profileArch(entry) });
    try {
      const result = await postProfile(entry.profile);
      if (result.ok) {
        const auth = {
          ...result.data,
          _profileKey: entry.key,
          _profileLabel: label,
          _profileArch: profileArch(entry),
          _obtainedAt: Date.now(),
        };
        await setAuthStored(auth);
        const ua = auth.deviceInfoProvider?.userAgentString;
        if (ua) await installCoreDnrRules(ua);
        broadcast('auth.event', { phase: 'ok', key: entry.key, label });
        broadcast('auth.event', { phase: 'done', profileKey: entry.key, profileLabel: label });
        return authStatus();
      }
      broadcast('auth.event', { phase: 'reject', key: entry.key, label, status: result.status });
    } catch (err) {
      lastErr = err;
      broadcast('auth.event', { phase: 'error', key: entry.key, label, error: String(err?.message || err) });
    }
  }
  broadcast('auth.event', { phase: 'fail' });
  throw new AuthError(lastErr ? `all profiles failed (last: ${lastErr.message})` : 'all profiles rejected by dispenser');
}

async function authStatus() {
  const auth = await getAuthStored();
  const arch = await getArchPref();
  if (!auth?.authToken) return { signedIn: false, arch };
  const ageMs = Date.now() - (auth._obtainedAt || 0);
  return {
    signedIn: true,
    arch,
    profileKey: auth._profileKey,
    profileLabel: auth._profileLabel,
    profileArch: auth._profileArch || 'arm64-v8a',
    gsfId: auth.gsfId,
    email: auth.email,
    ageMs,
    stale: ageMs > AUTH_TTL_MS,
  };
}

async function authSignOut() {
  await clearAuthStored();
  return { signedIn: false, arch: await getArchPref() };
}

async function setArchRpc({ arch }) {
  await setArchPref(arch);
  return authStatus();
}
