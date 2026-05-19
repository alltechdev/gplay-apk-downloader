// auth.js — anonymous authentication via the AuroraOSS dispenser.
// Mirrors gplay-downloader.py:get_dispenser_auth: POSTs a device profile,
// iterates the priority list until one yields an authToken.

import { getPriorityProfiles } from './profile.js';

const DISPENSER_URL = 'https://auroraoss.com/api/auth';
const STORAGE_KEY = 'gplaydl.auth';
const TOKEN_TTL_MS = 1000 * 60 * 60 * 4; // 4h — dispenser tokens have limited lifetime; we re-auth on first 401.

async function postProfile(profile) {
  const res = await fetch(DISPENSER_URL, {
    method: 'POST',
    headers: {
      'User-Agent': 'com.aurora.store-4.6.1-70',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(profile),
  });
  if (!res.ok) return { ok: false, status: res.status };
  const data = await res.json();
  if (!data?.authToken) return { ok: false, status: res.status, data };
  return { ok: true, data };
}

export async function signIn({ onProgress } = {}) {
  const profiles = await getPriorityProfiles();
  let lastErr = null;
  for (const entry of profiles) {
    const label = entry.profile?.UserReadableName || entry.key;
    onProgress?.({ phase: 'try', key: entry.key, label });
    try {
      const result = await postProfile(entry.profile);
      if (result.ok) {
        const auth = {
          ...result.data,
          _profileKey: entry.key,
          _profileLabel: label,
          _obtainedAt: Date.now(),
        };
        await chrome.storage.local.set({ [STORAGE_KEY]: auth });
        onProgress?.({ phase: 'ok', key: entry.key, label });
        return auth;
      }
      onProgress?.({ phase: 'reject', key: entry.key, label, status: result.status });
    } catch (err) {
      lastErr = err;
      onProgress?.({ phase: 'error', key: entry.key, label, error: String(err?.message || err) });
    }
  }
  throw new Error(lastErr ? `all profiles failed (last: ${lastErr.message})` : 'all profiles rejected by dispenser');
}

export async function getStatus() {
  const obj = await chrome.storage.local.get(STORAGE_KEY);
  const auth = obj?.[STORAGE_KEY];
  if (!auth?.authToken) return { signedIn: false };
  const ageMs = Date.now() - (auth._obtainedAt || 0);
  return {
    signedIn: true,
    profileKey: auth._profileKey,
    profileLabel: auth._profileLabel,
    gsfId: auth.gsfId,
    email: auth.email,
    ageMs,
    stale: ageMs > TOKEN_TTL_MS,
  };
}

export async function signOut() {
  await chrome.storage.local.remove(STORAGE_KEY);
  return { signedIn: false };
}

// Returns the raw auth object for use by Play API calls, or null if signed out.
export async function getAuth() {
  const obj = await chrome.storage.local.get(STORAGE_KEY);
  return obj?.[STORAGE_KEY] || null;
}
