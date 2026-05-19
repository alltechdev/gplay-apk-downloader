// profile.js — provides bundled device profiles in priority order.
// Loaded from src/profiles.json which was generated from
// gplay-apk-downloader/profiles/*.properties (Aurora Store format).

let cached = null;

async function load() {
  if (cached) return cached;
  const res = await fetch(chrome.runtime.getURL('profiles.json'));
  if (!res.ok) throw new Error(`profiles.json fetch failed: ${res.status}`);
  cached = await res.json();
  return cached;
}

export async function getPriorityProfiles() {
  const data = await load();
  return data.profiles; // already ordered by priority
}

export async function getProfileByKey(key) {
  const data = await load();
  return data.profiles.find((p) => p.key === key)?.profile;
}
