// 30-storage.js — chrome.storage wrappers and the in-memory download↔rule map.

async function getAuthStored() {
  const obj = await chrome.storage.local.get(AUTH_STORAGE_KEY);
  return obj?.[AUTH_STORAGE_KEY] || null;
}
async function setAuthStored(auth) {
  await chrome.storage.local.set({ [AUTH_STORAGE_KEY]: auth });
}
async function clearAuthStored() {
  await chrome.storage.local.remove(AUTH_STORAGE_KEY);
}

async function getArchPref() {
  const obj = await chrome.storage.local.get(ARCH_STORAGE_KEY);
  return obj?.[ARCH_STORAGE_KEY] || DEFAULT_ARCH;
}
async function setArchPref(arch) {
  if (arch !== 'arm64-v8a' && arch !== 'armeabi-v7a') throw new ValidationError('unknown arch: ' + arch);
  await chrome.storage.local.set({ [ARCH_STORAGE_KEY]: arch });
}

// download.id → DNR rule id, persisted in chrome.storage.session so a
// SW restart mid-download doesn't orphan rules.
const downloadRuleByDl = new Map();
let dlMapHydrated = false;
async function hydrateDlMap() {
  if (dlMapHydrated) return;
  try {
    const obj = await chrome.storage.session.get(DOWNLOAD_RULE_MAP_KEY);
    const persisted = obj?.[DOWNLOAD_RULE_MAP_KEY] || {};
    for (const [k, v] of Object.entries(persisted)) downloadRuleByDl.set(Number(k), v);
  } catch { /* storage.session unavailable on older Chrome — in-memory only */ }
  dlMapHydrated = true;
}
async function persistDlMap() {
  try {
    const o = {};
    for (const [k, v] of downloadRuleByDl) o[k] = v;
    await chrome.storage.session.set({ [DOWNLOAD_RULE_MAP_KEY]: o });
  } catch { /* best effort */ }
}
