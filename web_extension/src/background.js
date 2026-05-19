// Service worker for the GPlay APK Downloader extension.
//
// Single-file by design: Chrome 144's MV3 module-SW path was unreliable
// in early testing. One self-contained file keeps the loading story
// boring and reliable.
//
// Responsibilities:
//   - toolbar click → open index.html
//   - auth state (AuroraOSS dispenser tokens) in chrome.storage.local
//     - chooses profiles by architecture preference (arm64 / armv7)
//   - declarativeNetRequest rules that set the right User-Agent and strip
//     the extension Origin on Play / dispenser calls (browser-forbidden
//     headers can only be rewritten via DNR)
//   - Play API protobuf calls: /fdfe/details, /fdfe/purchase, /fdfe/delivery
//   - APK downloads via chrome.downloads (cookies attached via DNR)
//     - cleans up per-download DNR rules when chrome.downloads.onChanged
//       reports completion / interruption
//   - sequential bulk downloads from an imported backup list

// =========================================================================
//  Tiny protobuf decoder (inlined from src/modules/pb-decode.js)
// =========================================================================

const PB_STRING = 'string';
const PB_INT32 = 'int32';
const PB_INT64 = 'int64';
const PB_BOOL = 'bool';
const PB_BYTES = 'bytes';
const PB_NESTED = 'nested';

function pbReadVarint(buf, pos) {
  let result = 0n, shift = 0n, byte;
  for (;;) {
    if (pos >= buf.length) throw new Error('pb: truncated varint');
    byte = buf[pos++];
    result |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) break;
    shift += 7n;
    if (shift > 70n) throw new Error('pb: varint too long');
  }
  return [result, pos];
}
function pbSkip(buf, pos, wire) {
  if (wire === 0) return pbReadVarint(buf, pos)[1];
  if (wire === 2) { const [len, p] = pbReadVarint(buf, pos); return p + Number(len); }
  if (wire === 1) return pos + 8;
  if (wire === 5) return pos + 4;
  throw new Error('pb: unknown wire type ' + wire);
}
function pbDecode(buf, schema) {
  if (!(buf instanceof Uint8Array)) buf = new Uint8Array(buf);
  const out = {};
  let pos = 0;
  while (pos < buf.length) {
    const [tag, p1] = pbReadVarint(buf, pos);
    pos = p1;
    const fieldNo = Number(tag) >>> 3;
    const wire = Number(tag) & 7;
    const field = schema[fieldNo];
    if (!field) { pos = pbSkip(buf, pos, wire); continue; }
    let value;
    if (field.type === PB_STRING) {
      const [len, p2] = pbReadVarint(buf, pos);
      const L = Number(len);
      value = new TextDecoder('utf-8').decode(buf.subarray(p2, p2 + L));
      pos = p2 + L;
    } else if (field.type === PB_BYTES) {
      const [len, p2] = pbReadVarint(buf, pos);
      const L = Number(len);
      value = buf.subarray(p2, p2 + L);
      pos = p2 + L;
    } else if (field.type === PB_NESTED) {
      const [len, p2] = pbReadVarint(buf, pos);
      const L = Number(len);
      value = pbDecode(buf.subarray(p2, p2 + L), field.schema);
      pos = p2 + L;
    } else if (field.type === PB_INT32) {
      const [v, p2] = pbReadVarint(buf, pos);
      const n = Number(v & 0xffffffffn);
      value = (n & 0x80000000) ? n - 0x100000000 : n;
      pos = p2;
    } else if (field.type === PB_INT64) {
      const [v, p2] = pbReadVarint(buf, pos);
      value = v;
      pos = p2;
    } else if (field.type === PB_BOOL) {
      const [v, p2] = pbReadVarint(buf, pos);
      value = v !== 0n;
      pos = p2;
    } else {
      throw new Error('pb: unsupported type ' + field.type);
    }
    if (field.repeated) (out[field.name] ||= []).push(value);
    else out[field.name] = value;
  }
  return out;
}

// =========================================================================
//  Play API protobuf schemas (field numbers from gpapi descriptor)
// =========================================================================

const HttpCookieSchema = {
  1: { name: 'name',  type: PB_STRING },
  2: { name: 'value', type: PB_STRING },
};
const SplitDeliveryDataSchema = {
  1: { name: 'name',         type: PB_STRING },
  2: { name: 'downloadSize', type: PB_INT64 },
  5: { name: 'downloadUrl',  type: PB_STRING },
};
const AndroidAppDeliveryDataSchema = {
  1:  { name: 'downloadSize',         type: PB_INT64 },
  2:  { name: 'sha1',                 type: PB_STRING },
  3:  { name: 'downloadUrl',          type: PB_STRING },
  5:  { name: 'downloadAuthCookie',   type: PB_NESTED, schema: HttpCookieSchema, repeated: true },
  15: { name: 'splitDeliveryData',    type: PB_NESTED, schema: SplitDeliveryDataSchema, repeated: true },
};
const DeliveryResponseSchema = {
  1: { name: 'status',          type: PB_INT32 },
  2: { name: 'appDeliveryData', type: PB_NESTED, schema: AndroidAppDeliveryDataSchema },
};
const AppDetailsSchema = {
  1:  { name: 'developerName',    type: PB_STRING },
  3:  { name: 'versionCode',      type: PB_INT32 },
  4:  { name: 'versionString',    type: PB_STRING },
  9:  { name: 'installationSize', type: PB_INT64 },
  14: { name: 'packageName',      type: PB_STRING },
  16: { name: 'uploadDate',       type: PB_STRING },
  25: { name: 'splitId',          type: PB_STRING, repeated: true },
};
const DocumentDetailsSchema = {
  1: { name: 'appDetails', type: PB_NESTED, schema: AppDetailsSchema },
};
const DocV2Schema = {
  1:  { name: 'docid',   type: PB_STRING },
  5:  { name: 'title',   type: PB_STRING },
  13: { name: 'details', type: PB_NESTED, schema: DocumentDetailsSchema },
};
const DetailsResponseSchema = {
  4: { name: 'docV2', type: PB_NESTED, schema: DocV2Schema },
};
const PayloadSchema = {
  2:  { name: 'detailsResponse',  type: PB_NESTED, schema: DetailsResponseSchema },
  21: { name: 'deliveryResponse', type: PB_NESTED, schema: DeliveryResponseSchema },
};
const ResponseWrapperSchema = {
  1: { name: 'payload', type: PB_NESTED, schema: PayloadSchema },
};

// =========================================================================
//  Constants
// =========================================================================

const PAGE_URL = chrome.runtime.getURL('index.html');
const DISPENSER_URL = 'https://auroraoss.com/api/auth';
const PLAY_BASE = 'https://android.clients.google.com/fdfe';
const AUTH_STORAGE_KEY = 'gplaydl.auth';
const ARCH_STORAGE_KEY = 'gplaydl.arch';
const AUTH_TTL_MS = 1000 * 60 * 60 * 4;
const DEFAULT_ARCH = 'arm64-v8a';

const PLAY_FALLBACK_UA = 'Android-Finsky/45.8.21-31 [0] [PR] 747433787 (api=3,versionCode=84582130,sdk=35,device=tegu,hardware=tegu,product=tegu,platformVersionRelease=15,model=Pixel%209a,buildId=BD4A.250405.003,isWideScreen=0,supportedAbis=arm64-v8a)';
const DFE_ENCODED_TARGETS = 'CAESN/qigQYC2AMBFfUbyA7SM5Ij/CvfBoIDgxXrBPsDlQUdMfOLAfoFrwEHgAcBrQYhoA0cGt4MKK0Y2gI';
const DFE_PHENOTYPE = 'H4sIAAAAAAAAAB3OO3KjMAAA0KRNuWXukBkBQkAJ2MhgAZb5u2GCwQZbCH_EJ77QHmgvtDtbv-Z9_H63zXXU0NVPB1odlyGy7751Q3CitlPDvFd8lxhz3tpNmz7P92CFw73zdHU2Ie0Ad2kmR8lxhiErTFLt3RPGfJQHSDy7Clw10bg8kqf2owLokN4SecJTLoSwBnzQSd652_MOf2d1vKBNVedzg4ciPoLz2mQ8efGAgYeLou-l-PXn_7Sna1MfhHuySxt-4esulEDp8Sbq54CPPKjpANW-lkU2IZ0F92LBI-ukCKSptqeq1eXU96LD9nZfhKHdtjSWwJqUm_2r6pMHOxk01saVanmNopjX3YxQafC4iC6T55aRbC8nTI98AF_kItIQAJb5EQxnKTO7TZDWnr01HVPxelb9A2OWX6poidMWl16K54kcu_jhXw-JSBQkVcD_fPsLSZu6joIBAAA';

// =========================================================================
//  declarativeNetRequest — fixed-id dynamic rules
// =========================================================================

const DNR_DISPENSER_ID = 1;
const DNR_FDFE_ID = 2;
const DNR_CDN_ID = 3;
const DNR_DOWNLOAD_ID_MIN = 100;
const DNR_DOWNLOAD_ID_MAX = 9999;
let nextDownloadRuleId = DNR_DOWNLOAD_ID_MIN;
// Map from chrome.downloads id → DNR rule id, so onChanged can clean up.
// Persisted in chrome.storage.session (cleared on browser restart) so SW
// restarts mid-download don't lose the mapping.
const DOWNLOAD_RULE_MAP_KEY = 'gplaydl.downloadRules';
const downloadRuleByDl = new Map();
let dlMapHydrated = false;

async function hydrateDlMap() {
  if (dlMapHydrated) return;
  try {
    const obj = await chrome.storage.session.get(DOWNLOAD_RULE_MAP_KEY);
    const persisted = obj?.[DOWNLOAD_RULE_MAP_KEY] || {};
    for (const [k, v] of Object.entries(persisted)) downloadRuleByDl.set(Number(k), v);
  } catch { /* storage.session unavailable; in-memory only */ }
  dlMapHydrated = true;
}

async function persistDlMap() {
  try {
    const o = {};
    for (const [k, v] of downloadRuleByDl) o[k] = v;
    await chrome.storage.session.set({ [DOWNLOAD_RULE_MAP_KEY]: o });
  } catch { /* best effort */ }
}

function dnrDispenserRule() {
  return {
    id: DNR_DISPENSER_ID,
    priority: 1,
    action: {
      type: 'modifyHeaders',
      requestHeaders: [
        { header: 'User-Agent', operation: 'set', value: 'com.aurora.store-4.6.1-70' },
        { header: 'Origin', operation: 'remove' },
        { header: 'Sec-Fetch-Site', operation: 'remove' },
        { header: 'Sec-Fetch-Mode', operation: 'remove' },
        { header: 'Sec-Fetch-Dest', operation: 'remove' },
        { header: 'Sec-Fetch-User', operation: 'remove' },
      ],
    },
    condition: { urlFilter: '||auroraoss.com/api/auth', resourceTypes: ['xmlhttprequest'] },
  };
}
function dnrFdfeRule(userAgent) {
  return {
    id: DNR_FDFE_ID,
    priority: 1,
    action: {
      type: 'modifyHeaders',
      requestHeaders: [
        { header: 'User-Agent', operation: 'set', value: userAgent || PLAY_FALLBACK_UA },
        { header: 'Origin', operation: 'remove' },
        { header: 'Sec-Fetch-Site', operation: 'remove' },
        { header: 'Sec-Fetch-Mode', operation: 'remove' },
        { header: 'Sec-Fetch-Dest', operation: 'remove' },
        { header: 'Sec-Fetch-User', operation: 'remove' },
      ],
    },
    condition: { urlFilter: '||android.clients.google.com/fdfe', resourceTypes: ['xmlhttprequest'] },
  };
}
function dnrCdnRule() {
  // Strip Origin and Sec-Fetch-* on the Play CDN. Google's CDN doesn't
  // return CORS headers, so without this the page-side fetch fails after
  // /download/by-token redirects to *.gvt1.com.
  return {
    id: DNR_CDN_ID,
    priority: 1,
    action: {
      type: 'modifyHeaders',
      requestHeaders: [
        { header: 'Origin', operation: 'remove' },
        { header: 'Sec-Fetch-Site', operation: 'remove' },
        { header: 'Sec-Fetch-Mode', operation: 'remove' },
        { header: 'Sec-Fetch-Dest', operation: 'remove' },
        { header: 'Sec-Fetch-User', operation: 'remove' },
      ],
    },
    condition: {
      requestDomains: ['gvt1.com', 'googleusercontent.com', 'play.googleapis.com'],
      resourceTypes: ['xmlhttprequest'],
    },
  };
}

async function installCoreDnrRules(playUserAgent) {
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  const removeRuleIds = existing
    .filter((r) => r.id === DNR_DISPENSER_ID || r.id === DNR_FDFE_ID || r.id === DNR_CDN_ID)
    .map((r) => r.id);
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds,
    addRules: [dnrDispenserRule(), dnrFdfeRule(playUserAgent), dnrCdnRule()],
  });
}

async function allocDownloadRuleId() {
  // Reuse rule ids that have no live download attached.
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  const inUse = new Set(existing.filter((r) => r.id >= DNR_DOWNLOAD_ID_MIN && r.id <= DNR_DOWNLOAD_ID_MAX).map((r) => r.id));
  for (let attempts = 0; attempts <= (DNR_DOWNLOAD_ID_MAX - DNR_DOWNLOAD_ID_MIN); attempts++) {
    const id = nextDownloadRuleId;
    nextDownloadRuleId = nextDownloadRuleId >= DNR_DOWNLOAD_ID_MAX ? DNR_DOWNLOAD_ID_MIN : nextDownloadRuleId + 1;
    if (!inUse.has(id) && ![...downloadRuleByDl.values()].includes(id)) return id;
  }
  throw new Error('out of DNR download rule ids');
}

async function applyCookieRule(ruleId, url, cookies) {
  const cookieValue = cookies.map((c) => `${c.name}=${c.value}`).join('; ');
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: [ruleId],
    addRules: [{
      id: ruleId,
      priority: 1,
      action: {
        type: 'modifyHeaders',
        requestHeaders: [
          { header: 'Cookie', operation: 'set', value: cookieValue },
          { header: 'Origin', operation: 'remove' },
        ],
      },
      condition: {
        urlFilter: url,
        resourceTypes: ['xmlhttprequest', 'main_frame', 'sub_frame', 'other'],
      },
    }],
  });
}

async function clearDnrRule(ruleId) {
  if (!ruleId) return;
  try {
    await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: [ruleId], addRules: [] });
  } catch (err) {
    console.warn('clearDnrRule failed for', ruleId, err);
  }
}

chrome.runtime.onInstalled.addListener(() => { installCoreDnrRules().catch((e) => console.error('DNR install:', e)); });
chrome.runtime.onStartup.addListener(() => { installCoreDnrRules().catch((e) => console.error('DNR install:', e)); });
installCoreDnrRules().catch((e) => console.error('DNR install:', e));

// =========================================================================
//  Action: open page in tab
// =========================================================================

chrome.action.onClicked.addListener(async () => {
  const tabs = await chrome.tabs.query({ url: PAGE_URL });
  if (tabs.length > 0) {
    await chrome.tabs.update(tabs[0].id, { active: true });
    if (tabs[0].windowId) await chrome.windows.update(tabs[0].windowId, { focused: true });
  } else {
    await chrome.tabs.create({ url: PAGE_URL });
  }
});

// =========================================================================
//  Download lifecycle: clean up per-download DNR rules when chrome.downloads
//  reports completion / interruption.
// =========================================================================

chrome.downloads.onChanged.addListener(async (delta) => {
  await hydrateDlMap();
  const state = delta?.state?.current;
  if (state === 'in_progress' && delta?.bytesReceived?.current != null) {
    broadcast('download.event', { phase: 'progress', id: delta.id, bytes: delta.bytesReceived.current });
    return;
  }
  if (state !== 'complete' && state !== 'interrupted') return;
  const ruleId = downloadRuleByDl.get(delta.id);
  if (ruleId) {
    downloadRuleByDl.delete(delta.id);
    await persistDlMap();
    await clearDnrRule(ruleId);
  }
  const bytes = delta?.totalBytes?.current ?? delta?.bytesReceived?.current;
  broadcast('download.event', { phase: state, id: delta.id, bytes });
});

// =========================================================================
//  Helpers
// =========================================================================

function broadcast(type, payload) {
  chrome.runtime.sendMessage({ type, payload }).catch(() => {});
}

function validatePackageName(pkg) {
  if (typeof pkg !== 'string') throw new Error('package name must be a string');
  if (!/^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$/.test(pkg)) {
    throw new Error('invalid package name: ' + pkg);
  }
  return pkg;
}

async function loadProfilesJson() {
  const res = await fetch(chrome.runtime.getURL('profiles.json'));
  if (!res.ok) throw new Error(`profiles.json fetch failed: ${res.status}`);
  return res.json();
}

function profileArch(entry) {
  return entry.arch === 'armv7' ? 'armeabi-v7a' : 'arm64-v8a';
}

async function getArchPref() {
  const obj = await chrome.storage.local.get(ARCH_STORAGE_KEY);
  return obj?.[ARCH_STORAGE_KEY] || DEFAULT_ARCH;
}

// =========================================================================
//  Auth — AuroraOSS dispenser
// =========================================================================

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
  // Profiles already in priority order; filter to those matching the
  // requested arch, then fall back to any profile if none match (so we
  // never hang on a bad arch setting).
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
        await chrome.storage.local.set({ [AUTH_STORAGE_KEY]: auth });
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
  throw new Error(lastErr ? `all profiles failed (last: ${lastErr.message})` : 'all profiles rejected by dispenser');
}

async function authStatus() {
  const obj = await chrome.storage.local.get(AUTH_STORAGE_KEY);
  const auth = obj?.[AUTH_STORAGE_KEY];
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
  await chrome.storage.local.remove(AUTH_STORAGE_KEY);
  return { signedIn: false, arch: await getArchPref() };
}

async function getAuth() {
  const obj = await chrome.storage.local.get(AUTH_STORAGE_KEY);
  return obj?.[AUTH_STORAGE_KEY] || null;
}

async function setArch({ arch }) {
  if (arch !== 'arm64-v8a' && arch !== 'armeabi-v7a') throw new Error('unknown arch: ' + arch);
  await chrome.storage.local.set({ [ARCH_STORAGE_KEY]: arch });
  return authStatus();
}

// =========================================================================
//  Play API calls
// =========================================================================

function buildFdfeHeaders(auth) {
  const headers = {
    'Authorization': `Bearer ${auth.authToken}`,
    'X-DFE-Device-Id': auth.gsfId,
    'Accept-Language': 'en-US',
    'X-DFE-Encoded-Targets': DFE_ENCODED_TARGETS,
    'X-DFE-Phenotype': DFE_PHENOTYPE,
    'X-DFE-Client-Id': 'am-android-google',
    'X-DFE-Network-Type': '4',
    'X-DFE-Content-Filters': '',
    'X-DFE-Cookie': auth.dfeCookie || '',
    'X-DFE-UserLanguages': 'en_US',
    'X-DFE-Request-Params': 'timeoutMs=4000',
    'X-DFE-No-Prefetch': 'true',
  };
  if (auth.deviceCheckInConsistencyToken) headers['X-DFE-Device-Checkin-Consistency-Token'] = auth.deviceCheckInConsistencyToken;
  if (auth.deviceConfigToken) headers['X-DFE-Device-Config-Token'] = auth.deviceConfigToken;
  if (auth.deviceInfoProvider?.mccMnc) headers['X-DFE-MCCMNC'] = auth.deviceInfoProvider.mccMnc;
  return headers;
}

async function fdfeRequest(method, path, body) {
  let auth = await getAuth();
  if (!auth) throw new Error('not signed in');
  for (let attempt = 0; attempt < 2; attempt++) {
    const headers = buildFdfeHeaders(auth);
    if (body) headers['Content-Type'] = 'application/x-www-form-urlencoded';
    const res = await fetch(`${PLAY_BASE}${path}`, { method, headers, body });
    if (res.ok) return new Uint8Array(await res.arrayBuffer());
    if (res.status === 401 && attempt === 0) {
      broadcast('auth.event', { phase: 'refresh', reason: 'got 401 from ' + path });
      await authSignIn();
      auth = await getAuth();
      if (!auth) throw new Error('re-auth failed after 401');
      continue;
    }
    throw new Error(`Play /fdfe${path} → ${res.status}`);
  }
  throw new Error(`Play /fdfe${path}: retry exhausted`);
}
async function fdfeGet(_auth, path) { return fdfeRequest('GET', path, null); }
async function fdfePost(_auth, path, formBody) { return fdfeRequest('POST', path, formBody); }

async function appDetails({ packageName }) {
  validatePackageName(packageName);
  const bytes = await fdfeGet(null, `/details?doc=${encodeURIComponent(packageName)}`);
  const wrapper = pbDecode(bytes, ResponseWrapperSchema);
  const docV2 = wrapper?.payload?.detailsResponse?.docV2;
  if (!docV2?.docid) throw new Error(`no docV2 in response for ${packageName}`);
  const app = docV2.details?.appDetails || {};
  return {
    packageName: app.packageName || docV2.docid,
    title: docV2.title || '',
    developerName: app.developerName || '',
    versionCode: app.versionCode || 0,
    versionString: app.versionString || '',
    installationSize: app.installationSize != null ? Number(app.installationSize) : 0,
    uploadDate: app.uploadDate || '',
    splitId: app.splitId || [],
  };
}

async function appPurchase({ packageName, versionCode }) {
  validatePackageName(packageName);
  const body = `doc=${encodeURIComponent(packageName)}&ot=1&vc=${versionCode}`;
  await fdfePost(null, '/purchase', body);
  return { ok: true };
}

async function appDelivery({ packageName, versionCode }) {
  validatePackageName(packageName);
  const bytes = await fdfeGet(
    null,
    `/delivery?doc=${encodeURIComponent(packageName)}&ot=1&vc=${versionCode}`,
  );
  const wrapper = pbDecode(bytes, ResponseWrapperSchema);
  const data = wrapper?.payload?.deliveryResponse?.appDeliveryData;
  if (!data?.downloadUrl) {
    const status = wrapper?.payload?.deliveryResponse?.status;
    throw new Error(`no downloadUrl (status=${status}); the app may need purchase/license`);
  }
  return {
    downloadUrl: data.downloadUrl,
    downloadSize: data.downloadSize != null ? Number(data.downloadSize) : 0,
    sha1: data.sha1 || '',
    cookies: (data.downloadAuthCookie || []).map((c) => ({ name: c.name, value: c.value })),
    splits: (data.splitDeliveryData || []).map((s) => ({
      name: s.name,
      downloadUrl: s.downloadUrl,
      downloadSize: s.downloadSize != null ? Number(s.downloadSize) : 0,
    })),
  };
}

// =========================================================================
//  Downloads
// =========================================================================

function sanitizeFilenameSegment(s) {
  return String(s).replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 200);
}

async function queueDownloadFile({ url, cookies, filename }) {
  await hydrateDlMap();
  const ruleId = await allocDownloadRuleId();
  await applyCookieRule(ruleId, url, cookies);
  const id = await chrome.downloads.download({
    url,
    filename,
    saveAs: false,
    conflictAction: 'uniquify',
  });
  downloadRuleByDl.set(id, ruleId);
  await persistDlMap();
  return { id, ruleId, filename };
}

async function appDownload({ packageName, versionCode }) {
  validatePackageName(packageName);
  broadcast('download.event', { phase: 'purchase', packageName, versionCode });
  await appPurchase({ packageName, versionCode });
  broadcast('download.event', { phase: 'delivery', packageName, versionCode });
  const delivery = await appDelivery({ packageName, versionCode });

  const dirPrefix = `gplaydl/${sanitizeFilenameSegment(packageName)}-${versionCode}`;
  const files = [{ kind: 'base', name: 'base.apk', url: delivery.downloadUrl, size: delivery.downloadSize }];
  delivery.splits.forEach((s, i) => {
    const baseName = sanitizeFilenameSegment(s.name || `split${i}`);
    files.push({ kind: 'split', name: `${baseName}.apk`, url: s.downloadUrl, size: s.downloadSize });
  });

  const queued = [];
  for (const f of files) {
    broadcast('download.event', { phase: 'start', packageName, file: f.name, url: f.url, size: f.size });
    const q = await queueDownloadFile({ url: f.url, cookies: delivery.cookies, filename: `${dirPrefix}/${f.name}` });
    queued.push({ id: q.id, file: f.name, ruleId: q.ruleId });
    broadcast('download.event', { phase: 'queued', packageName, file: f.name, id: q.id });
  }
  return { dirPrefix, files: queued };
}

// Used by the extension page when an ADB device is connected: same as
// app.download up to delivery, but instead of scheduling chrome.downloads
// we just install per-URL DNR cookie rules and hand the URLs back to the
// page. The page then `fetch()`s each URL (cookies attached automatically)
// and pipes the blobs into gplaydlAdb.installSplit. Page must call
// app.releaseRules with the returned ruleIds when done.
async function appPrepareInstall({ packageName, versionCode }) {
  validatePackageName(packageName);
  broadcast('download.event', { phase: 'purchase', packageName, versionCode });
  await appPurchase({ packageName, versionCode });
  broadcast('download.event', { phase: 'delivery', packageName, versionCode });
  const delivery = await appDelivery({ packageName, versionCode });
  const files = [{ kind: 'base', name: 'base.apk', url: delivery.downloadUrl, size: delivery.downloadSize }];
  delivery.splits.forEach((s, i) => {
    const baseName = sanitizeFilenameSegment(s.name || `split${i}`);
    files.push({ kind: 'split', name: `${baseName}.apk`, url: s.downloadUrl, size: s.downloadSize });
  });
  const ruleIds = [];
  for (const f of files) {
    const ruleId = await allocDownloadRuleId();
    await applyCookieRule(ruleId, f.url, delivery.cookies);
    f.ruleId = ruleId;
    ruleIds.push(ruleId);
  }
  return { packageName, versionCode, files, ruleIds };
}

async function releaseRules({ ruleIds }) {
  if (!Array.isArray(ruleIds)) throw new Error('ruleIds must be an array');
  for (const id of ruleIds) await clearDnrRule(id);
  return { released: ruleIds.length };
}

let bulkAbort = false;

// Search the Play Store by scraping play.google.com/store/search HTML.
// Mirrors server.py:/api/search (Method 1 + Method 2 regex extraction).
async function appSearch({ query }) {
  if (typeof query !== 'string' || !query.trim()) throw new Error('query required');
  if (query.length > 200) throw new Error('query too long');
  const res = await fetch('https://play.google.com/store/search?q=' + encodeURIComponent(query) + '&c=apps');
  if (!res.ok) throw new Error('Play search HTTP ' + res.status);
  const html = await res.text();
  const results = [];
  const seen = new Set();
  const decodeHtml = (s) => s.replace(/&amp;/g, '&').replace(/&#39;/g, "'").replace(/&quot;/g, '"');
  const upgradeIcon = (url) => url.replace(/=s\d+/, '=s128').replace(/=w\d+/, '=s128');

  // Method 1a: featured app
  const featured = html.match(/href="\/store\/apps\/details\?id=([^"&]+)"[^>]*>[\s\S]*?<img[^>]*src="(https:\/\/play-lh\.googleusercontent\.com\/[^"]+)"[^>]*>[\s\S]*?<div class="vWM94c">([^<]+)<\/div>/);
  if (featured) {
    const [, pkg, icon, title] = featured;
    if (!seen.has(pkg)) { seen.add(pkg); results.push({ package: pkg, title: decodeHtml(title), icon: upgradeIcon(icon) }); }
  }

  // Method 1b: related apps
  const rel = /href="\/store\/apps\/details\?id=([^"&]+)"[^>]*>[\s\S]*?<img[^>]*src="(https:\/\/play-lh\.googleusercontent\.com\/[^"=]+=[sw]\d+[^"]*)"[^>]*>[\s\S]*?class="Epkrse\s*">([^<]+)<\/div>/g;
  let m;
  while ((m = rel.exec(html)) !== null && results.length < 10) {
    const [, pkg, icon, title] = m;
    if (seen.has(pkg)) continue;
    seen.add(pkg);
    results.push({ package: pkg, title: decodeHtml(title), icon: upgradeIcon(icon) });
  }

  // Method 2: JSON-embedded packages.
  if (results.length < 3) {
    const pkgRe = /\[\["(com\.[a-zA-Z0-9_.]+)",7\],\[null,2/g;
    let pm;
    while ((pm = pkgRe.exec(html)) !== null && results.length < 10) {
      const pkg = pm[1];
      if (seen.has(pkg)) continue;
      const titleRe = new RegExp('\\[\\["' + pkg.replace(/[.]/g, '\\.') + '",7\\][\\s\\S]*?\\],"([^"]+)",\\["[0-9.]+",\\s*[0-9.]+', '');
      const titleM = html.match(titleRe);
      const iconRe = new RegExp('\\[\\["' + pkg.replace(/[.]/g, '\\.') + '",7\\],\\[null,2,(?:null|\\[[0-9]+,[0-9]+\\]),\\[null,null,"(https://play-lh\\.googleusercontent\\.com/[^"]+)"\\]', '');
      const iconM = html.match(iconRe);
      seen.add(pkg);
      results.push({
        package: pkg,
        title: titleM ? titleM[1].replace(/\\u0026/g, '&').replace(/\\u0027/g, "'") : pkg,
        icon: iconM ? upgradeIcon(iconM[1]) : '',
      });
    }
  }
  return { results };
}

async function appDownloadList({ packages }) {
  if (!Array.isArray(packages) || packages.length === 0) throw new Error('packages must be a non-empty array');
  bulkAbort = false;
  const results = [];
  for (let i = 0; i < packages.length; i++) {
    if (bulkAbort) {
      broadcast('download.event', { phase: 'list.aborted', completed: results.length, remaining: packages.length - i });
      break;
    }
    const pkg = packages[i];
    try {
      validatePackageName(pkg);
      broadcast('download.event', { phase: 'list.start', index: i + 1, total: packages.length, packageName: pkg });
      const details = await appDetails({ packageName: pkg });
      const queued = await appDownload({ packageName: pkg, versionCode: details.versionCode });
      results.push({ packageName: pkg, ok: true, queued: queued.files.map((q) => q.file) });
      broadcast('download.event', { phase: 'list.itemDone', packageName: pkg, files: queued.files.length });
    } catch (err) {
      results.push({ packageName: pkg, ok: false, error: String(err?.message || err) });
      broadcast('download.event', { phase: 'list.itemFail', packageName: pkg, error: String(err?.message || err) });
    }
  }
  broadcast('download.event', { phase: 'list.done', results });
  return { results, aborted: bulkAbort };
}

function abortBulk() { bulkAbort = true; return { ok: true }; }

async function cancelDownload({ id }) {
  if (typeof id !== 'number') throw new Error('id must be number');
  await hydrateDlMap();
  await chrome.downloads.cancel(id);
  const ruleId = downloadRuleByDl.get(id);
  if (ruleId) { downloadRuleByDl.delete(id); await persistDlMap(); await clearDnrRule(ruleId); }
  return { ok: true };
}

async function showDownload({ id }) {
  if (typeof id !== 'number') throw new Error('id must be number');
  await chrome.downloads.show(id);
  return { ok: true };
}

// =========================================================================
//  RPC dispatch
// =========================================================================

const RPC = {
  'auth.status':     () => authStatus(),
  'auth.signIn':     (p) => authSignIn(p),
  'auth.signOut':    () => authSignOut(),
  'arch.set':        (p) => setArch(p),
  'app.details':     (p) => appDetails(p),
  'app.delivery':    (p) => appDelivery(p),
  'app.download':       (p) => appDownload(p),
  'app.downloadList':   (p) => appDownloadList(p),
  'app.abortBulk':      () => abortBulk(),
  'app.cancelDownload': (p) => cancelDownload(p),
  'app.showDownload':   (p) => showDownload(p),
  'app.prepareInstall': (p) => appPrepareInstall(p),
  'app.releaseRules':   (p) => releaseRules(p),
  'app.search':         (p) => appSearch(p),
};

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === 'auth.event' || msg?.type === 'download.event') return false; // broadcasts
  const fn = RPC[msg?.type];
  if (!fn) { sendResponse({ error: `unknown rpc: ${msg?.type}` }); return false; }
  Promise.resolve(fn(msg.payload || {}))
    .then((result) => sendResponse({ result }))
    .catch((err) => sendResponse({ error: String(err?.message || err) }));
  return true;
});
