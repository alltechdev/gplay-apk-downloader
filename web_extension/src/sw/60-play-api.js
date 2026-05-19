// 60-play-api.js — /fdfe/details, /fdfe/purchase, /fdfe/delivery.
//
// All requests carry the auth headers built from the stored AuroraOSS
// token. A 401 triggers a single re-sign-in + replay before failing.

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
  let auth = await getAuthStored();
  if (!auth) throw new Error('not signed in');
  for (let attempt = 0; attempt < 2; attempt++) {
    const headers = buildFdfeHeaders(auth);
    if (body) headers['Content-Type'] = 'application/x-www-form-urlencoded';
    const res = await fetch(`${PLAY_BASE}${path}`, { method, headers, body });
    if (res.ok) return new Uint8Array(await res.arrayBuffer());
    if (res.status === 401 && attempt === 0) {
      broadcast('auth.event', { phase: 'refresh', reason: 'got 401 from ' + path });
      await authSignIn();
      auth = await getAuthStored();
      if (!auth) throw new Error('re-auth failed after 401');
      continue;
    }
    throw new Error(`Play /fdfe${path} → ${res.status}`);
  }
  throw new Error(`Play /fdfe${path}: retry exhausted`);
}
const fdfeGet  = (path)         => fdfeRequest('GET',  path, null);
const fdfePost = (path, formBody) => fdfeRequest('POST', path, formBody);

async function appDetails({ packageName }) {
  validatePackageName(packageName);
  const bytes = await fdfeGet(`/details?doc=${encodeURIComponent(packageName)}`);
  const wrapper = pbDecode(bytes, PB_ResponseWrapper);
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
  await fdfePost('/purchase', `doc=${encodeURIComponent(packageName)}&ot=1&vc=${versionCode}`);
  return { ok: true };
}

async function appDelivery({ packageName, versionCode }) {
  validatePackageName(packageName);
  const bytes = await fdfeGet(`/delivery?doc=${encodeURIComponent(packageName)}&ot=1&vc=${versionCode}`);
  const wrapper = pbDecode(bytes, PB_ResponseWrapper);
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
