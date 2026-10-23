// 60-play-api.js — /fdfe/details, /fdfe/purchase, /fdfe/delivery.
//
// All requests carry the auth headers built from the stored personal account
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

async function fdfeRequest(method, path, body, options = {}) {
  const arch = options.arch || await getArchPref();
  let auth = await getAuthStored(arch);
  if (!auth) throw new AuthError('Sign in with your Google account first.');
  const { personalDefaults } = await loadProfilesJson();
  if (auth._profileKey !== personalDefaults?.[arch] || !auth.authToken || Date.now() - (auth._obtainedAt || 0) > AUTH_TTL_MS || auth._profileArch !== arch) {
    await authSignIn({ arch, preservePreference: true });
    auth = await getAuthStored(arch);
  }
  await installCoreDnrRules(auth.deviceInfoProvider?.userAgentString);
  for (let attempt = 0; attempt < 2; attempt++) {
    const headers = buildFdfeHeaders(auth);
    if (body) headers['Content-Type'] = 'application/x-www-form-urlencoded';
    const res = await fetch(`${PLAY_BASE}${path}`, { method, headers, body });
    if (res.ok) return new Uint8Array(await res.arrayBuffer());
    if (res.status === 401 && attempt === 0 && options.allowRefresh !== false) {
      broadcast('auth.event', { phase: 'refresh', reason: 'got 401 from ' + path });
      await authSignIn({ arch, preservePreference: true });
      auth = await getAuthStored(arch);
      if (!auth) throw new AuthError('re-auth failed after 401');
      continue;
    }
    throw new PlayApiError(`Play /fdfe${path} → ${res.status}`, res.status);
  }
  throw new PlayApiError(`Play /fdfe${path}: retry exhausted`);
}
const fdfeGet  = (path, options) => fdfeRequest('GET', path, null, options);
const fdfePost = (path, formBody, options) => fdfeRequest('POST', path, formBody, options);

/**
 * Fetch app details from /fdfe/details and shape into a plain object.
 * @param {{packageName:string}} args
 * @returns {Promise<{packageName,title,developerName,versionCode,versionString,installationSize,uploadDate,splitId:string[]}>}
 */
async function appDetails({ packageName, arch, refresh = true }) {
  validatePackageName(packageName);
  arch ||= await getArchPref();
  for (let attempt = 0; attempt < (refresh ? 2 : 1); attempt++) {
    try {
      const bytes = await fdfeGet(`/details?doc=${encodeURIComponent(packageName)}`, { arch, allowRefresh: false });
      const wrapper = pbDecode(bytes, PB_ResponseWrapper);
      const docV2 = wrapper?.payload?.detailsResponse?.docV2;
      if (!docV2?.docid) throw new PlayApiError('App not found or not available for this device/architecture.');
      const paid = docV2.offer?.find((offer) => offer.offerType === 1 && offer.micros > 0n);
      if (paid) throw new GplaydlError(`This app is not free (${paid.formattedAmount || 'paid'}). Only free apps can be downloaded.`, 'PAID_APP');
      const app = docV2.details?.appDetails || {};
      if (!app.versionCode) throw new GplaydlError(`No compatible version of ${docV2.title || packageName} for this device profile/architecture.`, 'INCOMPATIBLE');
      return { packageName: app.packageName || docV2.docid, arch,
        title: docV2.title || '', developerName: app.developerName || '',
        versionCode: app.versionCode, versionString: app.versionString || '',
        installationSize: app.installationSize != null ? Number(app.installationSize) : 0,
        uploadDate: app.uploadDate || '', splitId: app.splitId || [] };
    } catch (err) {
      if (!refresh || attempt > 0 || err.code === 'PAID_APP') throw err;
      broadcast('auth.event', { phase: 'refresh', reason: 'Cached session returned unusable app details' });
      await authSignIn({ arch, preservePreference: true });
    }
  }
}

async function appPurchase({ packageName, versionCode, arch }) {
  validatePackageName(packageName);
  if (!Number.isSafeInteger(versionCode) || versionCode <= 0) throw new ValidationError('No compatible app version to download.');
  await fdfePost('/purchase', `doc=${encodeURIComponent(packageName)}&ot=1&vc=${versionCode}`, { arch });
  return { ok: true };
}

/**
 * Resolve the download URLs (base + splits) + auth cookies for a package.
 * @param {{packageName:string, versionCode:number}} args
 * @returns {Promise<{downloadUrl:string, downloadSize:number, sha1:string,
 *                    cookies:{name:string,value:string}[],
 *                    splits:{name:string, downloadUrl:string, downloadSize:number}[]}>}
 */
async function appDelivery({ packageName, versionCode, arch, refresh = true }) {
  validatePackageName(packageName);
  arch ||= await getArchPref();
  let data;
  try {
    const bytes = await fdfeGet(`/delivery?doc=${encodeURIComponent(packageName)}&ot=1&vc=${versionCode}`, { arch, allowRefresh: false });
    const wrapper = pbDecode(bytes, PB_ResponseWrapper);
    data = wrapper?.payload?.deliveryResponse?.appDeliveryData;
    if (!data?.downloadUrl) throw new PlayApiError('No download URL available. App may require purchase or is region-restricted.');
  } catch (err) {
    if (!refresh) throw err;
    await authSignIn({ arch, preservePreference: true });
    const details = await appDetails({ packageName, arch, refresh: false });
    await appPurchase({ packageName, arch, versionCode: details.versionCode });
    return appDelivery({ packageName, arch, versionCode: details.versionCode, refresh: false });
  }
  return {
    versionCode, arch,
    downloadUrl: data.downloadUrl,
    downloadSize: data.downloadSize != null ? Number(data.downloadSize) : 0,
    sha1: data.sha1 || '',
    cookies: (data.downloadAuthCookie || []).map((c) => ({ name: c.name, value: c.value })),
    splits: (data.splitDeliveryData || []).filter((split) => split.downloadUrl).map((s) => ({
      name: s.name,
      downloadUrl: s.downloadUrl,
      downloadSize: s.downloadSize != null ? Number(s.downloadSize) : 0,
    })),
  };
}
