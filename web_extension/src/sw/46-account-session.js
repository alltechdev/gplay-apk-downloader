// Browser port of account_auth.py: oauth cookie -> AAS -> checkin -> Play session.
const ACCOUNT_CALLER_SIG = '38918a453d07199354f8b19af05ec6562ced5788';

async function accountFetch(url, options = {}) {
  const res = await fetch(url, { ...options, credentials: 'omit', redirect: 'error', signal: AbortSignal.timeout(30000) });
  if (!res.ok) throw new AuthError(`Google account request failed (HTTP ${res.status}). Sign in again if your account needs verification.`);
  return res;
}

async function accountTokenRequest(params, app = 'com.google.android.gms') {
  const res = await accountFetch(GOOGLE_AUTH_URL, {
    method: 'POST',
    headers: { app, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(params).toString(),
  });
  const data = {};
  for (const line of (await res.text()).split(/\s+/)) {
    const i = line.indexOf('=');
    if (i > 0) data[line.slice(0, i).toLowerCase()] = line.slice(i + 1);
  }
  // Never surface Google's raw body: it can contain credentials or redirect tokens.
  if (data.error) throw new AuthError('Google rejected the account credentials. Sign in again and complete any verification Google requests.');
  return data;
}

async function exchangeOauthToken(email, oauthToken) {
  // The server's oauth-cookie exchange sends an empty User-Agent.
  await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: [DNR_AUTH_ID], addRules: [dnrAuthRule('')] });
  let data;
  try { data = await accountTokenRequest({
    lang: 'en-US', google_play_services_version: 19629032, sdk_version: 28,
    device_country: 'us', Email: email, service: 'ac2dm', get_accountid: 1,
    ACCESS_TOKEN: 1, callerPkg: 'com.google.android.gms', add_account: 1,
    Token: oauthToken, callerSig: ACCOUNT_CALLER_SIG, droidguard_results: 'null',
  }); } finally {
    await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: [DNR_AUTH_ID], addRules: [dnrAuthRule()] });
  }
  if (!data.token?.startsWith('aas_et/')) throw new AuthError('Google did not return an AAS token. Obtain a fresh oauth_token and try again.');
  return data.token;
}

async function exchangeAasToken(email, aasToken, service, androidId) {
  const data = await accountTokenRequest({
    sdk_version: 28, Email: email, google_play_services_version: 19629032,
    device_country: 'us', lang: 'en', callerSig: ACCOUNT_CALLER_SIG,
    client_sig: ACCOUNT_CALLER_SIG, callerPkg: 'com.google.android.gms', Token: aasToken,
    oauth2_foreground: '1', token_request_options: 'CAA4AVAB', check_email: '1',
    system_partition: '1', service,
    ...(androidId ? { androidId, app: 'com.android.vending' } : {}),
  }, androidId ? 'com.google.android.gms' : 'com.android.vending');
  const token = data.auth || data.token;
  if (!token) throw new AuthError('Google did not return a service token. Sign in again.');
  return token;
}

function accountDevice(profile) {
  const p = Object.fromEntries(Object.entries(profile).map(([k, v]) => [k, String(v).replace(/\\([:=])/g, '$1')]));
  const list = (key) => (p[key] || '').split(',').filter(Boolean);
  const config = {};
  for (const [field, key] of Object.entries({ touchScreen: 'TouchScreen', keyboard: 'Keyboard', navigation: 'Navigation',
    screenLayout: 'ScreenLayout', screenDensity: 'Screen.Density', screenWidth: 'Screen.Width',
    screenHeight: 'Screen.Height', glEsVersion: 'GL.Version' })) config[field] = Number(p[key]);
  Object.assign(config, {
    hasHardKeyboard: p.HasHardKeyboard === 'true', hasFiveWayNavigation: p.HasFiveWayNavigation === 'true',
    nativePlatform: list('Platforms'), systemSharedLibrary: list('SharedLibraries'),
    systemAvailableFeature: list('Features'), systemSupportedLocale: list('Locales'), glExtension: list('GL.Extensions'),
  });
  const build = {
    id: p['Build.FINGERPRINT'], product: p['Build.HARDWARE'], carrier: p['Build.BRAND'],
    radio: p['Build.RADIO'], bootloader: p['Build.BOOTLOADER'], device: p['Build.DEVICE'],
    sdkVersion: Number(p['Build.VERSION.SDK_INT']), model: p['Build.MODEL'], manufacturer: p['Build.MANUFACTURER'],
    buildProduct: p['Build.PRODUCT'], client: p.Client, otaInstalled: false,
    timestamp: Math.floor(Date.now() / 1000), googleServices: Number(p['GSF.version']),
  };
  const uaFields = { api: 3, versionCode: p['Vending.version'], sdk: build.sdkVersion, device: build.device,
    hardware: p['Build.HARDWARE'], product: build.buildProduct, platformVersionRelease: p['Build.VERSION.RELEASE'],
    model: encodeURIComponent(build.model), buildId: p['Build.ID'], isWideScreen: 0, supportedAbis: list('Platforms').join(';') };
  return {
    config,
    userAgent: `Android-Finsky/${p['Vending.versionString']} (${Object.entries(uaFields).map(([k, v]) => `${k}=${v}`).join(',')})`,
    checkin: { id: 0n, checkin: { build, lastCheckinMsec: 0, cellOperator: p.CellOperator,
      simOperator: p.SimOperator, roaming: p.Roaming, userNumber: 0 },
    locale: 'en_US', timeZone: 'America/New_York', version: 3, deviceConfiguration: config, fragment: 0 },
  };
}

async function buildAccountSession(email, aasToken, entry) {
  const device = accountDevice(entry.profile);
  await installCoreDnrRules(device.userAgent);
  const progress = (message) => broadcast('auth.event', { phase: 'progress', message });
  progress('Registering the selected device with Google…');
  const ac2dmToken = await exchangeAasToken(email, aasToken, 'ac2dm');
  const checkin = async (data) => {
    const res = await accountFetch(GOOGLE_CHECKIN_URL, {
      method: 'POST', headers: { 'Content-Type': 'application/x-protobuffer' },
      body: pbEncode(data, PB_AndroidCheckinRequest),
    });
    return pbDecode(await res.arrayBuffer(), PB_AndroidCheckinResponse);
  };
  const first = await checkin(device.checkin);
  if (!first.androidId || !first.securityToken) throw new AuthError('Google device checkin did not return a device ID and security token.');
  const linked = await checkin({ ...device.checkin, id: first.androidId, securityToken: first.securityToken,
    accountCookie: [`[${email}]`, ac2dmToken] });
  const gsfId = first.androidId.toString(16);
  progress('Creating the Google Play session…');
  const authToken = await exchangeAasToken(email, aasToken, 'oauth2:https://www.googleapis.com/auth/googleplay', gsfId);
  const auth = { email, aasToken, authToken, gsfId, accountType: 'personal',
    deviceCheckInConsistencyToken: linked.deviceCheckinConsistencyToken || first.deviceCheckinConsistencyToken || '',
    deviceConfigToken: '', dfeCookie: '',
    deviceInfoProvider: { userAgentString: device.userAgent, mccMnc: entry.profile.CellOperator, device: entry.profile.UserReadableName },
  };
  // Use direct requests here: fdfeRequest's 401 retry would recursively start sign-in.
  const play = async (path, body, contentType) => {
    const res = await accountFetch(`${PLAY_BASE}/${path}`, { method: body ? 'POST' : 'GET',
      headers: { ...buildFdfeHeaders(auth), ...(contentType ? { 'Content-Type': contentType } : {}) }, body });
    return pbDecode(await res.arrayBuffer(), PB_ResponseWrapper);
  };
  try {
    const config = await play('uploadDeviceConfig', pbEncode({ deviceConfiguration: device.config }, PB_UploadDeviceConfigRequest), 'application/x-protobuf');
    auth.deviceConfigToken = config.payload?.uploadDeviceConfigResponse?.uploadDeviceConfigToken || '';
  } catch {
    // Matches account_auth.py: config upload is optional; device checkin is required.
    progress('Device configuration upload failed; continuing with the registered device.');
  }
  progress('Checking Google Play terms…');
  const toc = (await play('toc')).payload?.tocResponse;
  if (!toc) throw new AuthError('Google Play did not return session terms. Try signing in again.');
  if (toc.tosContent && toc.tosToken) {
    await play('acceptTos', new URLSearchParams({ tost: toc.tosToken, toscme: 'false' }).toString(), 'application/x-www-form-urlencoded');
  }
  auth.dfeCookie = toc.cookie || '';
  return auth;
}
