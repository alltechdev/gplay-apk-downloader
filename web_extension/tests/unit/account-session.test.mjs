import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { loadSw } from '../helpers/sw-load.mjs';

const profiles = JSON.parse(readFileSync(new URL('../../src/profiles.json', import.meta.url)));
const files = ['00-config.js', '05-logger.js', '10-utils.js', '15-errors.js', '20-pb.js', '30-storage.js', '40-dnr.js',
  '45-account-proto.js', '46-account-session.js', '50-auth.js', '60-play-api.js'];
function setup() {
  const local = {}, session = {}, calls = [], events = [], rules = [];
  let cookie = null, closed = [], sw, detectedEmail = 'test@example.com';
  const storage = (data) => ({ get: async (key) => ({ [key]: data[key] }),
    set: async (value) => Object.assign(data, value), remove: async (key) => { delete data[key]; } });
  const chrome = {
    runtime: { getURL: (path) => `chrome-extension://test/${path}`, sendMessage: async (msg) => { events.push(msg); } },
    storage: { local: storage(local), session: storage(session) },
    cookies: { get: async () => cookie },
    windows: { create: async () => ({ tabs: [{ id: 7 }] }) },
    scripting: { executeScript: async ({ target }) => { assert.equal(target.tabId, 7); return [{ result: detectedEmail }]; } },
    tabs: { get: async () => ({ id: 7 }), remove: async (id) => { closed.push(id); } },
    declarativeNetRequest: { getDynamicRules: async () => rules, updateDynamicRules: async ({ removeRuleIds, addRules }) => {
      for (const id of removeRuleIds) { const i = rules.findIndex((r) => r.id === id); if (i >= 0) rules.splice(i, 1); }
      rules.push(...addRules);
    } },
  };
  let fail = null;
  const fetch = async (url, opts = {}) => {
    calls.push({ url, ...opts });
    if (fail) { const result = await fail(url, opts); if (result) return result; }
    if (url.endsWith('profiles.json')) return { ok: true, json: async () => profiles };
    if (url.endsWith('/auth')) {
      const params = new URLSearchParams(opts.body);
      return new Response(params.has('ACCESS_TOKEN') ? 'Token=aas_et/test\nEmail=test@example.com'
        : params.get('service') === 'ac2dm' ? 'Auth=ac2dm-token' : 'Auth=play-token');
    }
    if (url.endsWith('/checkin')) return new Response(sw.pbEncode({ androidId: 0xfedcba9876543210n,
      securityToken: 0xdeadbeefabcdef01n, deviceCheckinConsistencyToken: 'consistent' }, sw.PB_AndroidCheckinResponse));
    if (url.endsWith('/uploadDeviceConfig')) return new Response(sw.pbEncode({ payload: {
      uploadDeviceConfigResponse: { uploadDeviceConfigToken: 'config-token' } } }, sw.PB_ResponseWrapper));
    if (url.endsWith('/toc')) return new Response(sw.pbEncode({ payload: { tocResponse: {
      tosContent: 'Terms', tosToken: 'terms-token', cookie: 'dfe-cookie' } } }, sw.PB_ResponseWrapper));
    if (url.endsWith('/purchase')) return new Response(new Uint8Array());
    if (url.endsWith('/acceptTos')) return new Response(new Uint8Array());
    if (url.includes('/details')) return new Response(new Uint8Array());
    throw new Error('Unexpected URL ' + url);
  };
  sw = loadSw(files, ['authSignIn', 'authSignOut', 'authStatus', 'authBeginLogin', 'authCompleteLogin', 'authCancelLogin',
    'pbEncode', 'pbDecode', 'PB_AndroidCheckinResponse', 'PB_AndroidCheckinRequest', 'PB_ResponseWrapper',
    'PB_UploadDeviceConfigRequest', 'appDetails', 'appDelivery', 'appPurchase', 'fdfeRequest', 'getAuthStored', 'installCoreDnrRules'],
  { chrome, fetch, URLSearchParams, AbortSignal, console });
  return { sw, local, session, calls, events, rules, closed, setEmail: (v) => { detectedEmail = v; }, setCookie: (v) => { cookie = v; }, setFailure: (fn) => { fail = fn; } };
}

test('personal login follows server exchanges, two checkins, config upload and terms acceptance', async () => {
  const { sw, local, calls, events } = setup();
  const status = await sw.authSignIn({ email: 'test@example.com', token: 'oauth2_4/single-use', arch: 'arm64-v8a' });
  assert.equal(status.signedIn, true);
  assert.equal(status.email, 'test@example.com');
  assert.equal(status.gsfId, 'fedcba9876543210');
  assert.equal(status.aasToken, undefined);
  const authCalls = calls.filter((c) => c.url.endsWith('/auth'));
  assert.equal(authCalls.length, 3);
  const oauth = new URLSearchParams(authCalls[0].body);
  assert.equal(oauth.get('ACCESS_TOKEN'), '1');
  assert.equal(oauth.get('add_account'), '1');
  assert.equal(oauth.get('Token'), 'oauth2_4/single-use');
  const play = new URLSearchParams(authCalls[2].body);
  assert.equal(play.get('androidId'), 'fedcba9876543210');
  assert.equal(play.get('service'), 'oauth2:https://www.googleapis.com/auth/googleplay');
  assert.equal(play.get('app'), 'com.android.vending');
  const checkins = calls.filter((c) => c.url.endsWith('/checkin'));
  assert.equal(checkins.length, 2);
  const second = sw.pbDecode(checkins[1].body, sw.PB_AndroidCheckinRequest);
  assert.equal(BigInt.asUintN(64, second.id), 0xfedcba9876543210n);
  assert.equal(second.securityToken, 0xdeadbeefabcdef01n);
  assert.deepEqual(Array.from(second.accountCookie), ['[test@example.com]', 'ac2dm-token']);
  assert.equal(second.checkin.build.device, 'tegu');
  assert.deepEqual(Array.from(second.deviceConfiguration.nativePlatform), ['arm64-v8a']);
  const stored = local['gplaydl.auth'];
  assert.equal(stored.aasToken, 'aas_et/test');
  assert.equal(stored.deviceConfigToken, 'config-token');
  assert.equal(stored.dfeCookie, 'dfe-cookie');
  assert.ok(calls.some((c) => c.url.endsWith('/acceptTos') && c.body === 'tost=terms-token&toscme=false'));
  assert.ok(calls.every((c) => !c.url.includes('aurora')));
  assert.ok(!JSON.stringify(events).includes('single-use'));
  assert.ok(!JSON.stringify(events).includes('aas_et/'));
});

test('fixed64 uses exact little endian wire representation and rejects truncation', () => {
  const { sw } = setup();
  const bytes = sw.pbEncode({ androidId: 0xfedcba9876543210n }, sw.PB_AndroidCheckinResponse);
  assert.deepEqual([...bytes], [0x39, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe]);
  assert.equal(sw.pbDecode(bytes, sw.PB_AndroidCheckinResponse).androidId, 0xfedcba9876543210n);
  assert.throws(() => sw.pbDecode(bytes.slice(0, 6), sw.PB_AndroidCheckinResponse), /fixed64/);
});

test('AAS reuse refreshes sessions for both architectures without requesting an oauth cookie', async () => {
  const { sw, calls } = setup();
  await sw.authSignIn({ email: 'test@example.com', token: 'aas_et/test' });
  const status = await sw.authSignIn({ arch: 'armeabi-v7a' });
  assert.equal(status.profileArch, 'armeabi-v7a');
  const checkins = calls.filter((c) => c.url.endsWith('/checkin'));
  const last = sw.pbDecode(checkins.at(-1).body, sw.PB_AndroidCheckinRequest);
  assert.ok(last.deviceConfiguration.nativePlatform.includes('armeabi-v7a'));
  assert.ok(calls.filter((c) => c.url.endsWith('/auth')).every((c) => !new URLSearchParams(c.body).has('ACCESS_TOKEN')));
});

test('failed checkin retains AAS for retry, but does not report signed in', async () => {
  const { sw, setFailure, local } = setup();
  setFailure((url) => url.endsWith('/checkin') ? new Response('', { status: 503 }) : null);
  await assert.rejects(sw.authSignIn({ email: 'test@example.com', token: 'oauth2_4/test' }), /HTTP 503/);
  assert.equal((await sw.authStatus()).signedIn, false);
  assert.equal((await sw.authStatus()).canRetry, true);
  assert.equal(local['gplaydl.auth'].aasToken, 'aas_et/test');
  setFailure(null);
  assert.equal((await sw.authSignIn()).signedIn, true);
});

test('Google rejection never leaks its raw response or secret values', async () => {
  const { sw, setFailure, local, events } = setup();
  setFailure((url) => url.endsWith('/auth') ? new Response('Error=BadAuthentication\nToken=SECRET') : null);
  await assert.rejects(sw.authSignIn({ email: 'test@example.com', token: 'oauth2_4/SECRET' }), (err) => {
    assert.match(err.message, /Google rejected/); assert.ok(!err.message.includes('SECRET')); return true;
  });
  assert.equal(local['gplaydl.auth'], undefined);
  assert.ok(!JSON.stringify(events).includes('SECRET'));
});

test('anonymous cache is deleted and never used for Play requests', async () => {
  const { sw, local, calls } = setup();
  local['gplaydl.auth'] = { authToken: 'old-anonymous', gsfId: '123' };
  await assert.rejects(sw.fdfeRequest('GET', '/details?doc=com.test', null), /Sign in/);
  assert.equal(local['gplaydl.auth'], undefined);
  assert.equal(calls.length, 0);
});

test('401 triggers exactly one refresh with saved AAS and retries Play', async () => {
  const { sw, setFailure, calls } = setup();
  await sw.authSignIn({ email: 'test@example.com', token: 'aas_et/test' });
  let attempts = 0;
  setFailure((url) => url.includes('/details') && ++attempts === 1 ? new Response('', { status: 401 }) : null);
  await sw.fdfeRequest('GET', '/details?doc=com.test', null);
  assert.equal(attempts, 2);
  assert.equal(calls.filter((c) => c.url.endsWith('/checkin')).length, 4);
  setFailure((url) => url.includes('/details') ? new Response('', { status: 401 }) : null);
  await assert.rejects(sw.fdfeRequest('GET', '/details?doc=com.test', null), /401/);
});

test('browser login ignores stale cookies; fresh cookie completes and cleans up', async () => {
  const { sw, setCookie, session, closed } = setup();
  setCookie({ value: 'oauth2_4/old' });
  await sw.authBeginLogin({ email: 'test@example.com', arch: 'arm64-v8a' });
  assert.equal((await sw.authStatus()).pendingLogin, true);
  assert.equal((await sw.authCompleteLogin()).pending, true);
  setCookie({ value: 'oauth2_4/new' });
  assert.equal((await sw.authCompleteLogin()).signedIn, true);
  assert.equal(session['gplaydl.pendingLogin'], undefined);
  assert.deepEqual(closed, [7]);
});

test('expired login, cancel, and sign-out clear pending login and credentials', async () => {
  const { sw, session, local } = setup();
  await sw.authBeginLogin({ email: 'test@example.com', arch: 'arm64-v8a' });
  session['gplaydl.pendingLogin'].startedAt = 0;
  await assert.rejects(sw.authCompleteLogin(), /expired/);
  assert.equal(session['gplaydl.pendingLogin'], undefined);
  await sw.authSignIn({ email: 'test@example.com', token: 'aas_et/test' });
  await sw.authBeginLogin({ email: 'test@example.com', arch: 'arm64-v8a' });
  await sw.authSignOut();
  assert.equal(local['gplaydl.auth'], undefined);
  assert.equal(session['gplaydl.pendingLogin'], undefined);
});

test('DNR replaces old rule 1 with Google-only rules; manifest has no Aurora host', async () => {
  const { sw, rules } = setup();
  rules.push({ id: 1, condition: { urlFilter: '||auroraoss.com/api/auth' } });
  await sw.installCoreDnrRules('profile-UA');
  assert.equal(rules.length, 5);
  assert.ok(!JSON.stringify(rules).includes('aurora'));
  assert.ok(rules.some((r) => r.condition.urlFilter?.includes('/checkin')));
  const manifest = JSON.parse(readFileSync(new URL('../../src/manifest.json', import.meta.url)));
  assert.ok(!manifest.host_permissions.some((host) => host.includes('aurora')));
  assert.ok(manifest.permissions.includes('cookies'));
});

test('expired sessions refresh before the next Play request', async () => {
  const { sw, local, calls } = setup();
  await sw.authSignIn({ email: 'test@example.com', token: 'aas_et/test' });
  local['gplaydl.auth']._obtainedAt = 0;
  local['gplaydl.auth']._sessions['arm64-v8a']._obtainedAt = 0;
  const before = calls.length;
  await sw.fdfeRequest('GET', '/details?doc=com.test', null);
  const next = calls.slice(before).filter((c) => !c.url.endsWith('profiles.json'));
  assert.ok(next[0].url.endsWith('/auth'));
  assert.ok(next.at(-1).url.includes('/details'));
});

test('sign-out during a refresh cannot restore credentials afterward', async () => {
  const { sw, setFailure, local } = setup();
  await sw.authSignIn({ email: 'test@example.com', token: 'aas_et/test' });
  let release, started;
  const waiting = new Promise((r) => { started = r; });
  const gate = new Promise((r) => { release = r; });
  let held = false;
  setFailure(async (url) => {
    if (!held && url.endsWith('/checkin')) { held = true; started(); await gate; }
    return null;
  });
  const refresh = sw.authSignIn();
  await waiting;
  const signOut = sw.authSignOut();
  release();
  await assert.rejects(refresh, /cancelled/);
  await signOut;
  assert.equal(local['gplaydl.auth'], undefined);
});

test('page and service worker protobuf decoders agree on exact fixed64 values', async () => {
  const { decode } = await import('../../src/modules/pb-decode.js');
  const { sw } = setup();
  const bytes = Uint8Array.from([0x39, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe]);
  assert.equal(decode(bytes, sw.PB_AndroidCheckinResponse).androidId,
    sw.pbDecode(bytes, sw.PB_AndroidCheckinResponse).androidId);
});


test('browser sign-in detects email automatically and waits for the post-login page', async () => {
  const { sw, setCookie, setEmail, session, calls } = setup();
  await sw.authBeginLogin({ arch: 'arm64-v8a' });
  assert.equal(session['gplaydl.pendingLogin'].email, undefined);
  setCookie({ value: 'oauth2_4/fresh' });
  setEmail(null);
  assert.equal((await sw.authCompleteLogin()).pending, true);
  assert.equal(calls.length, 0, 'do not consume the cookie before detecting the email');
  setEmail('detected@example.com');
  const status = await sw.authCompleteLogin();
  assert.equal(status.email, 'detected@example.com');
  assert.equal(status.signedIn, true);
});


test('server defaults: Pixel 9a and newest ARMv7 Samsung A13, cached separately', async () => {
  const { sw, local, calls } = setup();
  const status = await sw.authSignIn({ email: 'test@example.com', token: 'aas_et/test', registerBoth: true });
  assert.equal(status.profileKey, 'Pv');
  assert.equal(local['gplaydl.auth']._sessions['arm64-v8a']._profileKey, 'Pv');
  assert.equal(local['gplaydl.auth']._sessions['armeabi-v7a']._profileKey, 'Gj');
  const checkins = calls.filter((c) => c.url.endsWith('/checkin'));
  assert.equal(checkins.length, 4);
  const armv7 = sw.pbDecode(checkins[2].body, sw.PB_AndroidCheckinRequest);
  assert.equal(armv7.checkin.build.sdkVersion, 33);
  assert.deepEqual(Array.from(armv7.deviceConfiguration.nativePlatform), ['armeabi-v7a', 'armeabi']);
  const arm64 = await sw.getAuthStored('arm64-v8a');
  const v7 = await sw.getAuthStored('armeabi-v7a');
  assert.equal(arm64._profileKey, 'Pv');
  assert.equal(v7._profileKey, 'Gj');
  await sw.authSignOut();
  assert.equal(local['gplaydl.auth'], undefined);
});

test('failed secondary registration keeps the primary architecture usable', async () => {
  const { sw, setFailure } = setup();
  let checkins = 0;
  setFailure((url) => url.endsWith('/checkin') && ++checkins > 2 ? new Response('', { status: 503 }) : null);
  const status = await sw.authSignIn({ email: 'test@example.com', token: 'aas_et/test', registerBoth: true });
  assert.equal(status.signedIn, true);
  assert.equal(status.profileKey, 'Pv');
  assert.ok((await sw.getAuthStored('arm64-v8a')).authToken);
  assert.equal((await sw.getAuthStored('armeabi-v7a')).authToken, undefined);
});

test('switching ABI uses its own cached token without another registration', async () => {
  const { sw, local, calls } = setup();
  await sw.authSignIn({ email: 'test@example.com', token: 'aas_et/test', registerBoth: true });
  local['gplaydl.auth']._sessions['arm64-v8a'].authToken = 'arm64-token';
  local['gplaydl.auth']._sessions['armeabi-v7a'].authToken = 'armv7-token';
  const before = calls.filter((c) => c.url.endsWith('/checkin')).length;
  await sw.fdfeRequest('GET', '/details?doc=com.test', null, { arch: 'armeabi-v7a' });
  assert.equal(calls.at(-1).headers.Authorization, 'Bearer armv7-token');
  await sw.fdfeRequest('GET', '/details?doc=com.test', null, { arch: 'arm64-v8a' });
  assert.equal(calls.at(-1).headers.Authorization, 'Bearer arm64-token');
  assert.equal(calls.filter((c) => c.url.endsWith('/checkin')).length, before);
});

function detailsResponse(sw, versionCode, offer) {
  return new Response(sw.pbEncode({ payload: { detailsResponse: { docV2: {
    docid: 'com.test.app', title: 'Test app', offer,
    details: { appDetails: { versionCode, packageName: 'com.test.app' } },
  } } } }, sw.PB_ResponseWrapper));
}

test('zero-version details refresh the personal session once before retrying', async () => {
  const { sw, setFailure, calls } = setup();
  await sw.authSignIn({ email: 'test@example.com', token: 'aas_et/test' });
  let details = 0;
  setFailure((url) => url.includes('/details') ? detailsResponse(sw, ++details === 1 ? 0 : 123) : null);
  const result = await sw.appDetails({ packageName: 'com.test.app' });
  assert.equal(result.versionCode, 123);
  assert.equal(details, 2);
  assert.equal(calls.filter((c) => c.url.endsWith('/checkin')).length, 4);
});

test('fresh zero-version response reports incompatibility and never purchases version zero', async () => {
  const { sw, setFailure, calls } = setup();
  await sw.authSignIn({ email: 'test@example.com', token: 'aas_et/test' });
  setFailure((url) => url.includes('/details') ? detailsResponse(sw, 0) : null);
  await assert.rejects(sw.appDetails({ packageName: 'com.test.app' }), (err) => err.code === 'INCOMPATIBLE');
  assert.equal(calls.filter((c) => c.url.includes('/details')).length, 2);
  await assert.rejects(sw.appPurchase({ packageName: 'com.test.app', versionCode: 0 }), /No compatible/);
  assert.equal(calls.filter((c) => c.url.endsWith('/purchase')).length, 0);
});

test('paid apps are reported explicitly without a purchase or unnecessary refresh', async () => {
  const { sw, setFailure, calls } = setup();
  await sw.authSignIn({ email: 'test@example.com', token: 'aas_et/test' });
  setFailure((url) => url.includes('/details') ? detailsResponse(sw, 123, [{ offerType: 1, micros: 1990000n, formattedAmount: '$1.99' }]) : null);
  await assert.rejects(sw.appDetails({ packageName: 'com.test.app' }), (err) => err.code === 'PAID_APP' && err.message.includes('$1.99'));
  assert.equal(calls.filter((c) => c.url.endsWith('/checkin')).length, 2);
  assert.equal(calls.filter((c) => c.url.endsWith('/purchase')).length, 0);
});

test('empty delivery refreshes once, rechecks the version and reacquires the free app', async () => {
  const { sw, setFailure, calls } = setup();
  await sw.authSignIn({ email: 'test@example.com', token: 'aas_et/test' });
  let deliveries = 0;
  setFailure((url) => {
    if (url.includes('/details')) return detailsResponse(sw, 124);
    if (url.includes('/delivery')) return new Response(sw.pbEncode({ payload: { deliveryResponse: {
      appDeliveryData: ++deliveries === 1 ? {} : { downloadUrl: 'https://example.gvt1.com/base.apk', downloadSize: 10n },
    } } }, sw.PB_ResponseWrapper));
    return null;
  });
  const result = await sw.appDelivery({ packageName: 'com.test.app', versionCode: 123 });
  assert.equal(result.versionCode, 124);
  assert.equal(deliveries, 2);
  assert.ok(calls.some((c) => c.url.endsWith('/purchase') && c.body.includes('vc=124')));
});
