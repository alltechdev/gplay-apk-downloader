// Opt-in live Play tests with GPLAY_ACCOUNT_EMAIL and GPLAY_AAS_TOKEN.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { accountTestSkip, personalAccountSession } from '../helpers/personal-account.mjs';
import { decode } from '../../src/modules/pb-decode.js';
import { PB_ResponseWrapper } from '../helpers/pb-sw.mjs';

const SKIP = accountTestSkip;

const DFE_ENCODED_TARGETS = 'CAESN/qigQYC2AMBFfUbyA7SM5Ij/CvfBoIDgxXrBPsDlQUdMfOLAfoFrwEHgAcBrQYhoA0cGt4MKK0Y2gI';
const DFE_PHENOTYPE = 'H4sIAAAAAAAAAB3OO3KjMAAA0KRNuWXukBkBQkAJ2MhgAZb5u2GCwQZbCH_EJ77QHmgvtDtbv-Z9_H63zXXU0NVPB1odlyGy7751Q3CitlPDvFd8lxhz3tpNmz7P92CFw73zdHU2Ie0Ad2kmR8lxhiErTFLt3RPGfJQHSDy7Clw10bg8kqf2owLokN4SecJTLoSwBnzQSd652_MOf2d1vKBNVedzg4ciPoLz2mQ8efGAgYeLou-l-PXn_7Sna1MfhHuySxt-4esulEDp8Sbq54CPPKjpANW-lkU2IZ0F92LBI-ukCKSptqeq1eXU96LD9nZfhKHdtjSWwJqUm_2r6pMHOxk01saVanmNopjX3YxQafC4iC6T55aRbC8nTI98AF_kItIQAJb5EQxnKTO7TZDWnr01HVPxelb9A2OWX6poidMWl16K54kcu_jhXw-JSBQkVcD_fPsLSZu6joIBAAA';

function fdfeHeaders(auth) {
  return {
    'Authorization': `Bearer ${auth.authToken}`,
    'User-Agent': auth.deviceInfoProvider?.userAgentString || 'Android-Finsky/45.8.21-31 (api=3)',
    'X-DFE-Device-Id': auth.gsfId,
    'Accept-Language': 'en-US',
    'X-DFE-Encoded-Targets': DFE_ENCODED_TARGETS,
    'X-DFE-Phenotype': DFE_PHENOTYPE,
    'X-DFE-Client-Id': 'am-android-google',
    'X-DFE-Network-Type': '4',
    'X-DFE-Cookie': auth.dfeCookie || '',
    'X-DFE-UserLanguages': 'en_US',
    'X-DFE-Request-Params': 'timeoutMs=4000',
  };
}

async function fetchDetails(auth, pkg) {
  const res = await fetch(`https://android.clients.google.com/fdfe/details?doc=${encodeURIComponent(pkg)}`, { headers: fdfeHeaders(auth) });
  assert.equal(res.status, 200, `details returned ${res.status}`);
  return new Uint8Array(await res.arrayBuffer());
}

async function fetchDelivery(auth, pkg, vc) {
  const res = await fetch(`https://android.clients.google.com/fdfe/delivery?doc=${encodeURIComponent(pkg)}&ot=1&vc=${vc}`, { headers: fdfeHeaders(auth) });
  assert.equal(res.status, 200, `delivery returned ${res.status}`);
  return new Uint8Array(await res.arrayBuffer());
}

async function purchase(auth, pkg, vc) {
  await fetch('https://android.clients.google.com/fdfe/purchase', {
    method: 'POST',
    headers: { ...fdfeHeaders(auth), 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `doc=${encodeURIComponent(pkg)}&ot=1&vc=${vc}`,
  });
}

test('Play API: details + delivery for com.duckduckgo.mobile.android', { skip: SKIP, timeout: 180000 }, async () => {
  const auth = await personalAccountSession();
  console.log('  signed in as', auth.email, 'gsfId', auth.gsfId, 'profile', auth.deviceInfoProvider?.userReadableName);

  const PKG = 'com.duckduckgo.mobile.android';

  const detailsBytes = await fetchDetails(auth, PKG);
  console.log('  details bytes:', detailsBytes.byteLength);
  const detailsWrap = decode(detailsBytes, PB_ResponseWrapper);
  const app = detailsWrap?.payload?.detailsResponse?.docV2;
  assert.ok(app?.docid, 'no docV2.docid in details response');
  assert.equal(app.docid, PKG);
  const appDetails = app.details?.appDetails;
  assert.ok(appDetails?.versionCode, 'no versionCode in appDetails');
  console.log(`  ${app.title}  v${appDetails.versionString} (vc=${appDetails.versionCode}, size=${appDetails.installationSize})`);

  await purchase(auth, PKG, appDetails.versionCode);

  const deliveryBytes = await fetchDelivery(auth, PKG, appDetails.versionCode);
  console.log('  delivery bytes:', deliveryBytes.byteLength);
  const deliveryWrap = decode(deliveryBytes, PB_ResponseWrapper);
  const dd = deliveryWrap?.payload?.deliveryResponse?.appDeliveryData;
  assert.ok(dd, 'no appDeliveryData');
  assert.ok(dd.downloadUrl, 'no downloadUrl');
  console.log('  downloadUrl host:', new URL(dd.downloadUrl).host);
  console.log('  cookies:', (dd.downloadAuthCookie || []).map((c) => c.name).join(','));
  console.log('  splits:', (dd.splitDeliveryData || []).map((s) => s.name).join(',') || '(none)');
});
