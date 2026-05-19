// Integration test for /fdfe/details + /fdfe/delivery against real Google.
// 1. Signs in to AuroraOSS dispenser (Pv profile)
// 2. Calls /details for com.duckduckgo.mobile.android (small, free, multi-arch — safe target)
// 3. Calls /delivery for the returned versionCode
// 4. Parses each response with the same decoder + schemas the extension ships
//
// Skipped when NO_NETWORK=1.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  decode, STRING, INT32, INT64, NESTED,
} from '../../src/modules/pb-decode.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SKIP = process.env.NO_NETWORK === '1';

// Schemas — duplicate of the ones inlined in background.js. Source of truth
// here is identical; if the SW changes, this changes too.
const HttpCookie = { 1: { name: 'name', type: STRING }, 2: { name: 'value', type: STRING } };
const SplitDeliveryData = {
  1: { name: 'name', type: STRING },
  2: { name: 'downloadSize', type: INT64 },
  5: { name: 'downloadUrl', type: STRING },
};
const AndroidAppDeliveryData = {
  1:  { name: 'downloadSize',       type: INT64 },
  2:  { name: 'sha1',               type: STRING },
  3:  { name: 'downloadUrl',        type: STRING },
  5:  { name: 'downloadAuthCookie', type: NESTED, schema: HttpCookie, repeated: true },
  15: { name: 'splitDeliveryData',  type: NESTED, schema: SplitDeliveryData, repeated: true },
};
const DeliveryResponse = {
  1: { name: 'status', type: INT32 },
  2: { name: 'appDeliveryData', type: NESTED, schema: AndroidAppDeliveryData },
};
const AppDetails = {
  3:  { name: 'versionCode',      type: INT32 },
  4:  { name: 'versionString',    type: STRING },
  9:  { name: 'installationSize', type: INT64 },
  14: { name: 'packageName',      type: STRING },
  25: { name: 'splitId',          type: STRING, repeated: true },
};
const DocumentDetails = { 1: { name: 'appDetails', type: NESTED, schema: AppDetails } };
const DocV2 = {
  1:  { name: 'docid',   type: STRING },
  5:  { name: 'title',   type: STRING },
  13: { name: 'details', type: NESTED, schema: DocumentDetails },
};
const DetailsResponse = { 4: { name: 'docV2', type: NESTED, schema: DocV2 } };
const Payload = {
  2:  { name: 'detailsResponse',  type: NESTED, schema: DetailsResponse },
  21: { name: 'deliveryResponse', type: NESTED, schema: DeliveryResponse },
};
const ResponseWrapper = { 1: { name: 'payload', type: NESTED, schema: Payload } };

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

async function signIn() {
  const path = resolve(__dirname, '..', '..', 'src', 'profiles.json');
  const data = JSON.parse(await readFile(path, 'utf8'));
  for (const entry of data.profiles) {
    const res = await fetch('https://auroraoss.com/api/auth', {
      method: 'POST',
      headers: { 'User-Agent': 'com.aurora.store-4.6.1-70', 'Content-Type': 'application/json' },
      body: JSON.stringify(entry.profile),
    });
    if (!res.ok) continue;
    const auth = await res.json();
    if (auth?.authToken) return auth;
  }
  throw new Error('no profile accepted by dispenser');
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

test('Play API: details + delivery for com.duckduckgo.mobile.android', { skip: SKIP, timeout: 60000 }, async () => {
  const auth = await signIn();
  console.log('  signed in as', auth.email, 'gsfId', auth.gsfId, 'profile', auth.deviceInfoProvider?.userReadableName);

  const PKG = 'com.duckduckgo.mobile.android';

  const detailsBytes = await fetchDetails(auth, PKG);
  console.log('  details bytes:', detailsBytes.byteLength);
  const detailsWrap = decode(detailsBytes, ResponseWrapper);
  const app = detailsWrap?.payload?.detailsResponse?.docV2;
  assert.ok(app?.docid, 'no docV2.docid in details response');
  assert.equal(app.docid, PKG);
  const appDetails = app.details?.appDetails;
  assert.ok(appDetails?.versionCode, 'no versionCode in appDetails');
  console.log(`  ${app.title}  v${appDetails.versionString} (vc=${appDetails.versionCode}, size=${appDetails.installationSize})`);

  await purchase(auth, PKG, appDetails.versionCode);

  const deliveryBytes = await fetchDelivery(auth, PKG, appDetails.versionCode);
  console.log('  delivery bytes:', deliveryBytes.byteLength);
  const deliveryWrap = decode(deliveryBytes, ResponseWrapper);
  const dd = deliveryWrap?.payload?.deliveryResponse?.appDeliveryData;
  assert.ok(dd, 'no appDeliveryData');
  assert.ok(dd.downloadUrl, 'no downloadUrl');
  console.log('  downloadUrl host:', new URL(dd.downloadUrl).host);
  console.log('  cookies:', (dd.downloadAuthCookie || []).map((c) => c.name).join(','));
  console.log('  splits:', (dd.splitDeliveryData || []).map((s) => s.name).join(',') || '(none)');
});
