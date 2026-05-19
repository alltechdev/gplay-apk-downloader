// Test helper: vm-load `src/sw/20-pb.js` and re-export its decoder + schemas
// as ESM. This is the single source of truth for Play API protobuf
// schemas; both the drift test and the live integration test import from
// here so the schemas are never duplicated in two places.

import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const swPath = resolve(__dirname, '..', '..', 'src', 'sw', '20-pb.js');
const swCode = readFileSync(swPath, 'utf8');

// The SW file only references globals that we provide here. It doesn't
// touch chrome.* or DOM APIs at top level — it just declares functions
// and constants.
// Top-level `const` declarations inside the SW file are bindings in the
// script's lexical scope, not properties of the contextified global.
// In a real service worker the same script-record is shared with later
// `importScripts(...)` calls, so the names work; in a Node vm we have
// to explicitly capture them. Appending an assignment at the bottom
// publishes each name onto the context globalThis.
const EXPORT_NAMES = [
  'pbDecode',
  'PB_HttpCookie', 'PB_SplitDeliveryData', 'PB_AndroidAppDeliveryData',
  'PB_DeliveryResponse', 'PB_AppDetails', 'PB_DocumentDetails', 'PB_DocV2',
  'PB_DetailsResponse', 'PB_Payload', 'PB_ResponseWrapper',
];
const wrappedCode = swCode + `;Object.assign(globalThis, { ${EXPORT_NAMES.join(', ')} });`;

const ctx = vm.createContext({
  TextDecoder, Uint8Array, BigInt, Number,
});
vm.runInContext(wrappedCode, ctx);

export const pbDecode                  = ctx.pbDecode;
export const PB_HttpCookie             = ctx.PB_HttpCookie;
export const PB_SplitDeliveryData      = ctx.PB_SplitDeliveryData;
export const PB_AndroidAppDeliveryData = ctx.PB_AndroidAppDeliveryData;
export const PB_DeliveryResponse       = ctx.PB_DeliveryResponse;
export const PB_AppDetails             = ctx.PB_AppDetails;
export const PB_DocumentDetails        = ctx.PB_DocumentDetails;
export const PB_DocV2                  = ctx.PB_DocV2;
export const PB_DetailsResponse        = ctx.PB_DetailsResponse;
export const PB_Payload                = ctx.PB_Payload;
export const PB_ResponseWrapper        = ctx.PB_ResponseWrapper;
