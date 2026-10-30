// Wire schema from NoMore201/googleplay-api/googleplay.proto; used by account_auth.py via gpapi.
const PB_DeviceConfigurationProto = {
  1: { name: 'touchScreen', type: PB_INT32 },
  2: { name: 'keyboard', type: PB_INT32 },
  3: { name: 'navigation', type: PB_INT32 },
  4: { name: 'screenLayout', type: PB_INT32 },
  5: { name: 'hasHardKeyboard', type: PB_BOOL },
  6: { name: 'hasFiveWayNavigation', type: PB_BOOL },
  7: { name: 'screenDensity', type: PB_INT32 },
  8: { name: 'glEsVersion', type: PB_INT32 },
  9: { name: 'systemSharedLibrary', type: PB_STRING, repeated: true },
  10: { name: 'systemAvailableFeature', type: PB_STRING, repeated: true },
  11: { name: 'nativePlatform', type: PB_STRING, repeated: true },
  12: { name: 'screenWidth', type: PB_INT32 },
  13: { name: 'screenHeight', type: PB_INT32 },
  14: { name: 'systemSupportedLocale', type: PB_STRING, repeated: true },
  15: { name: 'glExtension', type: PB_STRING, repeated: true },
  16: { name: 'deviceClass', type: PB_INT32 },
  17: { name: 'maxApkDownloadSizeMb', type: PB_INT32 },
};
const PB_AndroidBuildProto = {
  1: { name: 'id', type: PB_STRING },
  2: { name: 'product', type: PB_STRING },
  3: { name: 'carrier', type: PB_STRING },
  4: { name: 'radio', type: PB_STRING },
  5: { name: 'bootloader', type: PB_STRING },
  6: { name: 'client', type: PB_STRING },
  7: { name: 'timestamp', type: PB_INT64 },
  8: { name: 'googleServices', type: PB_INT32 },
  9: { name: 'device', type: PB_STRING },
  10: { name: 'sdkVersion', type: PB_INT32 },
  11: { name: 'model', type: PB_STRING },
  12: { name: 'manufacturer', type: PB_STRING },
  13: { name: 'buildProduct', type: PB_STRING },
  14: { name: 'otaInstalled', type: PB_BOOL },
};
const PB_AndroidCheckinProto = {
  1: { name: 'build', type: PB_NESTED, schema: PB_AndroidBuildProto },
  2: { name: 'lastCheckinMsec', type: PB_INT64 },
  5: { name: 'requestedGroup', type: PB_STRING, repeated: true },
  6: { name: 'cellOperator', type: PB_STRING },
  7: { name: 'simOperator', type: PB_STRING },
  8: { name: 'roaming', type: PB_STRING },
  9: { name: 'userNumber', type: PB_INT32 },
};
const PB_AndroidCheckinRequest = {
  1: { name: 'imei', type: PB_STRING },
  2: { name: 'id', type: PB_INT64 },
  3: { name: 'digest', type: PB_STRING },
  4: { name: 'checkin', type: PB_NESTED, schema: PB_AndroidCheckinProto },
  5: { name: 'desiredBuild', type: PB_STRING },
  6: { name: 'locale', type: PB_STRING },
  7: { name: 'loggingId', type: PB_INT64 },
  8: { name: 'marketCheckin', type: PB_STRING },
  9: { name: 'macAddr', type: PB_STRING, repeated: true },
  10: { name: 'meid', type: PB_STRING },
  11: { name: 'accountCookie', type: PB_STRING, repeated: true },
  12: { name: 'timeZone', type: PB_STRING },
  13: { name: 'securityToken', type: PB_FIXED64 },
  14: { name: 'version', type: PB_INT32 },
  15: { name: 'otaCert', type: PB_STRING, repeated: true },
  16: { name: 'serialNumber', type: PB_STRING },
  17: { name: 'esn', type: PB_STRING },
  18: { name: 'deviceConfiguration', type: PB_NESTED, schema: PB_DeviceConfigurationProto },
  19: { name: 'macAddrType', type: PB_STRING, repeated: true },
  20: { name: 'fragment', type: PB_INT32 },
  21: { name: 'userName', type: PB_STRING },
  22: { name: 'userSerialNumber', type: PB_INT32 },
};
const PB_AndroidCheckinResponse = {
  1: { name: 'statsOk', type: PB_BOOL },
  3: { name: 'timeMsec', type: PB_INT64 },
  4: { name: 'digest', type: PB_STRING },
  6: { name: 'marketOk', type: PB_BOOL },
  7: { name: 'androidId', type: PB_FIXED64 },
  8: { name: 'securityToken', type: PB_FIXED64 },
  9: { name: 'settingsDiff', type: PB_BOOL },
  10: { name: 'deleteSetting', type: PB_STRING, repeated: true },
  12: { name: 'deviceCheckinConsistencyToken', type: PB_STRING },
};
const PB_UploadDeviceConfigRequest = {
  1: { name: 'deviceConfiguration', type: PB_NESTED, schema: PB_DeviceConfigurationProto },
  2: { name: 'manufacturer', type: PB_STRING },
  3: { name: 'gcmRegistrationId', type: PB_STRING },
};
const PB_UploadDeviceConfigResponse = {
  1: { name: 'uploadDeviceConfigToken', type: PB_STRING },
};
const PB_TocResponse = {
  2: { name: 'tosVersionDeprecated', type: PB_INT32 },
  3: { name: 'tosContent', type: PB_STRING },
  4: { name: 'homeUrl', type: PB_STRING },
  6: { name: 'tosCheckboxTextMarketingEmails', type: PB_STRING },
  7: { name: 'tosToken', type: PB_STRING },
  9: { name: 'iconOverrideUrl', type: PB_STRING },
  11: { name: 'requiresUploadDeviceConfig', type: PB_BOOL },
  13: { name: 'recsWidgetUrl', type: PB_STRING },
  15: { name: 'socialHomeUrl', type: PB_STRING },
  16: { name: 'ageVerificationRequired', type: PB_BOOL },
  17: { name: 'gplusSignupEnabled', type: PB_BOOL },
  18: { name: 'redeemEnabled', type: PB_BOOL },
  19: { name: 'helpUrl', type: PB_STRING },
  20: { name: 'themeId', type: PB_INT32 },
  21: { name: 'entertainmentHomeUrl', type: PB_STRING },
  22: { name: 'cookie', type: PB_STRING },
};
PB_Payload[6] = { name: 'tocResponse', type: PB_NESTED, schema: PB_TocResponse };
PB_Payload[28] = { name: 'uploadDeviceConfigResponse', type: PB_NESTED, schema: PB_UploadDeviceConfigResponse };

// Keep IDs as BigInt throughout: Android IDs and security tokens exceed 2^53.
function pbEncode(data, schema) {
  const out = [];
  function varint(value) {
    let n = BigInt.asUintN(64, BigInt(value));
    while (n > 127n) { out.push(Number(n & 127n) | 128); n >>= 7n; }
    out.push(Number(n));
  }
  for (const [number, field] of Object.entries(schema)) {
    const value = data[field.name];
    if (value == null) continue;
    for (const item of field.repeated ? value : [value]) {
      const delimited = [PB_STRING, PB_BYTES, PB_NESTED].includes(field.type);
      varint((Number(number) << 3) | (delimited ? 2 : field.type === PB_FIXED64 ? 1 : 0));
      if (delimited) {
        const bytes = field.type === PB_STRING ? new TextEncoder().encode(item)
          : field.type === PB_NESTED ? pbEncode(item, field.schema) : item;
        varint(bytes.length);
        for (const byte of bytes) out.push(byte);
      } else if (field.type === PB_FIXED64) {
        let n = BigInt.asUintN(64, BigInt(item));
        for (let i = 0; i < 8; i++) { out.push(Number(n & 255n)); n >>= 8n; }
      } else varint(field.type === PB_BOOL ? Number(item) : item);
    }
  }
  return new Uint8Array(out);
}
