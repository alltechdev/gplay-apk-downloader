# Port Spec — Python CLI → Browser Extension

Source: survey of `gplay-apk-downloader` repo on branch `feat/web-extension` at HEAD `3ccde88`.
Purpose: concrete spec of what each subsystem does and how it maps to a browser extension.

> **All claims here are derived from reading code.** Anything marked **[UNVERIFIED]** has not yet been confirmed by running the extension against Google's live endpoints. Do not treat unverified items as facts.

---

## 1. Authentication

**Current (Python):**
- Anonymous auth via AuroraOSS dispenser (`https://auroraoss.com/api/auth`).
- POST a device profile (JSON) → response contains `authToken`, `email`, `gsfId`, `dfeCookie`, device info.
- Cached in `~/.gplay-auth.json`.

**Key fields:**
- `authToken` — Bearer token used on Play API calls.
- `gsfId` — Google Services Framework / device ID.
- `dfeCookie` — opaque cookie sent on every Play API call.
- `deviceConfigToken`, `deviceCheckInConsistencyToken` — optional, returned by dispenser.

**Port:**
- Same POST to AuroraOSS dispenser from extension `background.js`.
- Store result in `chrome.storage.local`.
- No CORS issue expected for AuroraOSS itself **[UNVERIFIED — must test]**.

---

## 2. Device Profile

**Current:** `profiles/*.properties` files (Aurora Store format) + in-code fallback in `device_profiles.py:13–47`.

**Profile keys:** `Build.FINGERPRINT`, `Build.MODEL`, `Build.MANUFACTURER`, `Platforms`, `Build.VERSION.SDK_INT`, `Build.SUPPORTED_ABIS`, `Screen.Density`, `SharedLibraries`, `Features`, `GL.Extensions`.

**Priority order (`device_profiles.py:127–128`):**
- ARM64: `Pv` (Pixel 9a), `D2`, `eV`, `iq`
- ARMv7 fallback: `XK` (Samsung J5 Prime), `Gj`, `IV`

**Port:** embed 3–5 priority profiles as JSON in the extension bundle. POST chosen profile to dispenser.

---

## 3. Play Store API Calls

**Base URL:** `https://android.clients.google.com/fdfe`

| Operation | Endpoint | Method | Body / Query | Response |
|-----------|----------|--------|--------------|----------|
| Details   | `/details?doc={pkg}` | GET | — | protobuf `ResponseWrapper.payload.detailsResponse.docV2` |
| Purchase  | `/purchase` | POST | form: `doc={pkg}&ot=1&vc={vc}` | protobuf or 204 |
| Delivery  | `/delivery?doc={pkg}&ot=1&vc={vc}` | GET | — | protobuf `ResponseWrapper.payload.deliveryResponse.appDeliveryData` |
| Search    | `https://play.google.com/store/search?q=...` | GET | (HTML scrape) | HTML |

**Auth headers** (from `gplay-downloader.py:215–249`):
```
Authorization: Bearer {authToken}
User-Agent: Android-Finsky/...
X-DFE-Device-Id: {gsfId}
X-DFE-Encoded-Targets: <hardcoded>
X-DFE-Phenotype: <hardcoded base64>
X-DFE-Client-Id: am-android-google
X-DFE-Network-Type: 4
X-DFE-Cookie: {dfeCookie}
X-DFE-UserLanguages: en_US
Accept-Language: en-US
Content-Type: application/x-protobuf
```

**Port concerns:**
- Custom `X-DFE-*` headers trigger a CORS preflight. **[UNVERIFIED — must test whether Play API rejects browser-origin preflight or just allows it because the extension has `host_permissions`.]**
- Protobuf parsing: use `protobufjs` with `.proto` definitions for `ResponseWrapper`, `DocV2`, `AppDeliveryData`, `Split`. We need to source these proto files (likely from gpapi / aurora-store / googleplay-api forks).

---

## 4. APK Download

**Delivery response (`gplay-downloader.py:549–558`):**
- `delivery_data.downloadUrl` — base APK direct URL.
- `delivery_data.downloadSize`, `sha1`.
- `delivery_data.downloadAuthCookie[]` — name/value pairs to send as `Cookie:` header.
- `delivery_data.split[]` — each has `name`, `downloadUrl`.

**Port:** `fetch()` each URL with `Cookie` header, stream into a `Blob`, then `chrome.downloads.download()` with a generated `blob:` URL. Or stream directly to disk via the Native File System API if available.

**[UNVERIFIED — must test]:** whether the browser will let us set the `Cookie` header on a cross-origin request from an extension. Standard `fetch` blocks `Cookie` as a forbidden header; we may need `chrome.declarativeNetRequest` to inject it, or attach cookies via the `cookies` API.

---

## 5. Post-Download Processing

**Merge splits:** `APKEditor.jar` invoked via `java -jar`. **Not portable to browser.**
**Manifest patch:** `axml_patcher.py` — ~410 lines of pure binary AXML parsing. Portable to JS.
**Sign APK:** `apksigner` CLI with debug keystore. **Not portable to browser** (we'd need a WASM JCA implementation).

**Decision for v1:** ship splits as-is. User installs via `adb install-multiple` or a split-aware installer. No merging, no signing. This is also the option that minimizes legal posture (server never touches bytes; client never modifies the package).

---

## 6. Blacklist

`public/blacklist.json` — `{ "packages": [...], "message": "..." }`. 35 packages, mostly banking/fintech.
Check before any details/delivery call.

**Port:** bundle `blacklist.json` into the extension; check in background worker before issuing any Play API call.

---

## 7. Server Architecture (replaced, not ported)

`server.py` (Flask + Gunicorn + Gevent) wraps the CLI as REST endpoints. The whole purpose of the extension is to make this server unnecessary. Routes inventory only — we are not porting them:

- `/api/auth`, `/api/details/{pkg}`, `/api/delivery/{pkg}`, `/download/{pkg}`, `/app/{pkg}`.

---

## Open Questions to Resolve Empirically

1. Does AuroraOSS dispenser accept browser-origin POSTs?
2. Does the Play API `/fdfe/*` accept `X-DFE-*` preflight from an MV3 extension with `host_permissions: ["https://android.clients.google.com/*"]`?
3. Can `chrome.declarativeNetRequest` inject the `Cookie` header for APK CDN downloads?
4. Is the APK CDN URL same-origin enough that we can stream directly into a `chrome.downloads` call without buffering the whole file?
5. Do `.proto` definitions for `ResponseWrapper` etc. exist in a maintained open-source form, or do we need to extract from a fork?

All five must be answered with **real network calls**, not assumed.
