# Running `gplay-apk-downloader` on Cloudflare Workers — Feasibility Analysis

> Repository analysed: <https://github.com/alltechdev/gplay-apk-downloader>
> This document answers three questions:
> 1. How does this project actually work?
> 2. Can the functionality be ported to / run on a Cloudflare Worker?
> 3. Can't we just get the **direct download link** of an app?

---

## TL;DR

| Question | Answer |
|----------|--------|
| Can the **whole** project run on a Worker as-is? | **No.** It depends on Java (APKEditor), `apksigner`, `zipalign`, `adb`, the disk filesystem, and Python — none of which exist on Workers. |
| Can the **core "get the APK download link" feature** run on a Worker? | **Yes.** Auth → details → purchase → delivery is just HTTPS + protobuf. This maps cleanly onto a Worker. |
| Can you just grab a "direct link"? | **Partly.** The CDN URL Google returns *is* a direct link, but it is **short-lived, cookie-/token-bound, device-profile-specific, and not publicly shareable**. You must mint it yourself per request — you cannot hardcode one. |
| Can a Worker also **merge** split APKs into one installable file? | **Not realistically.** Merging needs APKEditor (Java) + signing + zipalign. Workers have no JVM, no subprocess, CPU/time/memory limits. Keep merging off-Worker. |

**Recommended Worker scope:** authentication + metadata + delivery-URL resolution + streaming proxy of the APK/splits. Leave merging/signing to a client (browser via WebUSB ADB, the existing Python service, or a container).

---

## 1. How the project works

The tool impersonates the **Aurora Store** Android client to talk to Google Play's private **`fdfe`** API (`https://android.clients.google.com/fdfe`). There is no official public API — it speaks the same protobuf protocol a real phone uses.

### The pipeline (from `gplay-downloader.py` → `cmd_download`)

```
                ┌─────────────────────────────────────────────┐
                │  1. AUTH (anonymous)                        │
   Device       │  POST  <dispenser-url>                       │
   profile  ───►│  body = device profile (.properties → JSON) │──► authToken, gsfId,
   (.properties)│  via "dispenser" service (Aurora-style)      │     dfeCookie, deviceInfo
                └─────────────────────────────────────────────┘
                                  │
                                  ▼
                ┌─────────────────────────────────────────────┐
                │  2. DETAILS (protobuf)                       │
                │  GET  /fdfe/details?doc=<pkg>                │──► title, versionCode,
                │  Accept: application/x-protobuf              │     offers (price), splits
                └─────────────────────────────────────────────┘
                                  │  (reject if paid: offer.offerType==1 && micros>0)
                                  ▼
                ┌─────────────────────────────────────────────┐
                │  3. PURCHASE (acquire free license)          │
                │  POST /fdfe/purchase                         │
                │  body: doc=<pkg>&ot=1&vc=<versionCode>       │
                └─────────────────────────────────────────────┘
                                  │
                                  ▼
                ┌─────────────────────────────────────────────┐
                │  4. DELIVERY (get CDN URLs)                  │
                │  GET /fdfe/delivery?doc=<pkg>&ot=1&vc=<vc>   │──► appDeliveryData:
                │                                              │      .downloadUrl  (base APK)
                │                                              │      .split[].downloadUrl
                │                                              │      .downloadAuthCookie[]
                │                                              │      .downloadSize, .sha1
                └─────────────────────────────────────────────┘
                                  │
                                  ▼
        ┌───────────── DOWNLOAD (HTTPS GET, with auth cookie) ─────────────┐
        │  base.apk  +  split_config.*.apk  (density / lang / abi splits)  │
        └──────────────────────────────────────────────────────────────────┘
                                  │
                ┌─────────────────┴─────────────────┐  (only if -m / merge)
                ▼                                     ▼
   5. MERGE (APKEditor.jar, Java)          (no merge) → ZIP of base+splits
   6. PATCH manifest (fused asset packs)        (original signatures kept)
   7. ZIPALIGN (Android 11+ arsc alignment)
   8. SIGN (apksigner + debug keystore)
                ▼
        single installable universal APK
```

### Key implementation facts (verified from source)

- **Auth** (`get_dispenser_auth`): uses `cloudscraper` to POST a device profile to a *dispenser* and receive `authToken` + `gsfId` + `dfeCookie`. The repo ships **23 device profiles** in `profiles/*.properties` (real devices: Galaxy S25 Ultra, Pixel 9a, Xperia 5, …) and **rotates** through them because some apps (banking etc.) only authorise on specific profiles.
- **Headers** (`get_auth_headers`): a long set of `X-DFE-*` headers (`X-DFE-Device-Id`, `X-DFE-Encoded-Targets`, `X-DFE-Phenotype`, `Authorization: Bearer <token>`, etc.) — these mimic the Finsky/Play client and are required.
- **Protobuf** is required for `details` and `delivery` (`from gpapi import googleplay_pb2; ResponseWrapper().ParseFromString(...)`). Only a few fields are actually read:
  - `payload.detailsResponse.docV2` → `title`, `details.appDetails.versionCode/versionString`, `offer[]`
  - `payload.deliveryResponse.appDeliveryData` → `downloadUrl`, `downloadSize`, `sha1`, `downloadAuthCookie[]`, `split[]{name, downloadUrl}`
- **Search/info** have an **HTML-scraping fallback** (so they can work even without protobuf).
- **Merging** (`merge_apks_with_apkeditor`) shells out to `java -jar APKEditor.jar m`. **Signing** shells out to `apksigner`. Manifest patching is custom binary AXML editing (`axml_patcher.py`). All of these touch `tempfile` / disk.
- The Flask `server.py` adds SSE streaming, concurrency limits, a temp-file store with TTL, a download counter, auto-generated SEO pages, and **WebUSB ADB** in the browser (`public/adb.js`) so split installs happen client-side with original signatures.

---

## 2. Can't we just get the direct link of an app?

**Short answer: you can get *a* direct link, but it is not a static, shareable, hardcodeable URL.**

The `downloadUrl` returned in step 4 (delivery) **is** a direct Google CDN link to the APK bytes. But:

1. **It is minted per-request and short-lived.** The URL is tied to the `authToken` you just obtained and usually carries a `downloadAuthCookie` (the code sends it back as a `Cookie:` header on the GET). Without that cookie/token context it 403s or expires.
2. **It is device-profile specific.** Which `downloadUrl`/splits you get depends on the device profile used for auth (architecture, screen density, locale, SDK). A link minted for an ARM64 Pixel profile is not the right artifact for an ARMv7 device.
3. **It points to *split* APKs, not one file.** Modern apps are App Bundles: you get `base.apk` **plus** several `split_config.*.apk` (density / language / ABI / asset packs). A single "the APK" link generally does not exist for these apps — that's the whole reason the project has a merge step.
4. **You must "purchase" (acquire) the free license first.** Delivery 403s/empties until step 3 runs for that account/token.
5. **Paid apps are rejected up front** — there is no delivery URL to get.

So the realistic model is: **a Worker mints a fresh, valid delivery URL on demand and either returns it (with the required cookie) or proxies/streams the bytes itself.** You cannot precompute and cache a permanent direct link.

---

## 3. Cloudflare Worker feasibility — component by component

| Component | Worker-friendly? | Notes |
|-----------|:---------------:|-------|
| Dispenser auth (HTTP POST profile → token) | ✅ Yes | Plain `fetch`. `cloudscraper` (Cloudflare-bypass) may be unneeded or replaceable depending on the dispenser. Profiles become static JSON. |
| `X-DFE-*` headers | ✅ Yes | Just string constants + token. |
| `details` (protobuf parse) | ✅ Yes* | Need a JS protobuf decoder (e.g. `protobufjs`) **or** a hand-rolled minimal decoder for the ~5 fields used. *No native deps.* |
| Paid-app detection | ✅ Yes | Read `offer[]` from the decoded details. |
| `purchase` (form POST) | ✅ Yes | Plain `fetch`. |
| `delivery` (protobuf parse) | ✅ Yes* | Same protobuf concern as details. |
| Return/stream APK bytes | ✅ Yes | Worker can `fetch` the CDN URL (forwarding `downloadAuthCookie`) and stream the body back. Watch limits below. |
| Search / info | ✅ Yes | Protobuf or the existing HTML fallback. |
| **Merge splits (APKEditor)** | ❌ No | Needs **Java/JVM** + subprocess + disk. Not available on Workers. |
| **Sign (apksigner) / zipalign** | ❌ No | Native binaries + keystore + filesystem. Not available. |
| **AXML manifest patch** | ⚠️ Maybe | Pure binary parsing → *could* be ported to JS, but only useful if you also merge (which you can't on Worker). |
| **ADB install (`-i`)** | ❌ No (server) / ✅ (browser) | CLI ADB is impossible on a Worker. But the **WebUSB ADB** path already runs in the *browser* — a Worker backend works fine with it. |
| SSE progress streaming | ✅ Yes | Workers support streaming responses / SSE. |
| Temp-file store + TTL + counter | ♻️ Re-architect | Use **R2** (objects) + **KV/Durable Objects** (counter, cache, token reuse) instead of local disk. |

\* Protobuf is the only non-trivial port. You don't need the full `googleplay.proto` — only the handful of nested fields listed in §1.

### Hard Worker constraints to design around
- **No filesystem / no subprocess / no JVM.** Kills merge + sign + zipalign + CLI adb on the server side.
- **CPU time limit** (even on paid plans, per-request CPU is bounded) and **memory ~128 MB**. Large APKs (hundreds of MB, games) can't be buffered in memory — you must **stream**, never `arrayBuffer()` the whole file.
- **Response/subrequest limits** — long downloads should stream straight from Google's CDN through the Worker (or just hand the client the URL+cookie).
- **No persistent local state** — use **R2** for any temp artifacts and **KV / Durable Objects** for tokens, caches, counters, rate limits.

---

## 4. Recommended architecture for a Worker port

**Scope the Worker to what HTTP can do; push native work to the edge of the system.**

```
Browser / client
      │  (UI: package name, arch, merge?)
      ▼
┌───────────────────────────── Cloudflare Worker ─────────────────────────────┐
│  GET  /api/auth            → mint/reuse anonymous token (KV cached, rotate)  │
│  GET  /api/info/:pkg       → details (protobufjs) → title, version, splits    │
│  GET  /api/download-info/:pkg?arch=…                                          │
│        → purchase + delivery → { downloadUrl, splits[], cookie, size, sha1 } │
│  GET  /dl/:pkg  (and /dl/:pkg/:splitIndex)                                    │
│        → fetch CDN URL with downloadAuthCookie, STREAM bytes back            │
│                                                                              │
│  Bindings:  KV (token cache, search cache, counter)                          │
│             R2 (optional: cache popular base/split APKs)                      │
│             Durable Object (rate limiting / per-token serialization)         │
└──────────────────────────────────────────────────────────────────────────────┘
      │ returns split APKs + URLs                  │ (merge needed?)
      ▼                                            ▼
Client installs splits via WebUSB ADB     OR   off-Worker merge service
(session install, original signatures —          (Java + APKEditor + apksigner,
 NO merge needed, already in repo!)               e.g. a small VPS / container)
```

### Why this split is the *right* design
- The repo **already supports installing splits directly via WebUSB ADB in the browser** (`adb.js`, session install `pm install-create/write/commit`). That path **needs no merging at all** and preserves original signatures — perfect partner for a merge-less Worker.
- The Worker handles 100% of the network/protocol work (the genuinely useful, reusable core).
- Merging — the only part that *requires* native tooling — stays where native tooling exists.

### Suggested project layout (TypeScript Worker)
```
worker/
├─ src/
│  ├─ index.ts            # router (itty-router / Hono)
│  ├─ auth.ts             # dispenser auth + token cache (KV) + profile rotation
│  ├─ profiles.ts         # 23 device profiles as static JSON (ported from .properties)
│  ├─ headers.ts          # X-DFE-* header builder
│  ├─ play.ts             # details / purchase / delivery via fetch
│  ├─ proto.ts            # protobufjs decoders for the few fields used
│  └─ stream.ts           # streaming proxy of CDN bytes (forward auth cookie)
├─ wrangler.toml          # KV/R2/DO bindings, compatibility_date
└─ package.json
```

### Minimal protobuf in the Worker
Only these need decoding (field numbers come from `gpapi/googleplay_pb2`):
- **DetailsResponse**: `docV2.title`, `docV2.details.appDetails.versionCode/versionString`, `docV2.offer[].offerType/micros/formattedAmount`
- **DeliveryResponse**: `appDeliveryData.downloadUrl`, `.downloadSize`, `.sha1`, `.downloadAuthCookie[].name/value`, `.split[].name/downloadUrl`

Use `protobufjs` with the relevant message definitions, or write a tiny varint/length-delimited reader for just these paths.

---

## 5. What you gain / lose by porting to a Worker

**Gains**
- Globally distributed, near-zero-cold-start auth + metadata + delivery resolution.
- No server to run for the core "give me the APK / its link" feature.
- Cheap caching of tokens (KV) and popular artifacts (R2).

**Loses / caveats**
- **No server-side merge/sign** → either install splits via WebUSB ADB (already supported) or keep a small native merge service.
- Big games may exceed memory if you don't stream strictly.
- You still need a working **dispenser** URL (the repo intentionally ships none — see repo issue #22; do **not** point at `auroraoss.com`).
- This interacts with a **private Google API** by impersonating a client — same ToS/anti-abuse considerations as the original project. Use responsibly.

---

## 6. Concrete answer to the brief

- **Is it possible to rewrite this for Cloudflare Workers?** — *Partially, and that's the correct way to do it.* The **download-link / delivery core** (auth → details → purchase → delivery → stream) ports cleanly and is the most valuable, reusable piece. The **merge + sign + zipalign + CLI-ADB** parts cannot run on a Worker and should stay off it.
- **Can the functionality run on a Worker?** — Yes for the protocol/networking half; pair it with the existing **browser WebUSB ADB split-install** path so you never need server-side merging.
- **Can't we just get a direct link?** — You get a *real but ephemeral* CDN link per request (token + cookie + profile bound, and usually multiple split URLs, not one file). A Worker is actually an ideal place to mint that link on demand — but it cannot be a permanent, hardcoded URL.
