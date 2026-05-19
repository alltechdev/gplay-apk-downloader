# Play API reference

Endpoints, request shapes, and protobuf schemas the extension uses. Field numbers are the source of truth — names match the gpapi Python package for parity with the legacy CLI.

## Base URL

`https://android.clients.google.com/fdfe`

## Endpoints

| Verb | Path                                                              | Body                            | Returns                          |
|------|-------------------------------------------------------------------|---------------------------------|----------------------------------|
| GET  | `/details?doc={pkg}`                                              | —                               | `ResponseWrapper` protobuf       |
| POST | `/purchase`                                                       | form: `doc={pkg}&ot=1&vc={vc}` | `ResponseWrapper` (or empty)     |
| GET  | `/delivery?doc={pkg}&ot=1&vc={vc}`                                | —                               | `ResponseWrapper` protobuf       |

## Auth headers (every call)

```
Authorization: Bearer {authToken}
X-DFE-Device-Id: {gsfId}
X-DFE-Encoded-Targets: <hardcoded constant>
X-DFE-Phenotype: <hardcoded base64>
X-DFE-Client-Id: am-android-google
X-DFE-Network-Type: 4
X-DFE-Content-Filters:
X-DFE-Cookie: {dfeCookie}
X-DFE-UserLanguages: en_US
X-DFE-Request-Params: timeoutMs=4000
X-DFE-No-Prefetch: true
Accept-Language: en-US
(optional) X-DFE-Device-Checkin-Consistency-Token: ...
(optional) X-DFE-Device-Config-Token: ...
(optional) X-DFE-MCCMNC: ...
```

`User-Agent` is set at the network layer via `declarativeNetRequest` — it is a forbidden header for `fetch()`. The value is `auth.deviceInfoProvider.userAgentString` after sign-in, falling back to a Pixel 9a Android-Finsky string.

## Protobuf schemas

Field numbers verified against gpapi's compiled descriptor.

### ResponseWrapper

| # | type    | name    |
|---|---------|---------|
| 1 | nested  | payload |

### Payload

| #  | type            | name              |
|----|-----------------|-------------------|
| 2  | DetailsResponse | detailsResponse   |
| 21 | DeliveryResponse| deliveryResponse  |

### DetailsResponse

| # | type  | name  |
|---|-------|-------|
| 4 | DocV2 | docV2 |

### DocV2

| #  | type             | name    |
|----|------------------|---------|
| 1  | string           | docid   |
| 5  | string           | title   |
| 13 | DocumentDetails  | details |

### DocumentDetails

| # | type        | name       |
|---|-------------|------------|
| 1 | AppDetails  | appDetails |

### AppDetails

| #  | type   | name             |
|----|--------|------------------|
| 1  | string | developerName    |
| 3  | int32  | versionCode      |
| 4  | string | versionString    |
| 9  | int64  | installationSize |
| 14 | string | packageName      |
| 16 | string | uploadDate       |
| 25 | string (repeated) | splitId  |

### DeliveryResponse

| # | type                    | name             |
|---|-------------------------|------------------|
| 1 | int32                   | status           |
| 2 | AndroidAppDeliveryData  | appDeliveryData  |

### AndroidAppDeliveryData

| #  | type                       | name                |
|----|----------------------------|---------------------|
| 1  | int64                      | downloadSize        |
| 2  | string                     | sha1                |
| 3  | string                     | downloadUrl         |
| 5  | HttpCookie (repeated)      | downloadAuthCookie  |
| 15 | SplitDeliveryData (repeated)| splitDeliveryData  |

### HttpCookie

| # | type   | name  |
|---|--------|-------|
| 1 | string | name  |
| 2 | string | value |

### SplitDeliveryData

| # | type   | name         |
|---|--------|--------------|
| 1 | string | name         |
| 2 | int64  | downloadSize |
| 5 | string | downloadUrl  |

## Notes / gotchas

- **`Item` vs `DocV2`**: newer Aurora Store proto renames field 4 of `DetailsResponse` from `docV2` (type `DocV2`) to `item` (type `Item`). Field numbers inside the nested message also differ: `DocV2.docid = 1 (string)` vs `Item.id = 1 (int32)`. The legacy CLI and the live server response use the older shape, so we parse as `DocV2`. If the server ever switches, the decoder will see a wrong wire-type and we'll need to update the schema.
- **Free apps still go through `/purchase`** — `ot=1` ("ownership type 1") is the implicit-acquire token. The response can be empty or contain a `BuyResponse`; we don't parse the body.
- **`splitDeliveryData` empty** for apps that ship a single APK. The download then has only `delivery.downloadUrl` (no splits).
- **Status non-1 in DeliveryResponse** means the app needs a real purchase, license, or is geo-blocked. We surface a clear error.
