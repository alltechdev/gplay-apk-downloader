# Extension architecture

The Manifest V3 service worker owns authentication, Google Play requests, and downloads. The extension page calls it through `sw/99-rpc.js`; no Python server is required.

## Authentication

`sw/46-account-session.js` ports the repository’s `account_auth.py` flow. A Google EmbeddedSetup login supplies an oauth_token cookie; the worker exchanges it for a long-lived AAS credential, obtains an AC2DM token, performs two device checkins, exchanges the AAS credential for a Play token, uploads device configuration, and handles Play terms/session cookies.

`sw/45-account-proto.js` contains the checkin/config/terms wire schemas and encoder. Android IDs and security tokens remain BigInt until the device ID is serialized to hexadecimal for storage. Device profiles come from `profiles.json` and determine the requested ABI and Play user agent.

`sw/50-auth.js` owns browser login with automatic email/cookie capture, refresh, status, and sign-out. Pending browser login lives in session storage and expires after 15 minutes. Credentials live in local storage; status RPCs never return tokens. Legacy anonymous records are discarded when read. Sign-out clears local credentials and pending login. Google’s password is never entered in the extension.

`sw/60-play-api.js` refreshes expired or mismatched-architecture sessions and retries a 401 once using saved personal credentials. Session setup uses direct requests to avoid recursive refresh.

## Request rules and downloads

`sw/40-dnr.js` installs dynamic request-header rules: 1 for Google auth, 2 for Play FDFE, 3 for download CDNs, 4 for Play web search, and 5 for Google checkin. Old rule 1 is replaced on startup, removing the previous anonymous endpoint. Rules 100–9999 carry per-download cookies and are reclaimed after completion or worker restart.

`sw/70-downloads.js` handles download preparation and browser downloads. APK merging, signing, and WebUSB installation run in the page through the bundled modules. APK data goes directly from Google’s CDN to the browser.

## Permissions and storage

The manifest grants narrow host access to Google account login, Android/Play APIs, CDN hosts, fonts, GitHub, and the existing analytics endpoint. The cookies API reads only oauth_token at the Google account URL after explicit login initiation; scripting reads the account email using the same selector as account_auth.py. There is no Aurora host permission or authentication endpoint.

`gplaydl.auth` stores the personal account credential and current session. `gplaydl.arch` stores the ABI preference. `gplaydl.pendingLogin` in session storage tracks the login tab, ABI, previous cookie, and start time. `gplaydl.downloadRules` tracks download rule ownership.
