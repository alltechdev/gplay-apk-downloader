// runtime.js — typed accessors for the two vendor-bundle globals.
//
// vendor/adb-bundle.js exposes `window.gplaydlAdb` (the WebUSB ADB client),
// vendor/apk-tools-bundle.js exposes `window.gplaydlApkTools` (merge + sign +
// bundleZip helpers). UI modules go through this file so we (a) avoid
// scattering `window.gplaydl…` references, (b) get an obvious place to
// guard against the bundle not being loaded, and (c) get one shared
// definition of "is a device connected".
//
// Each accessor is intentionally a function — the underlying globals are
// populated by `<script>` tags, so reading them at module-load time may
// race with the bundle script.

/** Returns the ADB manager, or `null` if the bundle hasn't loaded yet. */
export function adb() {
  return window.gplaydlAdb || null;
}

/** Returns `true` if WebUSB is available AND a device is currently connected. */
export function adbConnected() {
  return !!window.gplaydlAdb?.connected;
}

/** Returns `true` if WebUSB is available (Chrome/Edge in a secure context). */
export function adbSupported() {
  return !!(window.gplaydlAdb && window.gplaydlAdb.supported);
}

/** Returns the APK-tools API; throws if the bundle isn't loaded. */
export function apkTools() {
  if (!window.gplaydlApkTools) throw new Error('apk-tools bundle not loaded');
  return window.gplaydlApkTools;
}
