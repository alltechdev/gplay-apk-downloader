// 10-utils.js — small helpers reused across SW modules.

/**
 * Best-effort broadcast to all extension pages. Errors when there's no
 * listener are swallowed (the page may simply not be open).
 * @param {string} type
 * @param {object} payload
 */
function broadcast(type, payload) {
  chrome.runtime.sendMessage({ type, payload }).catch(() => {});
}

/**
 * Reject package names that wouldn't be a valid Android applicationId.
 * @param {string} pkg
 * @returns {string} The same string, for chaining.
 * @throws {ValidationError}
 */
function validatePackageName(pkg) {
  if (typeof pkg !== 'string') throw new ValidationError('package name must be a string');
  if (!/^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$/.test(pkg)) {
    throw new ValidationError('invalid package name: ' + pkg);
  }
  return pkg;
}

/** Make a safe filename segment out of arbitrary string input. */
function sanitizeFilenameSegment(s) {
  return String(s).replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 200);
}

/** Load the bundled profiles.json into a JS object. */
async function loadProfilesJson() {
  const res = await fetch(chrome.runtime.getURL('profiles.json'));
  if (!res.ok) throw new NetworkError(`profiles.json fetch failed: ${res.status}`, res.status);
  return res.json();
}
