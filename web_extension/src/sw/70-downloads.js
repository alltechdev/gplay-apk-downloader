// 70-downloads.js — chrome.downloads usage + per-download Cookie rule lifecycle.

chrome.downloads.onChanged.addListener(async (delta) => {
  await hydrateDlMap();
  const state = delta?.state?.current;
  if (state === 'in_progress' && delta?.bytesReceived?.current != null) {
    broadcast('download.event', { phase: 'progress', id: delta.id, bytes: delta.bytesReceived.current });
    return;
  }
  if (state !== 'complete' && state !== 'interrupted') return;
  const ruleId = downloadRuleByDl.get(delta.id);
  if (ruleId) {
    downloadRuleByDl.delete(delta.id);
    await persistDlMap();
    await clearDnrRule(ruleId);
  }
  const bytes = delta?.totalBytes?.current ?? delta?.bytesReceived?.current;
  broadcast('download.event', { phase: state, id: delta.id, bytes });
});

async function queueDownloadFile({ url, cookies, filename }) {
  await hydrateDlMap();
  const ruleId = await allocDownloadRuleId();
  await applyCookieRule(ruleId, url, cookies);
  const id = await chrome.downloads.download({
    url,
    filename,
    saveAs: false,
    conflictAction: 'uniquify',
  });
  downloadRuleByDl.set(id, ruleId);
  await persistDlMap();
  return { id, ruleId, filename };
}

async function cancelDownload({ id }) {
  if (typeof id !== 'number') throw new ValidationError('id must be number');
  await hydrateDlMap();
  await chrome.downloads.cancel(id);
  const ruleId = downloadRuleByDl.get(id);
  if (ruleId) { downloadRuleByDl.delete(id); await persistDlMap(); await clearDnrRule(ruleId); }
  return { ok: true };
}

async function showDownload({ id }) {
  if (typeof id !== 'number') throw new ValidationError('id must be number');
  await chrome.downloads.show(id);
  return { ok: true };
}

// Direct, server-style "download splits to disk" path (legacy single-app
// download with merge unchecked still kept around for power users + tests).
async function appDownload({ packageName, versionCode }) {
  validatePackageName(packageName);
  broadcast('download.event', { phase: 'purchase', packageName, versionCode });
  await appPurchase({ packageName, versionCode });
  broadcast('download.event', { phase: 'delivery', packageName, versionCode });
  const delivery = await appDelivery({ packageName, versionCode });
  const dirPrefix = `gplaydl/${sanitizeFilenameSegment(packageName)}-${versionCode}`;
  const files = [{ kind: 'base', name: 'base.apk', url: delivery.downloadUrl, size: delivery.downloadSize }];
  delivery.splits.forEach((s, i) => {
    const baseName = sanitizeFilenameSegment(s.name || `split${i}`);
    files.push({ kind: 'split', name: `${baseName}.apk`, url: s.downloadUrl, size: s.downloadSize });
  });
  const queued = [];
  for (const f of files) {
    broadcast('download.event', { phase: 'start', packageName, file: f.name, url: f.url, size: f.size });
    const q = await queueDownloadFile({ url: f.url, cookies: delivery.cookies, filename: `${dirPrefix}/${f.name}` });
    queued.push({ id: q.id, file: f.name, ruleId: q.ruleId });
    broadcast('download.event', { phase: 'queued', packageName, file: f.name, id: q.id });
  }
  return { dirPrefix, files: queued };
}

// Used by the page when "Merge splits" is unchecked or device is connected:
// returns the URLs + cookies and installs per-URL DNR rules so the page can
// fetch each blob directly (no chrome.downloads roundtrip). Page must call
// app.releaseRules with the returned ruleIds when done.
async function appPrepareInstall({ packageName, versionCode }) {
  validatePackageName(packageName);
  broadcast('download.event', { phase: 'purchase', packageName, versionCode });
  await appPurchase({ packageName, versionCode });
  broadcast('download.event', { phase: 'delivery', packageName, versionCode });
  const delivery = await appDelivery({ packageName, versionCode });
  const files = [{ kind: 'base', name: 'base.apk', url: delivery.downloadUrl, size: delivery.downloadSize }];
  delivery.splits.forEach((s, i) => {
    const baseName = sanitizeFilenameSegment(s.name || `split${i}`);
    files.push({ kind: 'split', name: `${baseName}.apk`, url: s.downloadUrl, size: s.downloadSize });
  });
  const ruleIds = [];
  for (const f of files) {
    const ruleId = await allocDownloadRuleId();
    await applyCookieRule(ruleId, f.url, delivery.cookies);
    f.ruleId = ruleId;
    ruleIds.push(ruleId);
  }
  return { packageName, versionCode, files, ruleIds };
}

async function releaseRules({ ruleIds }) {
  if (!Array.isArray(ruleIds)) throw new ValidationError('ruleIds must be an array');
  for (const id of ruleIds) await clearDnrRule(id);
  return { released: ruleIds.length };
}
