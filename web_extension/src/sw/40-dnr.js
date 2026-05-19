// 40-dnr.js — declarativeNetRequest dynamic rules.
//
// We use DNR because `fetch()` can't set the User-Agent, Origin, or
// Cookie request headers (they're on the browser's forbidden list).
// Rules are dynamic and re-installed on SW boot / onInstalled / onStartup.

let nextDownloadRuleId = DNR_DOWNLOAD_ID_MIN;

function dnrDispenserRule() {
  return {
    id: DNR_DISPENSER_ID,
    priority: 1,
    action: {
      type: 'modifyHeaders',
      requestHeaders: [
        { header: 'User-Agent', operation: 'set', value: DISPENSER_UA },
        { header: 'Origin', operation: 'remove' },
        { header: 'Sec-Fetch-Site', operation: 'remove' },
        { header: 'Sec-Fetch-Mode', operation: 'remove' },
        { header: 'Sec-Fetch-Dest', operation: 'remove' },
        { header: 'Sec-Fetch-User', operation: 'remove' },
      ],
    },
    condition: { urlFilter: '||auroraoss.com/api/auth', resourceTypes: ['xmlhttprequest'] },
  };
}
function dnrFdfeRule(userAgent) {
  return {
    id: DNR_FDFE_ID,
    priority: 1,
    action: {
      type: 'modifyHeaders',
      requestHeaders: [
        { header: 'User-Agent', operation: 'set', value: userAgent || PLAY_FALLBACK_UA },
        { header: 'Origin', operation: 'remove' },
        { header: 'Sec-Fetch-Site', operation: 'remove' },
        { header: 'Sec-Fetch-Mode', operation: 'remove' },
        { header: 'Sec-Fetch-Dest', operation: 'remove' },
        { header: 'Sec-Fetch-User', operation: 'remove' },
      ],
    },
    condition: { urlFilter: '||android.clients.google.com/fdfe', resourceTypes: ['xmlhttprequest'] },
  };
}
function dnrSearchRule() {
  // play.google.com redirects to accounts.google.com if the request looks
  // like a logged-out browser-extension fetch. A real desktop-Chrome UA
  // and a stripped Origin defuses that.
  return {
    id: DNR_SEARCH_ID,
    priority: 1,
    action: {
      type: 'modifyHeaders',
      requestHeaders: [
        { header: 'User-Agent', operation: 'set', value: PLAY_WEB_UA },
        { header: 'Origin', operation: 'remove' },
        { header: 'Referer', operation: 'set', value: 'https://play.google.com/' },
        { header: 'Sec-Fetch-Site', operation: 'remove' },
        { header: 'Sec-Fetch-Mode', operation: 'remove' },
        { header: 'Sec-Fetch-Dest', operation: 'remove' },
        { header: 'Sec-Fetch-User', operation: 'remove' },
      ],
    },
    condition: {
      urlFilter: '||play.google.com/store',
      resourceTypes: ['xmlhttprequest'],
    },
  };
}
function dnrCdnRule() {
  // The Play API redirects to *.gvt1.com; CDN doesn't return CORS headers,
  // so strip Origin + Sec-Fetch-* on those domains too.
  return {
    id: DNR_CDN_ID,
    priority: 1,
    action: {
      type: 'modifyHeaders',
      requestHeaders: [
        { header: 'Origin', operation: 'remove' },
        { header: 'Sec-Fetch-Site', operation: 'remove' },
        { header: 'Sec-Fetch-Mode', operation: 'remove' },
        { header: 'Sec-Fetch-Dest', operation: 'remove' },
        { header: 'Sec-Fetch-User', operation: 'remove' },
      ],
    },
    condition: {
      requestDomains: ['gvt1.com', 'googleusercontent.com', 'play.googleapis.com'],
      resourceTypes: ['xmlhttprequest'],
    },
  };
}

async function installCoreDnrRules(playUserAgent) {
  const coreIds = new Set([DNR_DISPENSER_ID, DNR_FDFE_ID, DNR_CDN_ID, DNR_SEARCH_ID]);
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  const removeRuleIds = existing.filter((r) => coreIds.has(r.id)).map((r) => r.id);
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds,
    addRules: [dnrDispenserRule(), dnrFdfeRule(playUserAgent), dnrCdnRule(), dnrSearchRule()],
  });
}

async function allocDownloadRuleId() {
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  const inUse = new Set(
    existing
      .filter((r) => r.id >= DNR_DOWNLOAD_ID_MIN && r.id <= DNR_DOWNLOAD_ID_MAX)
      .map((r) => r.id),
  );
  for (let attempt = 0; attempt <= DNR_DOWNLOAD_ID_MAX - DNR_DOWNLOAD_ID_MIN; attempt++) {
    const id = nextDownloadRuleId;
    nextDownloadRuleId = nextDownloadRuleId >= DNR_DOWNLOAD_ID_MAX ? DNR_DOWNLOAD_ID_MIN : nextDownloadRuleId + 1;
    if (!inUse.has(id) && ![...downloadRuleByDl.values()].includes(id)) return id;
  }
  throw new Error('out of DNR download rule ids');
}

async function applyCookieRule(ruleId, url, cookies) {
  const cookieValue = cookies.map((c) => `${c.name}=${c.value}`).join('; ');
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: [ruleId],
    addRules: [{
      id: ruleId,
      priority: 1,
      action: {
        type: 'modifyHeaders',
        requestHeaders: [
          { header: 'Cookie', operation: 'set', value: cookieValue },
          { header: 'Origin', operation: 'remove' },
        ],
      },
      condition: {
        urlFilter: url,
        resourceTypes: ['xmlhttprequest', 'main_frame', 'sub_frame', 'other'],
      },
    }],
  });
}

async function clearDnrRule(ruleId) {
  if (!ruleId) return;
  try {
    await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: [ruleId], addRules: [] });
  } catch (err) {
    swLog.warn('clearDnrRule failed for', ruleId, err);
  }
}

/**
 * On SW boot, any DNR rule in the per-download ID range that isn't
 * tracked in `downloadRuleByDl` is dead weight from a previous SW
 * lifetime — most often from a page-side `app.prepareInstall` that
 * never reached `app.releaseRules` because the SW restarted, the tab
 * was closed, or the merge crashed. Left around they accumulate and
 * eventually exhaust the dynamic-rule budget.
 *
 * `downloadRuleByDl` rules are kept because they're still tied to live
 * chrome.downloads jobs and `downloads.onChanged` will free them.
 */
async function sweepStaleDownloadRules() {
  try {
    await hydrateDlMap();
    const live = new Set(downloadRuleByDl.values());
    const existing = await chrome.declarativeNetRequest.getDynamicRules();
    const stale = existing
      .filter((r) => r.id >= DNR_DOWNLOAD_ID_MIN && r.id <= DNR_DOWNLOAD_ID_MAX && !live.has(r.id))
      .map((r) => r.id);
    if (stale.length === 0) return 0;
    await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: stale, addRules: [] });
    swLog.info('swept', stale.length, 'stale download DNR rule(s):', stale.slice(0, 10));
    return stale.length;
  } catch (err) {
    swLog.warn('sweepStaleDownloadRules failed:', err);
    return 0;
  }
}
