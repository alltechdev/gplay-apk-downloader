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
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  const removeRuleIds = existing
    .filter((r) => r.id === DNR_DISPENSER_ID || r.id === DNR_FDFE_ID || r.id === DNR_CDN_ID)
    .map((r) => r.id);
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds,
    addRules: [dnrDispenserRule(), dnrFdfeRule(playUserAgent), dnrCdnRule()],
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
    console.warn('clearDnrRule failed for', ruleId, err);
  }
}
