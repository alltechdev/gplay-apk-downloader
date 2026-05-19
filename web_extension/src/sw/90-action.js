// 90-action.js — toolbar button click + lifecycle hooks for DNR.

async function bootDnr(reason) {
  try { await installCoreDnrRules(); } catch (e) { swLog.error('DNR install (' + reason + '):', e); }
  // Sweep per-download rules orphaned by a previous SW lifetime (crashed
  // mid-merge, tab closed before releaseRules, etc.). Safe to nuke
  // anything in the download-id range that isn't tied to a live
  // chrome.downloads job in `downloadRuleByDl`.
  try { await sweepStaleDownloadRules(); } catch (e) { swLog.warn('DNR sweep (' + reason + '):', e); }
}

chrome.runtime.onInstalled.addListener(() => { bootDnr('onInstalled'); });
chrome.runtime.onStartup.addListener(()  => { bootDnr('onStartup'); });
// Also call eagerly on first SW boot — `onInstalled` does not fire when
// the SW is woken by a message rather than freshly installed.
bootDnr('boot');

chrome.action.onClicked.addListener(async () => {
  const tabs = await chrome.tabs.query({ url: PAGE_URL });
  if (tabs.length > 0) {
    await chrome.tabs.update(tabs[0].id, { active: true });
    if (tabs[0].windowId) await chrome.windows.update(tabs[0].windowId, { focused: true });
  } else {
    await chrome.tabs.create({ url: PAGE_URL });
  }
});
