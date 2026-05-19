// 90-action.js — toolbar button click + lifecycle hooks for DNR.

chrome.runtime.onInstalled.addListener(() => {
  installCoreDnrRules().catch((e) => swLog.error('DNR install (onInstalled):', e));
});
chrome.runtime.onStartup.addListener(() => {
  installCoreDnrRules().catch((e) => swLog.error('DNR install (onStartup):', e));
});
// Also call eagerly on first SW boot — `onInstalled` does not fire when
// the SW is woken by a message rather than freshly installed.
installCoreDnrRules().catch((e) => swLog.error('DNR install (boot):', e));

chrome.action.onClicked.addListener(async () => {
  const tabs = await chrome.tabs.query({ url: PAGE_URL });
  if (tabs.length > 0) {
    await chrome.tabs.update(tabs[0].id, { active: true });
    if (tabs[0].windowId) await chrome.windows.update(tabs[0].windowId, { focused: true });
  } else {
    await chrome.tabs.create({ url: PAGE_URL });
  }
});
