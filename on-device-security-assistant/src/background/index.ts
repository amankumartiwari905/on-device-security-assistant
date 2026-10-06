import { scanUrl } from '../engine';
import { blockThreshold, getSettings } from '../storage/settings';
import { getDetectionRules } from '../storage/detectionRules';
import { addHistory } from '../storage/history';
import type { Message } from '../shared/messages';
import { addAllowOnce, consumeAllowOnce } from './allowOnce';

// Check every top-level navigation before the page loads.
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0 || !/^https?:/i.test(details.url)) return;

  const settings = await getSettings();
  if (!settings.enabled) return;

  const hostname = new URL(details.url).hostname;
  if (settings.allowlist.includes(hostname)) return;
  if (await consumeAllowOnce(details.url, chrome.storage.session)) return;

  const rules = await getDetectionRules();
  const verdict = scanUrl(details.url, rules);
  if (verdict.score < blockThreshold(settings.sensitivity)) return;

  await addHistory({
    time: Date.now(),
    hostname,
    score: verdict.score,
    level: verdict.level,
    reasons: verdict.reasons.slice(0, 3),
  });

  const query = new URLSearchParams({
    url: details.url,
    score: String(verdict.score),
    signals: JSON.stringify(verdict.signals),
  });
  await chrome.tabs.update(details.tabId, { url: `${chrome.runtime.getURL('warning.html')}?${query}` });
});

chrome.runtime.onMessage.addListener((msg: Message, sender, sendResponse) => {
  if (msg.type === 'ALLOW_ONCE') {
    addAllowOnce(msg.url, chrome.storage.session)
      .then((ok) => sendResponse({ ok }))
      .catch(() => sendResponse({ ok: false }));
    return true; // keep the channel open for the async response
  }
  if (msg.type === 'PAGE_VERDICT' && sender.tab?.id !== undefined) {
    const tabId = sender.tab.id;
    chrome.action.setBadgeText({ tabId, text: msg.level === 'safe' ? '' : '!' });
    chrome.action.setBadgeBackgroundColor({
      tabId,
      color: msg.level === 'dangerous' ? '#dc2626' : '#d97706',
    });
  }
  return false;
});