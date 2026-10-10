import { scanUrl } from '../engine';
import { blockThreshold, getSettings } from '../storage/settings';
import { getDetectionRules } from '../storage/detectionRules';
import { addHistory } from '../storage/history';
import type { Message } from '../shared/messages';
import { routeMessageAnalysis } from './threatRouter';
import { checkEmailReputations, emailReputationLimits } from './emailReputation';
import { checkUrlReputations, MAX_URLS_PER_LOOKUP } from './urlReputation';
import { addAllowOnce, consumeAllowOnce } from './allowOnce';
import { getIntelSettings } from './intel/intelSettings';

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
  if (msg.type === 'ANALYZE_MESSAGE') {
    if (sender.id !== chrome.runtime.id || sender.tab !== undefined) {
      sendResponse({ error: 'Message analysis is only available from the AI Guard popup.' });
      return false;
    }
    if (typeof msg.text !== 'string' || msg.text.trim().length === 0 || msg.text.length > 20_000) {
      sendResponse({ error: 'Enter a message under 20,000 characters to analyze.' });
      return false;
    }
    if (msg.intent !== 'automatic' && msg.intent !== 'explain') {
      sendResponse({ error: 'Choose a valid message analysis action.' });
      return false;
    }

    void Promise.all([getDetectionRules(), getIntelSettings()])
      .then(([rules, intelSettings]) => routeMessageAnalysis(msg.text, rules, msg.intent, intelSettings.mode))
      .then(sendResponse)
      .catch((error: unknown) => {
        console.error('[AI Guard] message analysis failed', error);
        sendResponse({
          error: error instanceof Error ? error.message : 'Could not analyze this message.',
        });
      });
    return true;
  }
  if (msg.type === 'CHECK_EMAIL_REPUTATION') {
    if (
      sender.id !== chrome.runtime.id ||
      !sender.tab ||
      sender.frameId !== 0 ||
      !sender.url ||
      !/^https?:/i.test(sender.url)
    ) {
      sendResponse({ error: 'Online email reputation checks are only available for scanned web pages.' });
      return false;
    }
    if (
      !Array.isArray(msg.addresses) ||
      msg.addresses.length > emailReputationLimits.maxEmailsPerPage ||
      !msg.addresses.every((address) => typeof address === 'string')
    ) {
      sendResponse({ error: `Check up to ${emailReputationLimits.maxEmailsPerPage} email addresses per page.` });
      return false;
    }

    void getSettings()
      .then((settings) => {
        if (!settings.onlineEmailChecks) throw new Error('Online email reputation checks are disabled in settings.');
        return checkEmailReputations(msg.addresses);
      })
      .then((results) => {
        const response: import('../shared/emailReputation').EmailReputationResponse = {
          results,
          message: 'Online reputation lookup complete.',
        };
        sendResponse(response);
      })
      .catch((error: unknown) => {
        console.warn('[AI Guard] online email reputation lookup failed', error);
        sendResponse({
          error: error instanceof Error ? error.message : 'Online email reputation lookup failed.',
        });
      });
    return true;
  }
  if (msg.type === 'CHECK_URL_REPUTATION') {
    if (sender.id !== chrome.runtime.id || sender.tab !== undefined) {
      sendResponse({ error: 'Online URL reputation checks are only available from the AI Guard popup.' });
      return false;
    }
    if (
      !Array.isArray(msg.urls) ||
      msg.urls.length > MAX_URLS_PER_LOOKUP ||
      !msg.urls.every((url) => typeof url === 'string')
    ) {
      sendResponse({ error: `Check up to ${MAX_URLS_PER_LOOKUP} URLs at a time.` });
      return false;
    }

    void getSettings()
      .then((settings) => {
        if (!settings.onlineUrlChecks) {
          throw new Error('Online URL reputation checks are disabled in Settings. Enable "Allow manual URL lookups" in Settings to use this.');
        }
        return checkUrlReputations(msg.urls, settings);
      })
      .then((results) => sendResponse({ results, message: 'Online URL reputation lookup complete.' }))
      .catch((error: unknown) => {
        console.warn('[AI Guard] online URL reputation lookup failed', error);
        sendResponse({ error: error instanceof Error ? error.message : 'Online URL reputation lookup failed.' });
      });
    return true;
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