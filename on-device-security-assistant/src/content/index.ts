import { levelFor, scanPage, scanUrl } from '../engine';
import type { ScanResult, Verdict } from '../engine';
import { analyzePageEmails } from '../engine/email/emailAnalyzer';
import type { EmailAssessment, EmailStatus } from '../engine/email/emailAnalyzer';
import { getSettings } from '../storage/settings';
import { getDetectionRules } from '../storage/detectionRules';
import type { Message } from '../shared/messages';

const SCANNED = 'data-aiguard';
const EMAIL_PANEL_ID = 'aiguard-emails';
let lastScannedText: string | undefined;
let lastScannedUrl = '';
let lastPageVerdict: ScanResult | undefined;
let lastEmailSnapshot = '';
let emailPanelDismissed = false;
let timer: number | undefined;

function flagLink(a: HTMLAnchorElement, level: 'suspicious' | 'dangerous', message: string): void {
  a.style.outline = `2px solid ${level === 'dangerous' ? '#dc2626' : '#d97706'}`;
  a.title = `AI Guard: ${message}`;
}

/** Link text shows one site (paypal.com) but the href goes somewhere else. */
function textLooksLikeDifferentSite(a: HTMLAnchorElement): boolean {
  const shown = (a.textContent ?? '').trim();
  const m = shown.match(/^(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/?#]|$)/i);
  if (!m) return false;
  try {
    const real = new URL(a.href).hostname.replace(/^www\./, '');
    const claimed = m[1].toLowerCase().replace(/^www\./, '');
    return real !== claimed && !real.endsWith(`.${claimed}`);
  } catch {
    return false;
  }
}

function scanLinks(): void {
  document.querySelectorAll<HTMLAnchorElement>(`a[href]:not([${SCANNED}])`).forEach((a) => {
    a.setAttribute(SCANNED, '1');
    if (!/^https?:/i.test(a.href)) return;

    const v = scanUrl(a.href);
    if (v.level !== 'safe') {
      flagLink(a, v.level, `${v.level} link. ${v.reasons[0] ?? ''}`);
    } else if (textLooksLikeDifferentSite(a)) {
      flagLink(a, 'suspicious', 'The link text shows a different site than where it actually goes');
    }
  });
}

chrome.runtime.onMessage.addListener((msg: Message, sender, sendResponse) => {
  if (msg.type !== 'GET_PAGE_LINKS') return false;
  if (sender.id !== chrome.runtime.id) {
    sendResponse({ error: 'Page link analysis is only available to AI Guard.' });
    return false;
  }

  void getDetectionRules()
    .then((rules) => {
      const uniqueLinks = new Map<string, ReturnType<typeof scanUrl>>();
      const anchors = new Map<string, string>();
      document.querySelectorAll<HTMLAnchorElement>('a[href]').forEach((anchor) => {
        if (!/^https?:/i.test(anchor.href) || uniqueLinks.has(anchor.href)) return;
        const verdict = scanUrl(anchor.href, rules);
        if (verdict.level === 'safe' && !textLooksLikeDifferentSite(anchor)) return;
        uniqueLinks.set(anchor.href, verdict);
        anchors.set(anchor.href, (anchor.textContent ?? '').trim().slice(0, 160));
      });

      return {
        links: [...uniqueLinks].map(([url, verdict]) => ({
          url,
          text: anchors.get(url) ?? '',
          verdict,
        })),
      };
    })
    .then(sendResponse)
    .catch((error: unknown) => {
      console.error('[AI Guard] could not analyze links on this page', error);
      sendResponse({ error: 'Could not analyze links on this page.' });
    });
  return true;
});

function showBanner(verdict: Verdict): void {
  if (document.getElementById('aiguard-banner')) return;

  const host = document.createElement('div');
  host.id = 'aiguard-banner';
  const root = host.attachShadow({ mode: 'open' });

  const style = document.createElement('style');
  style.textContent = `
    .b { position: fixed; top: 12px; right: 12px; z-index: 2147483647; max-width: 340px;
         font: 13px/1.4 system-ui, sans-serif; color: #111; background: #fff;
         border: 2px solid #dc2626; border-radius: 10px; padding: 12px 14px;
         box-shadow: 0 6px 24px rgba(0,0,0,.25); }
    .b strong { color: #dc2626; display: block; margin-bottom: 6px; }
    .b ul { margin: 0 0 8px 18px; padding: 0; }
    .b button { cursor: pointer; border: 0; border-radius: 6px; padding: 5px 10px; background: #111; color: #fff; }
  `;

  const box = document.createElement('div');
  box.className = 'b';
  const title = document.createElement('strong');
  title.textContent = 'AI Guard: this page may contain scam content';
  const list = document.createElement('ul');
  for (const r of verdict.reasons) {
    const li = document.createElement('li');
    li.textContent = r; // textContent: reasons can include page-controlled strings
    list.appendChild(li);
  }
  const btn = document.createElement('button');
  btn.textContent = 'Dismiss';
  btn.addEventListener('click', () => host.remove());

  box.append(title, list, btn);
  root.append(style, box);
  document.documentElement.appendChild(host);
}

function emailStatusLabel(status: EmailStatus): string {
  if (status === 'matches-site') return 'Matches site';
  if (status === 'suspicious') return 'Suspicious';
  return 'External / unverified';
}

function mailtoAddress(href: string): string {
  const encodedAddress = href.replace(/^mailto:/i, '').split('?')[0];
  try {
    return decodeURIComponent(encodedAddress);
  } catch {
    return encodedAddress;
  }
}

function showEmailPanel(emails: EmailAssessment[]): void {
  if (emailPanelDismissed) return;
  const snapshot = JSON.stringify(emails);
  if (snapshot === lastEmailSnapshot) return;
  lastEmailSnapshot = snapshot;

  if (emails.length === 0) {
    document.getElementById(EMAIL_PANEL_ID)?.remove();
    return;
  }

  let host = document.getElementById(EMAIL_PANEL_ID);
  if (!host) {
    host = document.createElement('div');
    host.id = EMAIL_PANEL_ID;
    host.attachShadow({ mode: 'open' });
    document.documentElement.appendChild(host);
  }

  const root = host.shadowRoot;
  if (!root) return;

  const style = document.createElement('style');
  style.textContent = `
    .panel { position: fixed; right: 12px; bottom: 12px; z-index: 2147483647;
      width: min(360px, calc(100vw - 24px)); max-height: min(55vh, 420px); overflow: auto;
      box-sizing: border-box; padding: 12px; color: #172026; background: #fff;
      border: 1px solid #87949c; border-radius: 8px; box-shadow: 0 6px 24px rgba(0,0,0,.22);
      font: 13px/1.4 system-ui, sans-serif; }
    .head { display: flex; align-items: center; justify-content: space-between; gap: 10px; }
    .head strong { font-size: 14px; }
    .close { border: 0; padding: 2px 7px; color: #172026; background: #edf1f3;
      border-radius: 4px; cursor: pointer; font: inherit; }
    .note { margin: 6px 0 10px; color: #52616a; font-size: 11px; }
    .list { display: grid; gap: 8px; margin: 0; padding: 0; list-style: none; }
    .item { padding-top: 8px; border-top: 1px solid #e0e5e8; overflow-wrap: anywhere; }
    .address { font-weight: 650; }
    .status { display: inline-block; margin-left: 6px; font-size: 11px; font-weight: 650; }
    .matches-site { color: #176b3a; }
    .suspicious { color: #b42318; }
    .external { color: #8a5200; }
    .reason { margin: 3px 0 0; color: #52616a; font-size: 11px; }
  `;

  const panel = document.createElement('section');
  panel.className = 'panel';
  panel.setAttribute('aria-label', 'Email addresses found on this page');

  const head = document.createElement('div');
  head.className = 'head';
  const title = document.createElement('strong');
  title.textContent = `AI Guard: ${emails.length} email address${emails.length === 1 ? '' : 'es'}`;
  const close = document.createElement('button');
  close.className = 'close';
  close.type = 'button';
  close.textContent = 'Close';
  close.setAttribute('aria-label', 'Dismiss email analysis');
  close.addEventListener('click', () => {
    emailPanelDismissed = true;
    host?.remove();
  });
  head.append(title, close);

  const note = document.createElement('p');
  note.className = 'note';
  note.textContent = 'Offline checks cannot confirm mailbox existence or ownership.';

  const list = document.createElement('ul');
  list.className = 'list';
  for (const email of emails) {
    const item = document.createElement('li');
    item.className = 'item';
    const address = document.createElement('span');
    address.className = 'address';
    address.textContent = email.address;
    const status = document.createElement('span');
    status.className = `status ${email.status}`;
    status.textContent = emailStatusLabel(email.status);
    const reason = document.createElement('p');
    reason.className = 'reason';
    reason.textContent = email.explanation;
    item.append(address, status, reason);
    list.appendChild(item);
  }

  panel.append(head, note, list);
  root.replaceChildren(style, panel);
}

function scanPageEmails(): void {
  const visibleText = document.body?.innerText ?? '';
  const mailtoLinks = [...document.querySelectorAll<HTMLAnchorElement>('a[href^="mailto:"]')]
    .map((link) => mailtoAddress(link.href));
  showEmailPanel(analyzePageEmails([visibleText, ...mailtoLinks], location.hostname));
}

async function run(): Promise<void> {
  const settings = await getSettings();
  if (!settings.enabled || !settings.scanPageText) {
    document.getElementById(EMAIL_PANEL_ID)?.remove();
    lastEmailSnapshot = '';
    emailPanelDismissed = false;
  }
  if (!settings.enabled) return;

  scanLinks();

  let verdict = scanUrl(location.href);

  if (settings.scanPageText) {
    const text = document.body?.innerText ?? '';
    const url = location.href;
    if (text !== lastScannedText || url !== lastScannedUrl || !lastPageVerdict) {
      lastScannedText = text;
      lastScannedUrl = url;
      lastPageVerdict = scanPage(url, text);
    }
    verdict = lastPageVerdict;
    if (verdict.level === 'dangerous') showBanner(verdict);
    scanPageEmails();
  }

  const msg: Message = { type: 'PAGE_VERDICT', score: verdict.score, level: levelFor(verdict.score) };
  chrome.runtime.sendMessage(msg).catch(() => undefined);
}

function schedule(): void {
  clearTimeout(timer);
  timer = window.setTimeout(() => void run(), 1000);
}

new MutationObserver(schedule).observe(document.documentElement, {
  childList: true,
  subtree: true,
  characterData: true,
  attributes: true,
  attributeFilter: ['href'],
});
schedule();