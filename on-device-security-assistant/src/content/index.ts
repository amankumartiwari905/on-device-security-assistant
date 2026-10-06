import { levelFor, scanPage, scanUrl } from '../engine';
import type { ScanResult, Verdict } from '../engine';
import { analyzePageEmails } from '../engine/email/emailAnalyzer';
import type { EmailAssessment, EmailStatus } from '../engine/email/emailAnalyzer';
import { getSettings } from '../storage/settings';
import { DETECTION_RULES_KEY, getDetectionRules } from '../storage/detectionRules';
import type { DetectionRules } from '../engine/url/rules';
import type { Message } from '../shared/messages';

const SCANNED = 'data-aiguard';
const EMAIL_PANEL_ID = 'aiguard-emails';
let lastScannedText: string | undefined;
let lastScannedUrl = '';
let lastPageVerdict: ScanResult | undefined;
let lastEmailSnapshot = '';
let emailPanelDismissed = false;
let timer: number | undefined;
const originalLinkPresentation = new WeakMap<HTMLAnchorElement, { outline: string; title: string | null }>();

function detectionRulesVersion(rules: DetectionRules): string {
  const serialized = JSON.stringify(rules);
  let hashCode = 2166136261;
  for (let index = 0; index < serialized.length; index++) {
    hashCode = Math.imul(hashCode ^ serialized.charCodeAt(index), 16777619);
  }
  return (hashCode >>> 0).toString(36);
}

function clearLinkFlag(a: HTMLAnchorElement): void {
  const original = originalLinkPresentation.get(a);
  if (!original) return;
  a.style.outline = original.outline;
  if (original.title === null) a.removeAttribute('title');
  else a.setAttribute('title', original.title);
  originalLinkPresentation.delete(a);
}

function flagLink(a: HTMLAnchorElement, level: 'suspicious' | 'dangerous', message: string): void {
  if (!originalLinkPresentation.has(a)) {
    originalLinkPresentation.set(a, { outline: a.style.outline, title: a.getAttribute('title') });
  }
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

function scanLinks(rules: DetectionRules): void {
  const rulesVersion = detectionRulesVersion(rules);
  document.querySelectorAll<HTMLAnchorElement>('a[href]').forEach((a) => {
    const signature = `${a.href}|${a.textContent ?? ''}|${rulesVersion}`;
    if (a.getAttribute(SCANNED) === signature) return;
    clearLinkFlag(a);
    a.setAttribute(SCANNED, signature);
    if (!/^https?:/i.test(a.href)) return;

    const v = scanUrl(a.href, rules);
    if (v.level !== 'safe') {
      flagLink(a, v.level, `${v.level} link. ${v.reasons[0] ?? ''}`);
    } else if (textLooksLikeDifferentSite(a)) {
      flagLink(a, 'suspicious', 'The link text shows a different site than where it actually goes');
    }
  });
}

function showBanner(verdict: Verdict): void {
  if (document.getElementById('aiguard-banner')) return;

  const host = document.createElement('div');
  host.id = 'aiguard-banner';
  const root = host.attachShadow({ mode: 'open' });
  const color = verdict.level === 'dangerous' ? '#b42318' : verdict.level === 'suspicious' ? '#a15c00' : '#18794e';
  const levelLabel = verdict.level === 'dangerous' ? 'High risk' : verdict.level === 'suspicious' ? 'Elevated risk' : 'Lower risk';

  const style = document.createElement('style');
  style.textContent = `
    * { box-sizing: border-box; }
    .b { position: fixed; top: 12px; right: 12px; z-index: 2147483647;
         width: min(390px, calc(100vw - 24px));
         max-height: max(0px, calc((100vh - 40px) / 2));
         max-height: max(0px, calc((100dvh - 40px) / 2)); overflow: auto;
         font: 13px/1.45 system-ui, sans-serif; color: #172026; background: #fff;
         border: 1px solid ${color}; border-top: 4px solid ${color}; border-radius: 12px; padding: 14px;
         box-shadow: 0 8px 28px rgba(0,0,0,.2); }
    .head, .score-row, .actions { display: flex; align-items: center; justify-content: space-between; gap: 10px; }
    .head strong { color: ${color}; font-size: 15px; }
    .score { color: ${color}; font-size: 20px; font-weight: 750; white-space: nowrap; }
    .meter { height: 7px; margin: 7px 0 4px; overflow: hidden; background: #e8ecef; border-radius: 99px; }
    .meter > div { height: 100%; border-radius: inherit; background: ${color}; }
    .scale, .note { margin: 4px 0 10px; color: #59666e; font-size: 11px; }
    .section-title { margin: 12px 0 5px; font-size: 12px; }
    .signals { display: grid; gap: 8px; margin: 0 0 10px; padding: 0; list-style: none; }
    .signal { padding: 8px 9px; background: #f7f8f9; border: 1px solid #e6e9eb; border-radius: 8px; }
    .signal-head { display: flex; justify-content: space-between; gap: 8px; font-weight: 650; }
    .weight { color: #59666e; font-size: 11px; white-space: nowrap; }
    .evidence { margin: 4px 0 0; color: #59666e; font-size: 11px; overflow-wrap: anywhere; }
    .actions { justify-content: flex-end; }
    .b button { cursor: pointer; border: 0; border-radius: 6px; padding: 6px 10px; background: #172026; color: #fff; font: inherit; }
  `;

  const box = document.createElement('div');
  box.className = 'b';
  box.setAttribute('role', 'alert');
  box.setAttribute('aria-label', 'AI Guard page risk assessment');
  const head = document.createElement('div');
  head.className = 'head';
  const title = document.createElement('strong');
  title.textContent = `AI Guard: ${levelLabel}`;
  const score = document.createElement('span');
  score.className = 'score';
  score.textContent = `${verdict.score}/100`;
  head.append(title, score);

  const meter = document.createElement('div');
  meter.className = 'meter';
  meter.setAttribute('role', 'meter');
  meter.setAttribute('aria-label', 'Page risk score');
  meter.setAttribute('aria-valuemin', '0');
  meter.setAttribute('aria-valuemax', '100');
  meter.setAttribute('aria-valuenow', String(verdict.score));
  const fill = document.createElement('div');
  fill.style.width = `${verdict.score}%`;
  meter.appendChild(fill);
  const scale = document.createElement('p');
  scale.className = 'scale';
  scale.textContent = '0–29 lower risk · 30–59 elevated · 60–100 high risk';

  const sectionTitle = document.createElement('h2');
  sectionTitle.className = 'section-title';
  sectionTitle.textContent = `Detected indicators (${verdict.signals.length})`;
  const list = document.createElement('ul');
  list.className = 'signals';
  for (const signal of verdict.signals.slice(0, 5)) {
    const item = document.createElement('li');
    item.className = 'signal';
    const signalHead = document.createElement('div');
    signalHead.className = 'signal-head';
    const reason = document.createElement('span');
    reason.textContent = signal.reason;
    const weight = document.createElement('span');
    weight.className = 'weight';
    weight.textContent = `Signal ${signal.weight}/100`;
    signalHead.append(reason, weight);
    item.appendChild(signalHead);
    if (signal.evidence) {
      const evidence = document.createElement('p');
      evidence.className = 'evidence';
      evidence.textContent = `Matched: “${signal.evidence}”`;
      item.appendChild(evidence);
    }
    list.appendChild(item);
  }
  const note = document.createElement('p');
  note.className = 'note';
  note.textContent = 'This is an on-device, signal-based estimate—not a probability or a guarantee.';
  const actions = document.createElement('div');
  actions.className = 'actions';
  const btn = document.createElement('button');
  btn.textContent = 'Dismiss';
  btn.addEventListener('click', () => host.remove());
  actions.appendChild(btn);

  box.append(head, meter, scale, sectionTitle, list, note, actions);
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
    * { box-sizing: border-box; }
    .panel { position: fixed; right: 12px; bottom: 12px; z-index: 2147483647;
      width: min(410px, calc(100vw - 24px));
      max-height: max(0px, calc((100vh - 40px) / 2));
      max-height: max(0px, calc((100dvh - 40px) / 2)); overflow: auto;
      padding: 14px; color: #172026; background: #fff;
      border: 1px solid #cbd3d8; border-radius: 12px; box-shadow: 0 8px 28px rgba(0,0,0,.2);
      font: 13px/1.4 system-ui, sans-serif; }
    .head { display: flex; align-items: center; justify-content: space-between; gap: 10px; }
    .head strong { font-size: 14px; }
    .close { border: 0; padding: 2px 7px; color: #172026; background: #edf1f3;
      border-radius: 4px; cursor: pointer; font: inherit; }
    .note { margin: 8px 0 10px; color: #52616a; font-size: 11px; }
    .summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: 6px; margin: 10px 0; }
    .stat { padding: 7px; background: #f5f7f8; border-radius: 7px; text-align: center; }
    .stat strong { display: block; font-size: 15px; }
    .stat span { color: #52616a; font-size: 10px; }
    .list { display: grid; gap: 9px; margin: 0; padding: 0; list-style: none; }
    .item { padding: 10px; background: #fafbfb; border: 1px solid #e0e5e8; border-radius: 9px; overflow-wrap: anywhere; }
    .identity { display: flex; flex-wrap: wrap; align-items: center; gap: 4px 8px; }
    .address { font-weight: 650; }
    .status { display: inline-block; margin-left: 6px; font-size: 11px; font-weight: 650; }
    .matches-site { color: #176b3a; }
    .suspicious { color: #b42318; }
    .external { color: #8a5200; }
    .score-row { display: flex; justify-content: space-between; align-items: baseline; gap: 8px; margin-top: 8px; font-size: 11px; }
    .score { font-weight: 750; }
    .meter { height: 6px; margin: 4px 0 6px; overflow: hidden; background: #e5e9eb; border-radius: 99px; }
    .meter > div { height: 100%; border-radius: inherit; }
    .meta { color: #52616a; font-size: 10px; }
    .reason { margin: 5px 0 0; color: #39464e; font-size: 11px; }
    .signals { margin: 6px 0 0; padding-left: 16px; color: #52616a; font-size: 10px; }
    .signals li { margin-top: 3px; }
  `;

  const panel = document.createElement('section');
  panel.className = 'panel';
  panel.setAttribute('aria-label', 'Email addresses found on this page');

  const head = document.createElement('div');
  head.className = 'head';
  const title = document.createElement('strong');
  title.textContent = `AI Guard: email risk report`;
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
  note.textContent = 'Scores reflect detected warning signs—not the chance an address is fraudulent. Offline checks cannot confirm mailbox ownership.';

  const summary = document.createElement('div');
  summary.className = 'summary';
  const counts = [
    { label: 'Found', value: emails.length },
    { label: 'Suspicious', value: emails.filter((email) => email.status === 'suspicious').length },
    { label: 'Matches site', value: emails.filter((email) => email.status === 'matches-site').length },
    { label: 'External', value: emails.filter((email) => email.status === 'external').length },
  ];
  for (const count of counts) {
    const stat = document.createElement('div');
    stat.className = 'stat';
    const value = document.createElement('strong');
    value.textContent = String(count.value);
    const label = document.createElement('span');
    label.textContent = count.label;
    stat.append(value, label);
    summary.appendChild(stat);
  }

  const list = document.createElement('ul');
  list.className = 'list';
  const sortedEmails = [...emails].sort((a, b) => b.riskScore - a.riskScore);
  for (const email of sortedEmails) {
    const item = document.createElement('li');
    item.className = 'item';
    const color = email.riskScore >= 60 ? '#b42318' : email.riskScore >= 30 ? '#a15c00' : '#18794e';
    const identity = document.createElement('div');
    identity.className = 'identity';
    const address = document.createElement('span');
    address.className = 'address';
    address.textContent = email.address;
    const status = document.createElement('span');
    status.className = `status ${email.status}`;
    status.textContent = emailStatusLabel(email.status);
    identity.append(address, status);
    const scoreRow = document.createElement('div');
    scoreRow.className = 'score-row';
    const riskLevel = document.createElement('span');
    riskLevel.className = 'score';
    riskLevel.style.color = color;
    riskLevel.textContent = email.riskScore >= 60 ? 'High risk' : email.riskScore >= 30 ? 'Elevated risk' : 'Lower risk';
    const score = document.createElement('strong');
    score.className = 'score';
    score.style.color = color;
    score.textContent = `${email.riskScore}/100`;
    scoreRow.append(riskLevel, score);
    const meter = document.createElement('div');
    meter.className = 'meter';
    meter.setAttribute('role', 'meter');
    meter.setAttribute('aria-label', `Risk score for ${email.address}`);
    meter.setAttribute('aria-valuemin', '0');
    meter.setAttribute('aria-valuemax', '100');
    meter.setAttribute('aria-valuenow', String(email.riskScore));
    const fill = document.createElement('div');
    fill.style.width = `${email.riskScore}%`;
    fill.style.background = color;
    meter.appendChild(fill);
    const meta = document.createElement('div');
    meta.className = 'meta';
    meta.textContent = `${email.category.replace('-', ' ')} · ${email.source} · seen ${email.occurrences} time${email.occurrences === 1 ? '' : 's'}`;
    const reason = document.createElement('p');
    reason.className = 'reason';
    reason.textContent = email.explanation;
    item.append(identity, scoreRow, meter, meta, reason);
    if (email.signals.length > 0) {
      const signals = document.createElement('ul');
      signals.className = 'signals';
      for (const signal of email.signals.slice(0, 3)) {
        const signalItem = document.createElement('li');
        signalItem.textContent = `${signal.reason} (${signal.weight}/100)`;
        signals.appendChild(signalItem);
      }
      item.appendChild(signals);
    }
    list.appendChild(item);
  }

  panel.append(head, summary, note, list);
  root.replaceChildren(style, panel);
}

function scanPageEmails(rules: DetectionRules): void {
  const visibleText = document.body?.innerText ?? '';
  const mailtoLinks = [...document.querySelectorAll<HTMLAnchorElement>('a[href^="mailto:"]')]
    .map((link) => mailtoAddress(link.href));
  showEmailPanel(analyzePageEmails([visibleText, ...mailtoLinks], location.hostname, rules));
}

async function run(): Promise<void> {
  const [settings, rules] = await Promise.all([getSettings(), getDetectionRules()]);
  if (!settings.enabled || !settings.scanPageText) {
    document.getElementById(EMAIL_PANEL_ID)?.remove();
    lastEmailSnapshot = '';
    emailPanelDismissed = false;
  }
  if (!settings.enabled) return;

  scanLinks(rules);

  let verdict = scanUrl(location.href, rules);

  if (settings.scanPageText) {
    const text = document.body?.innerText ?? '';
    const url = location.href;
    if (text !== lastScannedText || url !== lastScannedUrl || !lastPageVerdict) {
      lastScannedText = text;
      lastScannedUrl = url;
      lastPageVerdict = scanPage(url, text, rules);
    }
    verdict = lastPageVerdict;
    if (verdict.level === 'dangerous') showBanner(verdict);
    scanPageEmails(rules);
  }

  const msg: Message = { type: 'PAGE_VERDICT', score: verdict.score, level: levelFor(verdict.score) };
  chrome.runtime.sendMessage(msg).catch(() => undefined);
}

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && changes[DETECTION_RULES_KEY]) {
      lastPageVerdict = undefined;
      schedule();
    }
  });

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