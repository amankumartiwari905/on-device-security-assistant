import { getDomain } from 'tldts';
import { DEFAULT_DETECTION_RULES } from './rules';
import type { DetectionRules } from './rules';

export { DEFAULT_DETECTION_RULES } from './rules';
export type { DetectionRules } from './rules';

/**
 * URL feature extraction using only native Web APIs.
 * FEATURE_ORDER is the contract with the Phase 2 Python training script (ml/train_url_model.py).
 */
export const FEATURE_ORDER = [
  'length',
  'hostLength',
  'subdomains',
  'specialChars',
  'hyphens',
  'digitRatio',
  'hostEntropy',
  'pathDepth',
  'queryParams',
  'hasIp',
  'hasAt',
  'isHttps',
  'hasPunycode',
  'suspiciousTld',
  'isShortener',
  'keywordCount',
] as const;

export type UrlFeatures = Record<(typeof FEATURE_ORDER)[number], number>;

export const SUSPICIOUS_TLDS = new Set(DEFAULT_DETECTION_RULES.suspiciousTlds);
export const URL_SHORTENERS = new Set(DEFAULT_DETECTION_RULES.urlShorteners);
export const SUSPICIOUS_KEYWORDS = DEFAULT_DETECTION_RULES.suspiciousKeywords;

export function parseUrl(raw: string): URL | null {
  try {
    return new URL(raw);
  } catch {
    return null;
  }
}

export function getRegistrableDomain(hostname: string): string {
  const normalized = hostname.toLowerCase().replace(/\.$/, '');
  return getDomain(normalized, { allowPrivateDomains: true }) ?? normalized;
}

export function calculateUrlLength(url: string): number {
  return url.length;
}

export function containsIpAddress(hostname: string): boolean {
  // new URL() already normalises decimal/hex/octal IPv4 into dotted form.
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || /^\[[0-9a-f:.]+\]$/i.test(hostname);
}

export function countSubdomains(hostname: string): number {
  if (containsIpAddress(hostname)) return 0;
  const total = hostname.split('.').length;
  const base = getRegistrableDomain(hostname).split('.').length;
  return Math.max(total - base, 0);
}

export function countSpecialCharacters(url: string): number {
  return (url.match(/[^a-zA-Z0-9]/g) || []).length;
}

export function countHyphens(hostname: string): number {
  return (hostname.match(/-/g) || []).length;
}

export function shannonEntropy(s: string): number {
  if (!s.length) return 0;
  const freq = new Map<string, number>();
  for (const c of s) freq.set(c, (freq.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export function countSuspiciousKeywords(url: URL, rules: DetectionRules = DEFAULT_DETECTION_RULES): number {
  const hay = (url.hostname + url.pathname).toLowerCase();
  return rules.suspiciousKeywords.filter((keyword) => hay.includes(keyword)).length;
}

export function extractUrlFeatures(
  url: URL,
  raw: string = url.href,
  rules: DetectionRules = DEFAULT_DETECTION_RULES,
): UrlFeatures {
  const host = url.hostname;
  const registrable = getRegistrableDomain(host);
  const tld = host.split('.').pop() ?? '';
  const digits = (host.match(/\d/g) || []).length;

  return {
    length: calculateUrlLength(raw),
    hostLength: host.length,
    subdomains: countSubdomains(host),
    specialChars: countSpecialCharacters(raw),
    hyphens: countHyphens(host),
    digitRatio: host.length ? digits / host.length : 0,
    hostEntropy: shannonEntropy(registrable.split('.')[0]),
    pathDepth: url.pathname.split('/').filter(Boolean).length,
    queryParams: [...url.searchParams.keys()].length,
    hasIp: containsIpAddress(host) ? 1 : 0,
    // Credentials before the host (http://paypal.com@evil.com) is the real trick.
    hasAt: url.username !== '' || url.password !== '' ? 1 : 0,
    isHttps: url.protocol === 'https:' ? 1 : 0,
    hasPunycode: host.includes('xn--') ? 1 : 0,
    suspiciousTld: rules.suspiciousTlds.includes(tld) ? 1 : 0,
    isShortener: rules.urlShorteners.includes(registrable) ? 1 : 0,
    keywordCount: countSuspiciousKeywords(url, rules),
  };
}

export function featuresToVector(f: UrlFeatures): number[] {
  return FEATURE_ORDER.map((k) => f[k]);
}