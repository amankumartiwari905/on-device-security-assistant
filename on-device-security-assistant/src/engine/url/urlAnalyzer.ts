import type { Signal } from '../types';
import { analyzeDomain } from '../domain/lookalike';
import { extractUrlFeatures, getRegistrableDomain, parseUrl } from './urlFeatures';
import { DEFAULT_DETECTION_RULES } from './rules';
import type { DetectionRules } from './rules';

const REDIRECT_KEYS = new Set([
  'callback', 'continue', 'continue_to', 'dest', 'destination', 'destination_url', 'forward', 'forward_url',
  'go', 'goto', 'link', 'next', 'out', 'redirect', 'redirect_uri', 'redirect_url', 'redirecturl',
  'return', 'return_to', 'return_url', 'returnto', 'returnurl', 'target', 'target_url', 'to', 'u', 'url',
]);
const SENSITIVE_QUERY_KEYS = new Set([
  'account', 'card', 'code', 'email', 'login', 'otp', 'pass', 'password', 'payment', 'pin', 'user', 'username',
]);
const SENSITIVE_PATH = /(?:^|[\/_-])(?:account|billing|checkout|confirm|login|payment|password|signin|verify)(?:$|[\/_-])/i;

function rawHostname(raw: string, fallback: string): string {
  const authority = raw.match(/^https?:\/\/([^/?#]*)/i)?.[1];
  if (!authority || authority.includes('\\')) return fallback;
  const hostPort = authority.slice(authority.lastIndexOf('@') + 1);
  if (hostPort.startsWith('[')) return hostPort.slice(0, hostPort.indexOf(']') + 1);
  return hostPort.replace(/:\d+$/, '');
}

function decodeCandidates(value: string): string[] {
  const candidates = [value];
  for (let i = 0; i < 2; i++) {
    try {
      const decoded = decodeURIComponent(candidates[i]);
      if (decoded === candidates[i]) break;
      candidates.push(decoded);
    } catch {
      break;
    }
  }
  return candidates;
}

function hasExternalRedirect(url: URL): boolean {
  const sourceDomain = getRegistrableDomain(url.hostname);
  const candidates: string[] = [];
  for (const [key, value] of url.searchParams) {
    const normalizedKey = key.toLowerCase();
    if (!REDIRECT_KEYS.has(normalizedKey) && !/https?:|%3a%2f%2f/i.test(value)) continue;
    candidates.push(...decodeCandidates(value));
  }
  candidates.push(...decodeCandidates(url.pathname));

  for (const candidate of candidates) {
    const embedded = candidate.match(/(?:https?:)?\/\/[^\s"'<>]+/gi) ?? [];
    const destinations = [candidate, ...embedded];
    for (const destination of destinations) {
      const absolute = destination.startsWith('//') ? `${url.protocol}${destination}` : destination;
      try {
        const target = new URL(absolute);
        if ((target.protocol === 'http:' || target.protocol === 'https:') &&
            getRegistrableDomain(target.hostname) !== sourceDomain) return true;
      } catch {
        // Ignore values that are not absolute redirect destinations.
      }
    }
  }
  return false;
}

export function analyzeUrl(raw: string, rules: DetectionRules = DEFAULT_DETECTION_RULES): Signal[] {
  const url = parseUrl(raw);
  if (!url || (url.protocol !== 'http:' && url.protocol !== 'https:')) {
    return [{ id: 'invalid-url', weight: 30, reason: 'The link is malformed or uses an unsupported protocol' }];
  }

  const f = extractUrlFeatures(url, raw, rules);
  const signals: Signal[] = [];
  const add = (id: string, weight: number, reason: string) => signals.push({ id, weight, reason });
  const encodedCharacters = raw.match(/%[0-9a-f]{2}/gi)?.length ?? 0;
  const authority = raw.match(/^https?:\/\/([^/?#]*)/i)?.[1] ?? '';
  const sensitiveQueryKeys = [...url.searchParams.keys()]
    .filter((key) => SENSITIVE_QUERY_KEYS.has(key.toLowerCase().replace(/[-_]/g, '')));
  let decodedPath = url.pathname;
  try {
    decodedPath = decodeURIComponent(decodedPath);
  } catch {
    // Malformed escapes are reported separately below.
  }

  if (f.hasIp) add('ip-host', 40, 'Uses a raw IP address instead of a domain name');
  if (f.hasAt) add('credentials-in-url', 30, 'Contains a username/password section that can hide the real destination');
  if (f.hasPunycode) add('punycode', 25, 'Domain uses special international characters that can imitate real brands');
  if (url.protocol === 'http:') add('no-https', 10, 'Connection is not encrypted (HTTP)');
  if (f.length > 500) add('long-url', 25, 'Extremely long link with excessive tracking or hidden data');
  else if (f.length > 200) add('long-url', 15, 'Unusually long link');
  else if (f.length > 100) add('long-url', 8, 'Long link');
  if (f.hostLength > 50) add('long-domain', 20, 'Domain name is unusually long');
  else if (f.hostLength > 30) add('long-domain', 10, 'Domain name is longer than typical');
  if (f.subdomains >= 5) add('many-subdomains', 25, 'Has an unusually large number of subdomains');
  else if (f.subdomains >= 3) add('many-subdomains', 15, 'Has many subdomains, a common way to disguise the real domain');
  if (f.hyphens >= 3) add('many-hyphens', 15, 'Domain contains many hyphens');
  if (url.port) add('unusual-port', 15, `Uses a nonstandard network port (${url.port})`);
  if (f.suspiciousTld) add('suspicious-tld', 15, 'Uses a domain ending that is frequently abused for scams');
  if (f.isShortener) add('shortener', 15, 'Shortened link hides the real destination');
  if (f.digitRatio > 0.3 && f.hostLength > 10) add('digit-heavy', 12, 'Domain is full of digits, which looks auto-generated');
  if (f.keywordCount >= 2) add('keywords', 20, 'Contains several credential-related words (login, verify, secure...)');
  else if (f.keywordCount === 1) add('keyword', 8, 'Contains a credential-related word');
  if (SENSITIVE_PATH.test(decodedPath)) add('sensitive-path', 14, 'Path targets a login, payment, or account-verification flow');
  if (sensitiveQueryKeys.length > 0) add('sensitive-query', 15, 'Query parameters request account, payment, or sign-in information');
  else if ([...url.searchParams.keys()].length >= 6) add('many-query-params', 10, 'Contains an unusually large number of query parameters');
  if (/%(?![0-9a-f]{2})/i.test(raw)) add('malformed-encoding', 30, 'Contains an invalid percent-encoding sequence');
  if (/[%](?:0[0-9a-f]|1[0-9a-f]|7f)/i.test(raw) || /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/u.test(raw) || /\\/.test(authority)) {
    add('suspicious-characters', 25, 'Contains hidden control, direction-changing, or authority-separator characters');
  }
  if (encodedCharacters >= 5 && encodedCharacters / raw.length > 0.08) {
    add('encoded-obfuscation', 15, 'Uses unusually dense percent-encoding to obscure the link');
  }
  if (hasExternalRedirect(url)) add('external-redirect', 30, 'Contains an embedded URL that redirects to a different site');

  if (!f.hasIp) {
    const domainSignals = analyzeDomain(rawHostname(raw, url.hostname), rules);
    signals.push(...domainSignals);
    if (domainSignals.length > 0 && f.keywordCount >= 2) {
      const brand = domainSignals[0].reason.match(/(?:imitate|resembles|uses the)\s+(?:the\s+)?([\w-]+)/i)?.[1] ?? 'a trusted brand';
      add('brand-credential-lure', 50, `Combines a ${brand} lookalike domain with login or verification language`);
    }
  }
  return signals;
}