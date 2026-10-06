import { getRegistrableDomain } from '../url/urlFeatures';
import {
  AUTHORITY_LOCAL_PARTS,
  DISPOSABLE_EMAIL_DOMAINS,
  EMAIL_BRANDS,
  FREE_EMAIL_PROVIDERS,
  FREEMAIL_TYPO_TARGETS,
  SUSPICIOUS_EMAIL_TLDS,
} from './emailData';
import type { EmailBrand } from './emailData';

export interface EmailSignal {
  id: string;
  weight: number;
  reason: string;
}

export const isFreeProvider = (registrable: string): boolean => FREE_EMAIL_PROVIDERS.has(registrable);
export const isDisposableDomain = (registrable: string): boolean => DISPOSABLE_EMAIL_DOMAINS.has(registrable);

const clip = (value: string, max = 40): string => (value.length > max ? `${value.slice(0, max)}...` : value);

export function tokenize(value: string): string[] {
  return value.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
}

/** Edit distance where swapping two adjacent letters counts as one edit (gmial -> gmail). */
export function editDistance(a: string, b: string): number {
  const dp: number[][] = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array<number>(b.length).fill(0)]);
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;

  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        dp[i][j] = Math.min(dp[i][j], dp[i - 2][j - 2] + 1);
      }
    }
  }
  return dp[a.length][b.length];
}

/** Probabilistic OR, the same scheme as the main risk scorer. Result is 0-100. */
export function combineWeights(items: readonly { weight: number }[]): number {
  const miss = items.reduce((p, s) => p * (1 - Math.min(s.weight, 99) / 100), 1);
  return Math.round((1 - miss) * 100);
}

export function findBrand(text: string): EmailBrand | undefined {
  const lower = text.toLowerCase();
  const tokens = tokenize(lower);
  return EMAIL_BRANDS.find(
    (brand) =>
      tokens.includes(brand.name) ||
      (brand.name.length >= 6 && tokens.some((t) => t.includes(brand.name))) ||
      (brand.aliases ?? []).some((alias) => lower.includes(alias)),
  );
}

/** Signals about the domain part (after the @). `domain` must already be ASCII/punycode. */
export function domainSignals(domain: string, pageHostname: string): EmailSignal[] {
  const signals: EmailSignal[] = [];
  const registrable = getRegistrableDomain(domain);
  const labels = domain.split('.');
  const free = isFreeProvider(registrable);

  if (isDisposableDomain(registrable)) {
    signals.push({ id: 'disposable-domain', weight: 45, reason: 'Uses a disposable email service, common in scams and throwaway accounts' });
  }

  if (!free) {
    const target = FREEMAIL_TYPO_TARGETS.find((t) => editDistance(registrable, t) === 1);
    if (target) signals.push({ id: 'freemail-typo', weight: 45, reason: `Domain looks like a misspelling of ${target}` });
  }

  if (labels.some((label) => label.startsWith('xn--'))) {
    signals.push({ id: 'idn-domain', weight: 30, reason: 'Domain uses international characters that can imitate a real brand' });
  }

  if (!free && SUSPICIOUS_EMAIL_TLDS.has(labels[labels.length - 1])) {
    signals.push({ id: 'suspicious-tld', weight: 20, reason: 'Domain ending is frequently abused for scams' });
  }

  if (labels.length - registrable.split('.').length >= 3) {
    signals.push({ id: 'deep-subdomain', weight: 15, reason: 'Domain has many subdomains, a common way to disguise the real one' });
  }

  const digits = (domain.match(/\d/g) ?? []).length;
  if (domain.length > 8 && digits / domain.length > 0.3) {
    signals.push({ id: 'digit-heavy-domain', weight: 15, reason: 'Domain is full of digits, which looks auto-generated' });
  }

  // Relationship to the page the address was found on.
  const pageRegistrable = pageHostname ? getRegistrableDomain(pageHostname) : '';
  if (pageRegistrable && pageRegistrable !== registrable && !free) {
    const siteName = pageRegistrable.split('.')[0];
    const mailName = registrable.split('.')[0];
    if (siteName.length >= 5 && mailName.length >= 4 && mailName !== siteName) {
      if (editDistance(siteName, mailName) <= 2) {
        signals.push({ id: 'resembles-this-site', weight: 40, reason: `Address domain looks like a near-copy of this website (${pageRegistrable})` });
      } else if (mailName.split('-').includes(siteName)) {
        signals.push({ id: 'contains-this-site-name', weight: 35, reason: `Address domain borrows this website's name (${pageRegistrable}) but is a different domain` });
      }
    }
  }
  return signals;
}

/** Signals about the part before the @. */
export function localPartSignals(local: string, registrable: string): EmailSignal[] {
  const signals: EmailSignal[] = [];
  const tokens = tokenize(local);
  const joined = tokens.join('');
  const hasAuthority =
    tokens.some((t) => AUTHORITY_LOCAL_PARTS.has(t)) ||
    [...AUTHORITY_LOCAL_PARTS].some((word) => word.length >= 7 && joined.includes(word));

  if (hasAuthority && isFreeProvider(registrable)) {
    signals.push({ id: 'authority-on-freemail', weight: 35, reason: 'Official-sounding address (support, billing, security...) on a free email service' });
  }

  // A brand name alone can be a person's name (chase.miller), so require an official-sounding word or an exact match.
  const brand = findBrand(local);
  if (brand && !brand.domains.includes(registrable) && (hasAuthority || joined === brand.name)) {
    signals.push({ id: 'brand-in-local-part', weight: 45, reason: `Uses the ${brand.name} name but is not on a ${brand.name} domain` });
  }

  const digits = (local.match(/\d/g) ?? []).length;
  if (digits >= 6 || (local.length >= 8 && digits / local.length > 0.4)) {
    signals.push({ id: 'random-local-part', weight: 15, reason: 'Name part looks auto-generated' });
  }
  if (local.length >= 40) {
    signals.push({ id: 'very-long-local-part', weight: 10, reason: 'Unusually long name part' });
  }
  return signals;
}

/** Signals from the name shown in front of the address ("PayPal Support" <x@evil.example>). */
export function displayNameSignals(displayName: string, registrable: string): EmailSignal[] {
  const name = displayName.trim();
  if (!name) return [];

  const shown = name.match(/[^\s<>()"',;]+@[^\s<>()"',;]+/);
  if (shown) {
    const shownAddress = shown[0].replace(/[.,;:]+$/, '');
    const shownDomain = shownAddress.slice(shownAddress.lastIndexOf('@') + 1).toLowerCase();
    if (getRegistrableDomain(shownDomain) !== registrable) {
      return [{ id: 'display-name-email-mismatch', weight: 55, reason: `Display name shows a different address (${clip(shownAddress)}) than the real sender` }];
    }
    return [];
  }

  const brand = findBrand(name);
  if (brand && !brand.domains.includes(registrable)) {
    return [{ id: 'display-name-impersonation', weight: 50, reason: `Display name says "${clip(name)}" but the address is on ${registrable}` }];
  }
  return [];
}