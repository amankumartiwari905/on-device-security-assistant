import type { EmailSignal } from '../../engine/email/emailSignals';
import { getRegistrableDomain } from '../../engine/url/urlFeatures';
import { cached } from './cache';
import { lookupDomainDns } from './dns';
import type { DnsFacts } from './dns';
import { daysSince, lookupRegistration } from './rdap';

export interface DomainIntel {
  domain: string;
  dns: DnsFacts;
  registeredAt: string | null;
  /** Days since registration, null when the registry does not say. */
  ageDays: number | null;
  /** Who hosts the domain's mail, when recognizable (informational). */
  mailProvider: string | null;
  checkedAt: number;
  errors: string[];
}

const MAIL_PROVIDERS: ReadonlyArray<readonly [RegExp, string]> = [
  [/(^|\.)(google|googlemail)\.com$/, 'Google Workspace / Gmail'],
  [/(^|\.)outlook\.com$/, 'Microsoft 365 / Outlook'],
  [/(^|\.)pphosted\.com$/, 'Proofpoint'],
  [/(^|\.)mimecast\.com$/, 'Mimecast'],
  [/(^|\.)zoho\.(com|in|eu)$/, 'Zoho Mail'],
  [/(^|\.)secureserver\.net$/, 'GoDaddy'],
  [/(^|\.)(privateemail\.com|registrar-servers\.com)$/, 'Namecheap'],
  [/(^|\.)yahoodns\.net$/, 'Yahoo Mail'],
  [/(^|\.)icloud\.com$/, 'iCloud'],
  [/(^|\.)(protonmail\.ch|proton\.ch)$/, 'Proton Mail'],
  [/(^|\.)messagingengine\.com$/, 'Fastmail'],
];

export function classifyMxProvider(mxHosts: readonly string[]): string | null {
  for (const host of mxHosts) {
    const found = MAIL_PROVIDERS.find(([pattern]) => pattern.test(host));
    if (found) return found[1];
  }
  return null;
}

const pluralDays = (n: number): string => (n === 0 ? 'today' : `${n} day${n === 1 ? '' : 's'} ago`);

/** Turns lookup results into scoring signals. `forEmail` enables the mail-specific checks. */
export function domainIntelSignals(intel: DomainIntel, context: { forEmail: boolean }): EmailSignal[] {
  const signals: EmailSignal[] = [];
  const { dns } = intel;

  if (dns.nxdomain === true) {
    signals.push({ id: 'online-domain-not-found', weight: 55, reason: 'This domain does not exist in DNS' });
  }

  if (context.forEmail && dns.nxdomain !== true) {
    if (dns.nullMx) {
      signals.push({ id: 'online-no-mail-server', weight: 45, reason: 'This domain explicitly refuses email (null MX record)' });
    } else if (dns.hasMx === false && dns.resolves === false) {
      signals.push({ id: 'online-no-mail-server', weight: 45, reason: 'This domain has no mail server, so the address cannot receive email' });
    }
    if (dns.hasSpf === false && dns.hasDmarc === false) {
      signals.push({ id: 'online-no-email-auth', weight: 12, reason: 'Domain publishes neither SPF nor DMARC, so anyone can forge mail from it' });
    }
    if (dns.spfAll === '+all') {
      signals.push({ id: 'online-spf-allows-all', weight: 25, reason: 'SPF record lets any server send mail as this domain' });
    }
  }

  const age = intel.ageDays;
  if (age !== null && age <= 90) {
    const weight = age <= 7 ? 40 : age <= 30 ? 30 : 12;
    signals.push({
      id: 'online-new-domain',
      weight,
      reason: `Domain was registered ${pluralDays(age)}; new domains are heavily used in scams (this alone does not prove fraud)`,
    });
  }
  return signals;
}

/** One signal per id, keeping the strongest, ordered by weight. */
export function mergeSignals(signals: readonly EmailSignal[]): EmailSignal[] {
  const byId = new Map<string, EmailSignal>();
  for (const signal of signals) {
    const existing = byId.get(signal.id);
    if (!existing || signal.weight > existing.weight) byId.set(signal.id, signal);
  }
  return [...byId.values()].sort((a, b) => b.weight - a.weight);
}

const IP_ADDRESS = /^\d{1,3}(\.\d{1,3}){3}$/;

async function fetchDomainIntel(domain: string): Promise<DomainIntel> {
  const base = { domain, checkedAt: Date.now() };
  const emptyDns: DnsFacts = {
    nxdomain: null, hasMx: null, mxHosts: [], nullMx: false, resolves: null,
    hasSpf: null, spfAll: null, hasDmarc: null, dmarcPolicy: null, errors: [],
  };

  if (IP_ADDRESS.test(domain)) {
    return { ...base, dns: { ...emptyDns, errors: ['IP-address domains are not looked up.'] }, registeredAt: null, ageDays: null, mailProvider: null, errors: ['IP-address domains are not looked up.'] };
  }

  const registrable = getRegistrableDomain(domain);
  const [dns, registration] = await Promise.all([lookupDomainDns(domain, registrable), lookupRegistration(registrable)]);
  return {
    ...base,
    dns,
    registeredAt: registration.registeredAt,
    ageDays: registration.registeredAt ? daysSince(registration.registeredAt) : null,
    mailProvider: classifyMxProvider(dns.mxHosts),
    errors: dns.errors,
  };
}

/** DNS + registration facts for a domain. Cached for six hours; failures are retried after a minute. */
export function getDomainIntel(domain: string): Promise<DomainIntel> {
  const name = domain.toLowerCase().replace(/\.$/, '');
  return cached(`domain:${name}`, () => fetchDomainIntel(name), {
    ttlMs: 6 * 3_600_000,
    failureTtlMs: 60_000,
    isFailure: (intel) => intel.dns.errors.length >= 3,
  });
}