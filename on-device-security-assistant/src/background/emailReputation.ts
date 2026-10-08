import { MAX_EMAILS_PER_PAGE } from '../shared/emailReputation';
import type { EmailReputationReport } from '../shared/emailReputation';
import type { EmailSignal } from '../engine/email/emailSignals';
import { CircuitBreaker } from './intel/breaker';
import { cached, clearIntelCache } from './intel/cache';
import { domainIntelSignals, getDomainIntel, mergeSignals } from './intel/domainIntel';
import type { DomainIntel } from './intel/domainIntel';
import { fetchJson, IntelHttpError } from './intel/http';
import { getIntelSettings } from './intel/intelSettings';
import type { IntelSettings } from './intel/intelSettings';
import { isRecord } from './intel/util';

const EMAILREP_ENDPOINT = 'https://emailrep.io/';
const CACHE_TTL_MS = 30 * 60_000;
const FAILURE_CACHE_TTL_MS = 60_000;

/** After a 429 the provider is left alone for 30 minutes, doubling on repeats up to 6 hours. */
const emailRepBreaker = new CircuitBreaker(30 * 60_000, 6 * 3_600_000);

interface DomainCheck {
  hasMx: boolean | null;
  mxHosts: string[];
  hasSpf: boolean | null;
  hasDmarc: boolean | null;
  ageDays: number | null;
  error: string | null;
  // Added by the online intelligence layer (extra fields are safe for existing consumers).
  dmarcPolicy: string | null;
  registeredAt: string | null;
  mailProvider: string | null;
  resolves: boolean | null;
  nxdomain: boolean | null;
}

interface EmailRepCheck {
  reputation: string | null;
  suspicious: boolean | null;
  references: number | null;
  firstSeen: string | null;
  lastSeen: string | null;
  dataBreaches: number | null;
  domainAgeDays: number | null;
  domainReputation: string | null;
  domainExists: boolean | null;
  flags: string[];
  error: string | null;
}

function validEmail(value: string): boolean {
  const separator = value.lastIndexOf('@');
  if (value.length > 254 || separator < 1 || value.indexOf('@') !== separator) return false;
  const local = value.slice(0, separator);
  if (
    local.length > 64 ||
    local.startsWith('.') ||
    local.endsWith('.') ||
    local.includes('..') ||
    !/^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+$/i.test(local)
  ) return false;
  const domain = value.slice(separator + 1).normalize('NFKC').toLowerCase().replace(/\.$/, '');
  if (!domain || /[/:\\?#%\s]/.test(domain)) return false;
  try {
    const ascii = new URL(`http://${domain}`).hostname;
    return ascii.includes('.') && ascii.length <= 253 && ascii.split('.').every((label) =>
      label.length > 0 && label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
    );
  } catch {
    return false;
  }
}

function normalizeEmail(value: string): string | null {
  if (!validEmail(value)) return null;
  const separator = value.lastIndexOf('@');
  const local = value.slice(0, separator);
  const domain = new URL(`http://${value.slice(separator + 1).normalize('NFKC')}`).hostname.toLowerCase();
  return `${local}@${domain}`;
}

function domainOf(email: string): string {
  return new URL(`http://${email.slice(email.lastIndexOf('@') + 1)}`).hostname.toLowerCase().replace(/\.$/, '');
}

function parseEmailRep(data: unknown): EmailRepCheck {
  if (!isRecord(data)) throw new Error('EmailRep returned an invalid response.');
  const details = isRecord(data.details) ? data.details : {};
  const flags: string[] = [];
  const mapFlags: [string, string][] = [
    ['malicious_activity', 'Reported malicious activity'],
    ['malicious_activity_recent', 'Recent malicious activity'],
    ['blacklisted', 'Listed on a blocklist'],
    ['spam', 'Associated with spam'],
    ['credentials_leaked', 'Credentials reported leaked'],
    ['disposable', 'Disposable email provider'],
    ['new_domain', 'Recently registered domain'],
  ];
  for (const [field, label] of mapFlags) if (details[field] === true) flags.push(label);

  return {
    reputation: typeof data.reputation === 'string' ? data.reputation.slice(0, 40) : null,
    suspicious: typeof data.suspicious === 'boolean' ? data.suspicious : null,
    references: typeof data.references === 'number' && Number.isFinite(data.references) ? data.references : null,
    firstSeen: typeof details.first_seen === 'string' ? details.first_seen.slice(0, 40) : null,
    lastSeen: typeof details.last_seen === 'string' ? details.last_seen.slice(0, 40) : null,
    dataBreaches: typeof details.data_breaches === 'number' && Number.isFinite(details.data_breaches)
      ? Math.max(0, details.data_breaches)
      : null,
    domainAgeDays: typeof details.days_since_domain_creation === 'number' &&
      Number.isFinite(details.days_since_domain_creation)
      ? Math.max(0, Math.floor(details.days_since_domain_creation))
      : null,
    domainReputation: typeof details.domain_reputation === 'string'
      ? details.domain_reputation.slice(0, 40)
      : null,
    domainExists: typeof details.domain_exists === 'boolean' ? details.domain_exists : null,
    flags,
    error: null,
  };
}

function emptyEmailRep(error: string): EmailRepCheck {
  return {
    reputation: null,
    suspicious: null,
    references: null,
    firstSeen: null,
    lastSeen: null,
    dataBreaches: null,
    domainAgeDays: null,
    domainReputation: null,
    domainExists: null,
    flags: [],
    error,
  };
}

async function checkEmail(email: string, settings: IntelSettings): Promise<EmailRepCheck> {
  if (settings.mode !== 'full') return emptyEmailRep('Skipped: domain-only privacy mode.');
  if (emailRepBreaker.isOpen) {
    return emptyEmailRep(`EmailRep is paused after rate limiting until ${new Date(emailRepBreaker.retryAt).toLocaleTimeString()}.`);
  }

  // persist: false keeps email addresses out of storage; they live in memory only.
  return cached(`emailrep:${email.toLowerCase()}`, async () => {
    try {
      const headers = settings.emailRepApiKey ? { Key: settings.emailRepApiKey } : undefined;
      const result = parseEmailRep(await fetchJson(
        `${EMAILREP_ENDPOINT}${encodeURIComponent(email)}`,
        { accept: 'application/json', headers, retries: 0 },
      ));
      emailRepBreaker.reset();
      return result;
    } catch (error) {
      if (error instanceof IntelHttpError && error.status === 429) {
        emailRepBreaker.trip(error.retryAfterMs);
        return emptyEmailRep(
          settings.emailRepApiKey
            ? 'EmailRep rate limit reached.'
            : 'EmailRep rate limit reached. A free API key raises the limit.',
        );
      }
      if (error instanceof IntelHttpError && error.status === 401) return emptyEmailRep('EmailRep rejected the API key.');
      return emptyEmailRep(error instanceof Error ? error.message : 'Email reputation lookup failed.');
    }
  }, {
    ttlMs: CACHE_TTL_MS,
    failureTtlMs: FAILURE_CACHE_TTL_MS,
    isFailure: (result) => result.error !== null,
    persist: false,
  });
}

function reputationSignals(email: EmailRepCheck): EmailSignal[] {
  const signals: EmailSignal[] = [];
  if (email.suspicious === true) {
    signals.push({ id: 'online-email-suspicious', weight: 55, reason: 'Email reputation provider marks this address as suspicious' });
  }
  if (email.flags.includes('Reported malicious activity') || email.flags.includes('Recent malicious activity')) {
    signals.push({ id: 'online-malicious-activity', weight: 75, reason: 'Email reputation provider reports malicious activity for this address' });
  }
  if (email.flags.includes('Listed on a blocklist')) {
    signals.push({ id: 'online-email-blocklisted', weight: 70, reason: 'Email reputation provider reports this address on a blocklist' });
  }
  if (email.flags.includes('Associated with spam')) {
    signals.push({ id: 'online-email-spam', weight: 55, reason: 'Email reputation provider associates this address with spam' });
  }
  if (email.flags.includes('Credentials reported leaked')) {
    signals.push({ id: 'online-credentials-leaked', weight: 35, reason: 'Credentials for this address appear in breach intelligence; this does not prove the sender is a scammer' });
  }
  if (email.flags.includes('Disposable email provider')) {
    signals.push({ id: 'online-disposable-provider', weight: 45, reason: 'Email reputation provider identifies a disposable email provider' });
  }
  if (email.domainExists === false) {
    signals.push({ id: 'online-domain-not-found', weight: 50, reason: 'Email reputation provider reports that the email domain does not exist' });
  }
  if ((email.domainAgeDays !== null && email.domainAgeDays <= 30) || email.flags.includes('Recently registered domain')) {
    const age = email.domainAgeDays === null ? 'recently' : `${email.domainAgeDays} days ago`;
    signals.push({ id: 'online-new-domain', weight: 20, reason: `Email domain was registered ${age}; this alone does not prove fraud` });
  }
  return signals;
}

function toDomainCheck(intel: DomainIntel | null, emailRep: EmailRepCheck): DomainCheck {
  if (!intel) {
    return {
      hasMx: null,
      mxHosts: [],
      hasSpf: null,
      hasDmarc: null,
      ageDays: emailRep.domainAgeDays,
      error: 'Domain checks are turned off.',
      dmarcPolicy: null,
      registeredAt: null,
      mailProvider: null,
      resolves: null,
      nxdomain: null,
    };
  }
  return {
    hasMx: intel.dns.hasMx,
    mxHosts: intel.dns.mxHosts,
    hasSpf: intel.dns.hasSpf,
    hasDmarc: intel.dns.hasDmarc,
    // Prefer the registry's date; fall back to EmailRep's when RDAP does not publish one.
    ageDays: intel.ageDays ?? emailRep.domainAgeDays,
    error: intel.errors.length > 0 ? intel.errors.join(' ') : null,
    dmarcPolicy: intel.dns.dmarcPolicy,
    registeredAt: intel.registeredAt,
    mailProvider: intel.mailProvider,
    resolves: intel.dns.resolves,
    nxdomain: intel.dns.nxdomain,
  };
}

function buildReport(emailRep: EmailRepCheck, intel: DomainIntel | null) {
  const domain = toDomainCheck(intel, emailRep);
  const emailAvailable = emailRep.error === null;
  const domainAvailable = domain.hasMx !== null || domain.hasSpf !== null || domain.hasDmarc !== null;
  const signals = mergeSignals([
    ...reputationSignals(emailRep),
    ...(intel ? domainIntelSignals(intel, { forEmail: true }) : []),
  ]);

  return {
    checkedAt: Date.now(),
    status: emailAvailable && domainAvailable ? 'complete' : emailAvailable || domainAvailable ? 'partial' : 'unavailable',
    emailRep,
    domain,
    signals,
  } as const;
}

export async function checkEmailReputations(addresses: readonly string[]): Promise<Record<string, EmailReputationReport>> {
  const settings = await getIntelSettings();

  const uniqueByAddress = new Map<string, string>();
  for (const address of addresses) {
    const normalized = normalizeEmail(address.trim());
    if (normalized && !uniqueByAddress.has(normalized.toLowerCase())) {
      uniqueByAddress.set(normalized.toLowerCase(), normalized);
    }
  }
  const unique = [...uniqueByAddress.values()].slice(0, MAX_EMAILS_PER_PAGE);

  const entries = await Promise.all(unique.map(async (email) => {
    if (settings.mode === 'off') {
      return [email.toLowerCase(), buildReport(emptyEmailRep('Online checks are turned off.'), null)] as const;
    }
    // Domain lookups are cached and shared, so many addresses on one domain cost one lookup.
    const [emailRep, intel] = await Promise.all([checkEmail(email, settings), getDomainIntel(domainOf(email))]);
    return [email.toLowerCase(), buildReport(emailRep, intel)] as const;
  }));

  return Object.fromEntries(entries);
}

export const emailReputationLimits = { maxEmailsPerPage: MAX_EMAILS_PER_PAGE };

/** For a "Clear online cache" button in settings. */
export { clearIntelCache as clearReputationCaches };