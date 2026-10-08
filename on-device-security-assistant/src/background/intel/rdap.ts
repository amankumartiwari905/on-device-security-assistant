import { cached } from './cache';
import { fetchJson } from './http';
import { isRecord } from './util';

/**
 * Domain registration date via RDAP (the successor to WHOIS). The IANA bootstrap file tells us which
 * registry serves each domain ending; registry RDAP servers are expected to allow browser (CORS) access.
 * Lookups are best effort: some country registries do not publish a registration date.
 */
const BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';
const DAY_MS = 86_400_000;

export interface RegistrationInfo {
  registeredAt: string | null;
  error: string | null;
}

/** Longest matching domain ending wins; only https services are used. */
export function findRdapBase(bootstrap: unknown, domain: string): string | null {
  if (!isRecord(bootstrap) || !Array.isArray(bootstrap.services)) return null;

  const name = domain.toLowerCase();
  let best: { length: number; base: string } | null = null;

  for (const service of bootstrap.services) {
    if (!Array.isArray(service) || service.length < 2) continue;
    const [endings, urls] = service as unknown[];
    if (!Array.isArray(endings) || !Array.isArray(urls)) continue;

    const base = urls.find((u): u is string => typeof u === 'string' && u.startsWith('https://'));
    if (!base) continue;

    for (const ending of endings) {
      if (typeof ending !== 'string') continue;
      const suffix = ending.toLowerCase();
      if (name === suffix || name.endsWith(`.${suffix}`)) {
        const length = suffix.split('.').length;
        if (!best || length > best.length) best = { length, base };
      }
    }
  }
  return best ? best.base : null;
}

export function parseRegistrationDate(data: unknown): string | null {
  if (!isRecord(data) || !Array.isArray(data.events)) return null;
  for (const event of data.events) {
    if (isRecord(event) && event.eventAction === 'registration' && typeof event.eventDate === 'string') {
      const time = Date.parse(event.eventDate);
      if (!Number.isNaN(time)) return new Date(time).toISOString();
    }
  }
  return null;
}

export function daysSince(iso: string, now: number = Date.now()): number {
  return Math.max(0, Math.floor((now - Date.parse(iso)) / DAY_MS));
}

async function loadBootstrap(): Promise<unknown> {
  return cached(
    'rdap:bootstrap',
    async () => {
      const data = await fetchJson(BOOTSTRAP_URL, { accept: 'application/json', timeoutMs: 10_000 });
      if (!isRecord(data) || !Array.isArray(data.services)) throw new Error('RDAP bootstrap file was not in the expected format.');
      return { services: data.services } as unknown;
    },
    { ttlMs: DAY_MS, failureTtlMs: 60_000, isFailure: () => false },
  );
}

async function fetchRegistration(domain: string): Promise<RegistrationInfo> {
  try {
    const base = findRdapBase(await loadBootstrap(), domain);
    if (!base) return { registeredAt: null, error: 'No RDAP service is published for this domain ending.' };

    const url = `${base.endsWith('/') ? base : `${base}/`}domain/${encodeURIComponent(domain)}`;
    const data = await fetchJson(url, { accept: 'application/rdap+json', timeoutMs: 10_000 });
    const registeredAt = parseRegistrationDate(data);
    return { registeredAt, error: registeredAt ? null : 'The registry does not publish a registration date.' };
  } catch (error) {
    return { registeredAt: null, error: error instanceof Error ? error.message : 'Registration lookup failed.' };
  }
}

/** Pass the registrable domain (example.com, not www.example.com). Cached for a day. */
export function lookupRegistration(domain: string): Promise<RegistrationInfo> {
  return cached(`rdap:${domain.toLowerCase()}`, () => fetchRegistration(domain.toLowerCase()), {
    ttlMs: DAY_MS,
    failureTtlMs: 5 * 60_000,
    isFailure: (info) => info.error !== null,
  });
}