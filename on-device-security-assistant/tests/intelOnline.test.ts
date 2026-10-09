import { describe, expect, it } from 'vitest';
import { CircuitBreaker } from '../src/background/intel/breaker';
import { cached } from '../src/background/intel/cache';
import {
  parseDmarc, parseDnsResponse, parseMx, parseSpf, unquoteTxt,
} from '../src/background/intel/dns';
import { classifyMxProvider, domainIntelSignals, mergeSignals } from '../src/background/intel/domainIntel';
import type { DomainIntel } from '../src/background/intel/domainIntel';
import { parseRetryAfter } from '../src/background/intel/http';
import { normalizeIntelSettings } from '../src/background/intel/intelSettings';
import { DEFAULT_SETTINGS } from '../src/storage/settings';
import { daysSince, findRdapBase, parseRegistrationDate } from '../src/background/intel/rdap';
import { registrationAgeSignal, shouldEnrich } from '../src/background/intel/urlIntel';

const intel = (over: Partial<DomainIntel> = {}, dns: Partial<DomainIntel['dns']> = {}): DomainIntel => ({
  domain: 'example.com',
  dns: {
    nxdomain: false, hasMx: true, mxHosts: ['mx.example.com'], nullMx: false, resolves: true,
    hasSpf: true, spfAll: '-all', hasDmarc: true, dmarcPolicy: 'reject', errors: [], ...dns,
  },
  registeredAt: null,
  ageDays: null,
  mailProvider: null,
  checkedAt: 0,
  errors: [],
  ...over,
});

const idsOf = (signals: { id: string }[]): string[] => signals.map((s) => s.id);

describe('DNS parsing', () => {
  it('reads answers and flags NXDOMAIN', () => {
    expect(parseDnsResponse({ Status: 0, Answer: [{ type: 15, data: '10 mx.example.com.' }] }).answers).toHaveLength(1);
    expect(parseDnsResponse({ Status: 3 }).nxdomain).toBe(true);
  });

  it('rejects server failures so the next provider is tried', () => {
    expect(() => parseDnsResponse({ Status: 2 })).toThrow();
    expect(() => parseDnsResponse('nope')).toThrow();
  });

  it('parses MX hosts and detects a null MX', () => {
    expect(parseMx([{ type: 15, value: '10 aspmx.l.google.com.' }])).toEqual({ hosts: ['aspmx.l.google.com'], nullMx: false });
    expect(parseMx([{ type: 15, value: '0 .' }])).toEqual({ hosts: [], nullMx: true });
    expect(parseMx([])).toEqual({ hosts: [], nullMx: false });
  });

  it('joins quoted TXT chunks', () => {
    expect(unquoteTxt('"v=spf1 " "include:x.com -all"')).toBe('v=spf1 include:x.com -all');
  });

  it('parses SPF strictness', () => {
    expect(parseSpf(['v=spf1 include:_spf.google.com -all'])).toEqual({ present: true, all: '-all' });
    expect(parseSpf(['v=spf1 +all'])).toEqual({ present: true, all: '+all' });
    expect(parseSpf(['something else'])).toEqual({ present: false, all: null });
  });

  it('parses the DMARC policy', () => {
    expect(parseDmarc(['v=DMARC1; p=reject; pct=100'])).toEqual({ present: true, policy: 'reject' });
    expect(parseDmarc(['v=DMARC1; p=none'])).toEqual({ present: true, policy: 'none' });
    expect(parseDmarc([])).toEqual({ present: false, policy: null });
  });
});

describe('RDAP', () => {
  const bootstrap = {
    services: [
      [['com', 'net'], ['http://insecure.example/', 'https://rdap.verisign.com/com/v1/']],
      [['uk'], ['https://rdap.nominet.uk/uk/']],
      [['co.uk'], ['https://rdap.special.example/co/']],
    ],
  };

  it('finds the registry service, preferring https and the longest ending', () => {
    expect(findRdapBase(bootstrap, 'example.com')).toBe('https://rdap.verisign.com/com/v1/');
    expect(findRdapBase(bootstrap, 'foo.org.uk')).toBe('https://rdap.nominet.uk/uk/');
    expect(findRdapBase(bootstrap, 'foo.co.uk')).toBe('https://rdap.special.example/co/');
    expect(findRdapBase(bootstrap, 'x.zzz')).toBeNull();
    expect(findRdapBase('garbage', 'example.com')).toBeNull();
  });

  it('reads the registration event', () => {
    const data = { events: [{ eventAction: 'last changed', eventDate: '2025-01-01T00:00:00Z' }, { eventAction: 'registration', eventDate: '2024-03-04T05:06:07Z' }] };
    expect(parseRegistrationDate(data)).toBe('2024-03-04T05:06:07.000Z');
    expect(parseRegistrationDate({ events: [] })).toBeNull();
    expect(parseRegistrationDate(null)).toBeNull();
  });

  it('computes age in whole days', () => {
    expect(daysSince('2024-01-01T00:00:00Z', Date.parse('2024-01-11T12:00:00Z'))).toBe(10);
    expect(daysSince('2030-01-01T00:00:00Z', Date.parse('2024-01-01T00:00:00Z'))).toBe(0);
  });
});

describe('domain signals', () => {
  it('scores very new domains highest', () => {
    const weight = (days: number) => domainIntelSignals(intel({ ageDays: days }), { forEmail: true }).find((s) => s.id === 'online-new-domain')?.weight;
    expect(weight(3)).toBe(40);
    expect(weight(20)).toBe(30);
    expect(weight(60)).toBe(12);
    expect(weight(400)).toBeUndefined();
  });

  it('flags domains that cannot receive mail', () => {
    expect(idsOf(domainIntelSignals(intel({}, { hasMx: false, resolves: false }), { forEmail: true }))).toContain('online-no-mail-server');
    expect(idsOf(domainIntelSignals(intel({}, { hasMx: false, nullMx: true }), { forEmail: true }))).toContain('online-no-mail-server');
    expect(idsOf(domainIntelSignals(intel({}, { hasMx: false, resolves: true }), { forEmail: true }))).not.toContain('online-no-mail-server');
  });

  it('flags missing email authentication and permissive SPF', () => {
    expect(idsOf(domainIntelSignals(intel({}, { hasSpf: false, hasDmarc: false }), { forEmail: true }))).toContain('online-no-email-auth');
    expect(idsOf(domainIntelSignals(intel({}, { spfAll: '+all' }), { forEmail: true }))).toContain('online-spf-allows-all');
  });

  it('flags a domain that does not exist', () => {
    expect(idsOf(domainIntelSignals(intel({}, { nxdomain: true }), { forEmail: false }))).toContain('online-domain-not-found');
  });

  it('skips mail-specific checks for website domains', () => {
    const ids = idsOf(domainIntelSignals(intel({}, { hasMx: false, resolves: false, hasSpf: false, hasDmarc: false }), { forEmail: false }));
    expect(ids).toEqual([]);
  });

  it('merges signals keeping the strongest per id', () => {
    const merged = mergeSignals([
      { id: 'a', weight: 20, reason: 'weak' },
      { id: 'a', weight: 40, reason: 'strong' },
      { id: 'b', weight: 30, reason: 'other' },
    ]);
    expect(merged).toEqual([{ id: 'a', weight: 40, reason: 'strong' }, { id: 'b', weight: 30, reason: 'other' }]);
  });

  it('labels well-known mail hosts', () => {
    expect(classifyMxProvider(['aspmx.l.google.com'])).toBe('Google Workspace / Gmail');
    expect(classifyMxProvider(['example-com.mail.protection.outlook.com'])).toBe('Microsoft 365 / Outlook');
    expect(classifyMxProvider(['mx.unknown-host.net'])).toBeNull();
  });
});

describe('URL enrichment rules', () => {
  it('only enriches borderline verdicts', () => {
    expect(shouldEnrich(5)).toBe(false);
    expect(shouldEnrich(15)).toBe(true);
    expect(shouldEnrich(59)).toBe(true);
    expect(shouldEnrich(60)).toBe(false);
  });

  it('turns domain age into a signal', () => {
    expect(registrationAgeSignal(2)?.weight).toBe(40);
    expect(registrationAgeSignal(20)?.weight).toBe(28);
    expect(registrationAgeSignal(80)?.weight).toBe(10);
    expect(registrationAgeSignal(365)).toBeNull();
    expect(registrationAgeSignal(null)).toBeNull();
  });
});

describe('infrastructure', () => {
  it('parses Retry-After in seconds and dates', () => {
    expect(parseRetryAfter('120')).toBe(120_000);
    expect(parseRetryAfter(null)).toBeNull();
    expect(parseRetryAfter('not a date')).toBeNull();
  });

  it('opens and resets the circuit breaker, with growing cooldowns', () => {
    const breaker = new CircuitBreaker(1000, 10_000);
    expect(breaker.isOpen).toBe(false);
    breaker.trip();
    expect(breaker.isOpen).toBe(true);
    const first = breaker.retryAt - Date.now();
    breaker.trip();
    expect(breaker.retryAt - Date.now()).toBeGreaterThan(first);
    breaker.reset();
    expect(breaker.isOpen).toBe(false);
  });

  it('shares one in-flight fetch between concurrent callers', async () => {
    let calls = 0;
    const fetcher = async () => {
      calls++;
      await new Promise((resolve) => setTimeout(resolve, 5));
      return { ok: true };
    };
    const options = { ttlMs: 1000, failureTtlMs: 10, isFailure: () => false };
    const [a, b] = await Promise.all([cached('test:inflight', fetcher, options), cached('test:inflight', fetcher, options)]);
    expect(calls).toBe(1);
    expect(a).toEqual(b);
  });

  it('caches successes, and retries failures only after the failure TTL', async () => {
    let good = 0;
    const goodFetch = async () => ({ error: null as string | null, n: ++good });
    const options = { ttlMs: 60_000, failureTtlMs: 0, isFailure: (v: { error: string | null }) => v.error !== null };
    await cached('test:good', goodFetch, options);
    await cached('test:good', goodFetch, options);
    expect(good).toBe(1);

    let bad = 0;
    const badFetch = async () => ({ error: 'down' as string | null, n: ++bad });
    await cached('test:bad', badFetch, options);
    await cached('test:bad', badFetch, options);
    expect(bad).toBe(2);
  });

  it('normalizes intel settings and ignores bad input', () => {
    expect(normalizeIntelSettings(undefined)).toEqual({ mode: 'off', emailRepApiKey: '' });
    expect(normalizeIntelSettings({ mode: 'domains', emailRepApiKey: '  abc  ' })).toEqual({ mode: 'domains', emailRepApiKey: 'abc' });
    expect(normalizeIntelSettings({ mode: 'everything' }).mode).toBe('off');
    expect(DEFAULT_SETTINGS.onlineEmailChecks).toBe(false);
    expect(DEFAULT_SETTINGS.onlineUrlChecks).toBe(false);
  });
});