import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { checkEmailReputations, clearReputationCaches } from '../src/background/emailReputation';
import { addOnlineReputation, analyzePageEmails } from '../src/engine/email/emailAnalyzer';

beforeEach(async () => {
  await clearReputationCaches();
  vi.stubGlobal('chrome', {
    storage: {
      local: {
        get: vi.fn().mockResolvedValue({
          intelSettings: { mode: 'full', emailRepApiKey: '' },
        }),
      },
    },
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('checkEmailReputations', () => {
  it('does not contact online providers when privacy mode is off', async () => {
    vi.stubGlobal('chrome', {
      storage: {
        local: {
          get: vi.fn().mockResolvedValue({
            intelSettings: { mode: 'off', emailRepApiKey: '' },
          }),
        },
      },
    });
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    const result = await checkEmailReputations(['private@example.test']);

    expect(fetchMock).not.toHaveBeenCalled();
    expect(result['private@example.test'].status).toBe('unavailable');
    expect(result['private@example.test'].emailRep.error).toBe('Online checks are turned off.');
  });

  it('combines email reputation, MX, SPF, and DMARC data without changing provider claims', async () => {
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      const url = String(input);
      if (url.startsWith('https://dns.google/')) {
        const query = new URL(url).searchParams;
        if (query.get('type') === 'TXT') {
          const record = query.get('name')?.startsWith('_dmarc.')
            ? '"v=DMARC1; p=quarantine"'
            : '"v=spf1 include:mail.example -all"';
          return new Response(JSON.stringify({
            Status: 0,
            Answer: [{ type: 16, data: record }],
          }), { status: 200 });
        }
        return new Response(JSON.stringify({
          Status: 0,
          Answer: [{ type: 15, data: '10 mx.scam-check-test.example.' }],
        }), { status: 200 });
      }
      if (url.startsWith('https://emailrep.io/')) {
        expect(url).toContain('known%40scam-check-test.example');
        return new Response(JSON.stringify({
          email: 'known@scam-check-test.example',
          reputation: 'low',
          suspicious: true,
          references: 12,
          details: {
            first_seen: '2025-01',
            data_breaches: 2,
            days_since_domain_creation: 10,
            domain_reputation: 'low',
            domain_exists: true,
            last_seen: '2026-01',
            malicious_activity: true,
            credentials_leaked: true,
          },
        }), { status: 200 });
      }
      if (url === 'https://data.iana.org/rdap/dns.json') {
        return new Response(JSON.stringify({
          services: [[['example'], ['https://rdap.example/']]],
        }), { status: 200 });
      }
      if (url === 'https://rdap.example/domain/scam-check-test.example') {
        return new Response(JSON.stringify({
          events: [{ eventAction: 'registration', eventDate: new Date(Date.now() - 10 * 86_400_000).toISOString() }],
        }), { status: 200 });
      }
      throw new Error(`Unexpected provider: ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    const result = await checkEmailReputations(['known@scam-check-test.example']);
    const report = result['known@scam-check-test.example'];

    expect(report.status).toBe('complete');
    expect(report.emailRep).toMatchObject({
      reputation: 'low',
      suspicious: true,
      references: 12,
      dataBreaches: 2,
      domainReputation: 'low',
      domainExists: true,
      lastSeen: '2026-01',
      flags: ['Reported malicious activity', 'Credentials reported leaked'],
    });
    expect(report.domain.hasMx).toBe(true);
    expect(report.domain.mxHosts).toEqual(['mx.scam-check-test.example']);
    expect(report.domain.hasSpf).toBe(true);
    expect(report.domain.hasDmarc).toBe(true);
    expect(report.emailRep.domainAgeDays).toBe(10);
    expect(report.signals.map((signal) => signal.id)).toEqual(expect.arrayContaining([
      'online-email-suspicious',
      'online-malicious-activity',
      'online-credentials-leaked',
      'online-new-domain',
    ]));
    expect(fetchMock).toHaveBeenCalledTimes(7);
  });

  it('adds provider evidence to local assessment without presenting it as proof', () => {
    const local = analyzePageEmails(['contact@external-check-test.example'], '')[0];
    const enriched = addOnlineReputation(local, {
      checkedAt: Date.now(),
      status: 'complete',
      emailRep: {
        reputation: 'low',
        suspicious: true,
        references: 4,
        firstSeen: null,
        lastSeen: null,
        dataBreaches: 0,
        domainAgeDays: null,
        domainReputation: null,
        domainExists: true,
        flags: [],
        error: null,
      },
      domain: {
        hasMx: true,
        mxHosts: ['mx.external-check-test.example'],
        hasSpf: null,
        hasDmarc: null,
        ageDays: null,
        error: null,
      },
      signals: [{
        id: 'online-email-suspicious',
        weight: 55,
        reason: 'Email reputation provider marks this address as suspicious',
      }],
    });

    expect(local.status).toBe('external');
    expect(enriched.status).toBe('suspicious');
    expect(enriched.riskScore).toBeGreaterThan(local.riskScore);
    expect(enriched.explanation).toContain('Email reputation provider');
  });

  it('limits lookups, deduplicates addresses, and reports provider failures explicitly', async () => {
    const fetchMock = vi.fn().mockRejectedValue(new Error('network unavailable'));
    vi.stubGlobal('fetch', fetchMock);

    const result = await checkEmailReputations([
      'one@failure-check-test.example',
      'ONE@failure-check-test.example',
      'invalid-address',
      'two@failure-check-test.example',
      'three@failure-check-test.example',
      'four@failure-check-test.example',
      'five@failure-check-test.example',
      'six@failure-check-test.example',
    ]);

    expect(Object.keys(result)).toEqual([
      'one@failure-check-test.example',
      'two@failure-check-test.example',
      'three@failure-check-test.example',
      'four@failure-check-test.example',
      'five@failure-check-test.example',
    ]);
    expect(result['one@failure-check-test.example'].status).toBe('unavailable');
    expect(result['one@failure-check-test.example'].emailRep.error).toContain('network unavailable');
    expect(result['one@failure-check-test.example'].domain.error).toContain('DNS/MX lookup failed');
  });
});
