import { afterEach, describe, expect, it, vi } from 'vitest';
import { checkUrlReputations } from '../src/background/urlReputation';
import type { UrlReputationCredentials } from '../src/background/urlReputation';

const credentials: UrlReputationCredentials = {
  googleSafeBrowsingKey: 'google-test-key',
  virusTotalKey: 'vt-test-key',
  urlhausAuthKey: 'urlhaus-test-key',
  phishTankAppKey: 'phishtank-test-key',
};

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('checkUrlReputations', () => {
  it('queries enabled providers and preserves provider-specific result meaning', async () => {
    const fetchMock = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input);
      if (url.includes('safebrowsing.googleapis.com')) {
        return new Response(JSON.stringify({ threats: [{ url: 'https://bad.example/' }] }), { status: 200 });
      }
      if (url.includes('virustotal.com')) {
        return new Response(JSON.stringify({
          data: { attributes: { last_analysis_stats: { malicious: 2, suspicious: 1, harmless: 20 } } },
        }), { status: 200 });
      }
      if (url.includes('urlhaus-api.abuse.ch')) {
        expect((init?.body as URLSearchParams).get('url')).toBe('https://example.test/path');
        return new Response(JSON.stringify({ query_status: 'no_results' }), { status: 200 });
      }
      if (url.includes('checkurl.phishtank.com')) {
        return new Response(JSON.stringify({ results: { in_database: false } }), { status: 200 });
      }
      throw new Error(`Unexpected endpoint: ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    const reports = await checkUrlReputations(['https://example.test/path'], credentials);
    const providers = reports['https://example.test/path'].providers;
    expect(providers.map(({ status }) => status)).toEqual(['listed', 'listed', 'not-listed', 'not-listed']);
    expect(providers[1].detail).toContain('2 malicious');
    expect(fetchMock).toHaveBeenCalledTimes(4);
  });

  it('does not query missing credentials and rejects non-web or oversized URLs', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    await expect(checkUrlReputations([
      'javascript:alert(1)',
      `https://example.test/${'x'.repeat(2_100)}`,
    ], { ...credentials, googleSafeBrowsingKey: '', virusTotalKey: '', urlhausAuthKey: '', phishTankAppKey: '' }))
      .rejects.toThrow('Only valid HTTP(S)');

    const reports = await checkUrlReputations(['https://example.test/'], {
      ...credentials,
      googleSafeBrowsingKey: '',
      virusTotalKey: '',
      urlhausAuthKey: '',
      phishTankAppKey: '',
    });
    expect(Object.keys(reports)).toEqual(['https://example.test/']);
    expect(reports['https://example.test/'].providers.every((provider) => provider.status === 'not-configured')).toBe(true);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('deduplicates requests and reports provider errors as unknown', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('network unavailable')));
    const reports = await checkUrlReputations(['https://example.test', 'https://example.test/'], credentials);

    expect(Object.keys(reports)).toEqual(['https://example.test/']);
    expect(reports['https://example.test/'].providers.every((provider) => provider.status === 'unknown')).toBe(true);
    expect(reports['https://example.test/'].providers[0].detail).toContain('network unavailable');
  });
});
