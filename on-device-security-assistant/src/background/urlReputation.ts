import type { UrlProviderResult, UrlReputationProvider, UrlReputationReport } from '../shared/urlReputation';

export const MAX_URLS_PER_LOOKUP = 5;
const REQUEST_TIMEOUT_MS = 8_000;

export interface UrlReputationCredentials {
  googleSafeBrowsingKey: string;
  virusTotalKey: string;
  urlhausAuthKey: string;
  phishTankAppKey: string;
}

type ProviderOutcome = Omit<UrlProviderResult, 'provider'>;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

async function request(url: string, init: RequestInit = {}): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
}

async function responseJson(response: Response, provider: string): Promise<unknown> {
  if (!response.ok) throw new Error(`${provider} returned HTTP ${response.status}.`);
  try {
    return await response.json() as unknown;
  } catch {
    throw new Error(`${provider} returned invalid JSON.`);
  }
}

async function checkGoogleSafeBrowsing(url: string, apiKey: string): Promise<ProviderOutcome> {
  // Use Safe Browsing v4 threatMatches:find for standard JSON payload; also support v5 mock shape
  const endpoint = new URL('https://safebrowsing.googleapis.com/v4/threatMatches:find');
  endpoint.searchParams.set('key', apiKey);
  const response = await request(endpoint.href, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({
      client: { clientId: 'ai-guard', clientVersion: '0.1.0' },
      threatInfo: {
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url }],
      },
    }),
  });
  const data = await responseJson(response, 'Google Safe Browsing');
  if (!isRecord(data)) throw new Error('Google Safe Browsing returned an invalid response.');
  const matches = Array.isArray(data.matches)
    ? data.matches
    : Array.isArray(data.threats)
      ? data.threats
      : [];
  if (matches.length > 0) {
    const threats = matches
      .map((m) => (isRecord(m) && typeof m.threatType === 'string' ? m.threatType : ''))
      .filter(Boolean);
    const detail = threats.length > 0
      ? `Reported as a threat: ${[...new Set(threats)].join(', ')} (${matches.length} match${matches.length === 1 ? '' : 'es'}).`
      : `Reported as a threat (${matches.length} match${matches.length === 1 ? '' : 'es'}).`;
    return { status: 'listed', detail };
  }
  return { status: 'not-listed', detail: 'No match in this lookup.' };
}

function base64Url(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function checkVirusTotal(url: string, apiKey: string): Promise<ProviderOutcome> {
  const encoded = base64Url(url);
  const response = await request(`https://www.virustotal.com/api/v3/urls/${encoded}`, {
    headers: { 'x-apikey': apiKey, Accept: 'application/json' },
  });
  if (response.status === 404) {
    return { status: 'not-listed', detail: 'URL not found in VirusTotal database (not analyzed).' };
  }
  const data = await responseJson(response, 'VirusTotal');
  if (!isRecord(data) || !isRecord(data.data) || !isRecord(data.data.attributes) ||
      !isRecord(data.data.attributes.last_analysis_stats)) {
    return { status: 'unknown', detail: 'No completed analysis is available for this URL.' };
  }
  const stats = data.data.attributes.last_analysis_stats;
  const malicious = typeof stats.malicious === 'number' ? stats.malicious : 0;
  const suspicious = typeof stats.suspicious === 'number' ? stats.suspicious : 0;
  const total = Object.values(stats).reduce<number>((sum, count) =>
    sum + (typeof count === 'number' && Number.isFinite(count) ? count : 0), 0);
  if (malicious + suspicious > 0) {
    return { status: 'listed', detail: `${malicious} malicious and ${suspicious} suspicious detections out of ${total} engines.` };
  }
  return { status: 'not-listed', detail: `No detections in the latest report (${total} engines).` };
}

async function checkUrlhaus(url: string, apiKey: string): Promise<ProviderOutcome> {
  const body = new URLSearchParams({ url });
  const headers: Record<string, string> = {
    'Content-Type': 'application/x-www-form-urlencoded',
    Accept: 'application/json',
  };
  if (apiKey && apiKey.trim()) {
    headers['Auth-Key'] = apiKey.trim();
    headers['auth-key'] = apiKey.trim();
  }
  const response = await request('https://urlhaus-api.abuse.ch/v1/url/', {
    method: 'POST',
    headers,
    body,
  });
  const data = await responseJson(response, 'URLhaus');
  if (!isRecord(data) || typeof data.query_status !== 'string') {
    throw new Error('URLhaus returned an invalid response.');
  }
  if (data.query_status === 'ok') {
    const threat = typeof data.threat === 'string' ? ` (${data.threat})` : '';
    const status = typeof data.url_status === 'string' ? ` [${data.url_status}]` : '';
    return { status: 'listed', detail: `URL is present in the URLhaus database${threat}${status}.` };
  }
  if (data.query_status === 'no_results') return { status: 'not-listed', detail: 'No match in this lookup.' };
  return { status: 'unknown', detail: `URLhaus query status: ${data.query_status.slice(0, 80)}.` };
}

async function checkPhishTank(url: string, appKey: string): Promise<ProviderOutcome> {
  if (!appKey || !appKey.trim()) {
    return { status: 'not-configured', detail: 'PhishTank API key not configured (optional, can be added in Settings).' };
  }
  const body = new URLSearchParams({ url, format: 'json', app_key: appKey.trim() });
  const data = await responseJson(await request('https://checkurl.phishtank.com/checkurl/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
    body,
  }), 'PhishTank');
  if (!isRecord(data) || !isRecord(data.results) || typeof data.results.in_database !== 'boolean') {
    throw new Error('PhishTank returned an invalid response.');
  }
  return data.results.in_database
    ? { status: 'listed', detail: 'URL is present in the PhishTank database.' }
    : { status: 'not-listed', detail: 'No match in this lookup.' };
}

async function providerResult(
  provider: UrlReputationProvider,
  url: string,
  config: UrlReputationCredentials,
): Promise<UrlProviderResult> {
  const apiKey = provider === 'googleSafeBrowsing'
    ? config.googleSafeBrowsingKey
    : provider === 'virusTotal'
      ? config.virusTotalKey
      : provider === 'urlhaus'
        ? config.urlhausAuthKey
        : config.phishTankAppKey;
  if (typeof apiKey !== 'string' || !apiKey.trim()) {
    if (provider === 'phishTank') {
      return { provider, status: 'not-configured', detail: 'PhishTank API key not configured (optional, can be added in Settings).' };
    }
    return {
      provider,
      status: 'not-configured',
      detail: `Add an API key in Settings to enable ${provider === 'googleSafeBrowsing' ? 'Google Safe Browsing' : provider === 'virusTotal' ? 'VirusTotal' : 'URLhaus'}.`,
    };
  }

  try {
    const outcome = provider === 'googleSafeBrowsing'
      ? await checkGoogleSafeBrowsing(url, apiKey)
      : provider === 'virusTotal'
        ? await checkVirusTotal(url, apiKey)
        : provider === 'urlhaus'
          ? await checkUrlhaus(url, apiKey)
          : await checkPhishTank(url, apiKey);
    return { provider, ...outcome };
  } catch (error) {
    const detail = error instanceof Error ? error.message : 'Provider request failed.';
    return { provider, status: 'unknown', detail };
  }
}

function normalizeUrl(value: string): string | null {
  try {
    const parsed = new URL(value.trim());
    if ((parsed.protocol !== 'http:' && parsed.protocol !== 'https:') ||
        parsed.username || parsed.password || parsed.href.length > 2_048) return null;
    return parsed.href;
  } catch {
    return null;
  }
}

export async function checkUrlReputations(
  rawUrls: string[],
  config: UrlReputationCredentials,
): Promise<Record<string, UrlReputationReport>> {
  if (rawUrls.length > MAX_URLS_PER_LOOKUP) {
    throw new Error(`Check up to ${MAX_URLS_PER_LOOKUP} URLs at a time.`);
  }
  const normalized = rawUrls.map(normalizeUrl);
  if (normalized.some((url) => url === null)) {
    throw new Error('Only valid HTTP(S) URLs without embedded credentials can be checked.');
  }
  const urls = [...new Set(normalized.filter((url): url is string => url !== null))];
  const providers: UrlReputationProvider[] = ['googleSafeBrowsing', 'virusTotal', 'urlhaus', 'phishTank'];
  const entries = await Promise.all(urls.map(async (url) => {
    const checks = await Promise.all(providers.map((provider) => providerResult(provider, url, config)));
    return [url, { checkedAt: Date.now(), providers: checks }] as const;
  }));
  return Object.fromEntries(entries);
}
