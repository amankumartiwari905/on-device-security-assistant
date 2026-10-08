export type UrlReputationProvider = 'googleSafeBrowsing' | 'virusTotal' | 'urlhaus' | 'phishTank';
export type UrlProviderStatus = 'listed' | 'not-listed' | 'unknown' | 'not-configured';

export interface UrlProviderResult {
  provider: UrlReputationProvider;
  status: UrlProviderStatus;
  detail: string;
}

export interface UrlReputationReport {
  checkedAt: number;
  providers: UrlProviderResult[];
}

export interface UrlReputationResponse {
  results: Record<string, UrlReputationReport>;
  message: string;
}
