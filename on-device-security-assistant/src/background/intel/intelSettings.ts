import { isRecord } from './util';

/**
 * off:     no network requests at all.
 * domains: only domain names leave the device (DNS-over-HTTPS and registration lookups).
 * full:    also sends full email addresses to EmailRep for reputation data.
 */
export type IntelMode = 'off' | 'domains' | 'full';

export interface IntelSettings {
  mode: IntelMode;
  /** Optional EmailRep API key (sent in the "Key" header). Raises the provider's rate limit. */
  emailRepApiKey: string;
}

export const DEFAULT_INTEL_SETTINGS: IntelSettings = { mode: 'off', emailRepApiKey: '' };

const KEY = 'intelSettings';

export function normalizeIntelSettings(raw: unknown): IntelSettings {
  const settings: IntelSettings = { ...DEFAULT_INTEL_SETTINGS };
  if (isRecord(raw)) {
    if (raw.mode === 'off' || raw.mode === 'domains' || raw.mode === 'full') settings.mode = raw.mode;
    if (typeof raw.emailRepApiKey === 'string') settings.emailRepApiKey = raw.emailRepApiKey.trim().slice(0, 200);
  }
  return settings;
}

export async function getIntelSettings(): Promise<IntelSettings> {
  if (typeof chrome === 'undefined' || !chrome.storage?.local) return { ...DEFAULT_INTEL_SETTINGS };
  try {
    const data = await chrome.storage.local.get(KEY);
    return normalizeIntelSettings(data[KEY]);
  } catch {
    return { ...DEFAULT_INTEL_SETTINGS };
  }
}

export async function saveIntelSettings(patch: Partial<IntelSettings>): Promise<void> {
  const next = normalizeIntelSettings({ ...(await getIntelSettings()), ...patch });
  await chrome.storage.local.set({ [KEY]: next });
}