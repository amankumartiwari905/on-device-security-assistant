export type Sensitivity = 'low' | 'medium' | 'high';

export interface Settings {
  enabled: boolean;
  sensitivity: Sensitivity;
  allowlist: string[]; // hostnames that are never blocked
  scanPageText: boolean;
}

export const DEFAULT_SETTINGS: Settings = {
  enabled: true,
  sensitivity: 'medium',
  allowlist: [],
  scanPageText: true,
};

const KEY = 'settings';

export async function getSettings(): Promise<Settings> {
  const data = await chrome.storage.local.get(KEY);
  return { ...DEFAULT_SETTINGS, ...(data[KEY] ?? {}) };
}

export async function saveSettings(patch: Partial<Settings>): Promise<void> {
  const current = await getSettings();
  await chrome.storage.local.set({ [KEY]: { ...current, ...patch } });
}

/** Score at which navigation is interrupted with the warning screen. */
export function blockThreshold(s: Sensitivity): number {
  return s === 'high' ? 45 : s === 'low' ? 75 : 60;
}