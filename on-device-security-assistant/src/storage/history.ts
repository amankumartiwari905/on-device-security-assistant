import type { RiskLevel } from '../engine/types';

export interface HistoryItem {
  time: number;
  hostname: string; // hostname only, never the full URL (privacy)
  score: number;
  level: RiskLevel;
  reasons: string[];
}

const KEY = 'history';
const MAX_ITEMS = 50;

export async function getHistory(): Promise<HistoryItem[]> {
  const data = await chrome.storage.local.get(KEY);
  return (data[KEY] as HistoryItem[] | undefined) ?? [];
}

export async function addHistory(item: HistoryItem): Promise<void> {
  const list = await getHistory();
  await chrome.storage.local.set({ [KEY]: [item, ...list].slice(0, MAX_ITEMS) });
}

export async function clearHistory(): Promise<void> {
  await chrome.storage.local.remove(KEY);
}