/**
 * Two-layer TTL cache for online lookups.
 *  - memory: fast, but lost whenever the MV3 service worker is stopped
 *  - chrome.storage.local: survives restarts (skip it with persist: false for sensitive keys)
 * Concurrent requests for the same key share one in-flight fetch.
 */
const STORAGE_PREFIX = 'intel:';
const MEMORY_LIMIT = 500;
const STORAGE_LIMIT = 300;
const PRUNE_EVERY_WRITES = 25;

interface Entry {
  value: unknown;
  expiresAt: number;
}

export interface CacheOptions<T> {
  ttlMs: number;
  /** TTL used when isFailure(value) is true, so errors are retried sooner than good data. */
  failureTtlMs: number;
  isFailure: (value: T) => boolean;
  /** Default true. Use false for keys that contain personal data (email addresses). */
  persist?: boolean;
}

const memory = new Map<string, Entry>();
const inflight = new Map<string, Promise<unknown>>();
let writesSincePrune = 0;

function storageArea(): chrome.storage.StorageArea | null {
  return typeof chrome !== 'undefined' && chrome.storage?.local ? chrome.storage.local : null;
}

function isEntry(value: unknown): value is Entry {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as { expiresAt?: unknown }).expiresAt === 'number' &&
    'value' in value
  );
}

function remember(key: string, entry: Entry): void {
  memory.set(key, entry);
  if (memory.size > MEMORY_LIMIT) {
    const oldest = memory.keys().next().value as string | undefined;
    if (oldest !== undefined) memory.delete(oldest);
  }
}

async function readEntry(key: string, persist: boolean): Promise<unknown> {
  const now = Date.now();
  const inMemory = memory.get(key);
  if (inMemory) {
    if (inMemory.expiresAt > now) return inMemory.value;
    memory.delete(key);
  }

  const area = persist ? storageArea() : null;
  if (!area) return undefined;
  try {
    const stored = await area.get(STORAGE_PREFIX + key);
    const entry: unknown = stored[STORAGE_PREFIX + key];
    if (isEntry(entry) && entry.expiresAt > now) {
      remember(key, entry);
      return entry.value;
    }
  } catch {
    /* storage unavailable: behave like a cache miss */
  }
  return undefined;
}

async function pruneStorage(area: chrome.storage.StorageArea): Promise<void> {
  const all = await area.get(null);
  const now = Date.now();
  const entries = Object.entries(all)
    .filter(([key]) => key.startsWith(STORAGE_PREFIX))
    .map(([key, value]) => ({ key, expiresAt: isEntry(value) ? value.expiresAt : 0 }));

  const expired = entries.filter((e) => e.expiresAt <= now).map((e) => e.key);
  const live = entries.filter((e) => e.expiresAt > now).sort((a, b) => a.expiresAt - b.expiresAt);
  const overflow = live.slice(0, Math.max(0, live.length - STORAGE_LIMIT)).map((e) => e.key);

  const remove = [...expired, ...overflow];
  if (remove.length > 0) await area.remove(remove);
}

async function writeEntry(key: string, value: unknown, ttlMs: number, persist: boolean): Promise<void> {
  const entry: Entry = { value, expiresAt: Date.now() + ttlMs };
  remember(key, entry);

  const area = persist ? storageArea() : null;
  if (!area) return;
  try {
    await area.set({ [STORAGE_PREFIX + key]: entry });
    writesSincePrune += 1;
    if (writesSincePrune >= PRUNE_EVERY_WRITES) {
      writesSincePrune = 0;
      await pruneStorage(area);
    }
  } catch {
    /* quota or storage problem: the memory layer still works */
  }
}

export async function cached<T>(key: string, fetcher: () => Promise<T>, options: CacheOptions<T>): Promise<T> {
  const persist = options.persist ?? true;

  const hit = await readEntry(key, persist);
  if (hit !== undefined) return hit as T;

  const pending = inflight.get(key);
  if (pending) return pending as Promise<T>;

  const request = (async () => {
    const value = await fetcher();
    await writeEntry(key, value, options.isFailure(value) ? options.failureTtlMs : options.ttlMs, persist);
    return value;
  })();
  inflight.set(key, request);
  try {
    return await request;
  } finally {
    inflight.delete(key);
  }
}

/** Removes every cached lookup (memory and storage), e.g. from a "Clear online cache" button. */
export async function clearIntelCache(): Promise<void> {
  memory.clear();
  const area = storageArea();
  if (!area) return;
  try {
    const all = await area.get(null);
    const keys = Object.keys(all).filter((key) => key.startsWith(STORAGE_PREFIX));
    if (keys.length > 0) await area.remove(keys);
  } catch {
    /* nothing to clear */
  }
}