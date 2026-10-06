export interface SessionStore {
  get(key: string): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(key: string): Promise<void>;
}

const KEY = 'tempAllow';
let consumptionQueue: Promise<void> = Promise.resolve();

function normalizeUrl(rawUrl: string): string | undefined {
  try {
    const url = new URL(rawUrl);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return undefined;
    url.hash = '';
    return url.href;
  } catch {
    return undefined;
  }
}

export async function addAllowOnce(rawUrl: string, storage: SessionStore): Promise<boolean> {
  const url = normalizeUrl(rawUrl);
  if (!url) return false;

  const data = await storage.get(KEY);
  const current = Array.isArray(data[KEY]) ? data[KEY].filter((entry): entry is string => typeof entry === 'string') : [];
  if (!current.includes(url)) current.push(url);
  await storage.set({ [KEY]: current });
  return true;
}

async function consume(rawUrl: string, storage: SessionStore): Promise<boolean> {
  const url = normalizeUrl(rawUrl);
  if (!url) return false;

  const data = await storage.get(KEY);
  const current = Array.isArray(data[KEY]) ? data[KEY].filter((entry): entry is string => typeof entry === 'string') : [];
  const index = current.indexOf(url);
  if (index === -1) return false;

  current.splice(index, 1);
  if (current.length > 0) await storage.set({ [KEY]: current });
  else await storage.remove(KEY);
  return true;
}

export function consumeAllowOnce(rawUrl: string, storage: SessionStore): Promise<boolean> {
  const result = consumptionQueue.then(() => consume(rawUrl, storage));
  consumptionQueue = result.then(() => undefined, () => undefined);
  return result;
}