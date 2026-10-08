/**
 * Shared HTTP helper for online lookups: timeout, a global concurrency limit, one retry for
 * transient failures, and a typed error that carries rate-limit information.
 */
const MAX_CONCURRENT_REQUESTS = 4;
const DEFAULT_TIMEOUT_MS = 8_000;

let activeRequests = 0;
const waiters: Array<() => void> = [];

export class IntelHttpError extends Error {
  readonly status: number | null;
  /** From the Retry-After header, when the provider sent one. */
  readonly retryAfterMs: number | null;

  constructor(message: string, status: number | null, retryAfterMs: number | null = null) {
    super(message);
    this.name = 'IntelHttpError';
    this.status = status;
    this.retryAfterMs = retryAfterMs;
  }
}

export interface FetchOptions {
  accept?: string;
  headers?: Record<string, string>;
  timeoutMs?: number;
  /** Extra attempts for transient failures (network errors, timeouts, HTTP 5xx). Default 1. */
  retries?: number;
}

export function parseRetryAfter(value: string | null): number | null {
  if (!value) return null;
  const seconds = Number(value);
  if (Number.isFinite(seconds)) return Math.max(0, seconds) * 1000;
  const date = Date.parse(value);
  return Number.isNaN(date) ? null : Math.max(0, date - Date.now());
}

async function acquireSlot(): Promise<void> {
  if (activeRequests >= MAX_CONCURRENT_REQUESTS) {
    await new Promise<void>((resolve) => waiters.push(resolve)); // the slot is handed over, not re-counted
  } else {
    activeRequests++;
  }
}

function releaseSlot(): void {
  const next = waiters.shift();
  if (next) next();
  else activeRequests--;
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

function isTransient(error: unknown): boolean {
  if (error instanceof IntelHttpError) return error.status !== null && error.status >= 500;
  const name = (error as { name?: string } | null)?.name;
  return name === 'AbortError' || name === 'TypeError';
}

export async function fetchJson(url: string, options: FetchOptions = {}): Promise<unknown> {
  const { accept = 'application/json', headers = {}, timeoutMs = DEFAULT_TIMEOUT_MS, retries = 1 } = options;

  await acquireSlot();
  try {
    for (let attempt = 0; ; attempt++) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const response = await fetch(url, { headers: { Accept: accept, ...headers }, signal: controller.signal });
        if (response.status === 429) {
          throw new IntelHttpError('Provider is rate limiting requests (HTTP 429).', 429, parseRetryAfter(response.headers.get('Retry-After')));
        }
        if (!response.ok) throw new IntelHttpError(`Provider returned HTTP ${response.status}.`, response.status);
        return (await response.json()) as unknown;
      } catch (error) {
        if (attempt >= retries || !isTransient(error)) throw error;
        await sleep(300 * 2 ** attempt);
      } finally {
        clearTimeout(timer);
      }
    }
  } finally {
    releaseSlot();
  }
}