/** Stops calling a provider for a while after it rate-limits us. Cooldown doubles on repeated trips. */
export class CircuitBreaker {
  private openUntil = 0;
  private failures = 0;
  private readonly baseCooldownMs: number;
  private readonly maxCooldownMs: number;

  constructor(baseCooldownMs: number, maxCooldownMs: number) {
    this.baseCooldownMs = baseCooldownMs;
    this.maxCooldownMs = maxCooldownMs;
  }

  get isOpen(): boolean {
    return Date.now() < this.openUntil;
  }

  /** Epoch milliseconds when requests may resume. */
  get retryAt(): number {
    return this.openUntil;
  }

  trip(retryAfterMs?: number | null): void {
    this.failures += 1;
    const backoff = Math.min(this.maxCooldownMs, this.baseCooldownMs * 2 ** (this.failures - 1));
    this.openUntil = Date.now() + Math.max(backoff, retryAfterMs ?? 0);
  }

  reset(): void {
    this.failures = 0;
    this.openUntil = 0;
  }
}