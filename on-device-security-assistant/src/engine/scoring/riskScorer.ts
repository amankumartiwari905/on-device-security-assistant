import type { RiskLevel, Signal, Verdict } from '../types';

export function levelFor(score: number): RiskLevel {
  if (score >= 60) return 'dangerous';
  if (score >= 30) return 'suspicious';
  return 'safe';
}

/**
 * Probabilistic OR: each signal independently "could be a threat" with p = weight/100.
 * Result stays within 0-100 and many weak signals add up without exploding.
 */
export function combineSignals(signals: Signal[]): Verdict {
  const unique = new Map<string, Signal>();
  for (const s of signals) unique.set(s.id, s);
  const list = [...unique.values()].sort((a, b) => b.weight - a.weight);

  const missProbability = list.reduce((p, s) => p * (1 - Math.min(s.weight, 95) / 100), 1);
  const score = Math.round((1 - missProbability) * 100);

  return {
    score,
    level: levelFor(score),
    reasons: list.slice(0, 5).map((s) => s.reason),
    signals: list,
  };
}