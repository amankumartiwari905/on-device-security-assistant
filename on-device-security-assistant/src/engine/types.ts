export type RiskLevel = 'safe' | 'suspicious' | 'dangerous';

/** One piece of evidence. weight = 0-100 "how strongly this suggests a threat". */
export interface Signal {
  id: string;
  weight: number;
  reason: string;
  /** Short excerpt that triggered the signal, shown to the user. */
  evidence?: string;
}

export interface Verdict {
  score: number; // 0-100
  level: RiskLevel;
  reasons: string[]; // top human-readable explanations
  signals: Signal[];
}