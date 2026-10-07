import type { RiskLevel, Verdict } from '../engine/types';

export type Message =
  | { type: 'ALLOW_ONCE'; url: string }
  | { type: 'ANALYZE_MESSAGE'; text: string; intent: AnalysisIntent }
  | { type: 'PAGE_VERDICT'; score: number; level: RiskLevel };

export type AnalysisIntent = 'automatic' | 'explain';

export interface ThreatExplanation {
  risk_level: 'SAFE' | 'SUSPICIOUS' | 'HIGH_RISK';
  summary: string;
  reasons: string[];
  recommendation: string;
}

export type AnalyzeMessageResponse =
  | {
      verdict: Verdict;
      explanation: ThreatExplanation | null;
      trigger: 'risk-threshold' | 'user-request' | 'not-triggered';
      ollama: { status: 'analyzed' | 'unavailable' | 'skipped'; message: string };
    }
  | { error: string };