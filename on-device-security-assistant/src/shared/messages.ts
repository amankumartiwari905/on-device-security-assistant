import type { RiskLevel, Verdict } from '../engine/types';
import type { EmailReputationResponse } from './emailReputation';
import type { UrlReputationResponse } from './urlReputation';

export interface PageLinkAssessment {
  url: string;
  text: string;
  verdict: Verdict;
}

export type Message =
  | { type: 'ALLOW_ONCE'; url: string }
  | { type: 'ANALYZE_MESSAGE'; text: string; intent: AnalysisIntent }
  | { type: 'CHECK_EMAIL_REPUTATION'; addresses: string[] }
  | { type: 'CHECK_URL_REPUTATION'; urls: string[] }
  | { type: 'GET_PAGE_LINKS' }
  | { type: 'PAGE_VERDICT'; score: number; level: RiskLevel };

export type AnalysisIntent = 'automatic' | 'explain';

export type PageLinksResponse = { links: PageLinkAssessment[] } | { error: string };
export type CheckUrlReputationResponse = UrlReputationResponse | { error: string };

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