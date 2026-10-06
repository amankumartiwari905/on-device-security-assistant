import type { RiskLevel } from '../engine/types';

export type Message =
  | { type: 'ALLOW_ONCE'; url: string }
  | { type: 'PAGE_VERDICT'; score: number; level: RiskLevel };