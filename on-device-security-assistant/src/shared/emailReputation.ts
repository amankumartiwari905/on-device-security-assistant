import type { EmailSignal } from '../engine/email/emailSignals';

export const MAX_EMAILS_PER_PAGE = 5;

export interface EmailReputationReport {
  checkedAt: number;
  status: 'complete' | 'partial' | 'unavailable';
  emailRep: {
    reputation: string | null;
    suspicious: boolean | null;
    references: number | null;
    firstSeen: string | null;
    lastSeen: string | null;
    dataBreaches: number | null;
    domainAgeDays: number | null;
    domainReputation: string | null;
    domainExists: boolean | null;
    flags: string[];
    error: string | null;
  };
  domain: {
    hasMx: boolean | null;
    mxHosts: string[];
    hasSpf: boolean | null;
    hasDmarc: boolean | null;
    ageDays: number | null;
    error: string | null;
  };
  signals: EmailSignal[];
}

export interface EmailReputationResponse {
  results: Record<string, EmailReputationReport>;
  message: string;
}
