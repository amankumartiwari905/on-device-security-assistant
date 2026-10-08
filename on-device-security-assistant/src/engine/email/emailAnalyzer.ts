import { analyzeDomain } from '../domain/lookalike';
import { getRegistrableDomain } from '../url/urlFeatures';
import { DEFAULT_DETECTION_RULES } from '../url/rules';
import type { DetectionRules } from '../url/rules';
import { extractEmailCandidates } from './emailExtraction';
import type { EmailCandidate, EmailSource } from './emailExtraction';
import {
  combineWeights,
  displayNameSignals,
  domainSignals,
  isDisposableDomain,
  isFreeProvider,
  localPartSignals,
} from './emailSignals';
import type { EmailSignal } from './emailSignals';
import type { EmailReputationReport } from '../../shared/emailReputation';

export type { EmailSignal } from './emailSignals';

export type EmailStatus = 'matches-site' | 'suspicious' | 'external';
export type EmailCategory = 'free-provider' | 'disposable' | 'same-site' | 'other-domain';

export interface EmailAssessment {
  address: string;
  status: EmailStatus;
  explanation: string;

  // Added in the advanced analyzer. All additive, so existing consumers keep working.
  /** Domain part, in ASCII/punycode form. */
  domain: string;
  category: EmailCategory;
  /** 0-100, combined from all signals. */
  riskScore: number;
  /** Every distinct warning sign found, strongest first. */
  signals: EmailSignal[];
  /** How many times the address appeared across the scanned sources. */
  occurrences: number;
  displayName?: string;
  source: EmailSource;
  onlineReputation?: EmailReputationReport;
}

export interface EmailSummary {
  total: number;
  suspicious: number;
  external: number;
  matchesSite: number;
  disposable: number;
  worst: EmailAssessment | null;
}

/** Original explanation texts, kept word for word. */
const TEXT = {
  obfuscated: 'This address is disguised with \u201Cat\u201D or \u201Cdot\u201D text.',
  invalid: 'This address does not have a valid email format.',
  matchesSite: 'The domain matches this website; the mailbox itself is not verified.',
  external: 'Valid-looking address on another domain; its owner and mailbox are unverified.',
} as const;

/** Risk at or above this marks an address "suspicious". */
const SUSPICIOUS_AT = 30;

const LOOKALIKE_IDS = new Set(['homoglyph', 'typosquat', 'brand-wrong-domain', 'brand-in-domain', 'brand-in-subdomain']);

/** Internationalized domains become punycode (xn--...) so they can be validated and compared. */
function toAsciiDomain(domain: string): string {
  const normalized = domain.normalize('NFKC').toLowerCase().replace(/\.$/, '');
  if (
    normalized.length === 0 ||
    normalized.length > 253 ||
    !/^[\p{L}\p{M}\p{N}.-]+$/u.test(normalized) ||
    normalized.includes('..') ||
    normalized.startsWith('.') ||
    normalized.endsWith('.')
  ) {
    return '';
  }

  try {
    const hostname = new URL(`http://${normalized}`).hostname.toLowerCase().replace(/\.$/, '');
    const labels = hostname.split('.');
    if (
      hostname.length > 253 ||
      labels.length < 2 ||
      labels.some((label) =>
        label.length === 0 ||
        label.length > 63 ||
        !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
      ) ||
      /^\d+$/.test(labels[labels.length - 1])
    ) {
      return '';
    }
    return hostname;
  } catch {
    return '';
  }
}

function isValidAddress(address: string): boolean {
  if (address.length > 254 || (address.match(/@/g) ?? []).length !== 1) return false;

  const [local, rawDomain] = address.split('@');
  if (!local || local.length > 64 || local.startsWith('.') || local.endsWith('.') || local.includes('..')) return false;
  if (!/^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+$/i.test(local)) return false;
  if (!rawDomain || /[\s/@\\:[\]?#%]/.test(rawDomain)) return false;

  const domain = toAsciiDomain(rawDomain);
  return Boolean(domain) && local.length + domain.length + 1 <= 254;
}

function normalizePageHostname(hostname: string): string {
  const raw = hostname.trim();
  if (!raw) return '';

  try {
    const parsed = /^[a-z][a-z\d+.-]*:\/\//i.test(raw)
      ? new URL(raw)
      : new URL(`http://${raw}`);
    if (parsed.username || parsed.password) return '';
    const host = parsed.hostname;
    return toAsciiDomain(host);
  } catch {
    return '';
  }
}

function uniqueSignals(signals: readonly EmailSignal[]): EmailSignal[] {
  const byId = new Map<string, EmailSignal>();
  for (const signal of signals) {
    const existing = byId.get(signal.id);
    if (!existing || signal.weight > existing.weight) byId.set(signal.id, signal);
  }
  return [...byId.values()].sort((a, b) => b.weight - a.weight || a.id.localeCompare(b.id));
}

function explain(signals: readonly EmailSignal[], suspicious: boolean, sameSite: boolean): string {
  if (!suspicious) return sameSite ? TEXT.matchesSite : TEXT.external;

  const primary = [...signals].sort((a, b) => b.weight - a.weight)[0];
  if (!primary) return TEXT.external;
  const others = signals.length - 1;
  return primary.weight < SUSPICIOUS_AT && others > 0
    ? `${primary.reason} (plus ${others} other warning sign${others === 1 ? '' : 's'})`
    : primary.reason;
}

export function addOnlineReputation(
  assessment: EmailAssessment,
  onlineReputation: EmailReputationReport,
): EmailAssessment {
  const signals = uniqueSignals([...assessment.signals, ...onlineReputation.signals]);
  const riskScore = combineWeights(signals);
  const suspicious = riskScore >= SUSPICIOUS_AT;
  const sameSite = assessment.category === 'same-site';
  return {
    ...assessment,
    status: suspicious ? 'suspicious' : sameSite ? 'matches-site' : 'external',
    explanation: explain(signals, suspicious, sameSite),
    riskScore,
    signals,
    onlineReputation,
  };
}

function assessCandidate(candidate: EmailCandidate, pageHostname: string, rules: DetectionRules): EmailAssessment {
  const address = candidate.address.trim();
  const discoveredSignals: EmailSignal[] = [];
  const normalizedPageHost = normalizePageHostname(pageHostname);
  const add = (id: string, weight: number, reason: string): void => {
    discoveredSignals.push({ id, weight, reason });
  };

  // Original checks first, in the original order.
  if (candidate.obfuscated) add('obfuscated', 55, TEXT.obfuscated);
  const valid = isValidAddress(address);
  if (!valid) add('invalid-format', 100, TEXT.invalid);

  const at = address.lastIndexOf('@');
  const local = at >= 0 ? address.slice(0, at) : address;
  const rawDomain = at >= 0 ? address.slice(at + 1).toLowerCase().replace(/\.$/, '') : '';
  const domain = valid ? toAsciiDomain(rawDomain) : rawDomain;
  const registrable = domain ? getRegistrableDomain(domain) : '';

  if (valid) {
    const lookalike = analyzeDomain(domain, rules).find((s) => LOOKALIKE_IDS.has(s.id));
    if (lookalike) add(lookalike.id, Math.max(lookalike.weight, 50), lookalike.reason);

    // Then the new checks.
    discoveredSignals.push(...domainSignals(domain, normalizedPageHost), ...localPartSignals(local, registrable));
    if (candidate.displayName) discoveredSignals.push(...displayNameSignals(candidate.displayName, registrable));
  }

  const signals = uniqueSignals(discoveredSignals);
  const riskScore = combineWeights(signals);
  const suspicious = riskScore >= SUSPICIOUS_AT;
  const pageRegistrable = normalizedPageHost ? getRegistrableDomain(normalizedPageHost) : '';
  const sameSite = valid && pageRegistrable !== '' && registrable === pageRegistrable;

  const category: EmailCategory = !valid
    ? 'other-domain'
    : isDisposableDomain(registrable)
      ? 'disposable'
      : isFreeProvider(registrable)
        ? 'free-provider'
        : sameSite
          ? 'same-site'
          : 'other-domain';

  return {
    address,
    status: suspicious ? 'suspicious' : sameSite ? 'matches-site' : 'external',
    explanation: explain(signals, suspicious, sameSite),
    domain,
    category,
    riskScore,
    signals,
    occurrences: candidate.occurrences,
    displayName: candidate.displayName,
    source: candidate.source,
  };
}

export function analyzePageEmails(
  sources: readonly string[],
  pageHostname: string,
  rules: DetectionRules = DEFAULT_DETECTION_RULES,
): EmailAssessment[] {
  return extractEmailCandidates(sources).map((candidate) => assessCandidate(candidate, pageHostname, rules));
}

/** Counts and the single riskiest address, handy for a popup badge or a banner. */
export function summarizeEmailAssessments(assessments: readonly EmailAssessment[]): EmailSummary {
  let worst: EmailAssessment | null = null;
  for (const a of assessments) {
    if (!worst || a.riskScore > worst.riskScore) worst = a;
  }
  return {
    total: assessments.length,
    suspicious: assessments.filter((a) => a.status === 'suspicious').length,
    external: assessments.filter((a) => a.status === 'external').length,
    matchesSite: assessments.filter((a) => a.status === 'matches-site').length,
    disposable: assessments.filter((a) => a.category === 'disposable').length,
    worst,
  };
}