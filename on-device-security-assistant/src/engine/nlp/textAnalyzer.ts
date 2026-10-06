import type { Signal } from '../types';
import { analyzeUrl } from '../url/urlAnalyzer';
import { combineSignals } from '../scoring/riskScorer';
import { findProtectivePositions, isNegated, isProtected } from './context';
import { extractUrls, findBrandLinkMismatch, findCallbackNumber, hostOf } from './linkAnalysis';
import { normalizeText } from './normalize';
import { TEXT_RULES } from './scamPatterns';
import type { Tactic } from './scamPatterns';
import { analyzeStructure } from './structure';
import { DEFAULT_DETECTION_RULES } from '../url/rules';
import type { DetectionRules } from '../url/rules';

const MAX_LENGTH = 20000;
const PRESSURE_TACTICS: readonly Tactic[] = ['urgency', 'fear', 'authority', 'reward'];
const HINDI_NEGATION = /(?:^|\s)(?:\u0928|\u092E\u0924)(?:\s|$)/; // "na" / "mat" inside a Hindi match

/** Global copies built once, so every occurrence of a rule can be inspected (not only the first). */
const COMPILED = TEXT_RULES.map((rule) => ({
  rule,
  matcher: new RegExp(rule.pattern.source, rule.pattern.flags.includes('g') ? rule.pattern.flags : `${rule.pattern.flags}g`),
}));

const snippet = (s: string, max = 80): string => (s.length > max ? `${s.slice(0, max)}...` : s);

/** First occurrence of the rule that is not in a protective / negated context. */
function findLiveMatch(entry: (typeof COMPILED)[number], text: string, protectedAt: number[]): string | null {
  for (const m of text.matchAll(entry.matcher)) {
    const index = m.index ?? 0;
    if (entry.rule.negatable) {
      if (isNegated(text, index) || isProtected(protectedAt, index)) continue;
      if (entry.rule.lang === 'hi' && HINDI_NEGATION.test(m[0])) continue;
    }
    return m[0];
  }
  return null;
}

function worstLink(urls: string[], rules: DetectionRules): { url: string; host: string; score: number } | null {
  let worst: { url: string; host: string; score: number } | null = null;
  for (const url of urls) {
    const score = combineSignals(analyzeUrl(url, rules)).score;
    if (!worst || score > worst.score) worst = { url, host: hostOf(url), score };
  }
  return worst;
}

export function analyzeText(raw: string, rules: DetectionRules = DEFAULT_DETECTION_RULES): Signal[] {
  const input = raw.slice(0, MAX_LENGTH);
  const { text, findings } = normalizeText(input);
  const signals: Signal[] = [];
  const tactics = new Set<Tactic>();

  // 1. Evasion attempts are evidence in themselves.
  for (const f of findings) {
    signals.push({ id: `obfuscation-${f.kind}`, weight: f.weight, reason: f.reason, evidence: f.evidence });
  }

  // 2. Scam-language rules (negation and protective context aware).
  const protectedAt = findProtectivePositions(text);
  for (const entry of COMPILED) {
    const hit = findLiveMatch(entry, text, protectedAt);
    if (hit === null) continue;
    signals.push({ id: entry.rule.id, weight: entry.rule.weight, reason: entry.rule.reason, evidence: snippet(hit) });
    tactics.add(entry.rule.tactic);
  }
  const strongTactics = [...tactics].filter((t) => t !== 'lure');
  const pressure = strongTactics.some((t) => PRESSURE_TACTICS.includes(t));

  // 3. Links inside the message.
  const urls = extractUrls(text);
  const risky = worstLink(urls, rules);
  if (risky && risky.score >= 30) {
    signals.push({ id: 'risky-link', weight: Math.min(60, risky.score), reason: `Contains a risky link (${risky.host})`, evidence: snippet(risky.url) });
  }
  if (strongTactics.length > 0) {
    const mismatch = findBrandLinkMismatch(text, urls);
    if (mismatch) {
      signals.push({
        id: 'brand-link-mismatch',
        weight: 35,
        reason: `Mentions ${mismatch.brand} but links to an unrelated site (${mismatch.host})`,
        evidence: snippet(mismatch.url),
      });
    }
  }

  // 4. Pressure + a way to act on it (click or call).
  if (pressure && urls.length > 0) {
    signals.push({ id: 'pressure-plus-link', weight: 20, reason: 'Pressure tactics combined with a link to click' });
  }
  const callback = findCallbackNumber(text);
  if (pressure && callback) {
    signals.push({ id: 'pressure-plus-callback', weight: 20, reason: 'Pressure tactics combined with a number to call', evidence: callback });
  }

  // 5. Style cues (use the original text: normalization may change capitalisation).
  signals.push(...analyzeStructure(input));

  // 6. Fusion: several different manipulation tactics together are far more suspicious than one.
  if (strongTactics.length >= 2) {
    const weight = strongTactics.length >= 4 ? 35 : strongTactics.length === 3 ? 25 : 12;
    signals.push({
      id: 'multi-tactic',
      weight,
      reason: `Combines ${strongTactics.length} manipulation tactics (${strongTactics.join(', ')})`,
    });
  }

  return signals;
}