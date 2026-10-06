import type { Signal } from '../types';
import { getRegistrableDomain } from '../url/urlFeatures';
import { DEFAULT_DETECTION_RULES } from '../url/rules';
import type { DetectionRules } from '../url/rules';

const DIGIT_SWAPS: Record<string, string> = { '0': 'o', '3': 'e', '4': 'a', '5': 's', '7': 't', $: 's' };
const UNICODE_CONFUSABLES: Record<string, string> = {
  'а': 'a', 'с': 'c', 'е': 'e', 'і': 'i', 'о': 'o', 'р': 'p', 'ѕ': 's', 'х': 'x', 'у': 'y',
  'α': 'a', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x',
};

/** Undo common character swaps (paypa1 -> paypal, g00gle -> google, rn -> m). */
export function normalizeConfusables(s: string, oneAs: 'l' | 'i' = 'l'): string {
  return s
    .toLowerCase()
    .replace(/[а-сеіорѕхуαεικορτυχ]/g, (c) => UNICODE_CONFUSABLES[c] ?? c)
    .replace(/rn/g, 'm')
    .replace(/vv/g, 'w')
    .replace(/1/g, oneAs)
    .replace(/[03457$]/g, (c) => DIGIT_SWAPS[c]);
}

export function levenshtein(a: string, b: string): number {
  const dp: number[][] = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
    }
  }
  return dp[a.length][b.length];
}

export function jaroWinkler(a: string, b: string): number {
  if (a === b) return 1;
  if (!a.length || !b.length) return 0;

  const matchDistance = Math.max(Math.floor(Math.max(a.length, b.length) / 2) - 1, 0);
  const aMatches = Array(a.length).fill(false) as boolean[];
  const bMatches = Array(b.length).fill(false) as boolean[];
  let matches = 0;

  for (let i = 0; i < a.length; i++) {
    const start = Math.max(0, i - matchDistance);
    const end = Math.min(i + matchDistance + 1, b.length);
    for (let j = start; j < end; j++) {
      if (bMatches[j] || a[i] !== b[j]) continue;
      aMatches[i] = true;
      bMatches[j] = true;
      matches++;
      break;
    }
  }
  if (!matches) return 0;

  let transpositions = 0;
  let bIndex = 0;
  for (let i = 0; i < a.length; i++) {
    if (!aMatches[i]) continue;
    while (!bMatches[bIndex]) bIndex++;
    if (a[i] !== b[bIndex]) transpositions++;
    bIndex++;
  }

  const jaro = (
    matches / a.length +
    matches / b.length +
    (matches - transpositions / 2) / matches
  ) / 3;
  let prefix = 0;
  while (prefix < Math.min(4, a.length, b.length) && a[prefix] === b[prefix]) prefix++;
  return jaro + prefix * 0.1 * (1 - jaro);
}

/** A token plus its de-obfuscated spellings, so "paypa1" also matches "paypal". */
function tokenVariants(token: string): string[] {
  return [token, normalizeConfusables(token, 'l'), normalizeConfusables(token, 'i')];
}

function combinedNameTokens(name: string): Set<string> {
  const parts = name.split('-').filter(Boolean);
  const tokens = new Set(name.split('-').flatMap(tokenVariants));
  for (let start = 0; start < parts.length; start++) {
    let combined = '';
    for (let end = start; end < parts.length; end++) {
      combined += parts[end];
      tokenVariants(combined).forEach((variant) => tokens.add(variant));
    }
  }
  return tokens;
}

/** Detects domains that imitate a well-known brand. Returns at most one signal. */
export function analyzeDomain(hostname: string, rules: DetectionRules = DEFAULT_DETECTION_RULES): Signal[] {
  const registrable = getRegistrableDomain(hostname);
  if (rules.brands.some((brand) => brand.domains.includes(registrable))) return [];

  const name = registrable.split('.')[0];
  const nameTokens = combinedNameTokens(name);
  const subLabels = hostname.slice(0, hostname.length - registrable.length).split('.').filter(Boolean);
  const subTokens = new Set(subLabels.flatMap((l) => l.split('-')).flatMap(tokenVariants));
  const normalized = normalizeConfusables(name, 'l');
  const variants = [
    normalized,
    normalizeConfusables(name, 'i'),
    normalized.replace(/i/g, 'l'),
    normalized.replace(/l/g, 'i'),
  ];

  for (const b of rules.brands) {
    const label = b.name;
    if (name === label) {
      return [{ id: 'brand-wrong-domain', weight: 45, reason: `Looks like ${label} but is not the official ${label} domain` }];
    }
    if (variants.includes(label)) {
      return [{ id: 'homoglyph', weight: 50, reason: `Domain uses visually similar characters to imitate ${label}` }];
    }
    if (label.length >= 6 && variants.some((v) =>
      levenshtein(v, label) === 1 || (Math.min(v.length, label.length) >= 6 && jaroWinkler(v, label) >= 0.93),
    )) {
      return [{ id: 'typosquat', weight: 45, reason: `Domain is one typo away from ${label}` }];
    }
    if (nameTokens.has(label)) {
      const displayName = label === 'paypal' ? 'PayPal' : label[0].toUpperCase() + label.slice(1);
      return [{
        id: 'brand-in-domain',
        weight: 50,
        reason: `Domain resembles ${displayName} but is not ${b.domains[0]}`,
      }];
    }
    if (subTokens.has(label)) {
      return [{ id: 'brand-in-subdomain', weight: 50, reason: `Puts the ${label} name in a subdomain of an unrelated site` }];
    }
  }
  return [];
}