import { DEFAULT_DETECTION_RULES } from '../engine/url/rules';
import type { DetectionRules } from '../engine/url/rules';

export const DETECTION_RULES_KEY = 'detectionRules';

export interface DetectionRuleText {
  brands: string;
  suspiciousTlds: string;
  urlShorteners: string;
  suspiciousKeywords: string;
}

function uniqueLines(value: string): string[] {
  return [...new Set(value.split(/[\n,]/).map((item) => item.trim().toLowerCase()).filter(Boolean))];
}

function validHostname(hostname: string): boolean {
  if (hostname.length > 253 || hostname.startsWith('.') || hostname.endsWith('.')) return false;
  const labels = hostname.split('.');
  return labels.length >= 2 && labels.every((label) =>
    label.length > 0 && label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
  );
}

export function formatDetectionRules(rules: DetectionRules): DetectionRuleText {
  return {
    brands: rules.brands.map((brand) => `${brand.name}=${brand.domains.join(', ')}`).join('\n'),
    suspiciousTlds: rules.suspiciousTlds.join('\n'),
    urlShorteners: rules.urlShorteners.join('\n'),
    suspiciousKeywords: rules.suspiciousKeywords.join('\n'),
  };
}

export function parseDetectionRuleText(text: DetectionRuleText): DetectionRules {
  const brands = text.brands.split('\n').map((line) => line.trim()).filter(Boolean).map((line) => {
    const separator = line.indexOf('=');
    const name = line.slice(0, separator).trim().toLowerCase();
    const domains = uniqueLines(line.slice(separator + 1));
    if (separator < 1 || !/^[a-z0-9-]{2,40}$/.test(name) || domains.length === 0 || !domains.every(validHostname)) {
      throw new Error(`Invalid brand rule: ${line}`);
    }
    return { name, domains };
  });
  const suspiciousTlds = uniqueLines(text.suspiciousTlds).map((tld) => tld.replace(/^\./, ''));
  if (!suspiciousTlds.every((tld) => /^[a-z0-9-]{2,63}$/.test(tld))) {
    throw new Error('Suspicious TLDs must be plain domain endings, one per line.');
  }
  const urlShorteners = uniqueLines(text.urlShorteners);
  if (!urlShorteners.every(validHostname)) {
    throw new Error('URL shorteners must be hostnames, one per line.');
  }
  const suspiciousKeywords = uniqueLines(text.suspiciousKeywords);
  if (!suspiciousKeywords.every((keyword) => /^[a-z0-9-]{2,50}$/.test(keyword))) {
    throw new Error('Keywords may contain only letters, numbers, and hyphens.');
  }
  return { brands, suspiciousTlds, urlShorteners, suspiciousKeywords };
}

function normalizeStoredRules(value: unknown): DetectionRules {
  if (!value || typeof value !== 'object') return formatDefaults();
  try {
    const text = formatDetectionRules({
      brands: Array.isArray((value as DetectionRules).brands) ? (value as DetectionRules).brands : [],
      suspiciousTlds: Array.isArray((value as DetectionRules).suspiciousTlds) ? (value as DetectionRules).suspiciousTlds : [],
      urlShorteners: Array.isArray((value as DetectionRules).urlShorteners) ? (value as DetectionRules).urlShorteners : [],
      suspiciousKeywords: Array.isArray((value as DetectionRules).suspiciousKeywords) ? (value as DetectionRules).suspiciousKeywords : [],
    });
    return parseDetectionRuleText(text);
  } catch {
    return formatDefaults();
  }
}

function formatDefaults(): DetectionRules {
  return {
    brands: DEFAULT_DETECTION_RULES.brands.map((brand) => ({ ...brand, domains: [...brand.domains] })),
    suspiciousTlds: [...DEFAULT_DETECTION_RULES.suspiciousTlds],
    urlShorteners: [...DEFAULT_DETECTION_RULES.urlShorteners],
    suspiciousKeywords: [...DEFAULT_DETECTION_RULES.suspiciousKeywords],
  };
}

export async function getDetectionRules(): Promise<DetectionRules> {
  const data = await chrome.storage.local.get(DETECTION_RULES_KEY);
  return data[DETECTION_RULES_KEY] === undefined
    ? formatDefaults()
    : normalizeStoredRules(data[DETECTION_RULES_KEY]);
}

export async function saveDetectionRules(rules: DetectionRules): Promise<void> {
  const normalized = parseDetectionRuleText(formatDetectionRules(rules));
  await chrome.storage.local.set({ [DETECTION_RULES_KEY]: normalized });
}