import type { Signal } from '../../engine/types';
import { getRegistrableDomain } from '../../engine/url/urlFeatures';
import { getIntelSettings } from './intelSettings';
import type { IntelMode } from './intelSettings';
import { daysSince, lookupRegistration } from './rdap';

/**
 * Online enrichment for website addresses. Only the domain age is used here, and only for
 * borderline verdicts: querying every visited site would reveal your browsing to registries.
 */
export const ENRICH_MIN_SCORE = 15;
export const ENRICH_MAX_SCORE = 60; // exclusive: at 60+ the page is already blocked

export function shouldEnrich(score: number): boolean {
  return score >= ENRICH_MIN_SCORE && score < ENRICH_MAX_SCORE;
}

export function registrationAgeSignal(ageDays: number | null): Signal | null {
  if (ageDays === null || ageDays > 90) return null;
  const weight = ageDays <= 7 ? 40 : ageDays <= 30 ? 28 : 10;
  const when = ageDays === 0 ? 'today' : `${ageDays} day${ageDays === 1 ? '' : 's'} ago`;
  return { id: 'new-domain', weight, reason: `This website's domain was registered ${when}` };
}

export async function urlDomainSignals(hostname: string, mode?: IntelMode): Promise<Signal[]> {
  const effectiveMode = mode ?? (await getIntelSettings()).mode;
  if (effectiveMode === 'off') return [];
  if (!hostname.includes('.') || /^[\d.]+$/.test(hostname) || hostname.includes(':')) return []; // localhost, IPs

  const info = await lookupRegistration(getRegistrableDomain(hostname));
  const signal = registrationAgeSignal(info.registeredAt ? daysSince(info.registeredAt) : null);
  return signal ? [signal] : [];
}