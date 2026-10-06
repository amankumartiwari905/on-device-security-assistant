import type { Signal } from '../types';

/** Cheap stylistic cues. Weak on their own; they only matter in combination with other signals. */
export function analyzeStructure(raw: string): Signal[] {
  const signals: Signal[] = [];

  const letters = raw.match(/[A-Za-z]/g)?.length ?? 0;
  const upper = raw.match(/[A-Z]/g)?.length ?? 0;
  if (letters >= 30 && upper / letters > 0.6) {
    signals.push({ id: 'shouting', weight: 8, reason: 'Written mostly in capital letters to alarm you' });
  }

  const exclamations = raw.match(/!/g)?.length ?? 0;
  if (exclamations >= 3) {
    signals.push({ id: 'exclamation-spam', weight: 6, reason: 'Uses many exclamation marks to pressure you' });
  }
  return signals;
}