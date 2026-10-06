/**
 * Context awareness: "Do not share your OTP" and "We will never ask for your PIN" mention the same
 * words as a scam, but protect the reader. Rules marked `negatable` skip matches found in such context.
 */

// A negator directly before the match, with at most ~15 characters of filler (no punctuation).
// "Do not ignore. Share OTP" is NOT negated because the period breaks the chain.
const NEGATION_BEFORE = /\b(?:do not|don'?t|dont|never|won'?t|will not|should not|must not|avoid|mat)\b[\s\w'-]{0,15}$/i;

// Phrases typical of genuine security notices and fraud awareness.
const PROTECTIVE =
  /\b(?:(?:will|would|shall) never (?:ask|call|request|message|email|send)|never (?:ask|share|disclose|reveal)|(?:do not|don'?t) (?:share|disclose|reveal)|beware of|fraud alert|scam alert|stay (?:alert|safe|vigilant)|be careful of)\b/gi;

/** How far after a protective phrase a match still counts as protected. */
const PROTECTIVE_WINDOW = 140;

export function isNegated(text: string, index: number): boolean {
  return NEGATION_BEFORE.test(text.slice(Math.max(0, index - 40), index));
}

export function findProtectivePositions(text: string): number[] {
  return Array.from(text.matchAll(PROTECTIVE), (m) => m.index ?? 0);
}

export function isProtected(positions: number[], index: number): boolean {
  return positions.some((p) => index >= p && index - p <= PROTECTIVE_WINDOW);
}