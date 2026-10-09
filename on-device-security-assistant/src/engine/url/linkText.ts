/** Returns true when visible link text claims a different site than its destination. */
export function linkTextClaimsDifferentSite(text: string, destination: string): boolean {
  const match = text.trim().match(/^(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/?#]|$)/i);
  if (!match) return false;

  try {
    const real = new URL(destination).hostname.replace(/^www\./, '');
    const claimed = match[1].toLowerCase().replace(/^www\./, '');
    return real !== claimed && !real.endsWith(`.${claimed}`);
  } catch {
    return false;
  }
}
