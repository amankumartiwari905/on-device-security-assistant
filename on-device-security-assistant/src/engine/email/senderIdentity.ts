import { getRegistrableDomain } from '../url/urlFeatures';
import { DEFAULT_DETECTION_RULES } from '../url/rules';
import type { DetectionRules } from '../url/rules';
import { analyzePageEmails } from './emailAnalyzer';
import type { EmailAssessment } from './emailAnalyzer';
import { combineWeights, isFreeProvider } from './emailSignals';
import type { EmailSignal } from './emailSignals';

/**
 * Consistency checks for a whole message (webmail view or pasted headers).
 * Pure data in, signals out: wire it to whatever extracts the headers.
 */
export interface SenderIdentityInput {
  /** Raw From value or visible sender, e.g. "Acme Billing <billing@acme.com>". */
  from: string;
  replyTo?: string;
  returnPath?: string;
  /** Absolute URLs found in the message body. */
  linkUrls?: readonly string[];
}

export interface SenderIdentityResult {
  riskScore: number;
  signals: EmailSignal[];
  sender: EmailAssessment | null;
}

const SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'tiny.cc', 'rb.gy',
]);

function domainOf(address: string): string {
  const raw = address.slice(address.lastIndexOf('@') + 1).toLowerCase().replace(/\.$/, '');
  return raw ? getRegistrableDomain(raw) : '';
}

function linkDomain(url: string): string {
  try {
    return getRegistrableDomain(new URL(url).hostname);
  } catch {
    return '';
  }
}

export function analyzeSenderIdentity(
  input: SenderIdentityInput,
  rules: DetectionRules = DEFAULT_DETECTION_RULES,
): SenderIdentityResult {
  const sender = analyzePageEmails([input.from], '', rules)[0] ?? null;
  if (!sender) {
    const signals = [{ id: 'no-sender', weight: 30, reason: 'The sender address could not be read' }];
    return { riskScore: combineWeights(signals), signals, sender: null };
  }

  const signals: EmailSignal[] = [...sender.signals];
  const senderDomain = domainOf(sender.address);

  if (input.replyTo) {
    const reply = analyzePageEmails([input.replyTo], '', rules)[0];
    if (reply) {
      const replyDomain = domainOf(reply.address);
      if (replyDomain !== senderDomain) {
        if (isFreeProvider(replyDomain) && !isFreeProvider(senderDomain)) {
          signals.push({ id: 'reply-to-freemail', weight: 45, reason: `Replies go to a free email address (${replyDomain}) instead of the sender's own domain` });
        } else {
          signals.push({ id: 'reply-to-mismatch', weight: 30, reason: `Replies go to a different domain (${replyDomain}) than the sender (${senderDomain})` });
        }
      }
      if (reply.status === 'suspicious') {
        signals.push({ id: 'reply-to-suspicious', weight: 35, reason: `The reply-to address looks suspicious: ${reply.explanation}` });
      }
    }
  }

  if (input.returnPath) {
    const path = analyzePageEmails([input.returnPath], '', rules)[0];
    if (path && domainOf(path.address) !== senderDomain) {
      // Mailing services legitimately differ here, so this is deliberately weak.
      signals.push({ id: 'return-path-mismatch', weight: 15, reason: 'The bounce address uses a different domain than the sender' });
    }
  }

  const linkDomains = (input.linkUrls ?? []).map(linkDomain).filter(Boolean);
  if (linkDomains.length > 0) {
    if (linkDomains.every((d) => d !== senderDomain)) {
      signals.push({ id: 'links-off-sender-domain', weight: 15, reason: "None of the links point to the sender's own domain" });
    }
    if (linkDomains.some((d) => SHORTENERS.has(d))) {
      signals.push({ id: 'shortened-links', weight: 15, reason: 'Contains shortened links that hide the real destination' });
    }
  }

  return { riskScore: combineWeights(signals), signals, sender };
}