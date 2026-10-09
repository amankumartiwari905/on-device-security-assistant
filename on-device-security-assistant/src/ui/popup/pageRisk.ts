import { combineSignals } from '../../engine';
import type { Verdict } from '../../engine';
import type { PageLinkAssessment } from '../../shared/messages';

export function includePageLinkClues(
  pageVerdict: Verdict,
  links: PageLinkAssessment[],
): Verdict {
  const linkSignals = links.flatMap(({ url, verdict }) =>
    verdict.signals.map((signal) => ({
      ...signal,
      evidence: signal.evidence ?? url,
    })),
  );
  const combined = combineSignals([...pageVerdict.signals, ...linkSignals]);
  const signals = combined.signals.slice(0, 3);

  return {
    ...combined,
    reasons: signals.map((signal) => signal.reason),
    signals,
  };
}
