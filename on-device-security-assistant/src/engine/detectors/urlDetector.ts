import type { Detector, ScanInput } from '../core/detector';
import type { Signal } from '../types';
import { analyzeUrl } from '../url/urlAnalyzer';

/** URL structure + lookalike/brand-impersonation analysis. */
export class UrlDetector implements Detector {
  readonly id = 'url';
  readonly handles = ['url', 'page'] as const;

  analyze(input: ScanInput): Signal[] {
    if (input.kind === 'text') return [];
    return analyzeUrl(input.url, input.rules);
  }
}