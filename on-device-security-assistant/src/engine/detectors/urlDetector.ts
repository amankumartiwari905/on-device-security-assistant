import type { Detector, ScanInputFor } from '../core/detector';
import type { Signal } from '../types';
import { analyzeUrl } from '../url/urlAnalyzer';

/** URL structure + lookalike/brand-impersonation analysis. */
export class UrlDetector implements Detector<'url' | 'page'> {
  readonly id = 'url';
  readonly handles = ['url', 'page'] as const;

  analyze(input: ScanInputFor<'url' | 'page'>): Signal[] {
    return analyzeUrl(input.url, input.rules);
  }
}