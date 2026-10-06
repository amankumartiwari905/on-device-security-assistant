import type { Detector, ScanInput } from '../core/detector';
import type { Signal } from '../types';
import { analyzeText } from '../nlp/textAnalyzer';

/** Scam / phishing language analysis (also scores any links found in the text). */
export class TextDetector implements Detector {
  readonly id = 'text';
  readonly handles = ['text', 'page'] as const;

  analyze(input: ScanInput): Signal[] {
    if (input.kind === 'url') return [];
    return analyzeText(input.text, input.rules);
  }
}