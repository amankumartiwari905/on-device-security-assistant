import type { Detector, ScanInputFor } from '../core/detector';
import type { Signal } from '../types';
import { analyzeText } from '../nlp/textAnalyzer';

/** Scam / phishing language analysis (also scores any links found in the text). */
export class TextDetector implements Detector<'text' | 'page'> {
  readonly id = 'text';
  readonly handles = ['text', 'page'] as const;

  analyze(input: ScanInputFor<'text' | 'page'>): Signal[] {
    return analyzeText(input.text, input.rules);
  }
}