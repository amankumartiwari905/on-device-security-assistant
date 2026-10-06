import { DetectionEngine } from './core/detectionEngine';
import type { ScanResult } from './core/detectionEngine';
import { TextDetector } from './detectors/textDetector';
import { UrlDetector } from './detectors/urlDetector';
import { DEFAULT_DETECTION_RULES } from './url/rules';
import type { DetectionRules } from './url/rules';

/** Builds the engine with all built-in detectors. Register new detectors here. */
export function createDefaultEngine(): DetectionEngine {
  return new DetectionEngine().register(new UrlDetector()).register(new TextDetector());
}

const engine = createDefaultEngine();

export function scanUrl(url: string, rules: DetectionRules = DEFAULT_DETECTION_RULES): ScanResult {
  return engine.scan({ kind: 'url', url, rules });
}

export function scanText(text: string, rules: DetectionRules = DEFAULT_DETECTION_RULES): ScanResult {
  return engine.scan({ kind: 'text', text, rules });
}

/** Scans a page's address and visible text together. */
export function scanPage(url: string, text: string, rules: DetectionRules = DEFAULT_DETECTION_RULES): ScanResult {
  return engine.scan({ kind: 'page', url, text, rules });
}

export { DetectionEngine } from './core/detectionEngine';
export { combineSignals, levelFor } from './scoring/riskScorer';
export type { Detector, ScanInput, ScanKind } from './core/detector';
export type { DetectorTiming, ScanResult } from './core/detectionEngine';
export type { RiskLevel, Signal, Verdict } from './types';