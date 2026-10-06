import type { Signal, Verdict } from '../types';
import { combineSignals } from '../scoring/riskScorer';
import type { Detector, ScanInput } from './detector';

export interface DetectorTiming {
  id: string;
  durationMs: number;
  signals: number;
  failed: boolean;
}

export interface ScanResult extends Verdict {
  /** Total on-device analysis time. */
  durationMs: number;
  /** Per-detector breakdown, useful for diagnostics and the demo. */
  timings: DetectorTiming[];
}

const now = (): number => (typeof performance !== 'undefined' ? performance.now() : Date.now());
const round2 = (n: number): number => Math.round(n * 100) / 100;

export class DetectionEngine {
  private readonly detectors: Detector[] = [];

  constructor(detectors: Detector[] = []) {
    detectors.forEach((d) => this.register(d));
  }

  /** Adds a detector. Chainable. Ids must be unique. */
  register(detector: Detector): this {
    if (this.detectors.some((d) => d.id === detector.id)) {
      throw new Error(`Detector "${detector.id}" is already registered`);
    }
    this.detectors.push(detector);
    return this;
  }

  /** Ids of registered detectors, in execution order. */
  list(): string[] {
    return this.detectors.map((d) => d.id);
  }

  scan(input: ScanInput): ScanResult {
    const started = now();
    const signals: Signal[] = [];
    const timings: DetectorTiming[] = [];

    for (const detector of this.detectors) {
      if (!detector.handles.includes(input.kind)) continue;

      const t0 = now();
      let produced: Signal[] = [];
      let failed = false;
      try {
        produced = detector.analyze(input);
      } catch (err) {
        // One broken detector must never take the whole pipeline down.
        failed = true;
        console.error(`[AI Guard] detector "${detector.id}" failed`, err);
      }

      signals.push(...produced);
      timings.push({
        id: detector.id,
        durationMs: round2(now() - t0),
        signals: produced.length,
        failed,
      });
    }

    return { ...combineSignals(signals), durationMs: round2(now() - started), timings };
  }
}