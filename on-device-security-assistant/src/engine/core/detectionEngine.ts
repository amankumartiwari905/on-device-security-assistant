import type { Signal, Verdict } from '../types';
import { combineSignals } from '../scoring/riskScorer';
import type { Detector, ScanInput, ScanKind } from './detector';

export type DetectorFailureReason = 'exception' | 'invalid-output';

export interface DetectorTiming {
  id: string;
  durationMs: number;
  signals: number;
  failed: boolean;
  failureReason: DetectorFailureReason | null;
}

export interface DetectorFailure {
  detectorId: string;
  reason: DetectorFailureReason;
}

export interface ScanResult extends Verdict {
  /** Total on-device analysis time. */
  durationMs: number;
  /** Per-detector breakdown, useful for diagnostics and the demo. */
  timings: DetectorTiming[];
  /** Failures are reported without discarding evidence from other detectors. */
  failures: DetectorFailure[];
}

interface RegisteredDetector {
  readonly id: string;
  readonly handles: readonly ScanKind[];
  readonly analyze: Detector['analyze'];
}

const VALID_KINDS = new Set<ScanKind>(['url', 'text', 'page']);
const MAX_DETECTOR_ID_LENGTH = 100;
// Bound malformed plug-in output so a detector cannot overwhelm the scan or UI.
const MAX_SIGNALS_PER_DETECTOR = 500;
const MAX_SIGNAL_ID_LENGTH = 128;
const MAX_SIGNAL_REASON_LENGTH = 1_000;
const MAX_SIGNAL_EVIDENCE_LENGTH = 1_000;

const now = (): number => (typeof performance !== 'undefined' ? performance.now() : Date.now());
const round2 = (n: number): number => Math.round(n * 100) / 100;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

function isDetectionRules(value: unknown): boolean {
  return isRecord(value) &&
    Array.isArray(value.brands) &&
    value.brands.every((brand) =>
      isRecord(brand) &&
      typeof brand.name === 'string' &&
      brand.name.trim().length > 0 &&
      isStringArray(brand.domains),
    ) &&
    isStringArray(value.suspiciousTlds) &&
    isStringArray(value.urlShorteners) &&
    isStringArray(value.suspiciousKeywords);
}

function assertValidScanInput(input: unknown): asserts input is ScanInput {
  if (!isRecord(input) || !VALID_KINDS.has(input.kind as ScanKind)) {
    throw new TypeError('Scan input must specify a supported kind: url, text, or page.');
  }

  const hasValidText = typeof input.text === 'string';
  const hasValidUrl = typeof input.url === 'string';
  if (
    (input.kind === 'url' && !hasValidUrl) ||
    (input.kind === 'text' && !hasValidText) ||
    (input.kind === 'page' && (!hasValidUrl || !hasValidText))
  ) {
    throw new TypeError(`Scan input for "${input.kind}" must include its required string fields.`);
  }

  if (input.rules !== undefined && !isDetectionRules(input.rules)) {
    throw new TypeError('Scan input rules do not match the detection rules schema.');
  }
}

function isSignal(value: unknown): value is Signal {
  if (!isRecord(value)) return false;
  return typeof value.id === 'string' &&
    value.id.trim().length > 0 &&
    value.id.length <= MAX_SIGNAL_ID_LENGTH &&
    typeof value.weight === 'number' &&
    Number.isFinite(value.weight) &&
    value.weight >= 0 &&
    value.weight <= 100 &&
    typeof value.reason === 'string' &&
    value.reason.trim().length > 0 &&
    value.reason.length <= MAX_SIGNAL_REASON_LENGTH &&
    (value.evidence === undefined ||
      (typeof value.evidence === 'string' && value.evidence.length <= MAX_SIGNAL_EVIDENCE_LENGTH));
}

function isSignalArray(value: unknown): value is Signal[] {
  return Array.isArray(value) &&
    value.length <= MAX_SIGNALS_PER_DETECTOR &&
    value.every(isSignal);
}

function validateDetector(detector: unknown): asserts detector is Detector {
  if (!isRecord(detector)) {
    throw new TypeError('A detector must be an object.');
  }
  if (
    typeof detector.id !== 'string' ||
    detector.id.trim().length === 0 ||
    detector.id.length > MAX_DETECTOR_ID_LENGTH ||
    !/^[a-z0-9][a-z0-9._-]*$/i.test(detector.id)
  ) {
    throw new TypeError('A detector id must be 1-100 characters and contain only letters, digits, ".", "_" or "-".');
  }
  if (
    !Array.isArray(detector.handles) ||
    detector.handles.length === 0 ||
    !detector.handles.every((kind) => typeof kind === 'string' && VALID_KINDS.has(kind as ScanKind)) ||
    new Set(detector.handles).size !== detector.handles.length
  ) {
    throw new TypeError(`Detector "${detector.id}" must declare unique supported input kinds.`);
  }
  if (typeof detector.analyze !== 'function') {
    throw new TypeError(`Detector "${detector.id}" must provide an analyze function.`);
  }
}

export class DetectionEngine {
  private readonly detectors: RegisteredDetector[] = [];

  constructor(detectors: Detector[] = []) {
    detectors.forEach((d) => this.register(d));
  }

  /** Adds a detector. Chainable. Ids must be unique. */
  register(detector: Detector): this {
    validateDetector(detector);
    if (this.detectors.some((d) => d.id === detector.id)) {
      throw new Error(`Detector "${detector.id}" is already registered`);
    }
    this.detectors.push({
      id: detector.id,
      handles: [...detector.handles],
      analyze: detector.analyze,
    });
    return this;
  }

  /** Ids of registered detectors, in execution order. */
  list(): string[] {
    return this.detectors.map((d) => d.id);
  }

  scan(input: ScanInput): ScanResult {
    assertValidScanInput(input);
    const started = now();
    const signals: Signal[] = [];
    const timings: DetectorTiming[] = [];
    const failures: DetectorFailure[] = [];

    for (const detector of this.detectors) {
      if (!detector.handles.includes(input.kind)) continue;

      const t0 = now();
      let produced: Signal[] = [];
      let failureReason: DetectorFailureReason | null = null;
      try {
        const output: unknown = detector.analyze(input);
        if (!isSignalArray(output)) {
          failureReason = 'invalid-output';
        } else {
          produced = output;
        }
      } catch (err) {
        // One broken detector must never take the whole pipeline down.
        failureReason = 'exception';
        console.error(`[AI Guard] detector "${detector.id}" failed`, err);
      }

      if (failureReason) failures.push({ detectorId: detector.id, reason: failureReason });
      signals.push(...produced);
      timings.push({
        id: detector.id,
        durationMs: round2(now() - t0),
        signals: produced.length,
        failed: failureReason !== null,
        failureReason,
      });
    }

    return {
      ...combineSignals(signals),
      durationMs: round2(now() - started),
      timings,
      failures,
    };
  }
}