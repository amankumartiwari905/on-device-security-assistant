import type { Signal } from '../types';
import type { DetectionRules } from '../url/rules';

/** Everything the engine can be asked to analyze. */
export type ScanInput =
  | { kind: 'url'; url: string; rules?: DetectionRules }
  | { kind: 'text'; text: string; rules?: DetectionRules }
  | { kind: 'page'; url: string; text: string; rules?: DetectionRules };

export type ScanKind = ScanInput['kind'];

/**
 * A detector turns an input into evidence (signals). It never decides the final
 * verdict; the risk scorer combines signals from all detectors.
 */
export interface Detector {
  /** Unique, stable id. Used for registration and diagnostics. */
  readonly id: string;
  /** Input kinds this detector understands. The engine skips it for other kinds. */
  readonly handles: readonly ScanKind[];
  analyze(input: ScanInput): Signal[];
}