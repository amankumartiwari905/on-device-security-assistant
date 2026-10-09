import { describe, expect, it, vi } from 'vitest';
import { DetectionEngine } from '../src/engine/core/detectionEngine';
import type { Detector, ScanInput, ScanKind } from '../src/engine/core/detector';
import { createDefaultEngine, scanPage, scanText, scanUrl } from '../src/engine';

const stub = (id: string, handles: Detector['handles'], weight = 40): Detector => ({
  id,
  handles,
  analyze: () => [{ id: `${id}-signal`, weight, reason: `${id} fired` }],
});

describe('DetectionEngine', () => {
  it('rejects duplicate detector ids', () => {
    const engine = new DetectionEngine([stub('a', ['url'])]);
    expect(() => engine.register(stub('a', ['text']))).toThrow(/already registered/);
  });

  it('rejects invalid detector metadata before registration', () => {
    const engine = new DetectionEngine();
    const noHandles = { id: 'no-handles', handles: [], analyze: () => [] };
    const duplicateKinds = { id: 'duplicate-kinds', handles: ['url', 'url'], analyze: () => [] };
    const invalidId = { id: 'bad id', handles: ['url'], analyze: () => [] };
    const noAnalyzer = { id: 'no-analyzer', handles: ['url'] };

    for (const detector of [noHandles, duplicateKinds, invalidId, noAnalyzer]) {
      expect(() => engine.register(detector as unknown as Detector)).toThrow(TypeError);
    }
    expect(engine.list()).toEqual([]);
  });

  it('runs only detectors that handle the input kind', () => {
    const engine = new DetectionEngine([stub('urlOnly', ['url'])]);
    expect(engine.scan({ kind: 'text', text: 'hello' }).signals).toHaveLength(0);
    expect(engine.scan({ kind: 'url', url: 'https://example.com' }).signals).toHaveLength(1);
  });

  it('rejects malformed scan input and detection rules', () => {
    const engine = new DetectionEngine();

    expect(() => engine.scan({ kind: 'url' } as unknown as ScanInput)).toThrow(/required string fields/);
    expect(() => engine.scan({ kind: 'text', text: 'hello', rules: {} } as unknown as ScanInput)).toThrow(/rules schema/);
    expect(() => engine.scan({ kind: 'unknown' } as unknown as ScanInput)).toThrow(/supported kind/);
  });

  it('isolates a crashing detector and still runs the others', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const bad: Detector = {
      id: 'bad',
      handles: ['url'],
      analyze: () => {
        throw new Error('boom');
      },
    };
    const result = new DetectionEngine([bad, stub('good', ['url'])]).scan({ kind: 'url', url: 'https://example.com' });

    expect(result.signals.map((s) => s.id)).toEqual(['good-signal']);
    expect(result.timings.find((t) => t.id === 'bad')?.failed).toBe(true);
    expect(result.timings.find((t) => t.id === 'bad')?.failureReason).toBe('exception');
    expect(result.failures).toEqual([{ detectorId: 'bad', reason: 'exception' }]);
    spy.mockRestore();
  });

  it('rejects malformed signals without discarding valid evidence from other detectors', () => {
    const invalid: Detector = {
      id: 'invalid-output',
      handles: ['url'],
      analyze: () => [{ id: 'bad-signal', weight: Number.NaN, reason: 'invalid weight' }],
    };
    const result = new DetectionEngine([invalid, stub('good', ['url'])])
      .scan({ kind: 'url', url: 'https://example.com' });

    expect(result.signals.map((signal) => signal.id)).toEqual(['good-signal']);
    expect(result.timings.find((timing) => timing.id === 'invalid-output')).toMatchObject({
      failed: true,
      failureReason: 'invalid-output',
      signals: 0,
    });
    expect(result.failures).toEqual([{ detectorId: 'invalid-output', reason: 'invalid-output' }]);
  });

  it('snapshots detector metadata when registering', () => {
    const handles: ScanKind[] = ['url'];
    const engine = new DetectionEngine([stub('snapshot', handles)]);
    handles.push('text');

    expect(engine.scan({ kind: 'text', text: 'hello' }).signals).toHaveLength(0);
    expect(engine.scan({ kind: 'url', url: 'https://example.com' }).signals).toHaveLength(1);
  });

  it('reports total and per-detector timing', () => {
    const result = new DetectionEngine([stub('a', ['url'])]).scan({ kind: 'url', url: 'https://example.com' });
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
    expect(result.timings).toHaveLength(1);
    expect(result.timings[0].signals).toBe(1);
    expect(result.failures).toEqual([]);
  });

  it('lists detectors in registration order', () => {
    expect(createDefaultEngine().list()).toEqual(['url', 'text']);
  });
});

describe('default engine helpers', () => {
  it('keeps scanUrl and scanText behaviour', () => {
    expect(scanUrl('https://www.google.com').level).toBe('safe');
    expect(scanText('Hey, are we still meeting for lunch tomorrow?').level).toBe('safe');
  });

  it('scanPage combines URL and text evidence', () => {
    const url = 'http://192.168.1.1/login';
    const text = 'Verify your PIN immediately or your account will be blocked';
    const result = scanPage(url, text);
    expect(result.signals.some((s) => s.id === 'ip-host')).toBe(true);
    expect(result.signals.some((s) => s.id === 'account-threat')).toBe(true);
    expect(result.score).toBeGreaterThan(Math.max(scanUrl(url).score, scanText(text).score));
  });
});