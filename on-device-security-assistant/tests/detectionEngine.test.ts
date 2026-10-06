import { describe, expect, it, vi } from 'vitest';
import { DetectionEngine } from '../src/engine/core/detectionEngine';
import type { Detector } from '../src/engine/core/detector';
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

  it('runs only detectors that handle the input kind', () => {
    const engine = new DetectionEngine([stub('urlOnly', ['url'])]);
    expect(engine.scan({ kind: 'text', text: 'hello' }).signals).toHaveLength(0);
    expect(engine.scan({ kind: 'url', url: 'https://example.com' }).signals).toHaveLength(1);
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
    spy.mockRestore();
  });

  it('reports total and per-detector timing', () => {
    const result = new DetectionEngine([stub('a', ['url'])]).scan({ kind: 'url', url: 'https://example.com' });
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
    expect(result.timings).toHaveLength(1);
    expect(result.timings[0].signals).toBe(1);
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