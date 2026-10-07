import { afterEach, describe, expect, it, vi } from 'vitest';
import { scanText } from '../src/engine';
import { DEFAULT_DETECTION_RULES } from '../src/engine/url/rules';
import { routeMessageAnalysis } from '../src/background/threatRouter';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const explanation = {
  risk_level: 'HIGH_RISK',
  summary: 'The message pressures you to share a one-time code.',
  reasons: ['It threatens account access unless you act immediately.'],
  recommendation: 'Do not share the code; contact the service through its official app.',
};

function ollamaResponse(content: unknown): Response {
  return new Response(
    JSON.stringify({ message: { content: JSON.stringify(content) } }),
    { status: 200, headers: { 'Content-Type': 'application/json' } },
  );
}

describe('routeMessageAnalysis', () => {
  it('triggers Qwen at the local risk threshold and sends structured evidence', async () => {
    const fetchMock = vi.fn().mockResolvedValue(ollamaResponse(explanation));
    vi.stubGlobal('fetch', fetchMock);
    const message = 'Share your OTP immediately or your account will be blocked.';
    const localVerdict = scanText(message);

    const result = await routeMessageAnalysis(message, DEFAULT_DETECTION_RULES);

    expect(localVerdict.score).toBeGreaterThanOrEqual(30);
    expect(result.trigger).toBe('risk-threshold');
    expect(result.ollama.status).toBe('analyzed');
    expect(result.explanation).toEqual(explanation);
    expect(result.verdict).toMatchObject({
      score: localVerdict.score,
      level: localVerdict.level,
      reasons: localVerdict.reasons,
      signals: localVerdict.signals,
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toBe('http://localhost:11434/api/chat');
    expect(fetchMock.mock.calls[0][1].method).toBe('POST');
    const requestBody = JSON.parse(fetchMock.mock.calls[0][1].body as string) as {
      messages: Array<{ role: string; content: string }>;
    };
    expect(requestBody.messages[0].content).toContain('untrusted evidence');
    expect(requestBody.messages[0].content).toContain('met the detector risk threshold');
    expect(requestBody.messages[1].content).toContain('"indicators"');
    expect(requestBody.messages[1].content).toContain(message);
  });

  it('does not call Qwen for a low-risk message unless the user requests an explanation', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const message = 'Hi, are we still meeting tomorrow?';

    const automatic = await routeMessageAnalysis(message, DEFAULT_DETECTION_RULES);

    expect(automatic.verdict.score).toBeLessThan(30);
    expect(automatic.trigger).toBe('not-triggered');
    expect(automatic.ollama.status).toBe('skipped');
    expect(automatic.explanation).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();

    fetchMock.mockResolvedValue(ollamaResponse({
      ...explanation,
      risk_level: 'SAFE',
      summary: 'The local scan found no elevated-risk indicators.',
      reasons: [],
    }));
    const requested = await routeMessageAnalysis(message, DEFAULT_DETECTION_RULES, 'explain');

    expect(requested.trigger).toBe('user-request');
    expect(requested.ollama.status).toBe('analyzed');
    expect(requested.explanation?.risk_level).toBe('SAFE');
    expect(requested.verdict.score).toBe(automatic.verdict.score);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const userPromptBody = JSON.parse(fetchMock.mock.calls[0][1].body as string) as {
      messages: Array<{ role: string; content: string }>;
    };
    expect(userPromptBody.messages[0].content).toContain('user who asked why');
  });

  it('keeps the local result and explicitly reports when Ollama is unavailable', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('connection refused')));
    vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    const message = 'Your account will be blocked unless you verify your OTP.';

    const result = await routeMessageAnalysis(message, DEFAULT_DETECTION_RULES);

    const localVerdict = scanText(message);
    expect(result.verdict).toMatchObject({
      score: localVerdict.score,
      level: localVerdict.level,
      reasons: localVerdict.reasons,
      signals: localVerdict.signals,
    });
    expect(result.trigger).toBe('risk-threshold');
    expect(result.explanation).toBeNull();
    expect(result.ollama).toMatchObject({ status: 'unavailable' });
    expect(result.ollama.message).toContain('local scan only');
  });

  it('rejects invalid explanation shapes and reports the Ollama failure', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(ollamaResponse({ risk_level: 'MALICIOUS', summary: '' })));
    vi.spyOn(console, 'warn').mockImplementation(() => undefined);

    const result = await routeMessageAnalysis(
      'Your account will be blocked unless you verify your OTP.',
      DEFAULT_DETECTION_RULES,
    );

    expect(result.ollama.status).toBe('unavailable');
    expect(result.ollama.message).toContain('unexpected format');
    expect(result.explanation).toBeNull();
  });

  it('rejects empty or oversized messages before contacting Ollama', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    await expect(routeMessageAnalysis('  ', DEFAULT_DETECTION_RULES)).rejects.toThrow('Enter a message');
    await expect(routeMessageAnalysis('x'.repeat(20_001), DEFAULT_DETECTION_RULES)).rejects.toThrow('20,000');
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
