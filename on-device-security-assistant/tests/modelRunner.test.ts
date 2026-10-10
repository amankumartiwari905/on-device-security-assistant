import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  analyzePhishingText,
  describeModelFailure,
  type PhishingModelPrediction,
} from '../src/engine/ml/modelRunner';

describe('modelRunner', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('formats failure descriptions with helpful context', () => {
    const errorMsg = describeModelFailure(new Error('WASM compilation failed'));
    expect(errorMsg).toContain('On-device phishing model unavailable: WASM compilation failed.');
    expect(errorMsg).toContain('Local detection rules remain active.');

    const stringError = describeModelFailure('Network error');
    expect(stringError).toContain('Network error');
  });

  it('falls back to teammate FastAPI server if onnx inference fails', async () => {
    const fastApiResponse: PhishingModelPrediction = {
      prediction: 'PHISHING',
      probability: 0.945,
      risk: 'HIGH',
    };

    const fetchMock = vi.fn(async (url: RequestInfo | URL) => {
      if (String(url).includes('8000/api/detect')) {
        return new Response(JSON.stringify(fastApiResponse), { status: 200 });
      }
      throw new Error(`Unexpected request: ${String(url)}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    // In a test environment without Chrome runtime/wasm assets, analyzePhishingText will attempt
    // ONNX, fail, and smoothly fallback to the FastAPI endpoint!
    const result = await analyzePhishingText('Your account is locked. Verify OTP immediately.');

    expect(result.prediction).toBe('PHISHING');
    expect(result.probability).toBe(0.945);
    expect(result.risk).toBe('HIGH');
    expect(fetchMock).toHaveBeenCalled();
  });

  it('throws descriptive error if both ONNX and FastAPI fail', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('FastAPI offline')));

    await expect(analyzePhishingText('Any sample text')).rejects.toThrow();
  });
});

