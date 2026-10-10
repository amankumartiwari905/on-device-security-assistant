import * as ort from 'onnxruntime-web/wasm';
import wasmAsset from 'onnxruntime-web/ort-wasm-simd-threaded.wasm?url';

const MODEL_PATH = 'models/phishing-text.onnx';
const FASTAPI_DETECT_URL = 'http://127.0.0.1:8000/api/detect';

export interface PhishingModelPrediction {
  prediction: 'LEGITIMATE' | 'SUSPICIOUS' | 'PHISHING';
  probability: number;
  risk: 'LOW' | 'SUSPICIOUS' | 'HIGH';
}

export function describeModelFailure(error: unknown): string {
  const reason = error instanceof Error ? error.message : String(error);
  const detail = reason.trim().slice(0, 240) || 'Unknown runtime error';
  return `On-device phishing model unavailable: ${detail}. Local detection rules remain active.`;
}

function resolveAssetUrl(path: string): string {
  if (typeof chrome !== 'undefined' && chrome.runtime?.getURL) {
    return chrome.runtime.getURL(path);
  }
  return path;
}

let sessionPromise: Promise<ort.InferenceSession> | null = null;

function getSession(): Promise<ort.InferenceSession> {
  if (!sessionPromise) {
    ort.env.wasm.numThreads = 1;
    ort.env.wasm.wasmPaths = {
      wasm: resolveAssetUrl(wasmAsset.replace(/^\//, '')),
    };
    sessionPromise = ort.InferenceSession.create(resolveAssetUrl(MODEL_PATH), {
      executionProviders: ['wasm'],
    })
      .catch((error: unknown) => {
        sessionPromise = null;
        throw error;
      });
  }
  return sessionPromise;
}

/** Runs the bundled TF-IDF + calibrated SVM model without sending text off-device. */
export async function predictPhishingProbability(text: string): Promise<number> {
  const session = await getSession();
  const inputName = session.inputNames[0];
  if (!inputName) throw new Error('The on-device phishing model has no input.');

  const output = await session.run({
    [inputName]: new ort.Tensor('string', [text], [1, 1]),
  });
  const probabilities = output.probabilities;
  if (
    !(probabilities instanceof ort.Tensor) ||
    probabilities.type !== 'float32' ||
    probabilities.data.length < 2
  ) {
    throw new Error('The on-device phishing model returned invalid probabilities.');
  }

  const probability = probabilities.data[1];
  if (typeof probability !== 'number' || !Number.isFinite(probability) || probability < 0 || probability > 1) {
    throw new Error('The on-device phishing model returned an invalid probability.');
  }
  return probability;
}

async function predictWithFastApi(text: string): Promise<PhishingModelPrediction> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 3500);
  try {
    const response = await fetch(FASTAPI_DETECT_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text }),
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`FastAPI returned HTTP ${response.status}.`);
    const data = (await response.json()) as Partial<PhishingModelPrediction>;
    if (typeof data.probability === 'number' && typeof data.prediction === 'string' && typeof data.risk === 'string') {
      return {
        prediction: data.prediction as PhishingModelPrediction['prediction'],
        probability: data.probability,
        risk: data.risk as PhishingModelPrediction['risk'],
      };
    }
    throw new Error('FastAPI returned an unexpected response format.');
  } finally {
    clearTimeout(timeout);
  }
}

export async function analyzePhishingText(text: string): Promise<PhishingModelPrediction> {
  try {
    const probability = await predictPhishingProbability(text);
    return probability < 0.3
      ? { prediction: 'LEGITIMATE', probability, risk: 'LOW' }
      : probability < 0.7
        ? { prediction: 'SUSPICIOUS', probability, risk: 'SUSPICIOUS' }
        : { prediction: 'PHISHING', probability, risk: 'HIGH' };
  } catch (onnxError) {
    // If on-device inference encounters an error, try the teammate's local FastAPI backend if running
    try {
      return await predictWithFastApi(text);
    } catch {
      throw onnxError;
    }
  }
}

