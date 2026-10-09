import * as ort from 'onnxruntime-web/wasm';
import wasmAsset from 'onnxruntime-web/ort-wasm-simd-threaded.wasm?url';

const MODEL_PATH = 'models/phishing-text.onnx';

export interface PhishingModelPrediction {
  prediction: 'LEGITIMATE' | 'SUSPICIOUS' | 'PHISHING';
  probability: number;
  risk: 'LOW' | 'SUSPICIOUS' | 'HIGH';
}

let sessionPromise: Promise<ort.InferenceSession> | null = null;

function getSession(): Promise<ort.InferenceSession> {
  if (!sessionPromise) {
    ort.env.wasm.numThreads = 1;
    ort.env.wasm.wasmPaths = {
      wasm: chrome.runtime.getURL(wasmAsset.replace(/^\//, '')),
    };
    sessionPromise = ort.InferenceSession.create(chrome.runtime.getURL(MODEL_PATH), {
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

export async function analyzePhishingText(text: string): Promise<PhishingModelPrediction> {
  const probability = await predictPhishingProbability(text);
  return probability < 0.3
    ? { prediction: 'LEGITIMATE', probability, risk: 'LOW' }
    : probability < 0.7
      ? { prediction: 'SUSPICIOUS', probability, risk: 'SUSPICIOUS' }
      : { prediction: 'PHISHING', probability, risk: 'HIGH' };
}
