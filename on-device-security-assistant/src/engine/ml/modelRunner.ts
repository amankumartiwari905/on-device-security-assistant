/**
 * PHASE 2 hook: on-device ML via ONNX Runtime Web.
 *   npm install onnxruntime-web
 * Run inference in an offscreen document (chrome.offscreen) or the popup, load
 * public/models/url-model.onnx, and feed it featuresToVector(extractUrlFeatures(url)).
 * Blend the model probability into combineSignals() as one more Signal.
 */
export interface MlScorer {
  /** Returns phishing probability 0-1 for a feature vector. */
  predict(features: number[]): Promise<number>;
}

export const noopScorer: MlScorer = {
  async predict() {
    return 0;
  },
};