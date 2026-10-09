import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import * as ort from 'onnxruntime-web';

const modelPath = resolve('public/models/phishing-text.onnx');
const session = await ort.InferenceSession.create(modelPath);
const texts = [
  'Hi, are we still meeting tomorrow?',
  'Verify your account immediately to avoid suspension.',
];
const outputs = await session.run({
  [session.inputNames[0]]: new ort.Tensor('string', texts, [texts.length, 1]),
});
const probabilities = outputs.probabilities;

assert.ok(probabilities instanceof ort.Tensor, 'model must return probabilities');
assert.equal(probabilities.type, 'float32');
assert.equal(probabilities.data.length, texts.length * 2);

const benignProbability = probabilities.data[1];
const phishingProbability = probabilities.data[3];
assert.ok(benignProbability < 0.3, `expected benign sample below 0.3, got ${benignProbability}`);
assert.ok(phishingProbability >= 0.7, `expected phishing sample at least 0.7, got ${phishingProbability}`);

console.log(`ONNX inference passed: benign=${benignProbability.toFixed(4)}, phishing=${phishingProbability.toFixed(4)}`);
