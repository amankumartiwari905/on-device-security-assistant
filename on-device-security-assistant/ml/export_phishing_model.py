"""Export the committed TF-IDF vectorizer and calibrated SVM for browser inference."""
from pathlib import Path
import warnings

import joblib
import numpy as np
import onnxruntime as ort
from sklearn.pipeline import Pipeline
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import StringTensorType

ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = ROOT / "backend" / "models"
OUTPUT_PATH = ROOT / "public" / "models" / "phishing-text.onnx"
MAX_PROBABILITY_ERROR = 0.01
VALIDATION_TEXTS = [
    "Hi, are we still meeting tomorrow?",
    "Your account is locked. Verify your password immediately.",
    "You won a prize; provide your OTP to claim it.",
    "Please review the attached project notes before our meeting.",
]


def main() -> None:
    vectorizer = joblib.load(MODEL_DIR / "phishing_tfidf.pkl")
    classifier = joblib.load(MODEL_DIR / "phishing_calibrated_svm.pkl")
    if list(classifier.classes_) != [0, 1]:
        raise ValueError("The phishing model must use class 1 for the phishing probability.")
    if vectorizer.analyzer != "word":
        raise ValueError("The browser exporter expects the committed word-level TF-IDF vectorizer.")

    pipeline = Pipeline([("tfidf", vectorizer), ("classifier", classifier)])
    model = convert_sklearn(
        pipeline,
        initial_types=[("text", StringTensorType([None, 1]))],
        options={id(classifier): {"zipmap": False}},
    )

    session = ort.InferenceSession(
        model.SerializeToString(),
        providers=["CPUExecutionProvider"],
    )
    input_name = session.get_inputs()[0].name
    output_names = [output.name for output in session.get_outputs()]
    if "probabilities" not in output_names:
        raise ValueError(f"Unexpected ONNX model outputs: {output_names}")

    text_batch = np.asarray(VALIDATION_TEXTS, dtype=object).reshape(-1, 1)
    onnx_outputs = session.run(None, {input_name: text_batch})
    probabilities = onnx_outputs[output_names.index("probabilities")][:, 1]
    expected = classifier.predict_proba(vectorizer.transform(VALIDATION_TEXTS))[:, 1]
    max_error = float(np.max(np.abs(expected - probabilities)))
    if max_error > MAX_PROBABILITY_ERROR:
        raise ValueError(
            f"ONNX conversion changed phishing probabilities by {max_error:.4f}; "
            f"maximum allowed is {MAX_PROBABILITY_ERROR:.2f}."
        )

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_bytes(model.SerializeToString())
    print(f"Exported {OUTPUT_PATH} ({OUTPUT_PATH.stat().st_size:,} bytes)")
    print(f"Validated {len(VALIDATION_TEXTS)} samples; maximum probability error: {max_error:.4f}")


if __name__ == "__main__":
    main()
