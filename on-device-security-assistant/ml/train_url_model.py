"""
Phase 2: train a URL phishing model and export it to ONNX for onnxruntime-web.

1. Collect labelled URLs (phishing: PhishTank/OpenPhish, benign: Tranco top list).
2. Produce data/features.csv with the columns below + a `label` column (1 = phishing).
   Use the TypeScript extractor (extractUrlFeatures) so training and the extension agree.
3. python train_url_model.py  ->  ../public/models/url-model.onnx
"""
from pathlib import Path

import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

# MUST match FEATURE_ORDER in src/engine/url/urlFeatures.ts (same names, same order)
FEATURE_ORDER = [
    "length", "hostLength", "subdomains", "specialChars", "hyphens", "digitRatio",
    "hostEntropy", "pathDepth", "queryParams", "hasIp", "hasAt", "isHttps",
    "hasPunycode", "suspiciousTld", "isShortener", "keywordCount",
]

df = pd.read_csv("data/features.csv")
X = df[FEATURE_ORDER].astype("float32")
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
clf = GradientBoostingClassifier(n_estimators=200, max_depth=3, random_state=42)
clf.fit(X_train, y_train)
print(classification_report(y_test, clf.predict(X_test)))

onnx_model = convert_sklearn(
    clf,
    initial_types=[("input", FloatTensorType([None, len(FEATURE_ORDER)]))],
    options={id(clf): {"zipmap": False}},
)
out = Path("../public/models/url-model.onnx")
out.parent.mkdir(parents=True, exist_ok=True)
out.write_bytes(onnx_model.SerializeToString())
print(f"Saved {out}")