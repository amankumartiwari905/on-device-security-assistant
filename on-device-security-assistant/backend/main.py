from pathlib import Path

import joblib
from fastapi import FastAPI
from pydantic import BaseModel


# --------------------------------------------------
# Paths
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / "models"

VECTORIZER_PATH = MODEL_DIR / "phishing_tfidf.pkl"
MODEL_PATH = MODEL_DIR / "phishing_calibrated_svm.pkl"


# --------------------------------------------------
# Load ML artifacts
# --------------------------------------------------

vectorizer = joblib.load(VECTORIZER_PATH)
model = joblib.load(MODEL_PATH)


# --------------------------------------------------
# FastAPI app
# --------------------------------------------------

app = FastAPI(
    title="AI Guard Security API",
    version="1.0.0"
)


# --------------------------------------------------
# Request schema
# --------------------------------------------------

class DetectRequest(BaseModel):
    text: str


# --------------------------------------------------
# Health check
# --------------------------------------------------

@app.get("/")
def root():
    return {
        "status": "online",
        "service": "AI Guard Security API"
    }


# --------------------------------------------------
# Phishing detection
# --------------------------------------------------

@app.post("/api/detect")
def detect(request: DetectRequest):

    text = request.text.strip()

    if not text:
        return {
            "prediction": "UNKNOWN",
            "probability": 0.0,
            "risk": "UNKNOWN"
        }

    # Convert text into TF-IDF features
    X = vectorizer.transform([text])

    # Get calibrated phishing probability
    phishing_probability = float(
        model.predict_proba(X)[0][1]
    )

    # Risk classification
    if phishing_probability < 0.30:
        prediction = "LEGITIMATE"
        risk = "LOW"

    elif phishing_probability < 0.70:
        prediction = "SUSPICIOUS"
        risk = "SUSPICIOUS"

    else:
        prediction = "PHISHING"
        risk = "HIGH"

    return {
        "prediction": prediction,
        "probability": round(phishing_probability, 4),
        "risk": risk
    }