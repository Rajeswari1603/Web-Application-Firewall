import joblib
import re

# Load the pre-trained ML model and vectorizer
model = joblib.load("ml_model.joblib")
vectorizer = joblib.load("vectorizer.joblib")

# List of known safe domains or keywords
SAFE_DOMAINS = ["youtube.com", "youtu.be", "google.com", "openai.com", "wikipedia.org","view.edu"]

# === Basic Preprocessing for ML input ===
def preprocess_payload(payload):
    # Remove non-alphanumeric characters, convert to lowercase
    payload = re.sub(r'\W+', ' ', payload.lower())
    return payload.strip()

# === Predict if payload is malicious (1) or safe (0) ===
def predict_payload(payload):
    # ✅ Bypass ML check for known safe domains
    for domain in SAFE_DOMAINS:
        if domain in payload.lower():
            return 0  # Treat as safe

    payload = preprocess_payload(payload)
    X = vectorizer.transform([payload])
    prediction = model.predict(X)
    return prediction[0]
