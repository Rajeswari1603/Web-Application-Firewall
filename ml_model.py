import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import joblib

# Load dataset
data = pd.read_csv("payload_dataset.csv")

X = data["payload"]
y = data["label"]

# Convert text to numerical features
vectorizer = TfidfVectorizer()
X_vectorized = vectorizer.fit_transform(X)

# Train model
model = LogisticRegression()
model.fit(X_vectorized, y)

# Save model and vectorizer
joblib.dump(model, "ml_model.joblib")
joblib.dump(vectorizer, "vectorizer.joblib")

print("Model trained and saved.")
