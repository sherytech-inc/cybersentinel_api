import os
import joblib
import numpy as np

ARTIFACT_DIR = os.path.join(os.path.dirname(__file__), "..", "artifacts")

class RandomForestService:
    def __init__(self):
        self.model = joblib.load(os.path.join(ARTIFACT_DIR, "model1", "random_forest_best.pkl"))
        self.labels = {0: "Normal", 1: "Suspicious", 2: "Malicious"}

    def predict(self, processed_features: np.ndarray) -> dict:
        pred_code = int(self.model.predict(processed_features)[0])
        probabilities = self.model.predict_proba(processed_features)[0]
        
        return {
            "prediction_code": pred_code,
            "classification": self.labels[pred_code],
            "confidence_scores": {
                "Normal": float(probabilities[0]),
                "Suspicious": float(probabilities[1]),
                "Malicious": float(probabilities[2])
            }
        }