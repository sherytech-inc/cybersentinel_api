import pickle
import pandas as pd
from pathlib import Path
import sys

# Import the modules and classes from their new home
from .model2_tools import encoder
from .model2_tools import scaler
from .model2_tools.encoder import ProtocolEncoder
from .model2_tools.scaler import FeatureScaler

# ==========================================
# THE PICKLE PATH INTERCEPTOR
# Trick pickle into thinking the 'features' folder still exists
# by pointing it to our new model2_tools modules.
# ==========================================
sys.modules['features'] = sys.modules[__name__]  # Create a dummy 'features' parent
sys.modules['features.encoder'] = encoder
sys.modules['features.scaler'] = scaler
# ==========================================


class IsolationForestService:
    def __init__(self):
        # Point specifically to the isolated model2 artifacts folder
        base_path = Path(__file__).resolve().parent.parent / "artifacts" / "model2"
        
        self.encoder = ProtocolEncoder.load(base_path / "onehot_encoder.pkl")
        self.scaler = FeatureScaler.load(base_path / "robust_scaler.pkl")
        
        with open(base_path / "isolation_forest_model.pkl", "rb") as f:
            self.model = pickle.load(f)

    def predict(self, raw_packet_data: dict) -> dict:
        """Processes raw data through Model 2's isolated pipeline and returns severity."""
        raw_df = pd.DataFrame([raw_packet_data])
        
        encoded_data = self.encoder.transform(raw_df)
        scaled_data = self.scaler.transform(encoded_data)
        
        raw_score = self.model.score_samples(scaled_data)[0]
        normalized_score = max(0.0, min(100.0, (0.5 - raw_score) * 100))
        threat_score = round(normalized_score, 2)
        
        if threat_score < 40: severity = "Normal"
        elif threat_score < 60: severity = "Unusual"
        elif threat_score < 80: severity = "Suspicious"
        else: severity = "Highly Anomalous"
            
        return {
            "m2_threat_score": threat_score,
            "m2_severity": severity
        }