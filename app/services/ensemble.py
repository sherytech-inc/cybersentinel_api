from .model_rf import RandomForestService
from .model_if import IsolationForestService
from .preprocessor import DataPreprocessor  # <-- Brought the preprocessor import back!

class CyberSentinelEnsemble:
    def __init__(self):
        self.preprocessor = DataPreprocessor()  # <-- Initialized it!
        self.model_rf = RandomForestService()
        self.model_if = IsolationForestService()

    def evaluate_packet(self, packet_data: dict) -> dict:
        # A. Route through Model 1 (Random Forest - Known Attacks)
        # Preprocess the dictionary into scaled numerical features first
        scaled_features_m1 = self.preprocessor.process(packet_data)
        rf_result = self.model_rf.predict(scaled_features_m1)

        # B. Route through Model 2 (Isolation Forest - Unknown Anomalies)
        # Model 2 handles its own preprocessing internally, so it takes the raw dict
        if_result = self.model_if.predict(packet_data)

       # C. Ensemble Aggregation Logic
        return {
            "status": "processed",
            "api_version": "2.0.0-rf-and-if",
            
            # Unpack Model 1 perfectly to satisfy FastAPI's schema
            **rf_result,   
            
            # Add Model 2 safely, converting the numpy float to a standard Python float
            "behavior_analysis": {
                "m2_threat_score": float(if_result["m2_threat_score"]),
                "m2_severity": if_result["m2_severity"]
            }
        }