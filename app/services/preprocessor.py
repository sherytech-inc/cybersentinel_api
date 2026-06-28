import os
import joblib
import pandas as pd

# Find where artifacts live dynamically
ARTIFACT_DIR = os.path.join(os.path.dirname(__file__), "..", "artifacts")

class DataPreprocessor:
    def __init__(self):
        # Load the exact tools fitted during your Colab training run
        self.encoder = joblib.load(os.path.join(ARTIFACT_DIR, "model1", "encoder.pkl"))
        self.scaler = joblib.load(os.path.join(ARTIFACT_DIR, "model1", "best_scaler.pkl"))
        
    def process(self, raw_packet_dict: dict) -> pd.DataFrame:
        # 1. Convert single incoming packet into a single-row DataFrame
        df = pd.DataFrame([raw_packet_dict])
        
        # 2. Extract numeric columns for scaling
        numeric_cols = [c for c in df.columns if c != 'protocol']
        
        # 3. Handle categorical encoding (One-Hot Encoding matching training setup)
        # We manually map out the OHE array based on what your encoder built
        encoded_protocols = {
            'protocol_TCP': 1.0 if raw_packet_dict['protocol'].upper() == 'TCP' else 0.0,
            'protocol_UDP': 1.0 if raw_packet_dict['protocol'].upper() == 'UDP' else 0.0,
            'protocol_ICMP': 1.0 if raw_packet_dict['protocol'].upper() == 'ICMP' else 0.0,
            'protocol_OTHER': 1.0 if raw_packet_dict['protocol'].upper() not in ['TCP', 'UDP', 'ICMP'] else 0.0
        }
        
        # Merge scaled numerical values and encoded protocols back into one DataFrame row
        df_numeric = df[numeric_cols].copy()
        for col, val in encoded_protocols.items():
            df_numeric[col] = val
            
        # 4. Use the robust scaler to transform features
        scaled_data = self.scaler.transform(df_numeric)
        return scaled_data