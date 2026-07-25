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
        
        # 2. Enforce strict ordering of numeric columns matching training setup
        # Both models use identical training features in this specific sequence
        ordered_numeric_cols = [
            "flow_duration",
            "src_pkts",
            "dst_pkts",
            "src_bytes",
            "dst_bytes",
            "pkt_len_mean",
            "pkt_len_std",
            "iat_mean",
            "iat_std",
            "src_port"
        ]
        
        # 3. Handle categorical encoding (One-Hot Encoding matching training setup)
        encoded_protocols = {
            'protocol_TCP': 1.0 if str(raw_packet_dict['protocol']).upper() == 'TCP' else 0.0,
            'protocol_UDP': 1.0 if str(raw_packet_dict['protocol']).upper() == 'UDP' else 0.0,
            'protocol_ICMP': 1.0 if str(raw_packet_dict['protocol']).upper() == 'ICMP' else 0.0,
            'protocol_OTHER': 1.0 if str(raw_packet_dict['protocol']).upper() not in ['TCP', 'UDP', 'ICMP'] else 0.0
        }
        
        # Merge scaled numerical values and encoded protocols back in the EXACT same sequence
        df_numeric = df[ordered_numeric_cols].copy()
        for col, val in encoded_protocols.items():
            df_numeric[col] = val
            
        # 4. Use the robust scaler to transform features
        # Note: we use .values to avoid scikit-learn feature name mismatch errors
        scaled_data = self.scaler.transform(df_numeric.values)
        return scaled_data