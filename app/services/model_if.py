import sys
import types

# ==========================================
# NUMPY 2.X TO 1.X INTERCEPTOR
# Intercept pickle loading numpy 2.0 objects under numpy 1.x
# ==========================================
try:
    import numpy.core.multiarray as numpy_multiarray
    import numpy.core.numeric as numpy_numeric
    
    numpy_core = types.ModuleType('numpy._core')
    numpy_core.__path__ = [] # Mark as package
    
    sys.modules['numpy._core'] = numpy_core
    sys.modules['numpy._core.multiarray'] = numpy_multiarray
    sys.modules['numpy._core.numeric'] = numpy_numeric
except ImportError:
    pass

import pickle
import pandas as pd
from pathlib import Path

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
    TRAINED_NUMERIC_FEATURES = [
        "destination_port",
        "flow_duration",
        "total_fwd_packets",
        "total_backward_packets",
        "flow_bytes_per_second",
        "flow_packets_per_second",
        "packet_length_mean",
        "packet_length_std",
        "flow_iat_mean",
        "flow_iat_std",
    ]
    TRAINED_PROTOCOL_FEATURES = [
        "protocol_TCP", "protocol_UDP", "protocol_ICMP", "protocol_OTHER"
    ]
    def __init__(self):
        # Point specifically to the isolated model2 artifacts folder
        base_path = Path(__file__).resolve().parent.parent / "artifacts" / "model2"
        
        self.encoder = ProtocolEncoder.load(base_path / "onehot_encoder.pkl")
        self.scaler = FeatureScaler.load(base_path / "robust_scaler.pkl")
        
        with open(base_path / "isolation_forest_model.pkl", "rb") as f:
            self.model = pickle.load(f)

    def predict(self, raw_packet_data: dict) -> dict:
        """Processes raw data through Model 2's isolated pipeline and returns severity."""
        scaled_data = self._prepare_inference_frame(raw_packet_data)
        
        raw_score = float(self.model.score_samples(scaled_data)[0])
        offset_ = getattr(self.model, "offset_", -0.6568521255544745)
        is_anomaly = bool(raw_score < offset_)
        
        if not is_anomaly:
            normalized_score = max(0.0, (raw_score / offset_) * 50.0) if offset_ != 0 else 0.0
        else:
            denom = -1.0 - offset_
            severity_fraction = min(1.0, max(0.0, (raw_score - offset_) / denom)) if denom != 0 else 0.0
            normalized_score = 50.0 + severity_fraction * 50.0
            
        normalized_score = max(0.0, min(100.0, normalized_score))
        threat_score = round(normalized_score, 2)
        
        if threat_score < 40: severity = "Normal"
        elif threat_score < 60: severity = "Unusual"
        elif threat_score < 80: severity = "Suspicious"
        else: severity = "Highly Anomalous"
            
        return {
            "m2_threat_score": threat_score,
            "m2_severity": severity
        }

    def predict_raw(self, raw_packet_data: dict) -> dict:
        """
        Processes raw features, returns the scikit-learn raw decision score,
        prediction flag (is_anomaly), and normalized threat score.
        """
        scaled_data = self._prepare_inference_frame(raw_packet_data)
        
        # Raw anomaly score: lower values are more anomalous
        raw_score = float(self.model.score_samples(scaled_data)[0])
        
        # predict() returns 1 for inlier, -1 for outlier/anomaly
        is_anomaly = bool(self.model.predict(scaled_data)[0] == -1)
        
        # Piecewise calibrated normalization pivoted at model offset
        offset_ = getattr(self.model, "offset_", -0.6568521255544745)
        
        if not is_anomaly:
            normalized_score = max(0.0, (raw_score / offset_) * 50.0) if offset_ != 0 else 0.0
        else:
            denom = -1.0 - offset_
            severity_fraction = min(1.0, max(0.0, (raw_score - offset_) / denom)) if denom != 0 else 0.0
            normalized_score = 50.0 + severity_fraction * 50.0
            
        normalized_score = max(0.0, min(100.0, normalized_score))
        
        return {
            "anomaly_score": round(raw_score, 4),
            "is_anomaly": is_anomaly,
            "normalized_score": round(normalized_score, 2)
        }

    def _prepare_inference_frame(self, raw: dict) -> pd.DataFrame:
        """Adapt current flow features to the exact persisted training schema."""
        duration = float(raw["flow_duration"])
        src_pkts = float(raw["src_pkts"])
        dst_pkts = float(raw["dst_pkts"])
        total_bytes = float(raw["src_bytes"]) + float(raw["dst_bytes"])
        total_packets = src_pkts + dst_pkts
        safe_duration = duration if duration > 0 else 1e-6

        numeric = pd.DataFrame([{
            # The current compatibility schema calls this value src_port.
            "destination_port": float(raw["src_port"]),
            "flow_duration": duration,
            "total_fwd_packets": src_pkts,
            "total_backward_packets": dst_pkts,
            "flow_bytes_per_second": total_bytes / safe_duration,
            "flow_packets_per_second": total_packets / safe_duration,
            "packet_length_mean": float(raw["pkt_len_mean"]),
            "packet_length_std": float(raw["pkt_len_std"]),
            "flow_iat_mean": float(raw["iat_mean"]),
            "flow_iat_std": float(raw["iat_std"]),
        }], columns=self.TRAINED_NUMERIC_FEATURES)

        scaled_numeric = self.scaler.transform(numeric)
        protocol = str(raw["protocol"]).upper()
        protocol_values = {
            name: 1.0 if name == f"protocol_{protocol}" else 0.0
            for name in self.TRAINED_PROTOCOL_FEATURES
        }
        if protocol not in {"TCP", "UDP", "ICMP"}:
            protocol_values["protocol_OTHER"] = 1.0

        inference = scaled_numeric.copy()
        for name in self.TRAINED_PROTOCOL_FEATURES:
            inference[name] = protocol_values[name]
        return inference[self.TRAINED_NUMERIC_FEATURES + self.TRAINED_PROTOCOL_FEATURES]
