"""
features/encoder.py
=====================
One-Hot Encodes the categorical 'protocol' column.
Fully decoupled for lightweight API inference.
"""

import logging
import pickle
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
from sklearn.preprocessing import OneHotEncoder

logger = logging.getLogger("encoder")

# ==========================================
# DECOUPLED CONFIGURATION (API-SAFE)
# We define these locally so we don't need the heavy research config.py
# ==========================================
PROTOCOL_CATEGORIES = ["TCP", "UDP", "ICMP", "OTHER"]

FEATURE_COLUMNS = [
    "flow_duration",
    "src_pkts",
    "dst_pkts",
    "src_bytes",
    "dst_bytes",
    "pkt_len_mean",
    "pkt_len_std",
    "iat_mean",
    "iat_std",
    "src_port",
    "protocol"
]
# ==========================================


class ProtocolEncoder:
    """
    Fits and applies One-Hot Encoding to the 'protocol' column.
    """

    def __init__(self):
        self.encoder: Optional[OneHotEncoder] = None
        self.is_fitted: bool = False
        self.ohe_cols: list[str] = []

    def fit(self, df: pd.DataFrame) -> "ProtocolEncoder":
        if "protocol" not in df.columns:
            raise ValueError("'protocol' column not found in DataFrame.")

        self.encoder = OneHotEncoder(
            categories=[PROTOCOL_CATEGORIES],
            handle_unknown="infrequent_if_exist",
            sparse_output=False,
        )

        self.encoder.fit(df[["protocol"]])
        self.ohe_cols = [f"protocol_{cat}" for cat in PROTOCOL_CATEGORIES]
        self.is_fitted = True

        logger.info(f"Protocol encoder fitted. Categories: {PROTOCOL_CATEGORIES}")
        return self

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        if not self.is_fitted:
            raise RuntimeError("Encoder must be fitted before transform.")

        if "protocol" not in df.columns:
            raise ValueError("'protocol' column not found in DataFrame.")

        df = df.copy()

        # Encode protocol
        encoded = self.encoder.transform(df[["protocol"]])
        ohe_df = pd.DataFrame(encoded, columns=self.ohe_cols, index=df.index)

        # Drop original protocol column, add OHE columns
        df = df.drop(columns=["protocol"])
        df = pd.concat([df, ohe_df], axis=1)

        return df

    def fit_transform(self, df: pd.DataFrame) -> pd.DataFrame:
        return self.fit(df).transform(df)

    def get_feature_names_out(self) -> list[str]:
        features = []
        for col in FEATURE_COLUMNS:
            if col == "protocol":
                features.extend(self.ohe_cols)
            else:
                features.append(col)
        return features

    def save(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump(self, f)
        return path

    @classmethod
    def load(cls, path: Path) -> "ProtocolEncoder":
        if not path.exists():
            raise FileNotFoundError(f"Encoder not found at: {path}")

        with open(path, "rb") as f:
            encoder = pickle.load(f)
        return encoder

def encode_features(
    df: pd.DataFrame,
    encoder: Optional[ProtocolEncoder] = None,
    fit: bool = True,
) -> tuple[pd.DataFrame, ProtocolEncoder]:
    if encoder is None:
        encoder = ProtocolEncoder()

    if fit:
        encoded_df = encoder.fit_transform(df)
    else:
        encoded_df = encoder.transform(df)

    return encoded_df, encoder