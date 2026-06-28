"""
features/scaler.py
===================
Implements scaler comparison and selection for Model 2.

Strategy:
  Tests: No Scaling, StandardScaler, RobustScaler
  Preferred: RobustScaler (handles network traffic outliers well)

  RobustScaler is chosen because:
    - Network traffic contains extreme outliers (DDoS bursts, large file transfers)
    - StandardScaler distorts the entire feature space when outliers are present
    - RobustScaler uses median and IQR — robust to extreme values
    - Isolation Forest performance degrades when outlier-driven features dominate

  The scaler is fit ONLY on training data.
  The fitted scaler is reused for all inference.
"""

import json
import logging
import pickle
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
from sklearn.preprocessing import RobustScaler, StandardScaler

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

# DECOUPLED CONFIGURATION (API-SAFE)
PREFERRED_SCALER = "robust"

logger = logging.getLogger("scaler")


# ─────────────────────────────────────────────
# SCALER COMPARISON
# ─────────────────────────────────────────────

def compare_scalers(df: pd.DataFrame) -> dict:
    """
    Compare the effect of different scalers on the numeric features.

    Produces summary statistics (mean, std, min, max, skewness) for each
    scaler variant so the best can be selected.

    Args:
        df: Encoded training DataFrame (protocol already OHE).

    Returns:
        Dictionary with statistics for each scaler variant.
    """
    numeric_cols = [c for c in NUMERIC_FEATURES if c in df.columns]
    results = {}

    for scaler_name in SCALERS_TO_COMPARE:
        scaled_df = apply_scaler_by_name(df, numeric_cols, scaler_name)
        stats = _compute_stats(scaled_df[numeric_cols], scaler_name)
        results[scaler_name] = stats
        logger.info(
            f"Scaler '{scaler_name}' — "
            f"Mean abs: {stats['mean_abs']:.4f} | "
            f"Std mean: {stats['std_mean']:.4f} | "
            f"Max abs:  {stats['max_abs']:.4f}"
        )

    # Save comparison report
    _save_scaler_report(results)
    return results


def apply_scaler_by_name(
    df: pd.DataFrame,
    numeric_cols: list[str],
    scaler_name: str,
) -> pd.DataFrame:
    """
    Apply a named scaler to the numeric columns of a DataFrame.
    Used during comparison — does NOT save a fitted scaler.

    Args:
        df:           DataFrame to scale.
        numeric_cols: Numeric columns to scale.
        scaler_name:  One of 'none', 'standard', 'robust'.

    Returns:
        Scaled DataFrame copy.
    """
    df_copy = df.copy()

    if scaler_name == "none":
        return df_copy

    if scaler_name == "standard":
        scaler = StandardScaler()
    elif scaler_name == "robust":
        scaler = RobustScaler()
    else:
        raise ValueError(f"Unknown scaler: '{scaler_name}'. Choose from {SCALERS_TO_COMPARE}")

    df_copy[numeric_cols] = scaler.fit_transform(df_copy[numeric_cols])
    return df_copy


def _compute_stats(df: pd.DataFrame, name: str) -> dict:
    """Compute summary statistics for a scaled DataFrame."""
    return {
        "scaler": name,
        "mean_abs": float(df.abs().mean().mean()),
        "std_mean": float(df.std().mean()),
        "max_abs": float(df.abs().max().max()),
        "skew_mean": float(df.skew().mean()),
        "columns_checked": list(df.columns),
    }


def _save_scaler_report(results: dict) -> None:
    """Save scaler comparison results to outputs/reports/."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    path = REPORTS_DIR / "scaler_comparison.json"
    with open(path, "w") as f:
        json.dump(results, f, indent=2)
    logger.info(f"Scaler comparison report saved: {path}")


# ─────────────────────────────────────────────
# PRODUCTION SCALER
# ─────────────────────────────────────────────

class FeatureScaler:
    """
    Production-ready scaler for Model 2.

    Wraps sklearn scalers with save/load functionality.
    Fits on training data only.
    Used for all inference through the AnomalyService.

    Attributes:
        scaler_name:  Name of the scaler ('robust', 'standard', or 'none').
        scaler:       Fitted sklearn scaler (or None if no scaling).
        numeric_cols: Columns that are scaled.
        is_fitted:    Whether the scaler has been fitted.
    """

    def __init__(self, scaler_name: str = PREFERRED_SCALER):
        self.scaler_name = scaler_name
        self.scaler = None
        self.numeric_cols: list[str] = []
        self.is_fitted: bool = False

    def fit(self, df: pd.DataFrame) -> "FeatureScaler":
        """
        Fit the scaler on training data.

        Args:
            df: Encoded training DataFrame.

        Returns:
            Self (for chaining).
        """
        self.numeric_cols = [c for c in NUMERIC_FEATURES if c in df.columns]

        if self.scaler_name == "none":
            logger.info("No scaling selected — skipping fit.")
        elif self.scaler_name == "standard":
            self.scaler = StandardScaler()
            self.scaler.fit(df[self.numeric_cols])
        elif self.scaler_name == "robust":
            self.scaler = RobustScaler()
            self.scaler.fit(df[self.numeric_cols])
        else:
            raise ValueError(f"Unknown scaler: '{self.scaler_name}'")

        self.is_fitted = True
        logger.info(
            f"FeatureScaler fitted — type: '{self.scaler_name}' | "
            f"columns: {self.numeric_cols}"
        )
        return self

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Apply the fitted scaler to new data.

        Args:
            df: DataFrame to scale.

        Returns:
            Scaled DataFrame copy.
        """
        if not self.is_fitted:
            raise RuntimeError("Scaler must be fitted before transform.")

        df = df.copy()

        if self.scaler_name == "none" or self.scaler is None:
            return df

        cols = [c for c in self.numeric_cols if c in df.columns]
        df[cols] = self.scaler.transform(df[cols])
        return df

    def fit_transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Fit and transform in one step."""
        return self.fit(df).transform(df)

    def save(self, path: Optional[Path] = None) -> Path:
        """
        Persist the fitted scaler to disk.

        Args:
            path: Save path. Defaults to config.SCALER_PATH.

        Returns:
            Path where the scaler was saved.
        """
        save_path = Path(path or SCALER_PATH)
        save_path.parent.mkdir(parents=True, exist_ok=True)

        with open(save_path, "wb") as f:
            pickle.dump(self, f)

        logger.info(f"Scaler saved: {save_path}")
        return save_path

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "FeatureScaler":
        """
        Load a previously saved FeatureScaler from disk.

        Args:
            path: Load path. Defaults to config.SCALER_PATH.

        Returns:
            Loaded FeatureScaler instance.
        """
        load_path = Path(path or SCALER_PATH)

        if not load_path.exists():
            raise FileNotFoundError(f"Scaler not found at: {load_path}")

        with open(load_path, "rb") as f:
            scaler = pickle.load(f)

        logger.info(f"Scaler loaded: {load_path}")
        return scaler
