"""
NetSentry AI - Isolation Forest Anomaly Detection Engine
Trains, persists, and executes unsupervised anomaly detection on network traffic.
"""

import logging
from pathlib import Path
from typing import Tuple, List, Dict, Any, Optional
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

from src.ml.features import FEATURE_COLUMNS, packets_to_dataframe

logger = logging.getLogger("netsentry.ml")


class IsolationForestDetector:
    """
    Unsupervised network anomaly detector using Scikit-Learn's Isolation Forest.
    
    Explanation for SOC Analysts:
    Isolation Forest isolates anomalies by randomly selecting a feature and splitting values.
    Anomalous network packets require fewer splits to isolate than normal baseline packets.
    Scores range from -1.0 (highly anomalous) to 1.0 (normal).
    
    NOTE: Anomaly detection flags statistical deviations from normal baselines.
    It does not inherently prove a malicious attack.
    """

    def __init__(self, contamination: float = 0.05, random_state: int = 42):
        self.contamination = contamination
        self.random_state = random_state
        self.model: Optional[IsolationForest] = None
        self.scaler = StandardScaler()
        self.is_trained = False

    def train(self, data: pd.DataFrame):
        """Fits the scaler and Isolation Forest model on baseline network features."""
        if data.empty or len(data) < 20:
            raise ValueError("Training requires at least 20 sample traffic records.")

        X = self.scaler.fit_transform(data[FEATURE_COLUMNS])

        self.model = IsolationForest(
            n_estimators=120,
            max_samples="auto",
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1,
        )
        self.model.fit(X)
        self.is_trained = True
        logger.info(f"Isolation Forest trained successfully on {len(data)} samples.")

    def score_packets(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Computes anomaly predictions and decision scores for a list of packets.
        Appends 'anomaly_score' and 'is_anomaly' to each packet.
        """
        if not packets:
            return []

        if not self.is_trained or self.model is None:
            # If not yet trained, return neutral scores
            for p in packets:
                p["anomaly_score"] = 0.0
                p["is_anomaly"] = False
            return packets

        df = packets_to_dataframe(packets)
        X = self.scaler.transform(df)

        # decision_function: negative scores represent anomalies
        raw_scores = self.model.decision_function(X)
        predictions = self.model.predict(X)  # -1 for anomaly, 1 for normal

        for i, p in enumerate(packets):
            score = float(np.round(raw_scores[i], 4))
            is_anom = bool(predictions[i] == -1)
            p["anomaly_score"] = score
            p["is_anomaly"] = is_anom
            if is_anom:
                p["is_suspicious"] = 1

        return packets

    def save(self, model_path: Path, scaler_path: Path):
        """Serializes the trained model and scaler to disk."""
        model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, model_path)
        joblib.dump(self.scaler, scaler_path)
        logger.info(f"Model saved to {model_path} and scaler to {scaler_path}")

    def load(self, model_path: Path, scaler_path: Path) -> bool:
        """Loads serialized model and scaler from disk if available."""
        if Path(model_path).exists() and Path(scaler_path).exists():
            try:
                self.model = joblib.load(model_path)
                self.scaler = joblib.load(scaler_path)
                self.is_trained = True
                logger.info("Loaded pre-trained Isolation Forest and scaler.")
                return True
            except Exception as e:
                logger.error(f"Failed to load model: {e}")
                self.is_trained = False
        return False


# Global singleton instance
_detector_instance: Optional[IsolationForestDetector] = None


def get_detector() -> IsolationForestDetector:
    """Returns the singleton detector instance, initializing it if necessary."""
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = IsolationForestDetector()
    return _detector_instance

