#!/usr/bin/env python3
"""
IDS Anomaly Detector for V2X (VeReMi NextGen dataset).

Architecture:
  - CNN + LSTM ensemble for per-message False Data Injection (FDI) detection
  - K-Means clustering for Sybil attack detection across message batches
  - Rule-based fallback when trained weights are absent

Model files (place in ids/models/ after training with train_ids_colab.ipynb):
  - cnn_model.keras
  - lstm_model.keras
  - kmeans_model.pkl
"""

import os
import json
import logging
import pickle
import numpy as np

logger = logging.getLogger(__name__)

# Paths relative to this file: ids/detection/ -> ids/models/
_HERE = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(_HERE, "..", "models")
CNN_PATH = os.path.join(MODEL_DIR, "cnn_model.keras")
LSTM_PATH = os.path.join(MODEL_DIR, "lstm_model.keras")
KMEANS_PATH = os.path.join(MODEL_DIR, "kmeans_model.pkl")

# Tuned on VeReMi NextGen with class-weighted training
ANOMALY_THRESHOLD = 0.65
SPEED_LIMIT_KMPH = 250.0   # physically impossible — rule-based FDI flag
SEVERITY_MAX = 9            # DENM severity > 9 is out-of-spec


def _extract_features(message: dict) -> np.ndarray:
    """
    Extract a fixed-length numeric feature vector from a V2X message dict.
    Works with both flat dicts and the {data: {...}, signature: ...} wrapper.
    """
    data = message.get("data", message)
    pos = data.get("position", [0.0, 0.0])
    return np.array(
        [
            float(data.get("speed", 0.0)),
            float(data.get("heading", 0.0)),
            float(data.get("acceleration", 0.0)),
            float(data.get("severity", 0)),
            float(pos[0]) if len(pos) > 0 else 0.0,   # latitude
            float(pos[1]) if len(pos) > 1 else 0.0,   # longitude
            float(len(json.dumps(message))),            # message length
            1.0 if data.get("message_type") == "DENM" else 0.0,
            1.0 if message.get("crypto") == "post_quantum" else 0.0,
        ],
        dtype=np.float32,
    )


class AnomalyDetector:
    """
    Loads trained CNN+LSTM and K-Means models on construction.
    Falls back to rule-based detection if model files are not found.
    """

    def __init__(self):
        self.cnn_model = None
        self.lstm_model = None
        self.kmeans_model = None
        self.mode = "rule-only"
        self._load_models()

    def _load_models(self):
        os.makedirs(MODEL_DIR, exist_ok=True)

        # --- Deep learning models (TensorFlow/Keras) ---
        try:
            from tensorflow import keras

            if os.path.exists(CNN_PATH) and os.path.exists(LSTM_PATH):
                self.cnn_model = keras.models.load_model(CNN_PATH)
                self.lstm_model = keras.models.load_model(LSTM_PATH)
                self.mode = "ml"
                logger.info(
                    f"Loaded CNN ({CNN_PATH}) and LSTM ({LSTM_PATH}) models"
                )
            else:
                logger.warning(
                    f"Model files not found in {MODEL_DIR}. "
                    "Running in rule-only mode. "
                    "Train with: ids/train_ids_colab.ipynb on VeReMi NextGen dataset."
                )
        except ImportError:
            logger.warning(
                "TensorFlow not installed (pip install tensorflow). "
                "Running in rule-only mode."
            )

        # --- K-Means Sybil model (sklearn) ---
        try:
            if os.path.exists(KMEANS_PATH):
                with open(KMEANS_PATH, "rb") as f:
                    self.kmeans_model = pickle.load(f)
                logger.info(f"Loaded K-Means Sybil model ({KMEANS_PATH})")
        except Exception as e:
            logger.warning(f"K-Means model load failed: {e}")

    # ------------------------------------------------------------------
    # Single-message detection
    # ------------------------------------------------------------------

    def detect(self, message: dict) -> dict:
        """
        Run anomaly detection on a single V2X message.

        Returns:
            {
                'vehicle_id': str,
                'mode': 'ml' | 'rule-only',
                'anomaly_detected': bool,
                'anomaly_score': float,   # 0–1
                'attack_type': str | None,
                'confidence': float,
            }
        """
        data = message.get("data", message)
        result = {
            "vehicle_id": data.get("vehicle_id", "unknown"),
            "mode": self.mode,
            "anomaly_detected": False,
            "anomaly_score": 0.0,
            "attack_type": None,
            "confidence": 0.0,
        }

        if self.mode == "ml":
            try:
                features = _extract_features(message)
                # CNN expects (batch, timesteps, channels) — reshape to (1, F, 1)
                feat_3d = features.reshape(1, -1, 1)
                cnn_score = float(self.cnn_model.predict(feat_3d, verbose=0)[0][0])
                lstm_score = float(self.lstm_model.predict(feat_3d, verbose=0)[0][0])
                score = (cnn_score + lstm_score) / 2.0
                result.update({
                    "anomaly_score": round(score, 4),
                    "anomaly_detected": score > ANOMALY_THRESHOLD,
                    "confidence": round(score, 4),
                    "attack_type": (
                        "FDI" if score > 0.85
                        else "Sybil" if score > ANOMALY_THRESHOLD
                        else None
                    ),
                })
                return result
            except Exception as e:
                logger.error(f"ML inference failed: {e} — falling back to rules")

        # Rule-based fallback (always runs if ML fails or mode == 'rule-only')
        speed = float(data.get("speed", 0.0))
        severity = int(data.get("severity", 0))

        if speed > SPEED_LIMIT_KMPH:
            result.update({
                "anomaly_detected": True,
                "anomaly_score": 0.92,
                "attack_type": "FDI",
                "confidence": 0.92,
            })
        elif severity > SEVERITY_MAX:
            result.update({
                "anomaly_detected": True,
                "anomaly_score": 0.78,
                "attack_type": "FDI",
                "confidence": 0.78,
            })

        return result

    # ------------------------------------------------------------------
    # Batch Sybil detection
    # ------------------------------------------------------------------

    def detect_sybil(self, messages: list) -> dict:
        """
        Detect Sybil attacks across a batch of messages using K-Means
        clustering or a rule-based position-collision heuristic.

        Returns:
            {
                'sybil_detected': bool,
                'suspicious_vehicles': [vehicle_id, ...],
                'method': 'kmeans' | 'rule-based',
            }
        """
        if not messages:
            return {"sybil_detected": False, "suspicious_vehicles": [], "method": "none"}

        if self.kmeans_model is not None:
            try:
                features = np.array([_extract_features(m) for m in messages])
                clusters = self.kmeans_model.predict(features)
                suspicious = []
                unique, counts = np.unique(clusters, return_counts=True)
                for cid, cnt in zip(unique, counts):
                    if cnt > 3:   # > 3 msgs in same cluster = suspicious
                        for m, c in zip(messages, clusters):
                            if c == cid:
                                vid = m.get("data", m).get("vehicle_id")
                                if vid:
                                    suspicious.append(vid)
                return {
                    "sybil_detected": len(suspicious) > 0,
                    "suspicious_vehicles": list(set(suspicious)),
                    "method": "kmeans",
                }
            except Exception as e:
                logger.error(f"K-Means Sybil detection failed: {e}")

        # Rule-based: multiple different vehicle IDs at the same GPS position
        position_map: dict = {}
        for m in messages:
            data = m.get("data", m)
            pos = tuple(data.get("position", []))
            vid = data.get("vehicle_id")
            if pos and vid:
                position_map.setdefault(pos, set()).add(vid)

        suspicious = [
            vid
            for vids in position_map.values()
            if len(vids) > 1
            for vid in vids
        ]
        return {
            "sybil_detected": len(suspicious) > 0,
            "suspicious_vehicles": list(set(suspicious)),
            "method": "rule-based",
        }


# Module-level singleton — import and call these directly
_detector = AnomalyDetector()


def detect(message: dict) -> dict:
    return _detector.detect(message)


def detect_sybil(messages: list) -> dict:
    return _detector.detect_sybil(messages)
