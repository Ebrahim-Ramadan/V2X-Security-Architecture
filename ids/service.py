#!/usr/bin/env python3
"""
IDS Flask service — exposes anomaly detection via HTTP.
Routes:
  GET  /health          — liveness probe
  POST /detect          — single-message FDI/anomaly detection
  POST /detect/batch    — multi-message Sybil detection
  GET  /mode            — which detection mode is active (ml / rule-only)
"""

import logging
from flask import Flask, request, jsonify
from ids.detection.anomaly_detector import _detector, detect, detect_sybil

app = Flask(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - IDS - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "service": "IDS",
        "status": "running",
        "detection_mode": _detector.mode,
        "ml_loaded": _detector.cnn_model is not None,
        "kmeans_loaded": _detector.kmeans_model is not None,
    }), 200


@app.route("/mode", methods=["GET"])
def mode():
    return jsonify({"mode": _detector.mode}), 200


@app.route("/detect", methods=["POST"])
def detect_endpoint():
    """Single-message FDI / anomaly detection."""
    message = request.get_json()
    if not message:
        return jsonify({"error": "No message provided"}), 400
    result = detect(message)
    status = 200
    if result.get("anomaly_detected"):
        logger.warning(
            f"ANOMALY detected — vehicle {result['vehicle_id']}, "
            f"type={result['attack_type']}, score={result['anomaly_score']}"
        )
    return jsonify(result), status


@app.route("/detect/batch", methods=["POST"])
def detect_batch():
    """Batch Sybil detection across multiple messages."""
    body = request.get_json()
    if not body or "messages" not in body:
        return jsonify({"error": "Expected {messages: [...]}"}), 400
    messages = body["messages"]
    result = detect_sybil(messages)
    if result.get("sybil_detected"):
        logger.warning(
            f"SYBIL detected — suspects: {result['suspicious_vehicles']}"
        )
    return jsonify(result), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5010, debug=False)
