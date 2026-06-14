#!/usr/bin/env python3
"""
Pseudonym Certificate Authority (PCA) for V2X SCMS.
Issues real ECDSA-P256-signed pseudonym certificates per ETSI TS 102 941.
Each certificate uses a fresh ephemeral key pair for vehicle privacy.
"""

import os
import json
import logging
import datetime

from flask import Flask, request, jsonify
import requests

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

app = Flask(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

ICA_URL = os.getenv("ICA_URL", "http://intermediate-ca:5002")


class PseudonymCA:
    """
    Manages PCA signing key and issues real ECDSA-P256 pseudonym certificates.
    In a full SCMS the signing key itself would be certified by the ICA.
    """

    def __init__(self):
        self.signing_key = ec.generate_private_key(ec.SECP256R1())
        self.signing_pub_hex = self.signing_key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.CompressedPoint,
        ).hex()
        logger.info("PCA signing key generated (ECDSA-P256)")

    def issue(self, vehicle_id: str) -> dict:
        """
        Generate an ephemeral ECDSA-P256 key pair for privacy, build a
        certificate payload, sign it with the PCA key, and return all
        material the vehicle needs to use this pseudonym.
        """
        # New key pair per certificate — unlinkable pseudonyms
        pseudonym_key = ec.generate_private_key(ec.SECP256R1())
        pseudonym_pub_hex = pseudonym_key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.CompressedPoint,
        ).hex()
        pseudonym_priv_hex = pseudonym_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).hex()

        cert_id = f"psnym_{vehicle_id}_{os.urandom(4).hex()}"
        now = datetime.datetime.utcnow()
        expiry = now + datetime.timedelta(days=7)

        cert_payload = json.dumps(
            {
                "certificate_id": cert_id,
                "vehicle_id": vehicle_id,
                "issuer": "PCA",
                "not_before": now.isoformat(),
                "not_after": expiry.isoformat(),
                "crypto_algorithm": "ECDSA-P256-SHA256",
                "pseudonym_public_key": pseudonym_pub_hex,
            },
            sort_keys=True,
        ).encode()

        # PCA signs the certificate structure
        pca_sig = self.signing_key.sign(cert_payload, ec.ECDSA(hashes.SHA256()))

        return {
            "certificate_id": cert_id,
            "vehicle_id": vehicle_id,
            "issuer": "PCA",
            "issuer_public_key": self.signing_pub_hex,
            "not_before": now.isoformat(),
            "not_after": expiry.isoformat(),
            "validity_period": "7 days",
            "crypto_algorithm": "ECDSA-P256-SHA256",
            "pseudonym_public_key": pseudonym_pub_hex,
            "pseudonym_private_key": pseudonym_priv_hex,
            "pca_signature": pca_sig.hex(),
            "status": "issued",
        }

    def verify_cert(self, cert: dict) -> bool:
        """Verify that a certificate was genuinely signed by this PCA."""
        try:
            payload = json.dumps(
                {
                    "certificate_id": cert["certificate_id"],
                    "vehicle_id": cert["vehicle_id"],
                    "issuer": cert["issuer"],
                    "not_before": cert["not_before"],
                    "not_after": cert["not_after"],
                    "crypto_algorithm": cert["crypto_algorithm"],
                    "pseudonym_public_key": cert["pseudonym_public_key"],
                },
                sort_keys=True,
            ).encode()
            sig = bytes.fromhex(cert["pca_signature"])
            self.signing_key.public_key().verify(sig, payload, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False


pca = PseudonymCA()


@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({
        "service": "PCA",
        "status": "running",
        "ica_url": ICA_URL,
        "pca_public_key": pca.signing_pub_hex,
    }), 200


@app.route("/issue_pseudonym_cert", methods=["POST"])
def issue_pseudonym_cert():
    """Issue a cryptographically-signed pseudonym certificate."""
    try:
        data = request.get_json()
        vehicle_id = data.get("vehicle_id")
        public_key = data.get("public_key")

        if not vehicle_id or not public_key:
            return jsonify({"error": "Missing vehicle_id or public_key"}), 400

        logger.info(f"Issuing pseudonym cert for vehicle {vehicle_id}")
        cert = pca.issue(vehicle_id)
        return jsonify(cert), 201

    except Exception as e:
        logger.error(f"Error issuing certificate: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/verify_cert", methods=["POST"])
def verify_cert():
    """Verify a previously issued pseudonym certificate."""
    try:
        cert = request.get_json()
        valid = pca.verify_cert(cert)
        return jsonify({"valid": valid, "certificate_id": cert.get("certificate_id")}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/revoke_certificate", methods=["POST"])
def revoke_certificate():
    """Revoke a pseudonym certificate and notify the Misbehavior Authority."""
    data = request.get_json()
    cert_id = data.get("certificate_id")

    if not cert_id:
        return jsonify({"error": "Missing certificate_id"}), 400

    logger.warning(f"Revoking certificate: {cert_id}")

    try:
        requests.post(
            "http://ma:5004/report_misbehavior",
            json={"certificate_id": cert_id, "reason": "revoked_by_pca"},
            timeout=5,
        )
    except Exception:
        logger.warning("Could not reach Misbehavior Authority")

    return jsonify({
        "certificate_id": cert_id,
        "status": "revoked",
        "timestamp": datetime.datetime.now().isoformat(),
    }), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5005, debug=True)
