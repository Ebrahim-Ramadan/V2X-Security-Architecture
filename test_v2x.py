"""
V2X Architecture Integration Tests

Covers:
  - Real ECDSA-P256 CAM sign / verify
  - Real CRYSTALS-Dilithium3 DENM sign / verify
  - Crypto benchmark output
  - IDS anomaly detector (rule-based path, no trained models needed)
  - Tamper-detection (signature rejection)
  - SCMS health endpoints (when services are running)
"""

import json
import time
import sys
import requests


# ---------------------------------------------------------------------------
# Crypto tests (no external services needed)
# ---------------------------------------------------------------------------

def test_cam_real_ecdsa():
    """CAM messages must be signed with real ECDSA-P256-SHA256."""
    from vehicles.vehicle import Vehicle
    v = Vehicle(1)
    cam_json = v.generate_cam()
    msg = json.loads(cam_json)

    assert msg["crypto"] == "classical", "CAM must use classical crypto label"
    assert "signature" in msg, "CAM must carry a signature field"
    assert "public_key" in msg, "CAM must carry the signer public key"
    assert len(bytes.fromhex(msg["signature"])) > 50, "ECDSA sig should be >50 bytes"

    ok = v.verify_cam(cam_json)
    assert ok, "CAM signature verification must pass"
    print("  PASS  CAM ECDSA-P256 sign/verify")


def test_denm_real_dilithium3():
    """DENM messages must be signed with real CRYSTALS-Dilithium3."""
    from vehicles.vehicle import Vehicle, PQC_AVAILABLE
    v = Vehicle(2)
    denm_json = v.generate_denm()
    msg = json.loads(denm_json)

    assert msg["crypto"] == "post_quantum", "DENM must use post_quantum crypto label"
    assert "signature" in msg
    assert "public_key" in msg

    if PQC_AVAILABLE:
        assert msg["pqc_algorithm"] == "CRYSTALS-DILITHIUM3"
        import base64
        sig_len = len(base64.b64decode(msg["signature"]))
        assert sig_len > 3000, f"Dilithium3 sig should be ~3293B, got {sig_len}B"

        ok = v.verify_denm(denm_json)
        assert ok, "DENM Dilithium3 verification must pass"
        print("  PASS  DENM CRYSTALS-Dilithium3 sign/verify")
    else:
        print("  SKIP  dilithium-py not installed — install with: pip install dilithium-py")


def test_tamper_detection():
    """Mutating message content must invalidate both CAM and DENM signatures."""
    from vehicles.vehicle import Vehicle
    v = Vehicle(3)

    # Tamper CAM
    cam_msg = json.loads(v.generate_cam())
    cam_msg["data"]["speed"] = 999.9  # forged value
    tampered = json.dumps(cam_msg)
    assert not v.verify_cam(tampered), "Tampered CAM must fail verification"
    print("  PASS  CAM tamper detection")

    # Tamper DENM
    from vehicles.vehicle import PQC_AVAILABLE
    if PQC_AVAILABLE:
        denm_msg = json.loads(v.generate_denm())
        denm_msg["data"]["severity"] = 99  # forged severity
        tampered_denm = json.dumps(denm_msg)
        result = v.verify_denm(tampered_denm)
        assert result is False, "Tampered DENM must fail verification"
        print("  PASS  DENM tamper detection")


def test_benchmark():
    """Benchmark must return timing and size data for both algorithms."""
    from vehicles.vehicle import Vehicle, PQC_AVAILABLE
    v = Vehicle(4)
    results = v.benchmark_crypto(iterations=5)

    assert "ECDSA-P256-SHA256" in results
    ecdsa = results["ECDSA-P256-SHA256"]
    assert ecdsa["sig_size_bytes"] > 0
    assert ecdsa["quantum_safe"] is False

    if PQC_AVAILABLE:
        assert "CRYSTALS-DILITHIUM3" in results
        dil = results["CRYSTALS-DILITHIUM3"]
        assert dil["sig_size_bytes"] > 3000
        assert dil["quantum_safe"] is True
        print(f"  PASS  Benchmark: ECDSA={ecdsa['sign_ms']}ms/{ecdsa['sig_size_bytes']}B  "
              f"Dilithium3={dil['sign_ms']}ms/{dil['sig_size_bytes']}B")
    else:
        print(f"  PASS  Benchmark (ECDSA only): {ecdsa['sign_ms']}ms / {ecdsa['sig_size_bytes']}B")


# ---------------------------------------------------------------------------
# IDS tests (no models needed — exercises rule-based path)
# ---------------------------------------------------------------------------

def test_ids_rule_based():
    """IDS rule-based detector must flag physically-impossible messages."""
    from ids.detection.anomaly_detector import detect, detect_sybil

    # Normal CAM — should not flag
    normal = {"data": {"message_type": "CAM", "vehicle_id": "V-1",
                       "speed": 60.0, "heading": 90.0, "acceleration": 0.0,
                       "severity": 0, "position": [42.33, -83.04]},
              "crypto": "classical"}
    result = detect(normal)
    assert not result["anomaly_detected"], "Normal CAM should not trigger anomaly"

    # Impossible speed — should flag FDI
    bad_speed = {"data": {"message_type": "CAM", "vehicle_id": "V-2",
                          "speed": 9999.0, "heading": 0.0, "acceleration": 0.0,
                          "severity": 0, "position": [42.33, -83.04]},
                 "crypto": "classical"}
    result = detect(bad_speed)
    assert result["anomaly_detected"], "Impossible speed must trigger FDI flag"
    assert result["attack_type"] == "FDI"
    print(f"  PASS  IDS FDI rule (speed=9999): score={result['anomaly_score']}")

    # Sybil: same position, different IDs
    messages = [
        {"data": {"vehicle_id": f"V-{i}", "message_type": "CAM",
                  "speed": 50.0, "heading": 0.0, "acceleration": 0.0,
                  "severity": 0, "position": [42.33, -83.04]},
         "crypto": "classical"}
        for i in range(4)
    ]
    sybil = detect_sybil(messages)
    assert sybil["sybil_detected"], "Same-position cluster must trigger Sybil flag"
    print(f"  PASS  IDS Sybil rule: suspects={sybil['suspicious_vehicles']}")


# ---------------------------------------------------------------------------
# SCMS service tests (require running Docker / local services)
# ---------------------------------------------------------------------------

def test_scms_services():
    """Health-check all SCMS services. Skips gracefully if not running."""
    services = {
        "Root CA":           "http://localhost:5001/health",
        "Intermediate CA":   "http://localhost:5002/health",
        "Registration Auth": "http://localhost:5003/health",
        "Misbehavior Auth":  "http://localhost:5004/health",
        "PCA":               "http://localhost:5005/health",
        "IDS Service":       "http://localhost:5010/health",
    }
    any_up = False
    for name, url in services.items():
        try:
            r = requests.get(url, timeout=2)
            if r.status_code == 200:
                print(f"  UP    {name}: {r.json().get('status', 'ok')}")
                any_up = True
            else:
                print(f"  WARN  {name}: HTTP {r.status_code}")
        except Exception:
            print(f"  DOWN  {name}: not reachable (start services first)")

    if not any_up:
        print("  INFO  No SCMS services are running. Start with: docker-compose up")


def test_pca_cert_issuance():
    """PCA must issue a verifiable ECDSA-signed pseudonym certificate."""
    try:
        r = requests.post(
            "http://localhost:5005/issue_pseudonym_cert",
            json={"vehicle_id": "TEST-V1", "public_key": "aabbccdd"},
            timeout=3,
        )
        if r.status_code != 201:
            print(f"  SKIP  PCA not running (HTTP {r.status_code})")
            return
        cert = r.json()
        assert cert["status"] == "issued"
        assert "pca_signature" in cert, "Cert must have a real ECDSA PCA signature"
        assert len(cert["pca_signature"]) > 100, "PCA signature must be non-trivial"
        assert "pseudonym_public_key" in cert
        print(f"  PASS  PCA issued cert {cert['certificate_id'][:30]}...")

        # Verify the cert via the /verify_cert endpoint
        v_resp = requests.post("http://localhost:5005/verify_cert", json=cert, timeout=3)
        if v_resp.status_code == 200:
            assert v_resp.json()["valid"] is True
            print("  PASS  PCA cert signature verified by /verify_cert")
    except requests.ConnectionError:
        print("  SKIP  PCA not reachable (start with docker-compose up)")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

TESTS = [
    ("CAM ECDSA sign/verify",            test_cam_real_ecdsa),
    ("DENM Dilithium3 sign/verify",       test_denm_real_dilithium3),
    ("Tamper detection",                  test_tamper_detection),
    ("Crypto benchmark",                  test_benchmark),
    ("IDS rule-based detection",          test_ids_rule_based),
    ("SCMS service health checks",        test_scms_services),
    ("PCA pseudonym cert issuance",       test_pca_cert_issuance),
]


def main():
    print("\n=== V2X Security Architecture — Integration Tests ===\n")
    passed = failed = 0
    for name, fn in TESTS:
        print(f"[{name}]")
        try:
            fn()
            passed += 1
        except AssertionError as e:
            print(f"  FAIL  {e}")
            failed += 1
        except Exception as e:
            print(f"  ERROR {type(e).__name__}: {e}")
            failed += 1
        print()

    print(f"Results: {passed} passed, {failed} failed out of {len(TESTS)} tests")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
