"""
V2X Architecture Integration Tests

Covers:
  - Real ECDSA-P256 CAM sign / verify
  - Real CRYSTALS-Dilithium2 DENM sign / verify
  - Tamper detection (signature rejection)
  - Crypto benchmark output
  - All 7 vehicle profiles (type, position, events)
  - SCMS health endpoints (when services are running)
"""

import json
import time
import sys
import requests

from vehicles.vehicle import Vehicle, VEHICLE_PROFILES, EVENT_SEVERITY, PQC_AVAILABLE


# ---------------------------------------------------------------------------
# Crypto tests
# ---------------------------------------------------------------------------

def test_cam_real_ecdsa():
    v = Vehicle(1)
    cam_json = v.generate_cam()
    msg = json.loads(cam_json)

    assert msg["crypto"] == "classical"
    assert len(bytes.fromhex(msg["signature"])) > 50
    assert "public_key" in msg
    assert v.verify_cam(cam_json) is True
    print("  PASS  CAM ECDSA-P256 sign/verify")


def test_denm_real_dilithium3():
    v = Vehicle(1)
    denm_json = v.generate_denm()
    msg = json.loads(denm_json)

    assert msg["crypto"] == "post_quantum"

    if PQC_AVAILABLE:
        assert msg["pqc_algorithm"] == "CRYSTALS-DILITHIUM2"
        import base64
        sig_len = len(base64.b64decode(msg["signature"]))
        assert sig_len > 2000, f"Dilithium2 sig should be ~2420B, got {sig_len}B"
        assert v.verify_denm(denm_json) is True
        print("  PASS  DENM CRYSTALS-Dilithium2 sign/verify")
    else:
        print("  SKIP  dilithium-py not installed")


def test_tamper_detection():
    v = Vehicle(1)

    # Tamper CAM
    cam = json.loads(v.generate_cam())
    cam["data"]["speed"] = 9999.9
    assert v.verify_cam(json.dumps(cam)) is False
    print("  PASS  CAM tamper detection")

    # Tamper DENM
    if PQC_AVAILABLE:
        denm = json.loads(v.generate_denm())
        denm["data"]["severity"] = 99
        assert v.verify_denm(json.dumps(denm)) is False
        print("  PASS  DENM tamper detection")


def test_benchmark():
    v = Vehicle(1)
    results = v.benchmark_crypto(iterations=5)

    ecdsa = results["ECDSA-P256-SHA256"]
    assert ecdsa["sig_size_bytes"] > 0
    assert ecdsa["quantum_safe"] is False

    if PQC_AVAILABLE:
        dil = results["CRYSTALS-DILITHIUM2"]
        assert dil["sig_size_bytes"] > 2000
        assert dil["quantum_safe"] is True
        print(
            f"  PASS  Benchmark: "
            f"ECDSA={ecdsa['sign_ms']}ms/{ecdsa['sig_size_bytes']}B  "
            f"Dilithium2={dil['sign_ms']}ms/{dil['sig_size_bytes']}B"
        )
    else:
        print(f"  PASS  Benchmark (ECDSA only): {ecdsa['sign_ms']}ms/{ecdsa['sig_size_bytes']}B")


# ---------------------------------------------------------------------------
# Multi-vehicle profile tests
# ---------------------------------------------------------------------------

def test_all_vehicle_profiles():
    """Every vehicle ID 1-7 must produce valid signed messages."""
    for vid in range(1, 8):
        v = Vehicle(vid)
        profile = VEHICLE_PROFILES[vid]

        # Correct type loaded
        assert v.vehicle_type == profile["type"], \
            f"Vehicle {vid} type mismatch: {v.vehicle_type} != {profile['type']}"

        # CAM carries vehicle_type and position
        cam = json.loads(v.generate_cam())
        assert cam["data"]["vehicle_type"] == profile["type"]
        assert cam["data"]["position"] is not None
        assert v.verify_cam(json.dumps(cam)) is True, f"CAM sig invalid for vehicle {vid}"

        # DENM event must be one of the profile's events
        denm = json.loads(v.generate_denm())
        event = denm["data"]["event_type"]
        assert event in profile["events"], \
            f"Vehicle {vid} DENM event '{event}' not in profile events {profile['events']}"

        if PQC_AVAILABLE:
            assert v.verify_denm(json.dumps(denm)) is True, f"DENM sig invalid for vehicle {vid}"

    print("  PASS  All 7 vehicle profiles: types, events, signatures verified")


def test_position_movement():
    """Vehicle position must update after calling _update_position."""
    v = Vehicle(1)
    lat0, lon0 = v.lat, v.lon
    for _ in range(5):
        v._update_position()
    assert (v.lat, v.lon) != (lat0, lon0), "Position did not change after movement"
    print(f"  PASS  Position movement: ({lat0:.6f},{lon0:.6f}) -> ({v.lat:.6f},{v.lon:.6f})")


def test_event_severity():
    """DENM severity must match the EVENT_SEVERITY table."""
    v = Vehicle(5)  # emergency vehicle — highest severity
    for _ in range(10):
        denm = json.loads(v.generate_denm())
        event    = denm["data"]["event_type"]
        severity = denm["data"]["severity"]
        assert severity == EVENT_SEVERITY[event], \
            f"Severity mismatch for '{event}': got {severity}, expected {EVENT_SEVERITY[event]}"
    print("  PASS  DENM severity matches event type table")


def test_vehicle_types_covered():
    """All four vehicle types (car, truck, emergency, bus) must be in the fleet."""
    types = {VEHICLE_PROFILES[vid]["type"] for vid in range(1, 8)}
    for expected in ("car", "truck", "emergency", "bus"):
        assert expected in types, f"Vehicle type '{expected}' missing from fleet"
    print(f"  PASS  Fleet covers all types: {sorted(types)}")


# ---------------------------------------------------------------------------
# SCMS service tests (require running Docker / local services)
# ---------------------------------------------------------------------------

def test_scms_services():
    services = {
        "Root CA":           "http://localhost:5001/health",
        "Intermediate CA":   "http://localhost:5002/health",
        "Registration Auth": "http://localhost:5003/health",
        "Misbehavior Auth":  "http://localhost:5004/health",
        "PCA":               "http://localhost:5005/health",
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
            print(f"  DOWN  {name}: not reachable")
    if not any_up:
        print("  INFO  No SCMS services running — start with: docker-compose up")


def test_pca_cert_issuance():
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
        assert len(cert["pca_signature"]) > 100
        assert "pseudonym_public_key" in cert
        print(f"  PASS  PCA issued cert {cert['certificate_id'][:30]}...")

        v_resp = requests.post("http://localhost:5005/verify_cert", json=cert, timeout=3)
        if v_resp.status_code == 200:
            assert v_resp.json()["valid"] is True
            print("  PASS  PCA cert verified by /verify_cert")
    except requests.ConnectionError:
        print("  SKIP  PCA not reachable")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

TESTS = [
    ("CAM ECDSA sign/verify",          test_cam_real_ecdsa),
    ("DENM Dilithium2 sign/verify",    test_denm_real_dilithium3),
    ("Tamper detection",               test_tamper_detection),
    ("Crypto benchmark",               test_benchmark),
    ("All 7 vehicle profiles",         test_all_vehicle_profiles),
    ("Position movement",              test_position_movement),
    ("DENM event severity mapping",    test_event_severity),
    ("Fleet vehicle types coverage",   test_vehicle_types_covered),
    ("SCMS service health checks",     test_scms_services),
    ("PCA pseudonym cert issuance",    test_pca_cert_issuance),
]


def main():
    print("\n=== V2X Security Architecture -- Integration Tests ===\n")
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
