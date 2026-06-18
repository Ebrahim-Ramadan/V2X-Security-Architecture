import json
import logging
import time
import math
import random
import hashlib
import argparse
import base64
import os
import sys
import socket
import threading

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

# Real CRYSTALS-Dilithium2 (NIST PQC standard) via dilithium-py
try:
    from dilithium_py.dilithium import Dilithium2
    PQC_AVAILABLE = True
except ImportError:
    PQC_AVAILABLE = False
    logging.warning("dilithium-py not installed -- install with: pip install dilithium-py")

if sys.platform == "win32":
    BROADCAST_ADDR = "255.255.255.255"
else:
    BROADCAST_ADDR = "<broadcast>"

# ---------------------------------------------------------------------------
# Vehicle profiles — realistic types, positions, speeds, headings
# Detroit area highway (I-94 corridor) + urban grid
# ---------------------------------------------------------------------------
VEHICLE_PROFILES = {
    1: {
        "type": "car",
        "speed": 72.0,     # km/h
        "heading": 90.0,   # East
        "lat": 42.3314,
        "lon": -83.0458,
        "events": ["emergency_braking", "accident"],
    },
    2: {
        "type": "car",
        "speed": 65.0,
        "heading": 88.0,
        "lat": 42.3320,
        "lon": -83.0520,
        "events": ["obstacle", "accident"],
    },
    3: {
        "type": "truck",
        "speed": 48.0,
        "heading": 270.0,  # West (opposite lane)
        "lat": 42.3308,
        "lon": -83.0390,
        "events": ["slow_vehicle", "roadwork"],
    },
    4: {
        "type": "car",
        "speed": 80.0,
        "heading": 45.0,   # North-East (on-ramp)
        "lat": 42.3350,
        "lon": -83.0470,
        "events": ["emergency_braking", "hazard"],
    },
    5: {
        "type": "emergency",
        "speed": 110.0,
        "heading": 90.0,
        "lat": 42.3295,
        "lon": -83.0600,
        "events": ["emergency_vehicle"],
    },
    6: {
        "type": "bus",
        "speed": 38.0,
        "heading": 180.0,  # South (urban route)
        "lat": 42.3340,
        "lon": -83.0480,
        "events": ["passenger_boarding", "obstacle"],
    },
    7: {
        "type": "truck",
        "speed": 44.0,
        "heading": 92.0,
        "lat": 42.3302,
        "lon": -83.0550,
        "events": ["slow_vehicle", "obstacle", "roadwork"],
    },
}

EVENT_SEVERITY = {
    "accident":               8,
    "emergency_braking":      7,
    "emergency_vehicle":      9,
    "obstacle":               5,
    "hazard":                 6,
    "slow_vehicle":           3,
    "roadwork":               4,
    "passenger_boarding":     2,
}


class Vehicle:
    def __init__(self, vehicle_id, ra_url="http://localhost:5003"):
        self.vehicle_id = vehicle_id
        self.ra_url = ra_url

        # Load profile (fallback to generic car if ID not in table)
        profile = VEHICLE_PROFILES.get(vehicle_id, {
            "type": "car", "speed": 60.0, "heading": 90.0,
            "lat": 42.3314, "lon": -83.0458, "events": ["accident"],
        })
        self.vehicle_type = profile["type"]
        self.speed        = profile["speed"]
        self.heading      = profile["heading"]
        self.lat          = profile["lat"]
        self.lon          = profile["lon"]
        self.denm_events  = profile["events"]

        # Classical crypto for CAM: ECDSA-P256
        self.cam_private_key = ec.generate_private_key(ec.SECP256R1())
        self.cam_public_key_hex = self.cam_private_key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.CompressedPoint,
        ).hex()

        # Post-quantum crypto for DENM: CRYSTALS-Dilithium2
        if PQC_AVAILABLE:
            self.pqc_public_key, self.pqc_secret_key = Dilithium2.keygen()
            self.pqc_public_key_b64 = base64.b64encode(self.pqc_public_key).decode()
            logging.info(
                f"Vehicle {vehicle_id} ({self.vehicle_type}): "
                f"Dilithium2 key pair generated "
                f"(pk={len(self.pqc_public_key)}B, sk={len(self.pqc_secret_key)}B)"
            )
        else:
            self.pqc_public_key     = b""
            self.pqc_secret_key     = None
            self.pqc_public_key_b64 = ""

        self._setup_socket()
        logging.info(
            f"Vehicle {vehicle_id} ({self.vehicle_type}) initialized | "
            f"speed={self.speed} km/h heading={self.heading} deg"
        )

    # ------------------------------------------------------------------
    # Socket setup
    # ------------------------------------------------------------------

    def _setup_socket(self):
        try:
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            if sys.platform == "win32":
                self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.broadcast_port = 5005
            self.listening = False
        except Exception as e:
            logging.error(f"Socket setup failed: {e}")

    # ------------------------------------------------------------------
    # Movement simulation
    # ------------------------------------------------------------------

    def _update_position(self):
        """Move vehicle one second forward based on speed and heading."""
        heading_rad  = math.radians(self.heading)
        speed_m_per_s = self.speed / 3.6
        # 1 deg lat ~ 111,320 m; 1 deg lon ~ 111,320 * cos(lat) m
        self.lat += (speed_m_per_s * math.cos(heading_rad)) / 111_320.0
        self.lon += (speed_m_per_s * math.sin(heading_rad)) / (
            111_320.0 * math.cos(math.radians(self.lat))
        )
        # Small realistic speed variation
        self.speed = max(0.0, self.speed + random.uniform(-0.8, 0.8))

    # ------------------------------------------------------------------
    # Message generation
    # ------------------------------------------------------------------

    def generate_cam(self):
        """Generate CAM signed with real ECDSA-P256-SHA256."""
        cam_data = {
            "message_type":  "CAM",
            "vehicle_id":    self.vehicle_id,
            "vehicle_type":  self.vehicle_type,
            "timestamp":     time.time(),
            "position":      [round(self.lat, 6), round(self.lon, 6)],
            "speed":         round(self.speed, 1),
            "heading":       round(self.heading, 1),
            "acceleration":  round(random.uniform(-1.0, 1.0), 2),
            "crypto_type":   "ECDSA-P256-SHA256",
        }

        msg_bytes = json.dumps(cam_data, sort_keys=True).encode()
        sig_bytes = self.cam_private_key.sign(msg_bytes, ec.ECDSA(hashes.SHA256()))

        return json.dumps({
            "data":       cam_data,
            "signature":  sig_bytes.hex(),
            "public_key": self.cam_public_key_hex,
            "crypto":     "classical",
        })

    def generate_denm(self):
        """Generate DENM signed with real CRYSTALS-Dilithium2."""
        event    = random.choice(self.denm_events)
        severity = EVENT_SEVERITY.get(event, 5)

        denm_data = {
            "message_type": "DENM",
            "vehicle_id":   self.vehicle_id,
            "vehicle_type": self.vehicle_type,
            "event_type":   event,
            "severity":     severity,
            "position":     [round(self.lat, 6), round(self.lon, 6)],
            "timestamp":    time.time(),
            "validity":     time.time() + 300,
            "crypto_type":  "CRYSTALS-DILITHIUM2" if PQC_AVAILABLE else "SHA512-SIM",
        }

        msg_bytes = json.dumps(denm_data, sort_keys=True).encode()

        if PQC_AVAILABLE:
            sig_bytes = Dilithium2.sign(self.pqc_secret_key, msg_bytes)
            signature = base64.b64encode(sig_bytes).decode()
            algorithm = "CRYSTALS-DILITHIUM2"
        else:
            signature = hashlib.sha512(msg_bytes).hexdigest()
            algorithm = "SHA512-SIM"

        return json.dumps({
            "data":          denm_data,
            "signature":     signature,
            "public_key":    self.pqc_public_key_b64,
            "crypto":        "post_quantum",
            "pqc_algorithm": algorithm,
        })

    # ------------------------------------------------------------------
    # Signature verification
    # ------------------------------------------------------------------

    def verify_cam(self, cam_json: str) -> bool:
        try:
            msg     = json.loads(cam_json)
            sig     = bytes.fromhex(msg["signature"])
            pub     = bytes.fromhex(msg["public_key"])
            pub_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub)
            pub_key.verify(sig, json.dumps(msg["data"], sort_keys=True).encode(),
                           ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    def verify_denm(self, denm_json: str):
        if not PQC_AVAILABLE:
            return None
        try:
            msg      = json.loads(denm_json)
            sig      = base64.b64decode(msg["signature"])
            pub_key  = base64.b64decode(msg["public_key"])
            msg_bytes = json.dumps(msg["data"], sort_keys=True).encode()
            return Dilithium2.verify(pub_key, msg_bytes, sig)
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Benchmark
    # ------------------------------------------------------------------

    def benchmark_crypto(self, iterations: int = 50) -> dict:
        results = {}
        payload = b"V2X benchmark payload - ETSI ITS V2X message"

        key = ec.generate_private_key(ec.SECP256R1())
        t0  = time.perf_counter()
        for _ in range(iterations):
            key.sign(payload, ec.ECDSA(hashes.SHA256()))
        ecdsa_ms   = (time.perf_counter() - t0) / iterations * 1000
        sample_sig = key.sign(payload, ec.ECDSA(hashes.SHA256()))
        pub_bytes  = key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
        )
        results["ECDSA-P256-SHA256"] = {
            "sign_ms":          round(ecdsa_ms, 3),
            "sig_size_bytes":   len(sample_sig),
            "pub_key_size_bytes": len(pub_bytes),
            "quantum_safe":     False,
        }

        if PQC_AVAILABLE:
            pk, sk = Dilithium2.keygen()
            t0 = time.perf_counter()
            for _ in range(iterations):
                Dilithium2.sign(sk, payload)
            dil_ms     = (time.perf_counter() - t0) / iterations * 1000
            sample_dil = Dilithium2.sign(sk, payload)
            results["CRYSTALS-DILITHIUM2"] = {
                "sign_ms":            round(dil_ms, 3),
                "sig_size_bytes":     len(sample_dil),
                "pub_key_size_bytes": len(pk),
                "quantum_safe":       True,
                "security_level":     "NIST Level 2",
            }

        return results

    # ------------------------------------------------------------------
    # Broadcast
    # ------------------------------------------------------------------

    def broadcast_message(self, message: str):
        try:
            self.udp_socket.sendto(message.encode(), (BROADCAST_ADDR, self.broadcast_port))

            ds = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ds.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if sys.platform == "win32":
                ds.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            dashboard_host = os.environ.get("DASHBOARD_HOST", "localhost")
            dashboard_port = int(os.environ.get("DASHBOARD_PORT", "5008"))
            ds.sendto(message.encode(), (dashboard_host, dashboard_port))
            ds.close()

            logging.info(f"Vehicle {self.vehicle_id} broadcast: {message[:80]}...")
        except Exception as e:
            logging.error(f"Broadcast error: {e}")

    def start_listening(self):
        self.listening = True
        threading.Thread(target=self._listen_thread, daemon=True).start()

    def _listen_thread(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", self.broadcast_port))
        sock.settimeout(1.0)
        while self.listening:
            try:
                data, addr = sock.recvfrom(65535)
                logging.debug(f"Vehicle {self.vehicle_id} rx from {addr}: {data[:60]}...")
            except socket.timeout:
                continue
            except Exception as e:
                logging.error(f"Listen error: {e}")
        sock.close()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="V2X Vehicle Node")
    parser.add_argument("--id",        type=int, required=True)
    parser.add_argument("--ra-url",    default="http://localhost:5003")
    parser.add_argument("--benchmark", action="store_true",
                        help="Run ECDSA vs Dilithium2 benchmark and exit")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(f"vehicle_{args.id}.log"),
            logging.StreamHandler(),
        ],
    )

    vehicle = Vehicle(args.id, args.ra_url)

    if args.benchmark:
        print("\n=== V2X Cryptographic Benchmark ===")
        print("Iterations per algorithm: 50\n")
        for algo, d in vehicle.benchmark_crypto().items():
            print(f"{algo}:")
            print(f"  Signing time   : {d['sign_ms']:.3f} ms/op")
            print(f"  Signature size : {d['sig_size_bytes']} bytes")
            print(f"  Public key size: {d['pub_key_size_bytes']} bytes")
            print(f"  Quantum-safe   : {d['quantum_safe']}")
            if "security_level" in d:
                print(f"  Security level : {d['security_level']}")
            print()
        return

    vehicle.start_listening()

    profile = VEHICLE_PROFILES.get(args.id, {})
    logging.info(
        f"Starting vehicle {args.id} | type={vehicle.vehicle_type} | "
        f"speed={vehicle.speed:.1f} km/h | heading={vehicle.heading} deg"
    )

    try:
        count = 0
        while True:
            vehicle._update_position()

            # CAM every 2 seconds
            if count % 2 == 0:
                vehicle.broadcast_message(vehicle.generate_cam())

            # DENM every 5 seconds
            if count % 5 == 0:
                vehicle.broadcast_message(vehicle.generate_denm())

            time.sleep(1)
            count += 1

    except KeyboardInterrupt:
        vehicle.listening = False
        logging.info(f"Vehicle {args.id} stopped")


if __name__ == "__main__":
    main()
