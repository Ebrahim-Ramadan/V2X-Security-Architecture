import json
import logging
import time
import hashlib
import argparse
import base64
import os
import sys
import socket
import threading
import datetime

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
import requests

# Real CRYSTALS-Dilithium3 (NIST PQC standard) via dilithium-py
try:
    from dilithium_py.dilithium import Dilithium3
    PQC_AVAILABLE = True
except ImportError:
    PQC_AVAILABLE = False
    logging.warning("dilithium-py not installed — install with: pip install dilithium-py")

if sys.platform == "win32":
    BROADCAST_ADDR = "255.255.255.255"
else:
    BROADCAST_ADDR = "<broadcast>"


class Vehicle:
    def __init__(self, vehicle_id, ra_url="http://localhost:5003"):
        self.vehicle_id = vehicle_id
        self.ra_url = ra_url

        # Classical crypto for CAM: ECDSA-P256
        self.cam_private_key = ec.generate_private_key(ec.SECP256R1())
        self.cam_public_key_hex = self.cam_private_key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.CompressedPoint,
        ).hex()

        # Post-quantum crypto for DENM: CRYSTALS-Dilithium3
        if PQC_AVAILABLE:
            self.pqc_public_key, self.pqc_secret_key = Dilithium3.keygen()
            self.pqc_public_key_b64 = base64.b64encode(self.pqc_public_key).decode()
            logging.info(
                f"Vehicle {vehicle_id}: Dilithium3 key pair generated "
                f"(pk={len(self.pqc_public_key)}B, sk={len(self.pqc_secret_key)}B)"
            )
        else:
            self.pqc_public_key = b""
            self.pqc_secret_key = None
            self.pqc_public_key_b64 = ""

        self.setup_windows_sockets()
        logging.info(f"Vehicle {vehicle_id} initialized on {sys.platform}")

    def setup_windows_sockets(self):
        try:
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            if sys.platform == "win32":
                self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.broadcast_port = 5005
            self.listening = False
        except Exception as e:
            logging.error(f"Socket setup failed: {e}")

    def generate_cam(self):
        """Generate CAM signed with real ECDSA-P256-SHA256."""
        cam_data = {
            "message_type": "CAM",
            "vehicle_id": self.vehicle_id,
            "timestamp": time.time(),
            "position": [42.3314, -83.0458],
            "speed": 60.5,
            "heading": 90.0,
            "acceleration": 0.0,
            "crypto_type": "ECDSA-P256-SHA256",
        }

        msg_bytes = json.dumps(cam_data, sort_keys=True).encode()
        sig_bytes = self.cam_private_key.sign(msg_bytes, ec.ECDSA(hashes.SHA256()))

        return json.dumps({
            "data": cam_data,
            "signature": sig_bytes.hex(),
            "public_key": self.cam_public_key_hex,
            "crypto": "classical",
        })

    def generate_denm(self, event_type="accident", severity=3):
        """Generate DENM signed with real CRYSTALS-Dilithium3."""
        denm_data = {
            "message_type": "DENM",
            "vehicle_id": self.vehicle_id,
            "event_type": event_type,
            "severity": severity,
            "position": [42.3314, -83.0458],
            "timestamp": time.time(),
            "validity": time.time() + 300,
            "crypto_type": "CRYSTALS-DILITHIUM3" if PQC_AVAILABLE else "SHA512-SIM",
        }

        msg_bytes = json.dumps(denm_data, sort_keys=True).encode()

        if PQC_AVAILABLE:
            sig_bytes = Dilithium3.sign(self.pqc_secret_key, msg_bytes)
            signature = base64.b64encode(sig_bytes).decode()
            algorithm = "CRYSTALS-DILITHIUM3"
        else:
            # Fallback so the system still runs if dilithium-py is absent
            signature = hashlib.sha512(msg_bytes).hexdigest()
            algorithm = "SHA512-SIM"

        return json.dumps({
            "data": denm_data,
            "signature": signature,
            "public_key": self.pqc_public_key_b64,
            "crypto": "post_quantum",
            "pqc_algorithm": algorithm,
        })

    def verify_cam(self, cam_json: str) -> bool:
        """Verify a CAM message's ECDSA-P256 signature."""
        try:
            msg = json.loads(cam_json)
            cam_data = msg["data"]
            sig_bytes = bytes.fromhex(msg["signature"])
            pub_bytes = bytes.fromhex(msg["public_key"])

            pub_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub_bytes)
            msg_bytes = json.dumps(cam_data, sort_keys=True).encode()
            pub_key.verify(sig_bytes, msg_bytes, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    def verify_denm(self, denm_json: str):
        """Verify a DENM message's Dilithium3 signature. Returns None if library absent."""
        if not PQC_AVAILABLE:
            return None
        try:
            msg = json.loads(denm_json)
            denm_data = msg["data"]
            sig_bytes = base64.b64decode(msg["signature"])
            pub_key = base64.b64decode(msg["public_key"])
            msg_bytes = json.dumps(denm_data, sort_keys=True).encode()
            return Dilithium3.verify(pub_key, msg_bytes, sig_bytes)
        except Exception:
            return False

    def benchmark_crypto(self, iterations: int = 50) -> dict:
        """
        Benchmark ECDSA-P256 vs CRYSTALS-Dilithium3 sign performance.
        Returns a dict suitable for logging or paper tables.
        """
        results = {}
        payload = b"V2X benchmark payload - ETSI ITS V2X message"

        # ECDSA-P256-SHA256
        key = ec.generate_private_key(ec.SECP256R1())
        t0 = time.perf_counter()
        for _ in range(iterations):
            key.sign(payload, ec.ECDSA(hashes.SHA256()))
        ecdsa_ms = (time.perf_counter() - t0) / iterations * 1000
        sample_sig = key.sign(payload, ec.ECDSA(hashes.SHA256()))
        pub_bytes = key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
        )
        results["ECDSA-P256-SHA256"] = {
            "sign_ms": round(ecdsa_ms, 3),
            "sig_size_bytes": len(sample_sig),
            "pub_key_size_bytes": len(pub_bytes),
            "quantum_safe": False,
        }

        if PQC_AVAILABLE:
            pk, sk = Dilithium3.keygen()
            t0 = time.perf_counter()
            for _ in range(iterations):
                Dilithium3.sign(sk, payload)
            dil_ms = (time.perf_counter() - t0) / iterations * 1000
            sample_dil = Dilithium3.sign(sk, payload)
            results["CRYSTALS-DILITHIUM3"] = {
                "sign_ms": round(dil_ms, 3),
                "sig_size_bytes": len(sample_dil),
                "pub_key_size_bytes": len(pk),
                "quantum_safe": True,
                "security_level": "NIST Level 3",
            }

        return results

    def broadcast_message(self, message: str):
        """Broadcast via UDP and forward to the dashboard."""
        try:
            self.udp_socket.sendto(message.encode(), (BROADCAST_ADDR, self.broadcast_port))

            ds = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ds.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if sys.platform == "win32":
                ds.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            dashboard_host = os.environ.get("DASHBOARD_HOST", "dashboard")
            dashboard_port = int(os.environ.get("DASHBOARD_PORT", "5008"))
            ds.sendto(message.encode(), (dashboard_host, dashboard_port))
            ds.close()

            logging.info(f"Vehicle {self.vehicle_id} broadcast: {message[:80]}...")
        except Exception as e:
            logging.error(f"Broadcast error: {e}")

    def start_listening(self):
        self.listening = True
        t = threading.Thread(target=self._listen_thread, daemon=True)
        t.start()

    def _listen_thread(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", self.broadcast_port))
        sock.settimeout(1.0)
        while self.listening:
            try:
                data, addr = sock.recvfrom(65535)
                logging.info(f"Vehicle {self.vehicle_id} rx from {addr}: {data[:60]}...")
            except socket.timeout:
                continue
            except Exception as e:
                logging.error(f"Listen error: {e}")
        sock.close()


def main():
    parser = argparse.ArgumentParser(description="V2X Vehicle Node")
    parser.add_argument("--id", type=int, required=True, help="Vehicle ID")
    parser.add_argument("--ra-url", default="http://localhost:5003")
    parser.add_argument(
        "--benchmark", action="store_true",
        help="Run ECDSA vs Dilithium3 benchmark and exit",
    )
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
        print(f"Iterations per algorithm: 50\n")
        results = vehicle.benchmark_crypto()
        for algo, d in results.items():
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

    try:
        count = 0
        while True:
            if count % 2 == 0:
                cam = vehicle.generate_cam()
                vehicle.broadcast_message(cam)
            if count % 10 == 0:
                denm = vehicle.generate_denm()
                vehicle.broadcast_message(denm)
            time.sleep(1)
            count += 1
    except KeyboardInterrupt:
        vehicle.listening = False
        logging.info("Vehicle stopped")


if __name__ == "__main__":
    main()
