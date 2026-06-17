# AI-Driven Adaptive Post-Quantum Security Framework for V2X Systems
## Technical Documentation

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [System Architecture](#2-system-architecture)
3. [Directory Structure](#3-directory-structure)
4. [Cryptographic Design](#4-cryptographic-design)
5. [Vehicle Fleet](#5-vehicle-fleet)
6. [SCMS Components](#6-scms-components)
7. [Dashboard](#7-dashboard)
8. [Running the System](#8-running-the-system)
9. [API Reference](#9-api-reference)
10. [Cryptographic Benchmark](#10-cryptographic-benchmark)
11. [Key Updates Applied](#11-key-updates-applied)

---

## 1. Project Overview

This project implements a V2X (Vehicle-to-Everything) security framework combining:

- **Classical cryptography** (ECDSA-P256-SHA256) for high-frequency CAM messages
- **Post-quantum cryptography** (CRYSTALS-Dilithium3, NIST FIPS 204) for safety-critical DENM messages
- **SCMS** (Security Credential Management System) architecture per ETSI TS 102 941
- **Real-time dashboard** for monitoring live V2X traffic

The system simulates a 7-vehicle fleet on the Detroit I-94 corridor with realistic movement, message broadcasting, and cryptographic signing.

---

## 2. System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        V2X Network                          │
│                                                             │
│  ┌──────────┐  CAM (ECDSA)    ┌──────────────────────────┐ │
│  │ Vehicle  │ ─────────────── │                          │ │
│  │  Fleet   │  DENM (Dilith3) │   Dashboard (port 8000)  │ │
│  │ (7 nodes)│ ─────────────── │   UDP listener :5008     │ │
│  └──────────┘                 └──────────────────────────┘ │
│       │                                                     │
│       │ Registration / Certificate requests                 │
│       ▼                                                     │
│  ┌─────────────────────────────────────────────────────┐   │
│  │               SCMS (7 microservices)                │   │
│  │  Root CA → ICA → PCA → RA → MA → LA1 → LA2         │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### Message Flow

```
Vehicle starts
    │
    ├─ Every 2 seconds ──► generate_cam()
    │                          │
    │                    ECDSA-P256-SHA256 sign
    │                          │
    │                    UDP broadcast → Dashboard :5008
    │
    └─ Every 5 seconds ──► generate_denm()
                               │
                         CRYSTALS-Dilithium3 sign
                               │
                         UDP broadcast → Dashboard :5008
```

---

## 3. Directory Structure

```
V2X-Security-Architecture/
│
├── vehicles/
│   └── vehicle.py          # Vehicle node: crypto, movement, broadcasting
│
├── scms/
│   ├── root_ca.py          # Root Certificate Authority (port 5001)
│   ├── intermediate_ca.py  # Intermediate CA (port 5002)
│   ├── pca.py              # Pseudonym CA — real ECDSA certs (port 5005)
│   ├── registration_authority.py  # RA (port 5003)
│   ├── misbehavior_authority.py   # MA + CRL (port 5004)
│   ├── linkage_auth.py     # Linkage Authority 1 (port 6001)
│   └── linkage_auth_2.py   # Linkage Authority 2 (port 6002)
│
├── dashboard/
│   ├── app.py              # Flask server + UDP listener (port 8000)
│   └── static/
│       └── index.html      # Real-time monitoring UI
│
├── infrastructure/
│   └── rse.py              # Roadside Equipment node
│
├── requirements.txt        # Python dependencies
├── docker-compose.yml      # Full stack orchestration (7 vehicles)
├── Dockerfile              # Container image
├── run_local.bat           # One-click local launcher (Windows)
├── test_v2x.py             # Integration test suite (10 tests)
└── DOCUMENTATION.md        # This file
```

---

## 4. Cryptographic Design

### Two-layer crypto strategy

V2X messages come in two types with different security requirements:

| Message | Frequency | Stakes | Algorithm | Key size | Sig size |
|---|---|---|---|---|---|
| CAM | Every 2s | Routine awareness | ECDSA-P256-SHA256 | 33 B | ~71 B |
| DENM | Every 5s | Safety-critical alert | CRYSTALS-Dilithium3 | 1952 B | 3293 B |

### CAM — ECDSA-P256-SHA256 (`vehicles/vehicle.py:70`)

```python
# Key generated once at vehicle startup
self.cam_private_key = ec.generate_private_key(ec.SECP256R1())

# Signing (every 2 seconds)
msg_bytes = json.dumps(cam_data, sort_keys=True).encode()
sig_bytes = self.cam_private_key.sign(msg_bytes, ec.ECDSA(hashes.SHA256()))
```

- Uses the `cryptography` Python library (wraps OpenSSL)
- Signature is deterministic per message content
- Public key embedded in every CAM so any receiver can verify
- **Not quantum-safe** — chosen for speed on high-frequency messages

### DENM — CRYSTALS-Dilithium3 (`vehicles/vehicle.py:108`)

```python
# Key pair generated once at vehicle startup
self.pqc_public_key, self.pqc_secret_key = Dilithium3.keygen()

# Signing (every 5 seconds)
msg_bytes = json.dumps(denm_data, sort_keys=True).encode()
sig_bytes = Dilithium3.sign(self.pqc_secret_key, msg_bytes)
signature = base64.b64encode(sig_bytes).decode()
```

- Uses `dilithium-py` — pure Python reference implementation of NIST FIPS 204
- CRYSTALS-Dilithium3 = NIST security level 3 (equivalent to AES-192)
- Based on Module Learning With Errors (MLWE) lattice problem
- Resistant to both classical and quantum computer attacks
- **Quantum-safe** — chosen for safety-critical messages that must remain secure long-term

### Verification

Both message types include full verification methods:

```python
vehicle.verify_cam(cam_json)    # True / False
vehicle.verify_denm(denm_json)  # True / False / None (if library absent)
```

Tampered messages are cryptographically rejected — demonstrated in `test_v2x.py`.

---

## 5. Vehicle Fleet

Seven vehicles simulate the Detroit I-94 corridor and urban grid. Each has a fixed profile defined in `VEHICLE_PROFILES` (`vehicles/vehicle.py:34`).

| ID | Type | Speed | Heading | Starting Position | DENM Events |
|---|---|---|---|---|---|
| 1 | Car | 72 km/h | East (90°) | 42.3314, -83.0458 | emergency_braking, accident |
| 2 | Car | 65 km/h | East (88°) | 42.3320, -83.0520 | obstacle, accident |
| 3 | Truck | 48 km/h | West (270°) | 42.3308, -83.0390 | slow_vehicle, roadwork |
| 4 | Car | 80 km/h | NE (45°) | 42.3350, -83.0470 | emergency_braking, hazard |
| 5 | Emergency | 110 km/h | East (90°) | 42.3295, -83.0600 | emergency_vehicle |
| 6 | Bus | 38 km/h | South (180°) | 42.3340, -83.0480 | passenger_boarding, obstacle |
| 7 | Truck | 44 km/h | East (92°) | 42.3302, -83.0550 | slow_vehicle, obstacle, roadwork |

### Movement Simulation (`vehicles/vehicle.py:100`)

Position updates every second using real heading/speed math:

```python
def _update_position(self):
    heading_rad   = math.radians(self.heading)
    speed_m_per_s = self.speed / 3.6
    self.lat += (speed_m_per_s * math.cos(heading_rad)) / 111_320.0
    self.lon += (speed_m_per_s * math.sin(heading_rad)) / (
        111_320.0 * math.cos(math.radians(self.lat))
    )
    self.speed = max(0.0, self.speed + random.uniform(-0.8, 0.8))
```

- 1 degree latitude ≈ 111,320 m
- 1 degree longitude ≈ 111,320 × cos(latitude) m
- Speed varies ±0.8 km/h per second (realistic fluctuation)

### DENM Event Severity Table

```python
EVENT_SEVERITY = {
    "accident":              8,
    "emergency_braking":     7,
    "emergency_vehicle":     9,
    "obstacle":              5,
    "hazard":                6,
    "slow_vehicle":          3,
    "roadwork":              4,
    "passenger_boarding":    2,
}
```

---

## 6. SCMS Components

The Security Credential Management System follows the ETSI TS 102 941 architecture. All services are Flask microservices.

### Root CA (`scms/root_ca.py` — port 5001)

- Generates a self-signed ECDSA-P256 certificate valid for 10 years
- Saves certificate to `data/certs/root_ca.pem`
- Trust anchor for the entire SCMS chain

### Intermediate CA (`scms/intermediate_ca.py` — port 5002)

- Issues certificates to PCAs
- Verifies Root CA health before issuing
- Certificates valid for 1 year

### Pseudonym CA (`scms/pca.py` — port 5005)

The PCA issues **real cryptographically-signed** pseudonym certificates:

```python
# PCA has its own ECDSA-P256 signing key
self.signing_key = ec.generate_private_key(ec.SECP256R1())

# Each certificate gets a fresh ephemeral key pair (unlinkable pseudonyms)
pseudonym_key = ec.generate_private_key(ec.SECP256R1())

# PCA signs the certificate payload
pca_sig = self.signing_key.sign(cert_payload, ec.ECDSA(hashes.SHA256()))
```

Key privacy property: **each certificate uses a different key pair** so certificates cannot be linked back to the same vehicle (unlinkable pseudonyms per ETSI TS 102 941).

Endpoints:
- `POST /issue_pseudonym_cert` — issues a signed pseudonym cert
- `POST /verify_cert` — verifies a cert's PCA signature
- `POST /revoke_certificate` — revokes and notifies MA

### Registration Authority (`scms/registration_authority.py` — port 5003)

- Registers vehicles with their public key
- Coordinates with PCA and Linkage Authorities
- Maintains in-memory vehicle database

### Misbehavior Authority (`scms/misbehavior_authority.py` — port 5004)

- Maintains Certificate Revocation List (CRL)
- Accepts misbehavior reports from PCA and RA
- Exposes `GET /crl` for revocation list

### Linkage Authorities (`scms/linkage_auth.py`, `linkage_auth_2.py` — ports 6001, 6002)

- Two independent authorities prevent single point of failure
- Generate linkage seeds for vehicle batches
- Privacy mechanism: prevents tracking across pseudonym changes

---

## 7. Dashboard

Flask server (`dashboard/app.py`) on **port 8000** with a real-time web UI.

### How messages arrive

```
Vehicle ──UDP:5008──► dashboard/app.py udp_listener() ──► messages[] ──► /messages API
```

The UDP receive buffer is **65535 bytes** — large enough for Dilithium3 DENM messages (~7KB after base64 encoding).

### API Endpoints

| Endpoint | Description |
|---|---|
| `GET /` | Main dashboard UI |
| `GET /health` | Liveness check |
| `GET /messages` | Last 20 received messages (JSON) |
| `GET /stats` | CAM/DENM counts, classical/PQC breakdown |
| `GET /clear` | Clear message buffer |
| `GET /api/overview` | Active vehicles, cert counts, uptime |
| `GET /api/components` | SCMS component statuses |
| `GET /api/charts/distribution` | Classical vs PQC message distribution |
| `GET /api/charts/provisioning` | Certificate provisioning timeline |
| `GET /api/activity` | Recent system activity log |
| `GET /api/misbehavior` | Misbehavior reports |
| `GET /api/fleet` | Fleet vehicle statuses |

### Crypto counting

```python
classical_count = sum(1 for m in messages if m.get('crypto') == 'classical')
pqc_count       = sum(1 for m in messages if m.get('crypto') in ('post_quantum', 'pqc'))
```

Accepts both `post_quantum` (current) and `pqc` (legacy) labels.

---

## 8. Running the System

### Prerequisites

```
Python 3.9+
pip install -r requirements.txt
```

Key dependencies:
- `cryptography>=41.0.0` — ECDSA-P256 for CAM
- `dilithium-py>=1.0.0` — CRYSTALS-Dilithium3 for DENM
- `flask>=2.3.0` — SCMS services and dashboard
- `numpy>=1.24.0` — numeric operations

### Option A — One click (Windows)

Double-click `run_local.bat`

Opens 8 windows: dashboard + 7 vehicles. Dashboard available at `http://localhost:8000`.

### Option B — Manual terminals

**Terminal 1 — Dashboard (start first)**
```bash
python dashboard/app.py
```

**Terminals 2–8 — Vehicles**
```bash
python vehicles/vehicle.py --id 1
python vehicles/vehicle.py --id 2
python vehicles/vehicle.py --id 3
python vehicles/vehicle.py --id 4
python vehicles/vehicle.py --id 5
python vehicles/vehicle.py --id 6
python vehicles/vehicle.py --id 7
```

### Option C — Docker (full stack)

```bash
docker-compose up --build
```

Dashboard at `http://localhost:9001`.

### Run Tests

```bash
python test_v2x.py
```

Expected: **10 passed, 0 failed**

### Crypto Benchmark

```bash
python vehicles/vehicle.py --id 1 --benchmark
```

---

## 9. API Reference

### Vehicle Message Formats

**CAM (Cooperative Awareness Message)**
```json
{
  "data": {
    "message_type": "CAM",
    "vehicle_id": 1,
    "vehicle_type": "car",
    "timestamp": 1718612345.123,
    "position": [42.331401, -83.044583],
    "speed": 72.3,
    "heading": 90.0,
    "acceleration": 0.12,
    "crypto_type": "ECDSA-P256-SHA256"
  },
  "signature": "3045022100...hex...",
  "public_key": "02abcdef...hex...",
  "crypto": "classical"
}
```

**DENM (Decentralized Environmental Notification Message)**
```json
{
  "data": {
    "message_type": "DENM",
    "vehicle_id": 5,
    "vehicle_type": "emergency",
    "event_type": "emergency_vehicle",
    "severity": 9,
    "position": [42.329501, -83.059874],
    "timestamp": 1718612350.456,
    "validity": 1718612650.456,
    "crypto_type": "CRYSTALS-DILITHIUM3"
  },
  "signature": "base64-encoded-3293-byte-dilithium3-signature...",
  "public_key": "base64-encoded-1952-byte-dilithium3-public-key...",
  "crypto": "post_quantum",
  "pqc_algorithm": "CRYSTALS-DILITHIUM3"
}
```

### PCA Certificate Format

```json
{
  "certificate_id": "psnym_1_a3f2c1b0",
  "vehicle_id": "1",
  "issuer": "PCA",
  "issuer_public_key": "02abcdef...hex...",
  "not_before": "2026-06-17T10:00:00",
  "not_after": "2026-06-24T10:00:00",
  "validity_period": "7 days",
  "crypto_algorithm": "ECDSA-P256-SHA256",
  "pseudonym_public_key": "03fedcba...hex...",
  "pseudonym_private_key": "308187...hex...",
  "pca_signature": "304502...hex...",
  "status": "issued"
}
```

---

## 10. Cryptographic Benchmark

Run with: `python vehicles/vehicle.py --id 1 --benchmark`

| Algorithm | Sign time | Signature size | Public key size | Quantum-safe |
|---|---|---|---|---|
| ECDSA-P256-SHA256 | ~0.2 ms | 71 bytes | 33 bytes | No |
| CRYSTALS-Dilithium3 | ~100 ms* | 3,293 bytes | 1,952 bytes | Yes (NIST Level 3) |

*Pure Python reference implementation (`dilithium-py`). Production C library (`liboqs`) achieves <1 ms.

**Design rationale:** CAM messages are sent every 2 seconds from every vehicle — ECDSA's 0.2ms keeps the network responsive. DENM safety alerts are sent every 5 seconds and must remain secure against future quantum computers — Dilithium3's larger signature is an acceptable cost for long-term protection.

---

## 11. Key Updates Applied

This section documents changes made from the original codebase.

### Fix 1 — Real CRYSTALS-Dilithium3 for DENM (Critical)

**Before:** `hashlib.sha512(message)` labeled as `CRYSTALS-DILITHIUM2-SIM` — SHA-512 is a hash function, not a signature scheme, and provides no quantum resistance.

**After:** Real `Dilithium3.sign()` and `Dilithium3.verify()` using `dilithium-py`, a reference implementation of NIST FIPS 204. Every DENM carries a genuine 3,293-byte lattice-based signature.

Files changed: `vehicles/vehicle.py`, `requirements.txt`

---

### Fix 2 — Real ECDSA for CAM

**Before:** `hashlib.sha256(message)` used as a "signature" — a hash is not a signature. The ECDSA private key was generated but never used.

**After:** `cam_private_key.sign(msg_bytes, ec.ECDSA(hashes.SHA256()))` — the private key now actually signs the message. Tampered messages are cryptographically rejected.

Files changed: `vehicles/vehicle.py`

---

### Fix 3 — Real ECDSA pseudonym certificates in PCA

**Before:** PCA returned a JSON dict with hardcoded strings — no actual key material, no real signature.

**After:** PCA generates a fresh ECDSA-P256 ephemeral keypair per certificate, signs the certificate payload with its own private key, and exposes `/verify_cert` to prove authenticity. Implements the unlinkable pseudonym property required by ETSI TS 102 941.

Files changed: `scms/pca.py`

---

### Fix 4 — 7 vehicle fleet with realistic profiles

**Before:** 2 generic vehicles with fixed position and no movement.

**After:** 7 vehicles across 4 types (car, truck, emergency, bus) with:
- Individual starting positions on the Detroit I-94 corridor
- Realistic speeds (38–110 km/h) and headings
- GPS position updates every second using real heading/speed math
- Type-appropriate DENM events (emergency vehicle triggers `emergency_vehicle`, trucks trigger `slow_vehicle`/`roadwork`, etc.)

Files changed: `vehicles/vehicle.py`, `docker-compose.yml`

---

### Fix 5 — Dashboard UDP buffer

**Before:** `sock.recvfrom(1024)` — DENM messages (~7KB with Dilithium3 signature) were silently truncated, causing JSON parse failures. DENMs never appeared in the dashboard.

**After:** `sock.recvfrom(65535)` — full messages received correctly.

Files changed: `dashboard/app.py`

---

### Fix 6 — Dashboard host default

**Before:** `DASHBOARD_HOST` defaulted to `"dashboard"` (Docker service name) — vehicles running locally sent UDP to an unresolvable hostname.

**After:** Defaults to `"localhost"` for local runs; Docker overrides via environment variable `DASHBOARD_HOST=dashboard`.

Files changed: `vehicles/vehicle.py`

---

### Removed — Anomaly Detection (IDS)

The `ids/` directory (anomaly_detector.py, service.py) has been removed. The project focuses on the cryptographic and SCMS contributions.
