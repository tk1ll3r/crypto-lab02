# UIT NT219 Cryptography Lab — AES-LAB02

Lab 02 project for the **Cryptography (NT219)** course at the University of Information Technology (UIT, VNU-HCM). Implementation of the **Advanced Encryption Standard (AES)** ([NIST FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf)) block cipher and **Modes of Operation** according to NIST standards, cross-verification with OpenSSL, and containerized deployment with Docker.

---

## Tasks Summary (Tasks 1–4 & Task Bonus)

### 🔹 Task 01 — Core AES Implementation & Standard A Modes (SP 800-38A)
- **Objective**: Implement AES-128, AES-192, and AES-256 block ciphers using pure **C++17 Standard Library** (zero third-party dependencies).
- **Features**: Full support for **NIST SP 800-38A** modes: ECB, CBC, CFB (CFB-8, CFB-128), OFB, CTR, and PKCS#7 padding.
- **Build**: Direct standalone compilation using `g++ main.cpp -o aes_lab`.

### 🔹 Task 02 — Modular CMake Library & Standard C Mode (AES-CCM)
- **Objective**: Restructure into a modular CMake project architecture (`include/`, `src/`, `tests/`, `cmake/`).
- **Features**:
  - Implements **Standard C ([NIST SP 800-38C](https://csrc.nist.rip/publications/nistpubs/800-38C/SP800-38C.pdf))**: Authenticated Encryption with Associated Data (**AES-CCM** — Counter with CBC-MAC) supporting customizable Nonce (7..13B) and Tag (4..16B).
  - Builds both static library (`libaes_crypto.a`) and dynamic/shared library (`libaes_crypto.so`).
  - Provides a C ABI (`c_api.h`) allowing direct integration into **C** (`test_c.c`) and **Python** via `ctypes` (`test_import.py`).

### 🔹 Task 03 — OpenSSL Cross-Verification & Benchmark
- **Objective**: Verify cryptographic correctness and evaluate computational performance.
- **Features**:
  - Comprehensive byte-for-byte cross-verification suite comparing `libaes_crypto` against **OpenSSL 3.x EVP API** across all supported modes (ECB, CBC, CFB, OFB, CTR, CCM).
  - Throughput benchmark measuring encryption/decryption speeds (MB/s).

### 🔹 Task 04 — Containerization with Docker & Multi-Suite Verification
- **Objective**: Ensure complete environment reproducibility and automated multi-suite testing.
- **Features**:
  - Packaged via `Dockerfile` (Ubuntu 22.04, GCC, CMake, OpenSSL, Python 3) and `docker-compose.yml`.
  - Automatically builds and runs all 5 test suites (NIST KAT, SP 800-38A/C, OpenSSL crosscheck, C test, Python ctypes test) with a single command.

### 🔹 Task Bonus — Countering AES Static S-Box Attack (Dynamic S-Box)
- **Objective**: Mitigate cache-timing and side-channel vulnerabilities inherent in static substitution tables.
- **Features**:
  - Implements round-dependent Dynamic S-Box generation based on *Rahnama et al. (ACM SIN '13, DOI: [10.1145/2523514.2523544](https://doi.org/10.1145/2523514.2523544))*.
  - Dynamically computes round sub-key permutations via Left Circular Shift (`BuildLCS`) and derives bijective substitution tables (`Dbox` / `iDbox`).
  - Evaluated with NIST Modes of Operation (CBC, CTR, CCM, GCM) alongside performance benchmarking.

---

## Directory Structure

```text
AES-LAB02/
├── Task 01/             # Task 1: Standalone AES core & SP 800-38A (g++ build)
├── Task 02/             # Task 2: Modular CMake library, AES-CCM, Static/Shared Lib, C ABI, Python ctypes
├── Task 03/             # Task 3: OpenSSL EVP cross-verification & Throughput benchmark
├── Task 04/             # Task 4: Dockerfile, docker-compose.yml, automated verification scripts
├── Task Bonus/          # Task Bonus: Dynamic S-Box (ACM SIN '13) & side-channel countermeasures
├── docker-compose.yml   # Multi-service Docker Compose configuration
└── README.md            # Project overview & documentation
```

---

## Quick Start Guide

### 1. Task 01 (Compile with g++)
```bash
cd "Task 01"
g++ -std=c++17 -O2 -Wall -Wextra main.cpp -o aes_lab
./aes_lab
```

### 2. Task 02 & Task 03 (Build with CMake)
```bash
cd "Task 02"  # or cd "Task 03"
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DAES_BUILD_EXECUTABLE=ON -DAES_LIBRARY_TYPE=BOTH
cmake --build build -j$(nproc)

# Run verification test suites
./build/test_sp800_38a_38c
./build/test_c
python3 tests/test_import.py
```

### 3. Task 04 (Run with Docker & Docker Compose)
```bash
# Option 1: Docker Compose (recommended)
docker compose up

# Option 2: Docker build & run directly
docker build -t uit-nt219-aes-modes "Task 04"
docker run --rm uit-nt219-aes-modes
```

### 4. Task Bonus (Dynamic S-Box Execution)
```bash
cd "Task Bonus"
./main --bonus       # Run round-by-round Dynamic S-Box verification & KAT
./main --all         # Run AES KAT + All NIST Standards + Task Bonus
```
