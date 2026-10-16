# Dockerfile - UIT NT219 Cryptography Lab (Task 4: Containerize Project)
# Builds Static (.a) and Shared (.so) libraries with CMake (`-DAES_LIBRARY_TYPE=BOTH`)
# and runs all 5 verification suites:
#   1. AES FIPS 197 KAT (`main`)
#   2. NIST SP 800-38A & SP 800-38C Suite (`test_sp800_38a_38c`)
#   3. OpenSSL libcrypto EVP Cross-Verification & Benchmark (`test_openssl_crosscheck`)
#   4. C11 Language Import Suite (`test_c`)
#   5. Python 3 ctypes + cryptography Cross-Verification (`tests/test_import.py`)
#
# Usage:
#   docker build -t uit-nt219-aes-modes .
#   docker run --rm uit-nt219-aes-modes

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    libssl-dev \
    python3 \
    python3-cryptography \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app/modes

COPY cmake/ ./cmake/
COPY include/ ./include/
COPY src/ ./src/
COPY tests/ ./tests/
COPY CMakeLists.txt CMakeLists_AES_v3.txt README.md ./

# 1. Configure & build `build-gcc` with Lecturer Nguyen Ngoc Tu's CMake options
RUN cmake -S . -B build-gcc \
      -DCMAKE_CXX_COMPILER=g++ \
      -DCMAKE_BUILD_TYPE=Release \
      -DAES_BUILD_EXECUTABLE=ON \
      -DAES_LIBRARY_TYPE=BOTH \
    && cmake --build build-gcc --parallel

# 2. Configure & build `build-gcc-attn` with Lecturer Nguyen Ngoc Tu's CMake options
RUN cmake -S . -B build-gcc-attn \
      -DCMAKE_CXX_COMPILER=g++ \
      -DCMAKE_BUILD_TYPE=Release \
      -DAES_BUILD_EXECUTABLE=ON \
      -DAES_LIBRARY_TYPE=BOTH \
    && cmake --build build-gcc-attn --parallel

# Default container entrypoint: run CTest + detailed verification suites
CMD ["sh", "-c", "ctest --test-dir build-gcc-attn --output-on-failure && ./build-gcc-attn/test_sp800_38a_38c && ./build-gcc-attn/test_openssl_crosscheck && ./build-gcc-attn/test_c && python3 tests/test_import.py"]
