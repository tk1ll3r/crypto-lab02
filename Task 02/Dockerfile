# Dockerfile - Containerize UIT NT219 AES Lab Task 2 (Standards A & C in modes/ layout)
# Usage:
#   docker build -t uit-nt219-aes-modes .
#   docker run --rm uit-nt219-aes-modes

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app/modes

COPY cmake/ ./cmake/
COPY include/ ./include/
COPY src/ ./src/
COPY tests/ ./tests/
COPY CMakeLists.txt CMakeLists_AES_v3.txt README.md ./

# 1. Build default CMake out-of-source build (modes/build)
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j$(nproc)

# 2. Build explicit GCC toolchain build (modes/build-gcc)
RUN cmake -S . -B build-gcc -DCMAKE_TOOLCHAIN_FILE=cmake/Toolchain-GCC.cmake -DCMAKE_BUILD_TYPE=Release \
    && cmake --build build-gcc -j$(nproc)

# Run CTest + Standard A & C verification suites + C import + Python ctypes import
CMD ["sh", "-c", "ctest --test-dir build --output-on-failure && ./build/test_sp800_38a_38c && ./build/test_c && python3 tests/test_import.py"]
