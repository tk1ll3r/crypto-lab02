#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME="uit-nt219-aes-modes"

echo "=== [1/3] Building Docker Image: ${IMAGE_NAME} ==="
docker build -t "${IMAGE_NAME}" .

echo ""
echo "=== [2/3] Listing Compiled Libraries & Executables Inside Container ==="
docker run --rm "${IMAGE_NAME}" ls -lh build-gcc-attn/

echo ""
echo "=== [3/3] Running CTest + C++ + OpenSSL + C + Python ctypes Suites in Container ==="
docker run --rm "${IMAGE_NAME}"
