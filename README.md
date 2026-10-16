# UIT NT219 Cryptography Lab — AES-LAB02

Dự án Lab 02 môn **Mật mã học (NT219)** — Trường Đại học Công nghệ Thông tin (UIT, VNU-HCM). Triển khai thuật toán mã hóa khối **AES** ([NIST FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf)) và các chế độ hoạt động (**Modes of Operation**) theo các tiêu chuẩn NIST, đối sánh kiểm chuẩn OpenSSL và đóng gói Docker container.

---

## Tóm tắt 4 Task

### 🔹 Task 01 — Cài đặt lõi AES & Chế độ cơ sở (SP 800-38A)
- **Mục tiêu**: Cài đặt thuật toán mã hóa khối AES-128, AES-192, AES-256 bằng **C++17 Standard Library** (không phụ thuộc thư viện ngoài).
- **Tính năng**: Hỗ trợ đầy đủ các chế độ hoạt động theo **NIST SP 800-38A**: ECB, CBC, CFB (CFB-8, CFB-128), OFB, CTR cùng cơ chế đệm PKCS#7.
- **Biên dịch**: Đơn giản trực tiếp qua `g++ main.cpp -o aes_lab`.

### 🔹 Task 02 — Chuẩn hóa Thư viện CMake & Tiêu chuẩn C (AES-CCM)
- **Mục tiêu**: Tái cấu trúc dự án chuẩn modular (`include/`, `src/`, `tests/`, `cmake/`) và biên dịch với **CMake**.
- **Tính năng**:
  - Triển khai **Tiêu chuẩn C ([NIST SP 800-38C](https://csrc.nist.rip/publications/nistpubs/800-38C/SP800-38C.pdf))**: chế độ mã hóa xác thực **AES-CCM** (Counter with CBC-MAC) hỗ trợ AAD, Nonce (7..13B), Tag (4..16B).
  - Đóng gói đồng thời thư viện tĩnh (`libaes_crypto.a`) và thư viện liên kết động (`libaes_crypto.so`).
  - C ABI (`c_api.h`) cho phép nạp thư viện trực tiếp từ ngôn ngữ **C** (`test_c.c`) và **Python** (`ctypes`).

### 🔹 Task 03 — Đối sánh kiểm chuẩn OpenSSL & Benchmark
- **Mục tiêu**: Xác thực độ chính xác và đánh giá hiệu năng thuật toán.
- **Tính năng**:
  - Bộ kiểm thử đối sánh (Cross-Verification) từng byte giữa thư viện `libaes_crypto` và **OpenSSL 3.x EVP API** trên toàn bộ các chế độ: ECB, CBC, CFB, OFB, CTR, CCM.
  - Đo lường và so sánh hiệu năng xử lý (Throughput MB/s).

### 🔹 Task 04 — Container hóa với Docker & Tự động hóa kiểm thử
- **Mục tiêu**: Đảm bảo tính tái lập (reproducibility) và đóng gói môi trường hoàn chỉnh.
- **Tính năng**:
  - Xây dựng `Dockerfile` (Ubuntu 22.04, GCC, CMake, OpenSSL, Python) và `docker-compose.yml`.
  - Tự động hóa chạy toàn bộ 5 test suites (NIST KAT, SP 800-38A/C, OpenSSL crosscheck, C test, Python ctypes test) chỉ với 1 lệnh.

---

## Cấu trúc thư mục

```text
AES-LAB02/
├── Task 01/             # Code Task 1: AES core & SP 800-38A (g++ build)
├── Task 02/             # Code Task 2: CMake modular, AES-CCM, Static/Shared Lib, C ABI, Python ctypes
├── Task 03/             # Code Task 3: OpenSSL cross-verification & Benchmark throughput
├── Task 04/             # Code Task 4: Dockerfile, docker-compose.yml, verification scripts
├── Task Bonus/          # Thư mục mở rộng
├── docker-compose.yml   # Docker Compose chạy toàn bộ test và demo CLI
└── README.md            # Tài liệu tổng quan dự án
```

---

## Hướng dẫn chạy nhanh

### 1. Task 01 (Biên dịch trực tiếp với g++)
```bash
cd "Task 01"
g++ -std=c++17 -O2 -Wall -Wextra main.cpp -o aes_lab
./aes_lab
```

### 2. Task 02 & Task 03 (Biên dịch với CMake)
```bash
cd "Task 02"  # hoặc cd "Task 03"
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DAES_BUILD_EXECUTABLE=ON -DAES_LIBRARY_TYPE=BOTH
cmake --build build -j$(nproc)

# Chạy test suites
./build/test_sp800_38a_38c
./build/test_c
python3 tests/test_import.py
```

### 3. Task 04 (Chạy bằng Docker & Docker Compose)
```bash
# Cách 1: Sử dụng Docker Compose (khuyến nghị)
docker compose up

# Cách 2: Sử dụng Dockerfile trực tiếp
docker build -t uit-nt219-aes-modes "Task 04"
docker run --rm uit-nt219-aes-modes
```
