# UIT NT219 Cryptography Lab — Task 3: OpenSSL Cross-Verification & Benchmark

Triển khai thư viện mã hóa khối **AES-128 / AES-192 / AES-256** ([NIST FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf)) cùng các chế độ hoạt động theo **Tiêu chuẩn A ([NIST SP 800-38A](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf))** và **Tiêu chuẩn C ([NIST SP 800-38C](https://csrc.nist.rip/publications/nistpubs/800-38C/SP800-38C.pdf))** bằng **C++17 Standard Library**.

## 1. Cấu trúc thư mục (`modes/`)

```text
modes/
├── build/                      # Thư mục build CMake mặc định
├── build-gcc/                  # Thư mục build với MinGW / GCC
├── build-gcc-attn/             # Thư mục build theo lệnh mẫu lớp ATTN của thầy Nguyễn Ngọc Tự
├── cmake/
│   ├── CompilerWarnings.cmake  # Thiết lập cờ biên dịch & tối ưu hóa đa nền tảng (-O2 -Wall -Wextra / /W4)
│   └── Toolchain-GCC.cmake     # Cấu hình trình biên dịch gcc / g++
├── include/
│   ├── aes.hpp                 # Header AES chuẩn theo tài liệu tham khảo của thầy (Block = std::array<Byte, 16>)
│   ├── AES.h                   # Header tương thích Task 1 & Task 2 (ByteVec = std::vector<Byte>)
│   ├── common.hpp              # Các kiểu dữ liệu & hàm tiện ích trong namespace lab (pad, unpad, block, xorblock)
│   ├── sp800_38a.hpp           # Header Tiêu chuẩn A trong namespace lab theo mẫu của thầy
│   ├── sp800_38c.hpp           # Header Tiêu chuẩn C (AES-CCM) trong namespace lab
│   ├── modes.h                 # Lớp modes tổng hợp (Tiêu chuẩn A, C, D, E, F)
│   └── c_api.h                 # C ABI Header (extern "C") để gọi từ C và Python ctypes
├── src/
│   ├── AES.cpp                 # Cài đặt lõi AES-128/192/256 hỗ trợ đồng thời Block và ByteVec
│   ├── sp800_38a.cpp           # Cài đặt Tiêu chuẩn A (cả namespace lab::* của thầy và lớp modes::*)
│   ├── sp800_38c.cpp           # Cài đặt Tiêu chuẩn C AES-CCM (cả namespace lab::* và lớp modes::*)
│   ├── sp800_38d.cpp           # Tiêu chuẩn D (NIST SP 800-38D: AES-GCM & GMAC)
│   ├── sp800_38e.cpp           # Tiêu chuẩn E (NIST SP 800-38E: AES-XTS)
│   ├── sp800_38f.cpp           # Tiêu chuẩn F (NIST SP 800-38F: AES-KW / KWP & RFC 8452 GCM-SIV)
│   ├── c_api.cpp               # Cài đặt C ABI Wrapper cho thư viện .a / .so / .dll
│   └── main.cpp                # Chương trình CLI và Known-Answer Tests (KAT)
├── tests/
│   ├── test_sp800_38a_38c.cpp  # Kiểm thử cả API namespace lab::* của thầy và modes::* (SP 800-38A & SP 800-38C)
│   ├── test_c.c                # Chương trình C kiểm thử liên kết thư viện C++ qua c_api.h
│   └── test_import.py          # Script Python nạp thư viện động (.so / .dll) qua ctypes
├── CMakeLists.txt              # File cấu hình CMake chính hỗ trợ -DAES_BUILD_EXECUTABLE & -DAES_LIBRARY_TYPE
├── CMakeLists_AES_v3.txt       # Bản sao cấu hình CMake v3 đa nền tảng
├── Dockerfile                  # Đóng gói container Ubuntu 22.04 tự động build và chạy toàn bộ test
└── README.md                   # Tài liệu hướng dẫn biên dịch, kiểm thử và sử dụng
```

## 2. Hướng dẫn biên dịch theo đúng lệnh CMake của Thầy Nguyễn Ngọc Tự

### Trên Windows (CMD với MSYS2 / MinGW64)

```cmd
cmake -S . -B build-gcc -G "MinGW Makefiles" ^
  -DCMAKE_CXX_COMPILER=D:/msys64/mingw64/bin/g++.exe ^
  -DCMAKE_BUILD_TYPE=Release ^
  -DAES_BUILD_EXECUTABLE=ON ^
  -DAES_LIBRARY_TYPE=BOTH

cmake -S . -B build-gcc-attn -G "MinGW Makefiles" ^
  -DCMAKE_CXX_COMPILER=D:/msys64/mingw64/bin/g++.exe ^
  -DCMAKE_BUILD_TYPE=Release ^
  -DAES_BUILD_EXECUTABLE=ON ^
  -DAES_LIBRARY_TYPE=BOTH

cmake --build build-gcc-attn --parallel

ctest --test-dir build-gcc-attn --output-on-failure
```

### Trên Linux / WSL / macOS

```bash
cmake -S . -B build-gcc-attn \
  -DCMAKE_CXX_COMPILER=g++ \
  -DCMAKE_BUILD_TYPE=Release \
  -DAES_BUILD_EXECUTABLE=ON \
  -DAES_LIBRARY_TYPE=BOTH

cmake --build build-gcc-attn --parallel
ctest --test-dir build-gcc-attn --output-on-failure
```

### Các tùy chọn CMake được hỗ trợ

| Biến CMake | Giá trị hỗ trợ | Mặc định | Ý nghĩa |
| :--- | :--- | :--- | :--- |
| **`AES_LIBRARY_TYPE`** | `STATIC`, `SHARED`, `BOTH` | `BOTH` | Chọn build thư viện tĩnh (`.a`/`.lib`), thư viện động (`.so`/`.dll`), hoặc cả hai cùng lúc |
| **`AES_BUILD_EXECUTABLE`** | `ON`, `OFF` | `ON` | Bật/tắt biên dịch các file thực thi (`main`, `test_sp800_38a_38c`, `test_c`) |
| **`AES_BUILD_TESTS`** | `ON`, `OFF` | `ON` | Bật/tắt đăng ký bộ kiểm thử tự động với `ctest` |

## 3. Chạy trực tiếp từng bộ kiểm thử

```bash
# 1. Bộ kiểm thử chuyên sâu namespace lab::* (sp800_38a.hpp, sp800_38c.hpp) & modes::*
./build-gcc-attn/test_sp800_38a_38c

# 2. Chạy CLI kiểm thử tổng hợp (AES + Standards A, C, D, E, F)
./build-gcc-attn/main --all

# 3. Chạy kiểm thử import thư viện vào ngôn ngữ C
./build-gcc-attn/test_c

# 4. Chạy kiểm thử import thư viện động (.so / .dll) vào Python bằng ctypes
python3 tests/test_import.py
```
