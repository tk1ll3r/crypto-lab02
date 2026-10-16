# UIT NT219 AES Lab — Task 1

C++17 implementation of AES-128, AES-192, AES-256, and the ECB, CBC, CFB, OFB, and CTR modes. Uses the C++ standard library and includes tests based on NIST vectors.

## Build and run (Linux)

```bash
g++ -std=c++17 -O2 -Wall -Wextra -Wpedantic main.cpp -o aes_lab
./aes_lab
```

`main.cpp` includes `modes.cpp`, which includes `AES.cpp`; compile only `main.cpp` with this layout.

References: NIST FIPS 197 and NIST SP 800-38A. Educational project; not security-audited.
