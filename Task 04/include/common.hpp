#pragma once
/**
 * common.hpp - Common types and block/padding helpers in namespace `lab`
 * used by sp800_38a.hpp, sp800_38a.cpp, sp800_38c.hpp, and sp800_38c.cpp.
 * UIT NT219 Cryptography Lab - Task 2.
 */

#include "aes.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace lab {

using Byte = AES::Byte;
using Bytes = std::vector<Byte>;
using Block = AES::Block;

inline void check_iv(const Bytes& iv) {
    if (iv.size() != AES::BLOCK_SIZE) {
        throw std::invalid_argument("IV / initial counter block must be exactly 16 bytes");
    }
}

inline void check_aligned(const Bytes& d) {
    if (d.empty() || d.size() % AES::BLOCK_SIZE != 0) {
        throw std::invalid_argument("Data length must be a non-zero multiple of 16 bytes");
    }
}

inline Block block(const Bytes& d, std::size_t offset = 0) {
    if (offset + AES::BLOCK_SIZE > d.size()) {
        throw std::invalid_argument("Insufficient bytes to form a 16-byte AES block");
    }
    Block b{};
    std::copy_n(d.begin() + static_cast<std::ptrdiff_t>(offset), AES::BLOCK_SIZE, b.begin());
    return b;
}

inline Block xorblock(const Block& a, const Block& b) noexcept {
    Block out{};
    for (std::size_t i = 0; i < AES::BLOCK_SIZE; ++i) {
        out[i] = static_cast<Byte>(a[i] ^ b[i]);
    }
    return out;
}

inline void append(Bytes& out, const Block& blk) {
    out.insert(out.end(), blk.begin(), blk.end());
}

inline Bytes pad(const Bytes& in) {
    std::size_t rem = in.size() % AES::BLOCK_SIZE;
    std::size_t pad_len = (rem == 0) ? AES::BLOCK_SIZE : (AES::BLOCK_SIZE - rem);
    Bytes out = in;
    out.insert(out.end(), pad_len, static_cast<Byte>(pad_len));
    return out;
}

inline Bytes unpad(const Bytes& in) {
    if (in.empty() || in.size() % AES::BLOCK_SIZE != 0) {
        throw std::invalid_argument("PKCS#7 padded data must be a non-zero multiple of 16 bytes");
    }
    std::size_t pad_len = in.back();
    if (pad_len == 0 || pad_len > AES::BLOCK_SIZE) {
        throw std::invalid_argument("Invalid PKCS#7 padding length");
    }
    for (std::size_t i = in.size() - pad_len; i < in.size(); ++i) {
        if (in[i] != static_cast<Byte>(pad_len)) {
            throw std::invalid_argument("Invalid PKCS#7 padding byte value");
        }
    }
    return Bytes(in.begin(), in.end() - static_cast<std::ptrdiff_t>(pad_len));
}

inline Bytes from_hex(const std::string& hex) {
    return AES::hex_to_bytes(hex);
}

inline std::string to_hex(const Bytes& data) {
    return AES::bytes_to_hex(data);
}

inline std::string to_hex(const Block& data) {
    return AES::bytes_to_hex(data);
}

} // namespace lab
