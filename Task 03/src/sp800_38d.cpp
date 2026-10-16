// -*- coding: utf-8 -*-
/**
 * sp800_38d.cpp - NIST SP 800-38D (Standard D): AES-GCM and GMAC Mode.
 * UIT NT219 Cryptography Lab - Task 2.
 */

#include "modes.h"

#include <algorithm>
#include <iostream>
#include <stdexcept>

void modes::_increment_be_32(ByteVec& counter) noexcept {
    for (int i = 15; i >= 12; --i) {
        if (++counter[i] != 0) {
            break;
        }
    }
}

modes::ByteVec modes::_gf128_mul(const ByteVec& X, const ByteVec& Y) {
    ByteVec Z(16, 0x00);
    ByteVec V = Y;
    for (int i = 0; i < 128; ++i) {
        if ((X[i / 8] >> (7 - (i % 8))) & 1) {
            for (int j = 0; j < 16; ++j) Z[j] ^= V[j];
        }
        bool lsb = (V[15] & 1) != 0;
        for (int j = 15; j > 0; --j) {
            V[j] = static_cast<Byte>((V[j] >> 1) | ((V[j - 1] & 1) << 7));
        }
        V[0] >>= 1;
        if (lsb) {
            V[0] ^= 0xE1;
        }
    }
    return Z;
}

modes::ByteVec modes::_ghash(const ByteVec& H, const ByteVec& A, const ByteVec& C) {
    ByteVec Y(16, 0x00);
    auto process_buf = [&](const ByteVec& buf) {
        for (size_t i = 0; i < buf.size(); i += 16) {
            ByteVec blk(16, 0x00);
            size_t n = std::min<size_t>(16, buf.size() - i);
            std::copy(buf.begin() + i, buf.begin() + i + n, blk.begin());
            Y = _gf128_mul(_xor(Y, blk), H);
        }
    };
    process_buf(A);
    process_buf(C);

    ByteVec len_blk(16, 0x00);
    uint64_t a_bits = static_cast<uint64_t>(A.size()) * 8ULL;
    uint64_t c_bits = static_cast<uint64_t>(C.size()) * 8ULL;
    for (int i = 0; i < 8; ++i) {
        len_blk[7 - i] = static_cast<Byte>((a_bits >> (8 * i)) & 0xFF);
        len_blk[15 - i] = static_cast<Byte>((c_bits >> (8 * i)) & 0xFF);
    }
    return _gf128_mul(_xor(Y, len_blk), H);
}

modes::ByteVec modes::_gctr(ByteVec icb, const ByteVec& X) {
    if (X.empty()) return {};
    ByteVec out;
    out.reserve(X.size());
    auto blocks = _chunks(X, BLOCK_SIZE);
    for (size_t i = 0; i < blocks.size(); ++i) {
        ByteVec enc = aes.encrypt(icb);
        ByteVec y = _xor(blocks[i], ByteVec(enc.begin(), enc.begin() + blocks[i].size()));
        if (verbose) {
            std::cout << "[GCM GCTR Block " << (i + 1) << "] Ctr=" << bytes_to_hex(icb)
                      << " -> Out=" << bytes_to_hex(y) << "\n";
        }
        out.insert(out.end(), y.begin(), y.end());
        _increment_be_32(icb);
    }
    return out;
}

modes::ByteVec modes::gcm_encrypt(const ByteVec& plaintext,
                                  const std::optional<ByteVec>& associated_data,
                                  const std::optional<ByteVec>& nonce,
                                  bool prepend_nonce) {
    ByteVec N = nonce.has_value() ? nonce.value() : random_bytes(12);
    if (N.size() != 12) {
        throw std::invalid_argument("AES-GCM nonce should be 12 bytes for the standard fast path.");
    }
    ByteVec A = associated_data.value_or(ByteVec{});
    ByteVec H = aes.encrypt(ByteVec(16, 0x00));

    ByteVec J0 = N;
    J0.insert(J0.end(), {0x00, 0x00, 0x00, 0x01});

    ByteVec icb = J0;
    _increment_be_32(icb);
    ByteVec C = _gctr(icb, plaintext);
    ByteVec S = _ghash(H, A, C);
    ByteVec T = _xor(aes.encrypt(J0), S);

    if (verbose) {
        std::cout << "[GCM Encrypt] H=" << bytes_to_hex(H)
                  << " | J0=" << bytes_to_hex(J0)
                  << " | Tag=" << bytes_to_hex(T) << "\n";
    }

    ByteVec out;
    if (prepend_nonce) {
        out.insert(out.end(), N.begin(), N.end());
    }
    out.insert(out.end(), C.begin(), C.end());
    out.insert(out.end(), T.begin(), T.end());
    return out;
}

modes::ByteVec modes::gcm_encrypt(const std::string& plaintext,
                                  const std::optional<ByteVec>& associated_data,
                                  const std::optional<ByteVec>& nonce,
                                  bool prepend_nonce) {
    return gcm_encrypt(utf8_to_bytes(plaintext), associated_data, nonce, prepend_nonce);
}

modes::ByteVec modes::gcm_decrypt_bytes(const ByteVec& ciphertext_and_tag,
                                        const std::optional<ByteVec>& associated_data,
                                        const std::optional<ByteVec>& nonce,
                                        bool has_nonce) {
    ByteVec N;
    ByteVec body;
    if (has_nonce) {
        if (ciphertext_and_tag.size() < 12 + 16) {
            throw std::invalid_argument(
                "AES-GCM input with prepended nonce must contain nonce + ciphertext/tag."
            );
        }
        N.assign(ciphertext_and_tag.begin(), ciphertext_and_tag.begin() + 12);
        body.assign(ciphertext_and_tag.begin() + 12, ciphertext_and_tag.end());
    } else {
        if (!nonce.has_value()) {
            throw std::invalid_argument("nonce is required when has_nonce=false.");
        }
        N = nonce.value();
        if (N.size() != 12) {
            throw std::invalid_argument("AES-GCM nonce should be 12 bytes.");
        }
        if (ciphertext_and_tag.size() < 16) {
            throw std::invalid_argument("AES-GCM input must contain at least a 16-byte authentication tag.");
        }
        body = ciphertext_and_tag;
    }

    ByteVec A = associated_data.value_or(ByteVec{});
    size_t c_len = body.size() - 16;
    ByteVec C(body.begin(), body.begin() + c_len);
    ByteVec T_recv(body.begin() + c_len, body.end());

    ByteVec H = aes.encrypt(ByteVec(16, 0x00));
    ByteVec J0 = N;
    J0.insert(J0.end(), {0x00, 0x00, 0x00, 0x01});

    ByteVec S = _ghash(H, A, C);
    ByteVec T_calc = _xor(aes.encrypt(J0), S);
    if (!_constant_time_equal(T_recv, T_calc)) {
        throw std::runtime_error("AES-GCM authentication failed: tag mismatch.");
    }

    ByteVec icb = J0;
    _increment_be_32(icb);
    return _gctr(icb, C);
}

std::string modes::gcm_decrypt(const ByteVec& ciphertext_and_tag,
                               const std::optional<ByteVec>& associated_data,
                               const std::optional<ByteVec>& nonce,
                               bool has_nonce) {
    return bytes_to_utf8(gcm_decrypt_bytes(ciphertext_and_tag, associated_data, nonce, has_nonce));
}

modes::ByteVec modes::gmac(const ByteVec& authenticated_data,
                           const std::optional<ByteVec>& nonce,
                           bool prepend_nonce) {
    return gcm_encrypt(ByteVec{}, authenticated_data, nonce, prepend_nonce);
}

bool modes::gmac_verify(const ByteVec& authenticated_data,
                        const ByteVec& tag,
                        const std::optional<ByteVec>& nonce,
                        bool has_nonce) {
    try {
        if (has_nonce && tag.size() != 28) {
            throw std::invalid_argument("GMAC token with prepended nonce must be 12-byte nonce + 16-byte tag.");
        }
        (void)gcm_decrypt_bytes(tag, authenticated_data, nonce, has_nonce);
        return true;
    } catch (...) {
        return false;
    }
}
