// -*- coding: utf-8 -*-
/**
 * sp800_38f.cpp - NIST SP 800-38F (Standard F): AES Key Wrap (KW / KWP) & RFC 8452 AES-GCM-SIV.
 * UIT NT219 Cryptography Lab - Task 2.
 */

#include "modes.h"

#include <algorithm>
#include <cstring>
#include <stdexcept>

modes::ByteVec modes::_kw_wrap_core(const ByteVec& P, const std::array<Byte, 8>& iv_init) {
    size_t n = P.size() / 8;
    if (n == 1) {
        ByteVec blk(16);
        std::copy(iv_init.begin(), iv_init.end(), blk.begin());
        std::copy(P.begin(), P.end(), blk.begin() + 8);
        return aes.encrypt(blk);
    }
    std::array<Byte, 8> A = iv_init;
    std::vector<std::array<Byte, 8>> R(n);
    for (size_t i = 0; i < n; ++i) {
        std::copy(P.begin() + i * 8, P.begin() + (i + 1) * 8, R[i].begin());
    }
    for (size_t j = 0; j < 6; ++j) {
        for (size_t i = 0; i < n; ++i) {
            ByteVec blk(16);
            std::copy(A.begin(), A.end(), blk.begin());
            std::copy(R[i].begin(), R[i].end(), blk.begin() + 8);
            ByteVec B = aes.encrypt(blk);
            uint64_t t = static_cast<uint64_t>(n * j + (i + 1));
            for (size_t k = 0; k < 8; ++k) {
                A[k] = static_cast<Byte>(B[k] ^ ((t >> (8 * (7 - k))) & 0xFF));
                R[i][k] = B[8 + k];
            }
        }
    }
    ByteVec C((n + 1) * 8);
    std::copy(A.begin(), A.end(), C.begin());
    for (size_t i = 0; i < n; ++i) {
        std::copy(R[i].begin(), R[i].end(), C.begin() + (i + 1) * 8);
    }
    return C;
}

std::pair<std::array<modes::Byte, 8>, modes::ByteVec> modes::_kw_unwrap_core(const ByteVec& C) {
    size_t n = (C.size() / 8) - 1;
    if (n == 1) {
        ByteVec B = aes.decrypt(C);
        std::array<Byte, 8> A{};
        std::copy(B.begin(), B.begin() + 8, A.begin());
        ByteVec P(B.begin() + 8, B.end());
        return {A, P};
    }
    std::array<Byte, 8> A{};
    std::copy(C.begin(), C.begin() + 8, A.begin());
    std::vector<std::array<Byte, 8>> R(n);
    for (size_t i = 0; i < n; ++i) {
        std::copy(C.begin() + (i + 1) * 8, C.begin() + (i + 2) * 8, R[i].begin());
    }
    for (int j = 5; j >= 0; --j) {
        for (int i = static_cast<int>(n) - 1; i >= 0; --i) {
            uint64_t t = static_cast<uint64_t>(n * static_cast<size_t>(j) + static_cast<size_t>(i + 1));
            ByteVec blk(16);
            for (size_t k = 0; k < 8; ++k) {
                blk[k] = static_cast<Byte>(A[k] ^ ((t >> (8 * (7 - k))) & 0xFF));
                blk[8 + k] = R[i][k];
            }
            ByteVec B = aes.decrypt(blk);
            std::copy(B.begin(), B.begin() + 8, A.begin());
            std::copy(B.begin() + 8, B.end(), R[i].begin());
        }
    }
    ByteVec P(n * 8);
    for (size_t i = 0; i < n; ++i) {
        std::copy(R[i].begin(), R[i].end(), P.begin() + i * 8);
    }
    return {A, P};
}

modes::ByteVec modes::key_wrap(const ByteVec& key_to_wrap, bool pad) {
    if (!pad) {
        if (key_to_wrap.size() < 16 || key_to_wrap.size() % 8 != 0) {
            throw std::invalid_argument(
                "AES-KW without padding requires key_to_wrap length >= 16 and multiple of 8 bytes."
            );
        }
        std::array<Byte, 8> iv = {0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6};
        return _kw_wrap_core(key_to_wrap, iv);
    }
    if (key_to_wrap.empty()) {
        throw std::invalid_argument("AES-KWP key_to_wrap must not be empty.");
    }
    uint32_t mli = static_cast<uint32_t>(key_to_wrap.size());
    std::array<Byte, 8> aiv = {
        0xA6, 0x59, 0x59, 0xA6,
        static_cast<Byte>((mli >> 24) & 0xFF),
        static_cast<Byte>((mli >> 16) & 0xFF),
        static_cast<Byte>((mli >> 8) & 0xFF),
        static_cast<Byte>(mli & 0xFF)
    };
    ByteVec P = key_to_wrap;
    while (P.size() % 8 != 0) {
        P.push_back(0x00);
    }
    return _kw_wrap_core(P, aiv);
}

modes::ByteVec modes::key_wrap(const std::string& key_to_wrap, bool pad) {
    return key_wrap(utf8_to_bytes(key_to_wrap), pad);
}

modes::ByteVec modes::key_unwrap(const ByteVec& wrapped_key, bool pad) {
    if (!pad) {
        if (wrapped_key.size() < 24 || wrapped_key.size() % 8 != 0) {
            throw std::invalid_argument("Invalid AES-KW wrapped_key length.");
        }
        auto [A, P] = _kw_unwrap_core(wrapped_key);
        std::array<Byte, 8> expected = {0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6};
        if (A != expected) {
            throw std::runtime_error("AES-KW integrity check failed.");
        }
        return P;
    }
    if (wrapped_key.size() < 16 || wrapped_key.size() % 8 != 0) {
        throw std::invalid_argument("Invalid AES-KWP wrapped_key length.");
    }
    auto [A, P] = _kw_unwrap_core(wrapped_key);
    if (A[0] != 0xA6 || A[1] != 0x59 || A[2] != 0x59 || A[3] != 0xA6) {
        throw std::runtime_error("AES-KWP AIV header check failed.");
    }
    uint32_t mli = (static_cast<uint32_t>(A[4]) << 24) |
                   (static_cast<uint32_t>(A[5]) << 16) |
                   (static_cast<uint32_t>(A[6]) << 8) |
                   static_cast<uint32_t>(A[7]);
    if (mli == 0 || mli > P.size() || (P.size() - mli) >= 8) {
        throw std::runtime_error("AES-KWP MLI length check failed.");
    }
    for (size_t i = mli; i < P.size(); ++i) {
        if (P[i] != 0x00) {
            throw std::runtime_error("AES-KWP non-zero padding check failed.");
        }
    }
    return ByteVec(P.begin(), P.begin() + mli);
}

// RFC 8452 AES-GCM-SIV helpers
modes::ByteVec modes::_byte_reverse_16(const ByteVec& b) {
    ByteVec out(b.rbegin(), b.rend());
    return out;
}

modes::ByteVec modes::_mulX_ghash(const ByteVec& V_in) {
    ByteVec V = V_in;
    bool lsb = (V[15] & 1) != 0;
    for (int j = 15; j > 0; --j) {
        V[j] = static_cast<Byte>((V[j] >> 1) | ((V[j - 1] & 1) << 7));
    }
    V[0] >>= 1;
    if (lsb) V[0] ^= 0xE1;
    return V;
}

modes::ByteVec modes::_polyval(const ByteVec& H, const std::vector<ByteVec>& blocks) {
    ByteVec H_rev = _mulX_ghash(_byte_reverse_16(H));
    ByteVec acc(16, 0x00);
    for (const auto& blk : blocks) {
        ByteVec rev_blk = _byte_reverse_16(blk);
        acc = _gf128_mul(_xor(acc, rev_blk), H_rev);
    }
    return _byte_reverse_16(acc);
}

std::pair<modes::ByteVec, modes::ByteVec> modes::_gcm_siv_derive_keys(const ByteVec& nonce) {
    if (key.size() != 16 && key.size() != 32) {
        throw std::invalid_argument("AES-GCM-SIV (RFC 8452) supports 16-byte or 32-byte keys.");
    }
    auto make_block = [&](uint32_t ctr) {
        ByteVec blk(16, 0x00);
        blk[0] = static_cast<Byte>(ctr & 0xFF);
        blk[1] = static_cast<Byte>((ctr >> 8) & 0xFF);
        blk[2] = static_cast<Byte>((ctr >> 16) & 0xFF);
        blk[3] = static_cast<Byte>((ctr >> 24) & 0xFF);
        std::copy(nonce.begin(), nonce.end(), blk.begin() + 4);
        ByteVec enc = aes.encrypt(blk);
        return ByteVec(enc.begin(), enc.begin() + 8);
    };
    ByteVec auth_key;
    for (uint32_t c = 0; c < 2; ++c) {
        auto half = make_block(c);
        auth_key.insert(auth_key.end(), half.begin(), half.end());
    }
    ByteVec enc_key;
    uint32_t blocks_needed = (key.size() == 16) ? 2 : 4;
    for (uint32_t c = 2; c < 2 + blocks_needed; ++c) {
        auto half = make_block(c);
        enc_key.insert(enc_key.end(), half.begin(), half.end());
    }
    return {auth_key, enc_key};
}

modes::ByteVec modes::_gcm_siv_compute_tag(AES& enc_aes,
                                           const ByteVec& auth_key,
                                           const ByteVec& nonce,
                                           const ByteVec& aad,
                                           const ByteVec& plaintext) {
    std::vector<ByteVec> blocks;
    auto push_padded = [&](const ByteVec& buf) {
        for (size_t i = 0; i < buf.size(); i += 16) {
            ByteVec blk(16, 0x00);
            size_t n = std::min<size_t>(16, buf.size() - i);
            std::copy(buf.begin() + i, buf.begin() + i + n, blk.begin());
            blocks.push_back(blk);
        }
    };
    push_padded(aad);
    push_padded(plaintext);

    ByteVec len_blk(16, 0x00);
    uint64_t a_bits = static_cast<uint64_t>(aad.size()) * 8ULL;
    uint64_t p_bits = static_cast<uint64_t>(plaintext.size()) * 8ULL;
    for (int i = 0; i < 8; ++i) {
        len_blk[i] = static_cast<Byte>((a_bits >> (8 * i)) & 0xFF);
        len_blk[8 + i] = static_cast<Byte>((p_bits >> (8 * i)) & 0xFF);
    }
    blocks.push_back(len_blk);

    ByteVec S = _polyval(auth_key, blocks);
    for (size_t i = 0; i < 12; ++i) S[i] ^= nonce[i];
    S[15] &= 0x7F;
    return enc_aes.encrypt(S);
}

modes::ByteVec modes::_gcm_siv_ctr(AES& enc_aes, const ByteVec& tag, const ByteVec& input) {
    ByteVec ctr = tag;
    ctr[15] |= 0x80;
    uint32_t cval = static_cast<uint32_t>(ctr[0]) |
                    (static_cast<uint32_t>(ctr[1]) << 8) |
                    (static_cast<uint32_t>(ctr[2]) << 16) |
                    (static_cast<uint32_t>(ctr[3]) << 24);
    ByteVec out;
    out.reserve(input.size());
    for (size_t i = 0; i < input.size(); i += 16) {
        ctr[0] = static_cast<Byte>(cval & 0xFF);
        ctr[1] = static_cast<Byte>((cval >> 8) & 0xFF);
        ctr[2] = static_cast<Byte>((cval >> 16) & 0xFF);
        ctr[3] = static_cast<Byte>((cval >> 24) & 0xFF);
        ByteVec ks = enc_aes.encrypt(ctr);
        size_t n = std::min<size_t>(16, input.size() - i);
        for (size_t j = 0; j < n; ++j) {
            out.push_back(input[i + j] ^ ks[j]);
        }
        ++cval;
    }
    return out;
}

modes::ByteVec modes::gcm_siv_encrypt(const ByteVec& plaintext,
                                      const std::optional<ByteVec>& associated_data,
                                      const std::optional<ByteVec>& nonce,
                                      bool prepend_nonce) {
    ByteVec N = nonce.has_value() ? nonce.value() : random_bytes(12);
    if (N.size() != 12) {
        throw std::invalid_argument("AES-GCM-SIV nonce must be 12 bytes.");
    }
    ByteVec A = associated_data.value_or(ByteVec{});
    auto [auth_key, enc_key] = _gcm_siv_derive_keys(N);
    AES enc_aes(enc_key, static_cast<int>(enc_key.size() * 8));
    ByteVec tag = _gcm_siv_compute_tag(enc_aes, auth_key, N, A, plaintext);
    ByteVec ct = _gcm_siv_ctr(enc_aes, tag, plaintext);

    ByteVec out;
    if (prepend_nonce) out.insert(out.end(), N.begin(), N.end());
    out.insert(out.end(), ct.begin(), ct.end());
    out.insert(out.end(), tag.begin(), tag.end());
    return out;
}

modes::ByteVec modes::gcm_siv_encrypt(const std::string& plaintext,
                                      const std::optional<ByteVec>& associated_data,
                                      const std::optional<ByteVec>& nonce,
                                      bool prepend_nonce) {
    return gcm_siv_encrypt(utf8_to_bytes(plaintext), associated_data, nonce, prepend_nonce);
}

modes::ByteVec modes::gcm_siv_decrypt_bytes(const ByteVec& ciphertext_and_tag,
                                            const std::optional<ByteVec>& associated_data,
                                            const std::optional<ByteVec>& nonce,
                                            bool has_nonce) {
    ByteVec N;
    ByteVec body;
    if (has_nonce) {
        if (ciphertext_and_tag.size() < 28) {
            throw std::invalid_argument("AES-GCM-SIV input with prepended nonce must contain nonce + ciphertext/tag.");
        }
        N.assign(ciphertext_and_tag.begin(), ciphertext_and_tag.begin() + 12);
        body.assign(ciphertext_and_tag.begin() + 12, ciphertext_and_tag.end());
    } else {
        if (!nonce.has_value()) {
            throw std::invalid_argument("nonce is required when has_nonce=false.");
        }
        N = nonce.value();
        if (N.size() != 12) throw std::invalid_argument("AES-GCM-SIV nonce must be 12 bytes.");
        if (ciphertext_and_tag.size() < 16) throw std::invalid_argument("AES-GCM-SIV input too short.");
        body = ciphertext_and_tag;
    }
    ByteVec A = associated_data.value_or(ByteVec{});
    size_t ct_len = body.size() - 16;
    ByteVec ct(body.begin(), body.begin() + ct_len);
    ByteVec tag_recv(body.begin() + ct_len, body.end());

    auto [auth_key, enc_key] = _gcm_siv_derive_keys(N);
    AES enc_aes(enc_key, static_cast<int>(enc_key.size() * 8));
    ByteVec pt = _gcm_siv_ctr(enc_aes, tag_recv, ct);
    ByteVec tag_calc = _gcm_siv_compute_tag(enc_aes, auth_key, N, A, pt);
    if (!_constant_time_equal(tag_recv, tag_calc)) {
        throw std::runtime_error("AES-GCM-SIV authentication failed: tag mismatch.");
    }
    return pt;
}

std::string modes::gcm_siv_decrypt(const ByteVec& ciphertext_and_tag,
                                   const std::optional<ByteVec>& associated_data,
                                   const std::optional<ByteVec>& nonce,
                                   bool has_nonce) {
    return bytes_to_utf8(gcm_siv_decrypt_bytes(ciphertext_and_tag, associated_data, nonce, has_nonce));
}
