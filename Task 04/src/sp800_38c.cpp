// -*- coding: utf-8 -*-
/**
 * sp800_38c.cpp - NIST SP 800-38C (Standard C): AES-CCM (Counter with CBC-MAC) Mode.
 *   Implements both `namespace lab` functions (sp800_38c.hpp) and `class modes` methods (modes.h).
 * Reference: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38c.pdf
 * UIT NT219 Cryptography Lab - Task 2.
 */

#include "sp800_38c.hpp"
#include "modes.h"

#include <algorithm>
#include <cstring>
#include <iostream>
#include <stdexcept>

namespace lab {

Bytes ccm_encrypt(const AES& aes, const Bytes& plaintext, const Bytes& nonce,
                  const Bytes& aad, std::size_t tag_len, bool prepend_nonce) {
    modes m(aes.key, false);
    return m.ccm_encrypt(plaintext, aad, nonce, tag_len, prepend_nonce);
}

Bytes ccm_decrypt(const AES& aes, const Bytes& ciphertext_and_tag, const Bytes& nonce,
                  const Bytes& aad, std::size_t tag_len, bool has_nonce) {
    modes m(aes.key, false);
    std::size_t n_len = nonce.empty() ? 13 : nonce.size();
    return m.ccm_decrypt_bytes(ciphertext_and_tag, aad, nonce, has_nonce, n_len, tag_len);
}

} // namespace lab

modes::ByteVec modes::_ccm_counter_block(const ByteVec& nonce, size_t counter_val) {
    size_t n = nonce.size();
    size_t q = 15 - n;
    ByteVec ctr(BLOCK_SIZE, 0x00);
    ctr[0] = static_cast<Byte>((q - 1) & 0x07);
    std::copy(nonce.begin(), nonce.end(), ctr.begin() + 1);
    for (size_t i = 0; i < q; ++i) {
        ctr[15 - i] = static_cast<Byte>((counter_val >> (8 * i)) & 0xFF);
    }
    return ctr;
}

modes::ByteVec modes::_ccm_cbc_mac(const ByteVec& plaintext,
                                   const ByteVec& aad,
                                   const ByteVec& nonce,
                                   size_t tag_length) {
    size_t n = nonce.size();
    size_t q = 15 - n;
    size_t p_len = plaintext.size();

    ByteVec b0(BLOCK_SIZE, 0x00);
    Byte flags = static_cast<Byte>(
        ((!aad.empty() ? 1 : 0) << 6) |
        (((tag_length - 2) / 2) << 3) |
        ((q - 1) & 0x07)
    );
    b0[0] = flags;
    std::copy(nonce.begin(), nonce.end(), b0.begin() + 1);
    for (size_t i = 0; i < q; ++i) {
        b0[15 - i] = static_cast<Byte>((p_len >> (8 * i)) & 0xFF);
    }

    ByteVec Y = aes.encrypt(b0);

    auto cbc_feed = [this, &Y](const ByteVec& buf) {
        for (size_t i = 0; i < buf.size(); i += BLOCK_SIZE) {
            ByteVec blk(BLOCK_SIZE, 0x00);
            size_t copy_len = std::min(BLOCK_SIZE, buf.size() - i);
            std::copy(buf.begin() + i, buf.begin() + i + copy_len, blk.begin());
            Y = aes.encrypt(_xor(Y, blk));
        }
    };

    if (!aad.empty()) {
        ByteVec formatted_aad;
        size_t a_len = aad.size();
        if (a_len < 0xFF00) {
            formatted_aad.push_back(static_cast<Byte>((a_len >> 8) & 0xFF));
            formatted_aad.push_back(static_cast<Byte>(a_len & 0xFF));
        } else {
            formatted_aad.push_back(0xFF);
            formatted_aad.push_back(0xFE);
            formatted_aad.push_back(static_cast<Byte>((a_len >> 24) & 0xFF));
            formatted_aad.push_back(static_cast<Byte>((a_len >> 16) & 0xFF));
            formatted_aad.push_back(static_cast<Byte>((a_len >> 8) & 0xFF));
            formatted_aad.push_back(static_cast<Byte>(a_len & 0xFF));
        }
        formatted_aad.insert(formatted_aad.end(), aad.begin(), aad.end());
        cbc_feed(formatted_aad);
    }

    if (!plaintext.empty()) {
        cbc_feed(plaintext);
    }

    return ByteVec(Y.begin(), Y.begin() + tag_length);
}

modes::ByteVec modes::ccm_encrypt(const ByteVec& plaintext,
                                  const std::optional<ByteVec>& associated_data,
                                  const std::optional<ByteVec>& nonce,
                                  size_t tag_length,
                                  bool prepend_nonce) {
    if (tag_length < 4 || tag_length > 16 || tag_length % 2 != 0) {
        throw std::invalid_argument("AES-CCM tag_length must be one of 4, 6, 8, 10, 12, 14, 16.");
    }
    ByteVec N = nonce.has_value() ? nonce.value() : random_bytes(13);
    if (N.size() < 7 || N.size() > 13) {
        throw std::invalid_argument("AES-CCM nonce length must be between 7 and 13 bytes.");
    }
    ByteVec A = associated_data.value_or(ByteVec{});

    ByteVec T = _ccm_cbc_mac(plaintext, A, N, tag_length);
    ByteVec S0 = aes.encrypt(_ccm_counter_block(N, 0));
    ByteVec U = _xor(T, ByteVec(S0.begin(), S0.begin() + tag_length));

    if (verbose) {
        std::cout << "[CCM Encrypt] Nonce=" << bytes_to_hex(N)
                  << " | CBC-MAC Tag=" << bytes_to_hex(U) << "\n";
    }

    ByteVec ct;
    auto blocks = _chunks(plaintext, BLOCK_SIZE);
    for (size_t i = 0; i < blocks.size(); ++i) {
        ByteVec ctr_blk = _ccm_counter_block(N, i + 1);
        ByteVec Si = aes.encrypt(ctr_blk);
        ByteVec c_blk = _xor(blocks[i], ByteVec(Si.begin(), Si.begin() + blocks[i].size()));
        if (verbose) {
            std::cout << "[CCM Encrypt Block " << (i + 1) << "] Ctr=" << bytes_to_hex(ctr_blk)
                      << " -> CT=" << bytes_to_hex(c_blk) << "\n";
        }
        ct.insert(ct.end(), c_blk.begin(), c_blk.end());
    }

    ByteVec out;
    if (prepend_nonce) {
        out.insert(out.end(), N.begin(), N.end());
    }
    out.insert(out.end(), ct.begin(), ct.end());
    out.insert(out.end(), U.begin(), U.end());
    return out;
}

modes::ByteVec modes::ccm_encrypt(const std::string& plaintext,
                                  const std::optional<ByteVec>& associated_data,
                                  const std::optional<ByteVec>& nonce,
                                  size_t tag_length,
                                  bool prepend_nonce) {
    return ccm_encrypt(utf8_to_bytes(plaintext), associated_data, nonce, tag_length, prepend_nonce);
}

modes::ByteVec modes::ccm_decrypt_bytes(const ByteVec& ciphertext_and_tag,
                                        const std::optional<ByteVec>& associated_data,
                                        const std::optional<ByteVec>& nonce,
                                        bool has_nonce,
                                        size_t nonce_length,
                                        size_t tag_length) {
    if (nonce_length < 7 || nonce_length > 13) {
        throw std::invalid_argument("nonce_length must be between 7 and 13 bytes.");
    }
    if (tag_length < 4 || tag_length > 16 || tag_length % 2 != 0) {
        throw std::invalid_argument("AES-CCM tag_length must be one of 4, 6, 8, 10, 12, 14, 16.");
    }

    ByteVec N;
    ByteVec body;
    if (has_nonce) {
        if (ciphertext_and_tag.size() < nonce_length + tag_length) {
            throw std::invalid_argument(
                "AES-CCM input with prepended nonce must contain nonce + ciphertext/tag."
            );
        }
        N.assign(ciphertext_and_tag.begin(), ciphertext_and_tag.begin() + nonce_length);
        body.assign(ciphertext_and_tag.begin() + nonce_length, ciphertext_and_tag.end());
    } else {
        if (!nonce.has_value()) {
            throw std::invalid_argument("nonce is required when has_nonce=false.");
        }
        N = nonce.value();
        if (N.size() < 7 || N.size() > 13) {
            throw std::invalid_argument("AES-CCM nonce length must be between 7 and 13 bytes.");
        }
        if (ciphertext_and_tag.size() < tag_length) {
            throw std::invalid_argument("AES-CCM input too short for tag.");
        }
        body = ciphertext_and_tag;
    }

    ByteVec A = associated_data.value_or(ByteVec{});
    size_t ct_len = body.size() - tag_length;
    ByteVec ct(body.begin(), body.begin() + ct_len);
    ByteVec U(body.begin() + ct_len, body.end());

    ByteVec pt;
    auto blocks = _chunks(ct, BLOCK_SIZE);
    for (size_t i = 0; i < blocks.size(); ++i) {
        ByteVec ctr_blk = _ccm_counter_block(N, i + 1);
        ByteVec Si = aes.encrypt(ctr_blk);
        ByteVec p_blk = _xor(blocks[i], ByteVec(Si.begin(), Si.begin() + blocks[i].size()));
        pt.insert(pt.end(), p_blk.begin(), p_blk.end());
    }

    ByteVec S0 = aes.encrypt(_ccm_counter_block(N, 0));
    ByteVec T_recv = _xor(U, ByteVec(S0.begin(), S0.begin() + tag_length));
    ByteVec T_calc = _ccm_cbc_mac(pt, A, N, tag_length);

    if (!_constant_time_equal(T_recv, T_calc)) {
        throw std::runtime_error("AES-CCM authentication failed: tag mismatch.");
    }
    return pt;
}

std::string modes::ccm_decrypt(const ByteVec& ciphertext_and_tag,
                               const std::optional<ByteVec>& associated_data,
                               const std::optional<ByteVec>& nonce,
                               bool has_nonce,
                               size_t nonce_length,
                               size_t tag_length) {
    return bytes_to_utf8(
        ccm_decrypt_bytes(ciphertext_and_tag, associated_data, nonce, has_nonce, nonce_length, tag_length)
    );
}
