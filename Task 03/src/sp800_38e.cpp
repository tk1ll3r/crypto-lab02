// -*- coding: utf-8 -*-
/**
 * sp800_38e.cpp - NIST SP 800-38E (Standard E): AES-XTS Mode for Block-Oriented Storage.
 * UIT NT219 Cryptography Lab - Task 2.
 */

#include "modes.h"

#include <algorithm>
#include <iostream>
#include <stdexcept>

void modes::_xts_mul_alpha(ByteVec& T) noexcept {
    Byte carry_in = 0;
    for (size_t i = 0; i < 16; ++i) {
        Byte next_carry = (T[i] >> 7) & 1;
        T[i] = static_cast<Byte>(((T[i] << 1) | carry_in) & 0xFF);
        carry_in = next_carry;
    }
    if (carry_in) {
        T[0] ^= 0x87;
    }
}

modes::ByteVec modes::xts_encrypt(const ByteVec& plaintext,
                                  const std::optional<ByteVec>& xts_key,
                                  const std::optional<ByteVec>& tweak,
                                  uint64_t data_unit_number) {
    if (plaintext.size() < BLOCK_SIZE) {
        throw std::invalid_argument("AES-XTS requires at least one full 16-byte block.");
    }
    ByteVec K1 = key;
    ByteVec K2 = key;
    if (xts_key.has_value()) {
        const ByteVec& full = xts_key.value();
        if (full.size() != 32 && full.size() != 64) {
            throw std::invalid_argument("AES-XTS requires a 32-byte or 64-byte double-length XTS key.");
        }
        size_t half = full.size() / 2;
        K1.assign(full.begin(), full.begin() + half);
        K2.assign(full.begin() + half, full.end());
        if (K1 == K2) {
            throw std::invalid_argument("In XTS mode duplicated keys (K1 == K2) are not allowed.");
        }
    } else {
        K2.back() ^= 0xA5;
    }

    AES aes1(K1, static_cast<int>(K1.size() * 8));
    AES aes2(K2, static_cast<int>(K2.size() * 8));

    ByteVec iv_blk(16, 0x00);
    if (tweak.has_value()) {
        iv_blk = _require_exact_block(tweak.value(), "tweak");
    } else {
        for (int i = 0; i < 8; ++i) {
            iv_blk[i] = static_cast<Byte>((data_unit_number >> (8 * i)) & 0xFF);
        }
    }

    ByteVec T = aes2.encrypt(iv_blk);
    size_t m = plaintext.size() / BLOCK_SIZE;
    size_t rem = plaintext.size() % BLOCK_SIZE;

    ByteVec out;
    out.reserve(plaintext.size());

    size_t full_blocks = (rem == 0) ? m : (m - 1);
    for (size_t i = 0; i < full_blocks; ++i) {
        ByteVec P(plaintext.begin() + i * 16, plaintext.begin() + (i + 1) * 16);
        ByteVec C = _xor(aes1.encrypt(_xor(P, T)), T);
        if (verbose) {
            std::cout << "[XTS Encrypt Block " << (i + 1) << "] Tweak=" << bytes_to_hex(T)
                      << " | PT=" << bytes_to_hex(P) << " -> CT=" << bytes_to_hex(C) << "\n";
        }
        out.insert(out.end(), C.begin(), C.end());
        _xts_mul_alpha(T);
    }

    if (rem > 0) {
        ByteVec T_prev = T;
        _xts_mul_alpha(T);
        ByteVec P_m1(plaintext.begin() + full_blocks * 16, plaintext.begin() + (full_blocks + 1) * 16);
        ByteVec CC = _xor(aes1.encrypt(_xor(P_m1, T_prev)), T_prev);

        ByteVec CP(CC.begin(), CC.begin() + rem);
        ByteVec PP(plaintext.begin() + (full_blocks + 1) * 16, plaintext.end());
        PP.insert(PP.end(), CC.begin() + rem, CC.end());

        ByteVec C_m1 = _xor(aes1.encrypt(_xor(PP, T)), T);
        out.insert(out.end(), C_m1.begin(), C_m1.end());
        out.insert(out.end(), CP.begin(), CP.end());
    }
    return out;
}

modes::ByteVec modes::xts_encrypt(const std::string& plaintext,
                                  const std::optional<ByteVec>& xts_key,
                                  const std::optional<ByteVec>& tweak,
                                  uint64_t data_unit_number) {
    return xts_encrypt(utf8_to_bytes(plaintext), xts_key, tweak, data_unit_number);
}

modes::ByteVec modes::xts_decrypt_bytes(const ByteVec& ciphertext,
                                        const std::optional<ByteVec>& xts_key,
                                        const std::optional<ByteVec>& tweak,
                                        uint64_t data_unit_number) {
    if (ciphertext.size() < BLOCK_SIZE) {
        throw std::invalid_argument("AES-XTS requires at least one full 16-byte block.");
    }
    ByteVec K1 = key;
    ByteVec K2 = key;
    if (xts_key.has_value()) {
        const ByteVec& full = xts_key.value();
        if (full.size() != 32 && full.size() != 64) {
            throw std::invalid_argument("AES-XTS requires a 32-byte or 64-byte double-length XTS key.");
        }
        size_t half = full.size() / 2;
        K1.assign(full.begin(), full.begin() + half);
        K2.assign(full.begin() + half, full.end());
        if (K1 == K2) {
            throw std::invalid_argument("In XTS mode duplicated keys (K1 == K2) are not allowed.");
        }
    } else {
        K2.back() ^= 0xA5;
    }

    AES aes1(K1, static_cast<int>(K1.size() * 8));
    AES aes2(K2, static_cast<int>(K2.size() * 8));

    ByteVec iv_blk(16, 0x00);
    if (tweak.has_value()) {
        iv_blk = _require_exact_block(tweak.value(), "tweak");
    } else {
        for (int i = 0; i < 8; ++i) {
            iv_blk[i] = static_cast<Byte>((data_unit_number >> (8 * i)) & 0xFF);
        }
    }

    ByteVec T = aes2.encrypt(iv_blk);
    size_t m = ciphertext.size() / BLOCK_SIZE;
    size_t rem = ciphertext.size() % BLOCK_SIZE;

    ByteVec out;
    out.reserve(ciphertext.size());

    size_t full_blocks = (rem == 0) ? m : (m - 1);
    for (size_t i = 0; i < full_blocks; ++i) {
        ByteVec C(ciphertext.begin() + i * 16, ciphertext.begin() + (i + 1) * 16);
        ByteVec P = _xor(aes1.decrypt(_xor(C, T)), T);
        out.insert(out.end(), P.begin(), P.end());
        _xts_mul_alpha(T);
    }

    if (rem > 0) {
        ByteVec T_m1 = T;
        _xts_mul_alpha(T);
        ByteVec C_m1(ciphertext.begin() + full_blocks * 16, ciphertext.begin() + (full_blocks + 1) * 16);
        ByteVec PP = _xor(aes1.decrypt(_xor(C_m1, T)), T);

        ByteVec P_m(PP.begin(), PP.begin() + rem);
        ByteVec CC(ciphertext.begin() + (full_blocks + 1) * 16, ciphertext.end());
        CC.insert(CC.end(), PP.begin() + rem, PP.end());

        ByteVec P_m1 = _xor(aes1.decrypt(_xor(CC, T_m1)), T_m1);
        out.insert(out.end(), P_m1.begin(), P_m1.end());
        out.insert(out.end(), P_m.begin(), P_m.end());
    }
    return out;
}
