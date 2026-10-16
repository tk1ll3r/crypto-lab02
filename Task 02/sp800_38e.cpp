// -*- coding: utf-8 -*-
/**
 * sp800_38e.cpp - Bộ tiêu chuẩn 4: NIST SP 800-38E / IEEE P1619 (AES-XTS)
 * Chế độ mã hóa chuyên dụng cho thiết bị lưu trữ (ổ cứng/sector) sử dụng khóa kép (K1, K2)
 * và kỹ thuật đánh cắp bản mã (Ciphertext Stealing) cho các block cuối không tròn 16 byte.
 *
 * Môn: Mật mã học (NT219 - UIT)
 * Giải thích cơ chế xử lý từng khối (Block-by-block) được comment chi tiết bên dưới.
 */

#include "modes.h"

#include <algorithm>
#include <iostream>
#include <stdexcept>

// KHỐI 1: PHÉP NHÂN TWEAK VỚI PHẦN TỬ NGUYÊN THỦY ALPHA TRONG GF(2^128) (LITTLE-ENDIAN)
// Sau mỗi Block thứ `q` trong cùng một Data Unit (sector), giá trị Tweak T_q được nhân với x (alpha)
// modulo đa thức x^128 + x^7 + x^2 + x + 1 (hằng số rút gọn 0x87 ở byte thấp nhất).

void modes::_xts_mul_alpha(ByteVec& T) noexcept {
    Byte carry = 0;
    for (size_t i = 0; i < 16; ++i) {
        Byte next_carry = (T[i] >> 7) & 1;
        T[i] = static_cast<Byte>((T[i] << 1) | carry);
        carry = next_carry;
    }
    if (carry) {
        T[0] ^= 0x87;
    }
}

// KHỐI 2: MÃ HÓA & GIẢI MÃ TỪNG BLOCK TRONG AES-XTS (NIST SP 800-38E)
// Nguyên lý từng Block:
//   - Khóa đầu vào XTS được chia đôi: K = K1 || K2 (K1 != K2).
//   - Khởi tạo Tweak ban đầu cho Block 0: T_0 = AES_Encrypt(K2, tweak_block_16_bytes).
//   - Với mỗi Block đầy đủ 16-byte thứ `q`:
//       + Mã hóa: C_q = AES_Encrypt(K1, P_q XOR T_q) XOR T_q
//       + Giải mã: P_q = AES_Decrypt(K1, C_q XOR T_q) XOR T_q
//       + Cập nhật Tweak cho Block tiếp theo: T_{q+1} = T_q * alpha
//   - Nếu dữ liệu có phần dư `b` byte ở cuối (0 < b < 16), áp dụng Ciphertext Stealing (CTS)
//     giữa Block áp chót (m-1) và phần dư cuối (m) để không làm tăng kích thước dữ liệu lưu trữ.

modes::ByteVec modes::xts_encrypt(const ByteVec& plaintext,
                                  const std::optional<ByteVec>& xts_key,
                                  const std::optional<ByteVec>& tweak,
                                  uint64_t data_unit_number) {
    ByteVec key_bytes = xts_key.has_value() ? xts_key.value() : this->key;
    if (key_bytes.size() != 32 && key_bytes.size() != 64) {
        throw std::invalid_argument("AES-XTS requires a 32-byte or 64-byte double-length XTS key.");
    }
    if (plaintext.size() < BLOCK_SIZE) {
        throw std::invalid_argument("AES-XTS requires at least one full 16-byte block.");
    }

    // Bước 1: Tách khóa kép thành K1 (mã hóa dữ liệu) và K2 (mã hóa tweak)
    size_t half = key_bytes.size() / 2;
    ByteVec k1(key_bytes.begin(), key_bytes.begin() + static_cast<std::ptrdiff_t>(half));
    ByteVec k2(key_bytes.begin() + static_cast<std::ptrdiff_t>(half), key_bytes.end());
    if (k1 == k2) {
        throw std::invalid_argument("In XTS mode duplicated keys (K1 == K2) are not allowed.");
    }

    AES aes1(k1, static_cast<int>(k1.size() * 8));
    AES aes2(k2, static_cast<int>(k2.size() * 8));

    // Bước 2: Mã hóa số thứ tự sector (Data Unit Number) bằng khóa K2 để tạo Tweak T_0
    ByteVec tweak_bytes(16, 0);
    if (tweak.has_value()) {
        tweak_bytes = _require_exact_block(tweak.value(), "tweak");
    } else {
        uint64_t dun = data_unit_number;
        for (size_t i = 0; i < 8; ++i) {
            tweak_bytes[i] = static_cast<Byte>((dun >> (8 * i)) & 0xFF);
        }
    }

    ByteVec T = aes2.encrypt(tweak_bytes);
    size_t m = plaintext.size() / BLOCK_SIZE;
    size_t b = plaintext.size() % BLOCK_SIZE;

    ByteVec out(plaintext.size());
    size_t full_blocks = (b == 0) ? m : (m - 1);

    // Bước 3: Mã hóa lần lượt các Block 16-byte hoàn chỉnh: C_q = AES_K1(P_q XOR T_q) XOR T_q
    for (size_t q = 0; q < full_blocks; ++q) {
        ByteVec P_q(plaintext.begin() + static_cast<std::ptrdiff_t>(q * 16),
                    plaintext.begin() + static_cast<std::ptrdiff_t>((q + 1) * 16));
        ByteVec C_q = _xor(aes1.encrypt(_xor(P_q, T)), T);
        if (this->verbose) {
            std::cout << "[XTS Encrypt Block " << q << "] Tweak=" << bytes_to_hex(T)
                      << " | PT=" << bytes_to_hex(P_q) << " -> CT=" << bytes_to_hex(C_q) << "\n";
        }
        std::copy(C_q.begin(), C_q.end(), out.begin() + static_cast<std::ptrdiff_t>(q * 16));
        _xts_mul_alpha(T);
    }

    // Bước 4: Nếu còn dư `b` byte lẻ ở cuối, thực hiện Ciphertext Stealing trên 2 Block cuối
    if (b > 0) {
        ByteVec T_m_minus_1 = T;
        _xts_mul_alpha(T);
        ByteVec T_m = T;

        ByteVec P_m_minus_1(plaintext.begin() + static_cast<std::ptrdiff_t>((m - 1) * 16),
                            plaintext.begin() + static_cast<std::ptrdiff_t>(m * 16));
        ByteVec CC = _xor(aes1.encrypt(_xor(P_m_minus_1, T_m_minus_1)), T_m_minus_1);

        // Mượn (16 - b) byte cuối của CC ghép vào sau phần lẻ P_m để tạo khối PP đủ 16 byte
        ByteVec PP(16);
        std::copy(plaintext.begin() + static_cast<std::ptrdiff_t>(m * 16), plaintext.end(), PP.begin());
        std::copy(CC.begin() + static_cast<std::ptrdiff_t>(b), CC.end(),
                  PP.begin() + static_cast<std::ptrdiff_t>(b));

        ByteVec C_m_minus_1 = _xor(aes1.encrypt(_xor(PP, T_m)), T_m);
        std::copy(C_m_minus_1.begin(), C_m_minus_1.end(),
                  out.begin() + static_cast<std::ptrdiff_t>((m - 1) * 16));
        std::copy(CC.begin(), CC.begin() + static_cast<std::ptrdiff_t>(b),
                  out.begin() + static_cast<std::ptrdiff_t>(m * 16));
    }

    return out;
}

modes::ByteVec modes::xts_encrypt(const std::string& plaintext,
                                  const std::optional<ByteVec>& xts_key,
                                  const std::optional<ByteVec>& tweak,
                                  uint64_t data_unit_number) {
    return xts_encrypt(_ensure_bytes(plaintext, "plaintext"), xts_key, tweak, data_unit_number);
}

modes::ByteVec modes::xts_decrypt_bytes(const ByteVec& ciphertext,
                                        const std::optional<ByteVec>& xts_key,
                                        const std::optional<ByteVec>& tweak,
                                        uint64_t data_unit_number) {
    ByteVec key_bytes = xts_key.has_value() ? xts_key.value() : this->key;
    if (key_bytes.size() != 32 && key_bytes.size() != 64) {
        throw std::invalid_argument("AES-XTS requires a 32-byte or 64-byte double-length XTS key.");
    }
    if (ciphertext.size() < BLOCK_SIZE) {
        throw std::invalid_argument("AES-XTS requires at least one full 16-byte block.");
    }

    size_t half = key_bytes.size() / 2;
    ByteVec k1(key_bytes.begin(), key_bytes.begin() + static_cast<std::ptrdiff_t>(half));
    ByteVec k2(key_bytes.begin() + static_cast<std::ptrdiff_t>(half), key_bytes.end());
    if (k1 == k2) {
        throw std::invalid_argument("In XTS mode duplicated keys (K1 == K2) are not allowed.");
    }

    AES aes1(k1, static_cast<int>(k1.size() * 8));
    AES aes2(k2, static_cast<int>(k2.size() * 8));

    ByteVec tweak_bytes(16, 0);
    if (tweak.has_value()) {
        tweak_bytes = _require_exact_block(tweak.value(), "tweak");
    } else {
        uint64_t dun = data_unit_number;
        for (size_t i = 0; i < 8; ++i) {
            tweak_bytes[i] = static_cast<Byte>((dun >> (8 * i)) & 0xFF);
        }
    }

    ByteVec T = aes2.encrypt(tweak_bytes);
    size_t m = ciphertext.size() / BLOCK_SIZE;
    size_t b = ciphertext.size() % BLOCK_SIZE;

    ByteVec out(ciphertext.size());
    size_t full_blocks = (b == 0) ? m : (m - 1);

    // Giải mã các Block 16-byte hoàn chỉnh: P_q = AES_Decrypt_K1(C_q XOR T_q) XOR T_q
    for (size_t q = 0; q < full_blocks; ++q) {
        ByteVec C_q(ciphertext.begin() + static_cast<std::ptrdiff_t>(q * 16),
                    ciphertext.begin() + static_cast<std::ptrdiff_t>((q + 1) * 16));
        ByteVec P_q = _xor(aes1.decrypt(_xor(C_q, T)), T);
        std::copy(P_q.begin(), P_q.end(), out.begin() + static_cast<std::ptrdiff_t>(q * 16));
        _xts_mul_alpha(T);
    }

    // Giải mã Ciphertext Stealing trên 2 Block cuối (dùng T_m trước rồi mới dùng T_{m-1})
    if (b > 0) {
        ByteVec T_m_minus_1 = T;
        _xts_mul_alpha(T);
        ByteVec T_m = T;

        ByteVec C_m_minus_1(ciphertext.begin() + static_cast<std::ptrdiff_t>((m - 1) * 16),
                            ciphertext.begin() + static_cast<std::ptrdiff_t>(m * 16));
        ByteVec PP = _xor(aes1.decrypt(_xor(C_m_minus_1, T_m)), T_m);

        ByteVec CC(16);
        std::copy(ciphertext.begin() + static_cast<std::ptrdiff_t>(m * 16), ciphertext.end(), CC.begin());
        std::copy(PP.begin() + static_cast<std::ptrdiff_t>(b), PP.end(),
                  CC.begin() + static_cast<std::ptrdiff_t>(b));

        ByteVec P_m_minus_1 = _xor(aes1.decrypt(_xor(CC, T_m_minus_1)), T_m_minus_1);
        std::copy(P_m_minus_1.begin(), P_m_minus_1.end(),
                  out.begin() + static_cast<std::ptrdiff_t>((m - 1) * 16));
        std::copy(PP.begin(), PP.begin() + static_cast<std::ptrdiff_t>(b),
                  out.begin() + static_cast<std::ptrdiff_t>(m * 16));
    }

    return out;
}
