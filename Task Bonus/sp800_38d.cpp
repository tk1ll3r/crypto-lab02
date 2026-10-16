// -*- coding: utf-8 -*-
/**
 * sp800_38d.cpp - Bộ tiêu chuẩn 3: NIST SP 800-38D (GCM: Galois/Counter Mode & GMAC)
 * Chế độ mã hóa xác thực tốc độ cao kết hợp GCTR (Counter Mode với hàm tăng 32-bit cuối inc32)
 * và hàm băm đa thức GHASH trên trường hữu hạn GF(2^128).
 *
 * Môn: Mật mã học (NT219 - UIT)
 * Giải thích cơ chế xử lý từng khối (Block-by-block) được comment chi tiết bên dưới.
 */

#include "modes.h"

#include <algorithm>
#include <iostream>
#include <stdexcept>

// 
// KHỐI 1: HÀM TĂNG 32-BIT CUỐI (INC_32) & NHÂN TRÊN TRƯỜNG HỮU HẠN GF(2^128)
//   - Khác với CTR của SP 800-38A (tăng cả 128 bit), GCTR của GCM chỉ tăng 32 bit cuối (byte 12..15)
//     và giữ nguyên 96 bit đầu (Nonce 12 byte).
//   - Phép nhân GF(2^128) (`_gf128_mul`) thực hiện nhân 2 khối 128-bit X và Y modulo đa thức tối giản:
//     f(x) = 1 + x + x^2 + x^7 + x^128 (hằng số phản xạ bit R = 0xE1000000000000000000000000000000).
// 

void modes::_increment_be_32(ByteVec& counter) noexcept {
    // Chỉ cộng 1 vào 4 byte cuối (index 12..15) theo thứ tự Big-Endian (hàm inc_32 của NIST SP 800-38D)
    for (int i = 15; i >= 12; --i) {
        if (++counter[static_cast<size_t>(i)] != 0) {
            break;
        }
    }
}

modes::ByteVec modes::_gf128_mul(const ByteVec& X, const ByteVec& Y) {
    ByteVec Z(16, 0);
    ByteVec V = Y;

    for (size_t i = 0; i < 128; ++i) {
        size_t byte_idx = i / 8;
        size_t bit_idx = 7 - (i % 8);
        if ((X[byte_idx] >> bit_idx) & 1) {
            for (size_t j = 0; j < 16; ++j) {
                Z[j] ^= V[j];
            }
        }
        bool lsb = (V[15] & 1) != 0;
        for (int j = 15; j > 0; --j) {
            V[static_cast<size_t>(j)] =
                static_cast<Byte>((V[static_cast<size_t>(j)] >> 1) |
                                  ((V[static_cast<size_t>(j - 1)] & 1) << 7));
        }
        V[0] >>= 1;
        if (lsb) {
            V[0] ^= 0xE1; // R = 11100001 || 0^120
        }
    }
    return Z;
}

// 
// KHỐI 2: HÀM BĂM ĐA THỨC GHASH VÀ HÀM MÃ HÓA DÒNG GCTR TỪNG BLOCK
// Nguyên lý từng Block của GHASH(H, A, C):
//   - Khởi tạo Y_0 = 0^128.
//   - Với mỗi Block 16-byte của AAD (A_1, ..., A_m, đệm 0 nếu lẻ):
//       Y_i = (Y_{i-1} XOR A_i) * H  (trong trường GF(2^128))
//   - Với mỗi Block 16-byte của Ciphertext (C_1, ..., C_n, đệm 0 nếu lẻ):
//       Y_i = (Y_{i-1} XOR C_i) * H
//   - Khối cuối cùng (Length Block 16-byte): Ghép [len(A)_bits (64-bit BE) || len(C)_bits (64-bit BE)]:
//       S = (Y_{m+n} XOR len_block) * H
// 

modes::ByteVec modes::_ghash(const ByteVec& H, const ByteVec& A, const ByteVec& C) {
    ByteVec Y(16, 0);

    // Xử lý lần lượt từng Block 16-byte của một vùng dữ liệu (AAD hoặc Ciphertext)
    auto process_region = [&](const ByteVec& data) {
        for (size_t i = 0; i < data.size(); i += 16) {
            ByteVec block(16, 0);
            size_t copy_len = std::min<size_t>(16, data.size() - i);
            std::copy(data.begin() + static_cast<std::ptrdiff_t>(i),
                      data.begin() + static_cast<std::ptrdiff_t>(i + copy_len),
                      block.begin());
            // Cập nhật đa thức cho Block hiện tại: Y = (Y XOR block) * H
            Y = _gf128_mul(_xor(Y, block), H);
        }
    };

    // Bước 1: Đưa các Block của AAD qua GHASH
    process_region(A);
    // Bước 2: Đưa các Block của Ciphertext qua GHASH
    process_region(C);

    // Bước 3: Đưa Block độ dài bit [len(A)_bits || len(C)_bits] qua GHASH
    uint64_t a_bits = static_cast<uint64_t>(A.size()) * 8;
    uint64_t c_bits = static_cast<uint64_t>(C.size()) * 8;
    ByteVec len_block(16, 0);
    for (size_t i = 0; i < 8; ++i) {
        len_block[i] = static_cast<Byte>((a_bits >> (56 - 8 * i)) & 0xFF);
        len_block[8 + i] = static_cast<Byte>((c_bits >> (56 - 8 * i)) & 0xFF);
    }
    Y = _gf128_mul(_xor(Y, len_block), H);
    return Y;
}

modes::ByteVec modes::_gctr(ByteVec icb, const ByteVec& X) {
    if (X.empty()) return {};
    ByteVec Y;
    Y.reserve(X.size());
    // Chia dữ liệu X thành các Block 16-byte và XOR với AES_K(CB_i)
    auto blocks = _chunks(X, BLOCK_SIZE);
    for (size_t idx = 0; idx < blocks.size(); ++idx) {
        ByteVec ks = this->aes.encrypt(icb);
        for (size_t j = 0; j < blocks[idx].size(); ++j) {
            Y.push_back(blocks[idx][j] ^ ks[j]);
        }
        if (this->verbose) {
            std::cout << "[GCM GCTR Block " << idx << "] Counter=" << bytes_to_hex(icb)
                      << " -> Keystream=" << bytes_to_hex(ks) << "\n";
        }
        _increment_be_32(icb);
    }
    return Y;
}

// 
// KHỐI 3: MÃ HÓA & GIẢI MÃ AES-GCM VÀ XÁC THỰC GMAC (NIST SP 800-38D MỤC 7.1 & 7.2)
//   - Bước 1: Tạo khóa con băm H = AES_K(0^128).
//   - Bước 2: Tạo khối Pre-counter J_0 = Nonce (12 byte) || 0x00000001.
//   - Bước 3: Mã hóa bản rõ bằng GCTR bắt đầu từ bộ đếm inc_32(J_0) -> tạo Ciphertext C.
//   - Bước 4: Tính S = GHASH(H, AAD, C) và tạo thẻ xác thực Tag = AES_K(J_0) XOR S.
// 

modes::ByteVec modes::gcm_encrypt(const ByteVec& plaintext,
                                  const std::optional<ByteVec>& associated_data,
                                  const std::optional<ByteVec>& nonce,
                                  bool prepend_nonce) {
    ByteVec nonce_bytes = nonce.has_value() ? nonce.value() : random_bytes(12);
    if (nonce_bytes.size() != 12) {
        throw std::invalid_argument("AES-GCM nonce should be 12 bytes for the standard fast path.");
    }
    ByteVec aad = associated_data.value_or(ByteVec{});

    // Bước 1: Tính Hash Subkey H = AES_K(0^128)
    ByteVec H = this->aes.encrypt(ByteVec(16, 0));

    // Bước 2: Khởi tạo khối J_0 = Nonce (96-bit) || 0x00000001
    ByteVec J0 = nonce_bytes;
    J0.insert(J0.end(), {0x00, 0x00, 0x00, 0x01});

    // Bước 3: Mã hóa từng Block bản rõ bằng GCTR với bộ đếm bắt đầu từ inc_32(J_0)
    ByteVec icb = J0;
    _increment_be_32(icb);
    ByteVec ciphertext = _gctr(icb, plaintext);

    // Bước 4: Tính GHASH trên các Block của AAD và Ciphertext, sau đó XOR với AES_K(J_0) để tạo Tag
    ByteVec S = _ghash(H, aad, ciphertext);
    ByteVec tag = _xor(this->aes.encrypt(J0), S);

    if (this->verbose) {
        std::cout << "[GCM Encrypt] H=" << bytes_to_hex(H)
                  << " | J0=" << bytes_to_hex(J0)
                  << " | Tag=" << bytes_to_hex(tag) << "\n";
    }

    ByteVec body = ciphertext;
    body.insert(body.end(), tag.begin(), tag.end());
    if (prepend_nonce) {
        ByteVec out = nonce_bytes;
        out.insert(out.end(), body.begin(), body.end());
        return out;
    }
    return body;
}

modes::ByteVec modes::gcm_encrypt(const std::string& plaintext,
                                  const std::optional<ByteVec>& associated_data,
                                  const std::optional<ByteVec>& nonce,
                                  bool prepend_nonce) {
    return gcm_encrypt(_ensure_bytes(plaintext, "plaintext"), associated_data, nonce, prepend_nonce);
}

modes::ByteVec modes::gcm_decrypt_bytes(const ByteVec& ciphertext_and_tag,
                                        const std::optional<ByteVec>& associated_data,
                                        const std::optional<ByteVec>& nonce,
                                        bool has_nonce) {
    ByteVec nonce_bytes;
    ByteVec data;
    if (has_nonce) {
        if (ciphertext_and_tag.size() < 12 + 16) {
            throw std::invalid_argument("AES-GCM input with prepended nonce must contain nonce + ciphertext/tag.");
        }
        nonce_bytes.assign(ciphertext_and_tag.begin(), ciphertext_and_tag.begin() + 12);
        data.assign(ciphertext_and_tag.begin() + 12, ciphertext_and_tag.end());
    } else {
        if (!nonce.has_value()) {
            throw std::invalid_argument("nonce is required when has_nonce=false.");
        }
        nonce_bytes = nonce.value();
        if (nonce_bytes.size() != 12) {
            throw std::invalid_argument("AES-GCM nonce should be 12 bytes.");
        }
        if (ciphertext_and_tag.size() < 16) {
            throw std::invalid_argument("AES-GCM input must contain at least a 16-byte authentication tag.");
        }
        data = ciphertext_and_tag;
    }

    ByteVec ciphertext(data.begin(), data.end() - 16);
    ByteVec received_tag(data.end() - 16, data.end());
    ByteVec aad = associated_data.value_or(ByteVec{});

    // Bước 1: Kiểm tra Tag xác thực trước khi giải mã (Authenticate-then-Decrypt)
    ByteVec H = this->aes.encrypt(ByteVec(16, 0));
    ByteVec J0 = nonce_bytes;
    J0.insert(J0.end(), {0x00, 0x00, 0x00, 0x01});

    ByteVec S = _ghash(H, aad, ciphertext);
    ByteVec expected_tag = _xor(this->aes.encrypt(J0), S);
    if (!_constant_time_equal(received_tag, expected_tag)) {
        throw std::runtime_error("AES-GCM authentication failed: tag mismatch.");
    }

    // Bước 2: Giải mã từng Block bản mã qua GCTR với inc_32(J_0)
    ByteVec icb = J0;
    _increment_be_32(icb);
    return _gctr(icb, ciphertext);
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
    // GMAC là trường hợp đặc biệt của AES-GCM với bản rõ rỗng (chỉ tạo Tag xác thực cho AAD)
    return gcm_encrypt(ByteVec{}, authenticated_data, nonce, prepend_nonce);
}

bool modes::gmac_verify(const ByteVec& authenticated_data,
                        const ByteVec& tag,
                        const std::optional<ByteVec>& nonce,
                        bool has_nonce) {
    if (has_nonce && tag.size() != 28) {
        throw std::invalid_argument("GMAC token with prepended nonce must be 12-byte nonce + 16-byte tag.");
    }
    try {
        (void)gcm_decrypt_bytes(tag, authenticated_data, nonce, has_nonce);
        return true;
    } catch (...) {
        return false;
    }
}
