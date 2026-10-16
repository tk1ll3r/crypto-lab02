// -*- coding: utf-8 -*-
/**
 * sp800_38f.cpp - Bộ tiêu chuẩn 5: NIST SP 800-38F (AES Key Wrap KW / KWP - RFC 3394 & RFC 5649)
 * kèm chế độ mở rộng RFC 8452 (AES-GCM-SIV) từ file modes.py.
 *
 * Môn: Mật mã học (NT219 - UIT)
 * Giải thích cơ chế xử lý từng khối / nửa khối (Semiblock 64-bit & Block 128-bit) bên dưới.
 */

#include "modes.h"

#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <tuple>

// 
// KHỐI 1: BAO KHÓA AES KEY WRAP (KW) & KEY WRAP WITH PADDING (KWP) (NIST SP 800-38F)
// Nguyên lý từng Semiblock (64-bit = 8 byte):
//   - Chia dữ liệu khóa cần bọc P thành `n` nửa khối (semiblocks) 8-byte: R_1, R_2, ..., R_n.
//   - Khởi tạo thanh ghi toàn vẹn 8-byte `A`:
//       + Với KW (không pad): A = 0xA6A6A6A6A6A6A6A6
//       + Với KWP (có pad)  : A = 0xA65959A6 || MLI (32-bit Big-Endian độ dài gốc của khóa)
//   - Lặp qua 6 vòng (j = 0..5), mỗi vòng đi qua từng semiblock (i = 1..n):
//       + Ghép thành 1 Block 16-byte [A || R_i] và mã hóa: B = AES_Encrypt(K, A || R_i)
//       + Cập nhật A = MSB_64(B) XOR t  (với bước đếm t = n * j + i)
//       + Cập nhật R_i = LSB_64(B)
// 

modes::ByteVec modes::_kw_wrap_core(const ByteVec& P, const std::array<Byte, 8>& iv_init) {
    size_t n = P.size() / 8;
    std::array<Byte, 8> A = iv_init;
    std::vector<std::array<Byte, 8>> R(n);
    for (size_t i = 0; i < n; ++i) {
        std::copy(P.begin() + static_cast<std::ptrdiff_t>(i * 8),
                  P.begin() + static_cast<std::ptrdiff_t>((i + 1) * 8),
                  R[i].begin());
    }

    // Lặp 6 vòng (j = 0..5) qua từng semiblock R[0..n-1]
    for (size_t j = 0; j <= 5; ++j) {
        for (size_t i = 1; i <= n; ++i) {
            ByteVec blk(16);
            std::copy(A.begin(), A.end(), blk.begin());
            std::copy(R[i - 1].begin(), R[i - 1].end(), blk.begin() + 8);
            ByteVec B = this->aes.encrypt(blk);
            uint64_t t = static_cast<uint64_t>(n * j + i);
            for (size_t k = 0; k < 8; ++k) {
                A[k] = B[k] ^ static_cast<Byte>((t >> (56 - 8 * k)) & 0xFF);
                R[i - 1][k] = B[8 + k];
            }
        }
    }

    ByteVec C;
    C.reserve((n + 1) * 8);
    C.insert(C.end(), A.begin(), A.end());
    for (size_t i = 0; i < n; ++i) {
        C.insert(C.end(), R[i].begin(), R[i].end());
    }
    return C;
}

std::pair<std::array<modes::Byte, 8>, modes::ByteVec> modes::_kw_unwrap_core(const ByteVec& C) {
    size_t n = (C.size() / 8) - 1;
    std::array<Byte, 8> A{};
    std::copy(C.begin(), C.begin() + 8, A.begin());
    std::vector<std::array<Byte, 8>> R(n);
    for (size_t i = 0; i < n; ++i) {
        std::copy(C.begin() + static_cast<std::ptrdiff_t>((i + 1) * 8),
                  C.begin() + static_cast<std::ptrdiff_t>((i + 2) * 8),
                  R[i].begin());
    }

    // Giải mã ngược 6 vòng (j = 5..0) và ngược từng semiblock (i = n..1)
    for (int j = 5; j >= 0; --j) {
        for (size_t i = n; i >= 1; --i) {
            uint64_t t = static_cast<uint64_t>(n * static_cast<size_t>(j) + i);
            ByteVec blk(16);
            for (size_t k = 0; k < 8; ++k) {
                blk[k] = A[k] ^ static_cast<Byte>((t >> (56 - 8 * k)) & 0xFF);
                blk[8 + k] = R[i - 1][k];
            }
            ByteVec B = this->aes.decrypt(blk);
            std::copy(B.begin(), B.begin() + 8, A.begin());
            std::copy(B.begin() + 8, B.end(), R[i - 1].begin());
        }
    }

    ByteVec out;
    out.reserve(n * 8);
    for (size_t i = 0; i < n; ++i) {
        out.insert(out.end(), R[i].begin(), R[i].end());
    }
    return {A, out};
}

modes::ByteVec modes::key_wrap(const ByteVec& key_to_wrap, bool pad) {
    if (!pad) {
        if (key_to_wrap.size() < 16 || key_to_wrap.size() % 8 != 0) {
            throw std::invalid_argument(
                "AES-KW without padding requires key_to_wrap length >= 16 and multiple of 8 bytes."
            );
        }
        std::array<Byte, 8> iv_kw = {0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6};
        return _kw_wrap_core(key_to_wrap, iv_kw);
    } else {
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
        ByteVec padded = key_to_wrap;
        size_t rem = padded.size() % 8;
        if (rem != 0) {
            padded.insert(padded.end(), 8 - rem, 0x00);
        }
        // Trường hợp đặc biệt trong RFC 5649: Nếu dữ liệu sau pad chỉ có 1 semiblock (8 byte),
        // ghép trực tiếp AIV || P[1] thành 1 Block 16-byte và mã hóa bằng 1 lần gọi AES_Encrypt.
        if (padded.size() == 8) {
            ByteVec block(16);
            std::copy(aiv.begin(), aiv.end(), block.begin());
            std::copy(padded.begin(), padded.end(), block.begin() + 8);
            return this->aes.encrypt(block);
        }
        return _kw_wrap_core(padded, aiv);
    }
}

modes::ByteVec modes::key_wrap(const std::string& key_to_wrap, bool pad) {
    return key_wrap(_ensure_bytes(key_to_wrap, "key_to_wrap"), pad);
}

modes::ByteVec modes::key_unwrap(const ByteVec& wrapped_key, bool pad) {
    if (!pad) {
        if (wrapped_key.size() < 24 || wrapped_key.size() % 8 != 0) {
            throw std::invalid_argument("Invalid AES-KW wrapped_key length.");
        }
        auto [A, R] = _kw_unwrap_core(wrapped_key);
        std::array<Byte, 8> expected_iv = {0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6};
        if (A != expected_iv) {
            throw std::runtime_error("AES-KW integrity check failed.");
        }
        return R;
    } else {
        if (wrapped_key.size() < 16 || wrapped_key.size() % 8 != 0) {
            throw std::invalid_argument("Invalid AES-KWP wrapped_key length.");
        }
        std::array<Byte, 8> A{};
        ByteVec R;
        if (wrapped_key.size() == 16) {
            ByteVec dec = this->aes.decrypt(wrapped_key);
            std::copy(dec.begin(), dec.begin() + 8, A.begin());
            R.assign(dec.begin() + 8, dec.end());
        } else {
            std::tie(A, R) = _kw_unwrap_core(wrapped_key);
        }
        if (A[0] != 0xA6 || A[1] != 0x59 || A[2] != 0x59 || A[3] != 0xA6) {
            throw std::runtime_error("AES-KWP AIV header check failed.");
        }
        uint32_t mli = (static_cast<uint32_t>(A[4]) << 24) |
                       (static_cast<uint32_t>(A[5]) << 16) |
                       (static_cast<uint32_t>(A[6]) << 8) |
                       static_cast<uint32_t>(A[7]);
        size_t b = R.size() - static_cast<size_t>(mli);
        if (mli == 0 || mli > R.size() || b >= 8) {
            throw std::runtime_error("AES-KWP MLI length check failed.");
        }
        for (size_t i = mli; i < R.size(); ++i) {
            if (R[i] != 0x00) {
                throw std::runtime_error("AES-KWP non-zero padding check failed.");
            }
        }
        R.resize(mli);
        return R;
    }
}

// 
// KHỐI 2: CHẾ ĐỘ MỞ RỘNG RFC 8452 (AES-GCM-SIV: NONCE MISUSE-RESISTANT AEAD)
// Nguyên lý từng Block:
//   - Bước 1: Dẫn xuất khóa xác thực `auth_key` (16 byte) và khóa mã hóa `enc_key` (16/32 byte)
//     bằng cách mã hóa các khối `[counter_32bit_LE || nonce_96bit]`.
//   - Bước 2: Đưa từng Block 16-byte của AAD, Plaintext và khối độ dài qua hàm đa thức `POLYVAL`.
//   - Bước 3: XOR kết quả POLYVAL với Nonce, xóa bit MSB của byte 15 và mã hóa qua AES để tạo Tag.
//   - Bước 4: Dùng Tag (với bit MSB của byte 15 bật lên 1) làm khối Counter ban đầu (tăng 32-bit đầu LE)
//     để mã hóa/giải mã từng Block dữ liệu.
// 

modes::ByteVec modes::_byte_reverse_16(const ByteVec& b) {
    ByteVec r(16);
    for (size_t i = 0; i < 16; ++i) r[i] = b[15 - i];
    return r;
}

modes::ByteVec modes::_mulX_ghash(const ByteVec& V_in) {
    ByteVec V = V_in;
    bool lsb = (V[15] & 1) != 0;
    for (int j = 15; j > 0; --j) {
        V[static_cast<size_t>(j)] =
            static_cast<Byte>((V[static_cast<size_t>(j)] >> 1) |
                              ((V[static_cast<size_t>(j - 1)] & 1) << 7));
    }
    V[0] >>= 1;
    if (lsb) {
        V[0] ^= 0xE1;
    }
    return V;
}

modes::ByteVec modes::_polyval(const ByteVec& H, const std::vector<ByteVec>& blocks) {
    ByteVec H_ghash = _mulX_ghash(_byte_reverse_16(H));
    ByteVec Y(16, 0);
    for (const auto& blk : blocks) {
        Y = _gf128_mul(_xor(Y, _byte_reverse_16(blk)), H_ghash);
    }
    return _byte_reverse_16(Y);
}

std::pair<modes::ByteVec, modes::ByteVec> modes::_gcm_siv_derive_keys(const ByteVec& nonce) {
    auto derive_block = [&](uint32_t counter) {
        ByteVec blk(16, 0);
        blk[0] = static_cast<Byte>(counter & 0xFF);
        blk[1] = static_cast<Byte>((counter >> 8) & 0xFF);
        blk[2] = static_cast<Byte>((counter >> 16) & 0xFF);
        blk[3] = static_cast<Byte>((counter >> 24) & 0xFF);
        std::copy(nonce.begin(), nonce.end(), blk.begin() + 4);
        ByteVec enc = this->aes.encrypt(blk);
        enc.resize(8);
        return enc;
    };

    ByteVec auth_key;
    for (uint32_t c = 0; c < 2; ++c) {
        ByteVec part = derive_block(c);
        auth_key.insert(auth_key.end(), part.begin(), part.end());
    }

    uint32_t enc_blocks = (this->key.size() == 16) ? 2 : 4;
    ByteVec enc_key;
    for (uint32_t c = 2; c < 2 + enc_blocks; ++c) {
        ByteVec part = derive_block(c);
        enc_key.insert(enc_key.end(), part.begin(), part.end());
    }
    return {auth_key, enc_key};
}

modes::ByteVec modes::_gcm_siv_compute_tag(AES& enc_aes,
                                           const ByteVec& auth_key,
                                           const ByteVec& nonce,
                                           const ByteVec& aad,
                                           const ByteVec& plaintext) {
    std::vector<ByteVec> poly_blocks;
    auto append_padded = [&](const ByteVec& data) {
        for (size_t i = 0; i < data.size(); i += 16) {
            ByteVec blk(16, 0);
            size_t n = std::min<size_t>(16, data.size() - i);
            std::copy(data.begin() + static_cast<std::ptrdiff_t>(i),
                      data.begin() + static_cast<std::ptrdiff_t>(i + n),
                      blk.begin());
            poly_blocks.push_back(blk);
        }
    };
    append_padded(aad);
    append_padded(plaintext);

    uint64_t aad_bits = static_cast<uint64_t>(aad.size()) * 8;
    uint64_t pt_bits = static_cast<uint64_t>(plaintext.size()) * 8;
    ByteVec len_blk(16, 0);
    for (size_t i = 0; i < 8; ++i) {
        len_blk[i] = static_cast<Byte>((aad_bits >> (8 * i)) & 0xFF);
        len_blk[8 + i] = static_cast<Byte>((pt_bits >> (8 * i)) & 0xFF);
    }
    poly_blocks.push_back(len_blk);

    ByteVec S_s = _polyval(auth_key, poly_blocks);
    for (size_t i = 0; i < 12; ++i) {
        S_s[i] ^= nonce[i];
    }
    S_s[15] &= 0x7F;
    return enc_aes.encrypt(S_s);
}

modes::ByteVec modes::_gcm_siv_ctr(AES& enc_aes, const ByteVec& tag, const ByteVec& input) {
    if (input.empty()) return {};
    ByteVec cb = tag;
    cb[15] |= 0x80;
    uint32_t ctr = static_cast<uint32_t>(cb[0]) |
                   (static_cast<uint32_t>(cb[1]) << 8) |
                   (static_cast<uint32_t>(cb[2]) << 16) |
                   (static_cast<uint32_t>(cb[3]) << 24);

    ByteVec out;
    out.reserve(input.size());
    auto blocks = _chunks(input, 16);
    for (const auto& blk : blocks) {
        cb[0] = static_cast<Byte>(ctr & 0xFF);
        cb[1] = static_cast<Byte>((ctr >> 8) & 0xFF);
        cb[2] = static_cast<Byte>((ctr >> 16) & 0xFF);
        cb[3] = static_cast<Byte>((ctr >> 24) & 0xFF);
        ByteVec ks = enc_aes.encrypt(cb);
        for (size_t j = 0; j < blk.size(); ++j) {
            out.push_back(blk[j] ^ ks[j]);
        }
        ++ctr;
    }
    return out;
}

modes::ByteVec modes::gcm_siv_encrypt(const ByteVec& plaintext,
                                      const std::optional<ByteVec>& associated_data,
                                      const std::optional<ByteVec>& nonce,
                                      bool prepend_nonce) {
    if (this->key.size() != 16 && this->key.size() != 32) {
        throw std::invalid_argument("AES-GCM-SIV (RFC 8452) supports 16-byte or 32-byte keys.");
    }
    ByteVec nonce_bytes = nonce.has_value() ? nonce.value() : random_bytes(12);
    if (nonce_bytes.size() != 12) {
        throw std::invalid_argument("AES-GCM-SIV nonce must be 12 bytes.");
    }
    ByteVec aad = associated_data.value_or(ByteVec{});

    auto [auth_key, enc_key] = _gcm_siv_derive_keys(nonce_bytes);
    AES enc_aes(enc_key, static_cast<int>(enc_key.size() * 8));

    ByteVec tag = _gcm_siv_compute_tag(enc_aes, auth_key, nonce_bytes, aad, plaintext);
    ByteVec ciphertext = _gcm_siv_ctr(enc_aes, tag, plaintext);

    ByteVec body = ciphertext;
    body.insert(body.end(), tag.begin(), tag.end());
    if (prepend_nonce) {
        ByteVec out = nonce_bytes;
        out.insert(out.end(), body.begin(), body.end());
        return out;
    }
    return body;
}

modes::ByteVec modes::gcm_siv_encrypt(const std::string& plaintext,
                                      const std::optional<ByteVec>& associated_data,
                                      const std::optional<ByteVec>& nonce,
                                      bool prepend_nonce) {
    return gcm_siv_encrypt(_ensure_bytes(plaintext, "plaintext"), associated_data, nonce, prepend_nonce);
}

modes::ByteVec modes::gcm_siv_decrypt_bytes(const ByteVec& ciphertext_and_tag,
                                            const std::optional<ByteVec>& associated_data,
                                            const std::optional<ByteVec>& nonce,
                                            bool has_nonce) {
    if (this->key.size() != 16 && this->key.size() != 32) {
        throw std::invalid_argument("AES-GCM-SIV (RFC 8452) supports 16-byte or 32-byte keys.");
    }
    ByteVec nonce_bytes;
    ByteVec data;
    if (has_nonce) {
        if (ciphertext_and_tag.size() < 12 + 16) {
            throw std::invalid_argument("AES-GCM-SIV input with prepended nonce must contain nonce + ciphertext/tag.");
        }
        nonce_bytes.assign(ciphertext_and_tag.begin(), ciphertext_and_tag.begin() + 12);
        data.assign(ciphertext_and_tag.begin() + 12, ciphertext_and_tag.end());
    } else {
        if (!nonce.has_value()) {
            throw std::invalid_argument("nonce is required when has_nonce=false.");
        }
        nonce_bytes = nonce.value();
        if (nonce_bytes.size() != 12) {
            throw std::invalid_argument("AES-GCM-SIV nonce must be 12 bytes.");
        }
        if (ciphertext_and_tag.size() < 16) {
            throw std::invalid_argument("AES-GCM-SIV input too short.");
        }
        data = ciphertext_and_tag;
    }

    ByteVec ciphertext(data.begin(), data.end() - 16);
    ByteVec received_tag(data.end() - 16, data.end());
    ByteVec aad = associated_data.value_or(ByteVec{});

    auto [auth_key, enc_key] = _gcm_siv_derive_keys(nonce_bytes);
    AES enc_aes(enc_key, static_cast<int>(enc_key.size() * 8));

    ByteVec plaintext = _gcm_siv_ctr(enc_aes, received_tag, ciphertext);
    ByteVec expected_tag = _gcm_siv_compute_tag(enc_aes, auth_key, nonce_bytes, aad, plaintext);
    if (!_constant_time_equal(received_tag, expected_tag)) {
        throw std::runtime_error("AES-GCM-SIV authentication failed: tag mismatch.");
    }
    return plaintext;
}

std::string modes::gcm_siv_decrypt(const ByteVec& ciphertext_and_tag,
                                   const std::optional<ByteVec>& associated_data,
                                   const std::optional<ByteVec>& nonce,
                                   bool has_nonce) {
    return bytes_to_utf8(gcm_siv_decrypt_bytes(ciphertext_and_tag, associated_data, nonce, has_nonce));
}
