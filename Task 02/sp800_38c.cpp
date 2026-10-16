// -*- coding: utf-8 -*-
/**
 * sp800_38c.cpp - Bộ tiêu chuẩn 2: NIST SP 800-38C (CCM: Counter with CBC-MAC)
 * Chế độ mã hóa có xác thực (AEAD) kết hợp CBC-MAC để tạo thẻ xác thực (Tag)
 * và chế độ CTR để mã hóa dữ liệu.
 * (Lưu ý: Đã loại bỏ tiêu chuẩn NIST SP 800-38B CMAC theo yêu cầu bài Lab).
 *
 * Môn: Mật mã học (NT219 - UIT)
 * Giải thích cơ chế xử lý từng khối (Block-by-block) được comment chi tiết bên dưới.
 */

#include "modes.h"

#include <algorithm>
#include <iostream>
#include <stdexcept>

// KHỐI 1: TẠO KHỐI BỘ ĐẾM CTR_i CHO CCM (NIST SP 800-38C APPENDIX A.3)
// Cấu trúc mỗi khối bộ đếm 16-byte `Ctr_i`:
//   - Byte 0     : Flags = (q - 1), trong đó q = 15 - độ_dài_nonce (số byte dành cho bộ đếm)
//   - Byte 1..15-q: Giá trị Nonce (dài từ 7 đến 13 byte)
//   - q byte cuối : Giá trị chỉ số khối `counter_val` (i = 0 dùng cho Tag, i = 1..m dùng cho các khối dữ liệu)

modes::ByteVec modes::_ccm_counter_block(const ByteVec& nonce, size_t counter_val) {
    size_t q = 15 - nonce.size();
    ByteVec blk(16, 0);
    blk[0] = static_cast<Byte>(q - 1);
    std::copy(nonce.begin(), nonce.end(), blk.begin() + 1);
    for (size_t i = 0; i < q; ++i) {
        blk[15 - i] = static_cast<Byte>((counter_val >> (8 * i)) & 0xFF);
    }
    return blk;
}

// KHỐI 2: TÍNH GIÁ TRỊ CBC-MAC TRÊN TỪNG BLOCK B_0, B_1, ..., B_r (NIST SP 800-38C MỤC 6.1)
// Nguyên lý từng Block:
//   - Khối đầu tiên B_0 (16 byte): Chứa Flags (1 byte) || Nonce (15-q byte) || Độ dài bản rõ Q (q byte).
//     Tính Y_0 = AES_Encrypt(K, B_0).
//   - Các khối dữ liệu xác thực phụ (AAD): Đóng gói độ dài `a` + nội dung AAD, đệm số 0 cho tròn bội số 16 byte,
//     rồi lần lượt cập nhật từng khối: Y_i = AES_Encrypt(K, Y_{i-1} XOR B_i).
//   - Các khối bản rõ (Plaintext): Chia thành các khối 16 byte (khối cuối thiếu thì đệm 0),
//     tiếp tục cập nhật: Y_i = AES_Encrypt(K, Y_{i-1} XOR B_i).
//   - Kết quả Y_r sau khối cuối cùng chính là giá trị MAC thô `T`.

modes::ByteVec modes::_ccm_cbc_mac(const ByteVec& plaintext,
                                   const ByteVec& aad,
                                   const ByteVec& nonce,
                                   size_t tag_length) {
    size_t q = 15 - nonce.size();
    size_t Q = plaintext.size();

    // Bước 1: Khởi tạo khối đầu tiên B_0 (16 byte) và mã hóa Y_0 = AES_K(B_0)
    ByteVec B0(16, 0);
    Byte flags = static_cast<Byte>(((aad.empty() ? 0 : 1) << 6) |
                                   (((tag_length - 2) / 2) << 3) |
                                   (q - 1));
    B0[0] = flags;
    std::copy(nonce.begin(), nonce.end(), B0.begin() + 1);
    for (size_t i = 0; i < q; ++i) {
        B0[15 - i] = static_cast<Byte>((Q >> (8 * i)) & 0xFF);
    }

    ByteVec Y = this->aes.encrypt(B0);

    // Hàm nội bộ: Chia luồng dữ liệu thành từng Block 16-byte (đệm 0 ở block cuối) và chạy chuỗi CBC-MAC
    auto feed_padded = [&](const ByteVec& stream) {
        for (size_t i = 0; i < stream.size(); i += 16) {
            ByteVec blk(16, 0);
            size_t n = std::min<size_t>(16, stream.size() - i);
            std::copy(stream.begin() + static_cast<std::ptrdiff_t>(i),
                      stream.begin() + static_cast<std::ptrdiff_t>(i + n),
                      blk.begin());
            // Móc xích từng Block: Y = AES_K(Y XOR blk)
            Y = this->aes.encrypt(_xor(Y, blk));
        }
    };

    // Bước 2: Đưa từng Block của Associated Data (AAD) vào chuỗi CBC-MAC
    if (!aad.empty()) {
        ByteVec formatted_aad;
        size_t a = aad.size();
        if (a < 0xFF00) {
            formatted_aad.push_back(static_cast<Byte>((a >> 8) & 0xFF));
            formatted_aad.push_back(static_cast<Byte>(a & 0xFF));
        } else {
            formatted_aad.push_back(0xFF);
            formatted_aad.push_back(0xFE);
            formatted_aad.push_back(static_cast<Byte>((a >> 24) & 0xFF));
            formatted_aad.push_back(static_cast<Byte>((a >> 16) & 0xFF));
            formatted_aad.push_back(static_cast<Byte>((a >> 8) & 0xFF));
            formatted_aad.push_back(static_cast<Byte>(a & 0xFF));
        }
        formatted_aad.insert(formatted_aad.end(), aad.begin(), aad.end());
        feed_padded(formatted_aad);
    }

    // Bước 3: Đưa từng Block của Bản rõ (Plaintext) vào chuỗi CBC-MAC
    if (!plaintext.empty()) {
        feed_padded(plaintext);
    }

    return Y;
}

// KHỐI 3: MÃ HÓA & GIẢI MÃ AES-CCM (NIST SP 800-38C MỤC 6.1 & 6.2)
//   - Mã hóa:
//       1. Tính T = CBC-MAC(B_0 || AAD || Plaintext)
//       2. Tạo khối bộ đếm S_0 = AES_K(Ctr_0) để che thẻ xác thực: Tag U = T[0..tag_len-1] XOR S_0[0..tag_len-1]
//       3. Với mỗi Block bản rõ thứ `i` (i = 0..m-1): tạo S_{i+1} = AES_K(Ctr_{i+1}) rồi XOR với P_i -> C_i
//   - Giải mã:
//       1. Giải mã từng Block bản mã C_i với S_{i+1} = AES_K(Ctr_{i+1}) để thu lại P_i
//       2. Tính lại CBC-MAC trên P_i và đối chiếu Tag trong thời gian hằng số

modes::ByteVec modes::ccm_encrypt(const ByteVec& plaintext,
                                  const std::optional<ByteVec>& associated_data,
                                  const std::optional<ByteVec>& nonce,
                                  size_t tag_length,
                                  bool prepend_nonce) {
    if (tag_length != 4 && tag_length != 6 && tag_length != 8 &&
        tag_length != 10 && tag_length != 12 && tag_length != 14 && tag_length != 16) {
        throw std::invalid_argument("AES-CCM tag_length must be one of 4, 6, 8, 10, 12, 14, 16.");
    }
    ByteVec nonce_bytes = nonce.has_value() ? nonce.value() : random_bytes(13);
    if (nonce_bytes.size() < 7 || nonce_bytes.size() > 13) {
        throw std::invalid_argument("AES-CCM nonce length must be between 7 and 13 bytes.");
    }
    ByteVec aad = associated_data.value_or(ByteVec{});

    // Bước 1: Tính CBC-MAC T qua toàn bộ các block AAD + Plaintext
    ByteVec T = _ccm_cbc_mac(plaintext, aad, nonce_bytes, tag_length);

    // Bước 2: Mã hóa khối bộ đếm thứ 0 (Ctr_0) để tạo mặt nạ che Tag U
    ByteVec S0 = _ccm_counter_block(nonce_bytes, 0);
    ByteVec enc_S0 = this->aes.encrypt(S0);
    ByteVec U(tag_length);
    for (size_t i = 0; i < tag_length; ++i) {
        U[i] = T[i] ^ enc_S0[i];
    }

    // Bước 3: Mã hóa từng Block bản rõ bằng chế độ CTR bắt đầu từ bộ đếm Ctr_1, Ctr_2, ...
    ByteVec ciphertext;
    ciphertext.reserve(plaintext.size());
    auto blocks = _chunks(plaintext, BLOCK_SIZE);
    for (size_t i = 0; i < blocks.size(); ++i) {
        ByteVec ctr_blk = _ccm_counter_block(nonce_bytes, i + 1);
        ByteVec ks = this->aes.encrypt(ctr_blk);
        for (size_t j = 0; j < blocks[i].size(); ++j) {
            ciphertext.push_back(blocks[i][j] ^ ks[j]);
        }
        if (this->verbose) {
            std::cout << "[CCM Encrypt Block " << i << "] Ctr=" << bytes_to_hex(ctr_blk)
                      << " -> Keystream=" << bytes_to_hex(ks) << "\n";
        }
    }

    if (this->verbose) {
        std::cout << "[CCM Encrypt] Nonce=" << bytes_to_hex(nonce_bytes)
                  << " | CBC-MAC Tag=" << bytes_to_hex(U) << "\n";
    }

    ByteVec body = ciphertext;
    body.insert(body.end(), U.begin(), U.end());
    if (prepend_nonce) {
        ByteVec out = nonce_bytes;
        out.insert(out.end(), body.begin(), body.end());
        return out;
    }
    return body;
}

modes::ByteVec modes::ccm_encrypt(const std::string& plaintext,
                                  const std::optional<ByteVec>& associated_data,
                                  const std::optional<ByteVec>& nonce,
                                  size_t tag_length,
                                  bool prepend_nonce) {
    return ccm_encrypt(_ensure_bytes(plaintext, "plaintext"), associated_data, nonce, tag_length, prepend_nonce);
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
    if (tag_length != 4 && tag_length != 6 && tag_length != 8 &&
        tag_length != 10 && tag_length != 12 && tag_length != 14 && tag_length != 16) {
        throw std::invalid_argument("AES-CCM tag_length must be one of 4, 6, 8, 10, 12, 14, 16.");
    }
    ByteVec nonce_bytes;
    ByteVec data;
    if (has_nonce) {
        if (ciphertext_and_tag.size() < nonce_length + tag_length) {
            throw std::invalid_argument("AES-CCM input with prepended nonce must contain nonce + ciphertext/tag.");
        }
        nonce_bytes.assign(ciphertext_and_tag.begin(),
                           ciphertext_and_tag.begin() + static_cast<std::ptrdiff_t>(nonce_length));
        data.assign(ciphertext_and_tag.begin() + static_cast<std::ptrdiff_t>(nonce_length),
                    ciphertext_and_tag.end());
    } else {
        if (!nonce.has_value()) {
            throw std::invalid_argument("nonce is required when has_nonce=false.");
        }
        nonce_bytes = nonce.value();
        if (nonce_bytes.size() < 7 || nonce_bytes.size() > 13) {
            throw std::invalid_argument("AES-CCM nonce length must be between 7 and 13 bytes.");
        }
        if (ciphertext_and_tag.size() < tag_length) {
            throw std::invalid_argument("AES-CCM input too short for tag.");
        }
        data = ciphertext_and_tag;
    }

    ByteVec ciphertext(data.begin(), data.end() - static_cast<std::ptrdiff_t>(tag_length));
    ByteVec received_U(data.end() - static_cast<std::ptrdiff_t>(tag_length), data.end());

    // Bước 1: Giải mã từng Block bản mã bằng CTR với bộ đếm Ctr_1, Ctr_2, ...
    ByteVec plaintext;
    plaintext.reserve(ciphertext.size());
    auto blocks = _chunks(ciphertext, BLOCK_SIZE);
    for (size_t i = 0; i < blocks.size(); ++i) {
        ByteVec ctr_blk = _ccm_counter_block(nonce_bytes, i + 1);
        ByteVec ks = this->aes.encrypt(ctr_blk);
        for (size_t j = 0; j < blocks[i].size(); ++j) {
            plaintext.push_back(blocks[i][j] ^ ks[j]);
        }
    }

    // Bước 2: Tính lại CBC-MAC trên bản rõ vừa giải mã và kiểm tra tính toàn vẹn của Tag U
    ByteVec aad = associated_data.value_or(ByteVec{});
    ByteVec T = _ccm_cbc_mac(plaintext, aad, nonce_bytes, tag_length);
    ByteVec S0 = _ccm_counter_block(nonce_bytes, 0);
    ByteVec enc_S0 = this->aes.encrypt(S0);
    ByteVec expected_U(tag_length);
    for (size_t i = 0; i < tag_length; ++i) {
        expected_U[i] = T[i] ^ enc_S0[i];
    }

    if (!_constant_time_equal(received_U, expected_U)) {
        throw std::runtime_error("AES-CCM authentication failed: tag mismatch.");
    }
    return plaintext;
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
