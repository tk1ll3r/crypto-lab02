// -*- coding: utf-8 -*-
/**
 * sp800_38a.cpp - Bộ tiêu chuẩn 1: NIST SP 800-38A (Confidentiality Modes of Operation)
 * Bao gồm 5 chế độ: ECB, CBC, CFB, OFB, CTR + PKCS#7 Padding & Các hàm chuyển đổi dữ liệu.
 * (Lưu ý: Đã loại bỏ tiêu chuẩn NIST SP 800-38B CMAC theo đúng yêu cầu bài Lab).
 *
 * Môn: Mật mã học (NT219 - UIT)
 * Giải thích cơ chế xử lý từng khối (Block-by-block) được comment chi tiết bên dưới.
 */

#include "modes.h"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>

// 
// KHỐI 1: KHỞI TẠO ĐỐI TƯỢNG MODES & KIỂM TRA KHÓA AES (128 / 192 / 256 BIT)
// 

modes::modes(const ByteVec& key_data, bool verbose_mode, AES::SBoxMode sbox_mode)
    : key(_ValidateKey(key_data)),
      aes(this->key, static_cast<int>(this->key.size() * 8), sbox_mode),
      verbose(verbose_mode),
      iv(std::nullopt) {}

modes::modes(const std::string& key_str, bool verbose_mode, AES::SBoxMode sbox_mode)
    : modes(_ensure_bytes(key_str, "key"), verbose_mode, sbox_mode) {}

modes::ByteVec modes::_ValidateKey(const ByteVec& k) {
    // Khóa AES hợp lệ bắt buộc phải có độ dài 16 byte (128-bit), 24 byte (192-bit) hoặc 32 byte (256-bit)
    if (std::find(VALID_AES_KEY_BYTES.begin(), VALID_AES_KEY_BYTES.end(), k.size()) ==
        VALID_AES_KEY_BYTES.end()) {
        throw std::invalid_argument("Invalid AES key length. Supported lengths are 16, 24, or 32 bytes.");
    }
    return k;
}

bool modes::_constant_time_equal(const ByteVec& a, const ByteVec& b) noexcept {
    // So sánh 2 mảng byte trong thời gian hằng số (chống tấn công timing side-channel khi kiểm tra tag)
    if (a.size() != b.size()) return false;
    Byte diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= (a[i] ^ b[i]);
    }
    return diff == 0;
}

// 
// KHỐI 2: CÁC HÀM CHUYỂN ĐỔI DỮ LIỆU & CHIA KHỐI (CHUNKING 16-BYTE BLOCKS)
// 

modes::ByteVec modes::_ensure_bytes(const ByteVec& data, const std::string& /*name*/) {
    return data;
}

modes::ByteVec modes::_ensure_bytes(const std::string& data, const std::string& /*name*/) {
    // Nếu chuỗi đầu vào bắt đầu bằng "0b", chuyển từ chuỗi nhị phân sang mảng byte
    if (data.size() >= 2 && data[0] == '0' && (data[1] == 'b' || data[1] == 'B')) {
        return binary_to_bytes(data.substr(2));
    }
    return utf8_to_bytes(data);
}

modes::ByteVec modes::utf8_to_bytes(const std::string& utf8_str) {
    return ByteVec(utf8_str.begin(), utf8_str.end());
}

std::string modes::bytes_to_utf8(const ByteVec& bytes_data) {
    return std::string(bytes_data.begin(), bytes_data.end());
}

std::string modes::bytes_to_hex(const ByteVec& bytes_data) {
    return AES::bytes_to_hex(bytes_data);
}

modes::ByteVec modes::hex_to_bytes(const std::string& hex_str) {
    return AES::hex_to_bytes(hex_str);
}

modes::ByteVec modes::binary_to_bytes(std::string binary_str) {
    // Chuyển chuỗi bit '0101...' sang byte có kèm padding bit '10*' khả nghịch để giữ các bit 0 ở đầu
    if (binary_str.size() >= 2 && binary_str[0] == '0' &&
        (binary_str[1] == 'b' || binary_str[1] == 'B')) {
        binary_str = binary_str.substr(2);
    }
    for (char ch : binary_str) {
        if (ch != '0' && ch != '1') {
            throw std::invalid_argument("binary_str must contain only '0' and '1'.");
        }
    }

    size_t pad_len = 8 - (binary_str.size() % 8);
    if (pad_len == 0) {
        pad_len = 8;
    }
    std::string padded = binary_str + "1" + std::string(pad_len - 1, '0');

    ByteVec out;
    out.reserve(padded.size() / 8);
    for (size_t i = 0; i < padded.size(); i += 8) {
        Byte b = 0;
        for (size_t bit = 0; bit < 8; ++bit) {
            b = static_cast<Byte>((b << 1) | (padded[i + bit] == '1' ? 1 : 0));
        }
        out.push_back(b);
    }
    return out;
}

std::string modes::bytes_to_binary(const ByteVec& bytes_data) {
    // Khôi phục lại chuỗi nhị phân '0b...' bằng cách tìm vị trí bit '1' cuối cùng (marker bit)
    std::string bit_stream;
    bit_stream.reserve(bytes_data.size() * 8);
    for (Byte b : bytes_data) {
        for (int bit = 7; bit >= 0; --bit) {
            bit_stream.push_back(((b >> bit) & 1) ? '1' : '0');
        }
    }
    auto marker = bit_stream.rfind('1');
    if (marker == std::string::npos) {
        throw std::invalid_argument("Invalid reversible binary padding: missing marker bit.");
    }
    return "0b" + bit_stream.substr(0, marker);
}

modes::ByteVec modes::_xor(const ByteVec& a, const ByteVec& b) {
    // Phép XOR từng byte giữa 2 khối dữ liệu có cùng kích thước
    if (a.size() != b.size()) {
        throw std::invalid_argument("XOR operands must have equal length.");
    }
    ByteVec out(a.size());
    for (size_t i = 0; i < a.size(); ++i) {
        out[i] = a[i] ^ b[i];
    }
    return out;
}

std::vector<modes::ByteVec> modes::_chunks(const ByteVec& data, size_t size) {
    // Chia luồng dữ liệu đầu vào thành từng khối (block/segment) có kích thước cố định `size` byte
    if (size == 0) {
        throw std::invalid_argument("Chunk size must be positive.");
    }
    std::vector<ByteVec> chunks;
    for (size_t i = 0; i < data.size(); i += size) {
        size_t end = std::min(i + size, data.size());
        chunks.emplace_back(data.begin() + static_cast<std::ptrdiff_t>(i),
                            data.begin() + static_cast<std::ptrdiff_t>(end));
    }
    return chunks;
}

void modes::_require_block_multiple(const ByteVec& data, const std::string& name) {
    if (data.empty() || data.size() % BLOCK_SIZE != 0) {
        throw std::invalid_argument(name + " length must be a non-zero multiple of 16 bytes.");
    }
}

modes::ByteVec modes::_require_exact_block(const ByteVec& data, const std::string& name) {
    if (data.size() != BLOCK_SIZE) {
        throw std::invalid_argument(name + " must be exactly 16 bytes.");
    }
    return data;
}

modes::ByteVec modes::random_bytes(size_t n) {
    std::random_device rd;
    ByteVec out(n);
    for (size_t i = 0; i < n; ++i) {
        out[i] = static_cast<Byte>(rd() & 0xFF);
    }
    return out;
}

modes::ByteVec modes::_fresh_iv(const std::optional<ByteVec>& custom_iv, const std::string& name) {
    // Khởi tạo Vector khởi tạo (IV) 16 byte ngẫu nhiên mới cho mỗi lần mã hóa nếu người dùng không truyền vào
    ByteVec value = custom_iv.has_value() ? custom_iv.value() : random_bytes(BLOCK_SIZE);
    _require_exact_block(value, name);
    this->iv = value;
    if (this->verbose) {
        std::string upper_name = name;
        for (char& c : upper_name) {
            c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        }
        std::cout << "[" << upper_name << "]: " << bytes_to_hex(value) << "\n";
    }
    return value;
}

// 
// KHỐI 3: ĐỆM DỮ LIỆU PKCS#7 PADDING & TÍNH SỐ BYTE BỊ THIẾU (BONUS POINT)
// 

size_t modes::get_padding_length(size_t data_len) noexcept {
    // Tính số byte cần đệm thêm (từ 1 đến 16 byte) để tổng độ dài chia hết cho 16 byte
    return BLOCK_SIZE - (data_len % BLOCK_SIZE);
}

modes::ByteVec modes::pkcs7_padding(const ByteVec& data_bytes, bool print_info) {
    // Block cuối cùng có phần dư `remainder = data_bytes.size() % 16`
    // Số byte bị thiếu trong block cuối: `missing_bytes = (remainder == 0) ? 0 : (16 - remainder)`
    // Theo chuẩn PKCS#7: luôn đệm thêm `padding_length = 16 - remainder` byte có giá trị bằng `padding_length`
    size_t remainder = data_bytes.size() % BLOCK_SIZE;
    size_t missing_bytes = (remainder == 0) ? 0 : (BLOCK_SIZE - remainder);
    size_t padding_length = BLOCK_SIZE - remainder;

    if (print_info) {
        std::cout << "[PKCS#7 Padding] data_len=" << data_bytes.size()
                  << " bytes | missing_bytes_in_last_block=" << missing_bytes
                  << " | padding_length=" << padding_length
                  << " (0x" << std::hex << std::setw(2) << std::setfill('0')
                  << padding_length << std::dec << ")\n";
    }

    ByteVec padded = data_bytes;
    padded.insert(padded.end(), padding_length, static_cast<Byte>(padding_length));
    return padded;
}

modes::ByteVec modes::pkcs7_padding(const std::string& data_str, bool print_info) {
    return pkcs7_padding(_ensure_bytes(data_str, "data"), print_info);
}

modes::ByteVec modes::pkcs7_unpadding(const ByteVec& data_bytes, bool print_info) {
    // Đọc byte cuối cùng của block cuối để lấy `padding_length`, kiểm tra tính hợp lệ của toàn bộ các byte đệm
    if (data_bytes.empty() || data_bytes.size() % BLOCK_SIZE != 0) {
        throw std::invalid_argument("PKCS#7 padded data must be a non-zero multiple of 16 bytes.");
    }
    size_t padding_length = data_bytes.back();
    if (padding_length < 1 || padding_length > BLOCK_SIZE) {
        throw std::invalid_argument("Invalid PKCS#7 padding length.");
    }
    for (size_t i = data_bytes.size() - padding_length; i < data_bytes.size(); ++i) {
        if (data_bytes[i] != static_cast<Byte>(padding_length)) {
            throw std::invalid_argument("Invalid PKCS#7 padding bytes.");
        }
    }
    if (print_info) {
        std::cout << "[PKCS#7 Unpadding] total_len=" << data_bytes.size()
                  << " bytes | removed padding_length=" << padding_length
                  << " bytes -> unpadded_len=" << (data_bytes.size() - padding_length) << " bytes\n";
    }
    return ByteVec(data_bytes.begin(),
                   data_bytes.end() - static_cast<std::ptrdiff_t>(padding_length));
}

// 
// KHỐI 4: CHẾ ĐỘ ECB (ELECTRONIC CODEBOOK - NIST SP 800-38A MỤC 6.1)
// Nguyên lý từng Block:
//   - Mã hóa: Mỗi khối bản rõ 16-byte P_i được mã hóa độc lập: C_i = AES_Encrypt(K, P_i)
//   - Giải mã: Mỗi khối bản mã 16-byte C_i được giải mã độc lập: P_i = AES_Decrypt(K, C_i)
// 

modes::ByteVec modes::ecb_encrypt(const ByteVec& plaintext, bool pad) {
    ByteVec data = plaintext;
    if (pad) {
        data = pkcs7_padding(data, this->verbose);
    } else {
        _require_block_multiple(data, "plaintext");
    }

    ByteVec out;
    out.reserve(data.size());
    // Chia dữ liệu đã pad thành các block 16 byte và mã hóa độc lập từng block
    auto blocks = _chunks(data, BLOCK_SIZE);
    for (size_t idx = 0; idx < blocks.size(); ++idx) {
        // Xử lý Block thứ `idx`: C[idx] = AES_K(P[idx])
        ByteVec enc = this->aes.encrypt(blocks[idx]);
        if (this->verbose) {
            std::cout << "[ECB Encrypt Block " << idx << "] PT=" << bytes_to_hex(blocks[idx])
                      << " -> CT=" << bytes_to_hex(enc) << "\n";
        }
        out.insert(out.end(), enc.begin(), enc.end());
    }
    return out;
}

modes::ByteVec modes::ecb_encrypt(const std::string& plaintext, bool pad) {
    return ecb_encrypt(_ensure_bytes(plaintext, "plaintext"), pad);
}

modes::ByteVec modes::ecb_decrypt_bytes(const ByteVec& ciphertext, bool unpad) {
    _require_block_multiple(ciphertext, "ciphertext");

    ByteVec plaintext;
    plaintext.reserve(ciphertext.size());
    // Chia bản mã thành các block 16 byte và giải mã độc lập từng block
    auto blocks = _chunks(ciphertext, BLOCK_SIZE);
    for (size_t idx = 0; idx < blocks.size(); ++idx) {
        // Xử lý Block thứ `idx`: P[idx] = AES_Decrypt_K(C[idx])
        ByteVec dec = this->aes.decrypt(blocks[idx]);
        if (this->verbose) {
            std::cout << "[ECB Decrypt Block " << idx << "] CT=" << bytes_to_hex(blocks[idx])
                      << " -> PT=" << bytes_to_hex(dec) << "\n";
        }
        plaintext.insert(plaintext.end(), dec.begin(), dec.end());
    }
    if (unpad) {
        plaintext = pkcs7_unpadding(plaintext, this->verbose);
    }
    return plaintext;
}

std::string modes::ecb_decrypt(const ByteVec& ciphertext, bool unpad) {
    return bytes_to_utf8(ecb_decrypt_bytes(ciphertext, unpad));
}

// 
// KHỐI 5: CHẾ ĐỘ CBC (CIPHER BLOCK CHAINING - NIST SP 800-38A MỤC 6.2)
// Nguyên lý từng Block:
//   - Mã hóa:
//       + Khối đầu tiên (Block 0): C_0 = AES_Encrypt(K, P_0 XOR IV)
//       + Các khối tiếp theo (Block i): C_i = AES_Encrypt(K, P_i XOR C_{i-1})
//   - Giải mã:
//       + Khối đầu tiên (Block 0): P_0 = AES_Decrypt(K, C_0) XOR IV
//       + Các khối tiếp theo (Block i): P_i = AES_Decrypt(K, C_i) XOR C_{i-1}
// 

modes::ByteVec modes::cbc_encrypt(const ByteVec& plaintext,
                                  const std::optional<ByteVec>& custom_iv,
                                  bool prepend_iv,
                                  bool pad) {
    ByteVec iv_bytes = _fresh_iv(custom_iv, "iv");
    ByteVec data = plaintext;
    if (pad) {
        data = pkcs7_padding(data, this->verbose);
    } else {
        _require_block_multiple(data, "plaintext");
    }

    ByteVec body;
    body.reserve(data.size());
    // Khởi tạo khối phản hồi trước đó `previous` bằng IV cho Block 0
    ByteVec previous = iv_bytes;
    auto blocks = _chunks(data, BLOCK_SIZE);
    for (size_t idx = 0; idx < blocks.size(); ++idx) {
        // Bước 1 của Block `idx`: XOR khối bản rõ hiện tại với khối bản mã liền trước (hoặc IV)
        ByteVec xored = _xor(blocks[idx], previous);
        // Bước 2 của Block `idx`: Mã hóa kết quả XOR qua hàm khối AES
        ByteVec encrypted = this->aes.encrypt(xored);
        if (this->verbose) {
            std::cout << "[CBC Encrypt Block " << idx << "] PT=" << bytes_to_hex(blocks[idx])
                      << " ^ Prev=" << bytes_to_hex(previous)
                      << " -> XOR=" << bytes_to_hex(xored)
                      << " -> CT=" << bytes_to_hex(encrypted) << "\n";
        }
        body.insert(body.end(), encrypted.begin(), encrypted.end());
        // Bước 3 của Block `idx`: Cập nhật `previous = C[idx]` để móc xích sang Block `idx + 1`
        previous = encrypted;
    }

    if (prepend_iv) {
        ByteVec result = iv_bytes;
        result.insert(result.end(), body.begin(), body.end());
        return result;
    }
    return body;
}

modes::ByteVec modes::cbc_encrypt(const std::string& plaintext,
                                  const std::optional<ByteVec>& custom_iv,
                                  bool prepend_iv,
                                  bool pad) {
    return cbc_encrypt(_ensure_bytes(plaintext, "plaintext"), custom_iv, prepend_iv, pad);
}

modes::ByteVec modes::cbc_decrypt_bytes(const ByteVec& ciphertext,
                                        const std::optional<ByteVec>& custom_iv,
                                        bool has_iv,
                                        bool unpad) {
    ByteVec iv_bytes;
    ByteVec data;
    // Tách 16 byte đầu làm IV nếu bản mã có đính kèm IV ở đầu (`has_iv = true`)
    if (has_iv) {
        if (ciphertext.size() < 2 * BLOCK_SIZE || ciphertext.size() % BLOCK_SIZE != 0) {
            throw std::invalid_argument(
                "CBC ciphertext with prepended IV must be at least 32 bytes and block-aligned."
            );
        }
        iv_bytes.assign(ciphertext.begin(), ciphertext.begin() + BLOCK_SIZE);
        data.assign(ciphertext.begin() + BLOCK_SIZE, ciphertext.end());
    } else {
        if (!custom_iv.has_value()) {
            throw std::invalid_argument("iv is required when has_iv=false.");
        }
        iv_bytes = _require_exact_block(custom_iv.value(), "iv");
        data = ciphertext;
        _require_block_multiple(data, "ciphertext");
    }

    ByteVec plaintext;
    plaintext.reserve(data.size());
    ByteVec previous = iv_bytes;
    auto blocks = _chunks(data, BLOCK_SIZE);
    for (size_t idx = 0; idx < blocks.size(); ++idx) {
        // Bước 1 của Block `idx`: Giải mã khối C[idx] qua AES_Decrypt
        ByteVec dec_block = this->aes.decrypt(blocks[idx]);
        // Bước 2 của Block `idx`: XOR với khối bản mã liền trước `previous` (hoặc IV) để khôi phục P[idx]
        ByteVec decrypted = _xor(dec_block, previous);
        if (this->verbose) {
            std::cout << "[CBC Decrypt Block " << idx << "] CT=" << bytes_to_hex(blocks[idx])
                      << " -> InvAES=" << bytes_to_hex(dec_block)
                      << " ^ Prev=" << bytes_to_hex(previous)
                      << " -> PT=" << bytes_to_hex(decrypted) << "\n";
        }
        plaintext.insert(plaintext.end(), decrypted.begin(), decrypted.end());
        // Bước 3 của Block `idx`: Lưu lại C[idx] làm `previous` cho Block `idx + 1`
        previous = blocks[idx];
    }

    if (unpad) {
        plaintext = pkcs7_unpadding(plaintext, this->verbose);
    }
    return plaintext;
}

std::string modes::cbc_decrypt(const ByteVec& ciphertext,
                               const std::optional<ByteVec>& custom_iv,
                               bool has_iv,
                               bool unpad) {
    return bytes_to_utf8(cbc_decrypt_bytes(ciphertext, custom_iv, has_iv, unpad));
}

// 
// KHỐI 6: CHẾ ĐỘ CFB (CIPHER FEEDBACK - NIST SP 800-38A MỤC 6.3)
// Nguyên lý từng phân đoạn (Segment s-bit, từ 8 đến 128 bit):
//   - Thanh ghi dịch 128-bit `reg` ban đầu được nạp giá trị IV.
//   - Với mỗi phân đoạn `segments[idx]`:
//       + Bước 1: Mã hóa thanh ghi `stream = AES_Encrypt(K, reg)` (Cả chiều mã hóa & giải mã đều dùng AES_Encrypt!)
//       + Bước 2: Lấy `s` bit đầu của `stream` đem XOR với phân đoạn bản rõ (hoặc bản mã).
//       + Bước 3: Dịch trái thanh ghi `reg` đi `s` bit và điền phân đoạn bản mã `C[idx]` vào `s` bit bên phải.
// 

modes::ByteVec modes::cfb_encrypt(const ByteVec& plaintext,
                                  const std::optional<ByteVec>& custom_iv,
                                  int segment_size,
                                  bool prepend_iv) {
    if (segment_size <= 0 || segment_size > 128 || segment_size % 8 != 0) {
        throw std::invalid_argument(
            "segment_size must be one of the byte-aligned sizes from 8 to 128 bits."
        );
    }
    size_t segment_bytes = static_cast<size_t>(segment_size / 8);
    ByteVec iv_bytes = _fresh_iv(custom_iv, "iv");

    ByteVec body;
    body.reserve(plaintext.size());
    ByteVec reg = iv_bytes;
    auto segments = _chunks(plaintext, segment_bytes);
    for (size_t idx = 0; idx < segments.size(); ++idx) {
        // Bước 1 của Segment `idx`: Mã hóa thanh ghi dịch 16-byte hiện tại bằng AES_Encrypt
        ByteVec stream = this->aes.encrypt(reg);
        // Bước 2 của Segment `idx`: Trích xuất số byte tương ứng và XOR với phân đoạn bản rõ
        ByteVec stream_slice(stream.begin(),
                             stream.begin() + static_cast<std::ptrdiff_t>(segments[idx].size()));
        ByteVec encrypted = _xor(segments[idx], stream_slice);
        if (this->verbose) {
            std::cout << "[CFB-" << segment_size << " Encrypt Seg " << idx << "] Reg=" << bytes_to_hex(reg)
                      << " -> Stream=" << bytes_to_hex(stream_slice)
                      << " ^ PT=" << bytes_to_hex(segments[idx])
                      << " -> CT=" << bytes_to_hex(encrypted) << "\n";
        }
        body.insert(body.end(), encrypted.begin(), encrypted.end());
        // Bước 3 của Segment `idx`: Dịch thanh ghi `reg` sang trái và nối bản mã `encrypted` vào cuối
        if (segments[idx].size() == segment_bytes) {
            ByteVec next_reg(reg.begin() + static_cast<std::ptrdiff_t>(segment_bytes), reg.end());
            next_reg.insert(next_reg.end(), encrypted.begin(), encrypted.end());
            reg = std::move(next_reg);
        }
    }

    if (prepend_iv) {
        ByteVec result = iv_bytes;
        result.insert(result.end(), body.begin(), body.end());
        return result;
    }
    return body;
}

modes::ByteVec modes::cfb_encrypt(const std::string& plaintext,
                                  const std::optional<ByteVec>& custom_iv,
                                  int segment_size,
                                  bool prepend_iv) {
    return cfb_encrypt(_ensure_bytes(plaintext, "plaintext"), custom_iv, segment_size, prepend_iv);
}

modes::ByteVec modes::cfb_decrypt_bytes(const ByteVec& ciphertext,
                                        const std::optional<ByteVec>& custom_iv,
                                        bool has_iv,
                                        int segment_size) {
    if (segment_size <= 0 || segment_size > 128 || segment_size % 8 != 0) {
        throw std::invalid_argument(
            "segment_size must be one of the byte-aligned sizes from 8 to 128 bits."
        );
    }
    size_t segment_bytes = static_cast<size_t>(segment_size / 8);
    ByteVec iv_bytes;
    ByteVec data;
    if (has_iv) {
        if (ciphertext.size() < BLOCK_SIZE) {
            throw std::invalid_argument("CFB ciphertext with prepended IV must be at least 16 bytes.");
        }
        iv_bytes.assign(ciphertext.begin(), ciphertext.begin() + BLOCK_SIZE);
        data.assign(ciphertext.begin() + BLOCK_SIZE, ciphertext.end());
    } else {
        if (!custom_iv.has_value()) {
            throw std::invalid_argument("iv is required when has_iv=false.");
        }
        iv_bytes = _require_exact_block(custom_iv.value(), "iv");
        data = ciphertext;
    }

    ByteVec out;
    out.reserve(data.size());
    ByteVec reg = iv_bytes;
    auto segments = _chunks(data, segment_bytes);
    for (size_t idx = 0; idx < segments.size(); ++idx) {
        // Bước 1 của Segment `idx`: Vẫn dùng AES_Encrypt trên thanh ghi `reg` để tái tạo keystream
        ByteVec stream = this->aes.encrypt(reg);
        ByteVec stream_slice(stream.begin(),
                             stream.begin() + static_cast<std::ptrdiff_t>(segments[idx].size()));
        // Bước 2 của Segment `idx`: XOR phân đoạn bản mã với keystream để thu được bản rõ
        ByteVec decrypted = _xor(segments[idx], stream_slice);
        if (this->verbose) {
            std::cout << "[CFB-" << segment_size << " Decrypt Seg " << idx << "] Reg=" << bytes_to_hex(reg)
                      << " -> Stream=" << bytes_to_hex(stream_slice)
                      << " ^ CT=" << bytes_to_hex(segments[idx])
                      << " -> PT=" << bytes_to_hex(decrypted) << "\n";
        }
        out.insert(out.end(), decrypted.begin(), decrypted.end());
        // Bước 3 của Segment `idx`: Đưa phân đoạn bản mã `segments[idx]` vào cuối thanh ghi dịch `reg`
        if (segments[idx].size() == segment_bytes) {
            ByteVec next_reg(reg.begin() + static_cast<std::ptrdiff_t>(segment_bytes), reg.end());
            next_reg.insert(next_reg.end(), segments[idx].begin(), segments[idx].end());
            reg = std::move(next_reg);
        }
    }
    return out;
}

std::string modes::cfb_decrypt(const ByteVec& ciphertext,
                               const std::optional<ByteVec>& custom_iv,
                               bool has_iv,
                               int segment_size) {
    return bytes_to_utf8(cfb_decrypt_bytes(ciphertext, custom_iv, has_iv, segment_size));
}

// 
// KHỐI 7: CHẾ ĐỘ OFB (OUTPUT FEEDBACK - NIST SP 800-38A MỤC 6.4)
// Nguyên lý từng Block:
//   - Biến `feedback` khởi đầu bằng IV: O_{-1} = IV.
//   - Với mỗi Block thứ `idx`:
//       + Bước 1: Sinh dòng khóa O_idx = AES_Encrypt(K, O_{idx-1}) (độc lập với cả bản rõ lẫn bản mã).
//       + Bước 2: C_idx = P_idx XOR O_idx (mã hóa) hoặc P_idx = C_idx XOR O_idx (giải mã).
// 

modes::ByteVec modes::ofb_encrypt(const ByteVec& plaintext,
                                  const std::optional<ByteVec>& custom_iv,
                                  bool prepend_iv) {
    ByteVec iv_bytes = _fresh_iv(custom_iv, "iv");
    ByteVec body;
    body.reserve(plaintext.size());
    ByteVec feedback = iv_bytes;
    auto blocks = _chunks(plaintext, BLOCK_SIZE);
    for (size_t idx = 0; idx < blocks.size(); ++idx) {
        // Bước 1 của Block `idx`: Mã hóa khối `feedback` trước đó để sinh khối keystream mới
        feedback = this->aes.encrypt(feedback);
        ByteVec fb_slice(feedback.begin(),
                         feedback.begin() + static_cast<std::ptrdiff_t>(blocks[idx].size()));
        // Bước 2 của Block `idx`: XOR khối bản rõ `blocks[idx]` với keystream
        ByteVec enc = _xor(blocks[idx], fb_slice);
        if (this->verbose) {
            std::cout << "[OFB Encrypt Block " << idx << "] Keystream=" << bytes_to_hex(fb_slice)
                      << " ^ PT=" << bytes_to_hex(blocks[idx])
                      << " -> CT=" << bytes_to_hex(enc) << "\n";
        }
        body.insert(body.end(), enc.begin(), enc.end());
    }

    if (prepend_iv) {
        ByteVec result = iv_bytes;
        result.insert(result.end(), body.begin(), body.end());
        return result;
    }
    return body;
}

modes::ByteVec modes::ofb_encrypt(const std::string& plaintext,
                                  const std::optional<ByteVec>& custom_iv,
                                  bool prepend_iv) {
    return ofb_encrypt(_ensure_bytes(plaintext, "plaintext"), custom_iv, prepend_iv);
}

modes::ByteVec modes::ofb_decrypt_bytes(const ByteVec& ciphertext,
                                        const std::optional<ByteVec>& custom_iv,
                                        bool has_iv) {
    ByteVec iv_bytes;
    ByteVec data;
    if (has_iv) {
        if (ciphertext.size() < BLOCK_SIZE) {
            throw std::invalid_argument("OFB ciphertext with prepended IV must be at least 16 bytes.");
        }
        iv_bytes.assign(ciphertext.begin(), ciphertext.begin() + BLOCK_SIZE);
        data.assign(ciphertext.begin() + BLOCK_SIZE, ciphertext.end());
    } else {
        if (!custom_iv.has_value()) {
            throw std::invalid_argument("iv is required when has_iv=false.");
        }
        iv_bytes = _require_exact_block(custom_iv.value(), "iv");
        data = ciphertext;
    }

    ByteVec out;
    out.reserve(data.size());
    ByteVec feedback = iv_bytes;
    auto blocks = _chunks(data, BLOCK_SIZE);
    for (size_t idx = 0; idx < blocks.size(); ++idx) {
        // Giải mã OFB hoàn toàn đối xứng với mã hóa: tái tạo `feedback` rồi XOR với bản mã
        feedback = this->aes.encrypt(feedback);
        ByteVec fb_slice(feedback.begin(),
                         feedback.begin() + static_cast<std::ptrdiff_t>(blocks[idx].size()));
        ByteVec dec = _xor(blocks[idx], fb_slice);
        if (this->verbose) {
            std::cout << "[OFB Decrypt Block " << idx << "] Keystream=" << bytes_to_hex(fb_slice)
                      << " ^ CT=" << bytes_to_hex(blocks[idx])
                      << " -> PT=" << bytes_to_hex(dec) << "\n";
        }
        out.insert(out.end(), dec.begin(), dec.end());
    }
    return out;
}

std::string modes::ofb_decrypt(const ByteVec& ciphertext,
                               const std::optional<ByteVec>& custom_iv,
                               bool has_iv) {
    return bytes_to_utf8(ofb_decrypt_bytes(ciphertext, custom_iv, has_iv));
}

// 
// KHỐI 8: CHẾ ĐỘ CTR (COUNTER MODE - NIST SP 800-38A MỤC 6.5)
// Nguyên lý từng Block:
//   - Khối bộ đếm 128-bit `counter` khởi đầu từ `iv_bytes` (Initial Counter Block).
//   - Với mỗi Block thứ `idx`:
//       + Bước 1: Mã hóa giá trị `counter` hiện tại: Keystream_idx = AES_Encrypt(K, counter).
//       + Bước 2: XOR `blocks[idx]` với `Keystream_idx` để tạo bản mã (hoặc khôi phục bản rõ).
//       + Bước 3: Tăng `counter = (counter + 1) mod 2^128` theo thứ tự Big-Endian cho Block tiếp theo.
// 

void modes::_increment_be_128(ByteVec& counter) noexcept {
    // Cộng 1 vào số nguyên 128-bit biểu diễn dạng Big-Endian (từ byte cuối 15 ngược về byte 0)
    for (int i = 15; i >= 0; --i) {
        if (++counter[static_cast<size_t>(i)] != 0) {
            break;
        }
    }
}

modes::ByteVec modes::ctr_encrypt(const ByteVec& plaintext,
                                  const std::optional<ByteVec>& custom_iv,
                                  bool prepend_iv) {
    ByteVec iv_bytes = _fresh_iv(custom_iv, "iv");
    ByteVec counter = iv_bytes;

    ByteVec body;
    body.reserve(plaintext.size());
    auto blocks = _chunks(plaintext, BLOCK_SIZE);
    for (size_t idx = 0; idx < blocks.size(); ++idx) {
        // Bước 1 của Block `idx`: Mã hóa khối bộ đếm `counter` để sinh keystream
        ByteVec key_stream = this->aes.encrypt(counter);
        ByteVec ks_slice(key_stream.begin(),
                         key_stream.begin() + static_cast<std::ptrdiff_t>(blocks[idx].size()));
        // Bước 2 của Block `idx`: XOR khối bản rõ với keystream
        ByteVec enc = _xor(blocks[idx], ks_slice);
        if (this->verbose) {
            std::cout << "[CTR Encrypt Block " << idx << "] Counter=" << bytes_to_hex(counter)
                      << " -> Keystream=" << bytes_to_hex(ks_slice)
                      << " ^ PT=" << bytes_to_hex(blocks[idx])
                      << " -> CT=" << bytes_to_hex(enc) << "\n";
        }
        body.insert(body.end(), enc.begin(), enc.end());
        // Bước 3 của Block `idx`: Tăng bộ đếm lên 1 đơn vị cho Block `idx + 1`
        _increment_be_128(counter);
    }

    if (prepend_iv) {
        ByteVec result = iv_bytes;
        result.insert(result.end(), body.begin(), body.end());
        return result;
    }
    return body;
}

modes::ByteVec modes::ctr_encrypt(const std::string& plaintext,
                                  const std::optional<ByteVec>& custom_iv,
                                  bool prepend_iv) {
    return ctr_encrypt(_ensure_bytes(plaintext, "plaintext"), custom_iv, prepend_iv);
}

modes::ByteVec modes::ctr_decrypt_bytes(const ByteVec& ciphertext,
                                        const std::optional<ByteVec>& custom_iv,
                                        bool has_iv) {
    ByteVec iv_bytes;
    ByteVec data;
    if (has_iv) {
        if (ciphertext.size() < BLOCK_SIZE) {
            throw std::invalid_argument("CTR ciphertext with prepended counter block must be at least 16 bytes.");
        }
        iv_bytes.assign(ciphertext.begin(), ciphertext.begin() + BLOCK_SIZE);
        data.assign(ciphertext.begin() + BLOCK_SIZE, ciphertext.end());
    } else {
        if (!custom_iv.has_value()) {
            throw std::invalid_argument("iv is required when has_iv=false.");
        }
        iv_bytes = _require_exact_block(custom_iv.value(), "iv");
        data = ciphertext;
    }

    ByteVec counter = iv_bytes;
    ByteVec out;
    out.reserve(data.size());
    auto blocks = _chunks(data, BLOCK_SIZE);
    for (size_t idx = 0; idx < blocks.size(); ++idx) {
        // Giải mã CTR giống hệt mã hóa: sinh keystream từ `counter` rồi XOR với khối bản mã
        ByteVec key_stream = this->aes.encrypt(counter);
        ByteVec ks_slice(key_stream.begin(),
                         key_stream.begin() + static_cast<std::ptrdiff_t>(blocks[idx].size()));
        ByteVec dec = _xor(blocks[idx], ks_slice);
        if (this->verbose) {
            std::cout << "[CTR Decrypt Block " << idx << "] Counter=" << bytes_to_hex(counter)
                      << " -> Keystream=" << bytes_to_hex(ks_slice)
                      << " ^ CT=" << bytes_to_hex(blocks[idx])
                      << " -> PT=" << bytes_to_hex(dec) << "\n";
        }
        out.insert(out.end(), dec.begin(), dec.end());
        _increment_be_128(counter);
    }
    return out;
}

std::string modes::ctr_decrypt(const ByteVec& ciphertext,
                               const std::optional<ByteVec>& custom_iv,
                               bool has_iv) {
    return bytes_to_utf8(ctr_decrypt_bytes(ciphertext, custom_iv, has_iv));
}
