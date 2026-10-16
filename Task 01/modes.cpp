// -*- coding: utf-8 -*-
/**
 * modes.cpp - AES modes of operation in pure C++17 Standard Library.
 * Converted from modes.py for UIT NT219 Cryptography Lab (Task 1).
 *
 * What this file implements (100% C++ Standard Library, zero external dependencies):
 *   1. Local AES block cipher primitive: #include "AES.cpp"
 *   2. NIST SP 800-38A confidentiality modes:
 *        - ECB, CBC, CFB (8..128-bit segments), OFB, CTR
 *   3. Additional NIST & RFC modes from modes.py implemented from scratch on top of AES:
 *        - AES-CCM        (AEAD; NIST SP 800-38C)
 *        - AES-GCM / GMAC (AEAD; NIST SP 800-38D)
 *        - AES-GCM-SIV    (Misuse-resistant AEAD; RFC 8452)
 *        - AES-XTS        (Storage encryption with ciphertext stealing; NIST SP 800-38E)
 *        - AES-KW / KWP   (Key Wrapping with/without padding; NIST SP 800-38F / RFC 3394 & 5649)
 *   4. Strict PKCS#7 padding/unpadding with missing_bytes / padding_length calculation.
 *   5. Reversible binary string ('0b...') <-> bytes & UTF-8 / Hex conversion helpers.
 *   6. Block-by-block command-line trace & automated test suite against NIST FIPS 197 & modes.py.
 *
 * Compile & run:
 *   g++ -std=c++17 -O2 modes.cpp -o modes && ./modes
 *   (or: g++ -std=c++17 -O2 AES.cpp modes.cpp -o modes && ./modes)
 */

#ifndef UIT_MODES_CPP_INCLUDED
#define UIT_MODES_CPP_INCLUDED

#include "AES.cpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <optional>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

class modes {
public:
    using Byte = AES::Byte;
    using ByteVec = AES::ByteVec;

    static constexpr size_t BLOCK_SIZE = 16;
    inline static constexpr std::array<size_t, 3> VALID_AES_KEY_BYTES = {16, 24, 32};

    ByteVec key;
    AES aes;
    bool verbose;
    std::optional<ByteVec> iv; // last IV/initial counter used; never reused by default

    /**
     * Construct AES modes wrapper with a 16-, 24-, or 32-byte key.
     */
    explicit modes(const ByteVec& key_data, bool verbose_mode = false)
        : key(_ValidateKey(key_data)),
          aes(this->key, static_cast<int>(this->key.size() * 8)),
          verbose(verbose_mode),
          iv(std::nullopt) {}

    explicit modes(const std::string& key_str, bool verbose_mode = false)
        : modes(_ensure_bytes(key_str, "key"), verbose_mode) {}

    // -------------------------------------------------------------------------
    // Data conversion helpers (matching modes.py)
    // -------------------------------------------------------------------------
    static ByteVec _ensure_bytes(const ByteVec& data, const std::string& /*name*/ = "data") {
        return data;
    }

    static ByteVec _ensure_bytes(const std::string& data, const std::string& /*name*/ = "data") {
        // Preserve original binary-string convenience path ("0b...")
        if (data.size() >= 2 && data[0] == '0' && (data[1] == 'b' || data[1] == 'B')) {
            return binary_to_bytes(data.substr(2));
        }
        return utf8_to_bytes(data);
    }

    static ByteVec utf8_to_bytes(const std::string& utf8_str) {
        return ByteVec(utf8_str.begin(), utf8_str.end());
    }

    static std::string bytes_to_utf8(const ByteVec& bytes_data) {
        return std::string(bytes_data.begin(), bytes_data.end());
    }

    static std::string bytes_to_hex(const ByteVec& bytes_data) {
        return AES::bytes_to_hex(bytes_data);
    }

    static ByteVec hex_to_bytes(const std::string& hex_str) {
        return AES::hex_to_bytes(hex_str);
    }

    /**
     * Convert a '0101...' bit string to bytes using reversible 1-bit padding ('10*').
     * Preserves leading zero bits exactly like modes.py.
     */
    static ByteVec binary_to_bytes(std::string binary_str) {
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

    /**
     * Inverse of binary_to_bytes(). Returns a '0b...' string.
     */
    static std::string bytes_to_binary(const ByteVec& bytes_data) {
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

    static ByteVec _xor(const ByteVec& a, const ByteVec& b) {
        if (a.size() != b.size()) {
            throw std::invalid_argument("XOR operands must have equal length.");
        }
        ByteVec out(a.size());
        for (size_t i = 0; i < a.size(); ++i) {
            out[i] = a[i] ^ b[i];
        }
        return out;
    }

    static std::vector<ByteVec> _chunks(const ByteVec& data, size_t size) {
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

    static void _require_block_multiple(const ByteVec& data, const std::string& name) {
        if (data.empty() || data.size() % BLOCK_SIZE != 0) {
            throw std::invalid_argument(name + " length must be a non-zero multiple of 16 bytes.");
        }
    }

    static ByteVec _require_exact_block(const ByteVec& data, const std::string& name) {
        if (data.size() != BLOCK_SIZE) {
            throw std::invalid_argument(name + " must be exactly 16 bytes.");
        }
        return data;
    }

    static ByteVec random_bytes(size_t n) {
        std::random_device rd;
        ByteVec out(n);
        for (size_t i = 0; i < n; ++i) {
            out[i] = static_cast<Byte>(rd() & 0xFF);
        }
        return out;
    }

    ByteVec _fresh_iv(const std::optional<ByteVec>& custom_iv = std::nullopt,
                      const std::string& name = "iv") {
        ByteVec value = custom_iv.has_value() ? custom_iv.value() : random_bytes(BLOCK_SIZE);
        _require_exact_block(value, name);
        this->iv = value;
        if (this->verbose) {
            std::string upper_name = name;
            for (char& c : upper_name) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
            std::cout << "[" << upper_name << "]: " << bytes_to_hex(value) << "\n";
        }
        return value;
    }

    // -------------------------------------------------------------------------
    // Padding helpers (PKCS#7 + missing bytes / padding_length inspection)
    // -------------------------------------------------------------------------

    /**
     * Compute padding_length (số byte bị thiếu để tròn block 16 bytes theo PKCS#7).
     * Nếu dữ liệu đã chia hết cho 16, PKCS#7 thêm đúng 1 block 16 bytes (0x10).
     */
    static size_t get_padding_length(size_t data_len) noexcept {
        return BLOCK_SIZE - (data_len % BLOCK_SIZE);
    }

    static ByteVec pkcs7_padding(const ByteVec& data_bytes, bool print_info = false) {
        size_t remainder = data_bytes.size() % BLOCK_SIZE;
        size_t missing_bytes = (remainder == 0) ? 0 : (BLOCK_SIZE - remainder);
        size_t padding_length = BLOCK_SIZE - remainder; // PKCS#7: 1..16 bytes

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

    static ByteVec pkcs7_padding(const std::string& data_str, bool print_info = false) {
        return pkcs7_padding(_ensure_bytes(data_str, "data"), print_info);
    }

    static ByteVec pkcs7_unpadding(const ByteVec& data_bytes, bool print_info = false) {
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

    // -------------------------------------------------------------------------
    // NIST SP 800-38A confidentiality modes: ECB, CBC, CFB, OFB, CTR
    // -------------------------------------------------------------------------

    /**
     * AES-ECB encryption.
     */
    ByteVec ecb_encrypt(const ByteVec& plaintext, bool pad = true) {
        ByteVec data = plaintext;
        if (pad) {
            data = pkcs7_padding(data, this->verbose);
        } else {
            _require_block_multiple(data, "plaintext");
        }

        ByteVec out;
        out.reserve(data.size());
        auto blocks = _chunks(data, BLOCK_SIZE);
        for (size_t idx = 0; idx < blocks.size(); ++idx) {
            ByteVec enc = this->aes.encrypt(blocks[idx]);
            if (this->verbose) {
                std::cout << "[ECB Encrypt Block " << idx << "] PT=" << bytes_to_hex(blocks[idx])
                          << " -> CT=" << bytes_to_hex(enc) << "\n";
            }
            out.insert(out.end(), enc.begin(), enc.end());
        }
        return out;
    }

    ByteVec ecb_encrypt(const std::string& plaintext, bool pad = true) {
        return ecb_encrypt(_ensure_bytes(plaintext, "plaintext"), pad);
    }

    ByteVec ecb_decrypt_bytes(const ByteVec& ciphertext, bool unpad = true) {
        _require_block_multiple(ciphertext, "ciphertext");

        ByteVec plaintext;
        plaintext.reserve(ciphertext.size());
        auto blocks = _chunks(ciphertext, BLOCK_SIZE);
        for (size_t idx = 0; idx < blocks.size(); ++idx) {
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

    std::string ecb_decrypt(const ByteVec& ciphertext, bool unpad = true) {
        return bytes_to_utf8(ecb_decrypt_bytes(ciphertext, unpad));
    }

    /**
     * AES-CBC encryption with a fresh random IV by default.
     */
    ByteVec cbc_encrypt(const ByteVec& plaintext,
                        const std::optional<ByteVec>& custom_iv = std::nullopt,
                        bool prepend_iv = true,
                        bool pad = true) {
        ByteVec iv_bytes = _fresh_iv(custom_iv, "iv");
        ByteVec data = plaintext;
        if (pad) {
            data = pkcs7_padding(data, this->verbose);
        } else {
            _require_block_multiple(data, "plaintext");
        }

        ByteVec body;
        body.reserve(data.size());
        ByteVec previous = iv_bytes;
        auto blocks = _chunks(data, BLOCK_SIZE);
        for (size_t idx = 0; idx < blocks.size(); ++idx) {
            ByteVec xored = _xor(blocks[idx], previous);
            ByteVec encrypted = this->aes.encrypt(xored);
            if (this->verbose) {
                std::cout << "[CBC Encrypt Block " << idx << "] PT=" << bytes_to_hex(blocks[idx])
                          << " ^ Prev=" << bytes_to_hex(previous)
                          << " -> XOR=" << bytes_to_hex(xored)
                          << " -> CT=" << bytes_to_hex(encrypted) << "\n";
            }
            body.insert(body.end(), encrypted.begin(), encrypted.end());
            previous = encrypted;
        }

        if (prepend_iv) {
            ByteVec result = iv_bytes;
            result.insert(result.end(), body.begin(), body.end());
            return result;
        }
        return body;
    }

    ByteVec cbc_encrypt(const std::string& plaintext,
                        const std::optional<ByteVec>& custom_iv = std::nullopt,
                        bool prepend_iv = true,
                        bool pad = true) {
        return cbc_encrypt(_ensure_bytes(plaintext, "plaintext"), custom_iv, prepend_iv, pad);
    }

    ByteVec cbc_decrypt_bytes(const ByteVec& ciphertext,
                              const std::optional<ByteVec>& custom_iv = std::nullopt,
                              bool has_iv = true,
                              bool unpad = true) {
        ByteVec iv_bytes;
        ByteVec data;
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
            ByteVec dec_block = this->aes.decrypt(blocks[idx]);
            ByteVec decrypted = _xor(dec_block, previous);
            if (this->verbose) {
                std::cout << "[CBC Decrypt Block " << idx << "] CT=" << bytes_to_hex(blocks[idx])
                          << " -> InvAES=" << bytes_to_hex(dec_block)
                          << " ^ Prev=" << bytes_to_hex(previous)
                          << " -> PT=" << bytes_to_hex(decrypted) << "\n";
            }
            plaintext.insert(plaintext.end(), decrypted.begin(), decrypted.end());
            previous = blocks[idx];
        }

        if (unpad) {
            plaintext = pkcs7_unpadding(plaintext, this->verbose);
        }
        return plaintext;
    }

    std::string cbc_decrypt(const ByteVec& ciphertext,
                            const std::optional<ByteVec>& custom_iv = std::nullopt,
                            bool has_iv = true,
                            bool unpad = true) {
        return bytes_to_utf8(cbc_decrypt_bytes(ciphertext, custom_iv, has_iv, unpad));
    }

    /**
     * AES-CFB encryption (segment_size in bits: 8..128, byte-aligned). No padding is used.
     */
    ByteVec cfb_encrypt(const ByteVec& plaintext,
                        const std::optional<ByteVec>& custom_iv = std::nullopt,
                        int segment_size = 128,
                        bool prepend_iv = true) {
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
            ByteVec stream = this->aes.encrypt(reg);
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

    ByteVec cfb_encrypt(const std::string& plaintext,
                        const std::optional<ByteVec>& custom_iv = std::nullopt,
                        int segment_size = 128,
                        bool prepend_iv = true) {
        return cfb_encrypt(_ensure_bytes(plaintext, "plaintext"), custom_iv, segment_size, prepend_iv);
    }

    ByteVec cfb_decrypt_bytes(const ByteVec& ciphertext,
                              const std::optional<ByteVec>& custom_iv = std::nullopt,
                              bool has_iv = true,
                              int segment_size = 128) {
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
            ByteVec stream = this->aes.encrypt(reg);
            ByteVec stream_slice(stream.begin(),
                                 stream.begin() + static_cast<std::ptrdiff_t>(segments[idx].size()));
            ByteVec decrypted = _xor(segments[idx], stream_slice);
            if (this->verbose) {
                std::cout << "[CFB-" << segment_size << " Decrypt Seg " << idx << "] Reg=" << bytes_to_hex(reg)
                          << " -> Stream=" << bytes_to_hex(stream_slice)
                          << " ^ CT=" << bytes_to_hex(segments[idx])
                          << " -> PT=" << bytes_to_hex(decrypted) << "\n";
            }
            out.insert(out.end(), decrypted.begin(), decrypted.end());
            if (segments[idx].size() == segment_bytes) {
                ByteVec next_reg(reg.begin() + static_cast<std::ptrdiff_t>(segment_bytes), reg.end());
                next_reg.insert(next_reg.end(), segments[idx].begin(), segments[idx].end());
                reg = std::move(next_reg);
            }
        }
        return out;
    }

    std::string cfb_decrypt(const ByteVec& ciphertext,
                            const std::optional<ByteVec>& custom_iv = std::nullopt,
                            bool has_iv = true,
                            int segment_size = 128) {
        return bytes_to_utf8(cfb_decrypt_bytes(ciphertext, custom_iv, has_iv, segment_size));
    }

    /**
     * AES-OFB encryption. No padding is used.
     */
    ByteVec ofb_encrypt(const ByteVec& plaintext,
                        const std::optional<ByteVec>& custom_iv = std::nullopt,
                        bool prepend_iv = true) {
        ByteVec iv_bytes = _fresh_iv(custom_iv, "iv");
        ByteVec body;
        body.reserve(plaintext.size());
        ByteVec feedback = iv_bytes;
        auto blocks = _chunks(plaintext, BLOCK_SIZE);
        for (size_t idx = 0; idx < blocks.size(); ++idx) {
            feedback = this->aes.encrypt(feedback);
            ByteVec fb_slice(feedback.begin(),
                             feedback.begin() + static_cast<std::ptrdiff_t>(blocks[idx].size()));
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

    ByteVec ofb_encrypt(const std::string& plaintext,
                        const std::optional<ByteVec>& custom_iv = std::nullopt,
                        bool prepend_iv = true) {
        return ofb_encrypt(_ensure_bytes(plaintext, "plaintext"), custom_iv, prepend_iv);
    }

    ByteVec ofb_decrypt_bytes(const ByteVec& ciphertext,
                              const std::optional<ByteVec>& custom_iv = std::nullopt,
                              bool has_iv = true) {
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

    std::string ofb_decrypt(const ByteVec& ciphertext,
                            const std::optional<ByteVec>& custom_iv = std::nullopt,
                            bool has_iv = true) {
        return bytes_to_utf8(ofb_decrypt_bytes(ciphertext, custom_iv, has_iv));
    }

    /**
     * AES-CTR encryption using a 128-bit initial counter block (big-endian increment mod 2^128).
     */
    ByteVec ctr_encrypt(const ByteVec& plaintext,
                        const std::optional<ByteVec>& custom_iv = std::nullopt,
                        bool prepend_iv = true) {
        ByteVec iv_bytes = _fresh_iv(custom_iv, "iv");
        ByteVec counter = iv_bytes;

        ByteVec body;
        body.reserve(plaintext.size());
        auto blocks = _chunks(plaintext, BLOCK_SIZE);
        for (size_t idx = 0; idx < blocks.size(); ++idx) {
            ByteVec key_stream = this->aes.encrypt(counter);
            ByteVec ks_slice(key_stream.begin(),
                             key_stream.begin() + static_cast<std::ptrdiff_t>(blocks[idx].size()));
            ByteVec enc = _xor(blocks[idx], ks_slice);
            if (this->verbose) {
                std::cout << "[CTR Encrypt Block " << idx << "] Counter=" << bytes_to_hex(counter)
                          << " -> Keystream=" << bytes_to_hex(ks_slice)
                          << " ^ PT=" << bytes_to_hex(blocks[idx])
                          << " -> CT=" << bytes_to_hex(enc) << "\n";
            }
            body.insert(body.end(), enc.begin(), enc.end());
            _increment_be_128(counter);
        }

        if (prepend_iv) {
            ByteVec result = iv_bytes;
            result.insert(result.end(), body.begin(), body.end());
            return result;
        }
        return body;
    }

    ByteVec ctr_encrypt(const std::string& plaintext,
                        const std::optional<ByteVec>& custom_iv = std::nullopt,
                        bool prepend_iv = true) {
        return ctr_encrypt(_ensure_bytes(plaintext, "plaintext"), custom_iv, prepend_iv);
    }

    ByteVec ctr_decrypt_bytes(const ByteVec& ciphertext,
                              const std::optional<ByteVec>& custom_iv = std::nullopt,
                              bool has_iv = true) {
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

    std::string ctr_decrypt(const ByteVec& ciphertext,
                            const std::optional<ByteVec>& custom_iv = std::nullopt,
                            bool has_iv = true) {
        return bytes_to_utf8(ctr_decrypt_bytes(ciphertext, custom_iv, has_iv));
    }

    // -------------------------------------------------------------------------
    // NIST SP 800-38D: AES-GCM & GMAC (Pure C++17 Standard Library implementation)
    // -------------------------------------------------------------------------

    ByteVec gcm_encrypt(const ByteVec& plaintext,
                        const std::optional<ByteVec>& associated_data = std::nullopt,
                        const std::optional<ByteVec>& nonce = std::nullopt,
                        bool prepend_nonce = true) {
        ByteVec nonce_bytes = nonce.has_value() ? nonce.value() : random_bytes(12);
        if (nonce_bytes.size() != 12) {
            throw std::invalid_argument("AES-GCM nonce should be 12 bytes for the standard fast path.");
        }
        ByteVec aad = associated_data.value_or(ByteVec{});

        // Hash subkey H = AES_K(0^128)
        ByteVec H = this->aes.encrypt(ByteVec(16, 0));

        // Pre-counter block J0 = nonce || 0x00000001 (for 96-bit nonce)
        ByteVec J0 = nonce_bytes;
        J0.push_back(0x00);
        J0.push_back(0x00);
        J0.push_back(0x00);
        J0.push_back(0x01);

        // Encrypt plaintext using GCTR with icb = inc32(J0)
        ByteVec icb = J0;
        _increment_be_32(icb);
        ByteVec ciphertext = _gctr(icb, plaintext);

        // Compute GHASH(H, A, C)
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

    ByteVec gcm_encrypt(const std::string& plaintext,
                        const std::optional<ByteVec>& associated_data = std::nullopt,
                        const std::optional<ByteVec>& nonce = std::nullopt,
                        bool prepend_nonce = true) {
        return gcm_encrypt(_ensure_bytes(plaintext, "plaintext"), associated_data, nonce, prepend_nonce);
    }

    ByteVec gcm_decrypt_bytes(const ByteVec& ciphertext_and_tag,
                              const std::optional<ByteVec>& associated_data = std::nullopt,
                              const std::optional<ByteVec>& nonce = std::nullopt,
                              bool has_nonce = true) {
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

        ByteVec H = this->aes.encrypt(ByteVec(16, 0));
        ByteVec J0 = nonce_bytes;
        J0.insert(J0.end(), {0x00, 0x00, 0x00, 0x01});

        ByteVec S = _ghash(H, aad, ciphertext);
        ByteVec expected_tag = _xor(this->aes.encrypt(J0), S);
        if (!_constant_time_equal(received_tag, expected_tag)) {
            throw std::runtime_error("AES-GCM authentication failed: tag mismatch.");
        }

        ByteVec icb = J0;
        _increment_be_32(icb);
        return _gctr(icb, ciphertext);
    }

    std::string gcm_decrypt(const ByteVec& ciphertext_and_tag,
                            const std::optional<ByteVec>& associated_data = std::nullopt,
                            const std::optional<ByteVec>& nonce = std::nullopt,
                            bool has_nonce = true) {
        return bytes_to_utf8(gcm_decrypt_bytes(ciphertext_and_tag, associated_data, nonce, has_nonce));
    }

    ByteVec gmac(const ByteVec& authenticated_data,
                 const std::optional<ByteVec>& nonce = std::nullopt,
                 bool prepend_nonce = true) {
        return gcm_encrypt(ByteVec{}, authenticated_data, nonce, prepend_nonce);
    }

    bool gmac_verify(const ByteVec& authenticated_data,
                     const ByteVec& tag,
                     const std::optional<ByteVec>& nonce = std::nullopt,
                     bool has_nonce = true) {
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

    // -------------------------------------------------------------------------
    // NIST SP 800-38C: AES-CCM (Pure C++17 Standard Library implementation)
    // -------------------------------------------------------------------------

    ByteVec ccm_encrypt(const ByteVec& plaintext,
                        const std::optional<ByteVec>& associated_data = std::nullopt,
                        const std::optional<ByteVec>& nonce = std::nullopt,
                        size_t tag_length = 16,
                        bool prepend_nonce = true) {
        if (tag_length != 4 && tag_length != 6 && tag_length != 8 &&
            tag_length != 10 && tag_length != 12 && tag_length != 14 && tag_length != 16) {
            throw std::invalid_argument("AES-CCM tag_length must be one of 4, 6, 8, 10, 12, 14, 16.");
        }
        ByteVec nonce_bytes = nonce.has_value() ? nonce.value() : random_bytes(13);
        if (nonce_bytes.size() < 7 || nonce_bytes.size() > 13) {
            throw std::invalid_argument("AES-CCM nonce length must be between 7 and 13 bytes.");
        }
        ByteVec aad = associated_data.value_or(ByteVec{});

        ByteVec T = _ccm_cbc_mac(plaintext, aad, nonce_bytes, tag_length);
        ByteVec S0 = _ccm_counter_block(nonce_bytes, 0);
        ByteVec enc_S0 = this->aes.encrypt(S0);
        ByteVec U(tag_length);
        for (size_t i = 0; i < tag_length; ++i) {
            U[i] = T[i] ^ enc_S0[i];
        }

        ByteVec ciphertext;
        ciphertext.reserve(plaintext.size());
        auto blocks = _chunks(plaintext, BLOCK_SIZE);
        for (size_t i = 0; i < blocks.size(); ++i) {
            ByteVec ctr_blk = _ccm_counter_block(nonce_bytes, i + 1);
            ByteVec ks = this->aes.encrypt(ctr_blk);
            for (size_t j = 0; j < blocks[i].size(); ++j) {
                ciphertext.push_back(blocks[i][j] ^ ks[j]);
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

    ByteVec ccm_encrypt(const std::string& plaintext,
                        const std::optional<ByteVec>& associated_data = std::nullopt,
                        const std::optional<ByteVec>& nonce = std::nullopt,
                        size_t tag_length = 16,
                        bool prepend_nonce = true) {
        return ccm_encrypt(_ensure_bytes(plaintext, "plaintext"), associated_data, nonce, tag_length, prepend_nonce);
    }

    ByteVec ccm_decrypt_bytes(const ByteVec& ciphertext_and_tag,
                              const std::optional<ByteVec>& associated_data = std::nullopt,
                              const std::optional<ByteVec>& nonce = std::nullopt,
                              bool has_nonce = true,
                              size_t nonce_length = 13,
                              size_t tag_length = 16) {
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

    std::string ccm_decrypt(const ByteVec& ciphertext_and_tag,
                            const std::optional<ByteVec>& associated_data = std::nullopt,
                            const std::optional<ByteVec>& nonce = std::nullopt,
                            bool has_nonce = true,
                            size_t nonce_length = 13,
                            size_t tag_length = 16) {
        return bytes_to_utf8(
            ccm_decrypt_bytes(ciphertext_and_tag, associated_data, nonce, has_nonce, nonce_length, tag_length)
        );
    }

    // -------------------------------------------------------------------------
    // RFC 8452: AES-GCM-SIV (Pure C++17 Standard Library implementation)
    // -------------------------------------------------------------------------

    ByteVec gcm_siv_encrypt(const ByteVec& plaintext,
                            const std::optional<ByteVec>& associated_data = std::nullopt,
                            const std::optional<ByteVec>& nonce = std::nullopt,
                            bool prepend_nonce = true) {
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

    ByteVec gcm_siv_encrypt(const std::string& plaintext,
                            const std::optional<ByteVec>& associated_data = std::nullopt,
                            const std::optional<ByteVec>& nonce = std::nullopt,
                            bool prepend_nonce = true) {
        return gcm_siv_encrypt(_ensure_bytes(plaintext, "plaintext"), associated_data, nonce, prepend_nonce);
    }

    ByteVec gcm_siv_decrypt_bytes(const ByteVec& ciphertext_and_tag,
                                  const std::optional<ByteVec>& associated_data = std::nullopt,
                                  const std::optional<ByteVec>& nonce = std::nullopt,
                                  bool has_nonce = true) {
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

    std::string gcm_siv_decrypt(const ByteVec& ciphertext_and_tag,
                                const std::optional<ByteVec>& associated_data = std::nullopt,
                                const std::optional<ByteVec>& nonce = std::nullopt,
                                bool has_nonce = true) {
        return bytes_to_utf8(gcm_siv_decrypt_bytes(ciphertext_and_tag, associated_data, nonce, has_nonce));
    }

    // -------------------------------------------------------------------------
    // NIST SP 800-38E: AES-XTS (Pure C++17 Standard Library implementation)
    // -------------------------------------------------------------------------

    ByteVec xts_encrypt(const ByteVec& plaintext,
                        const std::optional<ByteVec>& xts_key = std::nullopt,
                        const std::optional<ByteVec>& tweak = std::nullopt,
                        uint64_t data_unit_number = 0) {
        ByteVec key_bytes = xts_key.has_value() ? xts_key.value() : this->key;
        if (key_bytes.size() != 32 && key_bytes.size() != 64) {
            throw std::invalid_argument("AES-XTS requires a 32-byte or 64-byte double-length XTS key.");
        }
        if (plaintext.size() < BLOCK_SIZE) {
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
        size_t m = plaintext.size() / BLOCK_SIZE;
        size_t b = plaintext.size() % BLOCK_SIZE;

        ByteVec out(plaintext.size());
        size_t full_blocks = (b == 0) ? m : (m - 1);

        for (size_t q = 0; q < full_blocks; ++q) {
            ByteVec P_q(plaintext.begin() + static_cast<std::ptrdiff_t>(q * 16),
                        plaintext.begin() + static_cast<std::ptrdiff_t>((q + 1) * 16));
            ByteVec C_q = _xor(aes1.encrypt(_xor(P_q, T)), T);
            std::copy(C_q.begin(), C_q.end(), out.begin() + static_cast<std::ptrdiff_t>(q * 16));
            _xts_mul_alpha(T);
        }

        if (b > 0) {
            // Ciphertext stealing for last two blocks (m-1 and partial m)
            ByteVec T_m_minus_1 = T;
            _xts_mul_alpha(T);
            ByteVec T_m = T;

            ByteVec P_m_minus_1(plaintext.begin() + static_cast<std::ptrdiff_t>((m - 1) * 16),
                                plaintext.begin() + static_cast<std::ptrdiff_t>(m * 16));
            ByteVec CC = _xor(aes1.encrypt(_xor(P_m_minus_1, T_m_minus_1)), T_m_minus_1);

            // PP = P_m || CC[b..15]
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

    ByteVec xts_encrypt(const std::string& plaintext,
                        const std::optional<ByteVec>& xts_key = std::nullopt,
                        const std::optional<ByteVec>& tweak = std::nullopt,
                        uint64_t data_unit_number = 0) {
        return xts_encrypt(_ensure_bytes(plaintext, "plaintext"), xts_key, tweak, data_unit_number);
    }

    ByteVec xts_decrypt_bytes(const ByteVec& ciphertext,
                              const std::optional<ByteVec>& xts_key = std::nullopt,
                              const std::optional<ByteVec>& tweak = std::nullopt,
                              uint64_t data_unit_number = 0) {
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

        for (size_t q = 0; q < full_blocks; ++q) {
            ByteVec C_q(ciphertext.begin() + static_cast<std::ptrdiff_t>(q * 16),
                        ciphertext.begin() + static_cast<std::ptrdiff_t>((q + 1) * 16));
            ByteVec P_q = _xor(aes1.decrypt(_xor(C_q, T)), T);
            std::copy(P_q.begin(), P_q.end(), out.begin() + static_cast<std::ptrdiff_t>(q * 16));
            _xts_mul_alpha(T);
        }

        if (b > 0) {
            ByteVec T_m_minus_1 = T;
            _xts_mul_alpha(T);
            ByteVec T_m = T;

            ByteVec C_m_minus_1(ciphertext.begin() + static_cast<std::ptrdiff_t>((m - 1) * 16),
                                ciphertext.begin() + static_cast<std::ptrdiff_t>(m * 16));
            ByteVec PP = _xor(aes1.decrypt(_xor(C_m_minus_1, T_m)), T_m);

            // CC = C_m || PP[b..15]
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

    // -------------------------------------------------------------------------
    // NIST SP 800-38F: AES Key Wrap / KWP (RFC 3394 & RFC 5649 in pure C++)
    // -------------------------------------------------------------------------

    ByteVec key_wrap(const ByteVec& key_to_wrap, bool pad = false) {
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
            if (padded.size() == 8) {
                // RFC 5649 Section 4.1: when n == 1 semiblock, encrypt AIV || P[1] with a single AES block
                ByteVec block(16);
                std::copy(aiv.begin(), aiv.end(), block.begin());
                std::copy(padded.begin(), padded.end(), block.begin() + 8);
                return this->aes.encrypt(block);
            }
            return _kw_wrap_core(padded, aiv);
        }
    }

    ByteVec key_wrap(const std::string& key_to_wrap, bool pad = false) {
        return key_wrap(_ensure_bytes(key_to_wrap, "key_to_wrap"), pad);
    }

    ByteVec key_unwrap(const ByteVec& wrapped_key, bool pad = false) {
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

private:
    static ByteVec _ValidateKey(const ByteVec& k) {
        if (std::find(VALID_AES_KEY_BYTES.begin(), VALID_AES_KEY_BYTES.end(), k.size()) ==
            VALID_AES_KEY_BYTES.end()) {
            throw std::invalid_argument("Invalid AES key length. Supported lengths are 16, 24, or 32 bytes.");
        }
        return k;
    }

    static bool _constant_time_equal(const ByteVec& a, const ByteVec& b) noexcept {
        if (a.size() != b.size()) return false;
        Byte diff = 0;
        for (size_t i = 0; i < a.size(); ++i) {
            diff |= (a[i] ^ b[i]);
        }
        return diff == 0;
    }

    // Increment 128-bit big-endian counter (for NIST SP 800-38A CTR mode)
    static void _increment_be_128(ByteVec& counter) noexcept {
        for (int i = 15; i >= 0; --i) {
            if (++counter[static_cast<size_t>(i)] != 0) {
                break;
            }
        }
    }

    // Increment rightmost 32 bits big-endian (inc32 for NIST SP 800-38D GCM)
    static void _increment_be_32(ByteVec& counter) noexcept {
        for (int i = 15; i >= 12; --i) {
            if (++counter[static_cast<size_t>(i)] != 0) {
                break;
            }
        }
    }

    // GF(2^128) multiplication for GHASH (NIST SP 800-38D Section 6.3)
    static ByteVec _gf128_mul(const ByteVec& X, const ByteVec& Y) {
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

    static ByteVec _ghash(const ByteVec& H, const ByteVec& A, const ByteVec& C) {
        ByteVec Y(16, 0);

        auto process_region = [&](const ByteVec& data) {
            for (size_t i = 0; i < data.size(); i += 16) {
                ByteVec block(16, 0);
                size_t copy_len = std::min<size_t>(16, data.size() - i);
                std::copy(data.begin() + static_cast<std::ptrdiff_t>(i),
                          data.begin() + static_cast<std::ptrdiff_t>(i + copy_len),
                          block.begin());
                Y = _gf128_mul(_xor(Y, block), H);
            }
        };

        process_region(A);
        process_region(C);

        // Final length block: [len(A)_bits (64-bit BE) || len(C)_bits (64-bit BE)]
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

    ByteVec _gctr(ByteVec icb, const ByteVec& X) {
        if (X.empty()) return {};
        ByteVec Y;
        Y.reserve(X.size());
        auto blocks = _chunks(X, BLOCK_SIZE);
        for (const auto& blk : blocks) {
            ByteVec ks = this->aes.encrypt(icb);
            for (size_t j = 0; j < blk.size(); ++j) {
                Y.push_back(blk[j] ^ ks[j]);
            }
            _increment_be_32(icb);
        }
        return Y;
    }

    // CCM helpers (NIST SP 800-38C)
    static ByteVec _ccm_counter_block(const ByteVec& nonce, size_t counter_val) {
        size_t q = 15 - nonce.size();
        ByteVec blk(16, 0);
        blk[0] = static_cast<Byte>(q - 1);
        std::copy(nonce.begin(), nonce.end(), blk.begin() + 1);
        for (size_t i = 0; i < q; ++i) {
            blk[15 - i] = static_cast<Byte>((counter_val >> (8 * i)) & 0xFF);
        }
        return blk;
    }

    ByteVec _ccm_cbc_mac(const ByteVec& plaintext,
                         const ByteVec& aad,
                         const ByteVec& nonce,
                         size_t tag_length) {
        size_t q = 15 - nonce.size();
        size_t Q = plaintext.size();

        // B0 block
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

        auto feed_padded = [&](const ByteVec& stream) {
            for (size_t i = 0; i < stream.size(); i += 16) {
                ByteVec blk(16, 0);
                size_t n = std::min<size_t>(16, stream.size() - i);
                std::copy(stream.begin() + static_cast<std::ptrdiff_t>(i),
                          stream.begin() + static_cast<std::ptrdiff_t>(i + n),
                          blk.begin());
                Y = this->aes.encrypt(_xor(Y, blk));
            }
        };

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

        if (!plaintext.empty()) {
            feed_padded(plaintext);
        }

        return Y;
    }

    // GCM-SIV helpers (RFC 8452)
    static ByteVec _byte_reverse_16(const ByteVec& b) {
        ByteVec r(16);
        for (size_t i = 0; i < 16; ++i) r[i] = b[15 - i];
        return r;
    }

    // mulX_GHASH: multiply by x in GHASH representation
    static ByteVec _mulX_ghash(const ByteVec& V_in) {
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

    // RFC 8452 Appendix A relation between POLYVAL and GHASH:
    // POLYVAL(H, X_1, ..., X_n) = ByteReverse(GHASH(mulX_GHASH(ByteReverse(H)), ByteReverse(X_1), ..., ByteReverse(X_n)))
    static ByteVec _polyval(const ByteVec& H, const std::vector<ByteVec>& blocks) {
        ByteVec H_ghash = _mulX_ghash(_byte_reverse_16(H));
        ByteVec Y(16, 0);
        for (const auto& blk : blocks) {
            Y = _gf128_mul(_xor(Y, _byte_reverse_16(blk)), H_ghash);
        }
        return _byte_reverse_16(Y);
    }

    std::pair<ByteVec, ByteVec> _gcm_siv_derive_keys(const ByteVec& nonce) {
        auto derive_block = [&](uint32_t counter) {
            ByteVec blk(16, 0);
            blk[0] = static_cast<Byte>(counter & 0xFF);
            blk[1] = static_cast<Byte>((counter >> 8) & 0xFF);
            blk[2] = static_cast<Byte>((counter >> 16) & 0xFF);
            blk[3] = static_cast<Byte>((counter >> 24) & 0xFF);
            std::copy(nonce.begin(), nonce.end(), blk.begin() + 4);
            ByteVec enc = this->aes.encrypt(blk);
            enc.resize(8); // first 64 bits
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

    static ByteVec _gcm_siv_compute_tag(AES& enc_aes,
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

        // Length block (little-endian 64-bit lengths in bits: [aad_bits_le || pt_bits_le])
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
        S_s[15] &= 0x7F; // clear MSB
        return enc_aes.encrypt(S_s);
    }

    static ByteVec _gcm_siv_ctr(AES& enc_aes, const ByteVec& tag, const ByteVec& input) {
        if (input.empty()) return {};
        ByteVec cb = tag;
        cb[15] |= 0x80; // set MSB of byte 15
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

    // XTS GF(2^128) multiplication by alpha (modulo x^128 + x^7 + x^2 + x + 1, little-endian)
    static void _xts_mul_alpha(ByteVec& T) noexcept {
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

    // RFC 3394 Key Wrap / Unwrap core
    ByteVec _kw_wrap_core(const ByteVec& P, const std::array<Byte, 8>& iv_init) {
        size_t n = P.size() / 8;
        std::array<Byte, 8> A = iv_init;
        std::vector<std::array<Byte, 8>> R(n);
        for (size_t i = 0; i < n; ++i) {
            std::copy(P.begin() + static_cast<std::ptrdiff_t>(i * 8),
                      P.begin() + static_cast<std::ptrdiff_t>((i + 1) * 8),
                      R[i].begin());
        }

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

    std::pair<std::array<Byte, 8>, ByteVec> _kw_unwrap_core(const ByteVec& C) {
        size_t n = (C.size() / 8) - 1;
        std::array<Byte, 8> A{};
        std::copy(C.begin(), C.begin() + 8, A.begin());
        std::vector<std::array<Byte, 8>> R(n);
        for (size_t i = 0; i < n; ++i) {
            std::copy(C.begin() + static_cast<std::ptrdiff_t>((i + 1) * 8),
                      C.begin() + static_cast<std::ptrdiff_t>((i + 2) * 8),
                      R[i].begin());
        }

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
};

using AESModes = modes;

#ifndef MODES_NO_MAIN
// =============================================================================
// Command-Line Interface (CLI) & Automated Test Suite
// =============================================================================

static void run_automated_tests() {
    std::cout << "  UIT NT219 - AES & MODES OF OPERATION (C++17 STANDARD LIBRARY) TESTS\n";

    auto check = [](const std::string& label, bool cond) {
        std::cout << "  [" << (cond ? "PASS" : "FAIL") << "] " << label << "\n";
        if (!cond) {
            throw std::runtime_error("Test failed: " + label);
        }
    };

    // 1. NIST FIPS 197 Appendix A & B Test Vectors (AES-128, AES-192, AES-256)
    std::cout << "1. NIST FIPS 197 Single-Block AES Primitive & Round Trace:\n";
    auto key_128 = modes::hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
    auto pt_fips = modes::hex_to_bytes("3243f6a8885a308d313198a2e0370734");
    AES aes128(key_128, 128);
    auto ct128 = aes128.encrypt(pt_fips, true);
    check("NIST FIPS 197 Appendix B AES-128 Encrypt == 3925841d02dc09fbdc118597196a0b32",
          modes::bytes_to_hex(ct128) == "3925841d02dc09fbdc118597196a0b32");
    check("NIST FIPS 197 Appendix B AES-128 Decrypt matches Plaintext",
          aes128.decrypt(ct128) == pt_fips);

    auto key_192 = modes::hex_to_bytes("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    AES aes192(key_192, 192);
    auto ct192 = aes192.encrypt(pt_fips);
    check("AES-192 Encrypt matches Python AES.py (585e9fb6c2722b9af4f492c12bb024c1)",
          modes::bytes_to_hex(ct192) == "585e9fb6c2722b9af4f492c12bb024c1");
    check("AES-192 Decrypt matches Plaintext", aes192.decrypt(ct192) == pt_fips);

    auto key_256 = modes::hex_to_bytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    AES aes256(key_256, 256);
    auto ct256 = aes256.encrypt(pt_fips);
    check("AES-256 Encrypt matches Python AES.py (3021613a973e582f4a29234137aec494)",
          modes::bytes_to_hex(ct256) == "3021613a973e582f4a29234137aec494");
    check("AES-256 Decrypt matches Plaintext", aes256.decrypt(ct256) == pt_fips);

    // 2. PKCS#7 Padding & Missing Bytes (Bonus Point) + Binary String Helpers
    std::cout << "\n2. PKCS#7 Padding (padding_length / missing_bytes) & Data Helpers:\n";
    auto padded_sample = modes::pkcs7_padding("UIT_NT219_11B", true); // 13 bytes -> 3 missing bytes (0x03)
    check("PKCS#7 padding_length for 13-byte input is 3 bytes (0x030303)",
          padded_sample.size() == 16 && padded_sample.back() == 0x03);
    auto unpadded_sample = modes::pkcs7_unpadding(padded_sample, true);
    check("PKCS#7 unpadding restores original 13-byte string",
          modes::bytes_to_utf8(unpadded_sample) == "UIT_NT219_11B");

    auto bin_bytes = modes::binary_to_bytes("0b00101");
    check("binary_to_bytes('0b00101') == 0x2c & bytes_to_binary round-trip",
          modes::bytes_to_hex(bin_bytes) == "2c" && modes::bytes_to_binary(bin_bytes) == "0b00101");

    // 3. NIST SP 800-38A Modes (ECB, CBC, CFB-128, CFB-8, OFB, CTR) vs modes.py
    std::cout << "\n3. NIST SP 800-38A Modes (Block-by-Block Verbose Trace & Python Parity):\n";
    modes m(key_128, true);
    auto iv = modes::hex_to_bytes("000102030405060708090a0b0c0d0e0f");
    std::string msg = "Hello UIT Cryptography Lab NT219! Testing multi-block message.";

    auto ct_ecb = m.ecb_encrypt(msg);
    check("ECB Encrypt matches modes.py exactly",
          modes::bytes_to_hex(ct_ecb) ==
          "1a12b160b716020bdb86ffe07e0475757caa7ae35b9a75d5d2f338111b5ad5a38eab940e9a7f47cb334cc5d4a87e3bb6eb4490b0b8192f4d0171a1b044b97e52");
    check("ECB Decrypt restores original message", m.ecb_decrypt(ct_ecb) == msg);

    auto ct_cbc = m.cbc_encrypt(msg, iv);
    check("CBC Encrypt matches modes.py exactly",
          modes::bytes_to_hex(ct_cbc) ==
          "000102030405060708090a0b0c0d0e0fef8f455d7443aac67a4added445a9701536d7a51863bb15c518c14a58d503733ccf62dd5d94d1039fc03c80f4fc5424e434622892d1914286fda9d400b6b0a35");
    check("CBC Decrypt restores original message", m.cbc_decrypt(ct_cbc) == msg);

    m.verbose = false; // keep CFB-8 concise in full test output
    auto ct_cfb128 = m.cfb_encrypt(msg, iv, 128);
    check("CFB-128 Encrypt matches modes.py exactly",
          modes::bytes_to_hex(ct_cfb128) ==
          "000102030405060708090a0b0c0d0e0f189b0ba0f64d67ff8e29749be2df980f4c71f7622fd321faee38aa0b33ac2d30ce73b439bc336e408c161b0f0e08001c8349a196d64319d6427bdbeee38a");
    check("CFB-128 Decrypt restores original message", m.cfb_decrypt(ct_cfb128, std::nullopt, true, 128) == msg);

    auto ct_cfb8 = m.cfb_encrypt(msg, iv, 8);
    check("CFB-8 Encrypt matches modes.py exactly",
          modes::bytes_to_hex(ct_cfb8) ==
          "000102030405060708090a0b0c0d0e0f18bd6825311125939032799bdc191e7e7b4b51f0bf9a792fc44853e127c444c25cdbfe31a226f2366d9cbbcd1da27907e28fa70fb3b50bffaeafd338b5d0");
    check("CFB-8 Decrypt restores original message", m.cfb_decrypt(ct_cfb8, std::nullopt, true, 8) == msg);

    auto ct_ofb = m.ofb_encrypt(msg, iv);
    check("OFB Encrypt matches modes.py exactly",
          modes::bytes_to_hex(ct_ofb) ==
          "000102030405060708090a0b0c0d0e0f189b0ba0f64d67ff8e29749be2df980fbed6bbaa60eb03d30ae91d38d4d3674d86a84d3d4c776189c19f5bc4541ed60ea4bf2e0e4236310ab8fd30c54294");
    check("OFB Decrypt restores original message", m.ofb_decrypt(ct_ofb) == msg);

    auto ct_ctr = m.ctr_encrypt(msg, iv);
    check("CTR Encrypt matches modes.py exactly",
          modes::bytes_to_hex(ct_ctr) ==
          "000102030405060708090a0b0c0d0e0f189b0ba0f64d67ff8e29749be2df980fc853ef3eef9ab3e6bb536baa2fc59266b7cadbec76f7f92cdeeeeded60f94f1db9a6ee61b248ca2209ecd8b44e9e");
    check("CTR Decrypt restores original message", m.ctr_decrypt(ct_ctr) == msg);

    // 4. Modern & Specialized Modes (NIST SP 800-38C/D/E/F & RFC 8452) vs modes.py
    std::cout << "\n4. Additional NIST Standards (SP 800-38C CCM, 800-38D GCM/GMAC, 800-38E XTS, 800-38F KW/KWP):\n";
    auto nonce12 = modes::hex_to_bytes("000102030405060708090a0b");
    auto nonce13 = modes::hex_to_bytes("000102030405060708090a0b0c");
    auto aad = modes::utf8_to_bytes("UIT-NT219-AAD");

    auto ct_gcm = m.gcm_encrypt(msg, aad, nonce12);
    check("GCM (SP 800-38D) Encrypt matches modes.py",
          modes::bytes_to_hex(ct_gcm) ==
          "000102030405060708090a0b13aa573ad748db0bb4f857f4dbf9c0f86c48608625a0749e6468b5e96804640e27dea062320c0148f61cd843f3d04c807e27fa7f70948dd86708b745e7da8ac31d61002a9fa38b3bd65f9b96fabf");
    check("GCM (SP 800-38D) Decrypt & Verify Tag", m.gcm_decrypt(ct_gcm, aad) == msg);

    auto gmac_tok = m.gmac(aad, nonce12);
    check("GMAC (SP 800-38D) Tag matches modes.py",
          modes::bytes_to_hex(gmac_tok) == "000102030405060708090a0be6ba0123585d23ec2a61e2855b2606fc");
    check("GMAC Verify returns true", m.gmac_verify(aad, gmac_tok));

    auto ct_ccm = m.ccm_encrypt(msg, aad, nonce13, 16);
    check("CCM (SP 800-38C) Encrypt matches modes.py",
          modes::bytes_to_hex(ct_ccm) ==
          "000102030405060708090a0b0c6d12a2fdb52dec57db5f1ceeb54a4c67d1eec9440c2a3cde30f2679adb7ce0ef886a05a59e9f813e684682033974fe438bb701558d500556e8e83520681d04ff57f44922466cb7f9e236734c1147");
    check("CCM (SP 800-38C) Decrypt & Verify Tag", m.ccm_decrypt(ct_ccm, aad) == msg);

    auto ct_siv = m.gcm_siv_encrypt(msg, aad, nonce12);
    check("GCM-SIV (RFC 8452) Decrypt & Verify Tag", m.gcm_siv_decrypt(ct_siv, aad) == msg);

    auto ct_xts_partial = m.xts_encrypt(msg, key_256, std::nullopt, 42);
    check("XTS (SP 800-38E) Ciphertext Stealing matches modes.py",
          modes::bytes_to_hex(ct_xts_partial) ==
          "9c6a4dbe875db8f78bb1e1f9a9ebd8671ea09859f414aa93c3c43db14251732e3cd30bbe5afefbf79f610c35087027cad4dc3aef1f0308078f1be37d25b0");
    check("XTS (SP 800-38E) Decrypt restores original message",
          modes::bytes_to_utf8(m.xts_decrypt_bytes(ct_xts_partial, key_256, std::nullopt, 42)) == msg);

    auto wrapped_kw = m.key_wrap(key_256, false);
    check("AES-KW (SP 800-38F) matches modes.py",
          modes::bytes_to_hex(wrapped_kw) ==
          "414f06a566930aef30143e0def95c2811f00c02ce652ca7323a3aab862f6030d0f8a8405997ae91e");
    check("AES-KW Unwrap restores 256-bit key", m.key_unwrap(wrapped_kw, false) == key_256);

    auto wrapped_kwp = m.key_wrap("short_key_123", true);
    check("AES-KWP (SP 800-38F with padding) matches modes.py",
          modes::bytes_to_hex(wrapped_kwp) == "f9e467b1db89595f0773e66091544ce2a3726599b7a78bb1");
    check("AES-KWP Unwrap restores short key",
          modes::bytes_to_utf8(m.key_unwrap(wrapped_kwp, true)) == "short_key_123");

    std::cout << "\nAll configured automated tests passed!\n";
}

static void print_cli_help(const char* prog) {
    std::cout << "Usage:\n"
              << "  " << prog << " [--test]\n"
              << "  " << prog << " --mode <ecb|cbc|cfb|ofb|ctr|ccm|gcm|xts|kw|kwp>\n"
              << "          --action <encrypt|decrypt>\n"
              << "          --key <hex_key_16_24_or_32_bytes>\n"
              << "          [--iv <hex_iv_or_nonce>]\n"
              << "          [--aad <utf8_associated_data>]\n"
              << "          [--segment-size <8..128>]\n"
              << "          [--input <utf8_string> | --input-hex <hex_bytes>]\n"
              << "          [--verbose]\n";
}

int main(int argc, char* argv[]) {
    try {
        if (argc <= 1 || std::string(argv[1]) == "--test") {
            run_automated_tests();
            return 0;
        }
        if (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h") {
            print_cli_help(argv[0]);
            return 0;
        }

        std::string mode_name = "cbc";
        std::string action = "encrypt";
        std::string key_hex;
        std::optional<std::string> iv_hex;
        std::optional<std::string> aad_str;
        std::string input_str;
        bool input_is_hex = false;
        bool verbose = true;
        int segment_size = 128;

        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--mode" && i + 1 < argc) mode_name = argv[++i];
            else if (arg == "--action" && i + 1 < argc) action = argv[++i];
            else if (arg == "--key" && i + 1 < argc) key_hex = argv[++i];
            else if (arg == "--iv" && i + 1 < argc) iv_hex = argv[++i];
            else if (arg == "--aad" && i + 1 < argc) aad_str = argv[++i];
            else if (arg == "--segment-size" && i + 1 < argc) segment_size = std::stoi(argv[++i]);
            else if (arg == "--input" && i + 1 < argc) { input_str = argv[++i]; input_is_hex = false; }
            else if (arg == "--input-hex" && i + 1 < argc) { input_str = argv[++i]; input_is_hex = true; }
            else if (arg == "--verbose") verbose = true;
            else if (arg == "--quiet") verbose = false;
        }

        if (key_hex.empty()) {
            std::cerr << "Error: --key <hex> is required.\n";
            print_cli_help(argv[0]);
            return 1;
        }

        auto key_bytes = modes::hex_to_bytes(key_hex);
        modes cipher(key_bytes, verbose);
        auto data_bytes = input_is_hex ? modes::hex_to_bytes(input_str) : modes::utf8_to_bytes(input_str);
        std::optional<modes::ByteVec> iv_bytes = std::nullopt;
        if (iv_hex.has_value()) {
            iv_bytes = modes::hex_to_bytes(iv_hex.value());
        }
        std::optional<modes::ByteVec> aad_bytes = std::nullopt;
        if (aad_str.has_value()) {
            aad_bytes = modes::utf8_to_bytes(aad_str.value());
        }

        if (action == "encrypt") {
            modes::ByteVec out;
            if (mode_name == "ecb") out = cipher.ecb_encrypt(data_bytes);
            else if (mode_name == "cbc") out = cipher.cbc_encrypt(data_bytes, iv_bytes);
            else if (mode_name == "cfb") out = cipher.cfb_encrypt(data_bytes, iv_bytes, segment_size);
            else if (mode_name == "ofb") out = cipher.ofb_encrypt(data_bytes, iv_bytes);
            else if (mode_name == "ctr") out = cipher.ctr_encrypt(data_bytes, iv_bytes);
            else if (mode_name == "gcm") out = cipher.gcm_encrypt(data_bytes, aad_bytes, iv_bytes);
            else if (mode_name == "ccm") out = cipher.ccm_encrypt(data_bytes, aad_bytes, iv_bytes);
            else if (mode_name == "kw") out = cipher.key_wrap(data_bytes, false);
            else if (mode_name == "kwp") out = cipher.key_wrap(data_bytes, true);
            else throw std::invalid_argument("Unsupported mode: " + mode_name);

            std::cout << "Ciphertext (hex): " << modes::bytes_to_hex(out) << "\n";
        } else if (action == "decrypt") {
            modes::ByteVec out;
            bool has_iv = !iv_bytes.has_value();
            if (mode_name == "ecb") out = cipher.ecb_decrypt_bytes(data_bytes);
            else if (mode_name == "cbc") out = cipher.cbc_decrypt_bytes(data_bytes, iv_bytes, has_iv);
            else if (mode_name == "cfb") out = cipher.cfb_decrypt_bytes(data_bytes, iv_bytes, has_iv, segment_size);
            else if (mode_name == "ofb") out = cipher.ofb_decrypt_bytes(data_bytes, iv_bytes, has_iv);
            else if (mode_name == "ctr") out = cipher.ctr_decrypt_bytes(data_bytes, iv_bytes, has_iv);
            else if (mode_name == "gcm") out = cipher.gcm_decrypt_bytes(data_bytes, aad_bytes, iv_bytes, has_iv);
            else if (mode_name == "ccm") out = cipher.ccm_decrypt_bytes(data_bytes, aad_bytes, iv_bytes, has_iv);
            else if (mode_name == "kw") out = cipher.key_unwrap(data_bytes, false);
            else if (mode_name == "kwp") out = cipher.key_unwrap(data_bytes, true);
            else throw std::invalid_argument("Unsupported mode: " + mode_name);

            std::cout << "Plaintext (hex) : " << modes::bytes_to_hex(out) << "\n";
            std::cout << "Plaintext (utf8): " << modes::bytes_to_utf8(out) << "\n";
        } else {
            throw std::invalid_argument("Unsupported --action: use encrypt or decrypt.");
        }
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }
}
#endif // MODES_NO_MAIN

#endif // UIT_MODES_CPP_INCLUDED