// -*- coding: utf-8 -*-
/**
 * sp800_38a.cpp - NIST SP 800-38A (Standard A) Confidentiality Modes of Operation:
 *   Implements both Lecturer Nguyen Ngoc Tu's `namespace lab` functions (sp800_38a.hpp)
 *   and `class modes` methods (modes.h): ECB, CBC, CFB (CFB-8..CFB-128), OFB, CTR + PKCS#7.
 * Reference: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
 */

#include "sp800_38a.hpp"
#include "modes.h"

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>

namespace lab {

Bytes ecb_encrypt(const AES& aes, const Bytes& in, bool padding) {
    Bytes d = padding ? pad(in) : in;
    check_aligned(d);
    Bytes out;
    for (std::size_t i = 0; i < d.size(); i += 16) {
        append(out, aes.encrypt(block(d, i)));
    }
    return out;
}

Bytes ecb_decrypt(const AES& aes, const Bytes& d, bool padding) {
    check_aligned(d);
    Bytes out;
    for (std::size_t i = 0; i < d.size(); i += 16) {
        append(out, aes.decrypt(block(d, i)));
    }
    return padding ? unpad(out) : out;
}

Bytes cbc_encrypt(const AES& aes, const Bytes& in, const Bytes& iv, bool padding) {
    check_iv(iv);
    Bytes d = padding ? pad(in) : in;
    check_aligned(d);
    Bytes out;
    Block prev = block(iv);
    for (std::size_t i = 0; i < d.size(); i += 16) {
        prev = aes.encrypt(xorblock(block(d, i), prev));
        append(out, prev);
    }
    return out;
}

Bytes cbc_decrypt(const AES& aes, const Bytes& d, const Bytes& iv, bool padding) {
    check_iv(iv);
    check_aligned(d);
    Bytes out;
    Block prev = block(iv);
    for (std::size_t i = 0; i < d.size(); i += 16) {
        Block cur = block(d, i);
        append(out, xorblock(aes.decrypt(cur), prev));
        prev = cur;
    }
    return padding ? unpad(out) : out;
}

static Bytes cfb(const AES& aes, const Bytes& d, const Bytes& iv, int segbits, bool encrypt) {
    check_iv(iv);
    if (segbits < 8 || segbits > 128 || segbits % 8) {
        throw std::invalid_argument("CFB segment bits must be 8..128 byte aligned");
    }
    std::size_t n = static_cast<std::size_t>(segbits / 8);
    Block reg = block(iv);
    Bytes out;
    for (std::size_t i = 0; i < d.size(); i += n) {
        auto stream = aes.encrypt(reg);
        std::size_t take = std::min(n, d.size() - i);
        for (std::size_t j = 0; j < take; ++j) {
            out.push_back(static_cast<Byte>(d[i + j] ^ stream[j]));
        }
        if (take == n) {
            for (std::size_t j = 0; j < 16 - n; ++j) {
                reg[j] = reg[j + n];
            }
            for (std::size_t j = 0; j < n; ++j) {
                reg[16 - n + j] = encrypt ? out[i + j] : d[i + j];
            }
        }
    }
    return out;
}

Bytes cfb_encrypt(const AES& a, const Bytes& d, const Bytes& iv, int n) {
    return cfb(a, d, iv, n, true);
}

Bytes cfb_decrypt(const AES& a, const Bytes& d, const Bytes& iv, int n) {
    return cfb(a, d, iv, n, false);
}

Bytes ofb_crypt(const AES& aes, const Bytes& d, const Bytes& iv) {
    check_iv(iv);
    Block feed = block(iv);
    Bytes out;
    for (std::size_t i = 0; i < d.size(); i += 16) {
        feed = aes.encrypt(feed);
        for (std::size_t j = 0; j < std::min(std::size_t(16), d.size() - i); ++j) {
            out.push_back(static_cast<Byte>(d[i + j] ^ feed[j]));
        }
    }
    return out;
}

Bytes ctr_crypt(const AES& aes, const Bytes& d, const Bytes& iv) {
    check_iv(iv);
    Block counter = block(iv);
    Bytes out;
    for (std::size_t i = 0; i < d.size(); i += 16) {
        auto stream = aes.encrypt(counter);
        for (std::size_t j = 0; j < std::min(std::size_t(16), d.size() - i); ++j) {
            out.push_back(static_cast<Byte>(d[i + j] ^ stream[j]));
        }
        if (i + 16 < d.size()) {
            bool wrapped = true;
            for (int j = 15; j >= 0; --j) {
                if (++counter[j] != 0) {
                    wrapped = false;
                    break;
                }
            }
            if (wrapped) {
                throw std::overflow_error("CTR counter wrapped");
            }
        }
    }
    return out;
}

} // namespace lab


modes::ByteVec modes::_ValidateKey(const ByteVec& k) {
    if (k.size() != 16 && k.size() != 24 && k.size() != 32) {
        throw std::invalid_argument(
            "Invalid AES key length. Supported lengths are 16, 24, or 32 bytes."
        );
    }
    return k;
}

modes::modes(const ByteVec& key_data, bool verbose_mode)
    : key(_ValidateKey(key_data)),
      aes(key, static_cast<int>(key.size() * 8)),
      verbose(verbose_mode),
      iv(std::nullopt) {}

modes::modes(const std::string& key_str, bool verbose_mode)
    : modes(utf8_to_bytes(key_str), verbose_mode) {}

modes::ByteVec modes::_ensure_bytes(const ByteVec& data, const std::string&) {
    return data;
}

modes::ByteVec modes::_ensure_bytes(const std::string& data, const std::string&) {
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
    for (char c : binary_str) {
        if (c != '0' && c != '1') {
            throw std::invalid_argument("binary_str must contain only '0' and '1'.");
        }
    }
    binary_str.push_back('1');
    while (binary_str.size() % 8 != 0) {
        binary_str.push_back('0');
    }
    ByteVec out;
    out.reserve(binary_str.size() / 8);
    for (size_t i = 0; i < binary_str.size(); i += 8) {
        Byte b = 0;
        for (size_t j = 0; j < 8; ++j) {
            b = static_cast<Byte>((b << 1) | (binary_str[i + j] == '1' ? 1 : 0));
        }
        out.push_back(b);
    }
    return out;
}

std::string modes::bytes_to_binary(const ByteVec& bytes_data) {
    if (bytes_data.empty()) {
        throw std::invalid_argument("Invalid reversible binary padding: missing marker bit.");
    }
    std::string bits;
    bits.reserve(bytes_data.size() * 8);
    for (Byte b : bytes_data) {
        for (int i = 7; i >= 0; --i) {
            bits.push_back(((b >> i) & 1) ? '1' : '0');
        }
    }
    auto pos = bits.find_last_of('1');
    if (pos == std::string::npos) {
        throw std::invalid_argument("Invalid reversible binary padding: missing marker bit.");
    }
    return bits.substr(0, pos);
}

modes::ByteVec modes::_xor(const ByteVec& a, const ByteVec& b) {
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
    if (size == 0) {
        throw std::invalid_argument("Chunk size must be positive.");
    }
    std::vector<ByteVec> chunks;
    for (size_t i = 0; i < data.size(); i += size) {
        size_t end = std::min(i + size, data.size());
        chunks.emplace_back(data.begin() + i, data.begin() + end);
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
    ByteVec out(n);
    std::random_device rd;
    for (size_t i = 0; i < n; ++i) {
        out[i] = static_cast<Byte>(rd() & 0xFF);
    }
    return out;
}

modes::ByteVec modes::_fresh_iv(const std::optional<ByteVec>& custom_iv, const std::string& name) {
    if (custom_iv.has_value()) {
        iv = _require_exact_block(custom_iv.value(), name);
    } else {
        iv = random_bytes(BLOCK_SIZE);
    }
    return iv.value();
}

size_t modes::get_padding_length(size_t data_len) noexcept {
    size_t rem = data_len % BLOCK_SIZE;
    return (rem == 0) ? BLOCK_SIZE : (BLOCK_SIZE - rem);
}

modes::ByteVec modes::pkcs7_padding(const ByteVec& data_bytes, bool print_info) {
    size_t pad_len = get_padding_length(data_bytes.size());
    ByteVec out = data_bytes;
    out.insert(out.end(), pad_len, static_cast<Byte>(pad_len));
    if (print_info) {
        std::cout << "[PKCS#7 Padding] data_len=" << data_bytes.size()
                  << " bytes | missing_bytes_in_last_block=" << pad_len
                  << " | padding_length=" << pad_len
                  << " (0x" << std::hex << std::setw(2) << std::setfill('0') << pad_len << std::dec << ")\n";
    }
    return out;
}

modes::ByteVec modes::pkcs7_padding(const std::string& data_str, bool print_info) {
    return pkcs7_padding(utf8_to_bytes(data_str), print_info);
}

modes::ByteVec modes::pkcs7_unpadding(const ByteVec& data_bytes, bool print_info) {
    if (data_bytes.empty() || data_bytes.size() % BLOCK_SIZE != 0) {
        throw std::invalid_argument("PKCS#7 padded data must be a non-zero multiple of 16 bytes.");
    }
    size_t pad_len = data_bytes.back();
    if (pad_len == 0 || pad_len > BLOCK_SIZE) {
        throw std::invalid_argument("Invalid PKCS#7 padding length.");
    }
    for (size_t i = data_bytes.size() - pad_len; i < data_bytes.size(); ++i) {
        if (data_bytes[i] != static_cast<Byte>(pad_len)) {
            throw std::invalid_argument("Invalid PKCS#7 padding bytes.");
        }
    }
    ByteVec out(data_bytes.begin(), data_bytes.end() - pad_len);
    if (print_info) {
        std::cout << "[PKCS#7 Unpadding] total_len=" << data_bytes.size()
                  << " bytes | removed padding_length=" << pad_len
                  << " bytes -> unpadded_len=" << out.size() << " bytes\n";
    }
    return out;
}

bool modes::_constant_time_equal(const ByteVec& a, const ByteVec& b) noexcept {
    if (a.size() != b.size()) return false;
    Byte diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= (a[i] ^ b[i]);
    }
    return diff == 0;
}

void modes::_increment_be_128(ByteVec& counter) noexcept {
    for (int i = 15; i >= 0; --i) {
        if (++counter[i] != 0) {
            break;
        }
    }
}

// ============================================================================
// 1. Electronic Codebook (ECB) - NIST SP 800-38A Section 6.1
// ============================================================================
modes::ByteVec modes::ecb_encrypt(const ByteVec& plaintext, bool pad) {
    ByteVec data = pad ? pkcs7_padding(plaintext, verbose) : plaintext;
    _require_block_multiple(data, "plaintext");
    auto blocks = _chunks(data, BLOCK_SIZE);
    ByteVec out;
    out.reserve(data.size());
    for (size_t i = 0; i < blocks.size(); ++i) {
        ByteVec ct = aes.encrypt(blocks[i]);
        if (verbose) {
            std::cout << "[ECB Encrypt Block " << (i + 1) << "] PT=" << bytes_to_hex(blocks[i])
                      << " -> CT=" << bytes_to_hex(ct) << "\n";
        }
        out.insert(out.end(), ct.begin(), ct.end());
    }
    return out;
}

modes::ByteVec modes::ecb_encrypt(const std::string& plaintext, bool pad) {
    return ecb_encrypt(utf8_to_bytes(plaintext), pad);
}

modes::ByteVec modes::ecb_decrypt_bytes(const ByteVec& ciphertext, bool unpad) {
    _require_block_multiple(ciphertext, "ciphertext");
    auto blocks = _chunks(ciphertext, BLOCK_SIZE);
    ByteVec out;
    out.reserve(ciphertext.size());
    for (size_t i = 0; i < blocks.size(); ++i) {
        ByteVec pt = aes.decrypt(blocks[i]);
        if (verbose) {
            std::cout << "[ECB Decrypt Block " << (i + 1) << "] CT=" << bytes_to_hex(blocks[i])
                      << " -> PT=" << bytes_to_hex(pt) << "\n";
        }
        out.insert(out.end(), pt.begin(), pt.end());
    }
    return unpad ? pkcs7_unpadding(out, verbose) : out;
}

std::string modes::ecb_decrypt(const ByteVec& ciphertext, bool unpad) {
    return bytes_to_utf8(ecb_decrypt_bytes(ciphertext, unpad));
}

// ============================================================================
// 2. Cipher Block Chaining (CBC) - NIST SP 800-38A Section 6.2
// ============================================================================
modes::ByteVec modes::cbc_encrypt(const ByteVec& plaintext,
                                  const std::optional<ByteVec>& custom_iv,
                                  bool prepend_iv,
                                  bool pad) {
    ByteVec cur_iv = _fresh_iv(custom_iv, "iv");
    ByteVec data = pad ? pkcs7_padding(plaintext, verbose) : plaintext;
    _require_block_multiple(data, "plaintext");
    auto blocks = _chunks(data, BLOCK_SIZE);

    ByteVec out;
    out.reserve((prepend_iv ? BLOCK_SIZE : 0) + data.size());
    if (prepend_iv) {
        out.insert(out.end(), cur_iv.begin(), cur_iv.end());
    }

    ByteVec prev = cur_iv;
    for (size_t i = 0; i < blocks.size(); ++i) {
        ByteVec xored = _xor(blocks[i], prev);
        ByteVec ct = aes.encrypt(xored);
        if (verbose) {
            std::cout << "[CBC Encrypt Block " << (i + 1) << "] PT=" << bytes_to_hex(blocks[i])
                      << " ^ Prev=" << bytes_to_hex(prev)
                      << " -> XOR=" << bytes_to_hex(xored)
                      << " -> CT=" << bytes_to_hex(ct) << "\n";
        }
        out.insert(out.end(), ct.begin(), ct.end());
        prev = ct;
    }
    return out;
}

modes::ByteVec modes::cbc_encrypt(const std::string& plaintext,
                                  const std::optional<ByteVec>& custom_iv,
                                  bool prepend_iv,
                                  bool pad) {
    return cbc_encrypt(utf8_to_bytes(plaintext), custom_iv, prepend_iv, pad);
}

modes::ByteVec modes::cbc_decrypt_bytes(const ByteVec& ciphertext,
                                        const std::optional<ByteVec>& custom_iv,
                                        bool has_iv,
                                        bool unpad) {
    ByteVec cur_iv;
    ByteVec body;
    if (has_iv) {
        if (ciphertext.size() < 2 * BLOCK_SIZE || ciphertext.size() % BLOCK_SIZE != 0) {
            throw std::invalid_argument(
                "CBC ciphertext with prepended IV must be at least 32 bytes and block-aligned."
            );
        }
        cur_iv.assign(ciphertext.begin(), ciphertext.begin() + BLOCK_SIZE);
        body.assign(ciphertext.begin() + BLOCK_SIZE, ciphertext.end());
    } else {
        if (!custom_iv.has_value()) {
            throw std::invalid_argument("iv is required when has_iv=false.");
        }
        cur_iv = _require_exact_block(custom_iv.value(), "iv");
        _require_block_multiple(ciphertext, "ciphertext");
        body = ciphertext;
    }

    auto blocks = _chunks(body, BLOCK_SIZE);
    ByteVec out;
    out.reserve(body.size());
    ByteVec prev = cur_iv;
    for (size_t i = 0; i < blocks.size(); ++i) {
        ByteVec dec = aes.decrypt(blocks[i]);
        ByteVec pt = _xor(dec, prev);
        if (verbose) {
            std::cout << "[CBC Decrypt Block " << (i + 1) << "] CT=" << bytes_to_hex(blocks[i])
                      << " -> InvAES=" << bytes_to_hex(dec)
                      << " ^ Prev=" << bytes_to_hex(prev)
                      << " -> PT=" << bytes_to_hex(pt) << "\n";
        }
        out.insert(out.end(), pt.begin(), pt.end());
        prev = blocks[i];
    }
    return unpad ? pkcs7_unpadding(out, verbose) : out;
}

std::string modes::cbc_decrypt(const ByteVec& ciphertext,
                               const std::optional<ByteVec>& custom_iv,
                               bool has_iv,
                               bool unpad) {
    return bytes_to_utf8(cbc_decrypt_bytes(ciphertext, custom_iv, has_iv, unpad));
}

// ============================================================================
// 3. Cipher Feedback (CFB) - NIST SP 800-38A Section 6.3
// ============================================================================
modes::ByteVec modes::cfb_encrypt(const ByteVec& plaintext,
                                  const std::optional<ByteVec>& custom_iv,
                                  int segment_size,
                                  bool prepend_iv) {
    if (segment_size < 8 || segment_size > 128 || segment_size % 8 != 0) {
        throw std::invalid_argument(
            "segment_size must be one of the byte-aligned sizes from 8 to 128 bits."
        );
    }
    size_t seg_bytes = static_cast<size_t>(segment_size / 8);
    ByteVec cur_iv = _fresh_iv(custom_iv, "iv");
    ByteVec out;
    if (prepend_iv) {
        out.insert(out.end(), cur_iv.begin(), cur_iv.end());
    }
    ByteVec reg = cur_iv;
    auto segments = _chunks(plaintext, seg_bytes);
    for (size_t i = 0; i < segments.size(); ++i) {
        ByteVec enc_reg = aes.encrypt(reg);
        ByteVec stream(enc_reg.begin(), enc_reg.begin() + segments[i].size());
        ByteVec ct_seg = _xor(segments[i], stream);
        if (verbose) {
            std::cout << "[CFB-" << segment_size << " Encrypt Seg " << (i + 1) << "] Reg="
                      << bytes_to_hex(reg) << " -> Stream=" << bytes_to_hex(stream)
                      << " ^ PT=" << bytes_to_hex(segments[i])
                      << " -> CT=" << bytes_to_hex(ct_seg) << "\n";
        }
        out.insert(out.end(), ct_seg.begin(), ct_seg.end());
        if (ct_seg.size() == seg_bytes) {
            ByteVec next_reg(reg.begin() + seg_bytes, reg.end());
            next_reg.insert(next_reg.end(), ct_seg.begin(), ct_seg.end());
            reg = std::move(next_reg);
        }
    }
    return out;
}

modes::ByteVec modes::cfb_encrypt(const std::string& plaintext,
                                  const std::optional<ByteVec>& custom_iv,
                                  int segment_size,
                                  bool prepend_iv) {
    return cfb_encrypt(utf8_to_bytes(plaintext), custom_iv, segment_size, prepend_iv);
}

modes::ByteVec modes::cfb_decrypt_bytes(const ByteVec& ciphertext,
                                        const std::optional<ByteVec>& custom_iv,
                                        bool has_iv,
                                        int segment_size) {
    if (segment_size < 8 || segment_size > 128 || segment_size % 8 != 0) {
        throw std::invalid_argument(
            "segment_size must be one of the byte-aligned sizes from 8 to 128 bits."
        );
    }
    size_t seg_bytes = static_cast<size_t>(segment_size / 8);
    ByteVec cur_iv;
    ByteVec body;
    if (has_iv) {
        if (ciphertext.size() < BLOCK_SIZE) {
            throw std::invalid_argument("CFB ciphertext with prepended IV must be at least 16 bytes.");
        }
        cur_iv.assign(ciphertext.begin(), ciphertext.begin() + BLOCK_SIZE);
        body.assign(ciphertext.begin() + BLOCK_SIZE, ciphertext.end());
    } else {
        if (!custom_iv.has_value()) {
            throw std::invalid_argument("iv is required when has_iv=false.");
        }
        cur_iv = _require_exact_block(custom_iv.value(), "iv");
        body = ciphertext;
    }

    ByteVec out;
    ByteVec reg = cur_iv;
    auto segments = _chunks(body, seg_bytes);
    for (size_t i = 0; i < segments.size(); ++i) {
        ByteVec enc_reg = aes.encrypt(reg);
        ByteVec stream(enc_reg.begin(), enc_reg.begin() + segments[i].size());
        ByteVec pt_seg = _xor(segments[i], stream);
        if (verbose) {
            std::cout << "[CFB-" << segment_size << " Decrypt Seg " << (i + 1) << "] Reg="
                      << bytes_to_hex(reg) << " -> Stream=" << bytes_to_hex(stream)
                      << " ^ CT=" << bytes_to_hex(segments[i])
                      << " -> PT=" << bytes_to_hex(pt_seg) << "\n";
        }
        out.insert(out.end(), pt_seg.begin(), pt_seg.end());
        if (segments[i].size() == seg_bytes) {
            ByteVec next_reg(reg.begin() + seg_bytes, reg.end());
            next_reg.insert(next_reg.end(), segments[i].begin(), segments[i].end());
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

// ============================================================================
// 4. Output Feedback (OFB) - NIST SP 800-38A Section 6.4
// ============================================================================
modes::ByteVec modes::ofb_encrypt(const ByteVec& plaintext,
                                  const std::optional<ByteVec>& custom_iv,
                                  bool prepend_iv) {
    ByteVec cur_iv = _fresh_iv(custom_iv, "iv");
    ByteVec out;
    if (prepend_iv) {
        out.insert(out.end(), cur_iv.begin(), cur_iv.end());
    }
    ByteVec feedback = cur_iv;
    auto blocks = _chunks(plaintext, BLOCK_SIZE);
    for (size_t i = 0; i < blocks.size(); ++i) {
        feedback = aes.encrypt(feedback);
        ByteVec keystream(feedback.begin(), feedback.begin() + blocks[i].size());
        ByteVec ct = _xor(blocks[i], keystream);
        if (verbose) {
            std::cout << "[OFB Encrypt Block " << (i + 1) << "] Keystream=" << bytes_to_hex(keystream)
                      << " ^ PT=" << bytes_to_hex(blocks[i])
                      << " -> CT=" << bytes_to_hex(ct) << "\n";
        }
        out.insert(out.end(), ct.begin(), ct.end());
    }
    return out;
}

modes::ByteVec modes::ofb_encrypt(const std::string& plaintext,
                                  const std::optional<ByteVec>& custom_iv,
                                  bool prepend_iv) {
    return ofb_encrypt(utf8_to_bytes(plaintext), custom_iv, prepend_iv);
}

modes::ByteVec modes::ofb_decrypt_bytes(const ByteVec& ciphertext,
                                        const std::optional<ByteVec>& custom_iv,
                                        bool has_iv) {
    ByteVec cur_iv;
    ByteVec body;
    if (has_iv) {
        if (ciphertext.size() < BLOCK_SIZE) {
            throw std::invalid_argument("OFB ciphertext with prepended IV must be at least 16 bytes.");
        }
        cur_iv.assign(ciphertext.begin(), ciphertext.begin() + BLOCK_SIZE);
        body.assign(ciphertext.begin() + BLOCK_SIZE, ciphertext.end());
    } else {
        if (!custom_iv.has_value()) {
            throw std::invalid_argument("iv is required when has_iv=false.");
        }
        cur_iv = _require_exact_block(custom_iv.value(), "iv");
        body = ciphertext;
    }

    ByteVec out;
    ByteVec feedback = cur_iv;
    auto blocks = _chunks(body, BLOCK_SIZE);
    for (size_t i = 0; i < blocks.size(); ++i) {
        feedback = aes.encrypt(feedback);
        ByteVec keystream(feedback.begin(), feedback.begin() + blocks[i].size());
        ByteVec pt = _xor(blocks[i], keystream);
        if (verbose) {
            std::cout << "[OFB Decrypt Block " << (i + 1) << "] Keystream=" << bytes_to_hex(keystream)
                      << " ^ CT=" << bytes_to_hex(blocks[i])
                      << " -> PT=" << bytes_to_hex(pt) << "\n";
        }
        out.insert(out.end(), pt.begin(), pt.end());
    }
    return out;
}

std::string modes::ofb_decrypt(const ByteVec& ciphertext,
                               const std::optional<ByteVec>& custom_iv,
                               bool has_iv) {
    return bytes_to_utf8(ofb_decrypt_bytes(ciphertext, custom_iv, has_iv));
}

// ============================================================================
// 5. Counter (CTR) - NIST SP 800-38A Section 6.5
// ============================================================================
modes::ByteVec modes::ctr_encrypt(const ByteVec& plaintext,
                                  const std::optional<ByteVec>& custom_iv,
                                  bool prepend_iv) {
    ByteVec counter = _fresh_iv(custom_iv, "iv");
    ByteVec out;
    if (prepend_iv) {
        out.insert(out.end(), counter.begin(), counter.end());
    }
    auto blocks = _chunks(plaintext, BLOCK_SIZE);
    for (size_t i = 0; i < blocks.size(); ++i) {
        ByteVec enc_ctr = aes.encrypt(counter);
        ByteVec keystream(enc_ctr.begin(), enc_ctr.begin() + blocks[i].size());
        ByteVec ct = _xor(blocks[i], keystream);
        if (verbose) {
            std::cout << "[CTR Encrypt Block " << (i + 1) << "] Counter=" << bytes_to_hex(counter)
                      << " -> Keystream=" << bytes_to_hex(keystream)
                      << " ^ PT=" << bytes_to_hex(blocks[i])
                      << " -> CT=" << bytes_to_hex(ct) << "\n";
        }
        out.insert(out.end(), ct.begin(), ct.end());
        _increment_be_128(counter);
    }
    return out;
}

modes::ByteVec modes::ctr_encrypt(const std::string& plaintext,
                                  const std::optional<ByteVec>& custom_iv,
                                  bool prepend_iv) {
    return ctr_encrypt(utf8_to_bytes(plaintext), custom_iv, prepend_iv);
}

modes::ByteVec modes::ctr_decrypt_bytes(const ByteVec& ciphertext,
                                        const std::optional<ByteVec>& custom_iv,
                                        bool has_iv) {
    ByteVec counter;
    ByteVec body;
    if (has_iv) {
        if (ciphertext.size() < BLOCK_SIZE) {
            throw std::invalid_argument(
                "CTR ciphertext with prepended counter block must be at least 16 bytes."
            );
        }
        counter.assign(ciphertext.begin(), ciphertext.begin() + BLOCK_SIZE);
        body.assign(ciphertext.begin() + BLOCK_SIZE, ciphertext.end());
    } else {
        if (!custom_iv.has_value()) {
            throw std::invalid_argument("iv is required when has_iv=false.");
        }
        counter = _require_exact_block(custom_iv.value(), "iv");
        body = ciphertext;
    }

    ByteVec out;
    auto blocks = _chunks(body, BLOCK_SIZE);
    for (size_t i = 0; i < blocks.size(); ++i) {
        ByteVec enc_ctr = aes.encrypt(counter);
        ByteVec keystream(enc_ctr.begin(), enc_ctr.begin() + blocks[i].size());
        ByteVec pt = _xor(blocks[i], keystream);
        if (verbose) {
            std::cout << "[CTR Decrypt Block " << (i + 1) << "] Counter=" << bytes_to_hex(counter)
                      << " -> Keystream=" << bytes_to_hex(keystream)
                      << " ^ CT=" << bytes_to_hex(blocks[i])
                      << " -> PT=" << bytes_to_hex(pt) << "\n";
        }
        out.insert(out.end(), pt.begin(), pt.end());
        _increment_be_128(counter);
    }
    return out;
}

std::string modes::ctr_decrypt(const ByteVec& ciphertext,
                               const std::optional<ByteVec>& custom_iv,
                               bool has_iv) {
    return bytes_to_utf8(ctr_decrypt_bytes(ciphertext, custom_iv, has_iv));
}
