// -*- coding: utf-8 -*-
/**
 * modes.h - Header file for AES modes of operation (pure C++17 Standard Library).
 * UIT NT219 Cryptography Lab - Task 1.
 */

#ifndef UIT_MODES_H
#define UIT_MODES_H

#include "AES.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

class modes {
public:
    using Byte = AES::Byte;
    using ByteVec = AES::ByteVec;

    static constexpr size_t BLOCK_SIZE = 16;
    static constexpr std::array<size_t, 3> VALID_AES_KEY_BYTES = {16, 24, 32};

    ByteVec key;
    AES aes;
    bool verbose;
    std::optional<ByteVec> iv;

    explicit modes(const ByteVec& key_data, bool verbose_mode = false);
    explicit modes(const std::string& key_str, bool verbose_mode = false);

    // Data conversion helpers
    static ByteVec _ensure_bytes(const ByteVec& data, const std::string& name = "data");
    static ByteVec _ensure_bytes(const std::string& data, const std::string& name = "data");
    static ByteVec utf8_to_bytes(const std::string& utf8_str);
    static std::string bytes_to_utf8(const ByteVec& bytes_data);
    static std::string bytes_to_hex(const ByteVec& bytes_data);
    static ByteVec hex_to_bytes(const std::string& hex_str);
    static ByteVec binary_to_bytes(std::string binary_str);
    static std::string bytes_to_binary(const ByteVec& bytes_data);

    static ByteVec _xor(const ByteVec& a, const ByteVec& b);
    static std::vector<ByteVec> _chunks(const ByteVec& data, size_t size);
    static void _require_block_multiple(const ByteVec& data, const std::string& name);
    static ByteVec _require_exact_block(const ByteVec& data, const std::string& name);
    static ByteVec random_bytes(size_t n);
    ByteVec _fresh_iv(const std::optional<ByteVec>& custom_iv = std::nullopt,
                      const std::string& name = "iv");

    // PKCS#7 padding helpers (with missing_bytes / padding_length calculation)
    static size_t get_padding_length(size_t data_len) noexcept;
    static ByteVec pkcs7_padding(const ByteVec& data_bytes, bool print_info = false);
    static ByteVec pkcs7_padding(const std::string& data_str, bool print_info = false);
    static ByteVec pkcs7_unpadding(const ByteVec& data_bytes, bool print_info = false);

    // NIST SP 800-38A confidentiality modes: ECB, CBC, CFB, OFB, CTR
    ByteVec ecb_encrypt(const ByteVec& plaintext, bool pad = true);
    ByteVec ecb_encrypt(const std::string& plaintext, bool pad = true);
    ByteVec ecb_decrypt_bytes(const ByteVec& ciphertext, bool unpad = true);
    std::string ecb_decrypt(const ByteVec& ciphertext, bool unpad = true);

    ByteVec cbc_encrypt(const ByteVec& plaintext,
                        const std::optional<ByteVec>& custom_iv = std::nullopt,
                        bool prepend_iv = true,
                        bool pad = true);
    ByteVec cbc_encrypt(const std::string& plaintext,
                        const std::optional<ByteVec>& custom_iv = std::nullopt,
                        bool prepend_iv = true,
                        bool pad = true);
    ByteVec cbc_decrypt_bytes(const ByteVec& ciphertext,
                              const std::optional<ByteVec>& custom_iv = std::nullopt,
                              bool has_iv = true,
                              bool unpad = true);
    std::string cbc_decrypt(const ByteVec& ciphertext,
                            const std::optional<ByteVec>& custom_iv = std::nullopt,
                            bool has_iv = true,
                            bool unpad = true);

    ByteVec cfb_encrypt(const ByteVec& plaintext,
                        const std::optional<ByteVec>& custom_iv = std::nullopt,
                        int segment_size = 128,
                        bool prepend_iv = true);
    ByteVec cfb_encrypt(const std::string& plaintext,
                        const std::optional<ByteVec>& custom_iv = std::nullopt,
                        int segment_size = 128,
                        bool prepend_iv = true);
    ByteVec cfb_decrypt_bytes(const ByteVec& ciphertext,
                              const std::optional<ByteVec>& custom_iv = std::nullopt,
                              bool has_iv = true,
                              int segment_size = 128);
    std::string cfb_decrypt(const ByteVec& ciphertext,
                            const std::optional<ByteVec>& custom_iv = std::nullopt,
                            bool has_iv = true,
                            int segment_size = 128);

    ByteVec ofb_encrypt(const ByteVec& plaintext,
                        const std::optional<ByteVec>& custom_iv = std::nullopt,
                        bool prepend_iv = true);
    ByteVec ofb_encrypt(const std::string& plaintext,
                        const std::optional<ByteVec>& custom_iv = std::nullopt,
                        bool prepend_iv = true);
    ByteVec ofb_decrypt_bytes(const ByteVec& ciphertext,
                              const std::optional<ByteVec>& custom_iv = std::nullopt,
                              bool has_iv = true);
    std::string ofb_decrypt(const ByteVec& ciphertext,
                            const std::optional<ByteVec>& custom_iv = std::nullopt,
                            bool has_iv = true);

    ByteVec ctr_encrypt(const ByteVec& plaintext,
                        const std::optional<ByteVec>& custom_iv = std::nullopt,
                        bool prepend_iv = true);
    ByteVec ctr_encrypt(const std::string& plaintext,
                        const std::optional<ByteVec>& custom_iv = std::nullopt,
                        bool prepend_iv = true);
    ByteVec ctr_decrypt_bytes(const ByteVec& ciphertext,
                              const std::optional<ByteVec>& custom_iv = std::nullopt,
                              bool has_iv = true);
    std::string ctr_decrypt(const ByteVec& ciphertext,
                            const std::optional<ByteVec>& custom_iv = std::nullopt,
                            bool has_iv = true);

    // NIST SP 800-38D: AES-GCM & GMAC
    ByteVec gcm_encrypt(const ByteVec& plaintext,
                        const std::optional<ByteVec>& associated_data = std::nullopt,
                        const std::optional<ByteVec>& nonce = std::nullopt,
                        bool prepend_nonce = true);
    ByteVec gcm_encrypt(const std::string& plaintext,
                        const std::optional<ByteVec>& associated_data = std::nullopt,
                        const std::optional<ByteVec>& nonce = std::nullopt,
                        bool prepend_nonce = true);
    ByteVec gcm_decrypt_bytes(const ByteVec& ciphertext_and_tag,
                              const std::optional<ByteVec>& associated_data = std::nullopt,
                              const std::optional<ByteVec>& nonce = std::nullopt,
                              bool has_nonce = true);
    std::string gcm_decrypt(const ByteVec& ciphertext_and_tag,
                            const std::optional<ByteVec>& associated_data = std::nullopt,
                            const std::optional<ByteVec>& nonce = std::nullopt,
                            bool has_nonce = true);
    ByteVec gmac(const ByteVec& authenticated_data,
                 const std::optional<ByteVec>& nonce = std::nullopt,
                 bool prepend_nonce = true);
    bool gmac_verify(const ByteVec& authenticated_data,
                     const ByteVec& tag,
                     const std::optional<ByteVec>& nonce = std::nullopt,
                     bool has_nonce = true);

    // NIST SP 800-38C: AES-CCM
    ByteVec ccm_encrypt(const ByteVec& plaintext,
                        const std::optional<ByteVec>& associated_data = std::nullopt,
                        const std::optional<ByteVec>& nonce = std::nullopt,
                        size_t tag_length = 16,
                        bool prepend_nonce = true);
    ByteVec ccm_encrypt(const std::string& plaintext,
                        const std::optional<ByteVec>& associated_data = std::nullopt,
                        const std::optional<ByteVec>& nonce = std::nullopt,
                        size_t tag_length = 16,
                        bool prepend_nonce = true);
    ByteVec ccm_decrypt_bytes(const ByteVec& ciphertext_and_tag,
                              const std::optional<ByteVec>& associated_data = std::nullopt,
                              const std::optional<ByteVec>& nonce = std::nullopt,
                              bool has_nonce = true,
                              size_t nonce_length = 13,
                              size_t tag_length = 16);
    std::string ccm_decrypt(const ByteVec& ciphertext_and_tag,
                            const std::optional<ByteVec>& associated_data = std::nullopt,
                            const std::optional<ByteVec>& nonce = std::nullopt,
                            bool has_nonce = true,
                            size_t nonce_length = 13,
                            size_t tag_length = 16);

    // RFC 8452: AES-GCM-SIV
    ByteVec gcm_siv_encrypt(const ByteVec& plaintext,
                            const std::optional<ByteVec>& associated_data = std::nullopt,
                            const std::optional<ByteVec>& nonce = std::nullopt,
                            bool prepend_nonce = true);
    ByteVec gcm_siv_encrypt(const std::string& plaintext,
                            const std::optional<ByteVec>& associated_data = std::nullopt,
                            const std::optional<ByteVec>& nonce = std::nullopt,
                            bool prepend_nonce = true);
    ByteVec gcm_siv_decrypt_bytes(const ByteVec& ciphertext_and_tag,
                                  const std::optional<ByteVec>& associated_data = std::nullopt,
                                  const std::optional<ByteVec>& nonce = std::nullopt,
                                  bool has_nonce = true);
    std::string gcm_siv_decrypt(const ByteVec& ciphertext_and_tag,
                                const std::optional<ByteVec>& associated_data = std::nullopt,
                                const std::optional<ByteVec>& nonce = std::nullopt,
                                bool has_nonce = true);

    // NIST SP 800-38E: AES-XTS
    ByteVec xts_encrypt(const ByteVec& plaintext,
                        const std::optional<ByteVec>& xts_key = std::nullopt,
                        const std::optional<ByteVec>& tweak = std::nullopt,
                        uint64_t data_unit_number = 0);
    ByteVec xts_encrypt(const std::string& plaintext,
                        const std::optional<ByteVec>& xts_key = std::nullopt,
                        const std::optional<ByteVec>& tweak = std::nullopt,
                        uint64_t data_unit_number = 0);
    ByteVec xts_decrypt_bytes(const ByteVec& ciphertext,
                              const std::optional<ByteVec>& xts_key = std::nullopt,
                              const std::optional<ByteVec>& tweak = std::nullopt,
                              uint64_t data_unit_number = 0);

    // NIST SP 800-38F: AES Key Wrap / KWP
    ByteVec key_wrap(const ByteVec& key_to_wrap, bool pad = false);
    ByteVec key_wrap(const std::string& key_to_wrap, bool pad = false);
    ByteVec key_unwrap(const ByteVec& wrapped_key, bool pad = false);

private:
    static ByteVec _ValidateKey(const ByteVec& k);
    static bool _constant_time_equal(const ByteVec& a, const ByteVec& b) noexcept;
    static void _increment_be_128(ByteVec& counter) noexcept;
    static void _increment_be_32(ByteVec& counter) noexcept;

    static ByteVec _gf128_mul(const ByteVec& X, const ByteVec& Y);
    static ByteVec _ghash(const ByteVec& H, const ByteVec& A, const ByteVec& C);
    ByteVec _gctr(ByteVec icb, const ByteVec& X);

    static ByteVec _ccm_counter_block(const ByteVec& nonce, size_t counter_val);
    ByteVec _ccm_cbc_mac(const ByteVec& plaintext,
                         const ByteVec& aad,
                         const ByteVec& nonce,
                         size_t tag_length);

    static ByteVec _byte_reverse_16(const ByteVec& b);
    static ByteVec _mulX_ghash(const ByteVec& V_in);
    static ByteVec _polyval(const ByteVec& H, const std::vector<ByteVec>& blocks);
    std::pair<ByteVec, ByteVec> _gcm_siv_derive_keys(const ByteVec& nonce);
    static ByteVec _gcm_siv_compute_tag(AES& enc_aes,
                                        const ByteVec& auth_key,
                                        const ByteVec& nonce,
                                        const ByteVec& aad,
                                        const ByteVec& plaintext);
    static ByteVec _gcm_siv_ctr(AES& enc_aes, const ByteVec& tag, const ByteVec& input);

    static void _xts_mul_alpha(ByteVec& T) noexcept;
    ByteVec _kw_wrap_core(const ByteVec& P, const std::array<Byte, 8>& iv_init);
    std::pair<std::array<Byte, 8>, ByteVec> _kw_unwrap_core(const ByteVec& C);
};

using AESModes = modes;

#endif // UIT_MODES_H
