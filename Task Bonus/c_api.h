// -*- coding: utf-8 -*-
/**
 * c_api.h - C ABI wrapper for AES, Modes of Operation, and Dynamic S-Box (Task Bonus).
 * Enables importing the compiled library (.a / .so / .dll / .lib) into C and Python (ctypes).
 * UIT NT219 Cryptography Lab.
 */

#ifndef UIT_AES_C_API_H
#define UIT_AES_C_API_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) || defined(__CYGWIN__)
  #ifdef AES_CRYPTO_EXPORTS
    #define AES_API __declspec(dllexport)
  #else
    #define AES_API __declspec(dllimport)
  #endif
#else
  #if __GNUC__ >= 4
    #define AES_API __attribute__((visibility("default")))
  #else
    #define AES_API
  #endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Single 16-byte block AES-128 / AES-192 / AES-256 encryption & decryption (Standard Static S-Box).
 * Returns 0 on success, non-zero on error.
 */
AES_API int aes_encrypt_block(const uint8_t* key, size_t key_len,
                              const uint8_t* in_block16, uint8_t* out_block16);

AES_API int aes_decrypt_block(const uint8_t* key, size_t key_len,
                              const uint8_t* in_block16, uint8_t* out_block16);

/**
 * Bonus Task (ACM SIN '13 - Rahnama et al.):
 * Single 16-byte block AES-128 / AES-192 / AES-256 encryption & decryption using Dynamic S-Box.
 */
AES_API int aes_encrypt_block_dynamic(const uint8_t* key, size_t key_len,
                                      const uint8_t* in_block16, uint8_t* out_block16);

AES_API int aes_decrypt_block_dynamic(const uint8_t* key, size_t key_len,
                                      const uint8_t* in_block16, uint8_t* out_block16);

/**
 * Compute PKCS#7 padding_length (1..16 bytes needed to complete a 16-byte block).
 */
AES_API size_t aes_get_padding_length(size_t data_len);

/**
 * NIST SP 800-38A: AES-ECB encrypt / decrypt.
 */
AES_API int aes_ecb_encrypt(const uint8_t* key, size_t key_len,
                            const uint8_t* pt, size_t pt_len,
                            int pad, uint8_t* out_buf, size_t* out_len);

AES_API int aes_ecb_decrypt(const uint8_t* key, size_t key_len,
                            const uint8_t* ct, size_t ct_len,
                            int unpad, uint8_t* out_buf, size_t* out_len);

/**
 * NIST SP 800-38A: AES-CBC encrypt / decrypt.
 */
AES_API int aes_cbc_encrypt(const uint8_t* key, size_t key_len,
                            const uint8_t* iv16,
                            const uint8_t* pt, size_t pt_len,
                            int prepend_iv, int pad,
                            uint8_t* out_buf, size_t* out_len);

AES_API int aes_cbc_decrypt(const uint8_t* key, size_t key_len,
                            const uint8_t* iv16,
                            const uint8_t* ct, size_t ct_len,
                            int has_iv, int unpad,
                            uint8_t* out_buf, size_t* out_len);

/**
 * NIST SP 800-38A: AES-CFB encrypt / decrypt (segment_size: 8..128 bits, multiple of 8).
 */
AES_API int aes_cfb_encrypt(const uint8_t* key, size_t key_len,
                            const uint8_t* iv16,
                            const uint8_t* pt, size_t pt_len,
                            int segment_size, int prepend_iv,
                            uint8_t* out_buf, size_t* out_len);

AES_API int aes_cfb_decrypt(const uint8_t* key, size_t key_len,
                            const uint8_t* iv16,
                            const uint8_t* ct, size_t ct_len,
                            int segment_size, int has_iv,
                            uint8_t* out_buf, size_t* out_len);

/**
 * NIST SP 800-38A: AES-OFB encrypt / decrypt.
 */
AES_API int aes_ofb_encrypt(const uint8_t* key, size_t key_len,
                            const uint8_t* iv16,
                            const uint8_t* pt, size_t pt_len,
                            int prepend_iv,
                            uint8_t* out_buf, size_t* out_len);

AES_API int aes_ofb_decrypt(const uint8_t* key, size_t key_len,
                            const uint8_t* iv16,
                            const uint8_t* ct, size_t ct_len,
                            int has_iv,
                            uint8_t* out_buf, size_t* out_len);

/**
 * NIST SP 800-38A: AES-CTR encrypt / decrypt.
 */
AES_API int aes_ctr_encrypt(const uint8_t* key, size_t key_len,
                            const uint8_t* iv16,
                            const uint8_t* pt, size_t pt_len,
                            int prepend_iv,
                            uint8_t* out_buf, size_t* out_len);

AES_API int aes_ctr_decrypt(const uint8_t* key, size_t key_len,
                            const uint8_t* iv16,
                            const uint8_t* ct, size_t ct_len,
                            int has_iv,
                            uint8_t* out_buf, size_t* out_len);

/**
 * NIST SP 800-38D: AES-GCM AEAD encrypt / decrypt (12-byte nonce, 16-byte tag).
 */
AES_API int aes_gcm_encrypt(const uint8_t* key, size_t key_len,
                            const uint8_t* nonce12,
                            const uint8_t* aad, size_t aad_len,
                            const uint8_t* pt, size_t pt_len,
                            int prepend_nonce,
                            uint8_t* out_buf, size_t* out_len);

AES_API int aes_gcm_decrypt(const uint8_t* key, size_t key_len,
                            const uint8_t* nonce12,
                            const uint8_t* aad, size_t aad_len,
                            const uint8_t* ct, size_t ct_len,
                            int has_nonce,
                            uint8_t* out_buf, size_t* out_len);

/**
 * NIST SP 800-38C: AES-CCM AEAD encrypt / decrypt (nonce 7..13 bytes, tag 4..16 even bytes).
 */
AES_API int aes_ccm_encrypt(const uint8_t* key, size_t key_len,
                            const uint8_t* nonce, size_t nonce_len,
                            const uint8_t* aad, size_t aad_len,
                            const uint8_t* pt, size_t pt_len,
                            size_t tag_len, int prepend_nonce,
                            uint8_t* out_buf, size_t* out_len);

AES_API int aes_ccm_decrypt(const uint8_t* key, size_t key_len,
                            const uint8_t* nonce, size_t nonce_len,
                            const uint8_t* aad, size_t aad_len,
                            const uint8_t* ct, size_t ct_len,
                            size_t tag_len, int has_nonce,
                            uint8_t* out_buf, size_t* out_len);

#ifdef __cplusplus
}
#endif

#endif // UIT_AES_C_API_H
