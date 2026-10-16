// -*- coding: utf-8 -*-
/**
 * c_api.cpp - C ABI wrapper implementation for AES and Modes of Operation.
 * UIT NT219 Cryptography Lab - Task 2.
 */

#ifndef AES_CRYPTO_EXPORTS
#define AES_CRYPTO_EXPORTS
#endif

#include "c_api.h"
#include "AES.h"
#include "modes.h"

#include <algorithm>
#include <cstring>
#include <optional>

namespace {
std::optional<modes::ByteVec> make_opt_vec(const uint8_t* ptr, size_t len) {
    if (ptr == nullptr) {
        return std::nullopt;
    }
    return modes::ByteVec(ptr, ptr + len);
}

int copy_out(const modes::ByteVec& res, uint8_t* out_buf, size_t* out_len) {
    if (out_len == nullptr) {
        return -1;
    }
    *out_len = res.size();
    if (out_buf != nullptr && !res.empty()) {
        std::memcpy(out_buf, res.data(), res.size());
    }
    return 0;
}
} // namespace

extern "C" {

AES_API int aes_encrypt_block(const uint8_t* key, size_t key_len,
                              const uint8_t* in_block16, uint8_t* out_block16) {
    try {
        if (!key || !in_block16 || !out_block16) return -1;
        AES cipher(AES::ByteVec(key, key + key_len), static_cast<int>(key_len * 8));
        auto out = cipher.encrypt(AES::ByteVec(in_block16, in_block16 + 16));
        std::memcpy(out_block16, out.data(), 16);
        return 0;
    } catch (...) {
        return -1;
    }
}

AES_API int aes_decrypt_block(const uint8_t* key, size_t key_len,
                              const uint8_t* in_block16, uint8_t* out_block16) {
    try {
        if (!key || !in_block16 || !out_block16) return -1;
        AES cipher(AES::ByteVec(key, key + key_len), static_cast<int>(key_len * 8));
        auto out = cipher.decrypt(AES::ByteVec(in_block16, in_block16 + 16));
        std::memcpy(out_block16, out.data(), 16);
        return 0;
    } catch (...) {
        return -1;
    }
}

AES_API size_t aes_get_padding_length(size_t data_len) {
    return modes::get_padding_length(data_len);
}

AES_API int aes_ecb_encrypt(const uint8_t* key, size_t key_len,
                            const uint8_t* pt, size_t pt_len,
                            int pad, uint8_t* out_buf, size_t* out_len) {
    try {
        if (!key || (!pt && pt_len > 0)) return -1;
        modes m(modes::ByteVec(key, key + key_len));
        auto res = m.ecb_encrypt(modes::ByteVec(pt, pt + pt_len), pad != 0);
        return copy_out(res, out_buf, out_len);
    } catch (...) {
        return -1;
    }
}

AES_API int aes_ecb_decrypt(const uint8_t* key, size_t key_len,
                            const uint8_t* ct, size_t ct_len,
                            int unpad, uint8_t* out_buf, size_t* out_len) {
    try {
        if (!key || !ct) return -1;
        modes m(modes::ByteVec(key, key + key_len));
        auto res = m.ecb_decrypt_bytes(modes::ByteVec(ct, ct + ct_len), unpad != 0);
        return copy_out(res, out_buf, out_len);
    } catch (...) {
        return -1;
    }
}

AES_API int aes_cbc_encrypt(const uint8_t* key, size_t key_len,
                            const uint8_t* iv16,
                            const uint8_t* pt, size_t pt_len,
                            int prepend_iv, int pad,
                            uint8_t* out_buf, size_t* out_len) {
    try {
        if (!key || (!pt && pt_len > 0)) return -1;
        modes m(modes::ByteVec(key, key + key_len));
        auto res = m.cbc_encrypt(modes::ByteVec(pt, pt + pt_len),
                                 make_opt_vec(iv16, 16),
                                 prepend_iv != 0,
                                 pad != 0);
        return copy_out(res, out_buf, out_len);
    } catch (...) {
        return -1;
    }
}

AES_API int aes_cbc_decrypt(const uint8_t* key, size_t key_len,
                            const uint8_t* iv16,
                            const uint8_t* ct, size_t ct_len,
                            int has_iv, int unpad,
                            uint8_t* out_buf, size_t* out_len) {
    try {
        if (!key || !ct) return -1;
        modes m(modes::ByteVec(key, key + key_len));
        auto res = m.cbc_decrypt_bytes(modes::ByteVec(ct, ct + ct_len),
                                       make_opt_vec(iv16, 16),
                                       has_iv != 0,
                                       unpad != 0);
        return copy_out(res, out_buf, out_len);
    } catch (...) {
        return -1;
    }
}

AES_API int aes_cfb_encrypt(const uint8_t* key, size_t key_len,
                            const uint8_t* iv16,
                            const uint8_t* pt, size_t pt_len,
                            int segment_size, int prepend_iv,
                            uint8_t* out_buf, size_t* out_len) {
    try {
        if (!key || (!pt && pt_len > 0)) return -1;
        modes m(modes::ByteVec(key, key + key_len));
        auto res = m.cfb_encrypt(modes::ByteVec(pt, pt + pt_len),
                                 make_opt_vec(iv16, 16),
                                 segment_size,
                                 prepend_iv != 0);
        return copy_out(res, out_buf, out_len);
    } catch (...) {
        return -1;
    }
}

AES_API int aes_cfb_decrypt(const uint8_t* key, size_t key_len,
                            const uint8_t* iv16,
                            const uint8_t* ct, size_t ct_len,
                            int segment_size, int has_iv,
                            uint8_t* out_buf, size_t* out_len) {
    try {
        if (!key || !ct) return -1;
        modes m(modes::ByteVec(key, key + key_len));
        auto res = m.cfb_decrypt_bytes(modes::ByteVec(ct, ct + ct_len),
                                       make_opt_vec(iv16, 16),
                                       has_iv != 0,
                                       segment_size);
        return copy_out(res, out_buf, out_len);
    } catch (...) {
        return -1;
    }
}

AES_API int aes_ofb_encrypt(const uint8_t* key, size_t key_len,
                            const uint8_t* iv16,
                            const uint8_t* pt, size_t pt_len,
                            int prepend_iv,
                            uint8_t* out_buf, size_t* out_len) {
    try {
        if (!key || (!pt && pt_len > 0)) return -1;
        modes m(modes::ByteVec(key, key + key_len));
        auto res = m.ofb_encrypt(modes::ByteVec(pt, pt + pt_len),
                                 make_opt_vec(iv16, 16),
                                 prepend_iv != 0);
        return copy_out(res, out_buf, out_len);
    } catch (...) {
        return -1;
    }
}

AES_API int aes_ofb_decrypt(const uint8_t* key, size_t key_len,
                            const uint8_t* iv16,
                            const uint8_t* ct, size_t ct_len,
                            int has_iv,
                            uint8_t* out_buf, size_t* out_len) {
    try {
        if (!key || !ct) return -1;
        modes m(modes::ByteVec(key, key + key_len));
        auto res = m.ofb_decrypt_bytes(modes::ByteVec(ct, ct + ct_len),
                                       make_opt_vec(iv16, 16),
                                       has_iv != 0);
        return copy_out(res, out_buf, out_len);
    } catch (...) {
        return -1;
    }
}

AES_API int aes_ctr_encrypt(const uint8_t* key, size_t key_len,
                            const uint8_t* iv16,
                            const uint8_t* pt, size_t pt_len,
                            int prepend_iv,
                            uint8_t* out_buf, size_t* out_len) {
    try {
        if (!key || (!pt && pt_len > 0)) return -1;
        modes m(modes::ByteVec(key, key + key_len));
        auto res = m.ctr_encrypt(modes::ByteVec(pt, pt + pt_len),
                                 make_opt_vec(iv16, 16),
                                 prepend_iv != 0);
        return copy_out(res, out_buf, out_len);
    } catch (...) {
        return -1;
    }
}

AES_API int aes_ctr_decrypt(const uint8_t* key, size_t key_len,
                            const uint8_t* iv16,
                            const uint8_t* ct, size_t ct_len,
                            int has_iv,
                            uint8_t* out_buf, size_t* out_len) {
    try {
        if (!key || !ct) return -1;
        modes m(modes::ByteVec(key, key + key_len));
        auto res = m.ctr_decrypt_bytes(modes::ByteVec(ct, ct + ct_len),
                                       make_opt_vec(iv16, 16),
                                       has_iv != 0);
        return copy_out(res, out_buf, out_len);
    } catch (...) {
        return -1;
    }
}

AES_API int aes_gcm_encrypt(const uint8_t* key, size_t key_len,
                            const uint8_t* nonce12,
                            const uint8_t* aad, size_t aad_len,
                            const uint8_t* pt, size_t pt_len,
                            int prepend_nonce,
                            uint8_t* out_buf, size_t* out_len) {
    try {
        if (!key || (!pt && pt_len > 0)) return -1;
        modes m(modes::ByteVec(key, key + key_len));
        auto res = m.gcm_encrypt(modes::ByteVec(pt, pt + pt_len),
                                 make_opt_vec(aad, aad_len),
                                 make_opt_vec(nonce12, 12),
                                 prepend_nonce != 0);
        return copy_out(res, out_buf, out_len);
    } catch (...) {
        return -1;
    }
}

AES_API int aes_gcm_decrypt(const uint8_t* key, size_t key_len,
                            const uint8_t* nonce12,
                            const uint8_t* aad, size_t aad_len,
                            const uint8_t* ct, size_t ct_len,
                            int has_nonce,
                            uint8_t* out_buf, size_t* out_len) {
    try {
        if (!key || !ct) return -1;
        modes m(modes::ByteVec(key, key + key_len));
        auto res = m.gcm_decrypt_bytes(modes::ByteVec(ct, ct + ct_len),
                                       make_opt_vec(aad, aad_len),
                                       make_opt_vec(nonce12, 12),
                                       has_nonce != 0);
        return copy_out(res, out_buf, out_len);
    } catch (...) {
        return -1;
    }
}

AES_API int aes_ccm_encrypt(const uint8_t* key, size_t key_len,
                            const uint8_t* nonce, size_t nonce_len,
                            const uint8_t* aad, size_t aad_len,
                            const uint8_t* pt, size_t pt_len,
                            size_t tag_len, int prepend_nonce,
                            uint8_t* out_buf, size_t* out_len) {
    try {
        if (!key || (!pt && pt_len > 0)) return -1;
        modes m(modes::ByteVec(key, key + key_len));
        auto res = m.ccm_encrypt(modes::ByteVec(pt, pt + pt_len),
                                 make_opt_vec(aad, aad_len),
                                 make_opt_vec(nonce, nonce_len),
                                 tag_len,
                                 prepend_nonce != 0);
        return copy_out(res, out_buf, out_len);
    } catch (...) {
        return -1;
    }
}

AES_API int aes_ccm_decrypt(const uint8_t* key, size_t key_len,
                            const uint8_t* nonce, size_t nonce_len,
                            const uint8_t* aad, size_t aad_len,
                            const uint8_t* ct, size_t ct_len,
                            size_t tag_len, int has_nonce,
                            uint8_t* out_buf, size_t* out_len) {
    try {
        if (!key || !ct) return -1;
        modes m(modes::ByteVec(key, key + key_len));
        size_t n_len = (nonce_len == 0) ? 13 : nonce_len;
        auto res = m.ccm_decrypt_bytes(modes::ByteVec(ct, ct + ct_len),
                                       make_opt_vec(aad, aad_len),
                                       make_opt_vec(nonce, nonce_len),
                                       has_nonce != 0,
                                       n_len,
                                       tag_len);
        return copy_out(res, out_buf, out_len);
    } catch (...) {
        return -1;
    }
}

} // extern "C"