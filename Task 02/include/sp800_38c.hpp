#pragma once
#include "common.hpp"
namespace lab {
Bytes ccm_encrypt(const AES& aes, const Bytes& plaintext, const Bytes& nonce,
                  const Bytes& aad = {}, std::size_t tag_len = 16, bool prepend_nonce = false);
Bytes ccm_decrypt(const AES& aes, const Bytes& ciphertext_and_tag, const Bytes& nonce,
                  const Bytes& aad = {}, std::size_t tag_len = 16, bool has_nonce = false);
}
