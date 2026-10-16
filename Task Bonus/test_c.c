// -*- coding: utf-8 -*-
/**
 * test_c.c - Demo importing the compiled AES library (libaes_crypto.a / .so / .dll) into C.
 * UIT NT219 Cryptography Lab - Task 2.
 *
 * Compile:
 *   gcc -std=c11 -O2 test_c.c libaes_crypto.a -lstdc++ -lm -o test_c && ./test_c
 */

#include "c_api.h"

#include <stdio.h>
#include <string.h>

static void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("  %-10s: ", label);
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main(void) {
    printf("=== [C Language Import Test] Using c_api.h + libaes_crypto ===\n\n");

    // 1. Test Single-Block AES-128 Known-Answer Test in C
    const uint8_t key128[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    const uint8_t pt16[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    const uint8_t expected_ct16[16] = {
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
        0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
    };

    uint8_t ct16[16] = {0};
    uint8_t dec16[16] = {0};

    int rc1 = aes_encrypt_block(key128, 16, pt16, ct16);
    int rc2 = aes_decrypt_block(key128, 16, ct16, dec16);

    printf("AES-128 Known-Answer Test (from C)\n");
    print_hex("Key", key128, 16);
    print_hex("Plaintext", pt16, 16);
    print_hex("Expected", expected_ct16, 16);
    print_hex("Computed", ct16, 16);
    print_hex("Decrypted", dec16, 16);
    int enc_ok = (rc1 == 0 && memcmp(ct16, expected_ct16, 16) == 0);
    int dec_ok = (rc2 == 0 && memcmp(dec16, pt16, 16) == 0);
    printf("  %-10s: %s\n", "Encrypt", enc_ok ? "PASS" : "FAIL");
    printf("  %-10s: %s\n\n", "Decrypt", dec_ok ? "PASS" : "FAIL");

    // 2. Test AES-CBC with PKCS#7 padding in C
    const char* msg = "Hello from C language importing libaes_crypto!";
    size_t msg_len = strlen(msg);
    size_t pad_len = aes_get_padding_length(msg_len);

    uint8_t cbc_ct[128] = {0};
    size_t cbc_ct_len = 0;
    uint8_t cbc_pt[128] = {0};
    size_t cbc_pt_len = 0;

    int rc_cbc_enc = aes_cbc_encrypt(key128, 16, pt16,
                                     (const uint8_t*)msg, msg_len,
                                     1 /* prepend_iv */, 1 /* pad */,
                                     cbc_ct, &cbc_ct_len);
    int rc_cbc_dec = aes_cbc_decrypt(key128, 16, NULL,
                                     cbc_ct, cbc_ct_len,
                                     1 /* has_iv */, 1 /* unpad */,
                                     cbc_pt, &cbc_pt_len);
    cbc_pt[cbc_pt_len] = '\0';

    int cbc_ok = (rc_cbc_enc == 0 && rc_cbc_dec == 0 &&
                  cbc_pt_len == msg_len && strcmp((const char*)cbc_pt, msg) == 0);

    printf("AES-128-CBC + PKCS#7 Test (from C)\n");
    printf("  %-10s: %s (%zu bytes, padding_length=%zu)\n", "Input", msg, msg_len, pad_len);
    print_hex("Ciphertext", cbc_ct, cbc_ct_len);
    printf("  %-10s: %s\n", "Decrypted", (const char*)cbc_pt);
    printf("  %-10s: %s\n", "Status", cbc_ok ? "PASS" : "FAIL");

    return (enc_ok && dec_ok && cbc_ok) ? 0 : 1;
}
