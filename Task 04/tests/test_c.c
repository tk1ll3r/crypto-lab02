// -*- coding: utf-8 -*-
/**
 * test_c.c - Deep C11 Language Import Verification Suite (Task 3).
 * Imports the compiled C++ library (libaes_crypto.a / libaes_crypto.so / aes_crypto.dll)
 * via C ABI header `c_api.h` and verifies:
 *   1. AES-128, AES-192, AES-256 Single-Block Known-Answer Tests (FIPS 197)
 *   2. Standard A (NIST SP 800-38A): ECB, CBC (+ PKCS#7), CFB-128, CFB-8, OFB, CTR
 *   3. Standard C (NIST SP 800-38C): AES-CCM Appendix C Ex.1, Ex.2, Ex.3 & Tamper Detection
 */

#include "c_api.h"

#include <stdio.h>
#include <string.h>

static int g_pass = 0;
static int g_fail = 0;

static void check_c(int cond, const char* label) {
    if (cond) {
        ++g_pass;
        printf("  [PASS] %s\n", label);
    } else {
        ++g_fail;
        printf("  [FAIL] %s\n", label);
    }
}

static void print_hex_short(const char* label, const uint8_t* data, size_t len) {
    printf("    %-12s: ", label);
    size_t show = (len > 32) ? 32 : len;
    for (size_t i = 0; i < show; ++i) {
        printf("%02x", data[i]);
    }
    if (len > 32) printf("... (%zu bytes)", len);
    printf("\n");
}

int main(void) {
    printf("======================================================================\n");
    printf(" UIT NT219 Lab - Task 3: C11 Library Import Verification (c_api.h)\n");
    printf("======================================================================\n\n");

    // -----------------------------------------------------------------------
    // Part 1: FIPS 197 AES-128 / AES-192 / AES-256 Single-Block KAT in C
    // -----------------------------------------------------------------------
    printf("=== 1. FIPS 197 Single-Block KAT Imported in C ===\n");
    const uint8_t key256[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    const uint8_t pt16[16] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
    };
    const uint8_t exp128[16] = {
        0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a
    };
    const uint8_t exp192[16] = {
        0xdd,0xa9,0x7c,0xa4,0x86,0x4c,0xdf,0xe0,0x6e,0xaf,0x70,0xa0,0xec,0x0d,0x71,0x91
    };
    const uint8_t exp256[16] = {
        0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89
    };

    uint8_t ct[16] = {0}, dec[16] = {0};

    aes_encrypt_block(key256, 16, pt16, ct);
    aes_decrypt_block(key256, 16, ct, dec);
    check_c(memcmp(ct, exp128, 16) == 0 && memcmp(dec, pt16, 16) == 0,
            "C ABI: aes_encrypt_block & aes_decrypt_block (AES-128)");

    aes_encrypt_block(key256, 24, pt16, ct);
    aes_decrypt_block(key256, 24, ct, dec);
    check_c(memcmp(ct, exp192, 16) == 0 && memcmp(dec, pt16, 16) == 0,
            "C ABI: aes_encrypt_block & aes_decrypt_block (AES-192)");

    aes_encrypt_block(key256, 32, pt16, ct);
    aes_decrypt_block(key256, 32, ct, dec);
    check_c(memcmp(ct, exp256, 16) == 0 && memcmp(dec, pt16, 16) == 0,
            "C ABI: aes_encrypt_block & aes_decrypt_block (AES-256)");
    printf("\n");

    // -----------------------------------------------------------------------
    // Part 2: Standard A (NIST SP 800-38A) All 5 Modes Imported in C
    // -----------------------------------------------------------------------
    printf("=== 2. Standard A (NIST SP 800-38A) Modes Imported in C ===\n");
    const uint8_t k128[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    const uint8_t iv16[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    const char* msg = "UIT NT219 Task 3: C11 program calling C++ shared/static library!";
    size_t msg_len = strlen(msg);
    size_t pad_len = aes_get_padding_length(msg_len);

    uint8_t buf_ct[256] = {0}, buf_pt[256] = {0};
    size_t ct_len = 0, pt_len = 0;

    // 2.1 ECB + PKCS#7
    int rc = aes_ecb_encrypt(k128, 16, (const uint8_t*)msg, msg_len, 1, buf_ct, &ct_len);
    rc |= aes_ecb_decrypt(k128, 16, buf_ct, ct_len, 1, buf_pt, &pt_len);
    check_c(rc == 0 && pt_len == msg_len && memcmp(buf_pt, msg, msg_len) == 0,
            "C ABI: aes_ecb_encrypt & aes_ecb_decrypt with PKCS#7");

    // 2.2 CBC + PKCS#7 (prepended IV)
    rc = aes_cbc_encrypt(k128, 16, iv16, (const uint8_t*)msg, msg_len, 1, 1, buf_ct, &ct_len);
    rc |= aes_cbc_decrypt(k128, 16, NULL, buf_ct, ct_len, 1, 1, buf_pt, &pt_len);
    check_c(rc == 0 && pt_len == msg_len && memcmp(buf_pt, msg, msg_len) == 0,
            "C ABI: aes_cbc_encrypt & aes_cbc_decrypt (PKCS#7, prepended IV)");
    print_hex_short("CBC Cipher", buf_ct, ct_len);

    // 2.3 CFB-128 & CFB-8
    rc = aes_cfb_encrypt(k128, 16, iv16, (const uint8_t*)msg, msg_len, 128, 1, buf_ct, &ct_len);
    rc |= aes_cfb_decrypt(k128, 16, NULL, buf_ct, ct_len, 128, 1, buf_pt, &pt_len);
    check_c(rc == 0 && pt_len == msg_len && memcmp(buf_pt, msg, msg_len) == 0,
            "C ABI: aes_cfb_encrypt & aes_cfb_decrypt (CFB-128)");

    rc = aes_cfb_encrypt(k128, 16, iv16, (const uint8_t*)msg, msg_len, 8, 1, buf_ct, &ct_len);
    rc |= aes_cfb_decrypt(k128, 16, NULL, buf_ct, ct_len, 8, 1, buf_pt, &pt_len);
    check_c(rc == 0 && pt_len == msg_len && memcmp(buf_pt, msg, msg_len) == 0,
            "C ABI: aes_cfb_encrypt & aes_cfb_decrypt (CFB-8)");

    // 2.4 OFB
    rc = aes_ofb_encrypt(k128, 16, iv16, (const uint8_t*)msg, msg_len, 1, buf_ct, &ct_len);
    rc |= aes_ofb_decrypt(k128, 16, NULL, buf_ct, ct_len, 1, buf_pt, &pt_len);
    check_c(rc == 0 && pt_len == msg_len && memcmp(buf_pt, msg, msg_len) == 0,
            "C ABI: aes_ofb_encrypt & aes_ofb_decrypt (OFB)");

    // 2.5 CTR
    rc = aes_ctr_encrypt(k128, 16, iv16, (const uint8_t*)msg, msg_len, 1, buf_ct, &ct_len);
    rc |= aes_ctr_decrypt(k128, 16, NULL, buf_ct, ct_len, 1, buf_pt, &pt_len);
    check_c(rc == 0 && pt_len == msg_len && memcmp(buf_pt, msg, msg_len) == 0,
            "C ABI: aes_ctr_encrypt & aes_ctr_decrypt (CTR)");
    printf("    PKCS#7 Info : msg_len=%zu bytes -> padding_length=%zu bytes\n\n", msg_len, pad_len);

    // -----------------------------------------------------------------------
    // Part 3: Standard C (NIST SP 800-38C) AES-CCM Imported in C
    // -----------------------------------------------------------------------
    printf("=== 3. Standard C (NIST SP 800-38C) AES-CCM Imported in C ===\n");
    const uint8_t ccm_key[16] = {
        0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f
    };
    const uint8_t ccm_nonce[7] = {0x10,0x11,0x12,0x13,0x14,0x15,0x16};
    const uint8_t ccm_aad[8]   = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07};
    const uint8_t ccm_pt[4]    = {0x20,0x21,0x22,0x23};
    const uint8_t ccm_exp[8]   = {0x71,0x62,0x01,0x5b,0x4d,0xac,0x25,0x5d};

    uint8_t ccm_ct[64] = {0}, ccm_dec[64] = {0};
    size_t ccm_ct_len = 0, ccm_dec_len = 0;

    rc = aes_ccm_encrypt(ccm_key, 16, ccm_nonce, 7, ccm_aad, 8, ccm_pt, 4, 4, 0, ccm_ct, &ccm_ct_len);
    rc |= aes_ccm_decrypt(ccm_key, 16, ccm_nonce, 7, ccm_aad, 8, ccm_ct, ccm_ct_len, 4, 0, ccm_dec, &ccm_dec_len);
    check_c(rc == 0 && ccm_ct_len == 8 && memcmp(ccm_ct, ccm_exp, 8) == 0 &&
            ccm_dec_len == 4 && memcmp(ccm_dec, ccm_pt, 4) == 0,
            "C ABI: aes_ccm_encrypt & aes_ccm_decrypt (SP 800-38C Appendix C Ex.1)");

    // Tamper test in C: flipping 1 bit in tag must return non-zero error code (-1)
    ccm_ct[ccm_ct_len - 1] ^= 0x01;
    int tamper_rc = aes_ccm_decrypt(ccm_key, 16, ccm_nonce, 7, ccm_aad, 8, ccm_ct, ccm_ct_len, 4, 0, ccm_dec, &ccm_dec_len);
    check_c(tamper_rc != 0, "C ABI: aes_ccm_decrypt rejects forged/tampered authentication tag");

    printf("\nSummary (C11 Import Suite): %d passed, %d failed.\n", g_pass, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
