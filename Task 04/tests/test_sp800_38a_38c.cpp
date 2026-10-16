// -*- coding: utf-8 -*-
/**
 * test_sp800_38a_38c.cpp - Comprehensive NIST SP 800-38A (Standard A) & SP 800-38C (Standard C)
 * Known-Answer Test (KAT) Suite.
 * Verifies BOTH Lecturer Nguyen Ngoc Tu's `lab::` API (aes.hpp, sp800_38a.hpp, sp800_38c.hpp)
 * and the `modes` class API (modes.h).
 */

#include "aes.hpp"
#include "sp800_38a.hpp"
#include "sp800_38c.hpp"
#include "modes.h"

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

static int g_passed = 0;
static int g_failed = 0;

static void check(bool cond, const std::string& label) {
    if (cond) {
        ++g_passed;
        std::cout << "  [PASS] " << label << "\n";
    } else {
        ++g_failed;
        std::cout << "  [FAIL] " << label << "\n";
    }
}

void test_lecturer_lab_namespace_api() {
    std::cout << "=== 0. Lecturer Reference API (`namespace lab` in sp800_38a.hpp & sp800_38c.hpp) ===\n";

    const std::string pt_4blocks_hex =
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710";
    auto pt = lab::from_hex(pt_4blocks_hex);
    auto key128 = lab::from_hex("2b7e151628aed2a6abf7158809cf4f3c");
    auto iv     = lab::from_hex("000102030405060708090a0b0c0d0e0f");
    auto ctr_iv = lab::from_hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");

    AES aes128(key128, 128);

    // lab::ecb_encrypt / lab::ecb_decrypt
    auto ct_ecb = lab::ecb_encrypt(aes128, pt, false);
    check(lab::to_hex(ct_ecb).substr(0, 32) == "3ad77bb40d7a3660a89ecaf32466ef97" &&
          lab::ecb_decrypt(aes128, ct_ecb, false) == pt,
          "lab::ecb_encrypt & lab::ecb_decrypt (SP 800-38A F.1.1/F.1.2)");

    // lab::cbc_encrypt / lab::cbc_decrypt
    auto ct_cbc = lab::cbc_encrypt(aes128, pt, iv, false);
    check(lab::to_hex(ct_cbc).substr(0, 32) == "7649abac8119b246cee98e9b12e9197d" &&
          lab::cbc_decrypt(aes128, ct_cbc, iv, false) == pt,
          "lab::cbc_encrypt & lab::cbc_decrypt (SP 800-38A F.2.1/F.2.2)");

    // lab::cfb_encrypt / lab::cfb_decrypt (128-bit & 8-bit)
    auto ct_cfb128 = lab::cfb_encrypt(aes128, pt, iv, 128);
    check(lab::to_hex(ct_cfb128).substr(0, 32) == "3b3fd92eb72dad20333449f8e83cfb4a" &&
          lab::cfb_decrypt(aes128, ct_cfb128, iv, 128) == pt,
          "lab::cfb_encrypt & lab::cfb_decrypt 128-bit (SP 800-38A F.3.13/F.3.14)");

    lab::Bytes pt_18(pt.begin(), pt.begin() + 18);
    auto ct_cfb8 = lab::cfb_encrypt(aes128, pt_18, iv, 8);
    check(lab::to_hex(ct_cfb8) == "3b79424c9c0dd436bace9e0ed4586a4f32b9" &&
          lab::cfb_decrypt(aes128, ct_cfb8, iv, 8) == pt_18,
          "lab::cfb_encrypt & lab::cfb_decrypt 8-bit (SP 800-38A F.3.7/F.3.8)");

    // lab::ofb_crypt
    auto ct_ofb = lab::ofb_crypt(aes128, pt, iv);
    check(lab::to_hex(ct_ofb).substr(0, 32) == "3b3fd92eb72dad20333449f8e83cfb4a" &&
          lab::ofb_crypt(aes128, ct_ofb, iv) == pt,
          "lab::ofb_crypt (SP 800-38A F.4.1/F.4.2)");

    // lab::ctr_crypt
    auto ct_ctr = lab::ctr_crypt(aes128, pt, ctr_iv);
    check(lab::to_hex(ct_ctr).substr(0, 32) == "874d6191b620e3261bef6864990db6ce" &&
          lab::ctr_crypt(aes128, ct_ctr, ctr_iv) == pt,
          "lab::ctr_crypt (SP 800-38A F.5.1/F.5.2)");

    // lab::ccm_encrypt / lab::ccm_decrypt
    AES aes_ccm(lab::from_hex("404142434445464748494a4b4c4d4e4f"), 128);
    auto ccm_n   = lab::from_hex("10111213141516");
    auto ccm_aad = lab::from_hex("0001020304050607");
    auto ccm_pt  = lab::from_hex("20212223");
    auto ccm_ct  = lab::ccm_encrypt(aes_ccm, ccm_pt, ccm_n, ccm_aad, 4, false);
    check(lab::to_hex(ccm_ct) == "7162015b4dac255d" &&
          lab::ccm_decrypt(aes_ccm, ccm_ct, ccm_n, ccm_aad, 4, false) == ccm_pt,
          "lab::ccm_encrypt & lab::ccm_decrypt (SP 800-38C Appendix C.1 Ex.1)");
    std::cout << "\n";
}

void test_sp800_38a_appendix_f() {
    std::cout << "=== 1. NIST SP 800-38A (Standard A) Appendix F Multi-Block Vectors ===\n";

    const std::string pt_4blocks_hex =
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710";
    auto pt = modes::hex_to_bytes(pt_4blocks_hex);

    auto key128 = modes::hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
    auto key192 = modes::hex_to_bytes("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    auto key256 = modes::hex_to_bytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    auto iv     = modes::hex_to_bytes("000102030405060708090a0b0c0d0e0f");
    auto ctr_iv = modes::hex_to_bytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");

    modes m128(key128, false);
    modes m192(key192, false);
    modes m256(key256, false);

    // F.1.1 & F.1.2: ECB-AES128 (4 blocks)
    const std::string exp_ecb128 =
        "3ad77bb40d7a3660a89ecaf32466ef97"
        "f5d3d58503b9699de785895a96fdbaaf"
        "43b1cd7f598ece23881b00e3ed030688"
        "7b0c785e27e8ad3f8223207104725dd4";
    auto ct_ecb128 = m128.ecb_encrypt(pt, false);
    check(modes::bytes_to_hex(ct_ecb128) == exp_ecb128 && m128.ecb_decrypt_bytes(ct_ecb128, false) == pt,
          "SP 800-38A F.1.1/F.1.2: AES-128-ECB (4 blocks)");

    // F.1.5 & F.1.6: ECB-AES256 (4 blocks)
    const std::string exp_ecb256 =
        "f3eed1bdb5d2a03c064b5a7e3db181f8"
        "591ccb10d410ed26dc5ba74a31362870"
        "b6ed21b99ca6f4f9f153e7b1beafed1d"
        "23304b7a39f9f3ff067d8d8f9e24ecc7";
    auto ct_ecb256 = m256.ecb_encrypt(pt, false);
    check(modes::bytes_to_hex(ct_ecb256) == exp_ecb256 && m256.ecb_decrypt_bytes(ct_ecb256, false) == pt,
          "SP 800-38A F.1.5/F.1.6: AES-256-ECB (4 blocks)");

    // F.2.1 & F.2.2: CBC-AES128 (4 blocks)
    const std::string exp_cbc128 =
        "7649abac8119b246cee98e9b12e9197d"
        "5086cb9b507219ee95db113a917678b2"
        "73bed6b8e3c1743b7116e69e22229516"
        "3ff1caa1681fac09120eca307586e1a7";
    auto ct_cbc128 = m128.cbc_encrypt(pt, iv, false, false);
    check(modes::bytes_to_hex(ct_cbc128) == exp_cbc128 && m128.cbc_decrypt_bytes(ct_cbc128, iv, false, false) == pt,
          "SP 800-38A F.2.1/F.2.2: AES-128-CBC (4 blocks)");

    // F.2.3 & F.2.4: CBC-AES192 (4 blocks)
    const std::string exp_cbc192 =
        "4f021db243bc633d7178183a9fa071e8"
        "b4d9ada9ad7dedf4e5e738763f69145a"
        "571b242012fb7ae07fa9baac3df102e0"
        "08b0e27988598881d920a9e64f5615cd";
    auto ct_cbc192 = m192.cbc_encrypt(pt, iv, false, false);
    check(modes::bytes_to_hex(ct_cbc192) == exp_cbc192 && m192.cbc_decrypt_bytes(ct_cbc192, iv, false, false) == pt,
          "SP 800-38A F.2.3/F.2.4: AES-192-CBC (4 blocks)");

    // F.3.13 & F.3.14: CFB128-AES128 (4 blocks)
    const std::string exp_cfb128 =
        "3b3fd92eb72dad20333449f8e83cfb4a"
        "c8a64537a0b3a93fcde3cdad9f1ce58b"
        "26751f67a3cbb140b1808cf187a4f4df"
        "c04b05357c5d1c0eeac4c66f9ff7f2e6";
    auto ct_cfb128 = m128.cfb_encrypt(pt, iv, 128, false);
    check(modes::bytes_to_hex(ct_cfb128) == exp_cfb128 && m128.cfb_decrypt_bytes(ct_cfb128, iv, false, 128) == pt,
          "SP 800-38A F.3.13/F.3.14: AES-128-CFB128 (4 blocks)");

    // F.3.7 & F.3.8: CFB8-AES128 (First 18 segments = 18 bytes)
    auto pt_cfb8 = modes::ByteVec(pt.begin(), pt.begin() + 18);
    const std::string exp_cfb8_18 = "3b79424c9c0dd436bace9e0ed4586a4f32b9";
    auto ct_cfb8 = m128.cfb_encrypt(pt_cfb8, iv, 8, false);
    check(modes::bytes_to_hex(ct_cfb8) == exp_cfb8_18 && m128.cfb_decrypt_bytes(ct_cfb8, iv, false, 8) == pt_cfb8,
          "SP 800-38A F.3.7/F.3.8: AES-128-CFB8 (18 bytes)");

    // F.4.1 & F.4.2: OFB-AES128 (4 blocks)
    const std::string exp_ofb128 =
        "3b3fd92eb72dad20333449f8e83cfb4a"
        "7789508d16918f03f53c52dac54ed825"
        "9740051e9c5fecf64344f7a82260edcc"
        "304c6528f659c77866a510d9c1d6ae5e";
    auto ct_ofb128 = m128.ofb_encrypt(pt, iv, false);
    check(modes::bytes_to_hex(ct_ofb128) == exp_ofb128 && m128.ofb_decrypt_bytes(ct_ofb128, iv, false) == pt,
          "SP 800-38A F.4.1/F.4.2: AES-128-OFB (4 blocks)");

    // F.5.1 & F.5.2: CTR-AES128 (4 blocks)
    const std::string exp_ctr128 =
        "874d6191b620e3261bef6864990db6ce"
        "9806f66b7970fdff8617187bb9fffdff"
        "5ae4df3edbd5d35e5b4f09020db03eab"
        "1e031dda2fbe03d1792170a0f3009cee";
    auto ct_ctr128 = m128.ctr_encrypt(pt, ctr_iv, false);
    check(modes::bytes_to_hex(ct_ctr128) == exp_ctr128 && m128.ctr_decrypt_bytes(ct_ctr128, ctr_iv, false) == pt,
          "SP 800-38A F.5.1/F.5.2: AES-128-CTR (4 blocks)");

    // PKCS#7 Padding & Unpadding verification across boundary lengths (0, 1, 15, 16, 31 bytes)
    bool pkcs7_ok = true;
    for (std::size_t len : {std::size_t(0), std::size_t(1), std::size_t(15), std::size_t(16), std::size_t(31)}) {
        modes::ByteVec sample(len, 0x42);
        auto padded = modes::pkcs7_padding(sample, false);
        auto unpadded = modes::pkcs7_unpadding(padded, false);
        if (unpadded != sample || (padded.size() % 16 != 0)) {
            pkcs7_ok = false;
        }
    }
    check(pkcs7_ok, "PKCS#7 Padding & Unpadding (0, 1, 15, 16, 31 byte boundary checks)");
    std::cout << "\n";
}

void test_sp800_38c_appendix_c() {
    std::cout << "=== 2. NIST SP 800-38C (Standard C) Appendix C Official CCM Vectors ===\n";

    auto key = modes::hex_to_bytes("404142434445464748494a4b4c4d4e4f");
    modes m(key, false);

    // Appendix C.1 Example 1: Nonce=7 bytes, AAD=8 bytes, Payload=4 bytes, Tag=4 bytes
    {
        auto nonce = modes::hex_to_bytes("10111213141516");
        auto aad   = modes::hex_to_bytes("0001020304050607");
        auto pt    = modes::hex_to_bytes("20212223");
        std::string exp = "7162015b4dac255d";

        auto ct = m.ccm_encrypt(pt, aad, nonce, 4, false);
        auto dec = m.ccm_decrypt_bytes(ct, aad, nonce, false, 7, 4);
        check(modes::bytes_to_hex(ct) == exp && dec == pt,
              "SP 800-38C Appendix C.1 Example 1 (N=7B, A=8B, P=4B, T=4B)");
    }

    // Appendix C.2 Example 2: Nonce=8 bytes, AAD=16 bytes, Payload=16 bytes, Tag=6 bytes
    {
        auto nonce = modes::hex_to_bytes("1011121314151617");
        auto aad   = modes::hex_to_bytes("000102030405060708090a0b0c0d0e0f");
        auto pt    = modes::hex_to_bytes("202122232425262728292a2b2c2d2e2f");
        std::string exp = "d2a1f0e051ea5f62081a7792073d593d1fc64fbfaccd";

        auto ct = m.ccm_encrypt(pt, aad, nonce, 6, false);
        auto dec = m.ccm_decrypt_bytes(ct, aad, nonce, false, 8, 6);
        check(modes::bytes_to_hex(ct) == exp && dec == pt,
              "SP 800-38C Appendix C.2 Example 2 (N=8B, A=16B, P=16B, T=6B)");
    }

    // Appendix C.3 Example 3: Nonce=12 bytes, AAD=20 bytes, Payload=24 bytes, Tag=8 bytes
    {
        auto nonce = modes::hex_to_bytes("101112131415161718191a1b");
        auto aad   = modes::hex_to_bytes("000102030405060708090a0b0c0d0e0f10111213");
        auto pt    = modes::hex_to_bytes("202122232425262728292a2b2c2d2e2f3031323334353637");
        std::string exp = "e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5484392fbc1b09951";

        auto ct = m.ccm_encrypt(pt, aad, nonce, 8, false);
        auto dec = m.ccm_decrypt_bytes(ct, aad, nonce, false, 12, 8);
        check(modes::bytes_to_hex(ct) == exp && dec == pt,
              "SP 800-38C Appendix C.3 Example 3 (N=12B, A=20B, P=24B, T=8B)");
    }

    // Tamper detection test
    {
        auto nonce = modes::hex_to_bytes("101112131415161718191a1b1c");
        auto aad   = modes::utf8_to_bytes("UIT-NT219-CCM-Auth-Header");
        auto ct    = m.ccm_encrypt("Confidential payload for CCM tamper test", aad, nonce, 16, true);
        ct.back() ^= 0x01;
        bool caught = false;
        try {
            (void)m.ccm_decrypt(ct, aad, std::nullopt, true, 13, 16);
        } catch (const std::runtime_error&) {
            caught = true;
        }
        check(caught, "SP 800-38C CCM Authentication Tag Tamper Rejection");
    }
    std::cout << "\n";
}

int main() {
    std::cout << "====================================================================\n";
    std::cout << " UIT NT219 Cryptography Lab - Task 2 Verification (Standards A & C)\n";
    std::cout << "====================================================================\n\n";

    test_lecturer_lab_namespace_api();
    test_sp800_38a_appendix_f();
    test_sp800_38c_appendix_c();

    std::cout << "Summary: " << g_passed << " passed, " << g_failed << " failed.\n";
    return (g_failed == 0) ? 0 : 1;
}
