// -*- coding: utf-8 -*-
/**
 * main.cpp - File code thứ 7: Chương trình kiểm thử chính (Known-Answer Tests & Block CLI)
 * Kiểm thử lõi AES (FIPS 197) và cả 5 bộ tiêu chuẩn Mode of Operation:
 *   - Tiêu chuẩn A: NIST SP 800-38A (ECB, CBC, CFB, OFB, CTR)  [sp800_38a.cpp]
 *   - Tiêu chuẩn C: NIST SP 800-38C (AES-CCM)                  [sp800_38c.cpp]
 *   - Tiêu chuẩn D: NIST SP 800-38D (AES-GCM & GMAC)           [sp800_38d.cpp]
 *   - Tiêu chuẩn E: NIST SP 800-38E (AES-XTS)                  [sp800_38e.cpp]
 *   - Tiêu chuẩn F: NIST SP 800-38F (AES-KW & AES-KWP)         [sp800_38f.cpp]
 *
 * Biên dịch toàn bộ 7 file code C++:
 *   g++ -std=c++17 -O2 main.cpp AES.cpp sp800_38a.cpp sp800_38c.cpp sp800_38d.cpp sp800_38e.cpp sp800_38f.cpp -o main
 */

#include "AES.h"
#include "modes.h"

#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

struct KatVector {
    std::string title;
    int key_bits;
    std::string key_hex;
    std::string plaintext_hex;
    std::string expected_hex;
};

// KHỐI 1: KIỂM THỬ KNOWN-ANSWER TEST CHO AES-128 / 192 / 256 

bool run_aes_known_answer_tests() {
    const std::vector<KatVector> vectors = {
        {
            "AES-128 Known-Answer Test",
            128,
            "000102030405060708090a0b0c0d0e0f",
            "00112233445566778899aabbccddeeff",
            "69c4e0d86a7b0430d8cdb78070b4c55a"
        },
        {
            "AES-192 Known-Answer Test",
            192,
            "000102030405060708090a0b0c0d0e0f1011121314151617",
            "00112233445566778899aabbccddeeff",
            "dda97ca4864cdfe06eaf70a0ec0d7191"
        },
        {
            "AES-256 Known-Answer Test",
            256,
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "00112233445566778899aabbccddeeff",
            "8ea2b7ca516745bfeafc49904b496089"
        }
    };

    bool all_passed = true;
    for (size_t i = 0; i < vectors.size(); ++i) {
        const auto& v = vectors[i];
        auto key_bytes = AES::hex_to_bytes(v.key_hex);
        auto pt_bytes  = AES::hex_to_bytes(v.plaintext_hex);

        AES cipher(key_bytes, v.key_bits);
        auto ct_bytes  = cipher.encrypt(pt_bytes);
        auto dec_bytes = cipher.decrypt(ct_bytes);

        std::string computed_hex  = AES::bytes_to_hex(ct_bytes);
        std::string decrypted_hex = AES::bytes_to_hex(dec_bytes);

        bool enc_pass = (computed_hex == v.expected_hex);
        bool dec_pass = (decrypted_hex == v.plaintext_hex);
        all_passed = all_passed && enc_pass && dec_pass;

        std::cout << v.title << "\n"
                  << "  Key       : " << v.key_hex << "\n"
                  << "  Plaintext : " << v.plaintext_hex << "\n"
                  << "  Expected  : " << v.expected_hex << "\n"
                  << "  Computed  : " << computed_hex << "\n"
                  << "  Decrypted : " << decrypted_hex << "\n"
                  << "  Encrypt   : " << (enc_pass ? "PASS" : "FAIL") << "\n"
                  << "  Decrypt   : " << (dec_pass ? "PASS" : "FAIL") << "\n";

        if (i + 1 < vectors.size()) {
            std::cout << "\n";
        }
    }
    return all_passed;
}

// KHỐI 2: KIỂM THỬ CẢ 5 BỘ TIÊU CHUẨN NIST SP 800-38 (A, C, D, E, F)

bool run_modes_tests(bool verbose_blocks = false) {
    bool all_passed = true;
    auto key_128 = modes::hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
    auto key_256 = modes::hex_to_bytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    auto iv_128  = modes::hex_to_bytes("000102030405060708090a0b0c0d0e0f");
    auto pt_nist = modes::hex_to_bytes("6bc1bee22e409f96e93d7e117393172a");

    modes m(key_128, verbose_blocks);

    struct ModeTest {
        std::string title;
        std::string expected_hex;
        modes::ByteVec computed;
        modes::ByteVec decrypted;
    };

    // 1. Tiêu chuẩn A (NIST SP 800-38A): ECB, CBC, CFB, OFB, CTR
    auto ecb_ct = m.ecb_encrypt(pt_nist, false);
    auto ecb_pt = m.ecb_decrypt_bytes(ecb_ct, false);

    auto cbc_ct = m.cbc_encrypt(pt_nist, iv_128, false, false);
    auto cbc_pt = m.cbc_decrypt_bytes(cbc_ct, iv_128, false, false);

    auto cfb_ct = m.cfb_encrypt(pt_nist, iv_128, 128, false);
    auto cfb_pt = m.cfb_decrypt_bytes(cfb_ct, iv_128, false, 128);

    auto ofb_ct = m.ofb_encrypt(pt_nist, iv_128, false);
    auto ofb_pt = m.ofb_decrypt_bytes(ofb_ct, iv_128, false);

    auto ctr_iv = modes::hex_to_bytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    auto ctr_ct = m.ctr_encrypt(pt_nist, ctr_iv, false);
    auto ctr_pt = m.ctr_decrypt_bytes(ctr_ct, ctr_iv, false);

    std::vector<ModeTest> tests = {
        {"[Standard A] AES-128-ECB Known-Answer Test (SP 800-38A)", "3ad77bb40d7a3660a89ecaf32466ef97", ecb_ct, ecb_pt},
        {"[Standard A] AES-128-CBC Known-Answer Test (SP 800-38A)", "7649abac8119b246cee98e9b12e9197d", cbc_ct, cbc_pt},
        {"[Standard A] AES-128-CFB128 Known-Answer Test (SP 800-38A)", "3b3fd92eb72dad20333449f8e83cfb4a", cfb_ct, cfb_pt},
        {"[Standard A] AES-128-OFB Known-Answer Test (SP 800-38A)", "3b3fd92eb72dad20333449f8e83cfb4a", ofb_ct, ofb_pt},
        {"[Standard A] AES-128-CTR Known-Answer Test (SP 800-38A)", "874d6191b620e3261bef6864990db6ce", ctr_ct, ctr_pt}
    };

    for (const auto& t : tests) {
        std::string comp_hex = modes::bytes_to_hex(t.computed);
        std::string dec_hex  = modes::bytes_to_hex(t.decrypted);
        std::string pt_hex   = modes::bytes_to_hex(pt_nist);
        bool enc_ok = (comp_hex == t.expected_hex);
        bool dec_ok = (dec_hex == pt_hex);
        all_passed = all_passed && enc_ok && dec_ok;

        std::cout << "\n" << t.title << "\n"
                  << "  Key       : " << modes::bytes_to_hex(key_128) << "\n"
                  << "  Plaintext : " << pt_hex << "\n"
                  << "  Expected  : " << t.expected_hex << "\n"
                  << "  Computed  : " << comp_hex << "\n"
                  << "  Decrypted : " << dec_hex << "\n"
                  << "  Encrypt   : " << (enc_ok ? "PASS" : "FAIL") << "\n"
                  << "  Decrypt   : " << (dec_ok ? "PASS" : "FAIL") << "\n";
    }

    // 2. Kiểm thử Tiêu chuẩn C (CCM), D (GCM/GMAC), E (XTS), F (KW/KWP)
    std::string msg = "Hello UIT Cryptography Lab NT219! Testing multi-block message.";
    auto nonce12 = modes::hex_to_bytes("000102030405060708090a0b");
    auto nonce13 = modes::hex_to_bytes("000102030405060708090a0b0c");
    auto aad     = modes::utf8_to_bytes("UIT-NT219-AAD");

    // Standard C: CCM (SP 800-38C)
    auto ccm_ct = m.ccm_encrypt(msg, aad, nonce13, 16);
    bool ccm_ok = (m.ccm_decrypt(ccm_ct, aad) == msg);

    // Standard D: GCM & GMAC (SP 800-38D)
    auto gcm_ct = m.gcm_encrypt(msg, aad, nonce12);
    bool gcm_ok = (m.gcm_decrypt(gcm_ct, aad) == msg) && m.gmac_verify(aad, m.gmac(aad, nonce12));

    // Standard E: XTS (SP 800-38E)
    auto xts_ct = m.xts_encrypt(msg, key_256, std::nullopt, 42);
    bool xts_ok = (modes::bytes_to_utf8(m.xts_decrypt_bytes(xts_ct, key_256, std::nullopt, 42)) == msg);

    // Standard F: Key Wrap KW & KWP (SP 800-38F)
    auto kw_ct  = m.key_wrap(key_256, false);
    bool kw_ok  = (m.key_unwrap(kw_ct, false) == key_256);
    auto kwp_ct = m.key_wrap("short_key_123", true);
    bool kwp_ok = (modes::bytes_to_utf8(m.key_unwrap(kwp_ct, true)) == "short_key_123");

    all_passed = all_passed && ccm_ok && gcm_ok && xts_ok && kw_ok && kwp_ok;

    std::cout << "\n[Standards C, D, E, F] Multi-Block & Specialized Standards Summary\n"
              << "  Standard C (SP 800-38C CCM)     : " << (ccm_ok ? "PASS" : "FAIL") << "\n"
              << "  Standard D (SP 800-38D GCM/GMAC): " << (gcm_ok ? "PASS" : "FAIL") << "\n"
              << "  Standard E (SP 800-38E XTS)     : " << (xts_ok ? "PASS" : "FAIL") << "\n"
              << "  Standard F (SP 800-38F KW/KWP)  : " << ((kw_ok && kwp_ok) ? "PASS" : "FAIL") << "\n";

    return all_passed;
}

int main(int argc, char* argv[]) {
    try {
        // Mặc định khi gõ ./main: in đúng 3 bài test AES-128 / 192 / 256 giống màn chiếu của thầy
        if (argc <= 1) {
            bool ok = run_aes_known_answer_tests();
            return ok ? 0 : 1;
        }

        std::string arg1 = argv[1];
        if (arg1 == "--all" || arg1 == "--modes") {
            bool verbose = (argc > 2 && std::string(argv[2]) == "--verbose");
            bool ok1 = run_aes_known_answer_tests();
            bool ok2 = run_modes_tests(verbose);
            return (ok1 && ok2) ? 0 : 1;
        }

        if (arg1 == "--trace") {
            auto key_128 = AES::hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
            auto pt_fips = AES::hex_to_bytes("3243f6a8885a308d313198a2e0370734");
            AES aes128(key_128, 128);
            auto ct = aes128.encrypt(pt_fips, true);
            (void)aes128.decrypt(ct, true);
            return 0;
        }

        // Giao diện dòng lệnh (CLI) cho phép chạy và quan sát từng Block (--verbose)
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
            std::cout << "Usage:\n"
                      << "  " << argv[0] << "                  (Run AES-128/192/256 Known-Answer Tests)\n"
                      << "  " << argv[0] << " --all [--verbose] (Run AES + Standards A, C, D, E, F Tests)\n"
                      << "  " << argv[0] << " --trace          (Run FIPS 197 round-by-round trace)\n"
                      << "  " << argv[0] << " --mode <ecb|cbc|cfb|ofb|ctr|ccm|gcm|xts|kw|kwp> "
                      << "--action <encrypt|decrypt> --key <hex> [--iv <hex>] [--input <text>|--input-hex <hex>] [--verbose]\n";
            return 0;
        }

        auto key_bytes = modes::hex_to_bytes(key_hex);
        modes cipher(key_bytes, verbose);
        auto data_bytes = input_is_hex ? modes::hex_to_bytes(input_str) : modes::utf8_to_bytes(input_str);
        std::optional<modes::ByteVec> iv_bytes = std::nullopt;
        if (iv_hex.has_value()) iv_bytes = modes::hex_to_bytes(iv_hex.value());
        std::optional<modes::ByteVec> aad_bytes = std::nullopt;
        if (aad_str.has_value()) aad_bytes = modes::utf8_to_bytes(aad_str.value());

        if (action == "encrypt") {
            modes::ByteVec out;
            if (mode_name == "ecb") out = cipher.ecb_encrypt(data_bytes);
            else if (mode_name == "cbc") out = cipher.cbc_encrypt(data_bytes, iv_bytes);
            else if (mode_name == "cfb") out = cipher.cfb_encrypt(data_bytes, iv_bytes, segment_size);
            else if (mode_name == "ofb") out = cipher.ofb_encrypt(data_bytes, iv_bytes);
            else if (mode_name == "ctr") out = cipher.ctr_encrypt(data_bytes, iv_bytes);
            else if (mode_name == "ccm") out = cipher.ccm_encrypt(data_bytes, aad_bytes, iv_bytes);
            else if (mode_name == "gcm") out = cipher.gcm_encrypt(data_bytes, aad_bytes, iv_bytes);
            else if (mode_name == "xts") out = cipher.xts_encrypt(data_bytes);
            else if (mode_name == "kw") out = cipher.key_wrap(data_bytes, false);
            else if (mode_name == "kwp") out = cipher.key_wrap(data_bytes, true);
            else throw std::invalid_argument("Unsupported mode: " + mode_name);
            std::cout << "Ciphertext (hex): " << modes::bytes_to_hex(out) << "\n";
        } else {
            modes::ByteVec out;
            bool has_iv = !iv_bytes.has_value();
            if (mode_name == "ecb") out = cipher.ecb_decrypt_bytes(data_bytes);
            else if (mode_name == "cbc") out = cipher.cbc_decrypt_bytes(data_bytes, iv_bytes, has_iv);
            else if (mode_name == "cfb") out = cipher.cfb_decrypt_bytes(data_bytes, iv_bytes, has_iv, segment_size);
            else if (mode_name == "ofb") out = cipher.ofb_decrypt_bytes(data_bytes, iv_bytes, has_iv);
            else if (mode_name == "ctr") out = cipher.ctr_decrypt_bytes(data_bytes, iv_bytes, has_iv);
            else if (mode_name == "ccm") out = cipher.ccm_decrypt_bytes(data_bytes, aad_bytes, iv_bytes, has_iv);
            else if (mode_name == "gcm") out = cipher.gcm_decrypt_bytes(data_bytes, aad_bytes, iv_bytes, has_iv);
            else if (mode_name == "xts") out = cipher.xts_decrypt_bytes(data_bytes);
            else if (mode_name == "kw") out = cipher.key_unwrap(data_bytes, false);
            else if (mode_name == "kwp") out = cipher.key_unwrap(data_bytes, true);
            else throw std::invalid_argument("Unsupported mode: " + mode_name);
            std::cout << "Plaintext (hex) : " << modes::bytes_to_hex(out) << "\n";
            std::cout << "Plaintext (utf8): " << modes::bytes_to_utf8(out) << "\n";
        }
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }
}
