// -*- coding: utf-8 -*-
/**
 * main.cpp - Chương trình kiểm thử chính cho toàn bộ các Task (Task 1, 2, 3, 4 & Task Bonus)
 *   - Kiểm thử lõi AES (NIST FIPS 197): AES-128, AES-192, AES-256 Known-Answer Tests
 *   - Kiểm thử 5 bộ tiêu chuẩn Mode of Operation (NIST SP 800-38A, C, D, E, F; loại bỏ B)
 *   - Kiểm thử Task Bonus: Dynamic S-Box chống tấn công Side-Channel / Timing Attack
 *     theo bài báo "Countering AES Static S-Box Attack" (Rahnama et al., ACM SIN '13,
 *     DOI: 10.1145/2523514.2523544).
 *
 * Cách chạy:
 *   ./main           -> Chạy AES-128/192/256 Known-Answer Tests (giống màn chiếu của thầy)
 *   ./main --bonus   -> Chạy riêng Task Bonus: Phân tích từng vòng Dynamic S-Box, KAT & Benchmark
 *   ./main --all     -> Chạy toàn bộ (AES KAT + 5 bộ tiêu chuẩn NIST + Task Bonus Dynamic S-Box)
 */

#include "AES.h"
#include "modes.h"

#include <chrono>
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

// 
// KHỐI 1: KIỂM THỬ KNOWN-ANSWER TEST CHO AES-128 / 192 / 256 (GIỐNG MẪU CỦA THẦY)
// 
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

        AES cipher(key_bytes, v.key_bits, AES::SBoxMode::Standard);
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

// 
// KHỐI 2: KIỂM THỬ CẢ 5 BỘ TIÊU CHUẨN NIST SP 800-38 (A, C, D, E, F - LOẠI BỎ B)
// 
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

    std::string msg = "Hello UIT Cryptography Lab NT219! Testing multi-block message.";
    auto nonce12 = modes::hex_to_bytes("000102030405060708090a0b");
    auto nonce13 = modes::hex_to_bytes("000102030405060708090a0b0c");
    auto aad     = modes::utf8_to_bytes("UIT-NT219-AAD");

    auto ccm_ct = m.ccm_encrypt(msg, aad, nonce13, 16);
    bool ccm_ok = (m.ccm_decrypt(ccm_ct, aad) == msg);

    auto gcm_ct = m.gcm_encrypt(msg, aad, nonce12);
    bool gcm_ok = (m.gcm_decrypt(gcm_ct, aad) == msg) && m.gmac_verify(aad, m.gmac(aad, nonce12));

    auto xts_ct = m.xts_encrypt(msg, key_256, std::nullopt, 42);
    bool xts_ok = (modes::bytes_to_utf8(m.xts_decrypt_bytes(xts_ct, key_256, std::nullopt, 42)) == msg);

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

// 
// KHỐI 3: TASK BONUS - DYNAMIC S-BOX (RAHNAMA ET AL., ACM SIN '13, DOI: 10.1145/2523514.2523544)
// 
bool run_dynamic_sbox_bonus_tests() {
    std::cout << "\n\n"
              << "  TASK BONUS: COUNTERING AES STATIC S-BOX ATTACK (DYNAMIC S-BOX)\n"
              << "  Paper: Behnam Rahnama, Yunus Kiran, Raz Dara (ACM SIN '13)\n"
              << "  DOI  : 10.1145/2523514.2523544\n"
              << "\n\n";

    bool all_passed = true;

    // 1. In bảng phân tích chi tiết DBoxGen và BuildLCS qua 10 vòng của AES-128
    auto key128 = AES::hex_to_bytes("000102030405060708090a0b0c0d0e0f");
    AES aes128_dyn(key128, 128, AES::SBoxMode::Dynamic);

    std::cout << "1. Round-by-Round Dynamic S-Box Generation (AES-128, Key = 000102...0e0f):\n";
    for (int round = 1; round <= 10; ++round) {
        std::array<AES::Byte, 256> dbox{};
        std::array<AES::Byte, 256> idbox{};
        AES::Byte add_byte = 0;
        std::array<AES::Byte, 16> shifted_subkey{};
        aes128_dyn.DBoxGen(round, dbox, idbox, &add_byte, &shifted_subkey);

        // Kiểm tra tính song ánh (Bijection): iDbox[Dbox[x]] == x với mọi x thuộc [0..255]
        bool bijective = true;
        for (int x = 0; x < 256; ++x) {
            if (idbox[dbox[static_cast<size_t>(x)]] != static_cast<AES::Byte>(x)) {
                bijective = false;
                break;
            }
        }
        all_passed = all_passed && bijective;

        AES::ByteVec shifted_vec(shifted_subkey.begin(), shifted_subkey.end());
        AES::ByteVec dbox_sample(dbox.begin(), dbox.begin() + 4);

        std::cout << "  Round " << std::setw(2) << round
                  << " | MirroredKey[w" << std::setw(2) << (10 - round) * 4 << "..w" << std::setw(2) << (10 - round) * 4 + 3 << "]"
                  << " -> LCS(" << std::setw(2) << round << "): " << AES::bytes_to_hex(shifted_vec)
                  << " | AddByte: 0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(add_byte) << std::dec << std::setfill(' ')
                  << " | Dbox[0..3]: " << AES::bytes_to_hex(dbox_sample)
                  << " | Bijection: " << (bijective ? "PASS" : "FAIL") << "\n";
    }

    // 2. Kiểm thử Mã hóa / Giải mã với Dynamic S-Box cho AES-128, AES-192, AES-256
    std::cout << "\n2. Dynamic S-Box Encryption & Decryption Tests (AES-128 / 192 / 256):\n";
    const std::vector<KatVector> vectors = {
        {
            "AES-128 Dynamic S-Box Test",
            128,
            "000102030405060708090a0b0c0d0e0f",
            "00112233445566778899aabbccddeeff",
            "69c4e0d86a7b0430d8cdb78070b4c55a"
        },
        {
            "AES-192 Dynamic S-Box Test",
            192,
            "000102030405060708090a0b0c0d0e0f1011121314151617",
            "00112233445566778899aabbccddeeff",
            "dda97ca4864cdfe06eaf70a0ec0d7191"
        },
        {
            "AES-256 Dynamic S-Box Test",
            256,
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "00112233445566778899aabbccddeeff",
            "8ea2b7ca516745bfeafc49904b496089"
        }
    };

    for (size_t i = 0; i < vectors.size(); ++i) {
        const auto& v = vectors[i];
        auto key_bytes = AES::hex_to_bytes(v.key_hex);
        auto pt_bytes  = AES::hex_to_bytes(v.plaintext_hex);

        AES dyn_cipher(key_bytes, v.key_bits, AES::SBoxMode::Dynamic);
        auto dyn_ct  = dyn_cipher.encrypt(pt_bytes);
        auto dyn_dec = dyn_cipher.decrypt(dyn_ct);

        std::string dyn_ct_hex  = AES::bytes_to_hex(dyn_ct);
        std::string dyn_dec_hex = AES::bytes_to_hex(dyn_dec);

        // Bản mã Dynamic S-Box phải khác bản mã Static S-Box và giải mã khôi phục đúng 100% Plaintext
        bool diff_from_static = (dyn_ct_hex != v.expected_hex);
        bool dec_pass = (dyn_dec_hex == v.plaintext_hex);
        all_passed = all_passed && diff_from_static && dec_pass;

        std::cout << v.title << "\n"
                  << "  Key       : " << v.key_hex << "\n"
                  << "  Plaintext : " << v.plaintext_hex << "\n"
                  << "  Static CT : " << v.expected_hex << "\n"
                  << "  Dynamic CT: " << dyn_ct_hex << "\n"
                  << "  Decrypted : " << dyn_dec_hex << "\n"
                  << "  Dynamic!=Static : " << (diff_from_static ? "PASS" : "FAIL") << "\n"
                  << "  Decrypt   : " << (dec_pass ? "PASS" : "FAIL") << "\n";
        if (i + 1 < vectors.size()) {
            std::cout << "\n";
        }
    }

    // 3. Kiểm thử kết hợp Dynamic S-Box với các Mode of Operation (CBC, CTR, CCM, GCM)
    auto iv_128  = modes::hex_to_bytes("000102030405060708090a0b0c0d0e0f");
    auto nonce12 = modes::hex_to_bytes("000102030405060708090a0b");
    auto nonce13 = modes::hex_to_bytes("000102030405060708090a0b0c");
    auto aad     = modes::utf8_to_bytes("UIT-NT219-BONUS-AAD");
    std::string msg = "Dynamic S-Box protects AES against cache-timing & static S-Box analysis!";

    modes m_dyn(key128, false, AES::SBoxMode::Dynamic);
    bool dyn_cbc_ok = (m_dyn.cbc_decrypt(m_dyn.cbc_encrypt(msg, iv_128)) == msg);
    bool dyn_ctr_ok = (m_dyn.ctr_decrypt(m_dyn.ctr_encrypt(msg, iv_128)) == msg);
    bool dyn_ccm_ok = (m_dyn.ccm_decrypt(m_dyn.ccm_encrypt(msg, aad, nonce13, 16), aad) == msg);
    bool dyn_gcm_ok = (m_dyn.gcm_decrypt(m_dyn.gcm_encrypt(msg, aad, nonce12), aad) == msg);
    all_passed = all_passed && dyn_cbc_ok && dyn_ctr_ok && dyn_ccm_ok && dyn_gcm_ok;

    std::cout << "\n3. Dynamic S-Box with Modes of Operation (CBC / CTR / CCM / GCM):\n"
              << "  Dynamic AES-CBC : " << (dyn_cbc_ok ? "PASS" : "FAIL") << "\n"
              << "  Dynamic AES-CTR : " << (dyn_ctr_ok ? "PASS" : "FAIL") << "\n"
              << "  Dynamic AES-CCM : " << (dyn_ccm_ok ? "PASS" : "FAIL") << "\n"
              << "  Dynamic AES-GCM : " << (dyn_gcm_ok ? "PASS" : "FAIL") << "\n";

    // 4. Đo hiệu năng (Overhead Evaluation theo Abstract bài báo)
    constexpr int BENCH_ITERS = 2000;
    auto pt_bench = AES::hex_to_bytes("00112233445566778899aabbccddeeff");
    AES aes_std(key128, 128, AES::SBoxMode::Standard);
    AES aes_dyn(key128, 128, AES::SBoxMode::Dynamic);

    auto t0 = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < BENCH_ITERS; ++i) {
        pt_bench = aes_std.encrypt(pt_bench);
    }
    auto t1 = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < BENCH_ITERS; ++i) {
        pt_bench = aes_dyn.encrypt(pt_bench);
    }
    auto t2 = std::chrono::high_resolution_clock::now();

    double std_us = std::chrono::duration<double, std::micro>(t1 - t0).count() / BENCH_ITERS;
    double dyn_us = std::chrono::duration<double, std::micro>(t2 - t1).count() / BENCH_ITERS;
    std::cout << "\n4. Performance Benchmark (" << BENCH_ITERS << " blocks):\n"
              << "  Standard Static S-Box Avg Time : " << std::fixed << std::setprecision(2) << std_us << " us/block\n"
              << "  Dynamic S-Box Avg Time         : " << std::fixed << std::setprecision(2) << dyn_us << " us/block\n";

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
        if (arg1 == "--bonus" || arg1 == "--dynamic") {
            bool ok = run_dynamic_sbox_bonus_tests();
            return ok ? 0 : 1;
        }

        if (arg1 == "--all" || arg1 == "--modes") {
            bool verbose = (argc > 2 && std::string(argv[2]) == "--verbose");
            bool ok1 = run_aes_known_answer_tests();
            bool ok2 = run_modes_tests(verbose);
            bool ok3 = run_dynamic_sbox_bonus_tests();
            return (ok1 && ok2 && ok3) ? 0 : 1;
        }

        if (arg1 == "--trace") {
            auto key_128 = AES::hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
            auto pt_fips = AES::hex_to_bytes("3243f6a8885a308d313198a2e0370734");
            bool use_dyn = (argc > 2 && std::string(argv[2]) == "--dynamic");
            AES aes128(key_128, 128, use_dyn ? AES::SBoxMode::Dynamic : AES::SBoxMode::Standard);
            auto ct = aes128.encrypt(pt_fips, true);
            (void)aes128.decrypt(ct, true);
            return 0;
        }

        // Giao diện dòng lệnh (CLI)
        std::string mode_name = "cbc";
        std::string action = "encrypt";
        std::string key_hex;
        std::optional<std::string> iv_hex;
        std::optional<std::string> aad_str;
        std::string input_str;
        bool input_is_hex = false;
        bool verbose = true;
        bool dynamic_sbox = false;
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
            else if (arg == "--sbox-dynamic") dynamic_sbox = true;
            else if (arg == "--verbose") verbose = true;
            else if (arg == "--quiet") verbose = false;
        }

        if (key_hex.empty()) {
            std::cout << "Usage:\n"
                      << "  " << argv[0] << "                  (Run AES-128/192/256 Known-Answer Tests)\n"
                      << "  " << argv[0] << " --bonus          (Run Bonus Task: Dynamic S-Box SIN '13)\n"
                      << "  " << argv[0] << " --all [--verbose] (Run AES + Standards A, C, D, E, F + Bonus)\n"
                      << "  " << argv[0] << " --trace [--dynamic] (Run round-by-round trace)\n"
                      << "  " << argv[0] << " --mode <ecb|cbc|cfb|ofb|ctr|ccm|gcm|xts|kw|kwp> "
                      << "--action <encrypt|decrypt> --key <hex> [--iv <hex>] [--input <text>|--input-hex <hex>] [--sbox-dynamic] [--verbose]\n";
            return 0;
        }

        auto key_bytes = modes::hex_to_bytes(key_hex);
        modes cipher(key_bytes, verbose, dynamic_sbox ? AES::SBoxMode::Dynamic : AES::SBoxMode::Standard);
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
