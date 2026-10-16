// -*- coding: utf-8 -*-
/**
 * main.cpp - C++ CLI and Known-Answer Test Runner for AES & NIST SP 800-38A / SP 800-38C.
 * UIT NT219 Cryptography Lab - Task 2.
 */

#include "AES.h"
#include "modes.h"

#include <iostream>
#include <optional>
#include <string>
#include <vector>

bool run_aes_known_answer_tests() {
    struct Kat {
        std::string title;
        std::string key_hex;
        std::string pt_hex;
        std::string expected_hex;
        int key_bits;
    };
    const std::vector<Kat> vectors = {
        {
            "AES-128 Known-Answer Test",
            "000102030405060708090a0b0c0d0e0f",
            "00112233445566778899aabbccddeeff",
            "69c4e0d86a7b0430d8cdb78070b4c55a",
            128
        },
        {
            "AES-192 Known-Answer Test",
            "000102030405060708090a0b0c0d0e0f1011121314151617",
            "00112233445566778899aabbccddeeff",
            "dda97ca4864cdfe06eaf70a0ec0d7191",
            192
        },
        {
            "AES-256 Known-Answer Test",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "00112233445566778899aabbccddeeff",
            "8ea2b7ca516745bfeafc49904b496089",
            256
        }
    };

    bool all_ok = true;
    for (const auto& v : vectors) {
        auto key = AES::hex_to_bytes(v.key_hex);
        auto pt = AES::hex_to_bytes(v.pt_hex);
        AES cipher(key, v.key_bits);
        auto ct = cipher.encrypt(pt);
        auto dec = cipher.decrypt(ct);
        std::string ct_hex = AES::bytes_to_hex(ct);
        std::string dec_hex = AES::bytes_to_hex(dec);
        bool enc_ok = (ct_hex == v.expected_hex);
        bool dec_ok = (dec_hex == v.pt_hex);
        all_ok = all_ok && enc_ok && dec_ok;

        std::cout << v.title << "\n"
                  << "  Key       : " << v.key_hex << "\n"
                  << "  Plaintext : " << v.pt_hex << "\n"
                  << "  Expected  : " << v.expected_hex << "\n"
                  << "  Computed  : " << ct_hex << "\n"
                  << "  Decrypted : " << dec_hex << "\n"
                  << "  Encrypt   : " << (enc_ok ? "PASS" : "FAIL") << "\n"
                  << "  Decrypt   : " << (dec_ok ? "PASS" : "FAIL") << "\n\n";
    }
    return all_ok;
}

bool run_modes_tests(bool verbose) {
    bool all_ok = true;
    auto key = modes::hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
    auto iv = modes::hex_to_bytes("000102030405060708090a0b0c0d0e0f");
    auto ctr_iv = modes::hex_to_bytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    auto pt = modes::hex_to_bytes("6bc1bee22e409f96e93d7e117393172a");

    modes m(key, verbose);

    struct ModeKat {
        std::string title;
        modes::ByteVec computed;
        modes::ByteVec decrypted;
        std::string expected_hex;
    };

    auto ecb_ct = m.ecb_encrypt(pt, false);
    auto ecb_dec = m.ecb_decrypt_bytes(ecb_ct, false);

    auto cbc_ct = m.cbc_encrypt(pt, iv, false, false);
    auto cbc_dec = m.cbc_decrypt_bytes(cbc_ct, iv, false, false);

    auto cfb_ct = m.cfb_encrypt(pt, iv, 128, false);
    auto cfb_dec = m.cfb_decrypt_bytes(cfb_ct, iv, false, 128);

    auto ofb_ct = m.ofb_encrypt(pt, iv, false);
    auto ofb_dec = m.ofb_decrypt_bytes(ofb_ct, iv, false);

    auto ctr_ct = m.ctr_encrypt(pt, ctr_iv, false);
    auto ctr_dec = m.ctr_decrypt_bytes(ctr_ct, ctr_iv, false);

    std::vector<ModeKat> sp800_38a_kats = {
        {"[Standard A] AES-128-ECB Known-Answer Test (SP 800-38A)", ecb_ct, ecb_dec, "3ad77bb40d7a3660a89ecaf32466ef97"},
        {"[Standard A] AES-128-CBC Known-Answer Test (SP 800-38A)", cbc_ct, cbc_dec, "7649abac8119b246cee98e9b12e9197d"},
        {"[Standard A] AES-128-CFB128 Known-Answer Test (SP 800-38A)", cfb_ct, cfb_dec, "3b3fd92eb72dad20333449f8e83cfb4a"},
        {"[Standard A] AES-128-OFB Known-Answer Test (SP 800-38A)", ofb_ct, ofb_dec, "3b3fd92eb72dad20333449f8e83cfb4a"},
        {"[Standard A] AES-128-CTR Known-Answer Test (SP 800-38A)", ctr_ct, ctr_dec, "874d6191b620e3261bef6864990db6ce"}
    };

    for (const auto& t : sp800_38a_kats) {
        std::string comp_hex = modes::bytes_to_hex(t.computed);
        std::string dec_hex = modes::bytes_to_hex(t.decrypted);
        bool enc_ok = (comp_hex == t.expected_hex);
        bool dec_ok = (t.decrypted == pt);
        all_ok = all_ok && enc_ok && dec_ok;

        std::cout << t.title << "\n"
                  << "  Key       : " << modes::bytes_to_hex(key) << "\n"
                  << "  Plaintext : " << modes::bytes_to_hex(pt) << "\n"
                  << "  Expected  : " << t.expected_hex << "\n"
                  << "  Computed  : " << comp_hex << "\n"
                  << "  Decrypted : " << dec_hex << "\n"
                  << "  Encrypt   : " << (enc_ok ? "PASS" : "FAIL") << "\n"
                  << "  Decrypt   : " << (dec_ok ? "PASS" : "FAIL") << "\n\n";
    }

    // Standard C: NIST SP 800-38C Appendix C Example 1 Known-Answer Test
    auto ccm_key = modes::hex_to_bytes("404142434445464748494a4b4c4d4e4f");
    auto ccm_nonce = modes::hex_to_bytes("10111213141516");
    auto ccm_aad = modes::hex_to_bytes("0001020304050607");
    auto ccm_pt = modes::hex_to_bytes("20212223");
    std::string ccm_expected_hex = "7162015b4dac255d";

    modes m_ccm(ccm_key, verbose);
    auto ccm_ct = m_ccm.ccm_encrypt(ccm_pt, ccm_aad, ccm_nonce, 4, false);
    auto ccm_dec = m_ccm.ccm_decrypt_bytes(ccm_ct, ccm_aad, ccm_nonce, false, 7, 4);
    bool ccm_kat_enc_ok = (modes::bytes_to_hex(ccm_ct) == ccm_expected_hex);
    bool ccm_kat_dec_ok = (ccm_dec == ccm_pt);
    all_ok = all_ok && ccm_kat_enc_ok && ccm_kat_dec_ok;

    std::cout << "[Standard C] AES-128-CCM Known-Answer Test (SP 800-38C Appendix C Ex.1)\n"
              << "  Key       : " << modes::bytes_to_hex(ccm_key) << "\n"
              << "  Nonce     : " << modes::bytes_to_hex(ccm_nonce) << "\n"
              << "  AAD       : " << modes::bytes_to_hex(ccm_aad) << "\n"
              << "  Plaintext : " << modes::bytes_to_hex(ccm_pt) << "\n"
              << "  Expected  : " << ccm_expected_hex << "\n"
              << "  Computed  : " << modes::bytes_to_hex(ccm_ct) << "\n"
              << "  Decrypted : " << modes::bytes_to_hex(ccm_dec) << "\n"
              << "  Encrypt   : " << (ccm_kat_enc_ok ? "PASS" : "FAIL") << "\n"
              << "  Decrypt   : " << (ccm_kat_dec_ok ? "PASS" : "FAIL") << "\n\n";

    // Multi-block & Specialized Standards Summary
    std::string msg = "Hello UIT Cryptography Lab NT219! Testing multi-block message.";
    auto aad = modes::utf8_to_bytes("UIT-NT219-AAD");
    auto nonce12 = modes::hex_to_bytes("000102030405060708090a0b");
    auto nonce13 = modes::hex_to_bytes("000102030405060708090a0b0c");

    auto ccm_mb = m.ccm_encrypt(msg, aad, nonce13, 16, true);
    bool ccm_ok = (m.ccm_decrypt(ccm_mb, aad, std::nullopt, true, 13, 16) == msg);

    auto gcm_mb = m.gcm_encrypt(msg, aad, nonce12, true);
    bool gcm_ok = (m.gcm_decrypt(gcm_mb, aad, std::nullopt, true) == msg);

    auto xts_mb = m.xts_encrypt(msg);
    bool xts_ok = (modes::bytes_to_utf8(m.xts_decrypt_bytes(xts_mb)) == msg);

    auto kw_wrapped = m.key_wrap(key, false);
    auto kwp_wrapped = m.key_wrap(modes::utf8_to_bytes("short_key_123"), true);
    bool kw_ok = (m.key_unwrap(kw_wrapped, false) == key) &&
                 (modes::bytes_to_utf8(m.key_unwrap(kwp_wrapped, true)) == "short_key_123");

    std::cout << "[Standards C, D, E, F] Multi-Block & Specialized Standards Summary\n"
              << "  Standard C (SP 800-38C CCM)     : " << (ccm_ok ? "PASS" : "FAIL") << "\n"
              << "  Standard D (SP 800-38D GCM/GMAC): " << (gcm_ok ? "PASS" : "FAIL") << "\n"
              << "  Standard E (SP 800-38E XTS)     : " << (xts_ok ? "PASS" : "FAIL") << "\n"
              << "  Standard F (SP 800-38F KW/KWP)  : " << (kw_ok ? "PASS" : "FAIL") << "\n";

    return all_ok && ccm_ok && gcm_ok && xts_ok && kw_ok;
}

static void print_usage(const char* prog) {
    std::cout << "Usage:\n"
              << "  " << prog << "                  (Run AES-128/192/256 Known-Answer Tests)\n"
              << "  " << prog << " --all [--verbose] (Run AES + Standards A, C, D, E, F Tests)\n"
              << "  " << prog << " --trace          (Run FIPS 197 round-by-round trace)\n"
              << "  " << prog << " --mode <ecb|cbc|cfb|ofb|ctr|ccm|gcm|xts|kw|kwp> "
              << "--action <encrypt|decrypt> --key <hex> [--iv <hex>] [--aad <hex>] "
              << "[--input <text>|--input-hex <hex>] [--verbose]\n";
}

int main(int argc, char* argv[]) {
    try {
        if (argc <= 1) {
            return run_aes_known_answer_tests() ? 0 : 1;
        }
        std::string arg1 = argv[1];
        if (arg1 == "--help" || arg1 == "-h") {
            print_usage(argv[0]);
            return 0;
        }
        if (arg1 == "--all" || arg1 == "--modes") {
            bool verbose = (argc > 2 && std::string(argv[2]) == "--verbose");
            bool ok1 = run_aes_known_answer_tests();
            bool ok2 = run_modes_tests(verbose);
            return (ok1 && ok2) ? 0 : 1;
        }
        if (arg1 == "--trace") {
            AES cipher(AES::hex_to_bytes("000102030405060708090a0b0c0d0e0f"), 128);
            auto pt = AES::hex_to_bytes("00112233445566778899aabbccddeeff");
            auto ct = cipher.encrypt(pt, true);
            std::cout << "\n";
            cipher.decrypt(ct, true);
            return 0;
        }

        std::string mode_name = "cbc";
        std::string action = "encrypt";
        std::string key_hex;
        std::string iv_hex;
        std::string aad_hex;
        std::string input_str;
        bool input_is_hex = false;
        int segment_size = 128;
        bool verbose = true;

        for (int i = 1; i < argc; ++i) {
            std::string a = argv[i];
            if (a == "--mode" && i + 1 < argc) mode_name = argv[++i];
            else if (a == "--action" && i + 1 < argc) action = argv[++i];
            else if (a == "--key" && i + 1 < argc) key_hex = argv[++i];
            else if (a == "--iv" && i + 1 < argc) iv_hex = argv[++i];
            else if (a == "--aad" && i + 1 < argc) aad_hex = argv[++i];
            else if (a == "--segment-size" && i + 1 < argc) segment_size = std::stoi(argv[++i]);
            else if (a == "--input" && i + 1 < argc) { input_str = argv[++i]; input_is_hex = false; }
            else if (a == "--input-hex" && i + 1 < argc) { input_str = argv[++i]; input_is_hex = true; }
            else if (a == "--verbose") verbose = true;
            else if (a == "--quiet") verbose = false;
        }

        if (key_hex.empty()) {
            print_usage(argv[0]);
            return 1;
        }

        modes m(modes::hex_to_bytes(key_hex), verbose);
        modes::ByteVec data = input_is_hex ? modes::hex_to_bytes(input_str) : modes::utf8_to_bytes(input_str);
        std::optional<modes::ByteVec> opt_iv = iv_hex.empty() ? std::nullopt : std::make_optional(modes::hex_to_bytes(iv_hex));
        std::optional<modes::ByteVec> opt_aad = aad_hex.empty() ? std::nullopt : std::make_optional(modes::hex_to_bytes(aad_hex));

        if (action == "encrypt") {
            modes::ByteVec out;
            if (mode_name == "ecb") out = m.ecb_encrypt(data, true);
            else if (mode_name == "cbc") out = m.cbc_encrypt(data, opt_iv, true, true);
            else if (mode_name == "cfb") out = m.cfb_encrypt(data, opt_iv, segment_size, true);
            else if (mode_name == "ofb") out = m.ofb_encrypt(data, opt_iv, true);
            else if (mode_name == "ctr") out = m.ctr_encrypt(data, opt_iv, true);
            else if (mode_name == "ccm") out = m.ccm_encrypt(data, opt_aad, opt_iv, 16, true);
            else if (mode_name == "gcm") out = m.gcm_encrypt(data, opt_aad, opt_iv, true);
            else if (mode_name == "xts") out = m.xts_encrypt(data);
            else if (mode_name == "kw") out = m.key_wrap(data, false);
            else if (mode_name == "kwp") out = m.key_wrap(data, true);
            else throw std::invalid_argument("Unsupported mode: " + mode_name);
            std::cout << "Ciphertext (hex): " << modes::bytes_to_hex(out) << "\n";
        } else {
            modes::ByteVec out;
            bool has_iv = !opt_iv.has_value();
            if (mode_name == "ecb") out = m.ecb_decrypt_bytes(data, true);
            else if (mode_name == "cbc") out = m.cbc_decrypt_bytes(data, opt_iv, has_iv, true);
            else if (mode_name == "cfb") out = m.cfb_decrypt_bytes(data, opt_iv, has_iv, segment_size);
            else if (mode_name == "ofb") out = m.ofb_decrypt_bytes(data, opt_iv, has_iv);
            else if (mode_name == "ctr") out = m.ctr_decrypt_bytes(data, opt_iv, has_iv);
            else if (mode_name == "ccm") out = m.ccm_decrypt_bytes(data, opt_aad, opt_iv, has_iv, opt_iv ? opt_iv->size() : 13, 16);
            else if (mode_name == "gcm") out = m.gcm_decrypt_bytes(data, opt_aad, opt_iv, has_iv);
            else if (mode_name == "xts") out = m.xts_decrypt_bytes(data);
            else if (mode_name == "kw") out = m.key_unwrap(data, false);
            else if (mode_name == "kwp") out = m.key_unwrap(data, true);
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