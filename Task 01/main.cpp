// main.cpp - Main test program for UIT NT219 AES Lab Task 1.
// Build on Linux:
//   g++ -std=c++17 -O2 -Wall -Wextra -Wpedantic main.cpp -o aes_lab
// Run:
//   ./aes_lab
//
// modes.cpp includes AES.cpp itself. MODES_NO_MAIN disables the CLI/test main
// defined at the bottom of modes.cpp so this file can provide its own main().
#define MODES_NO_MAIN
#include "modes.cpp"

#include <exception>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

namespace {

using ByteVec = AES::ByteVec;

struct TestResult {
    int passed = 0;
    int failed = 0;

    void check(const std::string& label, bool condition) {
        std::cout << "  " << std::left << std::setw(9)
                  << (condition ? "PASS" : "FAIL") << " : " << label << '\n';
        if (condition) {
            ++passed;
        } else {
            ++failed;
        }
    }
};

// Print AES-128/192/256 test cases in the same layout as the class example.
void run_aes_known_answer_tests(TestResult& result) {
    const std::string plaintext_hex = "00112233445566778899aabbccddeeff";

    struct AesVector {
        int bits;
        const char* key;
        const char* ciphertext;
    };

    // FIPS 197 Appendix C known-answer vectors.
    const AesVector vectors[] = {
        {128,
         "000102030405060708090a0b0c0d0e0f",
         "69c4e0d86a7b0430d8cdb78070b4c55a"},
        {192,
         "000102030405060708090a0b0c0d0e0f1011121314151617",
         "dda97ca4864cdfe06eaf70a0ec0d7191"},
        {256,
         "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
         "8ea2b7ca516745bfeafc49904b496089"}
    };

    const ByteVec plaintext = AES::hex_to_bytes(plaintext_hex);

    std::cout << "UIT NT219 - AES KNOWN-ANSWER TESTS (NIST FIPS 197)\n\n";

    for (const auto& vector : vectors) {
        const ByteVec key = AES::hex_to_bytes(vector.key);
        const ByteVec expected = AES::hex_to_bytes(vector.ciphertext);
        AES aes(key, vector.bits);
        const ByteVec computed = aes.encrypt(plaintext);
        const ByteVec decrypted = aes.decrypt(computed);

        const bool encrypt_ok = (computed == expected);
        const bool decrypt_ok = (decrypted == plaintext);

        std::cout << "AES-" << vector.bits << " Known-Answer Test\n";
        std::cout << "  Key       : " << AES::bytes_to_hex(key) << '\n';
        std::cout << "  Plaintext : " << AES::bytes_to_hex(plaintext) << '\n';
        std::cout << "  Expected  : " << AES::bytes_to_hex(expected) << '\n';
        std::cout << "  Computed  : " << AES::bytes_to_hex(computed) << '\n';
        std::cout << "  Decrypted : " << AES::bytes_to_hex(decrypted) << '\n';
        result.check("Encrypt", encrypt_ok);
        result.check("Decrypt", decrypt_ok);
        std::cout << '\n';

    }
}

// Validate the five SP 800-38A confidentiality modes against the published
// AES-128 test vectors. Padding is disabled here because the NIST vectors use
// complete 16-byte blocks and specify the raw mode output.
void run_sp800_38a_mode_tests(TestResult& result) {
    const ByteVec key = AES::hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
    const ByteVec plaintext = AES::hex_to_bytes(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710");
    const ByteVec iv = AES::hex_to_bytes("000102030405060708090a0b0c0d0e0f");
    const ByteVec ctr_iv = AES::hex_to_bytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    const std::optional<ByteVec> iv_opt{iv};
    const std::optional<ByteVec> ctr_opt{ctr_iv};

    struct ModeVector {
        const char* name;
        const char* expected;
    };

    const ModeVector ecb_vector{
        "ECB",
        "3ad77bb40d7a3660a89ecaf32466ef97"
        "f5d3d58503b9699de785895a96fdbaaf"
        "43b1cd7f598ece23881b00e3ed030688"
        "7b0c785e27e8ad3f8223207104725dd4"};
    const ModeVector cbc_vector{
        "CBC",
        "7649abac8119b246cee98e9b12e9197d"
        "5086cb9b507219ee95db113a917678b2"
        "73bed6b8e3c1743b7116e69e22229516"
        "3ff1caa1681fac09120eca307586e1a7"};
    const ModeVector cfb_vector{
        "CFB-128",
        "3b3fd92eb72dad20333449f8e83cfb4a"
        "c8a64537a0b3a93fcde3cdad9f1ce58b"
        "26751f67a3cbb140b1808cf187a4f4df"
        "c04b05357c5d1c0eeac4c66f9ff7f2e6"};
    const ModeVector ofb_vector{
        "OFB",
        "3b3fd92eb72dad20333449f8e83cfb4a"
        "7789508d16918f03f53c52dac54ed825"
        "9740051e9c5fecf64344f7a82260edcc"
        "304c6528f659c77866a510d9c1d6ae5e"};
    const ModeVector ctr_vector{
        "CTR",
        "874d6191b620e3261bef6864990db6ce"
        "9806f66b7970fdff8617187bb9fffdff"
        "5ae4df3edbd5d35e5b4f09020db03eab"
        "1e031dda2fbe03d1792170a0f3009cee"};

    modes cipher(key, false); // verbose=false keeps the report concise.
    std::cout << "NIST SP 800-38A MODE TESTS (AES-128)\n";

    const ByteVec ecb = cipher.ecb_encrypt(plaintext, false);
    result.check("ECB vector", AES::bytes_to_hex(ecb) == ecb_vector.expected);
    result.check("ECB decrypt", cipher.ecb_decrypt_bytes(ecb, false) == plaintext);

    const ByteVec cbc = cipher.cbc_encrypt(plaintext, iv_opt, false, false);
    result.check("CBC vector", AES::bytes_to_hex(cbc) == cbc_vector.expected);
    result.check("CBC decrypt", cipher.cbc_decrypt_bytes(cbc, iv_opt, false, false) == plaintext);

    const ByteVec cfb = cipher.cfb_encrypt(plaintext, iv_opt, 128, false);
    result.check("CFB-128 vector", AES::bytes_to_hex(cfb) == cfb_vector.expected);
    result.check("CFB-128 decrypt", cipher.cfb_decrypt_bytes(cfb, iv_opt, false, 128) == plaintext);

    const ByteVec ofb = cipher.ofb_encrypt(plaintext, iv_opt, false);
    result.check("OFB vector", AES::bytes_to_hex(ofb) == ofb_vector.expected);
    result.check("OFB decrypt", cipher.ofb_decrypt_bytes(ofb, iv_opt, false) == plaintext);

    const ByteVec ctr = cipher.ctr_encrypt(plaintext, ctr_opt, false);
    result.check("CTR vector", AES::bytes_to_hex(ctr) == ctr_vector.expected);
    result.check("CTR decrypt", cipher.ctr_decrypt_bytes(ctr, ctr_opt, false) == plaintext);

    std::cout << '\n';
}

} // namespace

int main() {
    try {
        TestResult result;
        run_aes_known_answer_tests(result);
        run_sp800_38a_mode_tests(result);

        std::cout << "Test summary: " << result.passed << " passed, "
                  << result.failed << " failed\n";
        if (result.failed == 0) {
            std::cout << "All tests passed!\n";
            return 0;
        }
        std::cout << "Some tests failed.\n";
        return 1;
    } catch (const std::exception& ex) {
        std::cerr << "TEST ERROR: " << ex.what() << '\n';
        return 2;
    }
}
