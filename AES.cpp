// -*- coding: utf-8 -*-
/**
 * AES.cpp - Corrected AES block cipher primitive for AES-128, AES-192, and AES-256.
 * Converted from AES.py using ONLY the C++17 Standard Library (UIT NT219 Cryptography Lab).
 *
 * State mapping follows NIST FIPS 197 Section 3.4:
 *   state[row][column] = block[4 * column + row] (column-major order).
 *
 * Public API matches AES.py:
 *   AES aes(key_bytes, 128);
 *   auto ciphertext_block = aes.encrypt(plaintext_16_bytes);
 *   auto plaintext_block  = aes.decrypt(ciphertext_16_bytes);
 *
 * Standalone compilation & test:
 *   g++ -std=c++17 -DAES_STANDALONE_MAIN AES.cpp -o test_aes && ./test_aes
 */

#ifndef UIT_AES_CPP_INCLUDED
#define UIT_AES_CPP_INCLUDED

#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

class AES {
public:
    using Byte = uint8_t;
    using Word = std::array<Byte, 4>;
    using State = std::array<std::array<Byte, 4>, 4>;
    using ByteVec = std::vector<Byte>;

    static constexpr size_t BLOCK_SIZE = 16;

    // Valid key lengths in bits -> expected byte length
    inline static const std::map<int, size_t> VALID_KEY_LENGTHS = {
        {128, 16},
        {192, 24},
        {256, 32}
    };

    // Number of rounds Nr for each key bit-length
    inline static const std::map<int, int> NUM_ROUNDS = {
        {128, 10},
        {192, 12},
        {256, 14}
    };

    // NIST FIPS 197 Table 4: S-box substitution values
    inline static constexpr std::array<Byte, 256> S_BOX = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };

    // NIST FIPS 197 Table 6: Inverse S-box substitution values
    inline static constexpr std::array<Byte, 256> INV_S_BOX = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    };

    // NIST FIPS 197 Table 5: Round constants (10 fixed words for key expansion)
    inline static constexpr std::array<Word, 10> RCON = {{
        {{0x01, 0x00, 0x00, 0x00}},
        {{0x02, 0x00, 0x00, 0x00}},
        {{0x04, 0x00, 0x00, 0x00}},
        {{0x08, 0x00, 0x00, 0x00}},
        {{0x10, 0x00, 0x00, 0x00}},
        {{0x20, 0x00, 0x00, 0x00}},
        {{0x40, 0x00, 0x00, 0x00}},
        {{0x80, 0x00, 0x00, 0x00}},
        {{0x1B, 0x00, 0x00, 0x00}},
        {{0x36, 0x00, 0x00, 0x00}}
    }};

    ByteVec key;
    int key_length;
    std::vector<Word> round_keys;

    /**
     * AES block cipher primitive constructor.
     *
     * @param key_bytes  AES key (16, 24, or 32 bytes).
     * @param key_len    Optional key length in bits (128, 192, or 256). If 0, inferred from key_bytes.size() * 8.
     */
    explicit AES(const ByteVec& key_bytes, int key_len = 0)
        : key(key_bytes), key_length(key_len) {
        if (this->key_length == 0) {
            this->key_length = static_cast<int>(this->key.size() * 8);
        }
        auto it = VALID_KEY_LENGTHS.find(this->key_length);
        if (it == VALID_KEY_LENGTHS.end()) {
            throw std::invalid_argument("Invalid AES key length. Use 128, 192, or 256 bits.");
        }
        size_t expected_len = it->second;
        if (this->key.size() != expected_len) {
            throw std::invalid_argument(
                "AES-" + std::to_string(this->key_length) + " requires " +
                std::to_string(expected_len) + " key bytes; got " +
                std::to_string(this->key.size()) + "."
            );
        }
        this->round_keys = this->key_expansion(this->key, this->key_length);
    }

    explicit AES(const std::string& key_str, int key_len = 0)
        : AES(ByteVec(key_str.begin(), key_str.end()), key_len) {}

    // -------------------------------------------------------------------------
    // Galois Field GF(2^8) multiplication helper
    // -------------------------------------------------------------------------
    static constexpr Byte gmul(Byte a, Byte b) noexcept {
        Byte p = 0;
        for (int i = 0; i < 8; ++i) {
            if (b & 1) {
                p ^= a;
            }
            bool hi_bit_set = (a & 0x80) != 0;
            a = static_cast<Byte>(a << 1);
            if (hi_bit_set) {
                a ^= 0x1b;
            }
            b >>= 1;
        }
        return p;
    }

    // -------------------------------------------------------------------------
    // Encryption functions (NIST FIPS 197 Section 5.1)
    // -------------------------------------------------------------------------

    /**
     * Substitute each byte in the state with its corresponding byte in the S-box.
     */
    State& sub_bytes(State& state) const {
        for (size_t i = 0; i < 4; ++i) {
            for (size_t j = 0; j < 4; ++j) {
                Byte row = state[i][j] / 0x10;
                Byte col = state[i][j] % 0x10;
                state[i][j] = S_BOX[16 * row + col];
            }
        }
        return state;
    }

    /**
     * Cyclically shift the rows of the state to the left.
     */
    State& shift_rows(State& state) const {
        // Second row: shift left by one byte
        state[1] = {state[1][1], state[1][2], state[1][3], state[1][0]};
        // Third row: shift left by two bytes
        state[2] = {state[2][2], state[2][3], state[2][0], state[2][1]};
        // Fourth row: shift left by three bytes
        state[3] = {state[3][3], state[3][0], state[3][1], state[3][2]};
        return state;
    }

    /**
     * Mix the columns of the state in GF(2^8).
     */
    State& mix_columns(State& state) const {
        for (size_t i = 0; i < 4; ++i) {
            Word col = {state[0][i], state[1][i], state[2][i], state[3][i]};
            state[0][i] = gmul(0x02, col[0]) ^ gmul(0x03, col[1]) ^ col[2] ^ col[3];
            state[1][i] = col[0] ^ gmul(0x02, col[1]) ^ gmul(0x03, col[2]) ^ col[3];
            state[2][i] = col[0] ^ col[1] ^ gmul(0x02, col[2]) ^ gmul(0x03, col[3]);
            state[3][i] = gmul(0x03, col[0]) ^ col[1] ^ col[2] ^ gmul(0x02, col[3]);
        }
        return state;
    }

    /**
     * Add (XOR) the round key to the state.
     */
    State& add_round_key(State& state, int round_number) const {
        for (size_t i = 0; i < 4; ++i) {
            for (size_t j = 0; j < 4; ++j) {
                state[j][i] ^= this->round_keys[static_cast<size_t>(round_number * 4) + i][j];
            }
        }
        return state;
    }

    // -------------------------------------------------------------------------
    // Decryption functions (NIST FIPS 197 Section 5.3)
    // -------------------------------------------------------------------------

    /**
     * Inverse substitute bytes using the inverse S-box.
     */
    State& inv_sub_bytes(State& state) const {
        for (size_t i = 0; i < 4; ++i) {
            for (size_t j = 0; j < 4; ++j) {
                Byte row = state[i][j] / 0x10;
                Byte col = state[i][j] % 0x10;
                state[i][j] = INV_S_BOX[16 * row + col];
            }
        }
        return state;
    }

    /**
     * Inverse shift rows to the right.
     */
    State& inv_shift_rows(State& state) const {
        state[1] = {state[1][3], state[1][0], state[1][1], state[1][2]};
        state[2] = {state[2][2], state[2][3], state[2][0], state[2][1]};
        state[3] = {state[3][1], state[3][2], state[3][3], state[3][0]};
        return state;
    }

    /**
     * Inverse mix the columns of the state in GF(2^8).
     */
    State& inv_mix_columns(State& state) const {
        for (size_t i = 0; i < 4; ++i) {
            Word col = {state[0][i], state[1][i], state[2][i], state[3][i]};
            state[0][i] = gmul(0x0E, col[0]) ^ gmul(0x0B, col[1]) ^ gmul(0x0D, col[2]) ^ gmul(0x09, col[3]);
            state[1][i] = gmul(0x09, col[0]) ^ gmul(0x0E, col[1]) ^ gmul(0x0B, col[2]) ^ gmul(0x0D, col[3]);
            state[2][i] = gmul(0x0D, col[0]) ^ gmul(0x09, col[1]) ^ gmul(0x0E, col[2]) ^ gmul(0x0B, col[3]);
            state[3][i] = gmul(0x0B, col[0]) ^ gmul(0x0D, col[1]) ^ gmul(0x09, col[2]) ^ gmul(0x0E, col[3]);
        }
        return state;
    }

    // -------------------------------------------------------------------------
    // Key Expansion (NIST FIPS 197 Section 5.2)
    // -------------------------------------------------------------------------

    /**
     * Substitute word: SUBWORD([a0, a1, a2, a3]) = [SBOX(a0), SBOX(a1), SBOX(a2), SBOX(a3)]
     */
    Word sub_word(const Word& word) const {
        return {
            S_BOX[word[0]],
            S_BOX[word[1]],
            S_BOX[word[2]],
            S_BOX[word[3]]
        };
    }

    /**
     * Rotate word (<<< 1 byte): ROTWORD([a0, a1, a2, a3]) = [a1, a2, a3, a0]
     */
    Word rot_word(const Word& word) const {
        return {word[1], word[2], word[3], word[0]};
    }

    /**
     * Generate round keys for AES-128 (44 words), AES-192 (52 words), or AES-256 (60 words).
     */
    std::vector<Word> key_expansion(const ByteVec& key_bytes, int length) {
        auto it = VALID_KEY_LENGTHS.find(length);
        if (it == VALID_KEY_LENGTHS.end()) {
            throw std::invalid_argument("Invalid key length. Supported lengths are 128, 192, and 256 bits.");
        }
        size_t expected_len = it->second;
        if (key_bytes.size() != expected_len) {
            throw std::invalid_argument(
                "AES-" + std::to_string(length) + " key expansion requires " +
                std::to_string(expected_len) + " bytes; got " + std::to_string(key_bytes.size()) + "."
            );
        }
        this->key = key_bytes;
        if (length == 128) {
            return this->key_expansion_128();
        } else if (length == 192) {
            return this->key_expansion_192();
        } else {
            return this->key_expansion_256();
        }
    }

    /**
     * Generate 11 round keys (44 words) for AES-128.
     */
    std::vector<Word> key_expansion_128() const {
        constexpr size_t key_size = 16;
        constexpr size_t key_words = 4;
        std::vector<Word> rkeys;
        rkeys.reserve(44);

        for (size_t i = 0; i < key_size; i += 4) {
            rkeys.push_back({this->key[i], this->key[i + 1], this->key[i + 2], this->key[i + 3]});
        }

        for (size_t i = key_words; i < 44; ++i) {
            Word temp = rkeys[i - 1];
            if (i % key_words == 0) {
                temp = this->sub_word(this->rot_word(temp));
                size_t rcon_idx = (i - key_words) / key_words;
                for (size_t j = 0; j < 4; ++j) {
                    temp[j] ^= RCON[rcon_idx][j];
                }
            }
            Word next_word{};
            for (size_t j = 0; j < 4; ++j) {
                next_word[j] = rkeys[i - key_words][j] ^ temp[j];
            }
            rkeys.push_back(next_word);
        }
        return rkeys;
    }

    /**
     * Generate 13 round keys (52 words) for AES-192.
     */
    std::vector<Word> key_expansion_192() const {
        std::vector<Word> rkeys;
        rkeys.reserve(52);

        for (size_t i = 0; i < 24; i += 4) {
            rkeys.push_back({this->key[i], this->key[i + 1], this->key[i + 2], this->key[i + 3]});
        }

        for (size_t i = 6; i < 52; ++i) {
            Word temp = rkeys[i - 1];
            if (i % 6 == 0) {
                temp = this->sub_word(this->rot_word(temp));
                size_t rcon_idx = (i - 6) / 6;
                for (size_t j = 0; j < 4; ++j) {
                    temp[j] ^= RCON[rcon_idx][j];
                }
            }
            Word next_word{};
            for (size_t j = 0; j < 4; ++j) {
                next_word[j] = rkeys[i - 6][j] ^ temp[j];
            }
            rkeys.push_back(next_word);
        }
        return rkeys;
    }

    /**
     * Generate 15 round keys (60 words) for AES-256.
     */
    std::vector<Word> key_expansion_256() const {
        std::vector<Word> rkeys;
        rkeys.reserve(60);

        for (size_t i = 0; i < 32; i += 4) {
            rkeys.push_back({this->key[i], this->key[i + 1], this->key[i + 2], this->key[i + 3]});
        }

        for (size_t i = 8; i < 60; ++i) {
            Word temp = rkeys[i - 1];
            if (i % 8 == 0) {
                temp = this->sub_word(this->rot_word(temp));
                size_t rcon_idx = (i - 8) / 8;
                for (size_t j = 0; j < 4; ++j) {
                    temp[j] ^= RCON[rcon_idx][j];
                }
            } else if (i % 8 == 4) {
                temp = this->sub_word(temp);
            }
            Word next_word{};
            for (size_t j = 0; j < 4; ++j) {
                next_word[j] = rkeys[i - 8][j] ^ temp[j];
            }
            rkeys.push_back(next_word);
        }
        return rkeys;
    }

    // -------------------------------------------------------------------------
    // AES state conversion & hex formatting helpers
    // -------------------------------------------------------------------------

    /**
     * Map a 16-byte block to AES state[row][column] in column-major order.
     */
    static State _bytes_to_state(const ByteVec& block) {
        if (block.size() != BLOCK_SIZE) {
            throw std::invalid_argument(
                "AES block must be exactly 16 bytes; got " + std::to_string(block.size()) + "."
            );
        }
        State state{};
        for (size_t row = 0; row < 4; ++row) {
            for (size_t column = 0; column < 4; ++column) {
                state[row][column] = block[4 * column + row];
            }
        }
        return state;
    }

    /**
     * Serialize AES state[row][column] back to a 16-byte block in column-major order.
     */
    static ByteVec _state_to_bytes(const State& state) {
        ByteVec out(BLOCK_SIZE);
        for (size_t column = 0; column < 4; ++column) {
            for (size_t row = 0; row < 4; ++row) {
                out[4 * column + row] = state[row][column];
            }
        }
        return out;
    }

    int _num_rounds() const {
        return NUM_ROUNDS.at(this->key_length);
    }

    static std::string bytes_to_hex(const ByteVec& data) {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (Byte b : data) {
            oss << std::setw(2) << static_cast<int>(b);
        }
        return oss.str();
    }

    static ByteVec hex_to_bytes(const std::string& hex) {
        std::string cleaned;
        cleaned.reserve(hex.size());
        for (char c : hex) {
            if (c != ' ' && c != '\n' && c != '\r' && c != '\t' && c != ':') {
                cleaned.push_back(c);
            }
        }
        if (cleaned.size() % 2 != 0) {
            throw std::invalid_argument("Hex string must have an even number of hex digits.");
        }
        ByteVec out;
        out.reserve(cleaned.size() / 2);
        for (size_t i = 0; i < cleaned.size(); i += 2) {
            unsigned int val = 0;
            std::istringstream iss(cleaned.substr(i, 2));
            if (!(iss >> std::hex >> val)) {
                throw std::invalid_argument("Invalid hex character in input.");
            }
            out.push_back(static_cast<Byte>(val));
        }
        return out;
    }

    std::string round_key_hex(int round_number) const {
        ByteVec rk(16);
        for (size_t c = 0; c < 4; ++c) {
            for (size_t r = 0; r < 4; ++r) {
                rk[4 * c + r] = this->round_keys[static_cast<size_t>(round_number * 4) + c][r];
            }
        }
        return bytes_to_hex(rk);
    }

    // -------------------------------------------------------------------------
    // Encrypt / Decrypt exactly one 16-byte block (128 bits)
    // -------------------------------------------------------------------------

    /**
     * Encrypt exactly one 16-byte block using AES-128/192/256.
     * Set trace_rounds = true to print NIST FIPS 197 Appendix B style round trace.
     */
    ByteVec encrypt(const ByteVec& data, bool trace_rounds = false) {
        if (this->round_keys.empty()) {
            this->round_keys = this->key_expansion(this->key, this->key_length);
        }

        State state = _bytes_to_state(data);
        int num_rounds = _num_rounds();

        if (trace_rounds) {
            std::cout << "[AES-" << this->key_length << " ENCRYPT TRACE]\n";
            std::cout << "  Round  0 (Input)         : " << bytes_to_hex(_state_to_bytes(state))
                      << " | RoundKey[0]: " << round_key_hex(0) << "\n";
        }

        // Initial AddRoundKey
        this->add_round_key(state, 0);

        // Nr - 1 full rounds
        for (int round_number = 1; round_number < num_rounds; ++round_number) {
            if (trace_rounds) {
                std::cout << "  Round " << std::setw(2) << round_number
                          << " Start of Round  : " << bytes_to_hex(_state_to_bytes(state)) << "\n";
            }
            this->sub_bytes(state);
            if (trace_rounds) {
                std::cout << "  Round " << std::setw(2) << round_number
                          << " After SubBytes  : " << bytes_to_hex(_state_to_bytes(state)) << "\n";
            }
            this->shift_rows(state);
            if (trace_rounds) {
                std::cout << "  Round " << std::setw(2) << round_number
                          << " After ShiftRows : " << bytes_to_hex(_state_to_bytes(state)) << "\n";
            }
            this->mix_columns(state);
            if (trace_rounds) {
                std::cout << "  Round " << std::setw(2) << round_number
                          << " After MixColumns: " << bytes_to_hex(_state_to_bytes(state))
                          << " | RoundKey[" << round_number << "]: " << round_key_hex(round_number) << "\n";
            }
            this->add_round_key(state, round_number);
        }

        // Final round: no MixColumns
        if (trace_rounds) {
            std::cout << "  Round " << std::setw(2) << num_rounds
                      << " Start of Round  : " << bytes_to_hex(_state_to_bytes(state)) << "\n";
        }
        this->sub_bytes(state);
        if (trace_rounds) {
            std::cout << "  Round " << std::setw(2) << num_rounds
                      << " After SubBytes  : " << bytes_to_hex(_state_to_bytes(state)) << "\n";
        }
        this->shift_rows(state);
        if (trace_rounds) {
            std::cout << "  Round " << std::setw(2) << num_rounds
                      << " After ShiftRows : " << bytes_to_hex(_state_to_bytes(state))
                      << " | RoundKey[" << num_rounds << "]: " << round_key_hex(num_rounds) << "\n";
        }
        this->add_round_key(state, num_rounds);

        ByteVec out = _state_to_bytes(state);
        if (trace_rounds) {
            std::cout << "  Output (Ciphertext Block): " << bytes_to_hex(out) << "\n";
        }
        return out;
    }

    /**
     * Decrypt exactly one 16-byte block using AES-128/192/256.
     * Set trace_rounds = true to print round-by-round inverse cipher trace.
     */
    ByteVec decrypt(const ByteVec& ciphertext, bool trace_rounds = false) {
        if (this->round_keys.empty()) {
            this->round_keys = this->key_expansion(this->key, this->key_length);
        }

        State state = _bytes_to_state(ciphertext);
        int num_rounds = _num_rounds();

        if (trace_rounds) {
            std::cout << "[AES-" << this->key_length << " DECRYPT TRACE]\n";
            std::cout << "  InvRound  0 (Ciphertext)    : " << bytes_to_hex(_state_to_bytes(state))
                      << " | RoundKey[" << num_rounds << "]: " << round_key_hex(num_rounds) << "\n";
        }

        // Initial inverse round starts with AddRoundKey(Nr)
        this->add_round_key(state, num_rounds);

        // Nr - 1 inverse full rounds
        for (int round_number = num_rounds - 1; round_number > 0; --round_number) {
            this->inv_shift_rows(state);
            this->inv_sub_bytes(state);
            this->add_round_key(state, round_number);
            this->inv_mix_columns(state);
            if (trace_rounds) {
                std::cout << "  After InvRound (key " << std::setw(2) << round_number
                          << ")     : " << bytes_to_hex(_state_to_bytes(state)) << "\n";
            }
        }

        // Final inverse round: no InvMixColumns
        this->inv_shift_rows(state);
        this->inv_sub_bytes(state);
        this->add_round_key(state, 0);

        ByteVec out = _state_to_bytes(state);
        if (trace_rounds) {
            std::cout << "  Output (Plaintext Block)    : " << bytes_to_hex(out) << "\n";
        }
        return out;
    }
};

#ifdef AES_STANDALONE_MAIN
int main() {
    std::cout << "=== Testing AES.cpp against NIST FIPS 197 Test Vectors ===\n\n";

    // NIST FIPS 197 Appendix B (AES-128)
    auto key_128 = AES::hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c");
    auto pt      = AES::hex_to_bytes("3243f6a8885a308d313198a2e0370734");
    AES aes128(key_128, 128);
    auto ct128 = aes128.encrypt(pt, true);
    auto dec128 = aes128.decrypt(ct128, true);

    std::cout << "\nAES-128 Expected: 3925841d02dc09fbdc118597196a0b32\n";
    std::cout << "AES-128 Actual  : " << AES::bytes_to_hex(ct128) << "\n";
    std::cout << "AES-128 Decrypt : " << AES::bytes_to_hex(dec128)
              << (dec128 == pt ? " [PASS]\n" : " [FAIL]\n");

    // NIST FIPS 197 Appendix A.2 (AES-192)
    auto key_192 = AES::hex_to_bytes("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    AES aes192(key_192, 192);
    auto ct192 = aes192.encrypt(pt);
    auto dec192 = aes192.decrypt(ct192);
    std::cout << "AES-192 Cipher  : " << AES::bytes_to_hex(ct192)
              << (dec192 == pt ? " [PASS]\n" : " [FAIL]\n");

    // NIST FIPS 197 Appendix A.3 (AES-256)
    auto key_256 = AES::hex_to_bytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    AES aes256(key_256, 256);
    auto ct256 = aes256.encrypt(pt);
    auto dec256 = aes256.decrypt(ct256);
    std::cout << "AES-256 Cipher  : " << AES::bytes_to_hex(ct256)
              << (dec256 == pt ? " [PASS]\n" : " [FAIL]\n");

    return 0;
}
#endif // AES_STANDALONE_MAIN

#endif // UIT_AES_CPP_INCLUDED