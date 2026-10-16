// -*- coding: utf-8 -*-
/**
 * AES.h - Header file for AES-128, AES-192, and AES-256 block cipher primitive.
 * UIT NT219 Cryptography Lab - Task 1 (C++17 Standard Library).
 */

#ifndef UIT_AES_H
#define UIT_AES_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

class AES {
public:
    using Byte = uint8_t;
    using Word = std::array<Byte, 4>;
    using State = std::array<std::array<Byte, 4>, 4>;
    using ByteVec = std::vector<Byte>;

    static constexpr size_t BLOCK_SIZE = 16;

    static const std::map<int, size_t> VALID_KEY_LENGTHS;
    static const std::map<int, int> NUM_ROUNDS;
    static const std::array<Byte, 256> S_BOX;
    static const std::array<Byte, 256> INV_S_BOX;
    static const std::array<Word, 10> RCON;

    ByteVec key;
    int key_length;
    std::vector<Word> round_keys;

    explicit AES(const ByteVec& key_bytes, int key_len = 0);
    explicit AES(const std::string& key_str, int key_len = 0);

    // Galois Field GF(2^8) multiplication
    static Byte gmul(Byte a, Byte b) noexcept;

    // Encryption transformations (NIST FIPS 197 Section 5.1)
    State& sub_bytes(State& state) const;
    State& shift_rows(State& state) const;
    State& mix_columns(State& state) const;
    State& add_round_key(State& state, int round_number) const;

    // Decryption transformations (NIST FIPS 197 Section 5.3)
    State& inv_sub_bytes(State& state) const;
    State& inv_shift_rows(State& state) const;
    State& inv_mix_columns(State& state) const;

    // Key Expansion routines (NIST FIPS 197 Section 5.2)
    Word sub_word(const Word& word) const;
    Word rot_word(const Word& word) const;
    std::vector<Word> key_expansion(const ByteVec& key_bytes, int length);
    std::vector<Word> key_expansion_128() const;
    std::vector<Word> key_expansion_192() const;
    std::vector<Word> key_expansion_256() const;

    // State & Hex conversion helpers
    static State _bytes_to_state(const ByteVec& block);
    static ByteVec _state_to_bytes(const State& state);
    int _num_rounds() const;

    static std::string bytes_to_hex(const ByteVec& data);
    static ByteVec hex_to_bytes(const std::string& hex);
    std::string round_key_hex(int round_number) const;

    // Block cipher encrypt / decrypt (16-byte block)
    ByteVec encrypt(const ByteVec& data, bool trace_rounds = false);
    ByteVec decrypt(const ByteVec& ciphertext, bool trace_rounds = false);
};

#endif // UIT_AES_H
