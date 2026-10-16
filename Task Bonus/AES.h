// -*- coding: utf-8 -*-
/**
 * AES.h - Header file for AES-128, AES-192, and AES-256 block cipher primitive.
 * Supports both:
 *   - Standard Static S-Box mode (NIST FIPS 197)
 *   - Bonus Dynamic S-Box mode (Behnam Rahnama et al., "Countering AES Static S-Box Attack", ACM SIN '13)
 *
 * UIT NT219 Cryptography Lab.
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

    /**
     * Mode enumeration matching Section 4 of Rahnama et al. (ACM SIN '13):
     *   - Standard: Uses conventional static S_BOX / INV_S_BOX (NIST FIPS 197)
     *   - Dynamic : Dynamically generates round-dependent Dbox / iDbox from mirrored sub-key
     */
    enum class SBoxMode {
        Standard = 0,
        Dynamic  = 1
    };

    static constexpr size_t BLOCK_SIZE = 16;

    static const std::map<int, size_t> VALID_KEY_LENGTHS;
    static const std::map<int, int> NUM_ROUNDS;
    static const std::array<Byte, 256> S_BOX;
    static const std::array<Byte, 256> INV_S_BOX;
    static const std::array<Word, 10> RCON;

    ByteVec key;
    int key_length;
    SBoxMode sbox_mode;
    std::vector<Word> round_keys;

    explicit AES(const ByteVec& key_bytes, int key_len = 0, SBoxMode mode = SBoxMode::Standard);
    explicit AES(const std::string& key_str, int key_len = 0, SBoxMode mode = SBoxMode::Standard);

    void set_sbox_mode(SBoxMode mode) noexcept { this->sbox_mode = mode; }
    SBoxMode get_sbox_mode() const noexcept { return this->sbox_mode; }

    // Galois Field GF(2^8) multiplication
    static Byte gmul(Byte a, Byte b) noexcept;

    // Encryption transformations (NIST FIPS 197 Section 5.1 + Dynamic S-Box extension)
    State& sub_bytes(State& state, int round_number = 1) const;
    State& shift_rows(State& state) const;
    State& mix_columns(State& state) const;
    State& add_round_key(State& state, int round_number) const;

    // Decryption transformations (NIST FIPS 197 Section 5.3 + Dynamic S-Box extension)
    State& inv_sub_bytes(State& state, int round_number = 1) const;
    State& inv_shift_rows(State& state) const;
    State& inv_mix_columns(State& state) const;

    // -------------------------------------------------------------------------
    // Bonus Task: Dynamic S-Box methods (Rahnama et al., ACM SIN '13, Section 4)
    // Implemented in dynamic_sbox.cpp
    // -------------------------------------------------------------------------
    static void BuildLCS(std::array<Byte, 16>& data, int times) noexcept;
    void DBoxGen(int round_number,
                 std::array<Byte, 256>& dbox,
                 std::array<Byte, 256>& idbox,
                 Byte* out_add_byte = nullptr,
                 std::array<Byte, 16>* out_shifted_subkey = nullptr) const;

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
