#pragma once
/**
 * aes.hpp - Header file for AES-128, AES-192, and AES-256 block cipher primitive.
 * Compatible with Lecturer Nguyen Ngoc Tu's reference interface (AES::Block)
 * and Task 1/2 std::vector<uint8_t> (AES::ByteVec) interface.
 */

#ifndef UIT_AES_HPP
#define UIT_AES_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

class AES {
public:
    static constexpr std::size_t BLOCK_SIZE = 16;
    using Byte = std::uint8_t;
    using Block = std::array<Byte, BLOCK_SIZE>;
    using Word = std::array<Byte, 4>;
    using State = std::array<std::array<Byte, 4>, 4>; // state[row][column]
    using ByteVec = std::vector<Byte>;

    static const std::map<int, std::size_t> VALID_KEY_LENGTHS;
    static const std::map<int, int> NUM_ROUNDS;
    static const std::array<Byte, 256> S_BOX;
    static const std::array<Byte, 256> INV_S_BOX;
    static const std::array<Word, 10> RCON;

    ByteVec key;
    int key_length = 0;
    std::vector<Word> round_keys;

    // Constructors
    explicit AES(const std::vector<Byte>& key_bytes, int keyLengthBits = 0);
    explicit AES(const std::string& key_str, int keyLengthBits = 0);

    // Lecturer reference API (16-byte std::array<Byte, 16> Block)
    Block encrypt(const Block& plaintext, bool trace = false) const;
    Block decrypt(const Block& ciphertext, bool trace = false) const;
    void printAllRoundKeys() const;

    // Vector-based API (std::vector<Byte> ByteVec)
    ByteVec encrypt(const ByteVec& data, bool trace_rounds = false) const;
    ByteVec decrypt(const ByteVec& ciphertext, bool trace_rounds = false) const;

    // Galois Field GF(2^8) multiplication
    static Byte gmul(Byte a, Byte b) noexcept;

    // Transformations (camelCase from lecturer reference & snake_case aliases)
    static State bytesToState(const Block& block);
    static Block stateToBytes(const State& state);
    static void subBytes(State& state);
    static void invSubBytes(State& state);
    static void shiftRows(State& state);
    static void invShiftRows(State& state);
    static void mixColumns(State& state);
    static void invMixColumns(State& state);
    void addRoundKey(State& state, int round) const;
    static Word rotWord(Word w);
    static Word subWord(Word w);
    std::vector<Word> keyExpansion(const std::vector<Byte>& key_bytes) const;
    static std::string byteToHex(Byte b);
    void printRoundKey(int round) const;
    static void printState(const std::string& label, const State& state);

    // Snake_case methods for compatibility with Task 1/2 modes
    State& sub_bytes(State& state) const;
    State& shift_rows(State& state) const;
    State& mix_columns(State& state) const;
    State& add_round_key(State& state, int round_number) const;
    State& inv_sub_bytes(State& state) const;
    State& inv_shift_rows(State& state) const;
    State& inv_mix_columns(State& state) const;
    Word sub_word(const Word& word) const;
    Word rot_word(const Word& word) const;
    std::vector<Word> key_expansion(const ByteVec& key_bytes, int length);
    std::vector<Word> key_expansion_128() const;
    std::vector<Word> key_expansion_192() const;
    std::vector<Word> key_expansion_256() const;

    static State _bytes_to_state(const ByteVec& block);
    static ByteVec _state_to_bytes(const State& state);
    int _num_rounds() const;

    static std::string bytes_to_hex(const ByteVec& data);
    static std::string bytes_to_hex(const Block& data);
    static ByteVec hex_to_bytes(const std::string& hex);
    std::string round_key_hex(int round_number) const;

private:
    std::vector<Byte> key_;
    int keyLength_ = 0;
    int numRounds_ = 0;
    std::vector<Word> roundKeys_; // expanded words w[i]
};

#endif // UIT_AES_HPP
