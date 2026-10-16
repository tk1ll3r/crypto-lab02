// -*- coding: utf-8 -*-
/**
 * AES.cpp - Pure C++17 Standard Library implementation of AES-128, AES-192, AES-256.
 * Supports both Lecturer Nguyen Ngoc Tu's AES::Block API (aes.hpp) and
 * Task 1/2 AES::ByteVec API (AES.h).
 */

#include "AES.h"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>

const std::map<int, std::size_t> AES::VALID_KEY_LENGTHS = {
    {128, 16},
    {192, 24},
    {256, 32}
};

const std::map<int, int> AES::NUM_ROUNDS = {
    {128, 10},
    {192, 12},
    {256, 14}
};

const std::array<AES::Byte, 256> AES::S_BOX = {
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

const std::array<AES::Byte, 256> AES::INV_S_BOX = {
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

const std::array<AES::Word, 10> AES::RCON = {{
    {0x01, 0x00, 0x00, 0x00},
    {0x02, 0x00, 0x00, 0x00},
    {0x04, 0x00, 0x00, 0x00},
    {0x08, 0x00, 0x00, 0x00},
    {0x10, 0x00, 0x00, 0x00},
    {0x20, 0x00, 0x00, 0x00},
    {0x40, 0x00, 0x00, 0x00},
    {0x80, 0x00, 0x00, 0x00},
    {0x1b, 0x00, 0x00, 0x00},
    {0x36, 0x00, 0x00, 0x00}
}};

AES::AES(const ByteVec& key_bytes, int key_len) {
    if (key_len == 0) {
        if (key_bytes.size() == 16 || key_bytes.size() == 24 || key_bytes.size() == 32) {
            key_len = static_cast<int>(key_bytes.size() * 8);
        } else {
            key_len = 128;
        }
    }
    if (VALID_KEY_LENGTHS.find(key_len) == VALID_KEY_LENGTHS.end()) {
        throw std::invalid_argument("Invalid key length. Supported lengths are 128, 192, and 256 bits.");
    }
    key_length = key_len;
    keyLength_ = key_len;
    numRounds_ = NUM_ROUNDS.at(key_len);

    std::size_t target_bytes = VALID_KEY_LENGTHS.at(key_len);
    key = key_bytes;
    if (key.size() < target_bytes) {
        key.resize(target_bytes, 0x00);
    } else if (key.size() > target_bytes) {
        key.resize(target_bytes);
    }
    key_ = key;
    round_keys = key_expansion(key, key_length);
    roundKeys_ = round_keys;
}

AES::AES(const std::string& key_str, int key_len)
    : AES(ByteVec(key_str.begin(), key_str.end()), key_len) {}

AES::Byte AES::gmul(Byte a, Byte b) noexcept {
    Byte p = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) {
            p ^= a;
        }
        bool hi_bit_set = (a & 0x80) != 0;
        a = static_cast<Byte>((a << 1) & 0xFF);
        if (hi_bit_set) {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    return p;
}

// Lecturer static / camelCase methods
AES::State AES::bytesToState(const Block& block) {
    State state{};
    for (int r = 0; r < 4; ++r) {
        for (int c = 0; c < 4; ++c) {
            state[r][c] = block[r + 4 * c];
        }
    }
    return state;
}

AES::Block AES::stateToBytes(const State& state) {
    Block out{};
    for (int c = 0; c < 4; ++c) {
        for (int r = 0; r < 4; ++r) {
            out[4 * c + r] = state[r][c];
        }
    }
    return out;
}

void AES::subBytes(State& state) {
    for (int r = 0; r < 4; ++r) {
        for (int c = 0; c < 4; ++c) {
            state[r][c] = S_BOX[state[r][c]];
        }
    }
}

void AES::invSubBytes(State& state) {
    for (int r = 0; r < 4; ++r) {
        for (int c = 0; c < 4; ++c) {
            state[r][c] = INV_S_BOX[state[r][c]];
        }
    }
}

void AES::shiftRows(State& state) {
    for (int r = 1; r < 4; ++r) {
        std::array<Byte, 4> row = state[r];
        for (int c = 0; c < 4; ++c) {
            state[r][c] = row[(c + r) % 4];
        }
    }
}

void AES::invShiftRows(State& state) {
    for (int r = 1; r < 4; ++r) {
        std::array<Byte, 4> row = state[r];
        for (int c = 0; c < 4; ++c) {
            state[r][c] = row[(c + 4 - r) % 4];
        }
    }
}

void AES::mixColumns(State& state) {
    for (int c = 0; c < 4; ++c) {
        Byte s0 = state[0][c];
        Byte s1 = state[1][c];
        Byte s2 = state[2][c];
        Byte s3 = state[3][c];

        state[0][c] = gmul(0x02, s0) ^ gmul(0x03, s1) ^ s2 ^ s3;
        state[1][c] = s0 ^ gmul(0x02, s1) ^ gmul(0x03, s2) ^ s3;
        state[2][c] = s0 ^ s1 ^ gmul(0x02, s2) ^ gmul(0x03, s3);
        state[3][c] = gmul(0x03, s0) ^ s1 ^ s2 ^ gmul(0x02, s3);
    }
}

void AES::invMixColumns(State& state) {
    for (int c = 0; c < 4; ++c) {
        Byte s0 = state[0][c];
        Byte s1 = state[1][c];
        Byte s2 = state[2][c];
        Byte s3 = state[3][c];

        state[0][c] = gmul(0x0e, s0) ^ gmul(0x0b, s1) ^ gmul(0x0d, s2) ^ gmul(0x09, s3);
        state[1][c] = gmul(0x09, s0) ^ gmul(0x0e, s1) ^ gmul(0x0b, s2) ^ gmul(0x0d, s3);
        state[2][c] = gmul(0x0d, s0) ^ gmul(0x09, s1) ^ gmul(0x0e, s2) ^ gmul(0x0b, s3);
        state[3][c] = gmul(0x0b, s0) ^ gmul(0x0d, s1) ^ gmul(0x09, s2) ^ gmul(0x0e, s3);
    }
}

void AES::addRoundKey(State& state, int round) const {
    int base = round * 4;
    for (int c = 0; c < 4; ++c) {
        const Word& w = round_keys[base + c];
        for (int r = 0; r < 4; ++r) {
            state[r][c] ^= w[r];
        }
    }
}

AES::Word AES::rotWord(Word w) {
    return {w[1], w[2], w[3], w[0]};
}

AES::Word AES::subWord(Word w) {
    return {S_BOX[w[0]], S_BOX[w[1]], S_BOX[w[2]], S_BOX[w[3]]};
}

std::vector<AES::Word> AES::keyExpansion(const std::vector<Byte>& key_bytes) const {
    if (key_bytes.size() == 16) return key_expansion_128();
    if (key_bytes.size() == 24) return key_expansion_192();
    if (key_bytes.size() == 32) return key_expansion_256();
    throw std::invalid_argument("Invalid AES key length.");
}

std::string AES::byteToHex(Byte b) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(b);
    return oss.str();
}

void AES::printRoundKey(int round) const {
    std::cout << "RoundKey[" << std::setw(2) << round << "]: " << round_key_hex(round) << "\n";
}

void AES::printAllRoundKeys() const {
    int nr = _num_rounds();
    for (int r = 0; r <= nr; ++r) {
        printRoundKey(r);
    }
}

void AES::printState(const std::string& label, const State& state) {
    std::cout << label << ": " << bytes_to_hex(stateToBytes(state)) << "\n";
}

// Snake_case methods
AES::State& AES::sub_bytes(State& state) const { subBytes(state); return state; }
AES::State& AES::shift_rows(State& state) const { shiftRows(state); return state; }
AES::State& AES::mix_columns(State& state) const { mixColumns(state); return state; }
AES::State& AES::add_round_key(State& state, int round_number) const { addRoundKey(state, round_number); return state; }
AES::State& AES::inv_sub_bytes(State& state) const { invSubBytes(state); return state; }
AES::State& AES::inv_shift_rows(State& state) const { invShiftRows(state); return state; }
AES::State& AES::inv_mix_columns(State& state) const { invMixColumns(state); return state; }
AES::Word AES::sub_word(const Word& word) const { return subWord(word); }
AES::Word AES::rot_word(const Word& word) const { return rotWord(word); }

std::vector<AES::Word> AES::key_expansion_128() const {
    if (key.size() != 16) {
        throw std::invalid_argument("AES-128 key expansion requires 16 key bytes; got " + std::to_string(key.size()));
    }
    std::vector<Word> w(44);
    for (int i = 0; i < 4; ++i) {
        w[i] = {key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]};
    }
    for (int i = 4; i < 44; ++i) {
        Word temp = w[i - 1];
        if (i % 4 == 0) {
            temp = subWord(rotWord(temp));
            const Word& rcon = RCON[(i / 4) - 1];
            for (int j = 0; j < 4; ++j) temp[j] ^= rcon[j];
        }
        for (int j = 0; j < 4; ++j) {
            w[i][j] = w[i - 4][j] ^ temp[j];
        }
    }
    return w;
}

std::vector<AES::Word> AES::key_expansion_192() const {
    if (key.size() != 24) {
        throw std::invalid_argument("AES-192 key expansion requires 24 key bytes; got " + std::to_string(key.size()));
    }
    std::vector<Word> w(52);
    for (int i = 0; i < 6; ++i) {
        w[i] = {key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]};
    }
    for (int i = 6; i < 52; ++i) {
        Word temp = w[i - 1];
        if (i % 6 == 0) {
            temp = subWord(rotWord(temp));
            const Word& rcon = RCON[(i / 6) - 1];
            for (int j = 0; j < 4; ++j) temp[j] ^= rcon[j];
        }
        for (int j = 0; j < 4; ++j) {
            w[i][j] = w[i - 6][j] ^ temp[j];
        }
    }
    return w;
}

std::vector<AES::Word> AES::key_expansion_256() const {
    if (key.size() != 32) {
        throw std::invalid_argument("AES-256 key expansion requires 32 key bytes; got " + std::to_string(key.size()));
    }
    std::vector<Word> w(60);
    for (int i = 0; i < 8; ++i) {
        w[i] = {key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]};
    }
    for (int i = 8; i < 60; ++i) {
        Word temp = w[i - 1];
        if (i % 8 == 0) {
            temp = subWord(rotWord(temp));
            const Word& rcon = RCON[(i / 8) - 1];
            for (int j = 0; j < 4; ++j) temp[j] ^= rcon[j];
        } else if (i % 8 == 4) {
            temp = subWord(temp);
        }
        for (int j = 0; j < 4; ++j) {
            w[i][j] = w[i - 8][j] ^ temp[j];
        }
    }
    return w;
}

std::vector<AES::Word> AES::key_expansion(const ByteVec& key_bytes, int length) {
    key = key_bytes;
    if (length == 128) return key_expansion_128();
    if (length == 192) return key_expansion_192();
    if (length == 256) return key_expansion_256();
    throw std::invalid_argument("Invalid AES key length. Use 128, 192, or 256 bits.");
}

AES::State AES::_bytes_to_state(const ByteVec& block) {
    if (block.size() != BLOCK_SIZE) {
        throw std::invalid_argument("AES block must be exactly 16 bytes; got " + std::to_string(block.size()));
    }
    State state{};
    for (int r = 0; r < 4; ++r) {
        for (int c = 0; c < 4; ++c) {
            state[r][c] = block[r + 4 * c];
        }
    }
    return state;
}

AES::ByteVec AES::_state_to_bytes(const State& state) {
    ByteVec out(BLOCK_SIZE);
    for (int c = 0; c < 4; ++c) {
        for (int r = 0; r < 4; ++r) {
            out[4 * c + r] = state[r][c];
        }
    }
    return out;
}

int AES::_num_rounds() const {
    return NUM_ROUNDS.at(key_length);
}

std::string AES::bytes_to_hex(const ByteVec& data) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (Byte b : data) {
        oss << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}

std::string AES::bytes_to_hex(const Block& data) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (Byte b : data) {
        oss << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}

AES::ByteVec AES::hex_to_bytes(const std::string& hex) {
    std::string clean;
    clean.reserve(hex.size());
    for (char ch : hex) {
        if (!std::isspace(static_cast<unsigned char>(ch))) {
            clean.push_back(ch);
        }
    }
    if (clean.size() % 2 != 0) {
        throw std::invalid_argument("Hex string must have an even number of hex digits.");
    }
    ByteVec out;
    out.reserve(clean.size() / 2);
    for (std::size_t i = 0; i < clean.size(); i += 2) {
        char c1 = clean[i];
        char c2 = clean[i + 1];
        if (!std::isxdigit(static_cast<unsigned char>(c1)) ||
            !std::isxdigit(static_cast<unsigned char>(c2))) {
            throw std::invalid_argument("Invalid hex character in input.");
        }
        auto hex_val = [](char c) -> Byte {
            if (c >= '0' && c <= '9') return static_cast<Byte>(c - '0');
            if (c >= 'a' && c <= 'f') return static_cast<Byte>(c - 'a' + 10);
            return static_cast<Byte>(c - 'A' + 10);
        };
        out.push_back(static_cast<Byte>((hex_val(c1) << 4) | hex_val(c2)));
    }
    return out;
}

std::string AES::round_key_hex(int round_number) const {
    ByteVec rk;
    rk.reserve(16);
    int base = round_number * 4;
    for (int c = 0; c < 4; ++c) {
        for (int r = 0; r < 4; ++r) {
            rk.push_back(round_keys[base + c][r]);
        }
    }
    return bytes_to_hex(rk);
}

AES::Block AES::encrypt(const Block& plaintext, bool trace) const {
    ByteVec in(plaintext.begin(), plaintext.end());
    ByteVec out = encrypt(in, trace);
    Block res{};
    std::copy_n(out.begin(), BLOCK_SIZE, res.begin());
    return res;
}

AES::Block AES::decrypt(const Block& ciphertext, bool trace) const {
    ByteVec in(ciphertext.begin(), ciphertext.end());
    ByteVec out = decrypt(in, trace);
    Block res{};
    std::copy_n(out.begin(), BLOCK_SIZE, res.begin());
    return res;
}

AES::ByteVec AES::encrypt(const ByteVec& data, bool trace_rounds) const {
    State state = _bytes_to_state(data);
    int nr = _num_rounds();

    if (trace_rounds) {
        std::cout << "[AES-" << key_length << " ENCRYPT TRACE]\n";
        std::cout << "  Round  0 (Input)         : " << bytes_to_hex(_state_to_bytes(state))
                  << " | RoundKey[0]: " << round_key_hex(0) << "\n";
    }

    add_round_key(state, 0);

    for (int rnd = 1; rnd < nr; ++rnd) {
        if (trace_rounds) {
            std::cout << "  Round " << std::setw(2) << rnd << " Start of Round  : "
                      << bytes_to_hex(_state_to_bytes(state)) << "\n";
        }
        sub_bytes(state);
        if (trace_rounds) {
            std::cout << "  Round " << std::setw(2) << rnd << " After SubBytes  : "
                      << bytes_to_hex(_state_to_bytes(state)) << "\n";
        }
        shift_rows(state);
        if (trace_rounds) {
            std::cout << "  Round " << std::setw(2) << rnd << " After ShiftRows : "
                      << bytes_to_hex(_state_to_bytes(state)) << "\n";
        }
        mix_columns(state);
        if (trace_rounds) {
            std::cout << "  Round " << std::setw(2) << rnd << " After MixColumns: "
                      << bytes_to_hex(_state_to_bytes(state))
                      << " | RoundKey[" << rnd << "]: " << round_key_hex(rnd) << "\n";
        }
        add_round_key(state, rnd);
    }

    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, nr);

    ByteVec out = _state_to_bytes(state);
    if (trace_rounds) {
        std::cout << "  Output (Ciphertext Block): " << bytes_to_hex(out)
                  << " | RoundKey[" << nr << "]: " << round_key_hex(nr) << "\n";
    }
    return out;
}

AES::ByteVec AES::decrypt(const ByteVec& ciphertext, bool trace_rounds) const {
    State state = _bytes_to_state(ciphertext);
    int nr = _num_rounds();

    if (trace_rounds) {
        std::cout << "[AES-" << key_length << " DECRYPT TRACE]\n";
        std::cout << "  InvRound  0 (Ciphertext)    : " << bytes_to_hex(_state_to_bytes(state))
                  << " | RoundKey[" << nr << "]: " << round_key_hex(nr) << "\n";
    }

    add_round_key(state, nr);

    for (int rnd = nr - 1; rnd >= 1; --rnd) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, rnd);
        inv_mix_columns(state);
        if (trace_rounds) {
            std::cout << "  After InvRound (key " << std::setw(2) << rnd << ")     : "
                      << bytes_to_hex(_state_to_bytes(state)) << "\n";
        }
    }

    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, 0);

    ByteVec out = _state_to_bytes(state);
    if (trace_rounds) {
        std::cout << "  Output (Plaintext Block)    : " << bytes_to_hex(out) << "\n";
    }
    return out;
}
