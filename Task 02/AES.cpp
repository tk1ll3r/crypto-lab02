// -*- coding: utf-8 -*-
/**
 * AES.cpp - Bộ tiêu chuẩn Gốc: NIST FIPS 197 (Advanced Encryption Standard: AES-128, AES-192, AES-256)
 * Chuyển đổi từ AES.py sang C++17 Standard Library.
 *
 * Môn: Mật mã học (NT219 - UIT)
 * Giải thích chi tiết từng khối biến đổi (SubBytes, ShiftRows, MixColumns, AddRoundKey, KeyExpansion)
 * trên ma trận trạng thái 4x4 byte (1 Block = 16 bytes = 128 bits) ở từng phần bên dưới.
 */

#include "AES.h"

#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>

// KHỐI 1: CÁC BẢNG HẰNG SỐ CHUẨN NIST FIPS 197 (S-BOX, INV-S-BOX, RCON)

const std::map<int, size_t> AES::VALID_KEY_LENGTHS = {
    {128, 16}, // AES-128: Khóa 16 byte (4 words), 10 vòng
    {192, 24}, // AES-192: Khóa 24 byte (6 words), 12 vòng
    {256, 32}  // AES-256: Khóa 32 byte (8 words), 14 vòng
};

const std::map<int, int> AES::NUM_ROUNDS = {
    {128, 10},
    {192, 12},
    {256, 14}
};

// Bảng thế phi tuyến S-Box (NIST FIPS 197 Table 4): nghịch đảo nhân trên GF(2^8) + phép biến đổi Affine
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

// Bảng thế ngược InvS-Box dùng cho quá trình giải mã (NIST FIPS 197 Table 6)
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

// Hằng số vòng Rcon[j] = [x^(j-1), 0x00, 0x00, 0x00] trên GF(2^8) dùng khi mở rộng khóa (Table 5)
const std::array<AES::Word, 10> AES::RCON = {{
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

AES::AES(const ByteVec& key_bytes, int key_len)
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

AES::AES(const std::string& key_str, int key_len)
    : AES(ByteVec(key_str.begin(), key_str.end()), key_len) {}

// KHỐI 2: CÁC PHÉP BIẾN ĐỔI VÒNG MÃ HÓA TRÊN 1 BLOCK 16-BYTE (SUBBYTES, SHIFTROWS, MIXCOLUMNS, ADDROUNDKEY)

AES::Byte AES::gmul(Byte a, Byte b) noexcept {
    // Nhân hai đa thức bậc < 8 trong trường GF(2^8) modulo m(x) = x^8 + x^4 + x^3 + x + 1 (0x1b)
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

AES::State& AES::sub_bytes(State& state) const {
    // Thế từng byte s[i][j] trong ma trận trạng thái 4x4 bằng giá trị tra bảng S_BOX
    for (size_t i = 0; i < 4; ++i) {
        for (size_t j = 0; j < 4; ++j) {
            Byte row = state[i][j] / 0x10;
            Byte col = state[i][j] % 0x10;
            state[i][j] = S_BOX[16 * row + col];
        }
    }
    return state;
}

AES::State& AES::shift_rows(State& state) const {
    // Dịch vòng trái từng hàng r của ma trận trạng thái đi r vị trí (hàng 0 giữ nguyên)
    state[1] = {state[1][1], state[1][2], state[1][3], state[1][0]};
    state[2] = {state[2][2], state[2][3], state[2][0], state[2][1]};
    state[3] = {state[3][3], state[3][0], state[3][1], state[3][2]};
    return state;
}

AES::State& AES::mix_columns(State& state) const {
    // Nhân từng cột i (4 byte) của ma trận trạng thái với ma trận MDS cố định trên GF(2^8)
    for (size_t i = 0; i < 4; ++i) {
        Word col = {state[0][i], state[1][i], state[2][i], state[3][i]};
        state[0][i] = gmul(0x02, col[0]) ^ gmul(0x03, col[1]) ^ col[2] ^ col[3];
        state[1][i] = col[0] ^ gmul(0x02, col[1]) ^ gmul(0x03, col[2]) ^ col[3];
        state[2][i] = col[0] ^ col[1] ^ gmul(0x02, col[2]) ^ gmul(0x03, col[3]);
        state[3][i] = gmul(0x03, col[0]) ^ col[1] ^ col[2] ^ gmul(0x02, col[3]);
    }
    return state;
}

AES::State& AES::add_round_key(State& state, int round_number) const {
    // Kết hợp (XOR) từng cột i của ma trận trạng thái với từ khóa vòng round_keys[4 * round_number + i]
    for (size_t i = 0; i < 4; ++i) {
        for (size_t j = 0; j < 4; ++j) {
            state[j][i] ^= this->round_keys[static_cast<size_t>(round_number * 4) + i][j];
        }
    }
    return state;
}

// KHỐI 3: CÁC PHÉP BIẾN ĐỔI NGƯỢC GIẢI MÃ TRÊN 1 BLOCK 16-BYTE (INVSUBBYTES, INVSHIFTROWS, INVMIXCOLUMNS)

AES::State& AES::inv_sub_bytes(State& state) const {
    // Thế ngược từng byte của ma trận trạng thái qua bảng INV_S_BOX
    for (size_t i = 0; i < 4; ++i) {
        for (size_t j = 0; j < 4; ++j) {
            Byte row = state[i][j] / 0x10;
            Byte col = state[i][j] % 0x10;
            state[i][j] = INV_S_BOX[16 * row + col];
        }
    }
    return state;
}

AES::State& AES::inv_shift_rows(State& state) const {
    // Dịch vòng phải từng hàng r của ma trận trạng thái đi r vị trí
    state[1] = {state[1][3], state[1][0], state[1][1], state[1][2]};
    state[2] = {state[2][2], state[2][3], state[2][0], state[2][1]};
    state[3] = {state[3][1], state[3][2], state[3][3], state[3][0]};
    return state;
}

AES::State& AES::inv_mix_columns(State& state) const {
    // Nhân từng cột của ma trận trạng thái với ma trận nghịch đảo {0x0E, 0x0B, 0x0D, 0x09} trên GF(2^8)
    for (size_t i = 0; i < 4; ++i) {
        Word col = {state[0][i], state[1][i], state[2][i], state[3][i]};
        state[0][i] = gmul(0x0E, col[0]) ^ gmul(0x0B, col[1]) ^ gmul(0x0D, col[2]) ^ gmul(0x09, col[3]);
        state[1][i] = gmul(0x09, col[0]) ^ gmul(0x0E, col[1]) ^ gmul(0x0B, col[2]) ^ gmul(0x0D, col[3]);
        state[2][i] = gmul(0x0D, col[0]) ^ gmul(0x09, col[1]) ^ gmul(0x0E, col[2]) ^ gmul(0x0B, col[3]);
        state[3][i] = gmul(0x0B, col[0]) ^ gmul(0x0D, col[1]) ^ gmul(0x09, col[2]) ^ gmul(0x0E, col[3]);
    }
    return state;
}

// KHỐI 4: MỞ RỘNG KHÓA (KEY EXPANSION CHO AES-128 / 192 / 256 - NIST FIPS 197 MỤC 5.2)

AES::Word AES::sub_word(const Word& word) const {
    return {S_BOX[word[0]], S_BOX[word[1]], S_BOX[word[2]], S_BOX[word[3]]};
}

AES::Word AES::rot_word(const Word& word) const {
    return {word[1], word[2], word[3], word[0]};
}

std::vector<AES::Word> AES::key_expansion(const ByteVec& key_bytes, int length) {
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

std::vector<AES::Word> AES::key_expansion_128() const {
    // Sinh 44 words (11 khóa vòng 16-byte) từ khóa gốc 16 byte (Nk = 4)
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

std::vector<AES::Word> AES::key_expansion_192() const {
    // Sinh 52 words (13 khóa vòng 16-byte) từ khóa gốc 24 byte (Nk = 6)
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

std::vector<AES::Word> AES::key_expansion_256() const {
    // Sinh 60 words (15 khóa vòng 16-byte) từ khóa gốc 32 byte (Nk = 8, có thêm SubWord ở vị trí i % 8 == 4)
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

// KHỐI 5: ÁNH XẠ BLOCK 16-BYTE <-> MA TRẬN STATE 4x4 VÀ MÃ HÓA/GIẢI MÃ 1 BLOCK

AES::State AES::_bytes_to_state(const ByteVec& block) {
    // Ánh xạ 16 byte đầu vào sang ma trận state[row][column] theo thứ tự cột (column-major: block[4*c + r])
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

AES::ByteVec AES::_state_to_bytes(const State& state) {
    // Trải phẳng ma trận state[row][column] về lại mảng 16 byte theo thứ tự cột
    ByteVec out(BLOCK_SIZE);
    for (size_t column = 0; column < 4; ++column) {
        for (size_t row = 0; row < 4; ++row) {
            out[4 * column + row] = state[row][column];
        }
    }
    return out;
}

int AES::_num_rounds() const {
    return NUM_ROUNDS.at(this->key_length);
}

std::string AES::bytes_to_hex(const ByteVec& data) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (Byte b : data) {
        oss << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}

AES::ByteVec AES::hex_to_bytes(const std::string& hex) {
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

std::string AES::round_key_hex(int round_number) const {
    ByteVec rk(16);
    for (size_t c = 0; c < 4; ++c) {
        for (size_t r = 0; r < 4; ++r) {
            rk[4 * c + r] = this->round_keys[static_cast<size_t>(round_number * 4) + c][r];
        }
    }
    return bytes_to_hex(rk);
}

AES::ByteVec AES::encrypt(const ByteVec& data, bool trace_rounds) {
    // Mã hóa đúng 1 Block 16-byte qua Nr vòng (10 vòng cho AES-128, 12 cho AES-192, 14 cho AES-256)
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

    // Vòng khởi đầu (Round 0): Chỉ thực hiện AddRoundKey(state, 0)
    this->add_round_key(state, 0);

    // Nr - 1 vòng chính: SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
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

    // Vòng cuối (Round Nr): SubBytes -> ShiftRows -> AddRoundKey (không có MixColumns)
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

AES::ByteVec AES::decrypt(const ByteVec& ciphertext, bool trace_rounds) {
    // Giải mã đúng 1 Block 16-byte từ Round Nr lùi về Round 0
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

    // Bước đầu: AddRoundKey với khóa vòng cuối Nr
    this->add_round_key(state, num_rounds);

    // Nr - 1 vòng ngược: InvShiftRows -> InvSubBytes -> AddRoundKey -> InvMixColumns
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

    // Vòng ngược cuối: InvShiftRows -> InvSubBytes -> AddRoundKey(0)
    this->inv_shift_rows(state);
    this->inv_sub_bytes(state);
    this->add_round_key(state, 0);

    ByteVec out = _state_to_bytes(state);
    if (trace_rounds) {
        std::cout << "  Output (Plaintext Block)    : " << bytes_to_hex(out) << "\n";
    }
    return out;
}
