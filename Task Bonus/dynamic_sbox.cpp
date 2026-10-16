// -*- coding: utf-8 -*-
/**
 * dynamic_sbox.cpp - Task Bonus: Countering AES Static S-Box Attack
 * Cài đặt thuật toán Dynamic S-Box theo bài báo khoa học:
 *   Behnam Rahnama, Yunus Kıran, Raz Dara, "Countering AES Static S-Box Attack",
 *   Proceedings of the 6th International Conference on Security of Information and Networks (SIN '13),
 *   ACM, 2013, pp. 256-260. DOI: 10.1145/2523514.2523544
 *
 * Môn: Mật mã học (NT219 - UIT)
 * Giải thích chi tiết từng khối (Block-by-block) và các hiệu chỉnh từ mã giả bài báo ở bên dưới.
 */

#include "AES.h"

#include <stdexcept>

// 
// KHỐI 1: HÀM DỊCH VÒNG TRÁI MẢNG 16-BYTE KHÓA VÒNG (BuildLCS - Trang 4 bài báo)
// Nguyên lý:
//   - Nhận vào mảng 16 byte `data` (chứa khóa vòng đối xứng - mirrored sub-key)
//     và số lần dịch `times` (chính là chỉ số vòng hiện tại `round`).
//   - Dịch vòng trái (Left Circular Shift) mảng 16 byte đi `times` vị trí byte.
// 

void AES::BuildLCS(std::array<Byte, 16>& data, int times) noexcept {
    if (times <= 0) {
        return;
    }
    int shift = times % 16;
    for (int i = 0; i < shift; ++i) {
        Byte temp = data[0];
        for (size_t j = 0; j < 15; ++j) {
            data[j] = data[j + 1];
        }
        data[15] = temp;
    }
}

// 
// KHỐI 2: HÀM SINH BẢNG S-BOX ĐỘNG VÀ INV-S-BOX ĐỘNG THEO TỪNG VÒNG (DBoxGen - Trang 4 bài báo)
// Nguyên lý từng bước:
//   - Bước 1 (Lấy khóa vòng đối xứng - Mirrored Position Sub-Key):
//       Tại vòng thứ `round` (1 <= round <= Nr), lấy khóa vòng ở vị trí đối xứng `(Nr - round)`:
//       `Temp[r * 4 + c] = w[(Nr - round) * 4 + r][c]` (với r = 0..3, c = 0..3).
//       (Lưu ý: Trong mã in trang 4 của bài báo, vòng lặp gán `Temp` bị đặt nhầm xuống dưới
//        sau `BuildLCS`; ta đặt đúng vị trí trước `BuildLCS` để `Temp` chứa đúng sub-key đối xứng).
//   - Bước 2 (Dịch vòng trái theo số thứ tự vòng):
//       Gọi `BuildLCS(Temp, round)` để dịch vòng trái 16 byte `Temp` đi `round` vị trí.
//   - Bước 3 (Trích xuất byte biến thiên `AddByte` 8-bit):
//       Duyệt qua 8 vị trí byte chẵn `k = 0, 2, 4, 6, 8, 10, 12, 14` của `Temp`
//       (Lưu ý: Trong bài báo in nhầm `k+2` thành vòng lặp vô hạn, chuẩn xác là `k += 2`),
//       lấy bit thấp nhất `t = Temp[k] & 0x01` ghép dịch trái vào `AddByte`.
//   - Bước 4 (Cập nhật bảng Dbox[16x16] và bảng ngược iDbox[16x16]):
//       Với mỗi ô (i, j) trong ma trận 16x16 (tức chỉ số byte `idx = (i << 4) | j` từ 0..255):
//         + `Dbox[i, j] = S_BOX[i, j] ^ AddByte`
//         + Tách `row = Dbox[i, j] >> 4` và `col = Dbox[i, j] & 0x0F`
//         + Gán bảng nghịch đảo: `iDbox[row, col] = (i << 4) | j`
//       Nhờ phép XOR với hằng số `AddByte` trên bảng hoán vị `S_BOX`, `Dbox` luôn là một song ánh
//       (bijection) trên tập {0x00..0xFF} và `iDbox` là ánh xạ ngược tuyệt đối của `Dbox`.
// 

void AES::DBoxGen(int round_number,
                  std::array<Byte, 256>& dbox,
                  std::array<Byte, 256>& idbox,
                  Byte* out_add_byte,
                  std::array<Byte, 16>* out_shifted_subkey) const {
    int nr = this->_num_rounds();
    if (round_number < 1 || round_number > nr) {
        throw std::out_of_range("DBoxGen round_number must be between 1 and Nr.");
    }

    // Bước 1: Trích xuất 16 byte khóa vòng đối xứng (Mirrored Sub-Key) tại vị trí (Nr - round)
    std::array<Byte, 16> temp{};
    int mirrored_round = nr - round_number;
    for (size_t r = 0; r < 4; ++r) {
        for (size_t c = 0; c < 4; ++c) {
            temp[r * 4 + c] = this->round_keys[static_cast<size_t>(mirrored_round * 4) + r][c];
        }
    }

    // Bước 2: Dịch vòng trái mảng `temp` đi `round_number` lần bằng BuildLCS
    BuildLCS(temp, round_number);
    if (out_shifted_subkey != nullptr) {
        *out_shifted_subkey = temp;
    }

    // Bước 3: Tạo `AddByte` (8 bit) từ bit LSB của 8 byte ở vị trí chẵn (k = 0, 2, ..., 14)
    Byte add_byte = 0;
    for (size_t k = 0; k < 16; k += 2) {
        add_byte = static_cast<Byte>((add_byte << 1) | (temp[k] & 0x01));
    }
    if (out_add_byte != nullptr) {
        *out_add_byte = add_byte;
    }

    // Bước 4: Sinh bảng thế động `dbox` và bảng thế ngược động `idbox` cho vòng `round_number`
    for (size_t i = 0; i < 16; ++i) {
        for (size_t j = 0; j < 16; ++j) {
            size_t idx = (i << 4) | j;
            Byte val = static_cast<Byte>(S_BOX[idx] ^ add_byte);
            dbox[idx] = val;

            Byte row = static_cast<Byte>(val >> 4);
            Byte col = static_cast<Byte>(val & 0x0F);
            idbox[static_cast<size_t>((row << 4) | col)] = static_cast<Byte>(idx);
        }
    }
}
