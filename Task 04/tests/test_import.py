#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_import.py - Deep Python Shared Library (.so / .dll) Import & Cross-Verification Suite.
UIT NT219 Cryptography Lab - Task 3.

Verifies:
  1. Importing `libaes_crypto.so` / `aes_crypto.dll` into Python via `ctypes` (`AESCryptoLib`)
  2. FIPS 197 AES-128 / AES-192 / AES-256 Known-Answer Tests
  3. Standard A (NIST SP 800-38A: ECB, CBC, CFB-128, CFB-8, OFB, CTR) & Standard C (NIST SP 800-38C: CCM)
  4. Cross-checking byte-for-byte against Python's `cryptography` library (OpenSSL backend)
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aes_ctypes_wrapper import AESCryptoLib

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes as crypto_modes
    from cryptography.hazmat.primitives import padding as crypto_padding
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


def main() -> None:
    aes_lib = AESCryptoLib()
    print("======================================================================")
    print(" UIT NT219 Lab - Task 3: Python ctypes Import & Cross-Check Suite")
    print("======================================================================")
    print(f"[Loaded Shared Library] {aes_lib.lib_path}\n")

    # 1. FIPS 197 Known-Answer Tests
    print("=== 1. FIPS 197 AES-128 / AES-192 / AES-256 KAT via Python ctypes ===")
    kat_vectors = [
        (
            "AES-128 KAT",
            bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
            bytes.fromhex("00112233445566778899aabbccddeeff"),
            "69c4e0d86a7b0430d8cdb78070b4c55a",
        ),
        (
            "AES-192 KAT",
            bytes.fromhex("000102030405060708090a0b0c0d0e0f1011121314151617"),
            bytes.fromhex("00112233445566778899aabbccddeeff"),
            "dda97ca4864cdfe06eaf70a0ec0d7191",
        ),
        (
            "AES-256 KAT",
            bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
            bytes.fromhex("00112233445566778899aabbccddeeff"),
            "8ea2b7ca516745bfeafc49904b496089",
        ),
    ]

    for label, key, pt, exp_hex in kat_vectors:
        ct = aes_lib.encrypt_block(key, pt)
        dec = aes_lib.decrypt_block(key, ct)
        assert ct.hex() == exp_hex and dec == pt
        print(f"  [PASS] {label}: Computed={ct.hex()} == Expected")
    print()

    # 2. Standard A & Standard C Round-Trip via ctypes
    print("=== 2. Standard A (SP 800-38A) & Standard C (SP 800-38C) via Python ctypes ===")
    key128 = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv16 = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    nonce12 = bytes.fromhex("101112131415161718191a1b")
    aad = b"UIT-NT219-Python-ctypes-AAD"
    msg = b"Hello UIT NT219 Task 3! Testing Python ctypes bindings to libaes_crypto."

    ecb_ct = aes_lib.ecb_encrypt(key128, msg, pad=True)
    assert aes_lib.ecb_decrypt(key128, ecb_ct, unpad=True) == msg
    print("  [PASS] ctypes AES-128-ECB + PKCS#7 encrypt/decrypt round-trip")

    cbc_ct = aes_lib.cbc_encrypt(key128, msg, iv16, prepend_iv=False, pad=True)
    assert aes_lib.cbc_decrypt(key128, cbc_ct, iv16, has_iv=False, unpad=True) == msg
    print("  [PASS] ctypes AES-128-CBC + PKCS#7 encrypt/decrypt round-trip")

    cfb128_ct = aes_lib.cfb_encrypt(key128, msg, iv16, segment_size=128, prepend_iv=False)
    cfb8_ct = aes_lib.cfb_encrypt(key128, msg, iv16, segment_size=8, prepend_iv=False)
    ofb_ct = aes_lib.ofb_encrypt(key128, msg, iv16, prepend_iv=False)
    ctr_ct = aes_lib.ctr_encrypt(key128, msg, iv16, prepend_iv=False)
    ccm_ct = aes_lib.ccm_encrypt(key128, msg, nonce12, aad=aad, tag_len=16, prepend_nonce=False)
    assert aes_lib.ccm_decrypt(key128, ccm_ct, nonce12, aad=aad, tag_len=16, has_nonce=False) == msg
    print("  [PASS] ctypes AES-128-CCM (AEAD) encrypt/decrypt + tag verification")
    print()

    # 3. Cross-Check against Python `cryptography` (OpenSSL backend)
    if HAS_CRYPTOGRAPHY:
        print("=== 3. Cross-Verification: libaes_crypto (.so/.dll) vs. Python `cryptography` ===")
        padder = crypto_padding.PKCS7(128).padder()
        padded_msg = padder.update(msg) + padder.finalize()

        # ECB comparison
        enc_ecb = Cipher(algorithms.AES(key128), crypto_modes.ECB()).encryptor()
        ref_ecb = enc_ecb.update(padded_msg) + enc_ecb.finalize()
        assert ecb_ct == ref_ecb
        print("  [PASS] ECB Ciphertext matches Python `cryptography` (OpenSSL) 100%")

        # CBC comparison
        enc_cbc = Cipher(algorithms.AES(key128), crypto_modes.CBC(iv16)).encryptor()
        ref_cbc = enc_cbc.update(padded_msg) + enc_cbc.finalize()
        assert cbc_ct == ref_cbc
        print("  [PASS] CBC Ciphertext matches Python `cryptography` (OpenSSL) 100%")

        # CFB-128 comparison
        enc_cfb128 = Cipher(algorithms.AES(key128), crypto_modes.CFB(iv16)).encryptor()
        ref_cfb128 = enc_cfb128.update(msg) + enc_cfb128.finalize()
        assert cfb128_ct == ref_cfb128
        print("  [PASS] CFB-128 Ciphertext matches Python `cryptography` (OpenSSL) 100%")

        # CFB-8 comparison
        enc_cfb8 = Cipher(algorithms.AES(key128), crypto_modes.CFB8(iv16)).encryptor()
        ref_cfb8 = enc_cfb8.update(msg) + enc_cfb8.finalize()
        assert cfb8_ct == ref_cfb8
        print("  [PASS] CFB-8 Ciphertext matches Python `cryptography` (OpenSSL) 100%")

        # OFB comparison
        enc_ofb = Cipher(algorithms.AES(key128), crypto_modes.OFB(iv16)).encryptor()
        ref_ofb = enc_ofb.update(msg) + enc_ofb.finalize()
        assert ofb_ct == ref_ofb
        print("  [PASS] OFB Ciphertext matches Python `cryptography` (OpenSSL) 100%")

        # CTR comparison
        enc_ctr = Cipher(algorithms.AES(key128), crypto_modes.CTR(iv16)).encryptor()
        ref_ctr = enc_ctr.update(msg) + enc_ctr.finalize()
        assert ctr_ct == ref_ctr
        print("  [PASS] CTR Ciphertext matches Python `cryptography` (OpenSSL) 100%")

        # CCM comparison
        ref_ccm = AESCCM(key128, tag_length=16).encrypt(nonce12, msg, aad)
        assert ccm_ct == ref_ccm
        print("  [PASS] CCM Ciphertext+Tag matches Python `cryptography.AESCCM` 100%\n")

    print("All Python ctypes import and cross-verification tests PASSED!")


if __name__ == "__main__":
    main()
