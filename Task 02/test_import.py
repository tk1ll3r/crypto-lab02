#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_import.py - Import compiled C++ shared library (libaes_crypto.so / aes_crypto.dll)
into Python using ctypes (UIT NT219 Cryptography Lab - Task 2).
"""

import ctypes
import os
import sys
from pathlib import Path


def load_aes_shared_library() -> ctypes.CDLL:
    here = Path(__file__).resolve().parent
    candidates = [
        here / "libaes_crypto.so",
        here / "aes_crypto.dll",
        here / "libaes_crypto.dylib",
        here / "build" / "libaes_crypto.so",
        here / "build" / "aes_crypto.dll",
        here / "build" / "Release" / "aes_crypto.dll",
        here / "build" / "Debug" / "aes_crypto.dll",
    ]
    for path in candidates:
        if path.exists():
            return ctypes.CDLL(str(path))
    raise FileNotFoundError(
        "Could not find libaes_crypto.so or aes_crypto.dll. Run 'make' or 'cmake --build build' first."
    )


def setup_signatures(lib: ctypes.CDLL) -> None:
    u8_ptr = ctypes.POINTER(ctypes.c_uint8)
    size_ptr = ctypes.POINTER(ctypes.c_size_t)

    lib.aes_encrypt_block.argtypes = [u8_ptr, ctypes.c_size_t, u8_ptr, u8_ptr]
    lib.aes_encrypt_block.restype = ctypes.c_int

    lib.aes_decrypt_block.argtypes = [u8_ptr, ctypes.c_size_t, u8_ptr, u8_ptr]
    lib.aes_decrypt_block.restype = ctypes.c_int

    lib.aes_get_padding_length.argtypes = [ctypes.c_size_t]
    lib.aes_get_padding_length.restype = ctypes.c_size_t

    lib.aes_cbc_encrypt.argtypes = [
        u8_ptr, ctypes.c_size_t, u8_ptr, u8_ptr, ctypes.c_size_t,
        ctypes.c_int, ctypes.c_int, u8_ptr, size_ptr
    ]
    lib.aes_cbc_encrypt.restype = ctypes.c_int

    lib.aes_cbc_decrypt.argtypes = [
        u8_ptr, ctypes.c_size_t, u8_ptr, u8_ptr, ctypes.c_size_t,
        ctypes.c_int, ctypes.c_int, u8_ptr, size_ptr
    ]
    lib.aes_cbc_decrypt.restype = ctypes.c_int

    lib.aes_gcm_encrypt.argtypes = [
        u8_ptr, ctypes.c_size_t, u8_ptr, u8_ptr, ctypes.c_size_t,
        u8_ptr, ctypes.c_size_t, ctypes.c_int, u8_ptr, size_ptr
    ]
    lib.aes_gcm_encrypt.restype = ctypes.c_int

    lib.aes_gcm_decrypt.argtypes = [
        u8_ptr, ctypes.c_size_t, u8_ptr, u8_ptr, ctypes.c_size_t,
        u8_ptr, ctypes.c_size_t, ctypes.c_int, u8_ptr, size_ptr
    ]
    lib.aes_gcm_decrypt.restype = ctypes.c_int

    lib.aes_ccm_encrypt.argtypes = [
        u8_ptr, ctypes.c_size_t, u8_ptr, ctypes.c_size_t,
        u8_ptr, ctypes.c_size_t, u8_ptr, ctypes.c_size_t,
        ctypes.c_size_t, ctypes.c_int, u8_ptr, size_ptr
    ]
    lib.aes_ccm_encrypt.restype = ctypes.c_int

    lib.aes_ccm_decrypt.argtypes = [
        u8_ptr, ctypes.c_size_t, u8_ptr, ctypes.c_size_t,
        u8_ptr, ctypes.c_size_t, u8_ptr, ctypes.c_size_t,
        ctypes.c_size_t, ctypes.c_int, u8_ptr, size_ptr
    ]
    lib.aes_ccm_decrypt.restype = ctypes.c_int


def to_c_buf(data: bytes):
    return (ctypes.c_uint8 * len(data)).from_buffer_copy(data)


def main() -> None:
    lib = load_aes_shared_library()
    setup_signatures(lib)
    print("=== [Python ctypes Import Test] Loaded C++ Shared Library Successfully ===\n")

    # 1. Test AES-128, AES-192, AES-256 Known-Answer Tests via C++ shared library
    kat_vectors = [
        (
            "AES-128 Known-Answer Test (via Python ctypes)",
            bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
            bytes.fromhex("00112233445566778899aabbccddeeff"),
            "69c4e0d86a7b0430d8cdb78070b4c55a",
        ),
        (
            "AES-192 Known-Answer Test (via Python ctypes)",
            bytes.fromhex("000102030405060708090a0b0c0d0e0f1011121314151617"),
            bytes.fromhex("00112233445566778899aabbccddeeff"),
            "dda97ca4864cdfe06eaf70a0ec0d7191",
        ),
        (
            "AES-256 Known-Answer Test (via Python ctypes)",
            bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
            bytes.fromhex("00112233445566778899aabbccddeeff"),
            "8ea2b7ca516745bfeafc49904b496089",
        ),
    ]

    for title, key, pt, expected_hex in kat_vectors:
        ct_buf = (ctypes.c_uint8 * 16)()
        dec_buf = (ctypes.c_uint8 * 16)()
        lib.aes_encrypt_block(to_c_buf(key), len(key), to_c_buf(pt), ct_buf)
        lib.aes_decrypt_block(to_c_buf(key), len(key), ct_buf, dec_buf)

        computed_hex = bytes(ct_buf).hex()
        decrypted_hex = bytes(dec_buf).hex()
        enc_pass = computed_hex == expected_hex
        dec_pass = decrypted_hex == pt.hex()

        print(title)
        print(f"  Key       : {key.hex()}")
        print(f"  Plaintext : {pt.hex()}")
        print(f"  Expected  : {expected_hex}")
        print(f"  Computed  : {computed_hex}")
        print(f"  Decrypted : {decrypted_hex}")
        print(f"  Encrypt   : {'PASS' if enc_pass else 'FAIL'}")
        print(f"  Decrypt   : {'PASS' if dec_pass else 'FAIL'}\n")
        assert enc_pass and dec_pass

    # 2. Test Modes (CBC, GCM, CCM) via C++ shared library from Python
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    nonce12 = bytes.fromhex("000102030405060708090a0b")
    nonce13 = bytes.fromhex("000102030405060708090a0b0c")
    aad = b"UIT-NT219-AAD"
    msg = b"Hello UIT NT219 from Python ctypes calling C++ libaes_crypto.so!"

    # CBC
    out_buf = (ctypes.c_uint8 * 256)()
    out_len = ctypes.c_size_t(0)
    lib.aes_cbc_encrypt(to_c_buf(key), len(key), to_c_buf(iv), to_c_buf(msg), len(msg), 1, 1, out_buf, ctypes.byref(out_len))
    cbc_ct = bytes(out_buf[: out_len.value])

    dec_buf = (ctypes.c_uint8 * 256)()
    dec_len = ctypes.c_size_t(0)
    lib.aes_cbc_decrypt(to_c_buf(key), len(key), None, to_c_buf(cbc_ct), len(cbc_ct), 1, 1, dec_buf, ctypes.byref(dec_len))
    cbc_pt = bytes(dec_buf[: dec_len.value])
    assert cbc_pt == msg

    # GCM (NIST SP 800-38D)
    lib.aes_gcm_encrypt(to_c_buf(key), len(key), to_c_buf(nonce12), to_c_buf(aad), len(aad), to_c_buf(msg), len(msg), 1, out_buf, ctypes.byref(out_len))
    gcm_ct = bytes(out_buf[: out_len.value])
    lib.aes_gcm_decrypt(to_c_buf(key), len(key), None, to_c_buf(aad), len(aad), to_c_buf(gcm_ct), len(gcm_ct), 1, dec_buf, ctypes.byref(dec_len))
    gcm_pt = bytes(dec_buf[: dec_len.value])
    assert gcm_pt == msg

    # CCM (NIST SP 800-38C)
    lib.aes_ccm_encrypt(to_c_buf(key), len(key), to_c_buf(nonce13), len(nonce13), to_c_buf(aad), len(aad), to_c_buf(msg), len(msg), 16, 1, out_buf, ctypes.byref(out_len))
    ccm_ct = bytes(out_buf[: out_len.value])
    lib.aes_ccm_decrypt(to_c_buf(key), len(key), None, 13, to_c_buf(aad), len(aad), to_c_buf(ccm_ct), len(ccm_ct), 16, 1, dec_buf, ctypes.byref(dec_len))
    ccm_pt = bytes(dec_buf[: dec_len.value])
    assert ccm_pt == msg

    print("Modes Test via Python ctypes (CBC / GCM / CCM):")
    print(f"  Plaintext : {msg.decode('utf-8')}")
    print(f"  CBC Hex   : {cbc_ct.hex()}")
    print(f"  GCM Hex   : {gcm_ct.hex()}")
    print(f"  CCM Hex   : {ccm_ct.hex()}")
    print("  Result    : PASS (All C++ shared library calls succeeded in Python!)")


if __name__ == "__main__":
    main()
