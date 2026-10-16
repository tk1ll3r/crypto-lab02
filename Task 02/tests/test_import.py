#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_import.py - Import compiled C++ shared library (libaes_crypto.so / aes_crypto.dll)
into Python using ctypes (UIT NT219 Cryptography Lab - Task 2: Standards A & C).
"""

import ctypes
from pathlib import Path


def load_aes_shared_library() -> ctypes.CDLL:
    here = Path(__file__).resolve().parent
    root = here.parent if here.name == "tests" else here
    candidates = [
        root / "build" / "libaes_crypto.so",
        root / "build-gcc" / "libaes_crypto.so",
        root / "build-gcc-attn" / "libaes_crypto.so",
        root / "build-gcc-attn" / "libaes_crypto.dll",
        root / "build-gcc-attn" / "aes_crypto.dll",
        root / "build-gcc" / "libaes_crypto.dll",
        root / "libaes_crypto.so",
        here / "libaes_crypto.so",
        root / "build" / "aes_crypto.dll",
        root / "build-gcc" / "aes_crypto.dll",
        root / "aes_crypto.dll",
        root / "build" / "libaes_crypto.dylib",
        root / "build-gcc" / "libaes_crypto.dylib",
        root / "build" / "Release" / "aes_crypto.dll",
        root / "build" / "Debug" / "aes_crypto.dll",
    ]
    for path in candidates:
        if path.exists():
            print(f"[Loaded Shared Library] {path}")
            return ctypes.CDLL(str(path))
    raise FileNotFoundError(
        "Could not find libaes_crypto.so or aes_crypto.dll in build/ or build-gcc/."
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

    lib.aes_ecb_encrypt.argtypes = [
        u8_ptr, ctypes.c_size_t, u8_ptr, ctypes.c_size_t,
        ctypes.c_int, u8_ptr, size_ptr
    ]
    lib.aes_ecb_encrypt.restype = ctypes.c_int

    lib.aes_ecb_decrypt.argtypes = [
        u8_ptr, ctypes.c_size_t, u8_ptr, ctypes.c_size_t,
        ctypes.c_int, u8_ptr, size_ptr
    ]
    lib.aes_ecb_decrypt.restype = ctypes.c_int

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

    lib.aes_cfb_encrypt.argtypes = [
        u8_ptr, ctypes.c_size_t, u8_ptr, u8_ptr, ctypes.c_size_t,
        ctypes.c_int, ctypes.c_int, u8_ptr, size_ptr
    ]
    lib.aes_cfb_encrypt.restype = ctypes.c_int

    lib.aes_cfb_decrypt.argtypes = [
        u8_ptr, ctypes.c_size_t, u8_ptr, u8_ptr, ctypes.c_size_t,
        ctypes.c_int, ctypes.c_int, u8_ptr, size_ptr
    ]
    lib.aes_cfb_decrypt.restype = ctypes.c_int

    lib.aes_ofb_encrypt.argtypes = [
        u8_ptr, ctypes.c_size_t, u8_ptr, u8_ptr, ctypes.c_size_t,
        ctypes.c_int, u8_ptr, size_ptr
    ]
    lib.aes_ofb_encrypt.restype = ctypes.c_int

    lib.aes_ofb_decrypt.argtypes = [
        u8_ptr, ctypes.c_size_t, u8_ptr, u8_ptr, ctypes.c_size_t,
        ctypes.c_int, u8_ptr, size_ptr
    ]
    lib.aes_ofb_decrypt.restype = ctypes.c_int

    lib.aes_ctr_encrypt.argtypes = [
        u8_ptr, ctypes.c_size_t, u8_ptr, u8_ptr, ctypes.c_size_t,
        ctypes.c_int, u8_ptr, size_ptr
    ]
    lib.aes_ctr_encrypt.restype = ctypes.c_int

    lib.aes_ctr_decrypt.argtypes = [
        u8_ptr, ctypes.c_size_t, u8_ptr, u8_ptr, ctypes.c_size_t,
        ctypes.c_int, u8_ptr, size_ptr
    ]
    lib.aes_ctr_decrypt.restype = ctypes.c_int

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

    # 2. Test Standard A (NIST SP 800-38A: ECB, CBC, CFB, OFB, CTR) & Standard C (NIST SP 800-38C: CCM)
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    nonce13 = bytes.fromhex("000102030405060708090a0b0c")
    aad = b"UIT-NT219-AAD"
    msg = b"Hello UIT NT219 from Python ctypes calling C++ libaes_crypto.so!"

    out_buf = (ctypes.c_uint8 * 256)()
    out_len = ctypes.c_size_t(0)
    dec_buf = (ctypes.c_uint8 * 256)()
    dec_len = ctypes.c_size_t(0)

    # Standard A: ECB
    lib.aes_ecb_encrypt(to_c_buf(key), len(key), to_c_buf(msg), len(msg), 1, out_buf, ctypes.byref(out_len))
    ecb_ct = bytes(out_buf[: out_len.value])
    lib.aes_ecb_decrypt(to_c_buf(key), len(key), to_c_buf(ecb_ct), len(ecb_ct), 1, dec_buf, ctypes.byref(dec_len))
    assert bytes(dec_buf[: dec_len.value]) == msg

    # Standard A: CBC
    lib.aes_cbc_encrypt(to_c_buf(key), len(key), to_c_buf(iv), to_c_buf(msg), len(msg), 1, 1, out_buf, ctypes.byref(out_len))
    cbc_ct = bytes(out_buf[: out_len.value])
    lib.aes_cbc_decrypt(to_c_buf(key), len(key), None, to_c_buf(cbc_ct), len(cbc_ct), 1, 1, dec_buf, ctypes.byref(dec_len))
    assert bytes(dec_buf[: dec_len.value]) == msg

    # Standard A: CFB-128
    lib.aes_cfb_encrypt(to_c_buf(key), len(key), to_c_buf(iv), to_c_buf(msg), len(msg), 128, 1, out_buf, ctypes.byref(out_len))
    cfb_ct = bytes(out_buf[: out_len.value])
    lib.aes_cfb_decrypt(to_c_buf(key), len(key), None, to_c_buf(cfb_ct), len(cfb_ct), 128, 1, dec_buf, ctypes.byref(dec_len))
    assert bytes(dec_buf[: dec_len.value]) == msg

    # Standard A: OFB
    lib.aes_ofb_encrypt(to_c_buf(key), len(key), to_c_buf(iv), to_c_buf(msg), len(msg), 1, out_buf, ctypes.byref(out_len))
    ofb_ct = bytes(out_buf[: out_len.value])
    lib.aes_ofb_decrypt(to_c_buf(key), len(key), None, to_c_buf(ofb_ct), len(ofb_ct), 1, dec_buf, ctypes.byref(dec_len))
    assert bytes(dec_buf[: dec_len.value]) == msg

    # Standard A: CTR
    lib.aes_ctr_encrypt(to_c_buf(key), len(key), to_c_buf(iv), to_c_buf(msg), len(msg), 1, out_buf, ctypes.byref(out_len))
    ctr_ct = bytes(out_buf[: out_len.value])
    lib.aes_ctr_decrypt(to_c_buf(key), len(key), None, to_c_buf(ctr_ct), len(ctr_ct), 1, dec_buf, ctypes.byref(dec_len))
    assert bytes(dec_buf[: dec_len.value]) == msg

    # Standard C: CCM (NIST SP 800-38C)
    lib.aes_ccm_encrypt(to_c_buf(key), len(key), to_c_buf(nonce13), len(nonce13), to_c_buf(aad), len(aad), to_c_buf(msg), len(msg), 16, 1, out_buf, ctypes.byref(out_len))
    ccm_ct = bytes(out_buf[: out_len.value])
    lib.aes_ccm_decrypt(to_c_buf(key), len(key), None, 13, to_c_buf(aad), len(aad), to_c_buf(ccm_ct), len(ccm_ct), 16, 1, dec_buf, ctypes.byref(dec_len))
    assert bytes(dec_buf[: dec_len.value]) == msg

    print("Modes Test via Python ctypes (Standard A: ECB/CBC/CFB/OFB/CTR & Standard C: CCM):")
    print(f"  Plaintext : {msg.decode('utf-8')}")
    print(f"  ECB Hex   : {ecb_ct.hex()}")
    print(f"  CBC Hex   : {cbc_ct.hex()}")
    print(f"  CFB Hex   : {cfb_ct.hex()}")
    print(f"  OFB Hex   : {ofb_ct.hex()}")
    print(f"  CTR Hex   : {ctr_ct.hex()}")
    print(f"  CCM Hex   : {ccm_ct.hex()}")
    print("  Result    : PASS (All Standard A & Standard C shared library calls succeeded in Python!)")


if __name__ == "__main__":
    main()