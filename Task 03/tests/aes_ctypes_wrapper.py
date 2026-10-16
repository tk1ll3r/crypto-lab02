#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
aes_ctypes_wrapper.py - High-level object-oriented Python wrapper around the compiled
C++ shared library (`libaes_crypto.so` / `aes_crypto.dll` / `libaes_crypto.dylib`).
UIT NT219 Cryptography Lab - Task 3.
"""

import ctypes
from pathlib import Path
from typing import Optional


class AESCryptoLib:
    """Pythonic wrapper over C ABI functions exported by libaes_crypto."""

    def __init__(self, lib_path: Optional[Path] = None) -> None:
        self.lib_path = lib_path or self._find_library()
        self._lib = ctypes.CDLL(str(self.lib_path))
        self._bind_signatures()

    @staticmethod
    def _find_library() -> Path:
        here = Path(__file__).resolve().parent
        root = here.parent if here.name == "tests" else here
        candidates = [
            root / "build-gcc-attn" / "libaes_crypto.so",
            root / "build-gcc" / "libaes_crypto.so",
            root / "build" / "libaes_crypto.so",
            root / "build-gcc-attn" / "libaes_crypto.dll",
            root / "build-gcc-attn" / "aes_crypto.dll",
            root / "build-gcc" / "libaes_crypto.dll",
            root / "build-gcc" / "aes_crypto.dll",
            root / "build" / "aes_crypto.dll",
            root / "libaes_crypto.so",
            root / "aes_crypto.dll",
            here / "libaes_crypto.so",
        ]
        for cand in candidates:
            if cand.exists():
                return cand
        raise FileNotFoundError(
            "Could not locate libaes_crypto.so or aes_crypto.dll in build-gcc-attn/, build-gcc/, or build/."
        )

    def _bind_signatures(self) -> None:
        u8_p = ctypes.POINTER(ctypes.c_uint8)
        sz_p = ctypes.POINTER(ctypes.c_size_t)

        self._lib.aes_encrypt_block.argtypes = [u8_p, ctypes.c_size_t, u8_p, u8_p]
        self._lib.aes_encrypt_block.restype = ctypes.c_int

        self._lib.aes_decrypt_block.argtypes = [u8_p, ctypes.c_size_t, u8_p, u8_p]
        self._lib.aes_decrypt_block.restype = ctypes.c_int

        self._lib.aes_get_padding_length.argtypes = [ctypes.c_size_t]
        self._lib.aes_get_padding_length.restype = ctypes.c_size_t

        self._lib.aes_ecb_encrypt.argtypes = [u8_p, ctypes.c_size_t, u8_p, ctypes.c_size_t, ctypes.c_int, u8_p, sz_p]
        self._lib.aes_ecb_encrypt.restype = ctypes.c_int

        self._lib.aes_ecb_decrypt.argtypes = [u8_p, ctypes.c_size_t, u8_p, ctypes.c_size_t, ctypes.c_int, u8_p, sz_p]
        self._lib.aes_ecb_decrypt.restype = ctypes.c_int

        self._lib.aes_cbc_encrypt.argtypes = [u8_p, ctypes.c_size_t, u8_p, u8_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, u8_p, sz_p]
        self._lib.aes_cbc_encrypt.restype = ctypes.c_int

        self._lib.aes_cbc_decrypt.argtypes = [u8_p, ctypes.c_size_t, u8_p, u8_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, u8_p, sz_p]
        self._lib.aes_cbc_decrypt.restype = ctypes.c_int

        self._lib.aes_cfb_encrypt.argtypes = [u8_p, ctypes.c_size_t, u8_p, u8_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, u8_p, sz_p]
        self._lib.aes_cfb_encrypt.restype = ctypes.c_int

        self._lib.aes_cfb_decrypt.argtypes = [u8_p, ctypes.c_size_t, u8_p, u8_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, u8_p, sz_p]
        self._lib.aes_cfb_decrypt.restype = ctypes.c_int

        self._lib.aes_ofb_encrypt.argtypes = [u8_p, ctypes.c_size_t, u8_p, u8_p, ctypes.c_size_t, ctypes.c_int, u8_p, sz_p]
        self._lib.aes_ofb_encrypt.restype = ctypes.c_int

        self._lib.aes_ofb_decrypt.argtypes = [u8_p, ctypes.c_size_t, u8_p, u8_p, ctypes.c_size_t, ctypes.c_int, u8_p, sz_p]
        self._lib.aes_ofb_decrypt.restype = ctypes.c_int

        self._lib.aes_ctr_encrypt.argtypes = [u8_p, ctypes.c_size_t, u8_p, u8_p, ctypes.c_size_t, ctypes.c_int, u8_p, sz_p]
        self._lib.aes_ctr_encrypt.restype = ctypes.c_int

        self._lib.aes_ctr_decrypt.argtypes = [u8_p, ctypes.c_size_t, u8_p, u8_p, ctypes.c_size_t, ctypes.c_int, u8_p, sz_p]
        self._lib.aes_ctr_decrypt.restype = ctypes.c_int

        self._lib.aes_ccm_encrypt.argtypes = [
            u8_p, ctypes.c_size_t, u8_p, ctypes.c_size_t,
            u8_p, ctypes.c_size_t, u8_p, ctypes.c_size_t,
            ctypes.c_size_t, ctypes.c_int, u8_p, sz_p
        ]
        self._lib.aes_ccm_encrypt.restype = ctypes.c_int

        self._lib.aes_ccm_decrypt.argtypes = [
            u8_p, ctypes.c_size_t, u8_p, ctypes.c_size_t,
            u8_p, ctypes.c_size_t, u8_p, ctypes.c_size_t,
            ctypes.c_size_t, ctypes.c_int, u8_p, sz_p
        ]
        self._lib.aes_ccm_decrypt.restype = ctypes.c_int

    @staticmethod
    def _buf(data: Optional[bytes]):
        if data is None:
            return None
        return (ctypes.c_uint8 * len(data)).from_buffer_copy(data)

    def encrypt_block(self, key: bytes, block16: bytes) -> bytes:
        out = (ctypes.c_uint8 * 16)()
        rc = self._lib.aes_encrypt_block(self._buf(key), len(key), self._buf(block16), out)
        if rc != 0:
            raise ValueError("aes_encrypt_block failed")
        return bytes(out)

    def decrypt_block(self, key: bytes, block16: bytes) -> bytes:
        out = (ctypes.c_uint8 * 16)()
        rc = self._lib.aes_decrypt_block(self._buf(key), len(key), self._buf(block16), out)
        if rc != 0:
            raise ValueError("aes_decrypt_block failed")
        return bytes(out)

    def ecb_encrypt(self, key: bytes, pt: bytes, pad: bool = True) -> bytes:
        out = (ctypes.c_uint8 * (len(pt) + 32))()
        out_len = ctypes.c_size_t(0)
        rc = self._lib.aes_ecb_encrypt(self._buf(key), len(key), self._buf(pt), len(pt), int(pad), out, ctypes.byref(out_len))
        if rc != 0:
            raise ValueError("aes_ecb_encrypt failed")
        return bytes(out[: out_len.value])

    def ecb_decrypt(self, key: bytes, ct: bytes, unpad: bool = True) -> bytes:
        out = (ctypes.c_uint8 * (len(ct) + 16))()
        out_len = ctypes.c_size_t(0)
        rc = self._lib.aes_ecb_decrypt(self._buf(key), len(key), self._buf(ct), len(ct), int(unpad), out, ctypes.byref(out_len))
        if rc != 0:
            raise ValueError("aes_ecb_decrypt failed")
        return bytes(out[: out_len.value])

    def cbc_encrypt(self, key: bytes, pt: bytes, iv: bytes, prepend_iv: bool = False, pad: bool = True) -> bytes:
        out = (ctypes.c_uint8 * (len(pt) + 48))()
        out_len = ctypes.c_size_t(0)
        rc = self._lib.aes_cbc_encrypt(self._buf(key), len(key), self._buf(iv), self._buf(pt), len(pt), int(prepend_iv), int(pad), out, ctypes.byref(out_len))
        if rc != 0:
            raise ValueError("aes_cbc_encrypt failed")
        return bytes(out[: out_len.value])

    def cbc_decrypt(self, key: bytes, ct: bytes, iv: Optional[bytes] = None, has_iv: bool = False, unpad: bool = True) -> bytes:
        out = (ctypes.c_uint8 * (len(ct) + 16))()
        out_len = ctypes.c_size_t(0)
        rc = self._lib.aes_cbc_decrypt(self._buf(key), len(key), self._buf(iv), self._buf(ct), len(ct), int(has_iv), int(unpad), out, ctypes.byref(out_len))
        if rc != 0:
            raise ValueError("aes_cbc_decrypt failed")
        return bytes(out[: out_len.value])

    def cfb_encrypt(self, key: bytes, pt: bytes, iv: bytes, segment_size: int = 128, prepend_iv: bool = False) -> bytes:
        out = (ctypes.c_uint8 * (len(pt) + 32))()
        out_len = ctypes.c_size_t(0)
        rc = self._lib.aes_cfb_encrypt(self._buf(key), len(key), self._buf(iv), self._buf(pt), len(pt), segment_size, int(prepend_iv), out, ctypes.byref(out_len))
        if rc != 0:
            raise ValueError("aes_cfb_encrypt failed")
        return bytes(out[: out_len.value])

    def ofb_encrypt(self, key: bytes, pt: bytes, iv: bytes, prepend_iv: bool = False) -> bytes:
        out = (ctypes.c_uint8 * (len(pt) + 32))()
        out_len = ctypes.c_size_t(0)
        rc = self._lib.aes_ofb_encrypt(self._buf(key), len(key), self._buf(iv), self._buf(pt), len(pt), int(prepend_iv), out, ctypes.byref(out_len))
        if rc != 0:
            raise ValueError("aes_ofb_encrypt failed")
        return bytes(out[: out_len.value])

    def ctr_encrypt(self, key: bytes, pt: bytes, iv: bytes, prepend_iv: bool = False) -> bytes:
        out = (ctypes.c_uint8 * (len(pt) + 32))()
        out_len = ctypes.c_size_t(0)
        rc = self._lib.aes_ctr_encrypt(self._buf(key), len(key), self._buf(iv), self._buf(pt), len(pt), int(prepend_iv), out, ctypes.byref(out_len))
        if rc != 0:
            raise ValueError("aes_ctr_encrypt failed")
        return bytes(out[: out_len.value])

    def ccm_encrypt(self, key: bytes, pt: bytes, nonce: bytes, aad: bytes = b"", tag_len: int = 16, prepend_nonce: bool = False) -> bytes:
        out = (ctypes.c_uint8 * (len(pt) + len(nonce) + tag_len + 16))()
        out_len = ctypes.c_size_t(0)
        rc = self._lib.aes_ccm_encrypt(
            self._buf(key), len(key), self._buf(nonce), len(nonce),
            self._buf(aad), len(aad), self._buf(pt), len(pt),
            tag_len, int(prepend_nonce), out, ctypes.byref(out_len)
        )
        if rc != 0:
            raise ValueError("aes_ccm_encrypt failed")
        return bytes(out[: out_len.value])

    def ccm_decrypt(self, key: bytes, ct_and_tag: bytes, nonce: Optional[bytes] = None, aad: bytes = b"", tag_len: int = 16, has_nonce: bool = False) -> bytes:
        out = (ctypes.c_uint8 * (len(ct_and_tag) + 16))()
        out_len = ctypes.c_size_t(0)
        n_len = len(nonce) if nonce is not None else 13
        rc = self._lib.aes_ccm_decrypt(
            self._buf(key), len(key), self._buf(nonce), n_len,
            self._buf(aad), len(aad), self._buf(ct_and_tag), len(ct_and_tag),
            tag_len, int(has_nonce), out, ctypes.byref(out_len)
        )
        if rc != 0:
            raise ValueError("AES-CCM authentication / decryption failed")
        return bytes(out[: out_len.value])
