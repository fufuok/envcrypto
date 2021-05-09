# -*- coding:utf-8 -*-
"""
    crypto.py
    ~~~~~~~~
    A safe way to store environmental Variables.
    Any type and length of KEY can be used.

    pip3 install pycryptodome~=3.10.1

    e.g.::

        Ref: example.py

    :author: Fufu, 2020/4/29
    :update: Fufu, 2020/5/9 base58 for set_environ
"""
import os
from base64 import b64decode, b64encode, urlsafe_b64decode, urlsafe_b64encode
from hashlib import md5
from typing import Any, Union

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Padding

from .base58 import b58dc, b58ec


def set_environ(
        varname: str = '', value: Union[bytes, Any] = None, key: Any = None
) -> str:
    """Set an environment variable (encrypt data)"""
    if key is not None:
        value = encrypt(value, key)

    value = str(value)
    os.environ[varname] = value

    return value


def get_environ(
        varname: str = '', key: Any = None, default: Union[bytes, str, None] = None
) -> Union[bytes, str, None]:
    """Get an environment variable (decrypt data)"""
    value = os.getenv(varname)
    if value is None:
        return None if default is None else default

    if key is not None:
        value = decrypt(value, key)

    return value


def get_key_32(
        key: Any = None
) -> bytes:
    """Any value generate key (32 bytes)"""
    return bytes(md5(bytes(str(key), encoding='utf-8')).hexdigest(), encoding='utf-8')


def encrypt(
        plaintext: Union[bytes, Any], key: Any = None
) -> str:
    """Use get_key_32 encrypt and return to base58-encoded string"""
    return encrypt_aes_cbc_b58(plaintext, get_key_32(key))


def decrypt(
        ciphertext: str, key: Any = None
) -> Union[bytes, str, None]:
    """Use get_key_32 decrypt and return to bytes/str/None"""
    return decrypt_aes_cbc_b58(ciphertext, get_key_32(key))


def encrypt_aes_cbc(
        data_src: Union[bytes, Any], key: Any = None, iv: Any = None, bits: int = 256
) -> Union[bytes, None]:
    return AESCipher(key, iv, bits).encrypt_aes_cbc(data_src)


def encrypt_aes_cbc_hex(
        data_src: Union[bytes, Any], key: Any = None, iv: Any = None, bits: int = 256
) -> str:
    return AESCipher(key, iv, bits).encrypt_aes_cbc_hex(data_src)


def encrypt_aes_cbc_b58(
        data_src: Union[bytes, Any], key: Any = None, iv: Any = None, bits: int = 256
) -> str:
    return AESCipher(key, iv, bits).encrypt_aes_cbc_b58(data_src)


def encrypt_aes_cbc_b64(
        data_src: Union[bytes, Any], key: Any = None, iv: Any = None, bits: int = 256
) -> str:
    return AESCipher(key, iv, bits).encrypt_aes_cbc_b64(data_src)


def encrypt_aes_cbc_urlsafe_b64(
        data_src: Union[bytes, Any], key: Any = None, iv: Any = None, bits: int = 256
) -> str:
    return AESCipher(key, iv, bits).encrypt_aes_cbc_urlsafe_b64(data_src)


def decrypt_aes_cbc(
        encrypted: bytes, key: Any = None, iv: Any = None, bits: int = 256
) -> Union[bytes, str, None]:
    return AESCipher(key, iv, bits).decrypt_aes_cbc(encrypted)


def decrypt_aes_cbc_hex(
        encrypted: str, key: Any = None, iv: Any = None, bits: int = 256
) -> Union[bytes, str, None]:
    return AESCipher(key, iv, bits).decrypt_aes_cbc_hex(encrypted)


def decrypt_aes_cbc_b58(
        encrypted: str, key: Any = None, iv: Any = None, bits: int = 256
) -> Union[bytes, str, None]:
    return AESCipher(key, iv, bits).decrypt_aes_cbc_b58(encrypted)


def decrypt_aes_cbc_b64(
        encrypted: str, key: Any = None, iv: Any = None, bits: int = 256
) -> Union[bytes, str, None]:
    return AESCipher(key, iv, bits).decrypt_aes_cbc_b64(encrypted)


def decrypt_aes_cbc_urlsafe_b64(
        encrypted: str, key: Any = None, iv: Any = None, bits: int = 256
) -> Union[bytes, str, None]:
    return AESCipher(key, iv, bits).decrypt_aes_cbc_urlsafe_b64(encrypted)


class AESCipher:
    """AES CBC encrypt / decrypts."""

    def __init__(self, key: Any = None, iv: Any = None, bits: int = 256, style: str = 'pkcs7', with_type: bool = True):
        # Padding style
        self.style = style

        # 16, 24, 32
        # aes-cbc-128, aes-cbc-192, aes-cbc-256
        self.key = self.mk_key(key, int(bits / 8))

        # Automatically set to key[:blockSize] when iv is None
        self.iv = self.mk_key(self.key[:AES.block_size] if iv is None else iv, AES.block_size)

        # encrypted[0:1] is bytes(b) or string(s)
        self.with_type = with_type

    def encrypt_aes_cbc(self, data: Union[bytes, Any]) -> Union[bytes, None]:
        """Raw data is bytes or converted to strings."""
        try:
            raw_type = (b'b' if isinstance(data, bytes) else b's') if self.with_type else b''
            return raw_type + AES.new(self.key, AES.MODE_CBC, iv=self.iv).encrypt(self.mk_pad_bytes(data))
        except Exception:
            return None

    def encrypt_aes_cbc_hex(self, data: Union[bytes, Any]) -> str:
        encrypted = self.encrypt_aes_cbc(data)
        return '' if encrypted is None else encrypted.hex()

    def encrypt_aes_cbc_b58(self, data: Union[bytes, Any]) -> str:
        encrypted = self.encrypt_aes_cbc(data)
        return '' if encrypted is None else b58ec(encrypted)

    def encrypt_aes_cbc_b64(self, data: Union[bytes, Any]) -> str:
        encrypted = self.encrypt_aes_cbc(data)
        return '' if encrypted is None else b64encode(encrypted).decode('utf-8')

    def encrypt_aes_cbc_urlsafe_b64(self, data: Union[bytes, Any]) -> str:
        encrypted = self.encrypt_aes_cbc(data)
        return '' if encrypted is None else urlsafe_b64encode(encrypted).decode('utf-8')

    def decrypt_aes_cbc(self, encrypted: bytes) -> Union[bytes, str, None]:
        try:
            pos = 1 if self.with_type else 0
            raw_type = encrypted[:pos]
            value = AES.new(self.key, AES.MODE_CBC, iv=self.iv).decrypt(encrypted[pos:])
            value = Padding.unpad(value, AES.block_size)
            return value if raw_type == b'b' or raw_type == b'' else value.decode('utf-8')
        except Exception:
            return None

    def decrypt_aes_cbc_hex(self, encrypted: str) -> Union[bytes, str, None]:
        try:
            return self.decrypt_aes_cbc(bytes.fromhex(str(encrypted).strip()))
        except Exception:
            return None

    def decrypt_aes_cbc_b64(self, encrypted: str) -> Union[bytes, str, None]:
        try:
            return self.decrypt_aes_cbc(b64decode(str(encrypted).strip()))
        except Exception:
            return None

    def decrypt_aes_cbc_b58(self, encrypted: str) -> Union[bytes, str, None]:
        try:
            return self.decrypt_aes_cbc(b58dc(str(encrypted).strip()))
        except Exception:
            return None

    def decrypt_aes_cbc_urlsafe_b64(self, encrypted: str) -> Union[bytes, str, None]:
        try:
            return self.decrypt_aes_cbc(urlsafe_b64decode(str(encrypted).strip()))
        except Exception:
            return None

    def mk_bytes(self, data_src: Union[bytes, Any]) -> bytes:
        """Coerce arbitrary data to bytes."""
        return data_src if isinstance(data_src, bytes) else bytes(str(data_src), 'utf-8')

    def mk_pad_bytes(self, data_to_pad: Any, length: int = AES.block_size) -> bytes:
        """Apply standard padding."""
        return Padding.pad(self.mk_bytes(data_to_pad), length, style=self.style)

    def mk_key(self, key_src: Any = None, length: int = 16) -> bytes:
        """Generate a random key or apply standard padding."""
        if key_src is None:
            key = get_random_bytes(length)
        else:
            key = self.mk_pad_bytes(key_src, length)[:length]

        return key
