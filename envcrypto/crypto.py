# -*- coding:utf-8 -*-
"""
    crypto.py
    ~~~~~~~~
    A safe way to store environmental Variables.
    Any type and length of KEY can be used.

    pip3 install pycryptodome==3.10.1

    e.g.::

        Ref: main

    :author: Fufu, 2020/4/29
"""
import os
from base64 import b64decode, b64encode, urlsafe_b64decode, urlsafe_b64encode
from hashlib import md5
from typing import Any, Union

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Padding


def set_environ(varname: str = '', value: str = '', key: Any = None) -> str:
    """Set an environment variable (encrypt data)"""
    if key is not None:
        value = encrypt(value, get_key_32(key))

    os.environ[varname] = value

    return value


def get_environ(varname: str = '', key: Any = None, default: str = '') -> str:
    """Get an environment variable (decrypt data)"""
    value = os.getenv(varname)
    if value is None:
        return default

    if key is not None:
        value = decrypt(value, get_key_32(key))

    return value


def get_key_32(key: Any = None) -> bytes:
    """Any value generate key (32 bytes)"""
    checksum = md5(bytes(str(key), encoding='utf-8'))
    return checksum.digest() + bytes(checksum.hexdigest(), encoding='utf-8')[8:24]


def encrypt(plaintext: str, key: Any = None) -> str:
    """Use get_key_32 encrypt and return to url-safe base64-encoded string"""
    return encrypt_aes_cbc_urlsafe_b64(plaintext, get_key_32(key))


def decrypt(ciphertext: str, key: Any = None) -> str:
    """Use get_key_32 decrypt and return to string"""
    return decrypt_aes_cbc_urlsafe_b64(ciphertext, get_key_32(key))


def encrypt_aes_cbc(data_src: Any, key: Any = None, iv: Any = None, bits: int = 256) -> Union[bytes, None]:
    return AESCipher(key, iv, bits).encrypt_aes_cbc(data_src)


def encrypt_aes_cbc_hex(data_src: str, key: Any = None, iv: Any = None, bits: int = 256) -> str:
    return AESCipher(key, iv, bits).encrypt_aes_cbc_hex(data_src)


def encrypt_aes_cbc_b64(data_src: str, key: Any = None, iv: Any = None, bits: int = 256) -> str:
    return AESCipher(key, iv, bits).encrypt_aes_cbc_b64(data_src)


def encrypt_aes_cbc_urlsafe_b64(data_src: str, key: Any = None, iv: Any = None, bits: int = 256) -> str:
    return AESCipher(key, iv, bits).encrypt_aes_cbc_urlsafe_b64(data_src)


def decrypt_aes_cbc(encrypted: Any, key: Any = None, iv: Any = None) -> Union[bytes, None]:
    return AESCipher(key, iv).decrypt_aes_cbc(encrypted)


def decrypt_aes_cbc_hex(encrypted: str, key: Any = None, iv: Any = None) -> str:
    data = AESCipher(key, iv).decrypt_aes_cbc_hex(encrypted)
    return '' if data is None else data.decode('utf-8')


def decrypt_aes_cbc_b64(encrypted: str, key: Any = None, iv: Any = None) -> str:
    data = AESCipher(key, iv).decrypt_aes_cbc_b64(encrypted)
    return '' if data is None else data.decode('utf-8')


def decrypt_aes_cbc_urlsafe_b64(encrypted: str, key: Any = None, iv: Any = None) -> str:
    data = AESCipher(key, iv).decrypt_aes_cbc_urlsafe_b64(encrypted)
    return '' if data is None else data.decode('utf-8')


class AESCipher:
    """AES CBC encrypt / decrypts."""

    def __init__(self, key: Any = None, iv: Any = None, bits: int = 256, style: str = 'pkcs7'):
        # Padding style
        self.style = style

        # 16, 24, 32
        # aes-cbc-128, aes-cbc-192, aes-cbc-256
        self.key = self.mk_key(key, int(bits / 8))

        # Automatically set to key[:blockSize] when iv is invalid
        self.iv = self.mk_key(iv if iv else self.key[:AES.block_size], AES.block_size)

    def encrypt_aes_cbc(self, data: Union[bytes, Any]) -> Union[bytes, None]:
        try:
            return AES.new(self.key, AES.MODE_CBC, iv=self.iv).encrypt(self.mk_pad_bytes(data))
        except Exception:
            return None

    def encrypt_aes_cbc_hex(self, data: Union[bytes, Any]) -> str:
        encrypted = self.encrypt_aes_cbc(data)
        return '' if encrypted is None else encrypted.hex()

    def encrypt_aes_cbc_b64(self, data: Union[bytes, Any]) -> str:
        encrypted = self.encrypt_aes_cbc(data)
        return '' if encrypted is None else b64encode(encrypted).decode('utf-8')

    def encrypt_aes_cbc_urlsafe_b64(self, data: Union[bytes, Any]) -> str:
        encrypted = self.encrypt_aes_cbc(data)
        return '' if encrypted is None else urlsafe_b64encode(encrypted).decode('utf-8')

    def decrypt_aes_cbc(self, encrypted: bytes) -> Union[bytes, None]:
        try:
            data = AES.new(self.key, AES.MODE_CBC, iv=self.iv).decrypt(encrypted)
            data = Padding.unpad(data, AES.block_size)
            return data
        except Exception:
            return None

    def decrypt_aes_cbc_hex(self, encrypted: str) -> Union[bytes, None]:
        try:
            return self.decrypt_aes_cbc(bytes.fromhex(str(encrypted).strip()))
        except Exception:
            return None

    def decrypt_aes_cbc_b64(self, encrypted: str) -> Union[bytes, None]:
        try:
            return self.decrypt_aes_cbc(b64decode(str(encrypted).strip()))
        except Exception:
            return None

    def decrypt_aes_cbc_urlsafe_b64(self, encrypted: str) -> Union[bytes, None]:
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


if __name__ == '__main__':
    # Recommended usage
    api_secret = 'AABB.Fufu@TEST001'
    env_name = 'APP_API_SECRET'
    my_key = b'\02S\n\t@k\x02'  # Any type and any length
    print('''
Set environment variable in your OS:
    export {0}={1}
In your code:
    data = {2!r}'''.format(
        env_name,
        set_environ(env_name, api_secret, my_key),
        get_environ(env_name, key=my_key),
    ))

    print('''
Set environment variable in your OS (if key is None):
    export {0}={1}
In your code:
    data = {2!r}
'''.format(
        env_name,
        set_environ(env_name, api_secret),
        get_environ(env_name),
    ))

    print('default value:', get_environ('NOT_EXIST', default='default.value'))
    print()

    # Some additional extension methods
    any_data = 123.45
    any_key = False

    print('use key:', AESCipher(any_key).key)
    print('use iv:', AESCipher(any_key).iv)
    print('encrypted:', AESCipher(any_key).encrypt_aes_cbc(any_data))
    print('encrypted:', encrypt_aes_cbc(any_data, any_key))
    print('decrypted:', AESCipher(any_key).decrypt_aes_cbc(b'\xd5\xd4\x91\xa6olv\x8b\x0e0,\xa3/\x83\xa2_'))
    print('decrypted:', decrypt_aes_cbc(b'\xd5\xd4\x91\xa6olv\x8b\x0e0,\xa3/\x83\xa2_', any_key))
    print()

    my_data = 0x1011010
    my_key = 0o3334444
    my_iv = b'iv\f123'
    print(encrypt_aes_cbc(my_data, my_key, my_iv))
    # b'16846864'
    print(decrypt_aes_cbc(b'\x0b*\xf3\x90\x1a\x84.\xed\x1e\xf8\xb1\xce\x1c\xf7\xe9\xc0', my_key, my_iv))

    my_data = 'Fufu .$\x0f\r\ni^★地99'
    my_key = b'ff\xf4YF7777777\x024\x66~\xa7\xb6\x5c12356'

    a = encrypt(my_data, my_key)
    b = decrypt(a, my_key)
    # a:'57s0iy0Z2LqiQ9tq9Js2zozWhgLxpmEcGiRVylG9Ank='
    # b:'Fufu .$\x0f\r\ni^★地99'
    # b==my_data:True
    print('\na:{0!r}\nb:{1!r}\nb==my_data:{2!r}'.format(a, b, b == my_data))

    # encrypt aes-cbc
    ciphertext_bytes = encrypt_aes_cbc(my_data, my_key)
    ciphertext_hex = encrypt_aes_cbc_hex(my_data, my_key)
    ciphertext_b64 = encrypt_aes_cbc_b64(my_data, my_key)
    ciphertext_urlsafeb64 = encrypt_aes_cbc_urlsafe_b64(my_data, my_key)
    # bytes:b'\xbb\xff#z\x95\xcb7*\x8d\xca\x00\x1e\xb7\xcaN\xf8S\x05\xe5\x80\xcb\x9d#dr\xb6vp\xf6\xe0\x9c\x96'
    # hex:bbff237a95cb372a8dca001eb7ca4ef85305e580cb9d236472b67670f6e09c96
    # b64:u/8jepXLNyqNygAet8pO+FMF5YDLnSNkcrZ2cPbgnJY=
    # urlsafeb64:u_8jepXLNyqNygAet8pO-FMF5YDLnSNkcrZ2cPbgnJY=
    print('\nbytes:{}\nhex:{}\nb64:{}\nurlsafeb64:{}'.format(
        ciphertext_bytes, ciphertext_hex, ciphertext_b64, ciphertext_urlsafeb64))

    # decrypt aes-cbc
    plaintext_1 = decrypt_aes_cbc(ciphertext_bytes, my_key)
    plaintext_2 = decrypt_aes_cbc_hex(ciphertext_hex, my_key)
    plaintext_3 = decrypt_aes_cbc_b64(ciphertext_b64, my_key)
    plaintext_4 = decrypt_aes_cbc_urlsafe_b64(ciphertext_urlsafeb64, my_key)
    # b'Fufu .$\x0f\r\ni^\xe2\x98\x85\xe5\x9c\xb099'
    # 'Fufu .$\x0f\r\ni^★地99'
    # 'Fufu .$\x0f\r\ni^★地99'
    # 'Fufu .$\x0f\r\ni^★地99'
    # True
    print('\n{0!r}\n{1!r}\n{2!r}\n{3!r}\n{4}'.format(
        plaintext_1, plaintext_2, plaintext_3, plaintext_4, plaintext_4 == my_data))
